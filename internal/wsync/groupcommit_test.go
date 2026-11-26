package wsync

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/google/uuid"

	"github.com/ViniZap4/lumi-server/internal/crdt"
)

// gcRepo is memRepo plus crdt.BatchAppender, with knobs to slow down,
// gate or fail appends and counters for the COUNT queries the hot path
// must no longer make.
type gcRepo struct {
	*memRepo
	delay     time.Duration
	gate      atomic.Pointer[chan struct{}] // non-nil: appends block until closed
	failNext  atomic.Int32                  // fail this many append calls
	batches   atomic.Int64
	counts    atomic.Int64
	upserts   atomic.Int64
	maxBatch  atomic.Int64
	appendHit chan struct{} // optional: signalled when an append starts
}

func newGCRepo() *gcRepo { return &gcRepo{memRepo: newMemRepo()} }

func (g *gcRepo) wait() error {
	if g.appendHit != nil {
		select {
		case g.appendHit <- struct{}{}:
		default:
		}
	}
	if ch := g.gate.Load(); ch != nil {
		<-*ch
	}
	if g.delay > 0 {
		time.Sleep(g.delay)
	}
	if g.failNext.Load() > 0 && g.failNext.Add(-1) >= 0 {
		return errors.New("postgres: connection reset")
	}
	return nil
}

func (g *gcRepo) AppendUpdates(ctx context.Context, rows []crdt.PendingUpdate) error {
	if err := g.wait(); err != nil {
		return err
	}
	g.batches.Add(1)
	for {
		cur := g.maxBatch.Load()
		if int64(len(rows)) <= cur || g.maxBatch.CompareAndSwap(cur, int64(len(rows))) {
			break
		}
	}
	for _, r := range rows {
		if _, err := g.memRepo.AppendUpdate(ctx, r.VaultID, r.NoteID, r.Update, r.OriginUserID, r.OriginKind); err != nil {
			return err
		}
	}
	return nil
}

func (g *gcRepo) AppendUpdate(ctx context.Context, v uuid.UUID, n string, u []byte, a uuid.UUID, o string) (int64, error) {
	if err := g.wait(); err != nil {
		return 0, err
	}
	g.batches.Add(1)
	g.maxBatch.CompareAndSwap(0, 1)
	return g.memRepo.AppendUpdate(ctx, v, n, u, a, o)
}

func (g *gcRepo) CountUpdates(ctx context.Context, v uuid.UUID, n string) (int, int64, error) {
	g.counts.Add(1)
	return g.memRepo.CountUpdates(ctx, v, n)
}

func (g *gcRepo) UpsertSnapshot(ctx context.Context, v uuid.UUID, n string, state []byte) error {
	g.upserts.Add(1)
	return g.memRepo.UpsertSnapshot(ctx, v, n, state)
}

func (g *gcRepo) closeGate() func() {
	ch := make(chan struct{})
	g.gate.Store(&ch)
	var once sync.Once
	return func() { once.Do(func() { g.gate.Store(nil); close(ch) }) }
}

// client is a simulated WebSocket peer: a replica doc kept in sync with
// what the room broadcasts to it.
type client struct {
	t    testing.TB
	sub  *Subscriber
	doc  *crdt.Doc
	room *Room
}

func newClient(t testing.TB, hub *Hub, v uuid.UUID, note string) *client {
	t.Helper()
	sub := hub.NewSubscriber(uuid.New())
	room, err := hub.Join(context.Background(), v, note, sub)
	if err != nil {
		t.Fatal(err)
	}
	state, err := room.Doc().EncodeStateAsUpdate()
	if err != nil {
		t.Fatal(err)
	}
	doc, err := crdt.LoadDoc(state)
	if err != nil {
		t.Fatal(err)
	}
	return &client{t: t, sub: sub, doc: doc, room: room}
}

// absorb applies every broadcast queued for the client.
func (c *client) absorb() {
	for {
		select {
		case msg := <-c.sub.Out:
			m, err := DecodeMessage(msg)
			if err == nil && m.Type == MessageSync {
				_ = c.doc.ApplyUpdate(m.Body)
			}
		default:
			return
		}
	}
}

// edit inserts token at the end of the client's text and returns the
// update (what the client would send).
func (c *client) edit(token string) []byte {
	u, err := c.doc.ApplyPlanned(func(text string) ([]crdt.Edit, error) {
		return []crdt.Edit{{Pos: len(utf16.Encode([]rune(text))), Ins: token}}, nil
	}, "client")
	if err != nil {
		c.t.Fatal(err)
	}
	return u
}

func (c *client) close(hub *Hub) {
	hub.Leave(c.room, c.sub)
	_ = c.doc.Close()
}

// replayLog loads a note's log in id order into a fresh doc and fails if
// any row arrives before an update it depends on (a reordering).
func replayLog(t *testing.T, repo *memRepo, v uuid.UUID, note string) string {
	t.Helper()
	d := crdt.NewDoc()
	defer d.Close()
	if snap, err := repo.GetSnapshot(context.Background(), v, note); err == nil {
		if err := d.ApplyUpdate(snap.State); err != nil {
			t.Fatal(err)
		}
	}
	rows, _ := repo.ListUpdatesSince(context.Background(), v, note, 0, 0)
	for i, r := range rows {
		if err := d.ApplyUpdate(r.Update); err != nil {
			t.Fatal(err)
		}
		if pending, _ := d.HasPending(); pending {
			t.Fatalf("log row %d (id %d) depends on a later row: updates were reordered", i, r.ID)
		}
	}
	txt, _ := d.Text()
	return txt
}

// Several clients per note, several notes, all typing at once over a
// slow store: every acknowledged update is in the log, the log of each
// note replays in order without pending structs (persist-before-
// broadcast plus FIFO commit), and batching actually happened.
func TestGroupCommit_NoLostOrReorderedUpdates(t *testing.T) {
	repo := newGCRepo()
	repo.delay = 300 * time.Microsecond
	reg := crdt.NewRegistry(repo)
	hub := NewHub(reg, WithMirrorDebounce(0))
	defer hub.Close()

	v := uuid.New()
	const notes, perNote, edits = 4, 3, 40
	var wg sync.WaitGroup
	var acked atomic.Int64
	tokens := make([][]string, notes)
	for n := 0; n < notes; n++ {
		note := fmt.Sprintf("note-%d", n)
		for c := 0; c < perNote; c++ {
			cl := newClient(t, hub, v, note)
			tok := make([]string, edits)
			for i := range tok {
				tok[i] = fmt.Sprintf("[%d.%d.%d😀]", n, c, i)
			}
			tokens[n] = append(tokens[n], tok...)
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer cl.close(hub)
				for _, tk := range tok {
					cl.absorb()
					if err := cl.room.ApplyAndBroadcast(cl.edit(tk), cl.sub, cl.sub.UserID); err != nil {
						t.Error(err)
						return
					}
					acked.Add(1)
				}
			}()
		}
	}
	wg.Wait()

	if got, want := acked.Load(), int64(notes*perNote*edits); got != want {
		t.Fatalf("acked %d, want %d", got, want)
	}
	for n := 0; n < notes; n++ {
		note := fmt.Sprintf("note-%d", n)
		rows, _ := repo.ListUpdatesSince(context.Background(), v, note, 0, 0)
		if len(rows) != perNote*edits {
			t.Fatalf("%s: %d log rows, want %d", note, len(rows), perNote*edits)
		}
		txt := replayLog(t, repo.memRepo, v, note)
		for _, tk := range tokens[n] {
			if !strings.Contains(txt, tk) {
				t.Fatalf("%s: token %s lost", note, tk)
			}
		}
	}
	if repo.maxBatch.Load() < 2 {
		t.Fatalf("no batching under load (max batch %d)", repo.maxBatch.Load())
	}
	if repo.batches.Load() >= int64(notes*perNote*edits) {
		t.Fatalf("%d appends for %d updates: group commit saved nothing", repo.batches.Load(), notes*perNote*edits)
	}
	// The hot path never counts the log (only compaction verifies).
	if c := repo.counts.Load(); c != 0 {
		t.Fatalf("%d COUNT queries on the live path", c)
	}
}

// One writer at a time: each update is written alone, the moment it
// arrives, with no lingering.
func TestGroupCommit_IdleCommitsImmediately(t *testing.T) {
	var mu sync.Mutex
	var sizes []int
	var lingers []time.Duration
	repo := newGCRepo()
	hub := NewHub(crdt.NewRegistry(repo), WithMirrorDebounce(0), withBatchObserver(func(n int, l time.Duration) {
		mu.Lock()
		sizes = append(sizes, n)
		lingers = append(lingers, l)
		mu.Unlock()
	}))
	defer hub.Close()
	cl := newClient(t, hub, uuid.New(), "n")
	defer cl.close(hub)
	for i := 0; i < 20; i++ {
		if err := cl.room.ApplyAndBroadcast(cl.edit("x"), cl.sub, uuid.Nil); err != nil {
			t.Fatal(err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(sizes) != 20 {
		t.Fatalf("%d batches, want 20", len(sizes))
	}
	for i := range sizes {
		if sizes[i] != 1 || lingers[i] != 0 {
			t.Fatalf("batch %d: size %d linger %v, want 1 and 0", i, sizes[i], lingers[i])
		}
	}
}

// Under load the committer lingers to grow batches, but never longer than
// the configured cap (4 ms by default), even when a commit takes longer.
func TestGroupCommit_LingerCappedUnderLoad(t *testing.T) {
	var mu sync.Mutex
	var maxLinger time.Duration
	var lingered bool
	repo := newGCRepo()
	repo.delay = 6 * time.Millisecond // slower than the cap
	hub := NewHub(crdt.NewRegistry(repo), WithMirrorDebounce(0), WithGroupCommit(DefaultGroupCommitMaxDelay, 0, 1), withBatchObserver(func(_ int, l time.Duration) {
		mu.Lock()
		if l > maxLinger {
			maxLinger = l
		}
		if l > 0 {
			lingered = true
		}
		mu.Unlock()
	}))
	defer hub.Close()

	v := uuid.New()
	var wg sync.WaitGroup
	for n := 0; n < 8; n++ {
		cl := newClient(t, hub, v, fmt.Sprintf("n%d", n))
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer cl.close(hub)
			for i := 0; i < 6; i++ {
				if err := cl.room.ApplyAndBroadcast(cl.edit("y"), cl.sub, uuid.Nil); err != nil {
					t.Error(err)
					return
				}
			}
		}()
	}
	wg.Wait()
	mu.Lock()
	defer mu.Unlock()
	if !lingered {
		t.Fatal("never lingered under load")
	}
	if maxLinger > DefaultGroupCommitMaxDelay {
		t.Fatalf("lingered %v, cap %v", maxLinger, DefaultGroupCommitMaxDelay)
	}
}

// Nobody sees an update before it is durable: not the other subscribers,
// not the writer (the call blocks) and not a state-vector read (View
// waits), which is what makes the REST acknowledgement a durability proof.
func TestGroupCommit_PersistBeforeBroadcastAndAck(t *testing.T) {
	repo := newGCRepo()
	repo.appendHit = make(chan struct{}, 1)
	hub := NewHub(crdt.NewRegistry(repo), WithMirrorDebounce(0))
	defer hub.Close()
	v := uuid.New()
	writer := newClient(t, hub, v, "n")
	defer writer.close(hub)
	other := newClient(t, hub, v, "n")
	defer other.close(hub)

	release := repo.closeGate()
	defer release()
	done := make(chan error, 1)
	go func() { done <- writer.room.ApplyAndBroadcast(writer.edit("durable?"), writer.sub, uuid.Nil) }()
	<-repo.appendHit // the append is in flight (blocked on the gate)

	select {
	case <-other.sub.Out:
		t.Fatal("broadcast before the update was durable")
	case err := <-done:
		t.Fatalf("writer acknowledged before durable (err=%v)", err)
	case <-time.After(30 * time.Millisecond):
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	err := hub.View(ctx, v, "n", func(*crdt.Doc) error { return nil })
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("View returned %v while an update was in flight; want it to wait", err)
	}

	release()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	_ = recvUpdate(t, other.sub)
	var sv []byte
	if err := hub.View(context.Background(), v, "n", func(d *crdt.Doc) error {
		var err error
		sv, err = d.StateVectorV1()
		return err
	}); err != nil || len(sv) == 0 {
		t.Fatalf("view after commit: sv %v err %v", sv, err)
	}
}

// A failed append is reported to the writer and never broadcast. The
// change stays in the doc, so the next successful commit forces a
// compaction whose snapshot carries it: a later row that depends on the
// failed one still loads after a restart.
func TestGroupCommit_FailedAppendIsRepaired(t *testing.T) {
	repo := newGCRepo()
	hub := NewHub(crdt.NewRegistry(repo), WithMirrorDebounce(0))
	defer hub.Close()
	v := uuid.New()
	writer := newClient(t, hub, v, "n")
	defer writer.close(hub)
	other := newClient(t, hub, v, "n")
	defer other.close(hub)

	repo.failNext.Store(1)
	if err := writer.room.ApplyAndBroadcast(writer.edit("A"), writer.sub, uuid.Nil); err == nil {
		t.Fatal("want the append error")
	}
	select {
	case <-other.sub.Out:
		t.Fatal("a failed update was broadcast")
	case <-time.After(20 * time.Millisecond):
	}
	// B depends on A (same replica).
	if err := writer.room.ApplyAndBroadcast(writer.edit("B"), writer.sub, uuid.Nil); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for repo.upserts.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("no repair compaction after a failed append")
		}
		time.Sleep(2 * time.Millisecond)
	}
	// Restart: a new registry over the same storage.
	d, err := crdt.NewRegistry(repo.memRepo).LoadDoc(context.Background(), v, "n")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if txt, _ := d.Text(); txt != "AB" {
		t.Fatalf("after restart text %q, want AB", txt)
	}
	if p, _ := d.HasPending(); p {
		t.Fatal("restart left pending structs")
	}
}

// Crash semantics: what a writer saw acknowledged survives a crash (a new
// hub over the same storage, the old one never closed). An update whose
// commit had not finished is lost on the server but was never
// acknowledged, so the client still holds it and re-sends it on rejoin
// (its diff against the new server state vector).
func TestGroupCommit_CrashRestart(t *testing.T) {
	repo := newGCRepo()
	repo.appendHit = make(chan struct{}, 1)
	old := NewHub(crdt.NewRegistry(repo), WithMirrorDebounce(0))
	v := uuid.New()
	cl := newClient(t, old, v, "n")
	for _, tk := range []string{"one ", "two ", "three "} {
		if err := cl.room.ApplyAndBroadcast(cl.edit(tk), cl.sub, uuid.Nil); err != nil {
			t.Fatal(err)
		}
	}
	// An unacknowledged update: blocked in the store when the "crash"
	// happens. Simulate the crash by restarting over a copy of the storage
	// as it is now (the in-flight row never landed).
	select { // forget the signals of the acknowledged appends
	case <-repo.appendHit:
	default:
	}
	release := repo.closeGate()
	inflight := make(chan error, 1)
	go func() { inflight <- cl.room.ApplyAndBroadcast(cl.edit("four"), cl.sub, uuid.Nil) }()
	<-repo.appendHit
	crashed := newMemRepo()
	repo.mu.Lock()
	for k, rows := range repo.updates {
		crashed.updates[k] = append([]crdt.UpdateRow(nil), rows...)
	}
	for k, s := range repo.snapshots {
		crashed.snapshots[k] = s
	}
	crashed.nextID = repo.nextID
	repo.mu.Unlock()

	fresh := NewHub(crdt.NewRegistry(crashed), WithMirrorDebounce(0))
	defer fresh.Close()
	var serverText string
	var serverSV []byte
	if err := fresh.View(context.Background(), v, "n", func(d *crdt.Doc) error {
		serverText, _ = d.Text()
		serverSV, _ = d.StateVectorV1()
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if serverText != "one two three " {
		t.Fatalf("acknowledged updates lost in the crash: %q", serverText)
	}
	// Rejoin: the client sends what the server lacks.
	diff, err := cl.doc.EncodeDiffSince(serverSV)
	if err != nil {
		t.Fatal(err)
	}
	res, err := fresh.ApplyUpdate(context.Background(), v, "n", diff, ApplyOptions{Origin: OriginLive, WantText: true})
	if err != nil || res.Text != "one two three four" {
		t.Fatalf("resync: text %q err %v", res.Text, err)
	}

	release()
	<-inflight
	cl.close(old)
	old.Close()
}

// Hub.Close writes what was already queued before shutting rooms down.
func TestGroupCommit_CloseDrainsQueue(t *testing.T) {
	repo := newGCRepo()
	repo.appendHit = make(chan struct{}, 1)
	hub := NewHub(crdt.NewRegistry(repo), WithMirrorDebounce(0))
	v := uuid.New()
	release := repo.closeGate()
	var wg sync.WaitGroup
	errs := make(chan error, 4)
	for n := 0; n < 4; n++ {
		note := fmt.Sprintf("n%d", n)
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := hub.ApplyText(context.Background(), v, note, "body "+note, nil, ApplyOptions{Origin: "tui"})
			errs <- err
		}()
	}
	<-repo.appendHit
	closed := make(chan struct{})
	go func() { hub.Close(); close(closed) }()
	time.Sleep(10 * time.Millisecond)
	release()
	wg.Wait()
	<-closed
	close(errs)
	for err := range errs {
		if err != nil && !errors.Is(err, ErrHubClosed) {
			t.Fatalf("queued write failed: %v", err)
		}
	}
	for n := 0; n < 4; n++ {
		rows, _ := repo.ListUpdatesSince(context.Background(), v, fmt.Sprintf("n%d", n), 0, 0)
		if len(rows) > 1 {
			t.Fatalf("n%d: %d rows", n, len(rows))
		}
	}
}

// DropNote returns only after the dropped history's in-flight commits
// settle, so ResetNote / delete+recreate never see a late row.
func TestDropNote_WaitsForInFlightCommit(t *testing.T) {
	repo := newGCRepo()
	repo.appendHit = make(chan struct{}, 1)
	hub := NewHub(crdt.NewRegistry(repo), WithMirrorDebounce(0))
	defer hub.Close()
	v := uuid.New()
	cl := newClient(t, hub, v, "n")
	defer cl.close(hub)
	release := repo.closeGate()
	defer release()
	go func() { _ = cl.room.ApplyAndBroadcast(cl.edit("late"), cl.sub, uuid.Nil) }()
	<-repo.appendHit
	dropped := make(chan struct{})
	go func() { hub.DropNote(v, "n", CloseNotFound, "note_deleted"); close(dropped) }()
	select {
	case <-dropped:
		t.Fatal("DropNote returned with a commit of the old history in flight")
	case <-time.After(30 * time.Millisecond):
	}
	release()
	select {
	case <-dropped:
	case <-time.After(2 * time.Second):
		t.Fatal("DropNote never returned")
	}
}

// The update log is compacted from in-memory counters: crossing the
// threshold triggers one verified compaction in the background, without
// any COUNT per keystroke.
func TestGroupCommit_CompactionFromCounters(t *testing.T) {
	repo := newGCRepo()
	hub := NewHub(crdt.NewRegistry(repo), WithMirrorDebounce(0))
	defer hub.Close()
	v := uuid.New()
	cl := newClient(t, hub, v, "n")
	defer cl.close(hub)
	for i := 0; i < crdt.CompactCountThreshold+10; i++ {
		if err := cl.room.ApplyAndBroadcast(cl.edit("k"), cl.sub, uuid.Nil); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(2 * time.Second)
	for repo.upserts.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("log never compacted")
		}
		time.Sleep(2 * time.Millisecond)
	}
	// Let the compaction finish before reading.
	cl.room.compactMu.Lock()
	cl.room.compactMu.Unlock() //nolint:staticcheck
	if c := repo.counts.Load(); c > 4 {
		t.Fatalf("%d COUNT queries for %d updates", c, crdt.CompactCountThreshold+10)
	}
	rows, _ := repo.ListUpdatesSince(context.Background(), v, "n", 0, 0)
	if len(rows) >= crdt.CompactCountThreshold {
		t.Fatalf("%d rows left after compaction", len(rows))
	}
	if got := replayLog(t, repo.memRepo, v, "n"); got != strings.Repeat("k", crdt.CompactCountThreshold+10) {
		t.Fatalf("replay after compaction: %d chars", len(got))
	}
	if n := cl.room.logCount.Load(); n >= crdt.CompactCountThreshold {
		t.Fatalf("counter not re-based after compaction: %d", n)
	}
}

// BenchmarkRoomApplyAndBroadcast is the live keystroke path (apply,
// group commit, broadcast to one other subscriber) over an in-memory
// store: CPU and allocations of the hot path, without Postgres.
func BenchmarkRoomApplyAndBroadcast(b *testing.B) {
	repo := newMemRepo()
	hub := NewHub(crdt.NewRegistry(repo), WithMirrorDebounce(0))
	defer hub.Close()
	v := uuid.New()
	writer := newClient(b, hub, v, "n")
	defer writer.close(hub)
	reader := newClient(b, hub, v, "n")
	defer reader.close(hub)
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-reader.sub.Out:
			case <-stop:
				return
			}
		}
	}()
	defer close(stop)
	updates := make([][]byte, b.N)
	for i := range updates {
		updates[i] = writer.edit("a")
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := writer.room.ApplyAndBroadcast(updates[i], writer.sub, uuid.Nil); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkGroupCommitParallel runs many writers (one per note) over a
// store with a simulated 200 µs Postgres round trip. ns/op falls as
// batches grow; appends/op reports how many round trips each update cost.
func BenchmarkGroupCommitParallel(b *testing.B) {
	repo := newGCRepo()
	repo.delay = 200 * time.Microsecond
	hub := NewHub(crdt.NewRegistry(repo), WithMirrorDebounce(0))
	defer hub.Close()
	v := uuid.New()
	var next atomic.Int64
	b.SetParallelism(8)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		cl := newClient(b, hub, v, fmt.Sprintf("n%d", next.Add(1)))
		defer cl.close(hub)
		for pb.Next() {
			if err := cl.room.ApplyAndBroadcast(cl.edit("p"), cl.sub, uuid.Nil); err != nil {
				b.Error(err)
				return
			}
		}
	})
	b.StopTimer()
	b.ReportMetric(float64(repo.batches.Load())/float64(b.N), "appends/op")
}
