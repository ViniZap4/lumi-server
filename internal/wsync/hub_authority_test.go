package wsync

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ViniZap4/lumi-server/internal/crdt"
)

type mirrorRec struct {
	mu    sync.Mutex
	texts []string
}

func (m *mirrorRec) fn(_ context.Context, _ uuid.UUID, _ string, text string) error {
	m.mu.Lock()
	m.texts = append(m.texts, text)
	m.mu.Unlock()
	return nil
}

func (m *mirrorRec) last() (string, int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.texts) == 0 {
		return "", 0
	}
	return m.texts[len(m.texts)-1], len(m.texts)
}

func seedNote(t *testing.T, reg *crdt.Registry, v uuid.UUID, note, body string) {
	t.Helper()
	if err := reg.InitFromText(context.Background(), v, note, body, uuid.Nil, "snapshot-init"); err != nil {
		t.Fatal(err)
	}
}

func recvUpdate(t *testing.T, sub *Subscriber) []byte {
	t.Helper()
	select {
	case msg := <-sub.Out:
		m, err := DecodeMessage(msg)
		if err != nil {
			t.Fatal(err)
		}
		if m.Type != MessageSync || m.SyncSub != SyncUpdate {
			t.Fatalf("got %+v, want sync update", m)
		}
		return m.Body
	case <-time.After(time.Second):
		t.Fatal("live subscriber did not receive the update")
	}
	return nil
}

// S2: a REST write while a live room is open must go through the room's
// doc: the live client receives it, it is persisted once, and the mirror
// writes the merged text (not the stale room text).
func TestREST_ApplyTextWhileRoomLive(t *testing.T) {
	repo := newMemRepo()
	reg := crdt.NewRegistry(repo)
	mir := &mirrorRec{}
	hub := NewHub(reg, WithFSMirror(mir.fn), WithMirrorDebounce(30*time.Millisecond))
	defer hub.Close()
	v, note := uuid.New(), "n"
	seedNote(t, reg, v, note, "hello world")

	sub := hub.NewSubscriber(uuid.New())
	room, err := hub.Join(context.Background(), v, note, sub)
	if err != nil {
		t.Fatal(err)
	}
	defer hub.Leave(room, sub)

	// A live client edit lands first and schedules the debounced mirror.
	if err := room.ApplyAndBroadcast(clientUpdate(t, room, "# hello world"), nil, uuid.Nil); err != nil {
		t.Fatal(err)
	}
	_ = recvUpdate(t, sub)

	// REST write (e.g. PATCH body / sv-matching /diff) with a sync mirror.
	res, err := hub.ApplyText(context.Background(), v, note, "# hello brave world", nil,
		ApplyOptions{Origin: "tui", Mirror: MirrorNow, WantText: true})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Changed || res.Text != "# hello brave world" {
		t.Fatalf("result = %+v", res)
	}
	upd := recvUpdate(t, sub)

	// The live client's replica converges by applying what it received.
	if txt, _ := room.Doc().Text(); txt != "# hello brave world" {
		t.Fatalf("room doc = %q", txt)
	}
	replica := crdt.NewDoc()
	defer replica.Close()
	state, _ := reg.LoadDoc(context.Background(), v, note)
	defer state.Close()
	full, _ := state.EncodeStateAsUpdate()
	_ = replica.ApplyUpdate(full)
	_ = replica.ApplyUpdate(upd)
	if txt, _ := replica.Text(); txt != "# hello brave world" {
		t.Fatalf("persisted state = %q", txt)
	}

	if txt, _ := mir.last(); txt != "# hello brave world" {
		t.Fatalf("sync mirror wrote %q", txt)
	}
	// The pending debounced mirror was superseded; any later write must
	// still be the merged text, never the stale "# hello world".
	time.Sleep(80 * time.Millisecond)
	if txt, _ := mir.last(); txt != "# hello brave world" {
		t.Fatalf("later mirror wrote stale %q", txt)
	}
	rows, _ := repo.ListUpdatesSince(context.Background(), v, note, 0, 0)
	if len(rows) != 2 {
		t.Fatalf("persisted %d rows, want 2 (live + REST)", len(rows))
	}
}

func TestREST_ApplyUpdateWhileRoomLive(t *testing.T) {
	repo := newMemRepo()
	reg := crdt.NewRegistry(repo)
	hub := NewHub(reg)
	defer hub.Close()
	v, note := uuid.New(), "n"
	seedNote(t, reg, v, note, "hello")

	sub := hub.NewSubscriber(uuid.New())
	room, err := hub.Join(context.Background(), v, note, sub)
	if err != nil {
		t.Fatal(err)
	}
	defer hub.Leave(room, sub)

	u := clientUpdate(t, room, "hello apple")
	res, err := hub.ApplyUpdate(context.Background(), v, note, u, ApplyOptions{Origin: "apple-diff", Mirror: MirrorNow, WantText: true})
	if err != nil || !res.Changed || res.Text != "hello apple" {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	_ = recvUpdate(t, sub)

	// Replaying the same update is a no-op: no row, no broadcast.
	res, err = hub.ApplyUpdate(context.Background(), v, note, u, ApplyOptions{Origin: "apple-diff"})
	if err != nil || res.Changed {
		t.Fatalf("replay res=%+v err=%v", res, err)
	}
	select {
	case <-sub.Out:
		t.Fatal("no-op replay was broadcast")
	case <-time.After(30 * time.Millisecond):
	}
	rows, _ := repo.ListUpdatesSince(context.Background(), v, note, 0, 0)
	if len(rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(rows))
	}
}

// S3 / vector V17: the [0,0] SyncStep2 every up-to-date client sends on
// connect must not add a log row, fire the persist hook or mirror.
func TestEmptyStep2IsNotPersisted(t *testing.T) {
	repo := newMemRepo()
	reg := crdt.NewRegistry(repo)
	var hooks int
	reg.SetOnPersist(func(uuid.UUID, string, []byte, string) { hooks++ })
	mir := &mirrorRec{}
	hub := NewHub(reg, WithFSMirror(mir.fn), WithMirrorDebounce(10*time.Millisecond))
	defer hub.Close()
	v, note := uuid.New(), "n"
	seedNote(t, reg, v, note, "hello")

	a, b := hub.NewSubscriber(uuid.New()), hub.NewSubscriber(uuid.New())
	room, _ := hub.Join(context.Background(), v, note, a)
	defer hub.Leave(room, a)
	_, _ = hub.Join(context.Background(), v, note, b)
	defer hub.Leave(room, b)

	full, _ := room.Doc().EncodeStateAsUpdate()
	for _, u := range [][]byte{{0, 0}, full} {
		if err := room.ApplyAndBroadcast(u, a, uuid.Nil); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(40 * time.Millisecond)
	rows, _ := repo.ListUpdatesSince(context.Background(), v, note, 0, 0)
	if len(rows) != 0 || hooks != 0 {
		t.Fatalf("rows=%d hooks=%d, want 0/0", len(rows), hooks)
	}
	if _, n := mir.last(); n != 0 {
		t.Fatalf("mirror ran %d times for no-op updates", n)
	}
	select {
	case <-b.Out:
		t.Fatal("no-op update was broadcast")
	default:
	}
}

// A transient (REST) holder must not pin the doc in memory.
func TestTransientRoomIsEvictedAfterWrite(t *testing.T) {
	reg := crdt.NewRegistry(newMemRepo())
	hub := NewHub(reg)
	defer hub.Close()
	v := uuid.New()
	seedNote(t, reg, v, "n", "a")
	if _, err := hub.ApplyText(context.Background(), v, "n", "ab", nil, ApplyOptions{Origin: "tui"}); err != nil {
		t.Fatal(err)
	}
	if hub.RoomIfActive(v, "n") != nil {
		t.Fatal("transient room still registered")
	}
	// The change is durable: a fresh load sees it.
	d, _ := reg.LoadDoc(context.Background(), v, "n")
	defer d.Close()
	if txt, _ := d.Text(); txt != "ab" {
		t.Fatalf("reloaded text = %q", txt)
	}
}

func TestApplyText_BaseMismatchIsAtomic(t *testing.T) {
	reg := crdt.NewRegistry(newMemRepo())
	hub := NewHub(reg)
	defer hub.Close()
	v := uuid.New()
	seedNote(t, reg, v, "n", "hello")
	var sv []byte
	_ = hub.View(context.Background(), v, "n", func(d *crdt.Doc) error {
		sv, _ = d.StateVectorV1()
		return nil
	})
	if _, err := hub.ApplyText(context.Background(), v, "n", "hello!", sv, ApplyOptions{Origin: "tui"}); err != nil {
		t.Fatalf("matching base: %v", err)
	}
	// sv is now stale.
	if _, err := hub.ApplyText(context.Background(), v, "n", "bye", sv, ApplyOptions{Origin: "tui"}); !errors.Is(err, crdt.ErrBaseMismatch) {
		t.Fatalf("stale base: got %v, want ErrBaseMismatch", err)
	}
	_ = hub.View(context.Background(), v, "n", func(d *crdt.Doc) error {
		if txt, _ := d.Text(); txt != "hello!" {
			t.Fatalf("text = %q after rejected write", txt)
		}
		return nil
	})
}

// Concurrent first users of a note must share one doc (one LoadDoc).
func TestConcurrentAcquireSharesOneRoom(t *testing.T) {
	reg := crdt.NewRegistry(newMemRepo())
	hub := NewHub(reg)
	defer hub.Close()
	v := uuid.New()
	seedNote(t, reg, v, "n", "x")
	sub := hub.NewSubscriber(uuid.New())
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if i == 0 {
				r, err := hub.Join(context.Background(), v, "n", sub)
				if err == nil {
					_ = r
				}
				return
			}
			_, _ = hub.ApplyText(context.Background(), v, "n", "x", nil, ApplyOptions{Origin: "tui"})
		}(i)
	}
	wg.Wait()
	room := hub.RoomIfActive(v, "n")
	if room == nil {
		t.Fatal("live room missing")
	}
	hub.Leave(room, sub)
}

// Eviction flushes a pending debounced mirror instead of dropping it.
func TestEvictionFlushesPendingMirror(t *testing.T) {
	reg := crdt.NewRegistry(newMemRepo())
	mir := &mirrorRec{}
	hub := NewHub(reg, WithFSMirror(mir.fn), WithMirrorDebounce(time.Hour))
	v := uuid.New()
	seedNote(t, reg, v, "n", "a")
	sub := hub.NewSubscriber(uuid.New())
	room, _ := hub.Join(context.Background(), v, "n", sub)
	if err := room.ApplyAndBroadcast(clientUpdate(t, room, "ab"), sub, uuid.Nil); err != nil {
		t.Fatal(err)
	}
	hub.Close()
	if txt, n := mir.last(); n != 1 || txt != "ab" {
		t.Fatalf("mirror on close: %q (%d calls)", txt, n)
	}
}
