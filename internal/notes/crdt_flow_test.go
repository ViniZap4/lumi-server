package notes

import (
	"context"
	"errors"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"

	"github.com/ViniZap4/lumi-server/internal/crdt"
	"github.com/ViniZap4/lumi-server/internal/domain"
	"github.com/ViniZap4/lumi-server/internal/storage/fs"
	"github.com/ViniZap4/lumi-server/internal/wsync"
)

// memYjs is an in-memory crdt.SnapshotRepo.
type memYjs struct {
	mu        sync.Mutex
	snaps     map[string][]byte
	updates   map[string][]crdt.UpdateRow
	next      int64
	upsertErr error
}

func newMemYjs() *memYjs {
	return &memYjs{snaps: map[string][]byte{}, updates: map[string][]crdt.UpdateRow{}}
}
func yk(v uuid.UUID, n string) string { return v.String() + "/" + n }
func (m *memYjs) GetSnapshot(_ context.Context, v uuid.UUID, n string) (crdt.SnapshotRow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.snaps[yk(v, n)]
	if !ok {
		return crdt.SnapshotRow{}, domain.ErrNotFound
	}
	return crdt.SnapshotRow{State: s}, nil
}
func (m *memYjs) UpsertSnapshot(_ context.Context, v uuid.UUID, n string, st []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.upsertErr != nil {
		return m.upsertErr
	}
	m.snaps[yk(v, n)] = append([]byte(nil), st...)
	return nil
}
func (m *memYjs) AppendUpdate(_ context.Context, v uuid.UUID, n string, u []byte, _ uuid.UUID, o string) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.next++
	m.updates[yk(v, n)] = append(m.updates[yk(v, n)], crdt.UpdateRow{ID: m.next, Update: u, OriginKind: o})
	return m.next, nil
}
func (m *memYjs) ListUpdatesSince(_ context.Context, v uuid.UUID, n string, since int64, _ int) ([]crdt.UpdateRow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []crdt.UpdateRow
	for _, r := range m.updates[yk(v, n)] {
		if r.ID > since {
			out = append(out, r)
		}
	}
	return out, nil
}
func (m *memYjs) CountUpdates(_ context.Context, v uuid.UUID, n string) (int, int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.updates[yk(v, n)]), 0, nil
}
func (m *memYjs) DeleteUpdatesUpTo(context.Context, uuid.UUID, string, int64) (int64, error) {
	return 0, nil
}
func (m *memYjs) HighestUpdateID(context.Context, uuid.UUID, string) (int64, error) { return 0, nil }

type crdtFixture struct {
	svc   *Service
	hub   *wsync.Hub
	reg   *crdt.Registry
	yjs   *memYjs
	fsm   *fs.Manager
	vault domain.Vault
}

func newCRDTFixture(t *testing.T) *crdtFixture {
	t.Helper()
	mgr, err := fs.NewManager(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	vault := domain.Vault{ID: uuid.New(), Slug: "v"}
	if _, err := mgr.EnsureVaultDir(vault.Slug); err != nil {
		t.Fatal(err)
	}
	yjs := newMemYjs()
	reg := crdt.NewRegistry(yjs)
	svc := NewService(&fakeNoteRepo{byVault: map[uuid.UUID][]domain.Note{}},
		&fakeVaultLookup{byID: map[uuid.UUID]domain.Vault{vault.ID: vault}},
		mgr, nil, fakeCopyResolver{}, reg, nil)
	hub := wsync.NewHub(reg, wsync.WithFSMirror(svc.WriteBodyFromCRDT), wsync.WithMirrorDebounce(20*time.Millisecond))
	t.Cleanup(hub.Close)
	svc.SetLiveDocs(hub)
	reg.SetInitSource(svc.CRDTInitBody)
	return &crdtFixture{svc: svc, hub: hub, reg: reg, yjs: yjs, fsm: mgr, vault: vault}
}

func (f *crdtFixture) diskBody(t *testing.T, n domain.Note) string {
	t.Helper()
	_, body, err := f.fsm.ReadNote(f.vault.Slug, n.Path)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

// liveEdit simulates a connected web client: edit a replica of the room's
// doc and send the update over the socket path.
func liveEdit(t *testing.T, room *wsync.Room, sub *wsync.Subscriber, newText string) {
	t.Helper()
	st, _ := room.Doc().EncodeStateAsUpdate()
	replica, err := crdt.LoadDoc(st)
	if err != nil {
		t.Fatal(err)
	}
	defer replica.Close()
	u, err := replica.ApplyTextDiff(newText, "web")
	if err != nil {
		t.Fatal(err)
	}
	if err := room.ApplyAndBroadcast(u, sub, uuid.Nil); err != nil {
		t.Fatal(err)
	}
}

func expectBroadcast(t *testing.T, sub *wsync.Subscriber) {
	t.Helper()
	select {
	case msg := <-sub.Out:
		m, err := wsync.DecodeMessage(msg)
		if err != nil || m.Type != wsync.MessageSync || m.SyncSub != wsync.SyncUpdate {
			t.Fatalf("unexpected frame %+v err=%v", m, err)
		}
	case <-time.After(time.Second):
		t.Fatal("live client did not receive the REST change")
	}
}

// S1 + S2: TUI 3-way /diff while a web client is live (vector V9b).
func TestApplyDiff_ThreeWayWhileLive(t *testing.T) {
	f := newCRDTFixture(t)
	ctx := context.Background()
	n, err := f.svc.Create(ctx, f.vault.ID, CreateInput{Title: "Note", Body: "hello world"})
	if err != nil {
		t.Fatal(err)
	}

	// TUI fetches the base.
	snap, err := f.svc.GetSnapshot(ctx, f.vault.ID, n.ID)
	if err != nil {
		t.Fatal(err)
	}
	if snap.Text != "hello world" || len(snap.State) == 0 {
		t.Fatalf("snapshot = %+v", snap)
	}

	// Web client joins and edits.
	web := f.hub.NewSubscriber(uuid.New())
	other := f.hub.NewSubscriber(uuid.New())
	room, err := f.hub.Join(ctx, f.vault.ID, n.ID, web)
	if err != nil {
		t.Fatal(err)
	}
	defer f.hub.Leave(room, web)
	if _, err := f.hub.Join(ctx, f.vault.ID, n.ID, other); err != nil {
		t.Fatal(err)
	}
	defer f.hub.Leave(room, other)
	liveEdit(t, room, web, "# hello world")
	expectBroadcast(t, other)

	// Bare text without a base is refused (no more LWW, vector V9a).
	if _, err := f.svc.ApplyDiff(ctx, f.vault.ID, n.ID, DiffInput{Text: "hello brave world"}, "tui", uuid.Nil, "", ""); !errors.Is(err, errBaseRequired) {
		t.Fatalf("no base: got %v, want errBaseRequired", err)
	}
	// A stale base_clock is refused too.
	if _, err := f.svc.ApplyDiff(ctx, f.vault.ID, n.ID, DiffInput{Text: "hello brave world", BaseClock: snap.VectorClock}, "tui", uuid.Nil, "", ""); !errors.Is(err, errBaseRequired) {
		t.Fatalf("stale clock: got %v, want errBaseRequired", err)
	}

	// 3-way merge with the base state keeps the web edit.
	res, err := f.svc.ApplyDiff(ctx, f.vault.ID, n.ID, DiffInput{Text: "hello brave world", BaseState: snap.State}, "tui", uuid.Nil, "", "")
	if err != nil {
		t.Fatal(err)
	}
	const want = "# hello brave world"
	if res.Text != want {
		t.Fatalf("merged text = %q, want %q", res.Text, want)
	}
	expectBroadcast(t, web)
	expectBroadcast(t, other)
	if txt, _ := room.Doc().Text(); txt != want {
		t.Fatalf("live room text = %q", txt)
	}
	if got := f.diskBody(t, n); got != want {
		t.Fatalf("disk body = %q, want %q", got, want)
	}
	// The room's debounced mirror must not later restore stale text.
	time.Sleep(60 * time.Millisecond)
	if got := f.diskBody(t, n); got != want {
		t.Fatalf("disk body after debounce = %q", got)
	}

	// A current base_clock is accepted (nothing concurrent happened).
	cur, _ := f.svc.GetSnapshot(ctx, f.vault.ID, n.ID)
	res, err = f.svc.ApplyDiff(ctx, f.vault.ID, n.ID, DiffInput{Text: want + "!", BaseClock: cur.VectorClock}, "tui", uuid.Nil, "", "")
	if err != nil || res.Text != want+"!" {
		t.Fatalf("current clock: res=%+v err=%v", res, err)
	}
	expectBroadcast(t, web)
}

func TestApplyDiff_ForeignBaseRejected(t *testing.T) {
	f := newCRDTFixture(t)
	ctx := context.Background()
	n, err := f.svc.Create(ctx, f.vault.ID, CreateInput{Title: "Note", Body: "abc"})
	if err != nil {
		t.Fatal(err)
	}
	foreign := crdt.NewDoc()
	defer foreign.Close()
	_, _ = foreign.ApplyTextDiff("something else", "x")
	st, _ := foreign.EncodeStateAsUpdate()
	if _, err := f.svc.ApplyDiff(ctx, f.vault.ID, n.ID, DiffInput{Text: "zzz", BaseState: st}, "tui", uuid.Nil, "", ""); !errors.Is(err, crdt.ErrBaseMismatch) {
		t.Fatalf("got %v, want ErrBaseMismatch", err)
	}
}

// S2: PATCH body and raw /diff update reach live clients and disk.
func TestPatchBodyAndUpdateWhileLive(t *testing.T) {
	f := newCRDTFixture(t)
	ctx := context.Background()
	n, err := f.svc.Create(ctx, f.vault.ID, CreateInput{Title: "Note", Body: "one"})
	if err != nil {
		t.Fatal(err)
	}
	web := f.hub.NewSubscriber(uuid.New())
	room, err := f.hub.Join(ctx, f.vault.ID, n.ID, web)
	if err != nil {
		t.Fatal(err)
	}
	defer f.hub.Leave(room, web)

	body := "two"
	if _, err := f.svc.Update(ctx, f.vault.ID, n.ID, UpdateInput{Body: &body}); err != nil {
		t.Fatal(err)
	}
	expectBroadcast(t, web)
	if txt, _ := room.Doc().Text(); txt != "two" {
		t.Fatalf("room text after PATCH = %q", txt)
	}

	st, _ := room.Doc().EncodeStateAsUpdate()
	replica, _ := crdt.LoadDoc(st)
	u, _ := replica.ApplyTextDiff("two three", "apple")
	replica.Close()
	res, err := f.svc.ApplyUpdate(ctx, f.vault.ID, n.ID, u, "apple", uuid.Nil, "", "")
	if err != nil || res.Text != "two three" {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	expectBroadcast(t, web)
	if got := f.diskBody(t, n); got != "two three" {
		t.Fatalf("disk = %q", got)
	}
}

// S4: a note with no CRDT state is seeded from disk on first use, so a
// live client joining sees the file text (not an empty doc).
func TestLazyInitForLegacyNote(t *testing.T) {
	f := newCRDTFixture(t)
	ctx := context.Background()
	n, err := f.svc.Create(ctx, f.vault.ID, CreateInput{Title: "Legacy", Body: "from disk"})
	if err != nil {
		t.Fatal(err)
	}
	// Simulate a legacy note: drop its CRDT state entirely.
	f.yjs.mu.Lock()
	delete(f.yjs.snaps, yk(f.vault.ID, n.ID))
	f.yjs.mu.Unlock()

	sub := f.hub.NewSubscriber(uuid.New())
	room, err := f.hub.Join(ctx, f.vault.ID, n.ID, sub)
	if err != nil {
		t.Fatal(err)
	}
	defer f.hub.Leave(room, sub)
	if txt, _ := room.Doc().Text(); txt != "from disk" {
		t.Fatalf("lazy-init text = %q", txt)
	}
}

func TestMapCRDTErr_Conflicts(t *testing.T) {
	app := fiber.New()
	app.Get("/:k", func(c *fiber.Ctx) error {
		switch c.Params("k") {
		case "required":
			return mapCRDTErr(c, errBaseRequired)
		case "mismatch":
			return mapCRDTErr(c, crdt.ErrBaseMismatch)
		}
		return mapCRDTErr(c, errCRDTUnavailable)
	})
	for path, want := range map[string]int{"/required": 409, "/mismatch": 409, "/x": 503} {
		resp, err := app.Test(httptest.NewRequest("GET", path, nil))
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != want {
			t.Errorf("%s: status %d, want %d", path, resp.StatusCode, want)
		}
	}
}
