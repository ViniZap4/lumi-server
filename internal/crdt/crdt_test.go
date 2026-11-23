package crdt

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/ViniZap4/lumi-server/internal/domain"
)

// ---- helpers -----------------------------------------------------------------

func mustDocFromText(t *testing.T, text string) *Doc {
	t.Helper()
	d := NewDoc()
	if text != "" {
		if _, err := d.ApplyTextDiff(text, "test"); err != nil {
			t.Fatal(err)
		}
	}
	return d
}

func mustText(t *testing.T, d *Doc) string {
	t.Helper()
	s, err := d.Text()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func mustState(t *testing.T, d *Doc) []byte {
	t.Helper()
	s, err := d.EncodeStateAsUpdate()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func fork(t *testing.T, d *Doc) *Doc {
	t.Helper()
	f, err := LoadDoc(mustState(t, d))
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// ---- S3: no-op detection -----------------------------------------------------

func TestApplyUpdateChanged_EmptyUpdateIsNoop(t *testing.T) {
	d := mustDocFromText(t, "hello world")
	defer d.Close()
	for _, u := range [][]byte{nil, {}, {0, 0}} {
		changed, err := d.ApplyUpdateChanged(u)
		if err != nil || changed {
			t.Fatalf("update %v: changed=%v err=%v, want no-op", u, changed, err)
		}
	}
}

func TestApplyUpdateChanged_ReplayIsNoop(t *testing.T) { // V13
	server := mustDocFromText(t, "hello world")
	defer server.Close()
	client := fork(t, server)
	defer client.Close()
	upd, err := client.ApplyTextDiff("xhello world", "c")
	if err != nil {
		t.Fatal(err)
	}
	changed, err := server.ApplyUpdateChanged(upd)
	if err != nil || !changed {
		t.Fatalf("first apply: changed=%v err=%v", changed, err)
	}
	changed, err = server.ApplyUpdateChanged(upd)
	if err != nil || changed {
		t.Fatalf("replay: changed=%v err=%v, want no-op", changed, err)
	}
	if got := mustText(t, server); got != "xhello world" {
		t.Fatalf("text = %q", got)
	}
}

func TestApplyUpdateChanged_DeleteOnlyIsChange(t *testing.T) {
	server := mustDocFromText(t, "hello world")
	defer server.Close()
	client := fork(t, server)
	defer client.Close()
	upd, err := client.ApplyTextDiff("hello", "c")
	if err != nil {
		t.Fatal(err)
	}
	changed, err := server.ApplyUpdateChanged(upd)
	if err != nil || !changed {
		t.Fatalf("delete-only update: changed=%v err=%v, want changed", changed, err)
	}
}

func TestApplyUpdateChanged_FullStateOfSameDocIsNoop(t *testing.T) {
	// A reconnecting, already-synced client may send its whole state.
	server := mustDocFromText(t, "hello world")
	defer server.Close()
	changed, err := server.ApplyUpdateChanged(mustState(t, server))
	if err != nil || changed {
		t.Fatalf("changed=%v err=%v, want no-op", changed, err)
	}
}

func TestApplyUpdateChanged_PendingUpdateCountsAsChange(t *testing.T) {
	base := mustDocFromText(t, "hello")
	defer base.Close()
	a := fork(t, base)
	defer a.Close()
	u1, _ := a.ApplyTextDiff("hello1", "a")
	u2, _ := a.ApplyTextDiff("hello12", "a")
	_ = u1
	server := fork(t, base)
	defer server.Close()
	// u2 depends on u1, which the server has not seen yet.
	changed, err := server.ApplyUpdateChanged(u2)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("pending update must be reported as changed so it is persisted")
	}
	if p, _ := server.HasPending(); !p {
		t.Fatal("expected pending state")
	}
}

// ---- state vectors -------------------------------------------------------------

func TestDecodeStateVector(t *testing.T) {
	d := mustDocFromText(t, "abc")
	defer d.Close()
	raw, err := d.StateVectorV1()
	if err != nil {
		t.Fatal(err)
	}
	sv, err := DecodeStateVector(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(sv) != 1 {
		t.Fatalf("sv = %v, want one client", sv)
	}
	for _, clk := range sv {
		if clk != 3 {
			t.Fatalf("clock = %d, want 3", clk)
		}
	}
	if empty, err := DecodeStateVector([]byte{0}); err != nil || len(empty) != 0 {
		t.Fatalf("empty sv: %v %v", empty, err)
	}
	if _, err := DecodeStateVector([]byte{1, 0x80}); err == nil {
		t.Fatal("truncated sv must fail")
	}
	if _, err := DecodeStateVector([]byte{0, 9}); err == nil {
		t.Fatal("trailing bytes must fail")
	}
	a := StateVector{1: 3, 2: 5}
	if !a.Covers(StateVector{1: 3}) || a.Covers(StateVector{1: 4}) || !a.Equal(StateVector{2: 5, 1: 3}) {
		t.Fatal("Covers/Equal semantics")
	}
}

// ---- S1: 3-way merge vectors (CRDT-CLIENT-PROTOCOL §9) -------------------------

// setupV9 returns server doc after web inserted "# ", plus the TUI's base state.
func setupV9(t *testing.T, webEdit string) (*Doc, []byte) {
	t.Helper()
	server := mustDocFromText(t, "hello world")
	base := mustState(t, server) // what the TUI fetched from /snapshot
	web := fork(t, server)
	defer web.Close()
	upd, err := web.ApplyTextDiff(webEdit, "web")
	if err != nil {
		t.Fatal(err)
	}
	if err := server.ApplyUpdate(upd); err != nil {
		t.Fatal(err)
	}
	return server, base
}

func TestVector_V9a_DiffAgainstCurrentIsLWW(t *testing.T) {
	server, _ := setupV9(t, "# hello world")
	defer server.Close()
	if _, err := server.ApplyTextDiff("hello brave world", "tui"); err != nil {
		t.Fatal(err)
	}
	if got := mustText(t, server); got != "hello brave world" {
		t.Fatalf("V9a: got %q (documents the LWW hazard the 409 now prevents)", got)
	}
}

func TestVector_V9b_ThreeWayPreservesConcurrentEdit(t *testing.T) {
	server, base := setupV9(t, "# hello world")
	defer server.Close()
	res, err := ThreeWayUpdate(base, "hello brave world")
	if err != nil {
		t.Fatal(err)
	}
	if res.BaseText != "hello world" {
		t.Fatalf("base text = %q", res.BaseText)
	}
	if err := server.ApplyUpdate(res.Update); err != nil {
		t.Fatal(err)
	}
	if got := mustText(t, server); got != "# hello brave world" {
		t.Fatalf("V9b: got %q, want %q", got, "# hello brave world")
	}
}

func TestVector_V10_ConcurrentInsertInsideDeletionSurvives(t *testing.T) {
	server, base := setupV9(t, "hello woXrld")
	defer server.Close()
	res, err := ThreeWayUpdate(base, "hello")
	if err != nil {
		t.Fatal(err)
	}
	if err := server.ApplyUpdate(res.Update); err != nil {
		t.Fatal(err)
	}
	if got := mustText(t, server); got != "helloX" {
		t.Fatalf("V10: got %q, want %q", got, "helloX")
	}
}

func TestThreeWay_IncompleteBaseRejected(t *testing.T) {
	base := mustDocFromText(t, "hello")
	defer base.Close()
	a := fork(t, base)
	defer a.Close()
	_, _ = a.ApplyTextDiff("hello1", "a")
	u2, _ := a.ApplyTextDiff("hello12", "a") // depends on unseen ops
	if _, err := ThreeWayUpdate(u2, "x"); !errors.Is(err, ErrBaseMismatch) {
		t.Fatalf("got %v, want ErrBaseMismatch", err)
	}
}

// ---- S4: lazy init -------------------------------------------------------------

type memStore struct {
	mu        sync.Mutex
	snaps     map[string][]byte
	updates   map[string][]UpdateRow
	nextID    int64
	snapErr   error
	upserts   int
	appendLog []string
	epochs    map[string]string
	seq       int64
}

func newMemStore() *memStore {
	return &memStore{snaps: map[string][]byte{}, updates: map[string][]UpdateRow{}}
}

func mk(v uuid.UUID, n string) string { return v.String() + "/" + n }

func (m *memStore) GetSnapshot(_ context.Context, v uuid.UUID, n string) (SnapshotRow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.snapErr != nil {
		return SnapshotRow{}, m.snapErr
	}
	s, ok := m.snaps[mk(v, n)]
	if !ok {
		return SnapshotRow{}, domain.ErrNotFound
	}
	return SnapshotRow{State: s}, nil
}
func (m *memStore) UpsertSnapshot(_ context.Context, v uuid.UUID, n string, state []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.upserts++
	m.snaps[mk(v, n)] = append([]byte(nil), state...)
	return nil
}
func (m *memStore) SeedSnapshot(_ context.Context, v uuid.UUID, n string, state []byte, epoch string) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.upserts++
	m.snaps[mk(v, n)] = append([]byte(nil), state...)
	delete(m.updates, mk(v, n))
	if m.epochs == nil {
		m.epochs = map[string]string{}
	}
	if m.epochs[mk(v, n)] == epoch {
		return 0, nil
	}
	m.epochs[mk(v, n)] = epoch
	m.seq++
	return m.seq, nil
}
func (m *memStore) AppendUpdate(_ context.Context, v uuid.UUID, n string, u []byte, _ uuid.UUID, origin string) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nextID++
	m.updates[mk(v, n)] = append(m.updates[mk(v, n)], UpdateRow{ID: m.nextID, Update: u, OriginKind: origin})
	m.appendLog = append(m.appendLog, origin)
	return m.nextID, nil
}
func (m *memStore) ListUpdatesSince(_ context.Context, v uuid.UUID, n string, since int64, _ int) ([]UpdateRow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []UpdateRow
	for _, r := range m.updates[mk(v, n)] {
		if r.ID > since {
			out = append(out, r)
		}
	}
	return out, nil
}
func (m *memStore) CountUpdates(_ context.Context, v uuid.UUID, n string) (int, int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.updates[mk(v, n)]), 0, nil
}
func (m *memStore) DeleteUpdatesUpTo(context.Context, uuid.UUID, string, int64) (int64, error) {
	return 0, nil
}
func (m *memStore) HighestUpdateID(context.Context, uuid.UUID, string) (int64, error) { return 0, nil }

func TestLoadDoc_LazyInitFromDiskOnce(t *testing.T) {
	store := newMemStore()
	reg := NewRegistry(store)
	var calls int
	var mu sync.Mutex
	reg.SetInitSource(func(context.Context, uuid.UUID, string) (string, error) {
		mu.Lock()
		calls++
		mu.Unlock()
		return "legacy body", nil
	})
	v := uuid.New()

	var wg sync.WaitGroup
	texts := make([]string, 8)
	for i := range texts {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			d, err := reg.LoadDoc(context.Background(), v, "n")
			if err != nil {
				t.Error(err)
				return
			}
			defer d.Close()
			texts[i], _ = d.Text()
		}(i)
	}
	wg.Wait()
	for i, s := range texts {
		if s != "legacy body" {
			t.Fatalf("loader %d saw %q (duplicate seeding?)", i, s)
		}
	}
	if calls != 1 || store.upserts != 1 {
		t.Fatalf("seeded %d times (source calls %d), want exactly once", store.upserts, calls)
	}
}

func TestLoadDoc_LazyInitSkipsEmptyBody(t *testing.T) {
	store := newMemStore()
	reg := NewRegistry(store)
	reg.SetInitSource(func(context.Context, uuid.UUID, string) (string, error) { return "", nil })
	d, err := reg.LoadDoc(context.Background(), uuid.New(), "n")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if store.upserts != 0 {
		t.Fatal("empty body must not create a snapshot")
	}
}

func TestLoadDoc_StorageErrorDoesNotSeed(t *testing.T) {
	store := newMemStore()
	store.snapErr = errors.New("connection refused")
	reg := NewRegistry(store)
	reg.SetInitSource(func(context.Context, uuid.UUID, string) (string, error) {
		t.Fatal("init source must not be consulted on storage errors")
		return "", nil
	})
	if _, err := reg.LoadDoc(context.Background(), uuid.New(), "n"); err == nil {
		t.Fatal("want error on snapshot read failure")
	}
}
