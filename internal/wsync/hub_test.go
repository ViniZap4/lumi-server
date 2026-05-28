package wsync

import (
	"bytes"
	"context"
	"encoding/json"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ViniZap4/lumi-server/internal/crdt"
)

// memRepo is a minimal in-memory SnapshotRepo for tests. Not safe for
// production — no isolation, mutex protects map access only.
type memRepo struct {
	mu        sync.Mutex
	snapshots map[string][]byte
	updates   map[string][]crdt.UpdateRow
	nextID    int64
}

func newMemRepo() *memRepo {
	return &memRepo{
		snapshots: map[string][]byte{},
		updates:   map[string][]crdt.UpdateRow{},
	}
}

func key(v uuid.UUID, n string) string { return v.String() + "/" + n }

func (m *memRepo) GetSnapshot(_ context.Context, v uuid.UUID, n string) (crdt.SnapshotRow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok := m.snapshots[key(v, n)]; ok {
		return crdt.SnapshotRow{State: append([]byte(nil), s...)}, nil
	}
	return crdt.SnapshotRow{}, errNotFound
}

func (m *memRepo) UpsertSnapshot(_ context.Context, v uuid.UUID, n string, state []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.snapshots[key(v, n)] = append([]byte(nil), state...)
	return nil
}

func (m *memRepo) AppendUpdate(_ context.Context, v uuid.UUID, n string, u []byte, _ uuid.UUID, origin string) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nextID++
	row := crdt.UpdateRow{ID: m.nextID, Update: append([]byte(nil), u...), OriginKind: origin}
	m.updates[key(v, n)] = append(m.updates[key(v, n)], row)
	return m.nextID, nil
}

func (m *memRepo) ListUpdatesSince(_ context.Context, v uuid.UUID, n string, since int64, limit int) ([]crdt.UpdateRow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rows := m.updates[key(v, n)]
	out := []crdt.UpdateRow{}
	for _, r := range rows {
		if r.ID > since {
			out = append(out, r)
		}
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out, nil
}

func (m *memRepo) CountUpdates(_ context.Context, v uuid.UUID, n string) (int, int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rows := m.updates[key(v, n)]
	var b int64
	for _, r := range rows {
		b += int64(len(r.Update))
	}
	return len(rows), b, nil
}

func (m *memRepo) DeleteUpdatesUpTo(_ context.Context, v uuid.UUID, n string, maxID int64) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rows := m.updates[key(v, n)]
	kept := rows[:0]
	var deleted int64
	for _, r := range rows {
		if r.ID > maxID {
			kept = append(kept, r)
		} else {
			deleted++
		}
	}
	m.updates[key(v, n)] = kept
	return deleted, nil
}

func (m *memRepo) HighestUpdateID(_ context.Context, v uuid.UUID, n string) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var max int64
	for _, r := range m.updates[key(v, n)] {
		if r.ID > max {
			max = r.ID
		}
	}
	return max, nil
}

// errNotFound matches the sentinel the registry expects. We do not
// import domain here to avoid pulling more dependencies; the registry's
// errors.Is check on ErrNotFound returns nil for the wrong type, in
// which case the registry treats it as a transient error. For these
// tests we simply route GetSnapshot misses through this same path —
// the registry then proceeds with no initial state, exactly what an
// empty repo should produce.
var errNotFound = &repoError{msg: "not found"}

type repoError struct{ msg string }

func (e *repoError) Error() string { return e.msg }

// ---- Tests -----------------------------------------------------------------

func TestRoomBroadcastsToOthers(t *testing.T) {
	repo := newMemRepo()
	reg := crdt.NewRegistry(repo)
	hub := NewHub(reg, WithIdleTTL(50*time.Millisecond))
	defer hub.Close()

	vault := uuid.New()
	note := "hello"

	subA := hub.NewSubscriber(uuid.New())
	subB := hub.NewSubscriber(uuid.New())

	roomA, err := hub.Join(context.Background(), vault, note, subA)
	if err != nil {
		t.Fatalf("Join A: %v", err)
	}
	defer hub.Leave(roomA, subA)

	roomB, err := hub.Join(context.Background(), vault, note, subB)
	if err != nil {
		t.Fatalf("Join B: %v", err)
	}
	defer hub.Leave(roomB, subB)

	if roomA != roomB {
		t.Fatalf("expected shared room, got distinct")
	}

	// A makes an edit on the shared doc via ApplyTextDiff so we have
	// a real update blob and a doc state that B should learn about.
	doc := roomA.Doc()
	update, err := doc.ApplyTextDiff("Hello from A", "test")
	if err != nil {
		t.Fatalf("ApplyTextDiff: %v", err)
	}

	// Simulate a client of A having computed `update` (above) and
	// sending it back through the hub — this is what handleMessage
	// does on receiving SyncStep2 / SyncUpdate.
	if err := roomA.ApplyAndBroadcast(update, subA, subA.UserID); err != nil {
		t.Fatalf("ApplyAndBroadcast: %v", err)
	}

	// B should see an Update frame; A should not.
	select {
	case msg := <-subB.Out:
		parsed, err := DecodeMessage(msg)
		if err != nil {
			t.Fatalf("decode B frame: %v", err)
		}
		if parsed.Type != MessageSync || parsed.SyncSub != SyncUpdate {
			t.Fatalf("B got %+v, want Sync.Update", parsed)
		}
		if !bytes.Equal(parsed.Body, update) {
			t.Fatalf("B body mismatch")
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("B did not receive broadcast")
	}

	select {
	case msg := <-subA.Out:
		t.Fatalf("A received its own broadcast: %d bytes", len(msg))
	case <-time.After(50 * time.Millisecond):
		// Expected — origin suppression works.
	}

	// The repo should now hold one persisted update.
	rows, _ := repo.ListUpdatesSince(context.Background(), vault, note, 0, 0)
	if len(rows) != 1 {
		t.Fatalf("expected 1 persisted update, got %d", len(rows))
	}
}

func TestHubCloseSignalsSubscribers(t *testing.T) {
	repo := newMemRepo()
	reg := crdt.NewRegistry(repo)
	hub := NewHub(reg)

	vault := uuid.New()
	subs := make([]*Subscriber, 0, 5)
	for i := 0; i < 5; i++ {
		s := hub.NewSubscriber(uuid.New())
		if _, err := hub.Join(context.Background(), vault, "n", s); err != nil {
			t.Fatalf("Join %d: %v", i, err)
		}
		subs = append(subs, s)
	}

	hub.Close()

	// Every subscriber's Done channel must be closed within a small
	// window; this is what allows handleConn's closer-pump to exit.
	for i, s := range subs {
		select {
		case <-s.Done:
		case <-time.After(500 * time.Millisecond):
			t.Fatalf("sub %d Done not closed after Hub.Close", i)
		}
	}
}

func TestHubCloseIdempotent(t *testing.T) {
	repo := newMemRepo()
	reg := crdt.NewRegistry(repo)
	hub := NewHub(reg)
	hub.Close()
	// Second Close must not panic / double-evict.
	hub.Close()
}

func TestHubNoGoroutineLeakAfterClose(t *testing.T) {
	// Capture baseline AFTER warm-up so we ignore the test runner's
	// own goroutines.
	before := runtime.NumGoroutine()

	for cycle := 0; cycle < 3; cycle++ {
		repo := newMemRepo()
		reg := crdt.NewRegistry(repo)
		hub := NewHub(reg, WithIdleTTL(20*time.Millisecond))

		// Spawn rooms + subs to exercise the goroutine surface
		// (time.AfterFunc idle timers in particular).
		vault := uuid.New()
		for i := 0; i < 10; i++ {
			s := hub.NewSubscriber(uuid.New())
			room, err := hub.Join(context.Background(), vault, "n"+string(rune('0'+i)), s)
			if err != nil {
				t.Fatalf("Join: %v", err)
			}
			// Cause one of them to schedule an idle timer.
			hub.Leave(room, s)
		}
		hub.Close()
	}

	// Allow finalizers + system goroutines to settle.
	for i := 0; i < 20; i++ {
		if runtime.NumGoroutine() <= before+2 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	after := runtime.NumGoroutine()
	if after > before+2 {
		t.Fatalf("goroutine leak: before=%d after=%d", before, after)
	}
}

func TestRoomEvictsAfterIdle(t *testing.T) {
	repo := newMemRepo()
	reg := crdt.NewRegistry(repo)
	hub := NewHub(reg, WithIdleTTL(30*time.Millisecond))
	defer hub.Close()

	vault := uuid.New()
	note := "ephemeral"
	sub := hub.NewSubscriber(uuid.New())
	room, err := hub.Join(context.Background(), vault, note, sub)
	if err != nil {
		t.Fatalf("Join: %v", err)
	}
	hub.Leave(room, sub)

	// Wait past idle TTL.
	time.Sleep(120 * time.Millisecond)

	hub.mu.Lock()
	_, present := hub.rooms[roomKey(vault, note)]
	hub.mu.Unlock()
	if present {
		t.Fatalf("room not evicted after idle TTL")
	}
}

func TestUserSlotCapEnforced(t *testing.T) {
	repo := newMemRepo()
	reg := crdt.NewRegistry(repo)
	hub := NewHub(reg, WithMaxUserConnections(3))
	defer hub.Close()

	user := uuid.New()
	for i := 0; i < 3; i++ {
		if !hub.TryAcquireUserSlot(user) {
			t.Fatalf("acquire %d rejected unexpectedly", i)
		}
	}
	if hub.TryAcquireUserSlot(user) {
		t.Fatalf("acquire #4 should have been refused")
	}
	if got := hub.UserConnections(user); got != 3 {
		t.Fatalf("UserConnections = %d, want 3", got)
	}
	hub.ReleaseUserSlot(user)
	if !hub.TryAcquireUserSlot(user) {
		t.Fatalf("acquire after release should succeed")
	}
}

func TestUserSlotZeroUUIDBypass(t *testing.T) {
	repo := newMemRepo()
	reg := crdt.NewRegistry(repo)
	hub := NewHub(reg, WithMaxUserConnections(1))
	defer hub.Close()

	// Nil uuid means "auth didn't thread a user id"; we bypass the
	// cap rather than misclassify legitimate-but-unidentified callers
	// (the auth gate runs upstream and would have rejected an
	// anonymous request before reaching us).
	for i := 0; i < 100; i++ {
		if !hub.TryAcquireUserSlot(uuid.Nil) {
			t.Fatalf("nil uuid acquire %d rejected", i)
		}
	}
	if got := hub.UserConnections(uuid.Nil); got != 0 {
		t.Fatalf("UserConnections for nil = %d, want 0 (not counted)", got)
	}
}

func TestUserSlotIsolatedPerUser(t *testing.T) {
	repo := newMemRepo()
	reg := crdt.NewRegistry(repo)
	hub := NewHub(reg, WithMaxUserConnections(2))
	defer hub.Close()

	a := uuid.New()
	b := uuid.New()
	hub.TryAcquireUserSlot(a)
	hub.TryAcquireUserSlot(a)
	if hub.TryAcquireUserSlot(a) {
		t.Fatalf("user A should be at cap")
	}
	if !hub.TryAcquireUserSlot(b) {
		t.Fatalf("user B has its own quota")
	}
}

func TestFSMirrorFiresAfterDebounce(t *testing.T) {
	repo := newMemRepo()
	reg := crdt.NewRegistry(repo)

	type mirrorCall struct {
		vault uuid.UUID
		note  string
		text  string
	}
	var (
		mu    sync.Mutex
		calls []mirrorCall
	)
	mirror := func(_ context.Context, v uuid.UUID, n, text string) error {
		mu.Lock()
		calls = append(calls, mirrorCall{v, n, text})
		mu.Unlock()
		return nil
	}

	hub := NewHub(
		reg,
		WithFSMirror(mirror),
		WithMirrorDebounce(40*time.Millisecond),
	)
	defer hub.Close()

	vault := uuid.New()
	note := "mirror-test"
	sub := hub.NewSubscriber(uuid.New())
	room, err := hub.Join(context.Background(), vault, note, sub)
	if err != nil {
		t.Fatal(err)
	}
	defer hub.Leave(room, sub)

	// First edit.
	u1, _ := room.Doc().ApplyTextDiff("hello", "test")
	if err := room.ApplyAndBroadcast(u1, sub, sub.UserID); err != nil {
		t.Fatal(err)
	}

	// Second edit inside the debounce window must coalesce.
	time.Sleep(15 * time.Millisecond)
	u2, _ := room.Doc().ApplyTextDiff("hello world", "test")
	if err := room.ApplyAndBroadcast(u2, sub, sub.UserID); err != nil {
		t.Fatal(err)
	}

	// Wait past the second debounce.
	time.Sleep(120 * time.Millisecond)

	mu.Lock()
	got := append([]mirrorCall(nil), calls...)
	mu.Unlock()
	if len(got) != 1 {
		t.Fatalf("expected 1 coalesced mirror call, got %d: %+v", len(got), got)
	}
	if got[0].text != "hello world" {
		t.Fatalf("expected final text 'hello world', got %q", got[0].text)
	}
}

func TestFSMirrorSkipsFSWatcherOrigin(t *testing.T) {
	repo := newMemRepo()
	reg := crdt.NewRegistry(repo)
	var calls atomic.Int64
	mirror := func(_ context.Context, _ uuid.UUID, _, _ string) error {
		calls.Add(1)
		return nil
	}
	hub := NewHub(
		reg,
		WithFSMirror(mirror),
		WithMirrorDebounce(20*time.Millisecond),
	)
	defer hub.Close()

	vault := uuid.New()
	note := "fs-origin"
	sub := hub.NewSubscriber(uuid.New())
	room, err := hub.Join(context.Background(), vault, note, sub)
	if err != nil {
		t.Fatal(err)
	}
	defer hub.Leave(room, sub)

	u, _ := room.Doc().ApplyTextDiff("external edit", "test")
	if err := room.ApplyAndBroadcastFromFS(u); err != nil {
		t.Fatal(err)
	}
	time.Sleep(80 * time.Millisecond)

	if calls.Load() != 0 {
		t.Fatalf("FS-origin update should not trigger mirror; got %d calls", calls.Load())
	}
}

func TestRoomAwarenessRelay(t *testing.T) {
	repo := newMemRepo()
	reg := crdt.NewRegistry(repo)
	hub := NewHub(reg)
	defer hub.Close()

	vault := uuid.New()
	note := "presence"
	subA := hub.NewSubscriber(uuid.New())
	subB := hub.NewSubscriber(uuid.New())

	room, err := hub.Join(context.Background(), vault, note, subA)
	if err != nil {
		t.Fatalf("Join A: %v", err)
	}
	defer hub.Leave(room, subA)
	if _, err := hub.Join(context.Background(), vault, note, subB); err != nil {
		t.Fatalf("Join B: %v", err)
	}
	defer hub.Leave(room, subB)

	awareness := []byte("client=42; cursor=10")
	room.BroadcastAwareness(awareness, subA)

	select {
	case msg := <-subB.Out:
		parsed, err := DecodeMessage(msg)
		if err != nil {
			t.Fatalf("decode awareness: %v", err)
		}
		if parsed.Type != MessageAwareness {
			t.Fatalf("got type %d, want awareness", parsed.Type)
		}
		if !bytes.Equal(parsed.Body, awareness) {
			t.Fatalf("body mismatch")
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatalf("B did not receive awareness relay")
	}

	// A should not echo.
	select {
	case <-subA.Out:
		t.Fatalf("A got its own awareness back")
	case <-time.After(30 * time.Millisecond):
	}
}

// TestLeaveBroadcastsPresenceLeaveFrame verifies that when a subscriber
// with a non-nil ClientID departs, remaining subscribers receive a
// synthetic awareness frame carrying `{client_id, left: true}`. Without
// this, peers would only drop the departing presence after the
// client-side TTL elapses. Post-H follow-up.
func TestLeaveBroadcastsPresenceLeaveFrame(t *testing.T) {
	repo := newMemRepo()
	reg := crdt.NewRegistry(repo)
	hub := NewHub(reg)
	defer hub.Close()

	vault := uuid.New()
	note := "presence-leave"

	leaverClient := uuid.New()
	leaver := hub.NewSubscriberWithClient(uuid.New(), leaverClient)
	observer := hub.NewSubscriber(uuid.New())

	room, err := hub.Join(context.Background(), vault, note, leaver)
	if err != nil {
		t.Fatalf("Join leaver: %v", err)
	}
	if _, err := hub.Join(context.Background(), vault, note, observer); err != nil {
		t.Fatalf("Join observer: %v", err)
	}
	defer hub.Leave(room, observer)

	hub.Leave(room, leaver)

	select {
	case msg := <-observer.Out:
		parsed, err := DecodeMessage(msg)
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		if parsed.Type != MessageAwareness {
			t.Fatalf("got type %d, want awareness", parsed.Type)
		}
		var got struct {
			ClientID    string `json:"client_id"`
			Username    string `json:"username"`
			DisplayName string `json:"display_name"`
			Color       string `json:"color"`
			Left        bool   `json:"left"`
		}
		if err := json.Unmarshal(parsed.Body, &got); err != nil {
			t.Fatalf("decode body json: %v", err)
		}
		if got.ClientID != leaverClient.String() {
			t.Fatalf("leave-frame client_id = %q, want %q", got.ClientID, leaverClient.String())
		}
		if !got.Left {
			t.Fatalf("leave-frame left = false, want true")
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatalf("observer did not receive leave frame")
	}
}

// TestLeaveSkipsPresenceLeaveFrameForNilClientID confirms that a sub
// without a declared presence identity does NOT trigger a leave frame —
// the wire would carry uuid.Nil and peers can't match it to anything
// useful.
func TestLeaveSkipsPresenceLeaveFrameForNilClientID(t *testing.T) {
	repo := newMemRepo()
	reg := crdt.NewRegistry(repo)
	hub := NewHub(reg)
	defer hub.Close()

	vault := uuid.New()
	note := "anon-leave"

	leaver := hub.NewSubscriber(uuid.New())     // no ClientID
	observer := hub.NewSubscriber(uuid.New())

	room, err := hub.Join(context.Background(), vault, note, leaver)
	if err != nil {
		t.Fatalf("Join leaver: %v", err)
	}
	if _, err := hub.Join(context.Background(), vault, note, observer); err != nil {
		t.Fatalf("Join observer: %v", err)
	}
	defer hub.Leave(room, observer)

	hub.Leave(room, leaver)

	select {
	case msg := <-observer.Out:
		t.Fatalf("observer unexpectedly got a frame: %v", msg)
	case <-time.After(50 * time.Millisecond):
		// good — no broadcast
	}
}

// TestLeavePresenceLeaveFrameSuppressedWhenLastSub covers the edge case
// where the leaving sub is the last in the room. There's no one to
// notify, so the path must short-circuit without panic/deadlock.
func TestLeavePresenceLeaveFrameSuppressedWhenLastSub(t *testing.T) {
	repo := newMemRepo()
	reg := crdt.NewRegistry(repo)
	hub := NewHub(reg)
	defer hub.Close()

	vault := uuid.New()
	note := "only-me"
	leaver := hub.NewSubscriberWithClient(uuid.New(), uuid.New())
	room, err := hub.Join(context.Background(), vault, note, leaver)
	if err != nil {
		t.Fatalf("Join: %v", err)
	}
	// Single sub leaving — must not deadlock or attempt to broadcast.
	hub.Leave(room, leaver)
}
