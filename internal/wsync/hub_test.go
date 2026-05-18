package wsync

import (
	"bytes"
	"context"
	"sync"
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
