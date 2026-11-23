package crdt

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

func (m *memStore) epochOf(v uuid.UUID, n string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.epochs[mk(v, n)]
}

type epochEvent struct {
	note, epoch string
	seq         int64
}

// InitFromTextEpoch stamps the caller's epoch (no rotation when the row
// already holds it); InitFromText mints a fresh one.
func TestInitFromTextEpoch_StampsEpoch(t *testing.T) {
	store := newMemStore()
	reg := NewRegistry(store)
	ctx := context.Background()
	v := uuid.New()

	got, err := reg.InitFromTextEpoch(ctx, v, "a", "hello", "epoch-a", uuid.Nil, "snapshot-init")
	if err != nil || got != "epoch-a" || store.epochOf(v, "a") != "epoch-a" {
		t.Fatalf("got %q err %v stored %q", got, err, store.epochOf(v, "a"))
	}
	if err := reg.InitFromText(ctx, v, "b", "hi", uuid.Nil, "snapshot-init"); err != nil {
		t.Fatal(err)
	}
	if e := store.epochOf(v, "b"); len(e) != 32 || e == "epoch-a" {
		t.Fatalf("fresh epoch = %q", e)
	}
}

// Seeding is exactly-once per history: a second init on a note that
// already has state (e.g. a concurrent lazy init won the race) neither
// replaces the state nor rotates the epoch.
func TestInitFromTextEpoch_NoReseedOfExistingHistory(t *testing.T) {
	store := newMemStore()
	reg := NewRegistry(store)
	ctx := context.Background()
	v := uuid.New()
	if _, err := reg.InitFromTextEpoch(ctx, v, "n", "first", "e1", uuid.Nil, "snapshot-init"); err != nil {
		t.Fatal(err)
	}
	got, err := reg.InitFromTextEpoch(ctx, v, "n", "second", "e2", uuid.Nil, "snapshot-init")
	if err != nil || got != "" {
		t.Fatalf("reseed: got %q err %v, want no-op", got, err)
	}
	d, err := reg.LoadDoc(ctx, v, "n")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if txt, _ := d.Text(); txt != "first" || store.epochOf(v, "n") != "e1" {
		t.Fatalf("text %q epoch %q, want first/e1", txt, store.epochOf(v, "n"))
	}
}

// Lazy init starts a new history: fresh epoch, hook fired with the seq;
// later loads (and the edits, compactions in between) keep it.
func TestLazyInitRotatesEpoch_EditsAndCompactionKeepIt(t *testing.T) {
	store := newMemStore()
	store.epochs = map[string]string{}
	reg := NewRegistry(store)
	ctx := context.Background()
	v := uuid.New()
	store.epochs[mk(v, "n")] = "backfilled"
	reg.SetInitSource(func(context.Context, uuid.UUID, string) (string, error) { return "from disk", nil })
	var events []epochEvent
	reg.SetOnEpochChange(func(_ uuid.UUID, note, epoch string, seq int64) {
		events = append(events, epochEvent{note, epoch, seq})
	})

	d, err := reg.LoadDoc(ctx, v, "n")
	if err != nil {
		t.Fatal(err)
	}
	seeded := store.epochOf(v, "n")
	if seeded == "backfilled" || len(seeded) != 32 {
		t.Fatalf("lazy init kept epoch %q", seeded)
	}
	if len(events) != 1 || events[0].epoch != seeded || events[0].seq <= 0 {
		t.Fatalf("epoch hook events %+v", events)
	}

	// Edits through PersistChange, past the compaction threshold.
	upsertsBefore := store.upserts
	for i := 0; i < CompactCountThreshold+5; i++ {
		u, err := d.ApplyTextDiff("from disk "+string(rune('a'+i%26)), "web")
		if err != nil {
			t.Fatal(err)
		}
		if err := reg.PersistChange(ctx, v, "n", u, uuid.Nil, "web", d); err != nil {
			t.Fatal(err)
		}
	}
	d.Close()
	if store.upserts == upsertsBefore {
		t.Fatal("compaction never ran")
	}
	d2, err := reg.LoadDoc(ctx, v, "n")
	if err != nil {
		t.Fatal(err)
	}
	d2.Close()
	if e := store.epochOf(v, "n"); e != seeded || len(events) != 1 {
		t.Fatalf("epoch %q (want %q), hook events %d (want 1)", e, seeded, len(events))
	}
}
