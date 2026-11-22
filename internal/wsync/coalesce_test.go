package wsync

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ViniZap4/lumi-server/internal/crdt"
)

type bumpRec struct {
	mu    sync.Mutex
	calls []time.Time
	notes []string
}

func (b *bumpRec) fn(_ context.Context, _ uuid.UUID, note string) {
	b.mu.Lock()
	b.calls = append(b.calls, time.Now())
	b.notes = append(b.notes, note)
	b.mu.Unlock()
}

func (b *bumpRec) snapshot() ([]time.Time, []string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]time.Time(nil), b.calls...), append([]string(nil), b.notes...)
}

// S3: a burst of edits through every Hub entry point (live, REST text,
// fs-watcher) produces a leading bump plus one trailing bump, spaced by
// at least the interval — never one bump per keystroke.
func TestContentBump_CoalescesBurstPerNote(t *testing.T) {
	const interval = 150 * time.Millisecond
	reg := crdt.NewRegistry(newMemRepo())
	rec := &bumpRec{}
	hub := NewHub(reg, WithContentChanged(rec.fn, interval))
	defer hub.Close()
	v, note := uuid.New(), "n"
	seedNote(t, reg, v, note, "x")

	sub := hub.NewSubscriber(uuid.New())
	room, err := hub.Join(context.Background(), v, note, sub)
	if err != nil {
		t.Fatal(err)
	}
	defer hub.Leave(room, sub)

	ctx := context.Background()
	for i := 0; i < 10; i++ {
		switch i % 3 {
		case 0:
			if err := room.ApplyAndBroadcast(clientUpdate(t, room, fmt.Sprintf("live %d", i)), nil, uuid.Nil); err != nil {
				t.Fatal(err)
			}
		case 1:
			if _, err := hub.ApplyText(ctx, v, note, fmt.Sprintf("rest %d", i), nil, ApplyOptions{Origin: "tui", Mirror: MirrorNone}); err != nil {
				t.Fatal(err)
			}
		case 2:
			if _, err := hub.ApplyText(ctx, v, note, fmt.Sprintf("fs %d", i), nil, ApplyOptions{Origin: OriginFSWatcher, Mirror: MirrorNone}); err != nil {
				t.Fatal(err)
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(3 * interval)
	calls, _ := rec.snapshot()
	if len(calls) != 2 {
		t.Fatalf("got %d bumps for a 50ms burst, want 2 (leading + trailing)", len(calls))
	}
	if gap := calls[1].Sub(calls[0]); gap < interval-10*time.Millisecond {
		t.Fatalf("bumps %v apart, want >= %v", gap, interval)
	}
}

// S3: a no-op update (e.g. the [0,0] SyncStep2 every up-to-date client
// sends) produces no bump.
func TestContentBump_NoOpDoesNotBump(t *testing.T) {
	reg := crdt.NewRegistry(newMemRepo())
	rec := &bumpRec{}
	hub := NewHub(reg, WithContentChanged(rec.fn, 50*time.Millisecond))
	defer hub.Close()
	v, note := uuid.New(), "n"
	seedNote(t, reg, v, note, "same")

	res, err := hub.ApplyText(context.Background(), v, note, "same", nil, ApplyOptions{Origin: "tui", Mirror: MirrorNone})
	if err != nil || res.Changed {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	if _, err := hub.ApplyUpdate(context.Background(), v, note, []byte{0, 0}, ApplyOptions{Origin: "web"}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(150 * time.Millisecond)
	if calls, _ := rec.snapshot(); len(calls) != 0 {
		t.Fatalf("no-op produced %d bumps", len(calls))
	}
}

// Notes are coalesced independently.
func TestContentBump_IndependentPerNote(t *testing.T) {
	reg := crdt.NewRegistry(newMemRepo())
	rec := &bumpRec{}
	hub := NewHub(reg, WithContentChanged(rec.fn, time.Hour))
	defer hub.Close()
	v := uuid.New()
	for _, n := range []string{"a", "b"} {
		seedNote(t, reg, v, n, "x")
		if _, err := hub.ApplyText(context.Background(), v, n, "y", nil, ApplyOptions{Origin: "tui", Mirror: MirrorNone}); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(50 * time.Millisecond)
	if _, notes := rec.snapshot(); len(notes) != 2 {
		t.Fatalf("got bumps for %v, want one each for a and b", notes)
	}
}
