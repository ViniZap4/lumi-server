package crdt

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
)

// batchStore adds BatchAppender to memStore. failNote makes any batch (and
// any single append) touching that note fail, like a foreign-key error
// for a note deleted meanwhile.
type batchStore struct {
	*memStore
	failNote string
	batches  int
}

func (b *batchStore) AppendUpdates(ctx context.Context, rows []PendingUpdate) error {
	b.mu.Lock()
	b.batches++
	for _, r := range rows {
		if r.NoteID == b.failNote {
			b.mu.Unlock()
			return errors.New("fk violation")
		}
	}
	b.mu.Unlock()
	for _, r := range rows {
		if _, err := b.memStore.AppendUpdate(ctx, r.VaultID, r.NoteID, r.Update, r.OriginUserID, r.OriginKind); err != nil {
			return err
		}
	}
	return nil
}

func (b *batchStore) AppendUpdate(ctx context.Context, v uuid.UUID, n string, u []byte, actor uuid.UUID, origin string) (int64, error) {
	if n == b.failNote {
		return 0, errors.New("fk violation")
	}
	return b.memStore.AppendUpdate(ctx, v, n, u, actor, origin)
}

func TestAppendBatch_OneRoundTripInOrderWithHooks(t *testing.T) {
	store := &batchStore{memStore: newMemStore()}
	reg := NewRegistry(store)
	var hooked []string
	reg.SetOnPersist(func(_ uuid.UUID, _ string, _ []byte, origin string) { hooked = append(hooked, origin) })
	v := uuid.New()
	rows := []PendingUpdate{
		{VaultID: v, NoteID: "a", Update: []byte{1}, OriginKind: "o1"},
		{VaultID: v, NoteID: "b", Update: []byte{2}, OriginKind: "o2"},
		{VaultID: v, NoteID: "a", Update: []byte{3}, OriginKind: "o3"},
	}
	for i, err := range reg.AppendBatch(context.Background(), rows) {
		if err != nil {
			t.Fatalf("row %d: %v", i, err)
		}
	}
	if store.batches != 1 {
		t.Fatalf("batches = %d, want 1", store.batches)
	}
	if got := store.appendLog; len(got) != 3 || got[0] != "o1" || got[1] != "o2" || got[2] != "o3" {
		t.Fatalf("append order %v", got)
	}
	if len(hooked) != 3 || hooked[0] != "o1" || hooked[2] != "o3" {
		t.Fatalf("hook order %v", hooked)
	}
	a, _ := store.ListUpdatesSince(context.Background(), v, "a", 0, 0)
	if len(a) != 2 || a[0].ID >= a[1].ID || a[0].Update[0] != 1 || a[1].Update[0] != 3 {
		t.Fatalf("note a log %+v", a)
	}
}

func TestAppendBatch_FailingRowDoesNotFailNeighbours(t *testing.T) {
	store := &batchStore{memStore: newMemStore(), failNote: "gone"}
	reg := NewRegistry(store)
	var hooked []string
	reg.SetOnPersist(func(_ uuid.UUID, n string, _ []byte, _ string) { hooked = append(hooked, n) })
	v := uuid.New()
	errs := reg.AppendBatch(context.Background(), []PendingUpdate{
		{VaultID: v, NoteID: "a", Update: []byte{1}, OriginKind: "web"},
		{VaultID: v, NoteID: "gone", Update: []byte{2}, OriginKind: "web"},
		{VaultID: v, NoteID: "b", Update: []byte{3}, OriginKind: "web"},
	})
	if errs[0] != nil || errs[1] == nil || errs[2] != nil {
		t.Fatalf("errs = %v", errs)
	}
	if len(hooked) != 2 || hooked[0] != "a" || hooked[1] != "b" {
		t.Fatalf("hooks fired for %v, want [a b]", hooked)
	}
}

func TestAppendBatch_PlainStoreFallsBackPerRow(t *testing.T) {
	store := newMemStore() // no BatchAppender
	reg := NewRegistry(store)
	v := uuid.New()
	errs := reg.AppendBatch(context.Background(), []PendingUpdate{
		{VaultID: v, NoteID: "a", Update: []byte{1}, OriginKind: "x"},
		{VaultID: v, NoteID: "a", Update: []byte{2}, OriginKind: "y"},
	})
	if errs[0] != nil || errs[1] != nil || len(store.appendLog) != 2 {
		t.Fatalf("errs %v log %v", errs, store.appendLog)
	}
}

func TestLoadDocStats_CountsReplayedLog(t *testing.T) {
	store := newMemStore()
	reg := NewRegistry(store)
	v := uuid.New()
	d := NewDoc()
	defer d.Close()
	var bytes int64
	for _, s := range []string{"a", "ab", "abc"} {
		u, err := d.ApplyTextDiff(s, "web")
		if err != nil {
			t.Fatal(err)
		}
		bytes += int64(len(u))
		if _, err := store.AppendUpdate(context.Background(), v, "n", u, uuid.Nil, "web"); err != nil {
			t.Fatal(err)
		}
	}
	loaded, stats, err := reg.LoadDocStats(context.Background(), v, "n")
	if err != nil {
		t.Fatal(err)
	}
	defer loaded.Close()
	if stats.Count != 3 || stats.Bytes != bytes {
		t.Fatalf("stats %+v, want {3 %d}", stats, bytes)
	}
	if txt, _ := loaded.Text(); txt != "abc" {
		t.Fatalf("text %q", txt)
	}
}

func TestMaybeCompact_VerifiesBeforeCompacting(t *testing.T) {
	store := newMemStore()
	reg := NewRegistry(store)
	v := uuid.New()
	d := NewDoc()
	defer d.Close()
	u, _ := d.ApplyTextDiff("x", "web")
	_, _ = store.AppendUpdate(context.Background(), v, "n", u, uuid.Nil, "web")

	// Counters may say "over threshold"; the verify COUNT says otherwise.
	stats, compacted, err := reg.MaybeCompact(context.Background(), v, "n", d, false)
	if err != nil || compacted || stats.Count != 1 {
		t.Fatalf("stats %+v compacted %v err %v", stats, compacted, err)
	}
	if store.upserts != 0 {
		t.Fatal("compacted below threshold")
	}
	// force (repair after a failed append) compacts regardless of size.
	if _, compacted, err := reg.MaybeCompact(context.Background(), v, "n", d, true); err != nil || !compacted {
		t.Fatalf("forced compaction: compacted %v err %v", compacted, err)
	}
	if store.upserts != 1 {
		t.Fatalf("upserts %d", store.upserts)
	}
}
