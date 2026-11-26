package wsync

// Benchmarks for the live commit path (docs/PERF-BUDGETS.md, umbrella:
// server WS update apply -> broadcast p50 <= 2 ms, p99 <= 10 ms).
// The repo is in memory, so wall time here is the CPU floor (yrs merge,
// group-commit hand-off, broadcast, background compaction every 200
// updates). The `repo-calls/op` metric counts storage round trips per
// update (a batched append is one, as in Postgres): it is deterministic
// (compaction is waited for before counting), so it gates the Postgres
// work of the live path without a database in CI.
//
//   GOTOOLCHAIN=go1.26.11 go test -run '^$' -bench . -benchmem ./internal/wsync

import (
	"context"
	"fmt"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ViniZap4/lumi-server/internal/crdt"
	"github.com/ViniZap4/lumi-server/internal/perfcorpus"
)

// countingRepo counts every storage call (one call = one round trip in
// the Postgres store).
type countingRepo struct {
	*memRepo
	calls atomic.Int64
}

func (c *countingRepo) GetSnapshot(ctx context.Context, v uuid.UUID, n string) (crdt.SnapshotRow, error) {
	c.calls.Add(1)
	return c.memRepo.GetSnapshot(ctx, v, n)
}
func (c *countingRepo) UpsertSnapshot(ctx context.Context, v uuid.UUID, n string, s []byte) error {
	c.calls.Add(1)
	return c.memRepo.UpsertSnapshot(ctx, v, n, s)
}
func (c *countingRepo) SeedSnapshot(ctx context.Context, v uuid.UUID, n string, s []byte, e string) (int64, error) {
	c.calls.Add(1)
	return c.memRepo.SeedSnapshot(ctx, v, n, s, e)
}
func (c *countingRepo) AppendUpdate(ctx context.Context, v uuid.UUID, n string, u []byte, actor uuid.UUID, origin string) (int64, error) {
	c.calls.Add(1)
	return c.memRepo.AppendUpdate(ctx, v, n, u, actor, origin)
}

// AppendUpdates makes countingRepo a crdt.BatchAppender like the Postgres
// store: a group-commit batch is one round trip however many rows it has.
func (c *countingRepo) AppendUpdates(ctx context.Context, rows []crdt.PendingUpdate) error {
	c.calls.Add(1)
	for _, u := range rows {
		if _, err := c.memRepo.AppendUpdate(ctx, u.VaultID, u.NoteID, u.Update, u.OriginUserID, u.OriginKind); err != nil {
			return err
		}
	}
	return nil
}
func (c *countingRepo) ListUpdatesSince(ctx context.Context, v uuid.UUID, n string, since int64, limit int) ([]crdt.UpdateRow, error) {
	c.calls.Add(1)
	return c.memRepo.ListUpdatesSince(ctx, v, n, since, limit)
}
func (c *countingRepo) CountUpdates(ctx context.Context, v uuid.UUID, n string) (int, int64, error) {
	c.calls.Add(1)
	return c.memRepo.CountUpdates(ctx, v, n)
}
func (c *countingRepo) DeleteUpdatesUpTo(ctx context.Context, v uuid.UUID, n string, maxID int64) (int64, error) {
	c.calls.Add(1)
	return c.memRepo.DeleteUpdatesUpTo(ctx, v, n, maxID)
}
func (c *countingRepo) HighestUpdateID(ctx context.Context, v uuid.UUID, n string) (int64, error) {
	c.calls.Add(1)
	return c.memRepo.HighestUpdateID(ctx, v, n)
}

// poolSize keystroke updates are generated once per size; every chunk
// of poolSize iterations replays them on a fresh room loaded from the
// same snapshot, so generation (O(note) per update) stays off the clock.
const poolSize = 256

type liveFixture struct {
	state   []byte
	updates [][]byte
}

func newLiveFixture(b *testing.B, size int) liveFixture {
	b.Helper()
	text := perfcorpus.Prose(size)
	seed := crdt.NewDoc()
	defer seed.Close()
	if _, err := seed.ApplyTextDiff(text, "bench"); err != nil {
		b.Fatal(err)
	}
	state, err := seed.EncodeStateAsUpdate()
	if err != nil {
		b.Fatal(err)
	}
	replica, err := crdt.LoadDoc(state)
	if err != nil {
		b.Fatal(err)
	}
	defer replica.Close()
	at := perfcorpus.MidPoint(text)
	cur := text
	updates := make([][]byte, poolSize)
	for i := range updates {
		cur = cur[:at+i] + "x" + cur[at+i:]
		if updates[i], err = replica.ApplyTextDiff(cur, "client"); err != nil {
			b.Fatal(err)
		}
	}
	return liveFixture{state: state, updates: updates}
}

// waitCompaction blocks until the room's background compaction (if any)
// has finished, so its storage calls are counted in the chunk that
// triggered it.
func waitCompaction(r *Room) {
	for r.compacting.Load() {
		runtime.Gosched()
	}
	// Barrier: a compaction that already cleared compacting may still
	// hold compactMu.
	r.compactMu.Lock()
	r.compactMu.Unlock()
}

// BenchmarkRoomCommitLive: one live keystroke update through
// Room.ApplyAndBroadcast (apply, group commit, broadcast to one peer,
// debounced mirror scheduling; no COUNT and no eager Text/SV), with the
// background compaction amortised.
func BenchmarkRoomCommitLive(b *testing.B) {
	for _, size := range []int{20 * perfcorpus.KB, 200 * perfcorpus.KB} {
		b.Run(fmt.Sprintf("%dKB", size/perfcorpus.KB), func(b *testing.B) {
			fx := newLiveFixture(b, size)
			repo := &countingRepo{memRepo: newMemRepo()}
			hub := NewHub(crdt.NewRegistry(repo), WithIdleTTL(time.Hour), WithMirrorDebounce(time.Hour))
			defer hub.Close()
			vault := uuid.New()
			ctx := context.Background()

			var room *Room
			var author, peer *Subscriber
			stopDrain := func() {}
			open := func(chunk int) {
				note := fmt.Sprintf("bench-%d", chunk)
				_ = repo.memRepo.UpsertSnapshot(ctx, vault, note, fx.state)
				author, peer = hub.NewSubscriber(uuid.New()), hub.NewSubscriber(uuid.New())
				var err error
				if room, err = hub.Join(ctx, vault, note, author); err != nil {
					b.Fatal(err)
				}
				if _, err = hub.Join(ctx, vault, note, peer); err != nil {
					b.Fatal(err)
				}
				done := make(chan struct{})
				go func(out chan []byte) {
					for {
						select {
						case <-out:
						case <-done:
							return
						}
					}
				}(peer.Out)
				stopDrain = func() { close(done) }
			}
			closeRoom := func() {
				stopDrain()
				hub.Leave(room, peer)
				hub.Leave(room, author)
			}

			b.ReportAllocs()
			b.ResetTimer()
			b.StopTimer()
			var calls int64
			for i := 0; i < b.N; i++ {
				if i%poolSize == 0 {
					if room != nil {
						closeRoom()
					}
					open(i / poolSize)
					repo.calls.Store(0)
					b.StartTimer()
				}
				if err := room.ApplyAndBroadcast(fx.updates[i%poolSize], author, author.UserID); err != nil {
					b.Fatal(err)
				}
				if (i+1)%poolSize == 0 || i == b.N-1 {
					b.StopTimer()
					waitCompaction(room)
					calls += repo.calls.Load()
				}
			}
			closeRoom()
			b.ReportMetric(float64(calls)/float64(b.N), "repo-calls/op")
		})
	}
}

// BenchmarkHubApplyText: the REST write path (PATCH body, /diff with a
// matching base, fswatch) — Hub.ApplyText lowering a one-character
// change into ranged ops and committing it.
func BenchmarkHubApplyText(b *testing.B) {
	for _, size := range []int{20 * perfcorpus.KB, 200 * perfcorpus.KB} {
		b.Run(fmt.Sprintf("%dKB", size/perfcorpus.KB), func(b *testing.B) {
			text := perfcorpus.Prose(size)
			edited := perfcorpus.Edit(text, "x")
			repo := &countingRepo{memRepo: newMemRepo()}
			hub := NewHub(crdt.NewRegistry(repo), WithIdleTTL(time.Hour), WithMirrorDebounce(time.Hour))
			defer hub.Close()
			vault, note, ctx := uuid.New(), "bench", context.Background()
			keep := hub.NewSubscriber(uuid.New()) // keeps the room live between calls
			room, err := hub.Join(ctx, vault, note, keep)
			if err != nil {
				b.Fatal(err)
			}
			defer hub.Leave(room, keep)
			opts := ApplyOptions{Origin: "bench", Mirror: MirrorNone}
			if _, err := hub.ApplyText(ctx, vault, note, text, nil, opts); err != nil {
				b.Fatal(err)
			}
			go func() {
				for range keep.Out {
				}
			}()
			repo.calls.Store(0)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				target := edited
				if i%2 == 1 {
					target = text
				}
				if _, err := hub.ApplyText(ctx, vault, note, target, nil, opts); err != nil {
					b.Fatal(err)
				}
			}
			b.StopTimer()
			waitCompaction(room)
			b.ReportMetric(float64(repo.calls.Load())/float64(b.N), "repo-calls/op")
		})
	}
}
