package wsync

import (
	"context"
	"hash/fnv"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/ViniZap4/lumi-server/internal/crdt"
)

// DefaultGroupCommitMaxDelay caps how long the group committer lingers to
// gather more updates into one batch. It only lingers under load (the
// previous batch held more than one update); an idle server commits each
// update the moment it arrives. PHASE3-PROPOSAL §5b: <= 4 ms.
const DefaultGroupCommitMaxDelay = 4 * time.Millisecond

// DefaultGroupCommitMaxBatch bounds one batch (one INSERT statement).
const DefaultGroupCommitMaxBatch = 256

// DefaultGroupCommitShards is the number of independent committers. A
// note always uses the same shard, so its log order is kept, while a slow
// or failing batch for one note never stalls every other note.
const DefaultGroupCommitShards = 8

// groupCommitTimeout bounds one batch's append. Commits run on their own
// context so a graceful Hub.Close still drains what was queued.
const groupCommitTimeout = 10 * time.Second

// WithGroupCommit overrides the group-commit linger cap, batch size and
// shard count. maxDelay 0 disables lingering (batches then form only from
// updates that queue while the previous batch is being written); a
// non-positive maxBatch or shards keeps the default.
func WithGroupCommit(maxDelay time.Duration, maxBatch, shards int) HubOption {
	return func(h *Hub) {
		h.gcMaxDelay = maxDelay
		if maxBatch > 0 {
			h.gcMaxBatch = maxBatch
		}
		if shards > 0 {
			h.gcShards = shards
		}
	}
}

// gcFor returns the committer that owns a note.
func (h *Hub) gcFor(vaultID uuid.UUID, noteID string) *groupCommitter {
	if len(h.gc) == 1 {
		return h.gc[0]
	}
	f := fnv.New32a()
	_, _ = f.Write(vaultID[:])
	_, _ = f.Write([]byte(noteID))
	return h.gc[f.Sum32()%uint32(len(h.gc))]
}

// commitReq is one update, already applied to its room's doc, waiting to
// become durable. After the batch holding it is written, the committer
// runs the post-commit steps (feed bump, broadcast, mirror scheduling) in
// queue order and then reports the outcome on done.
type commitReq struct {
	room   *Room
	seq    uint64
	update []byte
	actor  uuid.UUID
	origin string
	from   *Subscriber
	mirror MirrorMode
	done   chan error
}

// groupCommitter is one shard of the hub's adaptive group commit for
// update-log appends (PHASE3-PROPOSAL §5b, research 03 b.2 #4).
//
// Invariants:
//   - Persist before broadcast: a request's broadcast runs only after its
//     row is durable, and a failed request is never broadcast.
//   - Per-room order: requests are enqueued under the room's opMu, the
//     queue is FIFO and a batch is appended in slice order, so the log of
//     each note keeps the apply order and post-commit steps run in it.
//   - Durable on return: the caller waits on done, so a WebSocket reader
//     still persists each update before reading its next frame (CRDT
//     client protocol §12.6).
//   - Idle means immediate: with an empty queue and an unloaded previous
//     batch the first request is written at once (no added latency).
type groupCommitter struct {
	reg      *crdt.Registry
	in       chan *commitReq
	maxDelay time.Duration
	maxBatch int

	mu     sync.RWMutex // guards closed against sends on a closed channel
	closed bool
	done   chan struct{}

	// onBatch, when set (tests), observes each batch before it is written.
	onBatch func(size int, linger time.Duration)
}

// withBatchObserver installs a test hook that sees every batch (size and
// linger used) before it is written. Applied before the loop starts.
func withBatchObserver(fn func(size int, linger time.Duration)) HubOption {
	return func(h *Hub) { h.gcObserve = fn }
}

func newGroupCommitter(reg *crdt.Registry, maxDelay time.Duration, maxBatch int, observe func(int, time.Duration)) *groupCommitter {
	if maxBatch <= 0 {
		maxBatch = DefaultGroupCommitMaxBatch
	}
	c := &groupCommitter{
		reg:      reg,
		in:       make(chan *commitReq, 4*maxBatch),
		maxDelay: maxDelay,
		maxBatch: maxBatch,
		done:     make(chan struct{}),
		onBatch:  observe,
	}
	go c.loop()
	return c
}

// enqueue hands req to the committer. False means the committer is
// closed (hub shutting down) and req will never be written.
func (c *groupCommitter) enqueue(req *commitReq) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.closed {
		return false
	}
	c.in <- req
	return true
}

// close stops accepting requests, writes everything already queued and
// returns once the loop has exited.
func (c *groupCommitter) close() {
	c.mu.Lock()
	if !c.closed {
		c.closed = true
		close(c.in)
	}
	c.mu.Unlock()
	<-c.done
}

func (c *groupCommitter) loop() {
	defer close(c.done)
	var linger time.Duration
	batch := make([]*commitReq, 0, c.maxBatch)
	for {
		req, ok := <-c.in
		if !ok {
			return
		}
		batch = append(batch[:0], req)
		open := c.drain(&batch)
		used := time.Duration(0)
		if open && linger > 0 && len(batch) < c.maxBatch {
			used = linger
			open = c.gather(&batch, linger)
		}
		if c.onBatch != nil {
			c.onBatch(len(batch), used)
		}
		start := time.Now()
		c.commit(batch)
		// Adapt: linger only while loaded (the batch held more than one
		// update), for half a commit's worth of time: it grows the next
		// batch by about half while adding at most half a commit of
		// latency, and never more than maxDelay. Idle resets it to 0.
		if len(batch) > 1 {
			linger = min(time.Since(start)/2, c.maxDelay)
		} else {
			linger = 0
		}
		clear(batch)
		if !open {
			// Channel closed while gathering: everything queued is in this
			// batch; nothing can follow.
			return
		}
	}
}

// drain moves every request already queued into batch (up to maxBatch)
// without waiting. It returns false once the channel is closed.
func (c *groupCommitter) drain(batch *[]*commitReq) bool {
	for len(*batch) < c.maxBatch {
		select {
		case req, ok := <-c.in:
			if !ok {
				return false
			}
			*batch = append(*batch, req)
		default:
			return true
		}
	}
	return true
}

// gather waits up to d for more requests (until the batch is full).
func (c *groupCommitter) gather(batch *[]*commitReq, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	for len(*batch) < c.maxBatch {
		select {
		case req, ok := <-c.in:
			if !ok {
				return false
			}
			*batch = append(*batch, req)
		case <-t.C:
			return true
		}
	}
	return true
}

func (c *groupCommitter) commit(batch []*commitReq) {
	rows := make([]crdt.PendingUpdate, len(batch))
	for i, r := range batch {
		rows[i] = crdt.PendingUpdate{
			VaultID: r.room.vaultID, NoteID: r.room.noteID,
			Update: r.update, OriginUserID: r.actor, OriginKind: r.origin,
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), groupCommitTimeout)
	errs := c.reg.AppendBatch(ctx, rows)
	cancel()
	for i, r := range batch {
		r.room.afterCommit(r, errs[i])
		r.done <- errs[i]
	}
}
