package wsync

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"
)

// DefaultContentBumpInterval is the minimum spacing between two content
// bumps of the same note (SPEC-LIVROS §3.4: at most one vault.head per
// second per note for live edits).
const DefaultContentBumpInterval = time.Second

// contentBumpTimeout bounds one bump call (a single small transaction).
const contentBumpTimeout = 10 * time.Second

// ContentChangedFunc is called by the Hub's per-note coalescer after a
// note's CRDT content changed. Wired in main.go to
// notes.Service.BumpContent (bump vault seq + change_seq + updated_at,
// publish vault.head).
type ContentChangedFunc func(ctx context.Context, vaultID uuid.UUID, noteID string)

// WithContentChanged installs the content-bump callback. Every committed
// (non no-op) change through the Hub — live WS, REST /diff and PATCH,
// fs-watcher, federation — schedules it; calls for one note are spaced at
// least interval apart (leading edge fires immediately, a burst collapses
// into one trailing call). interval <= 0 uses DefaultContentBumpInterval.
func WithContentChanged(fn ContentChangedFunc, interval time.Duration) HubOption {
	return func(h *Hub) {
		if interval <= 0 {
			interval = DefaultContentBumpInterval
		}
		h.bumps = newCoalescer(fn, interval)
	}
}

// coalescer rate-limits fn per key. A pending bump lost to a crash is
// acceptable: the content is already in the Yjs log, and clients reconcile
// on connect (the list just shows a stale updated_at until the next edit).
type coalescer struct {
	fn       ContentChangedFunc
	interval time.Duration
	ctx      context.Context
	cancel   context.CancelFunc
	now      func() time.Time

	mu      sync.Mutex
	entries map[noteKey]*coalesceEntry
	closed  bool
}

type noteKey struct {
	vault uuid.UUID
	note  string
}

type coalesceEntry struct {
	last      time.Time
	scheduled bool
	timer     *time.Timer
}

func newCoalescer(fn ContentChangedFunc, interval time.Duration) *coalescer {
	ctx, cancel := context.WithCancel(context.Background())
	return &coalescer{
		fn:       fn,
		interval: interval,
		ctx:      ctx,
		cancel:   cancel,
		now:      time.Now,
		entries:  map[noteKey]*coalesceEntry{},
	}
}

// touch records that the note changed. Never blocks on fn.
func (c *coalescer) touch(vaultID uuid.UUID, noteID string) {
	if c == nil || c.fn == nil {
		return
	}
	k := noteKey{vaultID, noteID}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	e := c.entries[k]
	if e == nil {
		e = &coalesceEntry{}
		c.entries[k] = e
	}
	if e.scheduled {
		return // the pending call will observe this change too
	}
	e.scheduled = true
	delay := c.interval - c.now().Sub(e.last)
	if e.last.IsZero() || delay < 0 {
		delay = 0
	}
	e.timer = time.AfterFunc(delay, func() { c.fire(k, e) })
}

func (c *coalescer) fire(k noteKey, e *coalesceEntry) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	e.scheduled = false
	e.timer = nil
	e.last = c.now()
	c.mu.Unlock()

	ctx, cancel := context.WithTimeout(c.ctx, contentBumpTimeout)
	c.fn(ctx, k.vault, k.note)
	cancel()

	// Forget idle notes once their spacing window has passed, so the map
	// does not grow with every note ever edited.
	time.AfterFunc(c.interval, func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		if cur := c.entries[k]; cur == e && !e.scheduled && c.now().Sub(e.last) >= c.interval {
			delete(c.entries, k)
		}
	})
}

// close stops pending bumps (they are dropped, see type doc).
func (c *coalescer) close() {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.closed = true
	for _, e := range c.entries {
		if e.timer != nil {
			e.timer.Stop()
		}
	}
	c.entries = map[noteKey]*coalesceEntry{}
	c.mu.Unlock()
	c.cancel()
}
