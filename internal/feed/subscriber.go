package feed

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"
)

// frame is one SSE event ready for the wire.
type frame struct {
	name string
	data []byte
}

// Subscriber is one open stream. Its readable-vault set is the capability
// filter: vault events reach it only for vaults in the set, and the set
// changes only through resolved access (hello, membership publications,
// periodic re-check).
type Subscriber struct {
	userID     uuid.UUID
	token      string // raw token, memory only: needed for the session re-check
	sessionKey string

	queue chan frame    // bounded; overflow drops the stream
	wake  chan struct{} // cap 1: a vault.head is pending
	done  chan struct{}

	mu      sync.Mutex
	ready   bool                      // hello computed; before that events are parked
	vaults  map[uuid.UUID]VaultAccess // readable set
	heads   map[uuid.UUID]int64       // pending coalesced vault.head
	sent    map[uuid.UUID]int64       // highest seq already announced
	recheck map[uuid.UUID]string      // access changes seen before ready (vault → revoke reason)
	final   *frame                    // written before closing (session.ended / reconnect)
	ended   bool
	dropped bool // slow consumer: close without draining
}

func newSubscriber(userID uuid.UUID, token string, buffer int) *Subscriber {
	if buffer <= 0 {
		buffer = 1
	}
	return &Subscriber{
		userID:     userID,
		token:      token,
		sessionKey: SessionKey(token),
		queue:      make(chan frame, buffer),
		wake:       make(chan struct{}, 1),
		done:       make(chan struct{}),
		vaults:     map[uuid.UUID]VaultAccess{},
		heads:      map[uuid.UUID]int64{},
		sent:       map[uuid.UUID]int64{},
		recheck:    map[uuid.UUID]string{},
	}
}

// end stops the stream. With f set (and override or no final frame yet),
// f is written before the connection closes. Idempotent.
func (s *Subscriber) end(f frame, override bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ended {
		return
	}
	if s.final == nil || override {
		ff := f
		s.final = &ff
	}
	s.ended = true
	close(s.done)
}

// drop closes the stream without a final frame (slow consumer). The
// client reconnects and reconciles.
func (s *Subscriber) dropLocked() {
	if s.ended {
		return
	}
	s.ended = true
	s.dropped = true
	close(s.done)
}

// enqueueLocked queues f or drops the stream when the buffer is full.
func (s *Subscriber) enqueueLocked(f frame) {
	if s.ended {
		return
	}
	select {
	case s.queue <- f:
	default:
		s.dropLocked()
	}
}

// offerHead records a new seq. Before hello every head is parked (and
// filtered at flush time); after hello only readable vaults count.
func (s *Subscriber) offerHead(vaultID uuid.UUID, seq int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ended {
		return
	}
	if s.ready {
		if _, ok := s.vaults[vaultID]; !ok {
			return
		}
	}
	if seq > s.heads[vaultID] {
		s.heads[vaultID] = seq
	}
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// sendIfReadable queues f when the vault is in the readable set.
func (s *Subscriber) sendIfReadable(vaultID uuid.UUID, f frame) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.ready {
		return // the client re-reads vault details after hello anyway
	}
	if _, ok := s.vaults[vaultID]; ok {
		s.enqueueLocked(f)
	}
}

// apply folds a resolved access result into the set and emits the delta:
// vault.access when gained or when role/can_edit changed, vault.revoked
// (with reason) when lost. Before hello it parks the vault for re-check.
func (s *Subscriber) apply(vaultID uuid.UUID, acc VaultAccess, ok bool, reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ended {
		return
	}
	if !s.ready {
		if cur, parked := s.recheck[vaultID]; !parked || cur != ReasonDeleted {
			s.recheck[vaultID] = reason
		}
		return
	}
	prev, had := s.vaults[vaultID]
	switch {
	case ok:
		if had && prev.Role == acc.Role && prev.CanEdit == acc.CanEdit {
			return
		}
		acc.VaultID = vaultID
		s.vaults[vaultID] = acc
		s.enqueueLocked(frame{EventVaultAccess, mustJSON(accessPayload{VaultID: vaultID, Role: acc.Role, CanEdit: acc.CanEdit})})
	case had:
		delete(s.vaults, vaultID)
		delete(s.heads, vaultID)
		delete(s.sent, vaultID)
		s.enqueueLocked(frame{EventVaultRevoked, mustJSON(revokedPayload{VaultID: vaultID, Reason: reason})})
	}
}

// becomeReady installs the hello set and returns the vaults whose access
// changed while hello was being computed.
func (s *Subscriber) becomeReady(accs []VaultAccess) map[uuid.UUID]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, a := range accs {
		s.vaults[a.VaultID] = a
		s.sent[a.VaultID] = a.Seq
	}
	s.ready = true
	parked := s.recheck
	s.recheck = map[uuid.UUID]string{}
	return parked
}

// readableIDs snapshots the readable set.
func (s *Subscriber) readableIDs() map[uuid.UUID]struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[uuid.UUID]struct{}, len(s.vaults))
	for id := range s.vaults {
		out[id] = struct{}{}
	}
	return out
}

// takeHeads returns the pending heads that are still readable and newer
// than what this stream already announced.
func (s *Subscriber) takeHeads() []frame {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []frame
	for v, seq := range s.heads {
		if _, ok := s.vaults[v]; ok && seq > s.sent[v] {
			out = append(out, frame{EventVaultHead, mustJSON(headPayload{VaultID: v, Seq: seq})})
			s.sent[v] = seq
		}
	}
	s.heads = map[uuid.UUID]int64{}
	return out
}

func (s *Subscriber) isDropped() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dropped
}

func (s *Subscriber) finalFrame() (f *frame, dropped bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.final, s.dropped
}

// ---- the stream loop ----------------------------------------------------------------

// eventWriter is the wire surface Serve needs (frameWriter in production).
type eventWriter interface {
	event(name string, data []byte) error
	ping() error
}

// Serve runs the stream until the client goes away, the session ends,
// the stream is dropped, the lifetime elapses or the broker closes. It
// always unregisters the subscriber.
func (b *Broker) Serve(s *Subscriber, w eventWriter) {
	defer b.unregister(s)
	defer s.end(frame{}, false) // make sure publications stop targeting it

	ctx := b.ctx
	rctx, cancel := context.WithTimeout(ctx, b.cfg.ResolveTimeout)
	accs, err := b.dir.Readable(rctx, s.userID)
	cancel()
	if err != nil {
		b.log.Warn().Err(err).Msg("feed: hello: list readable vaults")
		_ = w.event(EventReconnect, mustJSON(reconnectPayload{AfterMS: 1000}))
		return
	}
	parked := s.becomeReady(accs)
	if err := w.event(EventHello, helloFrame(s.userID, b.now(), accs).data); err != nil {
		return
	}
	if len(parked) > 0 {
		b.submit(func(ctx context.Context) {
			for v, reason := range parked {
				if reason == ReasonDeleted {
					s.apply(v, VaultAccess{}, false, ReasonDeleted)
					continue
				}
				rctx, cancel := context.WithTimeout(ctx, b.cfg.ResolveTimeout)
				acc, ok, err := b.dir.Access(rctx, s.userID, v)
				cancel()
				if err == nil {
					s.apply(v, acc, ok, reason)
				}
			}
		})
	}

	ping := time.NewTicker(b.cfg.Ping)
	defer ping.Stop()
	recheck := time.NewTicker(b.cfg.Recheck)
	defer recheck.Stop()
	life := time.NewTimer(b.cfg.MaxLifetime)
	defer life.Stop()
	var headTimer *time.Timer
	var headC <-chan time.Time
	var lastHeads time.Time
	defer func() {
		if headTimer != nil {
			headTimer.Stop()
		}
	}()

	write := func(f frame) bool {
		if s.isDropped() {
			return false
		}
		return w.event(f.name, f.data) == nil
	}
	drainQueue := func() bool {
		for {
			select {
			case f := <-s.queue:
				if !write(f) {
					return false
				}
			default:
				return true
			}
		}
	}
	flushHeads := func() bool {
		headTimer, headC = nil, nil
		// Queued access/revoke frames go first so a client never sees a
		// head for a vault it has not been told about.
		if !drainQueue() {
			return false
		}
		for _, f := range s.takeHeads() {
			if !write(f) {
				return false
			}
		}
		lastHeads = b.now()
		return true
	}

	for {
		select {
		case <-s.done:
			f, dropped := s.finalFrame()
			if dropped {
				return // slow consumer: just close
			}
			// Deliver what was queued before the end, then the final frame.
			if !drainQueue() {
				return
			}
			if f != nil && f.name != "" {
				_ = write(*f)
			}
			return
		case f := <-s.queue:
			if !write(f) {
				return
			}
		case <-s.wake:
			if headC != nil {
				continue // a flush is already scheduled
			}
			wait := b.cfg.HeadInterval - b.now().Sub(lastHeads)
			if wait <= 0 {
				if !flushHeads() {
					return
				}
				continue
			}
			headTimer = time.NewTimer(wait)
			headC = headTimer.C
		case <-headC:
			if !flushHeads() {
				return
			}
		case <-ping.C:
			if w.ping() != nil {
				return
			}
		case <-recheck.C:
			b.recheck(ctx, s)
		case <-life.C:
			_ = drainQueue()
			_ = write(frame{EventReconnect, mustJSON(reconnectPayload{AfterMS: 0})})
			return
		}
	}
}

// recheck re-validates the session and reconciles the readable set, so a
// token revoked out of band ends within one interval and a missed
// membership publication heals.
func (b *Broker) recheck(ctx context.Context, s *Subscriber) {
	if b.check != nil {
		rctx, cancel := context.WithTimeout(ctx, b.cfg.ResolveTimeout)
		reason, err := b.check(rctx, s.token)
		cancel()
		if err == nil && reason != "" {
			s.end(sessionEndedFrame(reason), false)
			return
		}
	}
	rctx, cancel := context.WithTimeout(ctx, b.cfg.ResolveTimeout)
	accs, err := b.dir.Readable(rctx, s.userID)
	cancel()
	if err != nil {
		return
	}
	stale := s.readableIDs()
	for _, a := range accs {
		delete(stale, a.VaultID)
		s.apply(a.VaultID, a, true, ReasonRemoved)
	}
	for v := range stale {
		s.apply(v, VaultAccess{}, false, ReasonRemoved)
	}
}
