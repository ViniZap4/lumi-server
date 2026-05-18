package wsync

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/ViniZap4/lumi-server/internal/crdt"
)

// DefaultIdleTTL is how long a Room with no subscribers may sit in the
// Hub before being evicted (doc closed, entry removed). Five minutes
// matches a typical "user opened a note in the background tab and is
// going to come back" window.
const DefaultIdleTTL = 5 * time.Minute

// DefaultSendBuffer is the per-subscriber outbound channel depth. Slow
// clients that block longer than this many queued messages are dropped.
const DefaultSendBuffer = 256

// Origin labels recorded in note_yjs_updates.origin_kind when an
// update arrives over this transport.
const OriginLive = "web"

// Room is the per-note collaboration channel: it owns a single
// *crdt.Doc, fans inbound updates out to subscribers, and persists
// each update through the CRDT registry.
type Room struct {
	vaultID uuid.UUID
	noteID  string

	doc *crdt.Doc

	subs       map[*Subscriber]struct{}
	subsMu     sync.RWMutex
	hub        *Hub
	persistCtx context.Context

	idleTimer *time.Timer
	idleMu    sync.Mutex
	evicted   atomic.Bool
}

// Subscriber represents a single WebSocket connection within a Room.
// Out is the outbound message queue: writers should push, the connection
// pump goroutine ranges over it. Done closes when the subscriber should
// stop.
type Subscriber struct {
	UserID uuid.UUID
	Out    chan []byte
	Done   chan struct{}
	doneCh sync.Once
}

// CloseSubscriber closes Done idempotently so the pump goroutine can exit.
func (s *Subscriber) CloseSubscriber() {
	s.doneCh.Do(func() { close(s.Done) })
}

// Hub indexes rooms by (vault_id, note_id) so multiple clients viewing
// the same note share a single in-memory doc.
type Hub struct {
	registry *crdt.Registry

	mu       sync.Mutex
	rooms    map[string]*Room
	idleTTL  time.Duration
	sendBuf  int
	rootCtx  context.Context
	rootCxl  context.CancelFunc
	closed   atomic.Bool
}

// HubOption configures Hub at construction.
type HubOption func(*Hub)

// WithIdleTTL overrides the default idle eviction window.
func WithIdleTTL(d time.Duration) HubOption {
	return func(h *Hub) { h.idleTTL = d }
}

// WithSendBuffer overrides the default per-subscriber outbound buffer.
func WithSendBuffer(n int) HubOption {
	return func(h *Hub) { h.sendBuf = n }
}

// NewHub constructs a Hub backed by the supplied CRDT registry.
func NewHub(registry *crdt.Registry, opts ...HubOption) *Hub {
	if registry == nil {
		panic("wsync.NewHub: registry is required")
	}
	ctx, cancel := context.WithCancel(context.Background())
	h := &Hub{
		registry: registry,
		rooms:    make(map[string]*Room),
		idleTTL:  DefaultIdleTTL,
		sendBuf:  DefaultSendBuffer,
		rootCtx:  ctx,
		rootCxl:  cancel,
	}
	for _, o := range opts {
		o(h)
	}
	return h
}

// Close evicts every room and stops accepting new joins. Active
// subscribers are signalled via their Done channels; their pump
// goroutines should exit promptly.
func (h *Hub) Close() {
	if !h.closed.CompareAndSwap(false, true) {
		return
	}
	h.rootCxl()
	h.mu.Lock()
	rooms := make([]*Room, 0, len(h.rooms))
	for _, r := range h.rooms {
		rooms = append(rooms, r)
	}
	h.rooms = map[string]*Room{}
	h.mu.Unlock()
	for _, r := range rooms {
		r.evict()
	}
}

func roomKey(vaultID uuid.UUID, noteID string) string {
	return vaultID.String() + "/" + noteID
}

// Join attaches sub to the (vault_id, note_id) room, loading the doc
// from persistent storage on first connection. Returns the room so the
// caller can drive the Yjs handshake (server-side SyncStep1 + reading
// the client's incoming messages). The caller is responsible for
// calling Leave when the subscriber disconnects.
func (h *Hub) Join(ctx context.Context, vaultID uuid.UUID, noteID string, sub *Subscriber) (*Room, error) {
	if h.closed.Load() {
		return nil, fmt.Errorf("wsync: hub is closed")
	}
	key := roomKey(vaultID, noteID)

	h.mu.Lock()
	room, ok := h.rooms[key]
	if ok {
		h.mu.Unlock()
		room.cancelIdle()
	} else {
		// Load the doc fresh — we don't hold h.mu across LoadDoc to
		// avoid serialising opens of distinct notes.
		h.mu.Unlock()
		doc, err := h.registry.LoadDoc(ctx, vaultID, noteID)
		if err != nil {
			return nil, err
		}
		room = &Room{
			vaultID:    vaultID,
			noteID:     noteID,
			doc:        doc,
			subs:       make(map[*Subscriber]struct{}),
			hub:        h,
			persistCtx: h.rootCtx,
		}
		// Race window: two concurrent first-joiners could each LoadDoc.
		// The loser closes its doc and adopts the winner's.
		h.mu.Lock()
		if existing, ok2 := h.rooms[key]; ok2 {
			h.mu.Unlock()
			_ = doc.Close()
			existing.cancelIdle()
			room = existing
		} else {
			h.rooms[key] = room
			h.mu.Unlock()
		}
	}

	room.subsMu.Lock()
	room.subs[sub] = struct{}{}
	room.subsMu.Unlock()
	return room, nil
}

// Leave detaches the subscriber and starts the idle timer if it was the
// last one in the room.
func (h *Hub) Leave(room *Room, sub *Subscriber) {
	if room == nil || sub == nil {
		return
	}
	room.subsMu.Lock()
	delete(room.subs, sub)
	empty := len(room.subs) == 0
	room.subsMu.Unlock()
	sub.CloseSubscriber()

	if empty {
		room.scheduleIdleEviction()
	}
}

// Doc exposes the underlying CRDT document for handshake reads (state
// vector / diff). Callers must not retain the pointer past the
// subscriber's lifetime.
func (r *Room) Doc() *crdt.Doc {
	return r.doc
}

// ApplyAndBroadcast applies update to the room's doc, persists it via
// the CRDT registry, and fans it out to every subscriber except origin.
// originUser is the user id recorded in note_yjs_updates.origin_user_id.
func (r *Room) ApplyAndBroadcast(update []byte, origin *Subscriber, originUser uuid.UUID) error {
	if r.evicted.Load() {
		return fmt.Errorf("wsync: room evicted")
	}
	if err := r.doc.ApplyUpdate(update); err != nil {
		return err
	}
	// Persist before broadcasting so a crash between the two doesn't
	// leave subscribers with state the server then loses.
	if err := r.hub.registry.PersistChange(
		r.persistCtx, r.vaultID, r.noteID, update, originUser, OriginLive, r.doc,
	); err != nil {
		return err
	}
	r.broadcast(EncodeSyncUpdate(update), origin)
	return nil
}

// BroadcastAwareness fans out an awareness blob to all subscribers
// other than origin. Awareness is never persisted.
func (r *Room) BroadcastAwareness(awareness []byte, origin *Subscriber) {
	r.broadcast(EncodeAwareness(awareness), origin)
}

// broadcast pushes msg into every subscriber's Out channel except
// origin. Subscribers whose outbound queue is full are dropped (their
// Done is closed); the pump will catch up next.
func (r *Room) broadcast(msg []byte, origin *Subscriber) {
	r.subsMu.RLock()
	subs := make([]*Subscriber, 0, len(r.subs))
	for s := range r.subs {
		if s == origin {
			continue
		}
		subs = append(subs, s)
	}
	r.subsMu.RUnlock()

	for _, s := range subs {
		select {
		case s.Out <- msg:
		default:
			// Slow consumer — disconnect rather than block everyone
			// behind it.
			s.CloseSubscriber()
		}
	}
}

func (r *Room) cancelIdle() {
	r.idleMu.Lock()
	if r.idleTimer != nil {
		r.idleTimer.Stop()
		r.idleTimer = nil
	}
	r.idleMu.Unlock()
}

func (r *Room) scheduleIdleEviction() {
	r.idleMu.Lock()
	defer r.idleMu.Unlock()
	if r.idleTimer != nil {
		r.idleTimer.Stop()
	}
	r.idleTimer = time.AfterFunc(r.hub.idleTTL, r.evict)
}

func (r *Room) evict() {
	if !r.evicted.CompareAndSwap(false, true) {
		return
	}
	r.hub.mu.Lock()
	delete(r.hub.rooms, roomKey(r.vaultID, r.noteID))
	r.hub.mu.Unlock()

	// Signal any remaining subscribers (Close should have drained, but
	// defensive) and close the doc.
	r.subsMu.Lock()
	subs := make([]*Subscriber, 0, len(r.subs))
	for s := range r.subs {
		subs = append(subs, s)
	}
	r.subs = map[*Subscriber]struct{}{}
	r.subsMu.Unlock()
	for _, s := range subs {
		s.CloseSubscriber()
	}
	_ = r.doc.Close()
}

// NewSubscriber allocates a Subscriber with the configured Hub send
// buffer.
func (h *Hub) NewSubscriber(userID uuid.UUID) *Subscriber {
	return &Subscriber{
		UserID: userID,
		Out:    make(chan []byte, h.sendBuf),
		Done:   make(chan struct{}),
	}
}
