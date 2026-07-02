package wsync

import (
	"context"
	"encoding/json"
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

// DefaultMaxUserConnections is the per-user concurrent WS cap. Past
// this, TryAcquireUserSlot returns false and the upgrade handler
// closes with a "policy violation" code.
const DefaultMaxUserConnections = 10

// DefaultMirrorDebounce is the per-room delay between the last
// CRDT update and the FS mirror write. Sized to coalesce a sustained
// typing burst (each Yjs op arrives independently) into a single FS
// write per ~500 ms while keeping the file freshness window short
// enough for TUI / apple clients tailing the dir to feel responsive.
const DefaultMirrorDebounce = 500 * time.Millisecond

// Origin labels recorded in note_yjs_updates.origin_kind when an
// update arrives over this transport.
const OriginLive = "web"

// FSMirrorFunc writes the current CRDT text back to the on-disk
// markdown file. Wired in main.go to notes.Service.WriteBodyFromCRDT.
// Nil means "no mirror" — useful for tests and for deployments that
// do not yet have notes.Service in the dep graph.
type FSMirrorFunc func(ctx context.Context, vaultID uuid.UUID, noteID, text string) error

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

	mirrorTimer *time.Timer
	mirrorMu    sync.Mutex
}

// Subscriber represents a single WebSocket connection within a Room.
// Out is the outbound message queue: writers should push, the connection
// pump goroutine ranges over it. Done closes when the subscriber should
// stop.
//
// ClientID is the per-session presence identity declared by the client
// at connect time via the `?client_id=<uuid>` query param. Optional —
// uuid.Nil for clients that don't participate in awareness (legacy TUI,
// internal callers). When non-nil, Leave broadcasts a synthetic
// awareness "left" frame to remaining subscribers so they can drop the
// peer from their presence list immediately instead of waiting on the
// client-side TTL.
type Subscriber struct {
	UserID   uuid.UUID
	ClientID uuid.UUID
	Out      chan []byte
	Done     chan struct{}
	doneCh   sync.Once
}

// CloseSubscriber closes Done idempotently so the pump goroutine can exit.
func (s *Subscriber) CloseSubscriber() {
	s.doneCh.Do(func() { close(s.Done) })
}

// Hub indexes rooms by (vault_id, note_id) so multiple clients viewing
// the same note share a single in-memory doc. Also tracks per-user
// concurrent connection counts so a single user cannot exhaust server
// goroutines or memory by opening thousands of WS sessions.
type Hub struct {
	registry *crdt.Registry

	mu       sync.Mutex
	rooms    map[string]*Room
	idleTTL  time.Duration
	sendBuf  int
	rootCtx  context.Context
	rootCxl  context.CancelFunc
	closed   atomic.Bool

	slotsMu      sync.Mutex
	userSlots    map[uuid.UUID]int
	maxUserSlots int

	mirrorMu       sync.RWMutex
	mirrorFn       FSMirrorFunc
	mirrorDebounce time.Duration
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

// WithMaxUserConnections overrides the default per-user WS connection
// cap. Use 0 to disable the cap entirely (not recommended in
// production).
func WithMaxUserConnections(n int) HubOption {
	return func(h *Hub) { h.maxUserSlots = n }
}

// WithFSMirror installs an FS-mirror callback at construction. Equivalent
// to calling SetFSMirror right after NewHub.
func WithFSMirror(fn FSMirrorFunc) HubOption {
	return func(h *Hub) { h.mirrorFn = fn }
}

// WithMirrorDebounce overrides DefaultMirrorDebounce.
func WithMirrorDebounce(d time.Duration) HubOption {
	return func(h *Hub) { h.mirrorDebounce = d }
}

// SetFSMirror swaps the active FS-mirror callback. Safe at runtime;
// nil disables mirroring.
func (h *Hub) SetFSMirror(fn FSMirrorFunc) {
	h.mirrorMu.Lock()
	h.mirrorFn = fn
	h.mirrorMu.Unlock()
}

// NewHub constructs a Hub backed by the supplied CRDT registry.
func NewHub(registry *crdt.Registry, opts ...HubOption) *Hub {
	if registry == nil {
		panic("wsync.NewHub: registry is required")
	}
	ctx, cancel := context.WithCancel(context.Background())
	h := &Hub{
		registry:       registry,
		rooms:          make(map[string]*Room),
		idleTTL:        DefaultIdleTTL,
		sendBuf:        DefaultSendBuffer,
		rootCtx:        ctx,
		rootCxl:        cancel,
		userSlots:      make(map[uuid.UUID]int),
		maxUserSlots:   DefaultMaxUserConnections,
		mirrorDebounce: DefaultMirrorDebounce,
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
// last one in the room. If the departing sub had a non-nil ClientID and
// other subscribers remain, a synthetic "left" awareness frame is
// broadcast so peers can drop the entry from their presence list right
// away (without waiting on a TTL).
func (h *Hub) Leave(room *Room, sub *Subscriber) {
	if room == nil || sub == nil {
		return
	}
	room.subsMu.Lock()
	delete(room.subs, sub)
	empty := len(room.subs) == 0
	room.subsMu.Unlock()
	sub.CloseSubscriber()

	if !empty && sub.ClientID != uuid.Nil {
		room.broadcastPresenceLeave(sub.ClientID)
	}
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

// OriginFSWatcher is the origin_kind tag for updates originating from
// the external filesystem watcher. Distinct from OriginLive so the
// audit log shows "user edited via Finder/$EDITOR" separately from
// "user edited via web client".
const OriginFSWatcher = "fs-watcher"

// ApplyAndBroadcast applies update to the room's doc, persists it via
// the CRDT registry, and fans it out to every subscriber except origin.
// originUser is the user id recorded in note_yjs_updates.origin_user_id.
func (r *Room) ApplyAndBroadcast(update []byte, origin *Subscriber, originUser uuid.UUID) error {
	return r.applyAndBroadcastWithOrigin(update, origin, originUser, OriginLive)
}

// ApplyAndBroadcastFromFS applies an externally-sourced update (the FS
// watcher having read a file edited outside the app), persists it
// tagged "fs-watcher", and broadcasts to ALL subscribers — there is no
// connection to suppress because the change did not originate from
// the WS transport.
func (r *Room) ApplyAndBroadcastFromFS(update []byte) error {
	return r.applyAndBroadcastWithOrigin(update, nil, uuid.Nil, OriginFSWatcher)
}

// ApplyAndBroadcastFederation applies an update relayed from a federated
// peer server (v3 F2). Broadcasts to ALL local subscribers (the change has
// no local WS origin to suppress) and schedules the FS mirror — unlike an
// FS-origin update, the local file does not yet reflect this change.
// originKind is "federation:<peer-url>" so the registry persist hook can
// suppress echoing the update back to its source link.
func (r *Room) ApplyAndBroadcastFederation(update []byte, originKind string) error {
	return r.applyAndBroadcastWithOrigin(update, nil, uuid.Nil, originKind)
}

func (r *Room) applyAndBroadcastWithOrigin(update []byte, origin *Subscriber, originUser uuid.UUID, originKind string) error {
	if r.evicted.Load() {
		return fmt.Errorf("wsync: room evicted")
	}
	if err := r.doc.ApplyUpdate(update); err != nil {
		return err
	}
	// Persist before broadcasting so a crash between the two doesn't
	// leave subscribers with state the server then loses.
	if err := r.hub.registry.PersistChange(
		r.persistCtx, r.vaultID, r.noteID, update, originUser, originKind, r.doc,
	); err != nil {
		return err
	}
	r.broadcast(EncodeSyncUpdate(update), origin)
	// Schedule the FS mirror. We do NOT mirror FS-originated updates
	// — the file is already the source for that change; mirroring
	// would race the fswatch suppression window.
	if originKind != OriginFSWatcher {
		r.scheduleMirror()
	}
	return nil
}

// scheduleMirror starts (or resets) a per-room debounce timer. On
// fire it reads the doc's current text and invokes the Hub's
// FSMirror callback. The room's mutex keeps the timer single-shot
// even under high-frequency update bursts.
func (r *Room) scheduleMirror() {
	if r.hub.mirrorDebounce <= 0 {
		return
	}
	r.mirrorMu.Lock()
	defer r.mirrorMu.Unlock()
	if r.mirrorTimer != nil {
		r.mirrorTimer.Stop()
	}
	r.mirrorTimer = time.AfterFunc(r.hub.mirrorDebounce, r.fireMirror)
}

func (r *Room) fireMirror() {
	if r.evicted.Load() {
		return
	}
	r.hub.mirrorMu.RLock()
	fn := r.hub.mirrorFn
	r.hub.mirrorMu.RUnlock()
	if fn == nil {
		return
	}
	text, err := r.doc.Text()
	if err != nil {
		return
	}
	// Use the hub's root context so the mirror call survives short-
	// lived per-handler contexts. notes.Service's WriteBodyFromCRDT
	// is quick (frontmatter parse + atomic write) so a stale ctx is
	// fine.
	_ = fn(r.hub.rootCtx, r.vaultID, r.noteID, text)
}

// BroadcastAwareness fans out an awareness blob to all subscribers
// other than origin. Awareness is never persisted.
func (r *Room) BroadcastAwareness(awareness []byte, origin *Subscriber) {
	r.broadcast(EncodeAwareness(awareness), origin)
}

// broadcastPresenceLeave emits a synthetic awareness frame signalling
// that clientID has departed. The payload mirrors the lumi PresenceState
// JSON shape with empty user fields and `left: true`. Clients drop the
// entry from their presence map without waiting on the per-peer TTL.
//
// Best-effort: a single Marshal failure (impossible for this fixed
// shape) silently no-ops. The room mutex isn't held here because
// broadcast() takes its own RLock and the caller has already removed
// sub from the map.
func (r *Room) broadcastPresenceLeave(clientID uuid.UUID) {
	payload, err := json.Marshal(struct {
		ClientID    string `json:"client_id"`
		Username    string `json:"username"`
		DisplayName string `json:"display_name"`
		Color       string `json:"color"`
		Left        bool   `json:"left"`
	}{ClientID: clientID.String(), Left: true})
	if err != nil {
		return
	}
	r.broadcast(EncodeAwareness(payload), nil)
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

	// Stop the FS mirror timer so we don't fire a stale mirror after
	// the doc has been closed.
	r.mirrorMu.Lock()
	if r.mirrorTimer != nil {
		r.mirrorTimer.Stop()
		r.mirrorTimer = nil
	}
	r.mirrorMu.Unlock()

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
// buffer. ClientID defaults to uuid.Nil — pass it via
// NewSubscriberWithClient when the client declares a presence identity
// at connect time.
func (h *Hub) NewSubscriber(userID uuid.UUID) *Subscriber {
	return &Subscriber{
		UserID: userID,
		Out:    make(chan []byte, h.sendBuf),
		Done:   make(chan struct{}),
	}
}

// NewSubscriberWithClient allocates a Subscriber carrying a presence
// ClientID. Equivalent to NewSubscriber when clientID is uuid.Nil.
func (h *Hub) NewSubscriberWithClient(userID, clientID uuid.UUID) *Subscriber {
	s := h.NewSubscriber(userID)
	s.ClientID = clientID
	return s
}

// RoomIfActive returns the live Room for (vaultID, noteID) without
// creating one. Used by the FS watcher to broadcast external edits to
// any currently-connected subscribers; if there are none, the watcher
// applies and persists through the registry directly without touching
// the WS layer.
func (h *Hub) RoomIfActive(vaultID uuid.UUID, noteID string) *Room {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.rooms[roomKey(vaultID, noteID)]
}

// TryAcquireUserSlot atomically checks the per-user WS cap and
// increments the counter on success. Returns false if the cap is
// already reached. Pair every successful call with ReleaseUserSlot.
//
// A zero uuid (anonymous) is allowed without limit — auth gates run
// before this so anonymous WS arrivals are already rejected; if a
// caller forgets to thread the user id we'd rather not deny the
// connection on a missing-userID bug.
func (h *Hub) TryAcquireUserSlot(userID uuid.UUID) bool {
	if h.maxUserSlots <= 0 || userID == uuid.Nil {
		return true
	}
	h.slotsMu.Lock()
	defer h.slotsMu.Unlock()
	cur := h.userSlots[userID]
	if cur >= h.maxUserSlots {
		return false
	}
	h.userSlots[userID] = cur + 1
	return true
}

// ReleaseUserSlot decrements the per-user counter. Never goes
// negative; calling on a user with no recorded slot is a no-op.
func (h *Hub) ReleaseUserSlot(userID uuid.UUID) {
	if userID == uuid.Nil {
		return
	}
	h.slotsMu.Lock()
	defer h.slotsMu.Unlock()
	cur := h.userSlots[userID]
	if cur <= 1 {
		delete(h.userSlots, userID)
		return
	}
	h.userSlots[userID] = cur - 1
}

// UserConnections returns the current count for userID. Intended for
// telemetry / tests; never returns a negative number.
func (h *Hub) UserConnections(userID uuid.UUID) int {
	h.slotsMu.Lock()
	defer h.slotsMu.Unlock()
	return h.userSlots[userID]
}
