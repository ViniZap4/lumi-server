package wsync

import (
	"context"
	"errors"
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

// loadTimeout bounds a room's initial LoadDoc. The load runs on the
// hub's root context, not the first caller's, so one cancelled HTTP
// request cannot fail the load for every concurrent waiter.
const loadTimeout = 30 * time.Second

// mirrorFlushTimeout bounds the synchronous mirror run during eviction
// and hub shutdown (the root context may already be cancelled there).
const mirrorFlushTimeout = 5 * time.Second

// Origin labels recorded in note_yjs_updates.origin_kind when an
// update arrives over this transport.
const OriginLive = "web"

// OriginFSWatcher is the origin_kind tag for updates originating from
// the external filesystem watcher. Distinct from OriginLive so the
// audit log shows "user edited via Finder/$EDITOR" separately from
// "user edited via web client". FS-origin updates never schedule the
// disk mirror (the file already holds the change).
const OriginFSWatcher = "fs-watcher"

// FSMirrorFunc writes the current CRDT text back to the on-disk
// markdown file. Wired in main.go to notes.Service.WriteBodyFromCRDT.
// Nil means "no mirror" — useful for tests and for deployments that
// do not yet have notes.Service in the dep graph.
type FSMirrorFunc func(ctx context.Context, vaultID uuid.UUID, noteID, text string) error

// MirrorMode selects what happens to the on-disk file after a change.
type MirrorMode int

const (
	// MirrorDebounced schedules the room's debounced mirror (live edits,
	// federation updates).
	MirrorDebounced MirrorMode = iota
	// MirrorNow writes the file synchronously before returning (REST
	// writes, so the response reflects what is on disk).
	MirrorNow
	// MirrorNone skips the mirror (fs-watcher input: the file is the
	// source of the change).
	MirrorNone
)

// ApplyOptions describes the provenance of a mutation routed through the
// Hub's authoritative document.
type ApplyOptions struct {
	// Actor is recorded as note_yjs_updates.origin_user_id (uuid.Nil for
	// system writes).
	Actor uuid.UUID
	// Origin is note_yjs_updates.origin_kind ("web", "tui", "fs-watcher",
	// "federation:<peer>", …). It also drives federation echo suppression.
	Origin string
	// Mirror selects the disk-mirror behaviour.
	Mirror MirrorMode
	// WantState fills ApplyResult.State (full encoded doc right after the
	// change, read under the room lock). Off by default: encoding the
	// whole doc is wasted work on hot paths (relay, live edits).
	WantState bool
}

// ApplyResult reports the outcome of a mutation on the authoritative doc.
type ApplyResult struct {
	// Changed is false when the update/text was a no-op (nothing
	// persisted, broadcast or mirrored).
	Changed bool
	// Update is the lib0-v1 update that was applied (nil when !Changed).
	Update []byte
	// Text and StateVector describe the document right after the change.
	Text        string
	StateVector []byte
	// State is the full lib0-v1 encoded doc after the change; only set
	// when ApplyOptions.WantState.
	State []byte
	// MirrorErr is set when Mirror==MirrorNow and the disk write failed;
	// the CRDT change itself is persisted and broadcast regardless.
	MirrorErr error
}

// ErrHubClosed is returned once the Hub has been shut down.
var ErrHubClosed = errors.New("wsync: hub is closed")

// Room is the per-note collaboration channel: it owns the single
// authoritative in-memory *crdt.Doc for the note while anyone (a WS
// subscriber or a transient REST/fs-watcher/federation writer) holds it,
// fans updates out to subscribers, and persists each change exactly once
// through the CRDT registry.
type Room struct {
	vaultID uuid.UUID
	noteID  string

	// ready is closed once doc/loadErr are set.
	ready   chan struct{}
	doc     *crdt.Doc
	loadErr error

	// refs counts subscribers plus transient holders. Guarded by hub.mu.
	refs int
	// dropped marks a room removed by DropNote while still referenced:
	// the last release shuts it down. Guarded by hub.mu.
	dropped bool
	// idleTimer is guarded by hub.mu.
	idleTimer *time.Timer

	subs       map[*Subscriber]struct{}
	subsMu     sync.RWMutex
	hub        *Hub
	persistCtx context.Context

	// opMu serialises mutations: apply → persist → broadcast → mirror,
	// so the update log order matches the apply order and the no-op
	// check cannot interleave with another writer.
	opMu    sync.Mutex
	evicted atomic.Bool

	// awareness register (presence.go)
	awMu sync.Mutex
	aw   map[uint64]*awEntry

	mirrorTimer *time.Timer
	mirrorGen   uint64
	mirrorMu    sync.Mutex
}

// Subscriber represents a single WebSocket connection within a Room.
// Out is the outbound message queue: writers should push, the connection
// pump goroutine ranges over it. Done closes when the subscriber should
// stop.
//
// ClientID is the per-session presence identity declared by the client
// at connect time via the `?client_id=<uuid>` query param (legacy JSON
// presence, Apple client). Optional.
type Subscriber struct {
	UserID   uuid.UUID
	ClientID uuid.UUID
	Out      chan []byte
	Done     chan struct{}
	doneCh   sync.Once

	// closeCode/closeReason are set (before Done closes) when the server
	// ends the subscription for a reason the client must see as a close
	// code, e.g. 4404 when the note is deleted.
	closeMu     sync.Mutex
	closeCode   int
	closeReason string

	aw awarenessTracker
}

// CloseSubscriber closes Done idempotently so the pump goroutine can exit.
func (s *Subscriber) CloseSubscriber() {
	s.doneCh.Do(func() { close(s.Done) })
}

// CloseWithCode records a WebSocket close code for the connection pump to
// send, then closes Done. The first recorded code wins.
func (s *Subscriber) CloseWithCode(code int, reason string) {
	s.closeMu.Lock()
	if s.closeCode == 0 {
		s.closeCode, s.closeReason = code, reason
	}
	s.closeMu.Unlock()
	s.CloseSubscriber()
}

// CloseCode returns the code recorded by CloseWithCode (0 when none).
func (s *Subscriber) CloseCode() (int, string) {
	s.closeMu.Lock()
	defer s.closeMu.Unlock()
	return s.closeCode, s.closeReason
}

// Hub indexes rooms by (vault_id, note_id) so every reader and writer of
// a note shares a single in-memory doc. Also tracks per-user concurrent
// connection counts so a single user cannot exhaust server goroutines or
// memory by opening thousands of WS sessions.
//
// Invariant (CRDT client protocol §10 S2): every mutation of a note's
// CRDT — live WS, REST /diff and PATCH body, fs-watcher, federation —
// goes through Hub.ApplyUpdate / Hub.ApplyText (or a Room method), never
// through a doc loaded separately from storage. That keeps live clients
// informed and stops the debounced mirror from writing stale text.
type Hub struct {
	registry *crdt.Registry

	mu      sync.Mutex
	rooms   map[string]*Room
	idleTTL time.Duration
	sendBuf int
	rootCtx context.Context
	rootCxl context.CancelFunc
	closed  atomic.Bool

	slotsMu      sync.Mutex
	userSlots    map[uuid.UUID]int
	maxUserSlots int

	mirrorMu       sync.RWMutex
	mirrorFn       FSMirrorFunc
	mirrorDebounce time.Duration

	// bumps coalesces content-change notifications per note (feed seq).
	bumps *coalescer
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

func (h *Hub) mirror() FSMirrorFunc {
	h.mirrorMu.RLock()
	defer h.mirrorMu.RUnlock()
	return h.mirrorFn
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

// Close evicts every room and stops accepting new joins. Pending debounced
// mirrors are flushed. Active subscribers are signalled via their Done
// channels; their pump goroutines should exit promptly.
func (h *Hub) Close() {
	if !h.closed.CompareAndSwap(false, true) {
		return
	}
	h.rootCxl()
	h.bumps.close()
	h.mu.Lock()
	rooms := make([]*Room, 0, len(h.rooms))
	for _, r := range h.rooms {
		if r.idleTimer != nil {
			r.idleTimer.Stop()
			r.idleTimer = nil
		}
		r.evicted.Store(true)
		rooms = append(rooms, r)
	}
	h.rooms = map[string]*Room{}
	h.mu.Unlock()
	for _, r := range rooms {
		r.shutdown()
	}
}

func roomKey(vaultID uuid.UUID, noteID string) string {
	return vaultID.String() + "/" + noteID
}

// acquire returns the note's room, loading the doc on first use, and
// takes a reference on it. Exactly one LoadDoc runs per room; concurrent
// acquirers wait for it. Pair with release.
func (h *Hub) acquire(ctx context.Context, vaultID uuid.UUID, noteID string) (*Room, error) {
	if h.closed.Load() {
		return nil, ErrHubClosed
	}
	key := roomKey(vaultID, noteID)

	h.mu.Lock()
	if h.closed.Load() {
		h.mu.Unlock()
		return nil, ErrHubClosed
	}
	room, ok := h.rooms[key]
	if ok {
		room.refs++
		if room.idleTimer != nil {
			room.idleTimer.Stop()
			room.idleTimer = nil
		}
		h.mu.Unlock()
		select {
		case <-room.ready:
		case <-ctx.Done():
			h.release(room, false)
			return nil, ctx.Err()
		}
		if room.loadErr != nil {
			h.release(room, false)
			return nil, room.loadErr
		}
		return room, nil
	}
	room = &Room{
		vaultID:    vaultID,
		noteID:     noteID,
		ready:      make(chan struct{}),
		refs:       1,
		subs:       make(map[*Subscriber]struct{}),
		hub:        h,
		persistCtx: h.rootCtx,
	}
	h.rooms[key] = room
	h.mu.Unlock()

	loadCtx, cancel := context.WithTimeout(h.rootCtx, loadTimeout)
	doc, err := h.registry.LoadDoc(loadCtx, vaultID, noteID)
	cancel()
	if err != nil {
		room.loadErr = err
		h.mu.Lock()
		if h.rooms[key] == room {
			delete(h.rooms, key)
		}
		room.evicted.Store(true)
		h.mu.Unlock()
		close(room.ready)
		return nil, err
	}
	room.doc = doc
	close(room.ready)
	return room, nil
}

// release drops a reference. When the last one goes, a room that served
// WS subscribers lingers for idleTTL (cheap reconnects); a room held only
// by a transient writer is evicted right away (flushing any pending
// mirror), so bulk REST/fs-watcher traffic does not pin docs in memory.
func (h *Hub) release(room *Room, linger bool) {
	key := roomKey(room.vaultID, room.noteID)
	h.mu.Lock()
	room.refs--
	if room.dropped && room.refs == 0 && room.loadErr == nil {
		room.dropped = false // shut down exactly once
		h.mu.Unlock()
		room.shutdown()
		return
	}
	if room.refs > 0 || h.rooms[key] != room || room.loadErr != nil {
		h.mu.Unlock()
		return
	}
	if linger && h.idleTTL > 0 {
		if room.idleTimer != nil {
			room.idleTimer.Stop()
		}
		room.idleTimer = time.AfterFunc(h.idleTTL, func() { h.tryEvict(room) })
		h.mu.Unlock()
		return
	}
	delete(h.rooms, key)
	room.evicted.Store(true)
	h.mu.Unlock()
	room.shutdown()
}

// tryEvict evicts room if it is still idle and still registered.
func (h *Hub) tryEvict(room *Room) {
	key := roomKey(room.vaultID, room.noteID)
	h.mu.Lock()
	if room.refs > 0 || h.rooms[key] != room {
		h.mu.Unlock()
		return
	}
	delete(h.rooms, key)
	room.idleTimer = nil
	room.evicted.Store(true)
	h.mu.Unlock()
	room.shutdown()
}

// DropNote ends the note's in-memory CRDT history, if a room holds one.
// Called when the note is deleted (and defensively before a note id is
// seeded again), so a lingering room can never serve — or persist onto
// the new note — the previous lineage's doc (protocol §12). The room is
// unregistered at once (the next acquirer loads the new history), its
// pending debounced mirror is discarded (the file now belongs to nobody
// or to the new note), every subscriber is closed with code/reason, and
// the doc is closed once the last in-flight holder releases it.
func (h *Hub) DropNote(vaultID uuid.UUID, noteID string, code int, reason string) {
	key := roomKey(vaultID, noteID)
	h.mu.Lock()
	room := h.rooms[key]
	if room == nil {
		h.mu.Unlock()
		return
	}
	delete(h.rooms, key)
	room.evicted.Store(true)
	if room.idleTimer != nil {
		room.idleTimer.Stop()
		room.idleTimer = nil
	}
	idle := room.refs == 0
	if !idle {
		room.dropped = true
	}
	h.mu.Unlock()

	room.mirrorMu.Lock()
	if room.mirrorTimer != nil {
		room.mirrorTimer.Stop()
		room.mirrorTimer = nil
	}
	room.mirrorMu.Unlock()

	room.subsMu.RLock()
	subs := make([]*Subscriber, 0, len(room.subs))
	for sub := range room.subs {
		subs = append(subs, sub)
	}
	room.subsMu.RUnlock()
	for _, sub := range subs {
		sub.CloseWithCode(code, reason)
	}
	if idle {
		room.shutdown()
	}
}

// Prewarm loads the note's room (running lazy init if the note was never
// seeded) and lets it linger for the idle TTL, so a WebSocket join that
// follows (ws-ticket → upgrade) finds the doc — and the note's CRDT
// epoch — already settled.
func (h *Hub) Prewarm(ctx context.Context, vaultID uuid.UUID, noteID string) error {
	room, err := h.acquire(ctx, vaultID, noteID)
	if err != nil {
		return err
	}
	h.release(room, true)
	return nil
}

// Join attaches sub to the (vault_id, note_id) room, loading the doc
// from persistent storage on first connection. Returns the room so the
// caller can drive the Yjs handshake (server-side SyncStep1 + reading
// the client's incoming messages). The caller is responsible for
// calling Leave when the subscriber disconnects.
func (h *Hub) Join(ctx context.Context, vaultID uuid.UUID, noteID string, sub *Subscriber) (*Room, error) {
	room, err := h.acquire(ctx, vaultID, noteID)
	if err != nil {
		return nil, err
	}
	room.subsMu.Lock()
	room.subs[sub] = struct{}{}
	room.subsMu.Unlock()
	return room, nil
}

// Leave detaches the subscriber and starts the idle timer if it was the
// last holder. Remaining subscribers receive an awareness update that
// removes the departed client's awareness entries (see presence.go).
func (h *Hub) Leave(room *Room, sub *Subscriber) {
	if room == nil || sub == nil {
		return
	}
	room.subsMu.Lock()
	_, present := room.subs[sub]
	delete(room.subs, sub)
	room.subsMu.Unlock()
	sub.CloseSubscriber()
	if !present {
		return
	}
	room.broadcastPresenceLeave(sub)
	h.release(room, true)
}

// RoomIfActive returns the live Room for (vaultID, noteID) without
// creating one, or nil. Read-only callers may use it; mutations must use
// ApplyUpdate / ApplyText so they are serialised with live traffic.
func (h *Hub) RoomIfActive(vaultID uuid.UUID, noteID string) *Room {
	h.mu.Lock()
	defer h.mu.Unlock()
	r := h.rooms[roomKey(vaultID, noteID)]
	if r == nil {
		return nil
	}
	select {
	case <-r.ready:
		if r.loadErr != nil {
			return nil
		}
		return r
	default:
		return nil
	}
}

// ApplyUpdate merges a lib0-v1 update into the note's authoritative doc
// (the live room's doc when one is active, else a transiently loaded one
// registered as the room for the duration), persists it once, broadcasts
// it to every live subscriber and mirrors per opts. No-op updates change
// nothing and report Changed=false.
func (h *Hub) ApplyUpdate(ctx context.Context, vaultID uuid.UUID, noteID string, update []byte, opts ApplyOptions) (ApplyResult, error) {
	room, err := h.acquire(ctx, vaultID, noteID)
	if err != nil {
		return ApplyResult{}, err
	}
	defer h.release(room, false)
	return room.applyUpdate(update, nil, opts)
}

// ApplyText replaces the note's text with newText, expressed as minimal
// ranged ops against the authoritative doc's current text (LWW for any
// part the caller did not see — callers must only use it where that is
// the intended semantics: fs-watcher input, PATCH body, or a /diff whose
// base matches the current state).
//
// When expectSV is non-nil the write happens only if the doc's current
// state vector equals it; otherwise crdt.ErrBaseMismatch is returned and
// nothing changes. The check and the write are atomic.
func (h *Hub) ApplyText(ctx context.Context, vaultID uuid.UUID, noteID, newText string, expectSV []byte, opts ApplyOptions) (ApplyResult, error) {
	room, err := h.acquire(ctx, vaultID, noteID)
	if err != nil {
		return ApplyResult{}, err
	}
	defer h.release(room, false)
	return room.applyText(newText, expectSV, opts)
}

// View runs fn against the note's authoritative doc for reading (state
// vector, diff, text, full state). fn must not mutate the doc.
func (h *Hub) View(ctx context.Context, vaultID uuid.UUID, noteID string, fn func(*crdt.Doc) error) error {
	room, err := h.acquire(ctx, vaultID, noteID)
	if err != nil {
		return err
	}
	defer h.release(room, false)
	return fn(room.doc)
}

// Doc exposes the underlying CRDT document for handshake reads (state
// vector / diff). Callers must not mutate it directly (use the Apply
// methods) nor retain the pointer past the subscriber's lifetime.
func (r *Room) Doc() *crdt.Doc {
	return r.doc
}

// ApplyAndBroadcast applies a live (WS) update to the room's doc,
// persists it via the CRDT registry, and fans it out to every subscriber
// except origin. originUser is the user id recorded in
// note_yjs_updates.origin_user_id. No-op updates (e.g. the [0,0]
// SyncStep2 sent by every up-to-date client on connect) are dropped.
func (r *Room) ApplyAndBroadcast(update []byte, origin *Subscriber, originUser uuid.UUID) error {
	_, err := r.applyUpdate(update, origin, ApplyOptions{Actor: originUser, Origin: OriginLive, Mirror: MirrorDebounced})
	return err
}

// ApplyAndBroadcastFromFS applies an externally-sourced update (the FS
// watcher having read a file edited outside the app), persists it
// tagged "fs-watcher", and broadcasts to ALL subscribers. No mirror.
func (r *Room) ApplyAndBroadcastFromFS(update []byte) error {
	_, err := r.applyUpdate(update, nil, ApplyOptions{Origin: OriginFSWatcher, Mirror: MirrorNone})
	return err
}

// ApplyAndBroadcastFederation applies an update relayed from a federated
// peer server (v3 F2). Broadcasts to ALL local subscribers and schedules
// the FS mirror. originKind is "federation:<peer-url>" so the registry
// persist hook can suppress echoing the update back to its source link.
func (r *Room) ApplyAndBroadcastFederation(update []byte, originKind string) error {
	_, err := r.applyUpdate(update, nil, ApplyOptions{Origin: originKind, Mirror: MirrorDebounced})
	return err
}

func (r *Room) applyUpdate(update []byte, origin *Subscriber, opts ApplyOptions) (ApplyResult, error) {
	r.opMu.Lock()
	defer r.opMu.Unlock()
	if r.evicted.Load() {
		return ApplyResult{}, fmt.Errorf("wsync: room evicted")
	}
	changed, err := r.doc.ApplyUpdateChanged(update)
	if err != nil {
		return ApplyResult{}, err
	}
	if !changed {
		return r.resultLocked(false, nil, nil, opts), nil
	}
	return r.commitLocked(update, origin, opts)
}

func (r *Room) applyText(newText string, expectSV []byte, opts ApplyOptions) (ApplyResult, error) {
	r.opMu.Lock()
	defer r.opMu.Unlock()
	if r.evicted.Load() {
		return ApplyResult{}, fmt.Errorf("wsync: room evicted")
	}
	if expectSV != nil {
		want, err := crdt.DecodeStateVector(expectSV)
		if err != nil {
			return ApplyResult{}, fmt.Errorf("%w: %v", crdt.ErrBaseMismatch, err)
		}
		rawCur, err := r.doc.StateVectorV1()
		if err != nil {
			return ApplyResult{}, err
		}
		cur, err := crdt.DecodeStateVector(rawCur)
		if err != nil {
			return ApplyResult{}, err
		}
		if !cur.Equal(want) {
			return ApplyResult{}, crdt.ErrBaseMismatch
		}
	}
	update, err := r.doc.ApplyTextDiff(newText, opts.Origin)
	if err != nil {
		return ApplyResult{}, err
	}
	if len(update) == 0 {
		return r.resultLocked(false, nil, nil, opts), nil
	}
	return r.commitLocked(update, nil, opts)
}

// commitLocked persists an update already applied to r.doc, broadcasts
// it and handles the mirror. Caller holds opMu.
func (r *Room) commitLocked(update []byte, origin *Subscriber, opts ApplyOptions) (ApplyResult, error) {
	// Persist before broadcasting so a crash between the two doesn't
	// leave subscribers with state the server then loses.
	if err := r.hub.registry.PersistChange(
		r.persistCtx, r.vaultID, r.noteID, update, opts.Actor, opts.Origin, r.doc,
	); err != nil {
		return ApplyResult{}, err
	}
	// Feed seq: schedule the coalesced content bump (<= 1/s per note).
	r.hub.bumps.touch(r.vaultID, r.noteID)
	r.broadcast(EncodeSyncUpdate(update), origin)
	var mirrorErr error
	switch {
	case opts.Origin == OriginFSWatcher || opts.Mirror == MirrorNone:
		// The file is the source of this change; mirroring would race
		// the fswatch suppression window.
	case opts.Mirror == MirrorNow:
		mirrorErr = r.flushMirror(r.hub.rootCtx)
	default:
		r.scheduleMirror()
	}
	return r.resultLocked(true, update, mirrorErr, opts), nil
}

func (r *Room) resultLocked(changed bool, update []byte, mirrorErr error, opts ApplyOptions) ApplyResult {
	res := ApplyResult{Changed: changed, Update: update, MirrorErr: mirrorErr}
	res.Text, _ = r.doc.Text()
	res.StateVector, _ = r.doc.StateVectorV1()
	if opts.WantState {
		res.State, _ = r.doc.EncodeStateAsUpdate()
	}
	return res
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
	r.mirrorGen++
	gen := r.mirrorGen
	r.mirrorTimer = time.AfterFunc(r.hub.mirrorDebounce, func() { r.fireMirror(gen) })
}

func (r *Room) fireMirror(gen uint64) {
	if r.evicted.Load() {
		return
	}
	r.mirrorMu.Lock()
	if gen != r.mirrorGen || r.mirrorTimer == nil {
		// Superseded by a newer schedule, or flushed already.
		r.mirrorMu.Unlock()
		return
	}
	r.mirrorTimer = nil
	r.mirrorMu.Unlock()
	_ = r.writeMirror(r.hub.rootCtx)
}

// flushMirror cancels any pending debounced mirror and writes now.
func (r *Room) flushMirror(ctx context.Context) error {
	r.mirrorMu.Lock()
	if r.mirrorTimer != nil {
		r.mirrorTimer.Stop()
		r.mirrorTimer = nil
	}
	r.mirrorMu.Unlock()
	return r.writeMirror(ctx)
}

func (r *Room) writeMirror(ctx context.Context) error {
	fn := r.hub.mirror()
	if fn == nil {
		return nil
	}
	text, err := r.doc.Text()
	if err != nil {
		return err
	}
	return fn(ctx, r.vaultID, r.noteID, text)
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
	r.broadcastFiltered(msg, origin, nil)
}

func (r *Room) broadcastFiltered(msg []byte, origin *Subscriber, keep func(*Subscriber) bool) {
	r.subsMu.RLock()
	subs := make([]*Subscriber, 0, len(r.subs))
	for s := range r.subs {
		if s == origin || (keep != nil && !keep(s)) {
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

// shutdown runs once the room is unregistered: flush a pending mirror
// (so the last debounced edit reaches disk), signal subscribers, close
// the doc.
func (r *Room) shutdown() {
	<-r.ready
	if r.loadErr != nil {
		return
	}
	r.opMu.Lock()
	defer r.opMu.Unlock()

	r.mirrorMu.Lock()
	pending := r.mirrorTimer != nil
	if pending {
		r.mirrorTimer.Stop()
		r.mirrorTimer = nil
	}
	r.mirrorMu.Unlock()
	if pending {
		ctx, cancel := context.WithTimeout(context.Background(), mirrorFlushTimeout)
		_ = r.writeMirror(ctx)
		cancel()
	}

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

// TotalConnections returns the number of authenticated WS connections
// across all users (admin status).
func (h *Hub) TotalConnections() int {
	h.slotsMu.Lock()
	defer h.slotsMu.Unlock()
	n := 0
	for _, c := range h.userSlots {
		n += c
	}
	return n
}
