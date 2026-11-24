// F2 content-plane relay: one WebSocket per (vault, peer link) multiplexing
// per-note Yjs sync. Both roles run the same Session; the home side sends
// the opening manifest. Live updates enter through the crdt.Registry persist
// hook (the one choke point every write path crosses) and fan out to every
// active link except the one they arrived on.
package federation

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/ViniZap4/lumi-server/internal/crdt"
	"github.com/ViniZap4/lumi-server/internal/domain"
	"github.com/ViniZap4/lumi-server/internal/wsync"
)

// binaryMessage is the WebSocket binary opcode; local constant so the relay
// core does not depend on a specific websocket package.
const binaryMessage = 2

// sendBuffer bounds per-link outbound queues. A link that cannot drain this
// fast is closed and left to the reconnect loop — blocking the write path
// on a slow peer is never acceptable.
const sendBuffer = 1024

// OriginFederationPrefix tags updates that arrived over a federation link:
// origin_kind = OriginFederationPrefix + peerURL.
const OriginFederationPrefix = "federation:"

// wsConn is the transport surface a Session needs. Satisfied by
// *websocket.Conn (both gofiber and fasthttp flavours) and by the in-memory
// pipe used in tests.
type wsConn interface {
	ReadMessage() (messageType int, data []byte, err error)
	WriteMessage(messageType int, data []byte) error
	Close() error
}

// MirrorFunc writes a note's current text to the vault filesystem.
// Implemented by notes.Service.WriteBodyFromCRDT (which also suppresses the
// resulting fswatch event).
type MirrorFunc func(ctx context.Context, vaultID uuid.UUID, noteID, text string) error

// NoteMetaRepo is the note-metadata surface the relay needs.
type NoteMetaRepo interface {
	Upsert(ctx context.Context, n domain.Note) error
	Get(ctx context.Context, vaultID uuid.UUID, id string) (domain.Note, error)
	ListForVault(ctx context.Context, vaultID uuid.UUID, limit, offset int) ([]domain.Note, error)
}

// DocAuthority is the single owner of each note's in-memory CRDT doc
// (implemented by *wsync.Hub). Relayed updates go through it so they reach
// connected clients immediately and are serialised with every other
// writer. nil-safe for tests: without it the relay loads, persists and
// mirrors through the registry directly — only correct when no Hub exists.
type DocAuthority interface {
	ApplyUpdate(ctx context.Context, vaultID uuid.UUID, noteID string, update []byte, opts wsync.ApplyOptions) (wsync.ApplyResult, error)
	View(ctx context.Context, vaultID uuid.UUID, noteID string, fn func(*crdt.Doc) error) error
}

// DeleteFunc removes a note (row + file + CRDT cascade) without notifying
// the federation layer back. Implemented by notes.Service.DeleteFromFederation.
type DeleteFunc func(ctx context.Context, vaultID uuid.UUID, noteID string) error

// MoveFunc applies a rename/move without notifying the federation layer
// back. Implemented by notes.Service.MoveFromFederation.
type MoveFunc func(ctx context.Context, vaultID uuid.UUID, noteID, newPath, newTitle string) error

// F3 control-plane callbacks; all nil-safe (F2-only setups skip them).
type (
	// ControlCurrentFunc returns home's signed control document for
	// session-open push. Implemented by Service.CurrentControlState.
	ControlCurrentFunc func(ctx context.Context, vaultID uuid.UUID) (state, sig []byte, ok bool)
	// ControlApplyFunc verifies+stores a document on the follower and
	// returns the applied cursor. Implemented by Service.ApplyControlState.
	ControlApplyFunc func(ctx context.Context, vaultID uuid.UUID, peerURL string, state, sig []byte) (int64, error)
	// ControlAckedFunc records follower progress on the home side.
	// Implemented by Service.RecordControlAck.
	ControlAckedFunc func(vaultID uuid.UUID, peerURL string, seq int64)
)

// RelayDeps is everything a Session needs to apply and read note state.
type RelayDeps struct {
	Registry *crdt.Registry
	Rooms    DocAuthority
	Notes    NoteMetaRepo
	Mirror   MirrorFunc
	Delete   DeleteFunc
	Move     MoveFunc
	Log      zerolog.Logger

	ControlCurrent ControlCurrentFunc
	ControlApply   ControlApplyFunc
	ControlAcked   ControlAckedFunc

	// PeerCaps is the home-side capability ceiling of a follower link
	// (G3): what home's control state grants that server's users.
	// Implemented by Service.PeerCapabilities. nil denies every write a
	// follower relays (fail closed).
	PeerCaps PeerCapsFunc
	// Audit records relay security events (denied follower writes,
	// mirror violations). nil-safe.
	Audit RelayAuditFunc
	// Tombstone reports the latest tombstone of a note id and the epoch
	// of the history it ended (G2). nil disables tombstone-aware
	// reconciliation.
	Tombstone TombstoneFunc
}

// TombstoneFunc returns the epoch of the latest tombstone of noteID ("" when
// it predates epoch tracking) and whether one exists.
type TombstoneFunc func(ctx context.Context, vaultID uuid.UUID, noteID string) (epoch string, found bool, err error)

// PeerCapsFunc returns the capability ceiling of the link to peerURL.
type PeerCapsFunc func(ctx context.Context, vaultID uuid.UUID, peerURL string) domain.CapabilitySet

// RelayAuditFunc records a relay audit event. Must not block for long.
type RelayAuditFunc func(ctx context.Context, vaultID uuid.UUID, action string, payload map[string]any)

// ---- Links: the live-session registry -------------------------------------------

// Links tracks active relay sessions and is the fan-out target for the
// registry persist hook and the note-created notifier.
type Links struct {
	mu      sync.RWMutex
	byVault map[uuid.UUID][]*Session

	deps    RelayDeps
	rootCtx context.Context
}

func NewLinks(rootCtx context.Context, deps RelayDeps) *Links {
	if deps.Registry == nil || deps.Notes == nil || deps.Mirror == nil {
		panic("federation.NewLinks: missing dependency")
	}
	if rootCtx == nil {
		rootCtx = context.Background()
	}
	return &Links{byVault: map[uuid.UUID][]*Session{}, deps: deps, rootCtx: rootCtx}
}

func (l *Links) add(s *Session) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.byVault[s.vaultID] = append(l.byVault[s.vaultID], s)
}

func (l *Links) remove(s *Session) {
	l.mu.Lock()
	defer l.mu.Unlock()
	sessions := l.byVault[s.vaultID]
	for i, existing := range sessions {
		if existing == s {
			l.byVault[s.vaultID] = append(sessions[:i], sessions[i+1:]...)
			break
		}
	}
	if len(l.byVault[s.vaultID]) == 0 {
		delete(l.byVault, s.vaultID)
	}
}

func (l *Links) sessionsFor(vaultID uuid.UUID) []*Session {
	l.mu.RLock()
	defer l.mu.RUnlock()
	out := make([]*Session, len(l.byVault[vaultID]))
	copy(out, l.byVault[vaultID])
	return out
}

// OnPersist is the crdt.Registry hook: forward every persisted update to all
// links on the vault except the one it arrived on. Non-blocking by
// construction (Session.send drops the link rather than waiting).
func (l *Links) OnPersist(vaultID uuid.UUID, noteID string, update []byte, originKind string) {
	for _, s := range l.sessionsFor(vaultID) {
		if s.originKind() == originKind {
			continue // don't echo an update back to its source link
		}
		s.send(EncodeNoteSync(noteID, wsync.EncodeSyncUpdate(update)))
	}
}

// NoteCreated is the notes.Service notifier: announce a brand-new note and
// push its full initial state to every link on the vault. (Note creation
// seeds the CRDT via InitFromText, which bypasses PersistChange — hence a
// dedicated hook.)
func (l *Links) NoteCreated(vaultID uuid.UUID, noteID, path, title string) {
	sessions := l.sessionsFor(vaultID)
	if len(sessions) == 0 {
		return
	}
	var state []byte
	var err error
	if l.deps.Rooms != nil {
		err = l.deps.Rooms.View(l.rootCtx, vaultID, noteID, func(doc *crdt.Doc) error {
			var err error
			state, err = doc.EncodeStateAsUpdate()
			return err
		})
	} else {
		var doc *crdt.Doc
		if doc, err = l.deps.Registry.LoadDoc(l.rootCtx, vaultID, noteID); err == nil {
			state, err = doc.EncodeStateAsUpdate()
			doc.Close()
		}
	}
	if err != nil {
		l.deps.Log.Warn().Err(err).Str("note", noteID).Msg("federation: note-created load")
		return
	}
	// The announce carries our epoch so the peer's row names the same
	// CRDT history as the state that follows (protocol §12).
	meta := NoteMeta{ID: noteID, Path: path, Title: title}
	if n, err := l.deps.Notes.Get(l.rootCtx, vaultID, noteID); err == nil {
		meta.Epoch = n.CRDTEpoch
	}
	announce := EncodeNoteAnnounce(meta)
	update := EncodeNoteSync(noteID, wsync.EncodeSyncUpdate(state))
	for _, s := range sessions {
		s.send(announce)
		s.send(update)
	}
}

// NoteDeleted is the notes.Service notifier for local deletions: propagate
// to every link on the vault.
func (l *Links) NoteDeleted(vaultID uuid.UUID, noteID string) {
	l.fanDelete(vaultID, noteID, nil)
}

// NoteMoved is the notes.Service notifier for local renames/moves.
func (l *Links) NoteMoved(vaultID uuid.UUID, noteID, newPath, newTitle string) {
	l.fanMove(vaultID, NoteMeta{ID: noteID, Path: newPath, Title: newTitle}, nil)
}

func (l *Links) fanMove(vaultID uuid.UUID, m NoteMeta, except *Session) {
	frame := EncodeNoteMove(m)
	for _, s := range l.sessionsFor(vaultID) {
		if s == except {
			continue
		}
		s.send(frame)
	}
}

// PushControl fans a fresh signed control document to every home-role link
// on the vault (only home authors control state).
func (l *Links) PushControl(vaultID uuid.UUID, state, sig []byte) {
	frame := EncodeControlState(state, sig)
	for _, s := range l.sessionsFor(vaultID) {
		if s.role == "home" {
			// The new document may grant or take away capabilities of
			// the link's users: refresh the ceiling before anything else
			// arrives on it.
			s.setCaps(PeerCeiling(state, s.peerURL))
			s.send(frame)
		}
	}
}

func (l *Links) fanDelete(vaultID uuid.UUID, noteID string, except *Session) {
	frame := EncodeNoteDelete(noteID)
	for _, s := range l.sessionsFor(vaultID) {
		if s == except {
			continue
		}
		s.send(frame)
	}
}

// ClosePeer drops every session to peerURL for the vault (federation revoke).
func (l *Links) ClosePeer(vaultID uuid.UUID, peerURL string) {
	for _, s := range l.sessionsFor(vaultID) {
		if s.peerURL == peerURL {
			s.close()
		}
	}
}

// ---- Session ---------------------------------------------------------------------

// Session is one live relay link. Symmetric after the handshake; role only
// decides who sends the opening manifest.
type Session struct {
	conn    wsConn
	vaultID uuid.UUID
	peerURL string
	role    string // "home" | "follower"

	links  *Links
	deps   RelayDeps
	ctx    context.Context
	sendCh chan []byte
	done   chan struct{}
	once   sync.Once

	// step1Sent dedupes proactive Step1s per note per connection.
	step1Mu   sync.Mutex
	step1Sent map[string]bool

	// Home side (G3): the link's capability ceiling, refreshed on every
	// control-state push. nil until loaded = no capability.
	caps atomic.Pointer[domain.CapabilitySet]
	// guardMu guards the per-connection authorization bookkeeping.
	guardMu sync.Mutex
	// denied dedupes "peer_denied" audit entries per (frame kind, note).
	denied map[string]bool
	// createdHere lists notes this link created (announce with
	// note.create): their first content may land without note.edit.
	createdHere map[string]bool
}

// NewSession builds a relay session; call Run to drive it.
func (l *Links) NewSession(ctx context.Context, conn wsConn, vaultID uuid.UUID, peerURL, role string) *Session {
	if ctx == nil {
		ctx = l.rootCtx
	}
	// Bound every inbound WS message regardless of which side created the
	// connection (home handler or follower dialer).
	if rl, ok := conn.(interface{ SetReadLimit(int64) }); ok {
		rl.SetReadLimit(maxRelayMessageBytes)
	}
	return &Session{
		conn:        conn,
		vaultID:     vaultID,
		peerURL:     peerURL,
		role:        role,
		links:       l,
		deps:        l.deps,
		ctx:         ctx,
		sendCh:      make(chan []byte, sendBuffer),
		done:        make(chan struct{}),
		step1Sent:   map[string]bool{},
		denied:      map[string]bool{},
		createdHere: map[string]bool{},
	}
}

func (s *Session) originKind() string { return OriginFederationPrefix + s.peerURL }

// send queues a frame; a full queue closes the session (slow peer).
func (s *Session) send(frame []byte) {
	select {
	case s.sendCh <- frame:
	case <-s.done:
	default:
		s.deps.Log.Warn().Str("peer", s.peerURL).Msg("federation: send buffer full, dropping link")
		s.close()
	}
}

func (s *Session) close() {
	s.once.Do(func() {
		close(s.done)
		_ = s.conn.Close()
	})
}

// Run drives the session until the connection drops or ctx is cancelled.
// Blocking; the caller owns reconnection policy.
func (s *Session) Run() error {
	s.links.add(s)
	defer s.links.remove(s)
	defer s.close()

	go s.writePump()
	go func() {
		select {
		case <-s.ctx.Done():
			s.close()
		case <-s.done:
		}
	}()

	if s.role == "home" {
		s.loadCaps()
		if err := s.sendOpening(); err != nil {
			return err
		}
	}
	return s.readLoop()
}

func (s *Session) writePump() {
	for {
		select {
		case frame := <-s.sendCh:
			if err := s.conn.WriteMessage(binaryMessage, frame); err != nil {
				s.close()
				return
			}
		case <-s.done:
			return
		}
	}
}

// sendOpening (home): manifest of every note, a Step1 per note so the
// follower can send us what we're missing while we send Step2s with what
// they're missing, then the current signed control state (F3).
func (s *Session) sendOpening() error {
	metas, err := s.listAllNotes()
	if err != nil {
		return err
	}
	s.send(EncodeManifest(metas))
	for _, m := range metas {
		s.sendStep1(m.ID)
	}
	if s.deps.ControlCurrent != nil {
		if state, sig, ok := s.deps.ControlCurrent(s.ctx, s.vaultID); ok {
			s.send(EncodeControlState(state, sig))
		}
	}
	return nil
}

func (s *Session) listAllNotes() ([]NoteMeta, error) {
	const page = 500
	var out []NoteMeta
	for offset := 0; ; offset += page {
		batch, err := s.deps.Notes.ListForVault(s.ctx, s.vaultID, page, offset)
		if err != nil {
			return nil, err
		}
		for _, n := range batch {
			out = append(out, NoteMeta{ID: n.ID, Path: n.Path, Title: n.Title, Epoch: n.CRDTEpoch})
		}
		if len(batch) < page {
			return out, nil
		}
	}
}

func (s *Session) readLoop() error {
	for {
		_, data, err := s.conn.ReadMessage()
		if err != nil {
			select {
			case <-s.done:
				return nil // deliberate close
			default:
				return err
			}
		}
		frame, err := DecodeFrame(data)
		if err != nil {
			return fmt.Errorf("federation: bad frame from %s: %w", s.peerURL, err)
		}
		if err := s.handleFrame(frame); err != nil {
			s.deps.Log.Warn().Err(err).Str("peer", s.peerURL).Msg("federation: frame handling")
		}
	}
}

func (s *Session) handleFrame(f Frame) error {
	switch f.Type {
	case frameManifest:
		// Only home sends a manifest. A follower that sends one would
		// otherwise make home create every listed note (G3).
		if s.role != "follower" {
			s.deny(f, "", "manifest_from_follower")
			return nil
		}
		// Follower side: make sure every home note exists locally, then
		// Step1 each so home sends us what we lack. Then advertise the
		// notes home doesn't know about.
		known := map[string]bool{}
		for _, m := range f.Manifest {
			known[m.ID] = true
			if s.deletedOffline(m) {
				// G2: deleted here while the link was down. Tell home
				// (it authorizes, G3) instead of recreating it locally.
				s.send(EncodeNoteDelete(m.ID))
				continue
			}
			if err := s.ensureNote(m); err != nil {
				s.deps.Log.Warn().Err(err).Str("note", m.ID).Msg("federation: manifest ensure")
				continue
			}
			s.sendStep1(m.ID)
		}
		locals, err := s.listAllNotes()
		if err != nil {
			return err
		}
		for _, m := range locals {
			if known[m.ID] {
				continue
			}
			s.send(EncodeNoteAnnounce(m))
			s.sendStep1(m.ID)
		}
		return nil

	case frameNoteAnnounce:
		if s.role == "home" {
			if _, err := s.deps.Notes.Get(s.ctx, s.vaultID, f.Note.ID); err != nil {
				if !errors.Is(err, domain.ErrNotFound) {
					return err
				}
				// G2: a follower that was offline while home deleted the
				// note re-announces it. Same history as the one home
				// ended: answer with the delete instead of recreating it.
				if s.deletedHere(f.Note) {
					s.deps.Log.Info().Str("peer", s.peerURL).Str("note", f.Note.ID).
						Msg("federation: refused to resurrect a deleted note")
					s.send(EncodeNoteDelete(f.Note.ID))
					return nil
				}
				if !s.authorize(domain.CapNoteCreate, f, f.Note.ID) {
					return nil
				}
				s.markCreatedHere(f.Note.ID)
			}
		}
		if err := s.ensureNote(f.Note); err != nil {
			return err
		}
		s.sendStep1(f.Note.ID)
		return nil

	case frameNoteDelete:
		if err := validateNoteID(f.NoteID); err != nil {
			return err
		}
		if s.role == "home" && !s.authorize(domain.CapNoteDelete, f, f.NoteID) {
			// Home is authoritative: give the peer its copy back.
			s.reannounce(f.NoteID)
			return nil
		}
		if s.deps.Delete == nil {
			return nil
		}
		if err := s.deps.Delete(s.ctx, s.vaultID, f.NoteID); err != nil {
			if errors.Is(err, domain.ErrNotFound) {
				return nil // idempotent: already gone locally
			}
			return err
		}
		// Relay onward to the vault's other links, skipping the source.
		s.links.fanDelete(s.vaultID, f.NoteID, s)
		return nil

	case frameNoteMove:
		if err := validateNoteID(f.Note.ID); err != nil {
			return err
		}
		if err := validateRelPath(f.Note.Path); err != nil {
			return err
		}
		if s.role == "home" {
			cur, err := s.deps.Notes.Get(s.ctx, s.vaultID, f.Note.ID)
			if err != nil {
				if errors.Is(err, domain.ErrNotFound) {
					return nil
				}
				return err
			}
			// A path change is a move; a title-only change is an edit
			// (the REST surface draws the same line).
			need := domain.CapNoteEdit
			if cur.Path != f.Note.Path {
				need = domain.CapNoteMove
			}
			if !s.authorize(need, f, f.Note.ID) {
				s.send(EncodeNoteMove(NoteMeta{ID: cur.ID, Path: cur.Path, Title: cur.Title}))
				return nil
			}
		}
		if s.deps.Move == nil {
			return nil
		}
		if err := s.deps.Move(s.ctx, s.vaultID, f.Note.ID, f.Note.Path, f.Note.Title); err != nil {
			if errors.Is(err, domain.ErrNotFound) {
				return nil // note never landed here; announce will bring it
			}
			return err
		}
		s.links.fanMove(s.vaultID, f.Note, s)
		return nil

	case frameControlState:
		// Only followers accept control state, and only from their home.
		if s.role != "follower" || s.deps.ControlApply == nil {
			return nil
		}
		seq, err := s.deps.ControlApply(s.ctx, s.vaultID, s.peerURL, f.Payload, f.Sig)
		if err != nil {
			// Verification failure means a hostile or misconfigured
			// peer: drop the link rather than run on unverified state.
			return fmt.Errorf("federation: control state rejected: %w", err)
		}
		s.send(EncodeControlAck(seq))
		return nil

	case frameControlAck:
		if s.role == "home" && s.deps.ControlAcked != nil {
			s.deps.ControlAcked(s.vaultID, s.peerURL, f.Seq)
		}
		return nil

	case frameNoteSync:
		if err := validateNoteID(f.NoteID); err != nil {
			return err
		}
		msg, err := wsync.DecodeMessage(f.Payload)
		if err != nil {
			return err
		}
		if msg.Type != wsync.MessageSync {
			return nil // awareness etc. not relayed in F2
		}
		switch msg.SyncSub {
		case wsync.SyncStep1:
			return s.handleStep1(f.NoteID, msg.Body)
		case wsync.SyncStep2, wsync.SyncUpdate:
			if s.role == "home" && !s.authorizeContent(f, msg.Body) {
				return nil
			}
			return s.applyRemote(f.NoteID, msg.Body)
		}
		return nil

	default:
		return nil
	}
}

// ---- tombstone-aware reconciliation (G2) ------------------------------------------

// lastTombstone wraps deps.Tombstone (nil-safe, errors = no tombstone).
func (s *Session) lastTombstone(noteID string) (string, bool) {
	if s.deps.Tombstone == nil {
		return "", false
	}
	epoch, found, err := s.deps.Tombstone(s.ctx, s.vaultID, noteID)
	if err != nil {
		s.deps.Log.Warn().Err(err).Str("note", noteID).Msg("federation: tombstone lookup")
		return "", false
	}
	return epoch, found
}

// deletedHere (home side) reports whether an announced note is one this
// server deleted: a tombstone of the same history. A tombstone or an
// announce without an epoch (written before epochs were tracked) counts
// as the same history: refusing a resurrection beats losing an erasure.
func (s *Session) deletedHere(m NoteMeta) bool {
	epoch, found := s.lastTombstone(m.ID)
	if !found {
		return false
	}
	return epoch == "" || m.Epoch == "" || epoch == m.Epoch
}

// deletedOffline (follower side) reports whether a note home still lists
// was deleted here, in the very history home holds. Only an exact epoch
// match counts: home may have recreated the id since.
func (s *Session) deletedOffline(m NoteMeta) bool {
	if s.role != "follower" || m.Epoch == "" {
		return false
	}
	if _, err := s.deps.Notes.Get(s.ctx, s.vaultID, m.ID); err == nil {
		return false
	}
	epoch, found := s.lastTombstone(m.ID)
	return found && epoch == m.Epoch
}

// reannounce sends the peer home's copy of a note (metadata + full state)
// after refusing its delete.
func (s *Session) reannounce(noteID string) {
	n, err := s.deps.Notes.Get(s.ctx, s.vaultID, noteID)
	if err != nil {
		return
	}
	state, err := s.withDoc(noteID, func(doc *crdt.Doc) ([]byte, error) {
		return doc.EncodeStateAsUpdate()
	})
	if err != nil {
		return
	}
	s.send(EncodeNoteAnnounce(NoteMeta{ID: n.ID, Path: n.Path, Title: n.Title, Epoch: n.CRDTEpoch}))
	s.send(EncodeNoteSync(noteID, wsync.EncodeSyncUpdate(state)))
}

// ---- home-side authorization of follower frames (G3) ----------------------------

// loadCaps reads the link's ceiling from home's control state.
func (s *Session) loadCaps() {
	var caps domain.CapabilitySet
	if s.deps.PeerCaps != nil {
		caps = s.deps.PeerCaps(s.ctx, s.vaultID, s.peerURL)
	}
	s.setCaps(caps)
}

func (s *Session) setCaps(caps domain.CapabilitySet) {
	if caps == nil {
		caps = domain.CapabilitySet{}
	}
	s.caps.Store(&caps)
}

func (s *Session) peerHas(c domain.Capability) bool {
	caps := s.caps.Load()
	return caps != nil && caps.Has(c)
}

func (s *Session) markCreatedHere(noteID string) {
	s.guardMu.Lock()
	s.createdHere[noteID] = true
	s.guardMu.Unlock()
}

func (s *Session) wasCreatedHere(noteID string) bool {
	s.guardMu.Lock()
	defer s.guardMu.Unlock()
	return s.createdHere[noteID]
}

// authorize reports whether the follower link may do what f asks on home.
// A refusal drops the frame (the link stays up: an offline edit made
// before a role change would otherwise make the link flap forever) and is
// audited once per (frame kind, note) per connection.
func (s *Session) authorize(c domain.Capability, f Frame, noteID string) bool {
	if s.peerHas(c) {
		return true
	}
	s.deny(f, noteID, "capability_missing:"+string(c))
	return false
}

// authorizeContent gates a Step2/Update from a follower: note.edit, or
// note.create for the first content of a note this link just created. A
// no-op update (the [0,0] Step2 of an up-to-date peer, or data home
// already holds) passes silently: it changes nothing.
func (s *Session) authorizeContent(f Frame, update []byte) bool {
	if s.peerHas(domain.CapNoteEdit) {
		return true
	}
	if s.wasCreatedHere(f.NoteID) && s.peerHas(domain.CapNoteCreate) {
		return true
	}
	if s.isNoop(f.NoteID, update) {
		return false
	}
	s.deny(f, f.NoteID, "capability_missing:"+string(domain.CapNoteEdit))
	return false
}

// isNoop reports whether update would change nothing in the note's
// current state. Evaluated on a throwaway copy, never on the live doc.
func (s *Session) isNoop(noteID string, update []byte) bool {
	if len(update) == 0 || (len(update) == 2 && update[0] == 0 && update[1] == 0) {
		return true
	}
	state, err := s.withDoc(noteID, func(doc *crdt.Doc) ([]byte, error) {
		return doc.EncodeStateAsUpdate()
	})
	if err != nil {
		return false
	}
	probe, err := crdt.LoadDoc(state)
	if err != nil {
		return false
	}
	defer probe.Close()
	changed, err := probe.ApplyUpdateChanged(update)
	return err == nil && !changed
}

func frameKind(t uint64) string {
	switch t {
	case frameManifest:
		return "manifest"
	case frameNoteSync:
		return "note_sync"
	case frameNoteAnnounce:
		return "announce"
	case frameNoteDelete:
		return "delete"
	case frameNoteMove:
		return "move"
	default:
		return fmt.Sprintf("frame_%d", t)
	}
}

// deny logs and audits (deduplicated) a refused follower frame.
func (s *Session) deny(f Frame, noteID, reason string) {
	kind := frameKind(f.Type)
	key := kind + "|" + noteID + "|" + reason
	s.guardMu.Lock()
	first := !s.denied[key]
	s.denied[key] = true
	s.guardMu.Unlock()
	if !first {
		return
	}
	s.deps.Log.Warn().Str("peer", s.peerURL).Str("vault", s.vaultID.String()).
		Str("frame", kind).Str("note", noteID).Str("reason", reason).
		Msg("federation: follower frame denied")
	if s.deps.Audit != nil {
		s.deps.Audit(s.ctx, s.vaultID, domain.ActionFederationPeerDenied, map[string]any{
			"peer_url": s.peerURL,
			"frame":    kind,
			"note_id":  noteID,
			"reason":   reason,
		})
	}
}

// sendStep1 advertises our state vector for a note, once per connection.
func (s *Session) sendStep1(noteID string) {
	s.step1Mu.Lock()
	already := s.step1Sent[noteID]
	s.step1Sent[noteID] = true
	s.step1Mu.Unlock()
	if already {
		return
	}
	sv, err := s.withDoc(noteID, func(doc *crdt.Doc) ([]byte, error) {
		return doc.StateVectorV1()
	})
	if err != nil {
		s.deps.Log.Warn().Err(err).Str("note", noteID).Msg("federation: step1 state vector")
		return
	}
	s.send(EncodeNoteSync(noteID, wsync.EncodeSyncStep1(sv)))
}

// handleStep1 answers the peer's state vector with the diff they lack.
func (s *Session) handleStep1(noteID string, sv []byte) error {
	// Never answer for a note this side does not hold: loading it would
	// hand out an empty (or lazily seeded) doc for an id the peer made up.
	if _, err := s.deps.Notes.Get(s.ctx, s.vaultID, noteID); err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return nil
		}
		return err
	}
	diff, err := s.withDoc(noteID, func(doc *crdt.Doc) ([]byte, error) {
		return doc.EncodeDiffSince(sv)
	})
	if err != nil {
		return err
	}
	if len(diff) > 0 {
		s.send(EncodeNoteSync(noteID, wsync.EncodeSyncStep2(diff)))
	}
	return nil
}

// applyRemote merges a remote update into local state: live room when one
// exists (persists, broadcasts to local clients, schedules mirror), cold
// path otherwise (persist + immediate mirror). Both persist via
// PersistChange, so Links.OnPersist relays it onward to other links.
func (s *Session) applyRemote(noteID string, update []byte) error {
	if len(update) == 0 {
		return nil
	}
	if _, err := s.deps.Notes.Get(s.ctx, s.vaultID, noteID); err != nil {
		return fmt.Errorf("federation: update for unknown note %q: %w", noteID, err)
	}
	origin := s.originKind()
	if s.deps.Rooms != nil {
		_, err := s.deps.Rooms.ApplyUpdate(s.ctx, s.vaultID, noteID, update, wsync.ApplyOptions{
			Origin: origin, Mirror: wsync.MirrorDebounced,
		})
		return err
	}
	doc, err := s.deps.Registry.LoadDoc(s.ctx, s.vaultID, noteID)
	if err != nil {
		return err
	}
	defer doc.Close()
	if err := doc.ApplyUpdate(update); err != nil {
		return err
	}
	if err := s.deps.Registry.PersistChange(s.ctx, s.vaultID, noteID, update, uuid.Nil, origin, doc); err != nil {
		return err
	}
	text, err := doc.Text()
	if err != nil {
		return err
	}
	return s.deps.Mirror(s.ctx, s.vaultID, noteID, text)
}

// withDoc runs fn against the note's doc — the live room's shared doc when
// one exists, else a freshly-loaded (and closed) one.
func (s *Session) withDoc(noteID string, fn func(*crdt.Doc) ([]byte, error)) ([]byte, error) {
	if s.deps.Rooms != nil {
		var out []byte
		err := s.deps.Rooms.View(s.ctx, s.vaultID, noteID, func(doc *crdt.Doc) error {
			var err error
			out, err = fn(doc)
			return err
		})
		return out, err
	}
	doc, err := s.deps.Registry.LoadDoc(s.ctx, s.vaultID, noteID)
	if err != nil {
		return nil, err
	}
	defer doc.Close()
	return fn(doc)
}

// ensureNote creates the local metadata row for a remote-announced note.
// The file lands on first mirrored update.
func (s *Session) ensureNote(m NoteMeta) error {
	if err := validateNoteID(m.ID); err != nil {
		return err
	}
	if err := validateRelPath(m.Path); err != nil {
		return err
	}
	if _, err := s.deps.Notes.Get(s.ctx, s.vaultID, m.ID); err == nil {
		return nil
	} else if !errors.Is(err, domain.ErrNotFound) {
		return err
	}
	now := time.Now().UTC()
	// Adopt the sender's epoch (when it sent one): the doc this row will
	// hold is the sender's history, relayed. Existing rows keep theirs.
	return s.deps.Notes.Upsert(s.ctx, domain.Note{
		ID:        m.ID,
		VaultID:   s.vaultID,
		Path:      m.Path,
		Title:     m.Title,
		CreatedAt: now,
		UpdatedAt: now,
		CRDTEpoch: m.Epoch,
	})
}

func validateNoteID(id string) error {
	if id == "" || len(id) > 256 || strings.ContainsAny(id, "/\\") || strings.HasPrefix(id, ".") {
		return fmt.Errorf("%w: invalid note id %q", domain.ErrValidation, id)
	}
	return nil
}

// validateRelPath gates peer-supplied note paths with the shared canonical
// note-path policy (.md only, no dot/hidden segments — a peer must not be
// able to target .lumi/vault.yaml or similar). Peers send canonical paths,
// so no normalisation is attempted. fs.SafeJoin remains the authoritative
// containment check on every disk access.
func validateRelPath(p string) error {
	return domain.ValidateNotePath(p)
}
