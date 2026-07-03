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

// RoomLookup finds a live wsync room so relayed updates reach connected
// clients immediately. nil-safe: without it the relay still persists and
// mirrors, clients catch up on next open.
type RoomLookup interface {
	RoomIfActive(vaultID uuid.UUID, noteID string) *wsync.Room
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
	Rooms    RoomLookup
	Notes    NoteMetaRepo
	Mirror   MirrorFunc
	Delete   DeleteFunc
	Move     MoveFunc
	Log      zerolog.Logger

	ControlCurrent ControlCurrentFunc
	ControlApply   ControlApplyFunc
	ControlAcked   ControlAckedFunc
}

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
	doc, err := l.deps.Registry.LoadDoc(l.rootCtx, vaultID, noteID)
	if err != nil {
		l.deps.Log.Warn().Err(err).Str("note", noteID).Msg("federation: note-created load")
		return
	}
	state, err := doc.EncodeStateAsUpdate()
	doc.Close()
	if err != nil {
		return
	}
	announce := EncodeNoteAnnounce(NoteMeta{ID: noteID, Path: path, Title: title})
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
}

// NewSession builds a relay session; call Run to drive it.
func (l *Links) NewSession(ctx context.Context, conn wsConn, vaultID uuid.UUID, peerURL, role string) *Session {
	if ctx == nil {
		ctx = l.rootCtx
	}
	return &Session{
		conn:      conn,
		vaultID:   vaultID,
		peerURL:   peerURL,
		role:      role,
		links:     l,
		deps:      l.deps,
		ctx:       ctx,
		sendCh:    make(chan []byte, sendBuffer),
		done:      make(chan struct{}),
		step1Sent: map[string]bool{},
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
			out = append(out, NoteMeta{ID: n.ID, Path: n.Path, Title: n.Title})
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
		// Follower side: make sure every home note exists locally, then
		// Step1 each so home sends us what we lack. Then advertise the
		// notes home doesn't know about.
		known := map[string]bool{}
		for _, m := range f.Manifest {
			known[m.ID] = true
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
		if err := s.ensureNote(f.Note); err != nil {
			return err
		}
		s.sendStep1(f.Note.ID)
		return nil

	case frameNoteDelete:
		if err := validateNoteID(f.NoteID); err != nil {
			return err
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
			return s.applyRemote(f.NoteID, msg.Body)
		}
		return nil

	default:
		return nil
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
		if room := s.deps.Rooms.RoomIfActive(s.vaultID, noteID); room != nil {
			return room.ApplyAndBroadcastFederation(update, origin)
		}
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
		if room := s.deps.Rooms.RoomIfActive(s.vaultID, noteID); room != nil {
			return fn(room.Doc())
		}
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
	return s.deps.Notes.Upsert(s.ctx, domain.Note{
		ID:        m.ID,
		VaultID:   s.vaultID,
		Path:      m.Path,
		Title:     m.Title,
		CreatedAt: now,
		UpdatedAt: now,
	})
}

func validateNoteID(id string) error {
	if id == "" || len(id) > 256 || strings.ContainsAny(id, "/\\") || strings.HasPrefix(id, ".") {
		return fmt.Errorf("%w: invalid note id %q", domain.ErrValidation, id)
	}
	return nil
}

// validateRelPath is a first-line guard on peer-supplied paths; the fs
// layer's SafeJoin remains the authoritative check on every disk access.
func validateRelPath(p string) error {
	if p == "" || len(p) > 1024 || strings.HasPrefix(p, "/") || strings.HasPrefix(p, "\\") {
		return fmt.Errorf("%w: invalid note path %q", domain.ErrValidation, p)
	}
	for _, seg := range strings.FieldsFunc(p, func(r rune) bool { return r == '/' || r == '\\' }) {
		if seg == ".." {
			return fmt.Errorf("%w: invalid note path %q", domain.ErrValidation, p)
		}
	}
	return nil
}
