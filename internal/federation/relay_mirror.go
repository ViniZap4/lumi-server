// Relay behaviour of mirror links (docs/SPEC-ESPELHO-SELADO.md §A4, §A7).
//
// Home side: send only. The opening is the manifest, frontmatter, control
// state and the vault head (frameChangesEnd); no Step1s. The only content
// input home accepts is a Step1 (answered with the diff). A Step2/Update
// that would change anything, or any announce/delete/move/meta2/manifest,
// closes the link and is audited as federation.mirror_violation.
//
// Mirror side: apply what home sends, never author. A manifest makes every
// listed note exist (path, title and lineage as home has them), deletes
// every local note home no longer lists, then backfills with a window of
// at most backfillWindow Step1s in flight. frameChangesEnd(seq) is
// acknowledged with frameMirrorAck(seq) once everything before it is
// applied (after the backfill when one runs).
package federation

import (
	"errors"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/ViniZap4/lumi-server/internal/domain"
	"github.com/ViniZap4/lumi-server/internal/metrics"
	"github.com/ViniZap4/lumi-server/internal/wsync"
)

const (
	// backfillWindow bounds the Step1s a mirror has in flight (§A7.1).
	backfillWindow = 32
	// backfillStepTimeout frees a window slot whose Step2 never came.
	backfillStepTimeout = 30 * time.Second
	// headInterval is how often home re-announces its head to a mirror
	// when it moved (the ack/lag granularity).
	headInterval = 2 * time.Second
)

// ---- home side -------------------------------------------------------------------

// homeMirrorFrame handles a frame a mirror sent. handled=false lets the
// shared path process it (Step1, control ack).
func (s *Session) homeMirrorFrame(f Frame) (bool, error) {
	switch f.Type {
	case frameControlAck:
		return false, nil
	case frameMirrorAck:
		if s.deps.MirrorAcked != nil {
			s.deps.MirrorAcked(s.vaultID, s.peerURL, f.Seq)
		}
		return true, nil
	case frameResumeFrom:
		if s.expectResume {
			select {
			case s.resumeCh <- f.Seq:
			default: // only the first one counts
			}
		}
		return true, nil
	case frameNoteSync:
		if err := validateNoteID(f.NoteID); err != nil {
			return true, err
		}
		msg, err := wsync.DecodeMessage(f.Payload)
		if err != nil {
			return true, err
		}
		if msg.Type != wsync.MessageSync {
			return true, nil
		}
		switch msg.SyncSub {
		case wsync.SyncStep1:
			return false, nil // the one input a mirror may send: answered with the diff
		case wsync.SyncStep2, wsync.SyncUpdate:
			if s.isNoop(f.NoteID, msg.Body) {
				return true, nil
			}
			s.mirrorViolation(f, f.NoteID)
			return true, nil
		}
		return true, nil
	case frameManifest, frameNoteAnnounce, frameNoteDelete, frameNoteMove, frameNoteMeta2:
		noteID := f.NoteID
		if noteID == "" {
			noteID = f.Note.ID
		}
		s.mirrorViolation(f, noteID)
		return true, nil
	default:
		return true, nil
	}
}

// mirrorViolation closes the link and reports a mirror that tried to
// author content.
func (s *Session) mirrorViolation(f Frame, noteID string) {
	kind := frameKind(f.Type)
	s.deps.Log.Warn().Str("peer", s.peerURL).Str("vault", s.vaultID.String()).
		Str("frame", kind).Str("note", noteID).Msg("federation: mirror sent content, closing link")
	metrics.MirrorViolation.Inc()
	s.close()
	if s.deps.MirrorViolation != nil {
		// Async: three violations revoke the link, which re-enters the
		// relay (StopLink) and must not run on the read loop.
		go s.deps.MirrorViolation(s.ctx, s.vaultID, s.peerURL, kind, noteID)
	}
}

// sendHead tells the mirror home's current vault seq (after everything
// already queued). force sends even when unchanged.
func (s *Session) sendHead(force bool) {
	if s.deps.Head == nil {
		return
	}
	head, err := s.deps.Head(s.ctx, s.vaultID)
	if err != nil {
		return
	}
	s.bf.mu.Lock()
	changed := head != s.bf.lastHeadSent
	s.bf.lastHeadSent = head
	s.bf.mu.Unlock()
	if changed || force {
		s.send(EncodeChangesEnd(head))
	}
}

// headLoop re-announces the head while the mirror link lives.
func (s *Session) headLoop() {
	t := time.NewTicker(headInterval)
	defer t.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-t.C:
			s.sendHead(false)
		}
	}
}

// ---- mirror side -----------------------------------------------------------------

// backfill is the mirror-side catch-up state of one session.
type backfill struct {
	mu           sync.Mutex
	active       bool
	slots        chan struct{}
	inflight     map[string]*time.Timer
	total        int
	done         int
	pendingHead  int64
	havePending  bool
	lastHeadSent int64 // home side: last frameChangesEnd value
	// resuming: the mirror asked for an incremental resume and collects
	// the notes home announces until frameChangesEnd.
	resuming  bool
	resumeIDs []string
}

// BackfillProgress is the catch-up state of a mirror link.
type BackfillProgress struct {
	Active bool
	Synced int
	Total  int
}

// mirrorFrame handles a frame home sent to this mirror.
func (s *Session) mirrorFrame(f Frame) (bool, error) {
	switch f.Type {
	case frameManifest:
		return true, s.mirrorManifest(f)
	case frameChangesEnd:
		s.bf.mu.Lock()
		resumed, ids := s.bf.resuming, s.bf.resumeIDs
		s.bf.resuming, s.bf.resumeIDs = false, nil
		s.bf.mu.Unlock()
		if resumed {
			// End of an incremental resume: fetch the changed notes
			// under the same window as a full backfill; the head is
			// acknowledged once they are all applied.
			s.startBackfill(ids)
		}
		s.onHomeHead(f.Seq)
		return true, nil
	case frameNoteAnnounce:
		if err := s.mirrorEnsure(f.Note); err != nil {
			return true, err
		}
		s.bf.mu.Lock()
		if s.bf.resuming {
			s.bf.resumeIDs = append(s.bf.resumeIDs, f.Note.ID)
			s.bf.mu.Unlock()
			return true, nil
		}
		s.bf.mu.Unlock()
		s.sendStep1(f.Note.ID)
		return true, nil
	case frameNoteSync:
		if err := validateNoteID(f.NoteID); err != nil {
			return true, err
		}
		msg, err := wsync.DecodeMessage(f.Payload)
		if err != nil {
			return true, err
		}
		if msg.Type != wsync.MessageSync {
			return true, nil
		}
		switch msg.SyncSub {
		case wsync.SyncStep1:
			return true, nil // home never needs anything from a mirror
		case wsync.SyncStep2:
			err := s.applyRemote(f.NoteID, msg.Body)
			if err == nil && len(f.SV) > 0 {
				s.checkMirrorDivergence(f.NoteID, f.SV)
			}
			s.backfillRelease(f.NoteID)
			return true, err
		case wsync.SyncUpdate:
			return true, s.applyRemote(f.NoteID, msg.Body)
		}
		return true, nil
	case frameMirrorAck, frameResumeFrom:
		return true, nil
	default:
		// announce / delete / move / meta2 / control state: the shared
		// path applies them (fan-out is skipped: a mirror has no other
		// link to send to).
		return false, nil
	}
}

// mirrorManifest reconciles the copy with home's full listing.
func (s *Session) mirrorManifest(f Frame) error {
	s.peerProto.Store(int32(f.Proto))
	// Home answered the resume with a full listing (cursor below its
	// tombstone floor, or a home that predates resume).
	s.bf.mu.Lock()
	s.bf.resuming, s.bf.resumeIDs = false, nil
	s.bf.mu.Unlock()
	known := make(map[string]bool, len(f.Manifest))
	ids := make([]string, 0, len(f.Manifest))
	for _, m := range f.Manifest {
		known[m.ID] = true
		if err := s.mirrorEnsure(m); err != nil {
			s.deps.Log.Warn().Err(err).Str("note", m.ID).Msg("federation: mirror manifest ensure")
			continue
		}
		ids = append(ids, m.ID)
	}
	// Notes home no longer lists were deleted there (possibly while the
	// link was down): delete them here too. This is how erasure reaches
	// a mirror that was offline (§A8).
	locals, err := s.listAllNotes()
	if err != nil {
		return err
	}
	removed := 0
	for _, m := range locals {
		if known[m.ID] || s.deps.Delete == nil {
			continue
		}
		if err := s.deps.Delete(s.ctx, s.vaultID, m.ID); err != nil && !errors.Is(err, domain.ErrNotFound) {
			s.deps.Log.Warn().Err(err).Str("note", m.ID).Msg("federation: mirror delete absent note")
			continue
		}
		removed++
	}
	if removed > 0 {
		s.deps.Log.Info().Str("vault", s.vaultID.String()).Int("deleted", removed).
			Msg("federation: mirror removed notes home no longer has")
	}
	s.startBackfill(ids)
	return nil
}

// mirrorEnsure makes the local row match home's: created when missing,
// moved/renamed when home moved it, and rebuilt when home's lineage
// differs (home deleted and recreated the id while the link was down).
func (s *Session) mirrorEnsure(m NoteMeta) error {
	if err := validateNoteID(m.ID); err != nil {
		return err
	}
	if err := validateRelPath(m.Path); err != nil {
		return err
	}
	cur, err := s.deps.Notes.Get(s.ctx, s.vaultID, m.ID)
	if err != nil {
		if !errors.Is(err, domain.ErrNotFound) {
			return err
		}
		return s.ensureNote(m)
	}
	if m.Epoch != "" && cur.CRDTEpoch != "" && m.Epoch != cur.CRDTEpoch && s.deps.Delete != nil {
		// Another history under the same id: readers of the old one get
		// 4404 (DeleteFromFederation drops the room) before the new row.
		if err := s.deps.Delete(s.ctx, s.vaultID, m.ID); err != nil && !errors.Is(err, domain.ErrNotFound) {
			return err
		}
		return s.ensureNote(m)
	}
	if (cur.Path != m.Path || cur.Title != m.Title) && s.deps.Move != nil {
		if err := s.deps.Move(s.ctx, s.vaultID, m.ID, m.Path, m.Title); err != nil && !errors.Is(err, domain.ErrNotFound) {
			return err
		}
	}
	return nil
}

// startBackfill asks home for every listed note, at most backfillWindow
// at a time. Each Step2 (or a timeout) frees a slot.
func (s *Session) startBackfill(ids []string) {
	s.bf.mu.Lock()
	s.bf.active = true
	s.bf.slots = make(chan struct{}, backfillWindow)
	s.bf.inflight = map[string]*time.Timer{}
	s.bf.total = len(ids)
	s.bf.done = 0
	slots := s.bf.slots
	s.bf.mu.Unlock()

	go func() {
		for _, id := range ids {
			select {
			case slots <- struct{}{}:
			case <-s.done:
				return
			}
			if !s.backfillStep(id) {
				<-slots
				s.bf.mu.Lock()
				s.bf.done++
				s.bf.mu.Unlock()
			}
		}
		// Wait for the window to drain: every slot back.
		for i := 0; i < cap(slots); i++ {
			select {
			case slots <- struct{}{}:
			case <-s.done:
				return
			}
		}
		s.bf.mu.Lock()
		s.bf.active = false
		head, ack := s.bf.pendingHead, s.bf.havePending
		s.bf.havePending = false
		s.bf.mu.Unlock()
		if ack {
			s.ackHome(head)
		}
	}()
}

// backfillStep sends one Step1 under a window slot; false when nothing
// was sent (a Step1 for the note already went out on this connection).
func (s *Session) backfillStep(noteID string) bool {
	s.step1Mu.Lock()
	already := s.step1Sent[noteID]
	s.step1Mu.Unlock()
	if already {
		return false
	}
	s.bf.mu.Lock()
	s.bf.inflight[noteID] = time.AfterFunc(backfillStepTimeout, func() { s.backfillRelease(noteID) })
	s.bf.mu.Unlock()
	s.sendStep1(noteID)
	return true
}

// backfillRelease frees the slot of a note whose Step2 arrived.
func (s *Session) backfillRelease(noteID string) {
	s.bf.mu.Lock()
	t, ok := s.bf.inflight[noteID]
	if ok {
		t.Stop()
		delete(s.bf.inflight, noteID)
		s.bf.done++
	}
	slots := s.bf.slots
	s.bf.mu.Unlock()
	if ok {
		<-slots
	}
}

// onHomeHead acknowledges home's head once everything before it applied.
// Frames are handled in order, so outside a backfill that is now.
func (s *Session) onHomeHead(seq int64) {
	s.bf.mu.Lock()
	if s.bf.active {
		s.bf.pendingHead, s.bf.havePending = seq, true
		s.bf.mu.Unlock()
		return
	}
	s.bf.mu.Unlock()
	s.ackHome(seq)
}

func (s *Session) ackHome(seq int64) {
	s.send(EncodeMirrorAck(seq))
	if s.deps.HomeSeqApplied != nil {
		s.deps.HomeSeqApplied(s.vaultID, s.peerURL, seq)
	}
}

func (s *Session) backfillProgress() BackfillProgress {
	s.bf.mu.Lock()
	defer s.bf.mu.Unlock()
	return BackfillProgress{Active: s.bf.active, Synced: s.bf.done, Total: s.bf.total}
}

// MirrorProgress reports the live backfill of the vault's mirror link on
// this (mirror) server; ok=false when no mirror session is up.
func (l *Links) MirrorProgress(vaultID uuid.UUID) (BackfillProgress, bool) {
	for _, s := range l.sessionsFor(vaultID) {
		if s.mode == ModeMirror && s.role == "follower" {
			return s.backfillProgress(), true
		}
	}
	return BackfillProgress{}, false
}
