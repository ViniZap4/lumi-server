// Mirror operations, phase M2 (docs/SPEC-ESPELHO-SELADO.md §A7.2, §A9,
// §A10): incremental resume, divergence detection and the integrity pass.
//
// Resume. A mirror that advertised it (relay WS query resume=1) opens with
// frameResumeFrom(home_seq), the highest home seq it fully applied. Home
// waits for it before the opening. When home_seq is at or above the
// vault's tombstone floor home walks its change log after home_seq
// instead of sending the manifest: an announce (+ noteMeta2) for every
// note whose change_seq moved and a delete for every tombstone, in seq
// order, then the control state and frameChangesEnd(head). Otherwise (0,
// below the floor, a publish link, no change log) it sends the full
// manifest as before. The mirror fetches the announced notes with the
// same 32-wide Step1 window as a full backfill and acknowledges the head
// once they are applied.
//
// Divergence. A mirror never authors operations, so its state vector of
// every note must be dominated by home's. Home checks the mirror's Step1
// SV; the mirror checks the SV home appends to every Step2 on a mirror
// link (after applying it). A mirror whose copy diverged drops the note's
// local history under the same row and epoch and asks for the full state.
//
// Integrity pass. Every integrityInterval (with jitter) the mirror sends a
// Step1 for every note at integrityRate notes/s (which re-runs the
// divergence check) and rewrites every file whose body differs from the
// CRDT text.
package federation

import (
	"crypto/sha256"
	"errors"
	"math/rand"
	"time"

	"github.com/google/uuid"

	"github.com/ViniZap4/lumi-server/internal/crdt"
	"github.com/ViniZap4/lumi-server/internal/domain"
	"github.com/ViniZap4/lumi-server/internal/wsync"
)

// Tunables; variables so tests can shorten them.
var (
	// resumeWait bounds how long home waits for a mirror's resumeFrom.
	resumeWait = 10 * time.Second
	// integrityInterval is the period of the integrity pass (§A10).
	integrityInterval = 24 * time.Hour
	// integrityRate is the integrity pass's notes per second.
	integrityRate = 50
)

// resumePage is the change-log page size of an incremental resume.
const resumePage = 500

// ---- home side -------------------------------------------------------------------

// sendResumeChanges sends the vault's changes after seq. ok=false asks
// for the full manifest instead (cursor below the tombstone floor, or no
// change log wired).
func (s *Session) sendResumeChanges(seq int64) (bool, error) {
	if s.deps.Changes == nil {
		return false, nil
	}
	after := seq
	for {
		ch, err := s.deps.Changes(s.ctx, s.vaultID, after, resumePage)
		var rr *domain.ResyncRequiredError
		if errors.As(err, &rr) || errors.Is(err, domain.ErrResyncRequired) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		// Merge by seq: a delete followed by a recreate of the same id
		// must reach the mirror in that order.
		i, j := 0, 0
		for i < len(ch.Notes) || j < len(ch.Deleted) {
			if j >= len(ch.Deleted) || (i < len(ch.Notes) && ch.Notes[i].ChangeSeq < ch.Deleted[j].Seq) {
				n := ch.Notes[i]
				i++
				m := NoteMeta{ID: n.ID, Path: n.Path, Title: n.Title, Epoch: n.CRDTEpoch}
				s.sendWait(EncodeNoteAnnounce(m))
				if s.speaksV2() {
					if frame := s.links.meta2Frame(s.vaultID, m); frame != nil {
						s.sendWait(frame)
					}
				}
				after = max(after, n.ChangeSeq)
				continue
			}
			d := ch.Deleted[j]
			j++
			s.sendWait(EncodeNoteDelete(d.ID))
			after = max(after, d.Seq)
		}
		if !ch.More {
			return true, nil
		}
	}
}

// answerMirrorStep1 answers a mirror's Step1 with the diff and home's
// state vector (trailing), and reports a mirror SV that home's does not
// cover (§A9 check 1).
func (s *Session) answerMirrorStep1(noteID string, sv []byte) error {
	if s.publish != nil && !s.isPublished(noteID) {
		// A publish mirror only ever learns in-scope notes; a Step1 for
		// anything else gets no answer (not even "it exists").
		return nil
	}
	var homeSV []byte
	diff, err := s.withDoc(noteID, func(doc *crdt.Doc) ([]byte, error) {
		var err error
		if homeSV, err = doc.StateVectorV1(); err != nil {
			return nil, err
		}
		return doc.EncodeDiffSince(sv)
	})
	if err != nil {
		return err
	}
	if peer, err := crdt.DecodeStateVector(sv); err == nil {
		if home, err := crdt.DecodeStateVector(homeSV); err == nil && !home.Covers(peer) {
			s.reportDivergent(noteID, "home")
		}
	}
	s.send(EncodeNoteSyncSV(noteID, wsync.EncodeSyncStep2(diff), homeSV))
	return nil
}

// ---- mirror side -----------------------------------------------------------------

// checkMirrorDivergence (mirror) compares the local copy with home's SV
// after applying home's Step2 (§A9 check 2) and rebuilds a diverged note.
func (s *Session) checkMirrorDivergence(noteID string, homeSVBytes []byte) {
	home, err := crdt.DecodeStateVector(homeSVBytes)
	if err != nil {
		return
	}
	localBytes, err := s.withDoc(noteID, func(doc *crdt.Doc) ([]byte, error) { return doc.StateVectorV1() })
	if err != nil {
		return
	}
	local, err := crdt.DecodeStateVector(localBytes)
	if err != nil || home.Covers(local) {
		return
	}
	s.reportDivergent(noteID, "mirror")
	if err := s.rebuildNote(noteID); err != nil {
		s.deps.Log.Warn().Err(err).Str("note", noteID).Msg("federation: mirror rebuild")
	}
}

// rebuildNote (mirror) drops the note's local CRDT history (same row,
// same epoch) and asks home for the full state.
func (s *Session) rebuildNote(noteID string) error {
	if s.deps.ResetDoc == nil {
		return errors.New("federation: no ResetDoc wired")
	}
	if _, err := s.deps.Notes.Get(s.ctx, s.vaultID, noteID); err != nil {
		return err
	}
	if err := s.deps.ResetDoc(s.ctx, s.vaultID, noteID); err != nil {
		return err
	}
	s.step1Mu.Lock()
	delete(s.step1Sent, noteID)
	s.step1Mu.Unlock()
	s.sendStep1(noteID)
	return nil
}

func (s *Session) reportDivergent(noteID, side string) {
	s.guardMu.Lock()
	first := !s.divergentSeen[noteID]
	s.divergentSeen[noteID] = true
	s.guardMu.Unlock()
	s.deps.Log.Warn().Str("peer", s.peerURL).Str("vault", s.vaultID.String()).
		Str("note", noteID).Str("side", side).Msg("federation: mirror copy diverged from home")
	if s.deps.Divergent != nil {
		s.deps.Divergent(s.vaultID, s.peerURL, noteID, side)
	}
	if first && side == "home" && s.deps.Audit != nil {
		s.deps.Audit(s.ctx, s.vaultID, domain.ActionFederationMirrorDivergent, map[string]any{
			"peer_url": s.peerURL,
			"note_id":  noteID,
		})
	}
}

// IntegrityReport is the outcome of one integrity pass.
type IntegrityReport struct {
	Notes     int
	Rewritten int
	Missing   int
	Errors    int
	Finished  time.Time
}

// integrityLoop (mirror) runs the integrity pass every integrityInterval
// with ±10% jitter, the first one integrityInterval after the previous
// pass (or within the first interval/24 when there never was one).
func (s *Session) integrityLoop() {
	next := integrityInterval
	if s.lastIntegrity.IsZero() {
		next = jitter(integrityInterval / 24)
	} else if d := time.Until(s.lastIntegrity.Add(integrityInterval)); d > 0 {
		next = jitter(d)
	} else {
		next = jitter(integrityInterval / 24)
	}
	for {
		t := time.NewTimer(next)
		select {
		case <-s.done:
			t.Stop()
			return
		case <-t.C:
		}
		// Never overlap a backfill: it covers every note anyway.
		for s.backfillProgress().Active {
			select {
			case <-s.done:
				return
			case <-time.After(time.Second):
			}
		}
		r := s.integrityPass()
		if s.deps.IntegrityDone != nil && r.Errors == 0 {
			s.deps.IntegrityDone(s.vaultID, s.peerURL, r)
		}
		next = jitter(integrityInterval)
	}
}

func jitter(d time.Duration) time.Duration {
	if d <= 0 {
		return time.Second
	}
	span := int64(d) / 5
	if span <= 0 {
		return d
	}
	return d - d/10 + time.Duration(rand.Int63n(span)) // #nosec G404 — jitter only
}

// integrityPass (mirror) re-verifies every note: a fresh Step1 (home's
// answer re-runs the divergence check) and a file rewrite when the body
// on disk differs from the CRDT text.
func (s *Session) integrityPass() IntegrityReport {
	var r IntegrityReport
	metas, err := s.listAllNotes()
	if err != nil {
		r.Errors++
		return r
	}
	rate := integrityRate
	if rate <= 0 {
		rate = 50
	}
	tick := time.NewTicker(time.Second / time.Duration(rate))
	defer tick.Stop()
	for _, m := range metas {
		select {
		case <-s.done:
			r.Errors++
			return r
		case <-tick.C:
		}
		r.Notes++
		s.step1Mu.Lock()
		delete(s.step1Sent, m.ID)
		s.step1Mu.Unlock()
		s.sendStep1(m.ID)
		if s.deps.ReadBody == nil {
			continue
		}
		textBytes, err := s.withDoc(m.ID, func(doc *crdt.Doc) ([]byte, error) {
			t, err := doc.Text()
			return []byte(t), err
		})
		if err != nil {
			r.Errors++
			continue
		}
		body, err := s.deps.ReadBody(s.ctx, s.vaultID, m.ID)
		switch {
		case errors.Is(err, domain.ErrNotFound):
			r.Missing++
		case err != nil:
			r.Errors++
			continue
		case sha256.Sum256([]byte(body)) == sha256.Sum256(textBytes):
			continue
		}
		if len(textBytes) == 0 && errors.Is(err, domain.ErrNotFound) {
			continue // nothing landed yet: no file to write
		}
		if err := s.deps.Mirror(s.ctx, s.vaultID, m.ID, string(textBytes)); err != nil {
			r.Errors++
			continue
		}
		r.Rewritten++
	}
	r.Finished = time.Now().UTC()
	return r
}

// ResyncNote (mirror side) rebuilds one note from home over the live
// session of the vault's mirror link. ok=false when no session is up.
func (l *Links) ResyncNote(vaultID uuid.UUID, noteID string) (bool, error) {
	for _, s := range l.sessionsFor(vaultID) {
		if s.mode == ModeMirror && s.role == "follower" {
			return true, s.rebuildNote(noteID)
		}
	}
	return false, nil
}

// controlFor is the control document for this link.
func (s *Session) controlFor() (state, sig []byte, ok bool) {
	if s.publish != nil {
		if s.deps.ControlFor == nil {
			return nil, nil, false // never hand a publish mirror the full member list
		}
		return s.deps.ControlFor(s.ctx, s.vaultID, s.peerURL)
	}
	return s.deps.ControlCurrent(s.ctx, s.vaultID)
}
