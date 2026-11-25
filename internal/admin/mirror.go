// Mirror operations of the admin API and CLI (docs/SPEC-ESPELHO-SELADO.md
// §A12–A13). Pause, resume and resync exist in both; promote is CLI-only
// (an admin token alone cannot fork a book) and is not routed in http.go.
package admin

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/ViniZap4/lumi-server/internal/domain"
)

// Mirror audit actions (admin side). Promotion is audited as
// domain.ActionMirrorPromote ("mirror.promote") with the admin actor.
const (
	ActionFederationPause  = "admin.federation.pause"
	ActionFederationResume = "admin.federation.resume"
	ActionMirrorResync     = "admin.mirror.resync"
)

// NoteResyncer (optional on MirrorOps) rebuilds one note of a live mirror
// link from home (*federation.Service.ResyncNote).
type NoteResyncer interface {
	ResyncNote(ctx context.Context, id uuid.UUID, noteID string) (domain.Federation, error)
}

// MirrorOps is the link control surface (*federation.Service). In the
// running server it also stops/starts the live link; from the CLI only
// the rows change and the server converges within its reconcile interval.
type MirrorOps interface {
	PauseLink(ctx context.Context, id uuid.UUID) (domain.Federation, error)
	ResumeLink(ctx context.Context, id uuid.UUID) (domain.Federation, error)
	ResyncLink(ctx context.Context, id uuid.UUID) (domain.Federation, error)
}

// Promotion is what a mirror promotion carries over from home's last
// replicated control state.
type Promotion struct {
	Roles   []domain.Role
	Members []PromotedMember
	// Dropped are member keys of other servers (not carried over).
	Dropped []string
}

// PromotedMember is a local user and the role name home gave them.
type PromotedMember struct {
	Username string
	Role     string
}

// PromoteResult reports what a promotion did.
type PromoteResult struct {
	FederationID uuid.UUID
	PeerURL      string
	RolesCreated []string
	RolesUpdated []string
	// Members are "username:role" pairs granted locally.
	Members []string
	// Missing are usernames home granted on this server that do not
	// exist here; Dropped are other servers' members.
	Missing []string
	Dropped []string
}

// fillProgress adds the live backfill of a mirror link (mirror side).
func (s *Service) fillProgress(f *Federation) {
	if s.Progress == nil || f.Role != "follower" || f.Mode != "mirror" {
		return
	}
	if p, ok := s.Progress(f.VaultID); ok {
		f.Backfill = &p
	}
}

// GetFederation returns one link with its mirror details.
func (s *Service) GetFederation(ctx context.Context, id uuid.UUID) (Federation, error) {
	f, err := s.Store.GetFederation(ctx, id)
	if err != nil {
		return Federation{}, err
	}
	s.fillProgress(&f)
	return f, nil
}

func (s *Service) mirrorOps() (MirrorOps, error) {
	if s.Mirrors == nil {
		return nil, errors.New("admin: mirror operations not wired")
	}
	return s.Mirrors, nil
}

// linkActionNote is the single-note resync flavour of linkAction.
func (s *Service) linkActionNote(ctx context.Context, a Actor, id uuid.UUID, noteID string,
	run func(MirrorOps, context.Context, uuid.UUID) (domain.Federation, error)) (Federation, error) {
	return s.linkActionWith(ctx, a, id, ActionMirrorResync, true, map[string]any{"note_id": noteID}, run)
}

// linkAction audits then runs a pause/resume/resync.
func (s *Service) linkAction(ctx context.Context, a Actor, id uuid.UUID, action string, mirrorOnly bool,
	run func(MirrorOps, context.Context, uuid.UUID) (domain.Federation, error)) (Federation, error) {
	return s.linkActionWith(ctx, a, id, action, mirrorOnly, nil, run)
}

func (s *Service) linkActionWith(ctx context.Context, a Actor, id uuid.UUID, action string, mirrorOnly bool, extra map[string]any,
	run func(MirrorOps, context.Context, uuid.UUID) (domain.Federation, error)) (Federation, error) {
	f, err := s.Store.GetFederation(ctx, id)
	if err != nil {
		return Federation{}, err
	}
	ops, err := s.mirrorOps()
	if err != nil {
		return Federation{}, err
	}
	if mirrorOnly && (f.Mode != "mirror" || f.Role != "follower") {
		return Federation{}, invalid("id", "resync runs on the mirror side of a mirror link")
	}
	if f.Status != "active" {
		return Federation{}, fmt.Errorf("%w: federation %s", domain.ErrConflict, f.Status)
	}
	payload := map[string]any{
		"federation_id": f.ID,
		"peer_url":      f.PeerURL,
		"role":          f.Role,
		"mode":          f.Mode,
	}
	for k, v := range extra {
		payload[k] = v
	}
	e := s.entry(a, action, nil, &f.VaultID, payload)
	if err := s.Store.RecordAudit(ctx, e); err != nil {
		return Federation{}, fmt.Errorf("audit %s: %w", action, err)
	}
	if _, err := run(ops, ctx, id); err != nil {
		s.logFailure(a, action, err).Str("federation_id", id.String()).Msg("admin action failed after audit")
		return Federation{}, err
	}
	s.logAction(a, action).Str("federation_id", id.String()).Str("peer_url", f.PeerURL).Msg("admin action")
	return s.GetFederation(ctx, id)
}

// PauseFederation stops a link without revoking it.
func (s *Service) PauseFederation(ctx context.Context, a Actor, id uuid.UUID) (Federation, error) {
	return s.linkAction(ctx, a, id, ActionFederationPause, false, MirrorOps.PauseLink)
}

// ResumeFederation restarts a paused link.
func (s *Service) ResumeFederation(ctx context.Context, a Actor, id uuid.UUID) (Federation, error) {
	return s.linkAction(ctx, a, id, ActionFederationResume, false, MirrorOps.ResumeLink)
}

// ResyncMirror forgets a mirror's progress and runs a full pass.
func (s *Service) ResyncMirror(ctx context.Context, a Actor, id uuid.UUID) (Federation, error) {
	return s.linkAction(ctx, a, id, ActionMirrorResync, true, MirrorOps.ResyncLink)
}

// ResyncMirrorNote rebuilds one note of a mirror link (mirror side, the
// link must be connected): the local history is dropped and the full
// state requested from home. Audited admin.mirror.resync with note_id.
func (s *Service) ResyncMirrorNote(ctx context.Context, a Actor, id uuid.UUID, noteID string) (Federation, error) {
	if noteID == "" || len(noteID) > 256 {
		return Federation{}, invalid("note_id", "is invalid")
	}
	ops, err := s.mirrorOps()
	if err != nil {
		return Federation{}, err
	}
	nr, ok := ops.(NoteResyncer)
	if !ok {
		return Federation{}, fmt.Errorf("%w: single-note resync needs the running server", domain.ErrConflict)
	}
	return s.linkActionNote(ctx, a, id, noteID, func(_ MirrorOps, ctx context.Context, id uuid.UUID) (domain.Federation, error) {
		return nr.ResyncNote(ctx, id, noteID)
	})
}

// PromoteMirror turns the mirror of vaultRef (slug or id) into an
// independent home: the follower row is severed and marked promoted (the
// read-only clamp lifts, fswatch and lazy init come back), home's roles
// become local roles and home's grants to users of this server become
// local memberships. Members of other servers are listed as not carried
// over. CLI only; audited as mirror.promote.
func (s *Service) PromoteMirror(ctx context.Context, a Actor, vaultRef string) (Vault, PromoteResult, error) {
	if s.Planner == nil {
		return Vault{}, PromoteResult{}, errors.New("admin: promotion planner not wired")
	}
	v, err := s.ResolveVault(ctx, vaultRef)
	if err != nil {
		return Vault{}, PromoteResult{}, err
	}
	plan := func(state []byte) (Promotion, error) {
		if len(state) == 0 {
			return Promotion{}, nil
		}
		return s.Planner(state)
	}
	entry := func(r PromoteResult) domain.AuditEntry {
		return s.entry(a, domain.ActionMirrorPromote, nil, &v.ID, map[string]any{
			"federation_id": r.FederationID,
			"peer_url":      r.PeerURL,
			"roles_created": r.RolesCreated,
			"roles_updated": r.RolesUpdated,
			"members":       len(r.Members),
			"missing":       len(r.Missing),
			"dropped":       len(r.Dropped),
		})
	}
	res, err := s.Store.PromoteMirror(ctx, v.ID, s.clock().UTC(), plan, entry)
	if err != nil {
		return Vault{}, PromoteResult{}, err
	}
	s.logAction(a, domain.ActionMirrorPromote).Str("vault", v.Slug).Str("peer_url", res.PeerURL).Msg("admin action")
	return v, res, nil
}
