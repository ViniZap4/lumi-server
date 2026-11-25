// Mirror operations of phase M2 on the service side
// (docs/SPEC-ESPELHO-SELADO.md §A8, §A10, §A13): the erasure SLA alert,
// integrity-pass bookkeeping and single-note resync.
package federation

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/ViniZap4/lumi-server/internal/domain"
	"github.com/ViniZap4/lumi-server/internal/metrics"
)

// DefaultErasureSLA is LUMI_MIRROR_ERASURE_SLA's default (§A8).
const DefaultErasureSLA = 24 * time.Hour

// erasureAlertEvery bounds federation.erasure_lagging to once per link
// per day.
const erasureAlertEvery = 24 * time.Hour

// SetErasureSLA sets how old the oldest unacknowledged delete of a mirror
// may get before the link is flagged (<= 0 restores the default).
func (s *Service) SetErasureSLA(d time.Duration) { s.erasureSLA = d }

// ErasureSLA is the configured erasure SLA.
func (s *Service) ErasureSLA() time.Duration {
	if s.erasureSLA <= 0 {
		return DefaultErasureSLA
	}
	return s.erasureSLA
}

// SetLinks gives the service the live relay sessions (single-note resync).
func (s *Service) SetLinks(l *Links) { s.links = l }

// CheckErasureSLA (home side) audits federation.erasure_lagging for every
// active mirror link whose oldest unacknowledged delete is older than the
// SLA, at most once per link per day. It returns the lagging links.
func (s *Service) CheckErasureSLA(ctx context.Context) []domain.Federation {
	rows, err := s.federations.ListActiveByRole(ctx, "home")
	if err != nil {
		return nil
	}
	var lagging []domain.Federation
	now := s.now()
	for _, f := range rows {
		if f.Mode != ModeMirror {
			continue
		}
		st := s.MirrorLinkStats(ctx, f)
		if !st.ErasureLagging {
			continue
		}
		lagging = append(lagging, f)
		s.erasureMu.Lock()
		last, seen := s.erasureAlert[f.ID]
		due := !seen || now.Sub(last) >= erasureAlertEvery
		if due {
			s.erasureAlert[f.ID] = now
		}
		s.erasureMu.Unlock()
		if !due {
			continue
		}
		payload := map[string]any{
			"peer_url":        f.PeerURL,
			"pending_deletes": st.PendingDeletes,
			"sla_seconds":     int64(s.ErasureSLA() / time.Second),
		}
		if st.OldestPendingDeleteAt != nil {
			payload["oldest_pending_delete_at"] = st.OldestPendingDeleteAt.UTC().Format(time.RFC3339)
		}
		s.recordAudit(ctx, nil, f.VaultID, domain.ActionFederationErasureLagging, "", "", payload)
	}
	return lagging
}

// RunErasureMonitor checks the erasure SLA every interval until ctx ends.
func (s *Service) RunErasureMonitor(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = time.Hour
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.CheckErasureSLA(ctx)
		}
	}
}

// IntegrityStore is the optional store surface for integrity passes.
type IntegrityStore interface {
	RecordIntegrity(ctx context.Context, vaultID uuid.UUID, peerURL string, at time.Time) error
}

// RecordIntegrity (mirror side) stores a finished integrity pass; a pass
// that had to rewrite files is audited as mirror.integrity.
func (s *Service) RecordIntegrity(vaultID uuid.UUID, peerURL string, r IntegrityReport) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if is, ok := s.mirrors.(IntegrityStore); ok {
		_ = is.RecordIntegrity(ctx, vaultID, peerURL, r.Finished)
	}
	metrics.MirrorIntegrityRewritten.Add(int64(r.Rewritten))
	if r.Rewritten > 0 || r.Missing > 0 {
		s.recordAudit(ctx, nil, vaultID, domain.ActionMirrorIntegrity, "", "", map[string]any{
			"peer_url":  peerURL,
			"notes":     r.Notes,
			"rewritten": r.Rewritten,
			"missing":   r.Missing,
		})
	}
}

// MirrorDivergent counts a divergent mirror copy (relay callback).
func (s *Service) MirrorDivergent(_ uuid.UUID, _ string, _ string, _ string) {
	metrics.MirrorDivergent.Inc()
}

// ResyncNote (mirror side) rebuilds one note of a mirror link from home
// over the live session (§A13 resync {"note_id"}).
func (s *Service) ResyncNote(ctx context.Context, id uuid.UUID, noteID string) (domain.Federation, error) {
	f, err := s.federations.Get(ctx, id)
	if err != nil {
		return domain.Federation{}, err
	}
	if !f.IsMirrorFollower() {
		return domain.Federation{}, fmt.Errorf("%w: note resync runs on the mirror side of a mirror link", domain.ErrValidation)
	}
	if err := validateNoteID(noteID); err != nil {
		return domain.Federation{}, err
	}
	if s.links == nil {
		return domain.Federation{}, fmt.Errorf("%w: relay not running", domain.ErrConflict)
	}
	ok, err := s.links.ResyncNote(f.VaultID, noteID)
	if err != nil {
		return domain.Federation{}, err
	}
	if !ok {
		return domain.Federation{}, fmt.Errorf("%w: mirror link is not connected", domain.ErrConflict)
	}
	return f, nil
}
