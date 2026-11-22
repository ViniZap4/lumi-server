package federation

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/ViniZap4/lumi-server/internal/domain"
)

// Revocation notices: when home revokes a link, the follower must learn
// it (set its row to "severed", stop dialling, fall back to local
// authorization) instead of retrying the dead link forever.
//
// Two delivery paths carry the same home-signed notice:
//
//  1. push — home POSTs it to {follower}/api/federation/revoked right after
//     the revoke (best effort, a few retries);
//  2. pull — a follower that was offline learns it from its next
//     sync-challenge: home answers 410 with the notice, but only when the
//     challenge carries a fresh signature by the enrolled follower key
//     (StatusProofMessage), so anonymous callers still get the uniform 403
//     and cannot probe which links existed.
//
// The notice is signed by home's server key over RevokeNoticeMessage and
// verified with the home key the follower pinned at join. A notice only
// severs a link created before (revoked_at + revokeSkew), so a notice for
// an old link cannot be replayed against a later re-join.

const (
	revokeNoticePrefix = "lumi-federation-revoke-v1"
	statusProofPrefix  = "lumi-federation-status-v1"
	// revokeSkew tolerates clock skew between home and follower.
	revokeSkew = 5 * time.Minute
	// statusProofWindow bounds the age of a challenge status proof.
	statusProofWindow = 5 * time.Minute
)

// RevokeNotice is home's signed statement that a federation link is revoked.
type RevokeNotice struct {
	VaultID     uuid.UUID `json:"vault_id"`
	HomeURL     string    `json:"home_url"`
	FollowerURL string    `json:"follower_url"`
	RevokedAt   string    `json:"revoked_at"` // RFC 3339 (nano), UTC
	Signature   string    `json:"signature"`  // hex Ed25519 over RevokeNoticeMessage
}

// RevokeNoticeMessage is the canonical byte string home signs.
func RevokeNoticeMessage(vaultID uuid.UUID, homeURL, followerURL, revokedAt string) []byte {
	return []byte(revokeNoticePrefix + "|" + vaultID.String() + "|" + homeURL + "|" + followerURL + "|" + revokedAt)
}

// StatusProofMessage is what a follower signs to ask home about a link it
// may have lost (sent with sync-challenge as ts + sig).
func StatusProofMessage(vaultID uuid.UUID, followerURL string, ts int64) []byte {
	return []byte(statusProofPrefix + "|" + vaultID.String() + "|" + followerURL + "|" + strconv.FormatInt(ts, 10))
}

// RevokedError is returned by HomeClient.SyncChallenge when home reports
// the link revoked (HTTP 410 with a notice).
type RevokedError struct{ Notice RevokeNotice }

func (e *RevokedError) Error() string { return "federation: home reports link revoked" }

// errLinkInactive ends a follower dial loop: the link is no longer active
// locally (revoked here, or severed by home).
var errLinkInactive = errors.New("federation: link no longer active")

// signRevokeNotice builds home's notice for a revoked home-role link.
func (s *Service) signRevokeNotice(vaultID uuid.UUID, followerURL string, revokedAt time.Time) RevokeNotice {
	at := revokedAt.UTC().Format(time.RFC3339Nano)
	sig := ed25519.Sign(s.priv, RevokeNoticeMessage(vaultID, s.baseURL, followerURL, at))
	return RevokeNotice{
		VaultID:     vaultID,
		HomeURL:     s.baseURL,
		FollowerURL: followerURL,
		RevokedAt:   at,
		Signature:   hex.EncodeToString(sig),
	}
}

// notifyRevokedAsync pushes the notice to the follower in the background.
// Failures are fine: the follower's next sync-challenge pulls it.
func (s *Service) notifyRevokedAsync(n RevokeNotice) {
	go func() {
		delays := []time.Duration{0, 2 * time.Second, 10 * time.Second, 30 * time.Second}
		for _, d := range delays {
			time.Sleep(d)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			err := s.client.NotifyRevoked(ctx, n.FollowerURL, n)
			cancel()
			if err == nil || errors.Is(err, errPeerRejected) {
				return
			}
		}
	}()
}

// statusProofValid reports whether (ts, sigHex) is a fresh signature by
// pub over StatusProofMessage.
func (s *Service) statusProofValid(pub []byte, vaultID uuid.UUID, followerURL string, ts int64, sigHex string) bool {
	if ts == 0 || sigHex == "" || len(pub) != ed25519.PublicKeySize {
		return false
	}
	if d := s.now().Sub(time.Unix(ts, 0)); d > statusProofWindow || d < -statusProofWindow {
		return false
	}
	sig, err := hex.DecodeString(sigHex)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pub), StatusProofMessage(vaultID, followerURL, ts), sig)
}

// revokedNoticeFor (home side, pull path) returns the notice for a revoked
// home-role link to followerURL when the caller proved it holds the
// enrolled follower key.
func (s *Service) revokedNoticeFor(ctx context.Context, vaultID uuid.UUID, followerURL string, ts int64, sigHex string) (RevokeNotice, bool) {
	if sigHex == "" {
		return RevokeNotice{}, false
	}
	rows, err := s.federations.ListForVault(ctx, vaultID)
	if err != nil {
		return RevokeNotice{}, false
	}
	var latest *domain.Federation
	for i := range rows {
		r := &rows[i]
		if r.Role != "home" || r.PeerURL != followerURL || r.Status != "revoked" || r.RevokedAt == nil {
			continue
		}
		if latest == nil || r.RevokedAt.After(*latest.RevokedAt) {
			latest = r
		}
	}
	if latest == nil || !s.statusProofValid(latest.PeerPubKey, vaultID, followerURL, ts, sigHex) {
		return RevokeNotice{}, false
	}
	return s.signRevokeNotice(vaultID, followerURL, *latest.RevokedAt), true
}

// ApplyRevokeNotice (follower side) verifies home's notice and severs the
// matching active follower link: status → severed, dial loop and live
// session stopped, authorization falls back to local membership. A notice
// for a link that is already inactive is accepted idempotently.
func (s *Service) ApplyRevokeNotice(ctx context.Context, n RevokeNotice) error {
	forbidden := fmt.Errorf("%w: revoke notice not applicable", domain.ErrForbidden)
	if s.baseURL == "" || normalizeServerURL(n.FollowerURL) != s.baseURL || n.VaultID == uuid.Nil {
		return forbidden
	}
	homeURL := normalizeServerURL(n.HomeURL)
	revokedAt, err := time.Parse(time.RFC3339Nano, n.RevokedAt)
	if err != nil {
		return fmt.Errorf("%w: revoked_at must be RFC 3339", domain.ErrValidation)
	}
	sig, err := hex.DecodeString(n.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return forbidden
	}
	msg := RevokeNoticeMessage(n.VaultID, homeURL, s.baseURL, n.RevokedAt)
	rows, err := s.federations.ListForVault(ctx, n.VaultID)
	if err != nil {
		return err
	}
	var target *domain.Federation
	seenInactive := false
	for i := range rows {
		r := &rows[i]
		if r.Role != "follower" || r.PeerURL != homeURL {
			continue
		}
		if len(r.PeerPubKey) != ed25519.PublicKeySize || !ed25519.Verify(ed25519.PublicKey(r.PeerPubKey), msg, sig) {
			continue
		}
		// Only links that existed when home revoked: an old notice
		// must not sever a later re-join.
		if r.CreatedAt.After(revokedAt.Add(revokeSkew)) {
			continue
		}
		if r.Status != "active" {
			seenInactive = true
			continue
		}
		target = r
		break
	}
	if target == nil {
		if seenInactive {
			return nil
		}
		return forbidden
	}
	if err := s.federations.UpdateStatus(ctx, target.ID, "severed", s.now().UTC()); err != nil {
		return err
	}
	if s.relay != nil {
		s.relay.StopLink(n.VaultID, homeURL)
	}
	if s.resolverCache != nil {
		s.resolverCache.invalidate(n.VaultID)
	}
	s.feedFederationChanged(n.VaultID)
	if s.feed != nil {
		s.feed.VaultAccessChanged(n.VaultID)
	}
	s.recordAudit(ctx, nil, n.VaultID, domain.ActionFederationRevoke, "", "", map[string]any{
		"kind":       "severed_by_home",
		"peer_url":   homeURL,
		"revoked_at": n.RevokedAt,
	})
	return nil
}
