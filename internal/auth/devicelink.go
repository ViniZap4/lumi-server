package auth

// Device links (SPEC-LIVROS §8.4): a client that holds a session mints a
// short-lived, single-use code bound to a PKCE challenge chosen by the
// client that wants a session. The second client redeems the code with
// the verifier and gets a session of its own, revocable on its own and
// linked to the issuer so "sign out on this Mac" ends both.
//
// Nothing secret crosses between the two clients: the code is useless
// without the verifier, which never leaves the requester's memory.

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/ViniZap4/lumi-server/internal/domain"
)

// Audit actions for device links. Kept here (not in domain) so the
// feature stays inside internal/auth.
const (
	ActionDeviceLinkIssue  = "auth.device_link_issue"
	ActionDeviceLinkRedeem = "auth.device_link_redeem"
	ActionDeviceLinkFailed = "auth.device_link_failed"
	ActionLogoutDevice     = "auth.logout_device"
)

// DeviceLinkTTL bounds how long a minted code is redeemable.
const DeviceLinkTTL = 120 * time.Second

const (
	maxLinkLabel   = 80
	challengeLen   = 43 // base64url(SHA-256) without padding
	minVerifierLen = 43
	maxVerifierLen = 128
)

// ErrInvalidLink is the single answer for an unknown, used, expired or
// mismatched code, so a caller learns nothing about which it was.
var ErrInvalidLink = errors.New("auth: invalid device link")

// ErrDeviceLinksDisabled is returned when no DeviceLinkStore is wired.
var ErrDeviceLinksDisabled = errors.New("auth: device links disabled")

// LinkCode is one minted code. Issuer is the issuing session's reference,
// SessionRef(token) — the same SHA-256 hex the session store keys on —
// so no store ever needs the raw token back.
type LinkCode struct {
	CodeHash  string
	UserID    uuid.UUID
	Issuer    string
	Challenge string
	Label     string
	CreatedAt time.Time
	ExpiresAt time.Time
}

// DeviceLinkStore persists codes and session link groups.
type DeviceLinkStore interface {
	// CreateLinkCode stores a code (and may purge expired ones).
	CreateLinkCode(ctx context.Context, c LinkCode) error
	// ConsumeLinkCode deletes the code and returns it. domain.ErrNotFound
	// when it does not exist or its issuer session is gone or expired.
	// The caller checks expiry and the verifier; the code is spent
	// either way.
	ConsumeLinkCode(ctx context.Context, codeHash string) (LinkCode, error)
	// LinkSessions puts newToken in the issuer's link group (issuer is a
	// SessionRef), creating the group when the issuer has none.
	LinkSessions(ctx context.Context, issuer, newToken string) error
	// DeleteLinkedSessions deletes every session of userID in token's
	// link group except token itself. Returns how many were deleted.
	DeleteLinkedSessions(ctx context.Context, userID uuid.UUID, token string) (int, error)
}

// SetDeviceLinkStore enables device links; nil disables them.
func (s *Service) SetDeviceLinkStore(st DeviceLinkStore) {
	s.links = st
	if s.rlLinkIssue == nil {
		s.rlLinkIssue = NewRateLimiter(10, time.Minute, 10*time.Minute)
	}
	if s.rlLinkRedeem == nil {
		s.rlLinkRedeem = NewRateLimiter(30, time.Minute, 10*time.Minute)
	}
}

// SessionRef is the at-rest reference of a session: lowercase hex
// SHA-256 of the token, identical to the session store's token_hash.
func SessionRef(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// HashLinkCode is the at-rest form of a link code (lowercase hex SHA-256).
func HashLinkCode(code string) string {
	sum := sha256.Sum256([]byte(code))
	return hex.EncodeToString(sum[:])
}

// PKCEChallenge returns base64url-nopad(SHA-256(verifier)) (RFC 7636 S256).
func PKCEChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func isBase64URL(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_':
		default:
			return false
		}
	}
	return true
}

func cleanLabel(l string) string {
	l = strings.TrimSpace(l)
	l = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, l)
	if r := []rune(l); len(r) > maxLinkLabel {
		l = string(r[:maxLinkLabel])
	}
	return l
}

// IssueDeviceLink mints a code for the session's user, bound to challenge.
func (s *Service) IssueDeviceLink(ctx context.Context, sess domain.Session, challenge, label string) (string, time.Time, error) {
	if s.links == nil {
		return "", time.Time{}, ErrDeviceLinksDisabled
	}
	challenge = strings.TrimSpace(challenge)
	if len(challenge) != challengeLen || !isBase64URL(challenge) {
		return "", time.Time{}, fmt.Errorf("auth: challenge must be base64url SHA-256: %w", domain.ErrValidation)
	}
	if !s.rlLinkIssue.Allow(sess.UserID.String()) {
		return "", time.Time{}, fmt.Errorf("auth: device link issue throttled: %w", domain.ErrRateLimited)
	}
	code, err := IssueToken() // 32 random bytes, hex
	if err != nil {
		return "", time.Time{}, err
	}
	now := time.Now().UTC()
	lc := LinkCode{
		CodeHash:  HashLinkCode(code),
		UserID:    sess.UserID,
		Issuer:    SessionRef(sess.Token),
		Challenge: challenge,
		Label:     cleanLabel(label),
		CreatedAt: now,
		ExpiresAt: now.Add(DeviceLinkTTL),
	}
	if err := s.links.CreateLinkCode(ctx, lc); err != nil {
		return "", time.Time{}, fmt.Errorf("auth: store device link: %w", err)
	}
	uid := sess.UserID
	s.recordAudit(ctx, domain.AuditEntry{
		UserID:  &uid,
		Action:  ActionDeviceLinkIssue,
		Payload: mustJSON(map[string]any{"label": lc.Label}),
	})
	return code, lc.ExpiresAt, nil
}

// RedeemDeviceLink spends code and, when the verifier matches, issues a
// new session linked to the issuer's.
func (s *Service) RedeemDeviceLink(ctx context.Context, code, verifier, label, ip, userAgent string) (domain.Session, error) {
	if s.links == nil {
		return domain.Session{}, ErrDeviceLinksDisabled
	}
	if !s.rlLinkRedeem.Allow(ip) {
		return domain.Session{}, fmt.Errorf("auth: device link redeem throttled: %w", domain.ErrRateLimited)
	}
	code = strings.TrimSpace(code)
	if code == "" || len(code) > 128 || len(verifier) < minVerifierLen || len(verifier) > maxVerifierLen || !isBase64URL(verifier) {
		s.linkFailed(ctx, nil, "malformed", ip, userAgent)
		return domain.Session{}, ErrInvalidLink
	}
	lc, err := s.links.ConsumeLinkCode(ctx, HashLinkCode(code))
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			s.linkFailed(ctx, nil, "unknown_code", ip, userAgent)
			return domain.Session{}, ErrInvalidLink
		}
		return domain.Session{}, fmt.Errorf("auth: consume device link: %w", err)
	}
	uid := lc.UserID
	if !lc.ExpiresAt.After(time.Now().UTC()) {
		s.linkFailed(ctx, &uid, "expired", ip, userAgent)
		return domain.Session{}, ErrInvalidLink
	}
	if !ConstantTimeEqual(PKCEChallenge(verifier), lc.Challenge) {
		s.linkFailed(ctx, &uid, "verifier_mismatch", ip, userAgent)
		return domain.Session{}, ErrInvalidLink
	}
	// The issuing session is alive (ConsumeLinkCode guarantees it); the
	// user must still be enabled.
	user, err := s.users.GetByID(ctx, lc.UserID)
	if err != nil || user.DisabledAt != nil {
		s.linkFailed(ctx, &uid, "user_unavailable", ip, userAgent)
		return domain.Session{}, ErrInvalidLink
	}
	sess, err := s.issueSession(ctx, lc.UserID)
	if err != nil {
		return domain.Session{}, fmt.Errorf("auth: device link session: %w", err)
	}
	if err := s.links.LinkSessions(ctx, lc.Issuer, sess.Token); err != nil {
		// A session that can't be grouped would escape "sign out on this
		// Mac"; refuse it rather than hand it out.
		_ = s.sessions.DeleteSession(ctx, sess.Token)
		return domain.Session{}, fmt.Errorf("auth: link sessions: %w", err)
	}
	s.recordAudit(ctx, domain.AuditEntry{
		UserID:    &uid,
		Action:    ActionDeviceLinkRedeem,
		Payload:   mustJSON(map[string]any{"issuer_label": lc.Label, "label": cleanLabel(label)}),
		IP:        nilIfEmpty(ip),
		UserAgent: nilIfEmpty(userAgent),
	})
	return sess, nil
}

func (s *Service) linkFailed(ctx context.Context, uid *uuid.UUID, reason, ip, ua string) {
	s.recordAudit(ctx, domain.AuditEntry{
		UserID:    uid,
		Action:    ActionDeviceLinkFailed,
		Payload:   mustJSON(map[string]any{"reason": reason}),
		IP:        nilIfEmpty(ip),
		UserAgent: nilIfEmpty(ua),
	})
}

// LogoutDevice ends token's session and every session linked to it.
// Without a link store it is a plain Logout.
func (s *Service) LogoutDevice(ctx context.Context, token string) (int, error) {
	if token == "" {
		return 0, nil
	}
	sess, err := s.sessions.GetSession(ctx, token)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return 0, nil
		}
		return 0, fmt.Errorf("auth: logout device lookup: %w", err)
	}
	n := 0
	if s.links != nil {
		n, err = s.links.DeleteLinkedSessions(ctx, sess.UserID, token)
		if err != nil {
			return 0, fmt.Errorf("auth: logout device linked: %w", err)
		}
	}
	if err := s.Logout(ctx, token); err != nil {
		return n, err
	}
	uid := sess.UserID
	s.recordAudit(ctx, domain.AuditEntry{
		UserID:  &uid,
		Action:  ActionLogoutDevice,
		Payload: mustJSON(map[string]any{"linked_sessions": n}),
	})
	return n + 1, nil
}
