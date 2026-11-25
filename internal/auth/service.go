package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/ViniZap4/lumi-server/internal/domain"
)

// Service is the entry point for all auth operations.
type Service struct {
	users    UserRepo
	sessions SessionStore
	consents ConsentStore
	audit    AuditRecorder
	cfg      Config

	rlUser *RateLimiter
	rlIP   *RateLimiter

	dummyHash string

	listener SessionListener

	// Device links (devicelink.go); nil links disables the feature.
	links        DeviceLinkStore
	rlLinkIssue  *RateLimiter
	rlLinkRedeem *RateLimiter
}

// SessionListener hears about sessions ending so long-lived streams (the
// account feed) close at once instead of at their next re-check.
// Implementations must not block. Reasons: "revoked", "expired", "deleted".
type SessionListener interface {
	SessionEnded(token, reason string)
	UserSessionsEnded(userID uuid.UUID, reason string)
}

// SetSessionListener wires the listener; nil disables.
func (s *Service) SetSessionListener(l SessionListener) { s.listener = l }

func NewService(users UserRepo, sessions SessionStore, consents ConsentStore, audit AuditRecorder, cfg Config) (*Service, error) {
	if users == nil || sessions == nil || consents == nil || audit == nil {
		return nil, fmt.Errorf("auth: nil dependency: users=%v sessions=%v consents=%v audit=%v",
			users == nil, sessions == nil, consents == nil, audit == nil)
	}
	cfg = cfg.withDefaults()
	dummy, err := bcrypt.GenerateFromPassword([]byte("lumi-dummy-"+uuid.NewString()), cfg.BcryptCost)
	if err != nil {
		return nil, fmt.Errorf("auth: precompute dummy hash: %w", err)
	}
	return &Service{
		users:     users,
		sessions:  sessions,
		consents:  consents,
		audit:     audit,
		cfg:       cfg,
		dummyHash: string(dummy),
		rlUser:    NewRateLimiter(5, time.Minute, 30*time.Minute),
		rlIP:      NewRateLimiter(30, time.Minute, 30*time.Minute),
	}, nil
}

func (s *Service) Config() Config { return s.cfg }

type ConsentInput struct {
	TosVersion     string
	PrivacyVersion string
}

type RegisterInput struct {
	Username    string
	Password    string
	DisplayName string
	Consent     ConsentInput
	IP          string
	UserAgent   string
}

type LoginInput struct {
	Username  string
	Password  string
	IP        string
	UserAgent string
}

const (
	usernameMin = 3
	usernameMax = 32
)

// CanonicaliseUsername applies the registration rules (trim, lower-case,
// 3-32 of [a-z0-9_-], no leading/trailing separator). Exposed so operator
// tooling creates accounts under exactly the same rules as Register.
func CanonicaliseUsername(raw string) (string, error) { return canonicaliseUsername(raw) }

func canonicaliseUsername(raw string) (string, error) {
	u := strings.TrimSpace(strings.ToLower(raw))
	if len(u) < usernameMin || len(u) > usernameMax {
		return "", fmt.Errorf("auth: username length out of range: %w", domain.ErrValidation)
	}
	for i, r := range u {
		switch {
		case unicode.IsLower(r), unicode.IsDigit(r):
		case r == '-' || r == '_':
			if i == 0 || i == len(u)-1 {
				return "", fmt.Errorf("auth: username may not start or end with separator: %w", domain.ErrValidation)
			}
		default:
			return "", fmt.Errorf("auth: username contains invalid character %q: %w", r, domain.ErrValidation)
		}
	}
	return u, nil
}

// Register creates a new user, records consent, and issues an initial session.
func (s *Service) Register(ctx context.Context, in RegisterInput) (domain.Session, error) {
	return s.register(ctx, in, s.cfg.RequireConsent)
}

// registerSkippingConsent is the bootstrap entry point.
func (s *Service) registerSkippingConsent(ctx context.Context, in RegisterInput) (domain.Session, error) {
	return s.register(ctx, in, false)
}

func (s *Service) register(ctx context.Context, in RegisterInput, requireConsent bool) (domain.Session, error) {
	username, err := canonicaliseUsername(in.Username)
	if err != nil {
		return domain.Session{}, err
	}
	if err := ValidatePassword(in.Password); err != nil {
		return domain.Session{}, err
	}
	if requireConsent {
		if strings.TrimSpace(in.Consent.TosVersion) == "" || strings.TrimSpace(in.Consent.PrivacyVersion) == "" {
			return domain.Session{}, fmt.Errorf("auth: missing consent versions: %w", domain.ErrConsentRequired)
		}
		if s.cfg.TosVersion != "" && in.Consent.TosVersion != s.cfg.TosVersion {
			return domain.Session{}, fmt.Errorf("auth: stale tos version: %w", domain.ErrConsentRequired)
		}
		if s.cfg.PrivacyVersion != "" && in.Consent.PrivacyVersion != s.cfg.PrivacyVersion {
			return domain.Session{}, fmt.Errorf("auth: stale privacy version: %w", domain.ErrConsentRequired)
		}
	}

	hash, err := HashPassword(in.Password, s.cfg.BcryptCost)
	if err != nil {
		return domain.Session{}, fmt.Errorf("auth: register: %w", err)
	}

	user, err := s.users.CreateUser(ctx, CreateUserInput{
		Username:     username,
		PasswordHash: hash,
		DisplayName:  strings.TrimSpace(in.DisplayName),
	})
	if err != nil {
		return domain.Session{}, fmt.Errorf("auth: create user: %w", err)
	}

	tosVersion := in.Consent.TosVersion
	privacyVersion := in.Consent.PrivacyVersion
	if tosVersion == "" {
		tosVersion = s.cfg.TosVersion
	}
	if privacyVersion == "" {
		privacyVersion = s.cfg.PrivacyVersion
	}
	consent := domain.Consent{
		UserID:         user.ID,
		TosVersion:     tosVersion,
		PrivacyVersion: privacyVersion,
		AcceptedAt:     time.Now().UTC(),
		IP:             nilIfEmpty(in.IP),
		UserAgent:      nilIfEmpty(in.UserAgent),
	}
	if err := s.consents.RecordConsent(ctx, consent); err != nil {
		return domain.Session{}, fmt.Errorf("auth: record consent: %w", err)
	}

	session, err := s.issueSession(ctx, user.ID)
	if err != nil {
		return domain.Session{}, fmt.Errorf("auth: register: %w", err)
	}

	s.recordAudit(ctx, domain.AuditEntry{
		UserID:    &user.ID,
		Action:    domain.ActionAuthRegister,
		Payload:   mustJSON(map[string]any{"username": user.Username}),
		IP:        nilIfEmpty(in.IP),
		UserAgent: nilIfEmpty(in.UserAgent),
	})
	s.recordAudit(ctx, domain.AuditEntry{
		UserID:    &user.ID,
		Action:    domain.ActionConsentAccept,
		Payload:   mustJSON(map[string]any{"tos_version": tosVersion, "privacy_version": privacyVersion}),
		IP:        nilIfEmpty(in.IP),
		UserAgent: nilIfEmpty(in.UserAgent),
	})
	return session, nil
}

// Login authenticates and issues a session. Constant-time on user-not-found
// via a precomputed dummy hash.
func (s *Service) Login(ctx context.Context, in LoginInput) (domain.Session, error) {
	user, err := s.verifyLogin(ctx, in, domain.ActionAuthLoginFailed)
	if err != nil {
		return domain.Session{}, err
	}
	session, err := s.issueSession(ctx, user.ID)
	if err != nil {
		return domain.Session{}, fmt.Errorf("auth: login issue session: %w", err)
	}
	s.recordAudit(ctx, domain.AuditEntry{
		UserID:    &user.ID,
		Action:    domain.ActionAuthLogin,
		IP:        nilIfEmpty(in.IP),
		UserAgent: nilIfEmpty(in.UserAgent),
	})
	return session, nil
}

// AdminLogin verifies an admin-panel password login (SPEC-PARTE2 §10)
// with exactly the public login's checks: the same per-IP and per-user
// rate limiters, bcrypt against a dummy hash for unknown users, the
// persistent lockout and failed-login accounting. The account must also
// be a server admin. Every refusal is audited as admin.login_failed and
// answered with domain.ErrInvalidCredentials (or domain.ErrRateLimited),
// so the caller cannot tell an unknown user from a wrong password, a
// disabled account or a non-admin. The one exception mirrors the public
// login: a locked server admin who gives the RIGHT password gets
// *domain.AccountLockedError. It issues nothing: the admin service
// mints its own session token.
func (s *Service) AdminLogin(ctx context.Context, in LoginInput) (domain.User, error) {
	user, err := s.verifyLogin(ctx, in, domain.ActionAdminLoginFailed)
	var locked *domain.AccountLockedError
	if errors.As(err, &locked) && !user.ServerAdmin {
		// The panel tells a lock only to a server admin who proved the
		// password; anyone else learns nothing about the account.
		return domain.User{}, domain.ErrInvalidCredentials
	}
	if err != nil {
		return domain.User{}, err
	}
	if !user.ServerAdmin {
		// The password was right: no lockout count, but still refused
		// with the same answer, after the same bcrypt cost.
		id := user.ID
		s.recordFailure(ctx, domain.ActionAdminLoginFailed, &id, in, "not_server_admin")
		return domain.User{}, domain.ErrInvalidCredentials
	}
	return user, nil
}

// verifyLogin is the credential check shared by Login and AdminLogin;
// failAction is the audit action of its refusals.
func (s *Service) verifyLogin(ctx context.Context, in LoginInput, failAction string) (domain.User, error) {
	fail := func(uid *uuid.UUID, reason string) {
		s.recordFailure(ctx, failAction, uid, in, reason)
	}
	username, err := canonicaliseUsername(in.Username)
	if err != nil {
		s.consumeFailureBudget("", in.IP)
		_ = CheckPassword(s.dummyHash, in.Password)
		fail(nil, "invalid_username")
		return domain.User{}, domain.ErrInvalidCredentials
	}

	if !s.rlIP.Allow(in.IP) {
		fail(nil, "rate_limited_ip")
		return domain.User{}, fmt.Errorf("auth: ip throttled: %w", domain.ErrRateLimited)
	}
	if !s.rlUser.Allow(username) {
		fail(nil, "rate_limited_user")
		return domain.User{}, fmt.Errorf("auth: user throttled: %w", domain.ErrRateLimited)
	}

	user, lookupErr := s.users.GetByUsername(ctx, username)
	hash := s.dummyHash
	var realUser bool
	if lookupErr == nil {
		hash = user.PasswordHash
		realUser = true
	} else if !errors.Is(lookupErr, domain.ErrNotFound) {
		_ = CheckPassword(s.dummyHash, in.Password)
		fail(nil, "lookup_error")
		return domain.User{}, domain.ErrInvalidCredentials
	}

	// A disabled account gets the same answer as a wrong password, after
	// the same bcrypt cost, so the response reveals neither the state nor
	// that the account exists. A locked account is told so only when the
	// password is right (the caller already owns the account); a wrong
	// password during the lock is the generic refusal and does not extend
	// the lock.
	if realUser {
		now := time.Now()
		if reason := blockedReason(user, now); reason != "" {
			id := user.ID
			if reason == "account_locked" {
				if CheckPassword(hash, in.Password) == nil {
					fail(&id, reason)
					return user, &domain.AccountLockedError{RetryAfter: user.LockedUntil.Sub(now)}
				}
				fail(&id, "account_locked_bad_password")
				return domain.User{}, domain.ErrInvalidCredentials
			}
			_ = CheckPassword(s.dummyHash, in.Password)
			fail(&id, reason)
			return domain.User{}, domain.ErrInvalidCredentials
		}
	}

	cmpErr := CheckPassword(hash, in.Password)
	if !realUser || cmpErr != nil {
		var uid *uuid.UUID
		if realUser {
			id := user.ID
			uid = &id
			s.countLoginFailure(ctx, id)
		}
		fail(uid, "invalid_credentials")
		return domain.User{}, domain.ErrInvalidCredentials
	}

	s.rlUser.Reset(username)
	if user.FailedLogins > 0 || user.LockedUntil != nil {
		s.resetLoginFailures(ctx, user.ID)
	}
	return user, nil
}

func (s *Service) Logout(ctx context.Context, token string) error {
	if token == "" {
		return nil
	}
	sess, err := s.sessions.GetSession(ctx, token)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return nil
		}
		return fmt.Errorf("auth: logout lookup: %w", err)
	}
	if err := s.sessions.DeleteSession(ctx, token); err != nil {
		return fmt.Errorf("auth: logout delete: %w", err)
	}
	if s.listener != nil {
		s.listener.SessionEnded(token, "revoked")
	}
	uid := sess.UserID
	s.recordAudit(ctx, domain.AuditEntry{
		UserID: &uid,
		Action: domain.ActionAuthLogout,
	})
	return nil
}

// CheckPassword satisfies users.PasswordChecker (LGPD erasure password
// confirmation flow).
func (s *Service) CheckPassword(ctx context.Context, userID uuid.UUID, password string) error {
	user, err := s.users.GetByID(ctx, userID)
	if err != nil {
		_ = CheckPassword(s.dummyHash, password)
		return domain.ErrInvalidCredentials
	}
	return CheckPassword(user.PasswordHash, password)
}

func (s *Service) ChangePassword(ctx context.Context, userID uuid.UUID, oldPassword, newPassword string) error {
	user, err := s.users.GetByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("auth: change password: %w", err)
	}
	if err := CheckPassword(user.PasswordHash, oldPassword); err != nil {
		s.recordAudit(ctx, domain.AuditEntry{
			UserID:  &userID,
			Action:  domain.ActionAuthLoginFailed,
			Payload: mustJSON(map[string]any{"reason": "old_password_mismatch", "in": "change_password"}),
		})
		return domain.ErrInvalidCredentials
	}
	if err := ValidatePassword(newPassword); err != nil {
		return err
	}
	if oldPassword == newPassword {
		return fmt.Errorf("auth: new password equals old: %w", domain.ErrValidation)
	}
	hash, err := HashPassword(newPassword, s.cfg.BcryptCost)
	if err != nil {
		return fmt.Errorf("auth: change password hash: %w", err)
	}
	if err := s.users.UpdatePasswordHash(ctx, userID, hash); err != nil {
		return fmt.Errorf("auth: change password store: %w", err)
	}
	if _, err := s.sessions.DeleteSessionsForUser(ctx, userID); err != nil {
		s.cfg.Logger.Warn().Err(err).Str("user_id", userID.String()).Msg("auth: failed to revoke sessions after password change")
	}
	if s.listener != nil {
		s.listener.UserSessionsEnded(userID, "revoked")
	}
	s.recordAudit(ctx, domain.AuditEntry{
		UserID: &userID,
		Action: domain.ActionAuthPasswordChange,
	})
	return nil
}

func (s *Service) UpdateDisplayName(ctx context.Context, userID uuid.UUID, displayName string) error {
	dn := strings.TrimSpace(displayName)
	if len(dn) > 80 {
		return fmt.Errorf("auth: display name too long: %w", domain.ErrValidation)
	}
	if err := s.users.UpdateDisplayName(ctx, userID, dn); err != nil {
		return fmt.Errorf("auth: update display name: %w", err)
	}
	s.recordAudit(ctx, domain.AuditEntry{
		UserID:  &userID,
		Action:  domain.ActionUserUpdate,
		Payload: mustJSON(map[string]any{"field": "display_name"}),
	})
	return nil
}

// Validate is called by the middleware on every authenticated request.
func (s *Service) Validate(ctx context.Context, token string) (domain.Session, domain.User, error) {
	if token == "" {
		return domain.Session{}, domain.User{}, domain.ErrTokenInvalid
	}
	sess, err := s.sessions.GetSession(ctx, token)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return domain.Session{}, domain.User{}, domain.ErrTokenInvalid
		}
		return domain.Session{}, domain.User{}, fmt.Errorf("auth: validate lookup: %w", err)
	}

	now := time.Now().UTC()
	if !sess.ExpiresAt.After(now) {
		_ = s.sessions.DeleteSession(ctx, token)
		return domain.Session{}, domain.User{}, domain.ErrTokenExpired
	}

	user, err := s.users.GetByID(ctx, sess.UserID)
	if err != nil || user.DisabledAt != nil {
		_ = s.sessions.DeleteSession(ctx, token)
		return domain.Session{}, domain.User{}, domain.ErrTokenInvalid
	}

	newExpiry := now.Add(s.cfg.SessionTTL)
	if err := s.sessions.TouchSession(ctx, token, now, newExpiry); err == nil {
		sess.LastUsedAt = now
		sess.ExpiresAt = newExpiry
	} else {
		s.cfg.Logger.Warn().Err(err).Msg("auth: session touch failed")
	}
	return sess, user, nil
}

// Check reports whether token is still a live session WITHOUT sliding its
// TTL (Validate does slide). Used by the account feed's periodic re-check.
// reason is "" while valid, else "revoked" (unknown token: logged out or
// revoked), "expired" or "deleted" (user erased). err is a transient
// lookup failure.
func (s *Service) Check(ctx context.Context, token string) (reason string, err error) {
	if token == "" {
		return "revoked", nil
	}
	sess, err := s.sessions.GetSession(ctx, token)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return "revoked", nil
		}
		return "", fmt.Errorf("auth: check lookup: %w", err)
	}
	if !sess.ExpiresAt.After(time.Now().UTC()) {
		return "expired", nil
	}
	user, err := s.users.GetByID(ctx, sess.UserID)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return "deleted", nil
		}
		return "", fmt.Errorf("auth: check user: %w", err)
	}
	if user.DisabledAt != nil {
		return "revoked", nil
	}
	return "", nil
}

func (s *Service) issueSession(ctx context.Context, userID uuid.UUID) (domain.Session, error) {
	token, err := IssueToken()
	if err != nil {
		return domain.Session{}, fmt.Errorf("auth: issue token: %w", err)
	}
	now := time.Now().UTC()
	sess := domain.Session{
		Token:      token,
		UserID:     userID,
		CreatedAt:  now,
		ExpiresAt:  now.Add(s.cfg.SessionTTL),
		LastUsedAt: now,
	}
	if err := s.sessions.CreateSession(ctx, sess); err != nil {
		return domain.Session{}, fmt.Errorf("auth: persist session: %w", err)
	}
	return sess, nil
}

// HashPassword exposes the password-hashing primitive for callers (e.g.
// internal/invites which creates users without going through Register).
func (s *Service) HashPassword(plaintext string) (string, error) {
	return HashPassword(plaintext, s.cfg.BcryptCost)
}

// NewSessionToken exposes session-token issuance to callers like
// internal/invites that synthesise a session at the end of accept-with-signup.
func (s *Service) NewSessionToken() string {
	t, _ := IssueToken()
	return t
}

// Persistent lockout (docs/ADMIN.md): after LockoutThreshold consecutive
// wrong passwords an existing account refuses logins for 2^(n-threshold)
// seconds, capped at LockoutMax. Unlike the in-memory limiters it survives
// restarts and is visible to (and cleared by) the operator.
const (
	LockoutThreshold = 10
	LockoutMax       = 15 * time.Minute
)

// LoginAttempts is the optional persistent-lockout surface of a UserRepo
// (implemented by *pg.UserStore). Repos without it skip the lockout.
type LoginAttempts interface {
	RecordLoginFailure(ctx context.Context, id uuid.UUID, threshold int, maxLock time.Duration) error
	ResetLoginFailures(ctx context.Context, id uuid.UUID) error
}

// blockedReason is "account_disabled", "account_locked" or "".
func blockedReason(u domain.User, now time.Time) string {
	switch {
	case u.DisabledAt != nil:
		return "account_disabled"
	case u.LockedUntil != nil && u.LockedUntil.After(now):
		return "account_locked"
	}
	return ""
}

func (s *Service) countLoginFailure(ctx context.Context, id uuid.UUID) {
	la, ok := s.users.(LoginAttempts)
	if !ok {
		return
	}
	if err := la.RecordLoginFailure(ctx, id, LockoutThreshold, LockoutMax); err != nil {
		s.cfg.Logger.Warn().Err(err).Msg("auth: record login failure")
	}
}

func (s *Service) resetLoginFailures(ctx context.Context, id uuid.UUID) {
	la, ok := s.users.(LoginAttempts)
	if !ok {
		return
	}
	if err := la.ResetLoginFailures(ctx, id); err != nil {
		s.cfg.Logger.Warn().Err(err).Msg("auth: reset login failures")
	}
}

func (s *Service) consumeFailureBudget(username, ip string) {
	if username != "" {
		s.rlUser.Allow(username)
	}
	if ip != "" {
		s.rlIP.Allow(ip)
	}
}

func (s *Service) recordFailure(ctx context.Context, action string, uid *uuid.UUID, in LoginInput, reason string) {
	s.recordAudit(ctx, domain.AuditEntry{
		UserID:    uid,
		Action:    action,
		Payload:   mustJSON(map[string]any{"reason": reason, "username": maskUsername(in.Username)}),
		IP:        nilIfEmpty(in.IP),
		UserAgent: nilIfEmpty(in.UserAgent),
	})
}

func (s *Service) recordAudit(ctx context.Context, e domain.AuditEntry) {
	if s.audit == nil {
		return
	}
	if err := s.audit.Record(ctx, e); err != nil {
		s.cfg.Logger.Error().Err(err).Str("action", e.Action).Msg("auth: audit record failed")
	}
}

func maskUsername(u string) string {
	u = strings.ToLower(strings.TrimSpace(u))
	if u == "" {
		return ""
	}
	if len(u) <= 2 {
		return u[:1] + "*"
	}
	return u[:1] + strings.Repeat("*", len(u)-2) + u[len(u)-1:]
}

func nilIfEmpty(s string) *string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	return &s
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		return []byte("{}")
	}
	return b
}
