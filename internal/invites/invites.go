// Package invites generates and validates vault invitation tokens, and
// implements the accept-and-signup-in-one-step flow.
package invites

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
	"unicode"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"

	"github.com/ViniZap4/lumi-server/internal/audit"
	"github.com/ViniZap4/lumi-server/internal/capguard"
	"github.com/ViniZap4/lumi-server/internal/domain"
)

// Tunables.
var (
	MinMaxUses     = 1
	MaxMaxUses     = 100
	MaxLifetime    = 30 * 24 * time.Hour
	MinLifetime    = 1 * time.Minute
	SessionTTL     = 30 * 24 * time.Hour
	MinPasswordLen = 8
	UsernameMinLen = 3
	UsernameMaxLen = 32
)

// Repo persists invite rows.
type Repo interface {
	Create(ctx context.Context, inv domain.Invite) error
	Get(ctx context.Context, token string) (domain.Invite, error)
	IncrementUse(ctx context.Context, token string, now time.Time) (domain.Invite, error)
	Revoke(ctx context.Context, token string, now time.Time) error
	ListForVault(ctx context.Context, vaultID uuid.UUID) ([]domain.Invite, error)
}

// UserRepo is the slice the invite service needs.
type UserRepo interface {
	GetByUsername(ctx context.Context, username string) (domain.User, error)
	CreateUserDirect(ctx context.Context, u domain.User) error
}

// MemberRepo is the slice the invite service needs.
type MemberRepo interface {
	Add(ctx context.Context, m domain.Member) error
	Get(ctx context.Context, vaultID, userID uuid.UUID) (domain.Member, error)
}

// VaultRepo is the slice the invite service needs.
type VaultRepo interface {
	GetByID(ctx context.Context, id uuid.UUID) (domain.Vault, error)
	GetBySlug(ctx context.Context, slug string) (domain.Vault, error)
}

// RoleRepo is the slice the invite service needs.
type RoleRepo interface {
	GetByID(ctx context.Context, roleID uuid.UUID) (domain.Role, error)
}

// ConsentRepo is the slice the invite service needs.
type ConsentRepo interface {
	Record(ctx context.Context, c domain.Consent) error
}

// SessionRepo is the slice the invite service needs.
type SessionRepo interface {
	Create(ctx context.Context, s domain.Session) error
}

// AuthHasher hides password hashing to avoid an import cycle.
type AuthHasher interface {
	HashPassword(plaintext string) (string, error)
}

// TokenIssuer hides session-token issuance to avoid an import cycle.
type TokenIssuer interface {
	NewSessionToken() string
}

// IssueToken returns a 32-byte hex random token for invites.
func IssueToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("invites: crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(b)
}

// Service is the public façade.
type Service struct {
	repo          Repo
	users         UserRepo
	members       MemberRepo
	vaults        VaultRepo
	roles         RoleRepo
	consents      ConsentRepo
	sessions      SessionRepo
	hasher        AuthHasher
	tokens        TokenIssuer
	audit         audit.Recorder
	publicBaseURL string
	now           func() time.Time
}

type Deps struct {
	Repo          Repo
	Users         UserRepo
	Members       MemberRepo
	Vaults        VaultRepo
	Roles         RoleRepo
	Consents      ConsentRepo
	Sessions      SessionRepo
	Hasher        AuthHasher
	Tokens        TokenIssuer
	Audit         audit.Recorder
	PublicBaseURL string
	Now           func() time.Time
}

func NewService(d Deps) *Service {
	if d.Repo == nil || d.Users == nil || d.Members == nil || d.Vaults == nil ||
		d.Roles == nil || d.Consents == nil || d.Sessions == nil ||
		d.Hasher == nil || d.Tokens == nil {
		panic("invites.NewService: nil dependency")
	}
	a := d.Audit
	if a == nil {
		a = audit.Noop{}
	}
	now := d.Now
	if now == nil {
		now = time.Now
	}
	return &Service{
		repo:          d.Repo,
		users:         d.Users,
		members:       d.Members,
		vaults:        d.Vaults,
		roles:         d.Roles,
		consents:      d.Consents,
		sessions:      d.Sessions,
		hasher:        d.Hasher,
		tokens:        d.Tokens,
		audit:         a,
		publicBaseURL: strings.TrimRight(d.PublicBaseURL, "/"),
		now:           now,
	}
}

type CreateInput struct {
	VaultID   uuid.UUID
	RoleID    uuid.UUID
	InviterID uuid.UUID
	MaxUses   int
	ExpiresAt time.Time
	EmailHint string
	IP        string
	UA        string
}

func (s *Service) Create(ctx context.Context, in CreateInput) (domain.Invite, error) {
	if in.VaultID == uuid.Nil || in.RoleID == uuid.Nil || in.InviterID == uuid.Nil {
		return domain.Invite{}, fmt.Errorf("%w: vault_id, role_id, inviter_id required", domain.ErrValidation)
	}
	if in.MaxUses < MinMaxUses || in.MaxUses > MaxMaxUses {
		return domain.Invite{}, fmt.Errorf("%w: max_uses must be in [%d,%d]", domain.ErrValidation, MinMaxUses, MaxMaxUses)
	}
	now := s.now().UTC()
	if !in.ExpiresAt.After(now.Add(MinLifetime)) {
		return domain.Invite{}, fmt.Errorf("%w: expires_at too soon", domain.ErrValidation)
	}
	if in.ExpiresAt.Sub(now) > MaxLifetime {
		return domain.Invite{}, fmt.Errorf("%w: expires_at exceeds max lifetime", domain.ErrValidation)
	}
	role, err := s.roles.GetByID(ctx, in.RoleID)
	if err != nil {
		return domain.Invite{}, fmt.Errorf("load role: %w", err)
	}
	if role.VaultID != in.VaultID {
		return domain.Invite{}, fmt.Errorf("%w: role does not belong to vault", domain.ErrValidation)
	}

	inv := domain.Invite{
		Token:         IssueToken(),
		VaultID:       in.VaultID,
		InviterUserID: in.InviterID,
		RoleID:        in.RoleID,
		EmailHint:     strings.TrimSpace(in.EmailHint),
		MaxUses:       in.MaxUses,
		ExpiresAt:     in.ExpiresAt.UTC(),
		CreatedAt:     now,
	}
	if err := s.repo.Create(ctx, inv); err != nil {
		return domain.Invite{}, fmt.Errorf("persist invite: %w", err)
	}
	s.recordAudit(ctx, domain.ActionInviteCreate, &in.InviterID, &in.VaultID, in.IP, in.UA, map[string]any{
		"role_id":    in.RoleID.String(),
		"max_uses":   in.MaxUses,
		"expires_at": inv.ExpiresAt,
	})
	return inv, nil
}

type InviteInfo struct {
	VaultID       uuid.UUID
	VaultName     string
	VaultSlug     string
	RoleID        uuid.UUID
	RoleName      string
	InviterUserID uuid.UUID
	ExpiresAt     time.Time
	MaxUses       int
	UseCount      int
	EmailHint     string
}

func (s *Service) Info(ctx context.Context, token string) (InviteInfo, error) {
	if token == "" {
		return InviteInfo{}, domain.ErrNotFound
	}
	inv, err := s.repo.Get(ctx, token)
	if err != nil {
		return InviteInfo{}, err
	}
	if err := s.checkUsable(inv); err != nil {
		return InviteInfo{}, err
	}
	vault, err := s.vaults.GetByID(ctx, inv.VaultID)
	if err != nil {
		return InviteInfo{}, fmt.Errorf("load vault: %w", err)
	}
	role, err := s.roles.GetByID(ctx, inv.RoleID)
	if err != nil {
		return InviteInfo{}, fmt.Errorf("load role: %w", err)
	}
	return InviteInfo{
		VaultID:       vault.ID,
		VaultName:     vault.Name,
		VaultSlug:     vault.Slug,
		RoleID:        role.ID,
		RoleName:      role.Name,
		InviterUserID: inv.InviterUserID,
		ExpiresAt:     inv.ExpiresAt,
		MaxUses:       inv.MaxUses,
		UseCount:      inv.UseCount,
		EmailHint:     inv.EmailHint,
	}, nil
}

type ConsentInput struct {
	TosVersion     string
	PrivacyVersion string
	AcceptedAt     time.Time
}

type AcceptSignupInput struct {
	Token       string
	Username    string
	Password    string
	DisplayName string
	Consent     ConsentInput
	IP          string
	UA          string
}

// AcceptWithSignup creates a user, joins the vault, returns a session.
// Phase 1 trade-off: not transactional (storage tx not wired). Failure
// modes are handled by per-step error checks; partial state can be
// reconciled via background cleanup.
func (s *Service) AcceptWithSignup(ctx context.Context, in AcceptSignupInput) (domain.Session, error) {
	if err := s.validateSignup(in); err != nil {
		return domain.Session{}, err
	}
	username := strings.ToLower(strings.TrimSpace(in.Username))
	display := strings.TrimSpace(in.DisplayName)
	hash, err := s.hasher.HashPassword(in.Password)
	if err != nil {
		return domain.Session{}, fmt.Errorf("hash password: %w", err)
	}
	now := s.now().UTC()

	inv, err := s.repo.IncrementUse(ctx, in.Token, now)
	if err != nil {
		return domain.Session{}, err
	}
	user := domain.User{
		ID:           uuid.New(),
		Username:     username,
		PasswordHash: hash,
		DisplayName:  display,
		CreatedAt:    now,
	}
	if err := s.users.CreateUserDirect(ctx, user); err != nil {
		return domain.Session{}, fmt.Errorf("create user: %w", err)
	}
	consent := domain.Consent{
		UserID:         user.ID,
		TosVersion:     in.Consent.TosVersion,
		PrivacyVersion: in.Consent.PrivacyVersion,
		AcceptedAt:     coalesce(in.Consent.AcceptedAt, now),
		IP:             nilIfEmpty(in.IP),
		UserAgent:      nilIfEmpty(in.UA),
	}
	if err := s.consents.Record(ctx, consent); err != nil {
		return domain.Session{}, fmt.Errorf("record consent: %w", err)
	}
	if err := s.members.Add(ctx, domain.Member{
		VaultID: inv.VaultID, UserID: user.ID, RoleID: inv.RoleID, JoinedAt: now,
	}); err != nil {
		return domain.Session{}, fmt.Errorf("add member: %w", err)
	}
	session := domain.Session{
		Token:      s.tokens.NewSessionToken(),
		UserID:     user.ID,
		CreatedAt:  now,
		ExpiresAt:  now.Add(SessionTTL),
		LastUsedAt: now,
	}
	if err := s.sessions.Create(ctx, session); err != nil {
		return domain.Session{}, fmt.Errorf("create session: %w", err)
	}
	s.recordAudit(ctx, domain.ActionAuthRegister, &user.ID, nil, in.IP, in.UA, map[string]any{"username": username, "via": "invite"})
	s.recordAudit(ctx, domain.ActionConsentAccept, &user.ID, nil, in.IP, in.UA, map[string]any{"tos_version": consent.TosVersion, "privacy_version": consent.PrivacyVersion})
	s.recordAudit(ctx, domain.ActionMemberAdd, &user.ID, &inv.VaultID, in.IP, in.UA, map[string]any{"role_id": inv.RoleID.String(), "via": "invite"})
	s.recordAudit(ctx, domain.ActionInviteAccept, &user.ID, &inv.VaultID, in.IP, in.UA, map[string]any{"signup": true})
	return session, nil
}

type AcceptExistingInput struct {
	Token  string
	UserID uuid.UUID
	IP     string
	UA     string
}

func (s *Service) AcceptAsExistingUser(ctx context.Context, in AcceptExistingInput) error {
	if in.Token == "" || in.UserID == uuid.Nil {
		return fmt.Errorf("%w: token + user_id required", domain.ErrValidation)
	}
	pre, err := s.repo.Get(ctx, in.Token)
	if err != nil {
		return err
	}
	if err := s.checkUsable(pre); err != nil {
		return err
	}
	if _, err := s.members.Get(ctx, pre.VaultID, in.UserID); err == nil {
		return fmt.Errorf("%w: user is already a member", domain.ErrConflict)
	} else if !errors.Is(err, domain.ErrNotFound) {
		return fmt.Errorf("check existing membership: %w", err)
	}

	now := s.now().UTC()
	inv, err := s.repo.IncrementUse(ctx, in.Token, now)
	if err != nil {
		return err
	}
	if err := s.members.Add(ctx, domain.Member{
		VaultID: inv.VaultID, UserID: in.UserID, RoleID: inv.RoleID, JoinedAt: now,
	}); err != nil {
		return fmt.Errorf("add member: %w", err)
	}
	s.recordAudit(ctx, domain.ActionMemberAdd, &in.UserID, &inv.VaultID, in.IP, in.UA, map[string]any{"role_id": inv.RoleID.String(), "via": "invite"})
	s.recordAudit(ctx, domain.ActionInviteAccept, &in.UserID, &inv.VaultID, in.IP, in.UA, map[string]any{"signup": false})
	return nil
}

func (s *Service) Revoke(ctx context.Context, vaultID uuid.UUID, token string, actorID uuid.UUID, ip, ua string) error {
	if vaultID == uuid.Nil || token == "" {
		return fmt.Errorf("%w: vault_id and token required", domain.ErrValidation)
	}
	inv, err := s.repo.Get(ctx, token)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(inv.VaultID[:], vaultID[:]) != 1 {
		return domain.ErrNotFound
	}
	if err := s.repo.Revoke(ctx, token, s.now().UTC()); err != nil {
		return err
	}
	s.recordAudit(ctx, domain.ActionInviteRevoke, &actorID, &vaultID, ip, ua, map[string]any{"role_id": inv.RoleID.String()})
	return nil
}

func (s *Service) List(ctx context.Context, vaultID uuid.UUID) ([]domain.Invite, error) {
	if vaultID == uuid.Nil {
		return nil, fmt.Errorf("%w: vault_id required", domain.ErrValidation)
	}
	return s.repo.ListForVault(ctx, vaultID)
}

func (s *Service) PublicURL(token string) string {
	if s.publicBaseURL == "" {
		return ""
	}
	return s.publicBaseURL + "/invite/" + token
}

func (s *Service) checkUsable(inv domain.Invite) error {
	if inv.RevokedAt != nil {
		return domain.ErrInviteRevoked
	}
	if !inv.ExpiresAt.After(s.now()) {
		return domain.ErrInviteExpired
	}
	if inv.UseCount >= inv.MaxUses {
		return domain.ErrInviteExhausted
	}
	return nil
}

func (s *Service) validateSignup(in AcceptSignupInput) error {
	if in.Token == "" {
		return fmt.Errorf("%w: token required", domain.ErrValidation)
	}
	if err := validateUsername(in.Username); err != nil {
		return err
	}
	if len(in.Password) < MinPasswordLen {
		return fmt.Errorf("%w: password too short", domain.ErrValidation)
	}
	if in.Consent.TosVersion == "" || in.Consent.PrivacyVersion == "" {
		return domain.ErrConsentRequired
	}
	return nil
}

func validateUsername(u string) error {
	u = strings.TrimSpace(u)
	if len(u) < UsernameMinLen || len(u) > UsernameMaxLen {
		return fmt.Errorf("%w: username length out of range", domain.ErrValidation)
	}
	for _, r := range u {
		switch {
		case unicode.IsLower(r), unicode.IsDigit(r):
		case r == '.' || r == '_' || r == '-':
		default:
			return fmt.Errorf("%w: username invalid character %q", domain.ErrValidation, r)
		}
	}
	return nil
}

func (s *Service) recordAudit(ctx context.Context, action string, userID, vaultID *uuid.UUID, ip, ua string, payload map[string]any) {
	body, err := json.Marshal(payload)
	if err != nil {
		body = []byte(`{}`)
	}
	entry := domain.AuditEntry{
		UserID:    userID,
		VaultID:   vaultID,
		Action:    action,
		Payload:   body,
		IP:        nilIfEmpty(ip),
		UserAgent: nilIfEmpty(ua),
		CreatedAt: s.now().UTC(),
	}
	_ = s.audit.Record(ctx, entry)
}

func nilIfEmpty(s string) *string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	return &s
}

func coalesce(t, fallback time.Time) time.Time {
	if t.IsZero() {
		return fallback
	}
	return t
}

// ---- Handlers --------------------------------------------------------------

const userIDKey = "auth.user"

type Handlers struct {
	svc *Service
}

func NewHandlers(svc *Service) *Handlers { return &Handlers{svc: svc} }

func (h *Handlers) Register(app *fiber.App, authedGroup fiber.Router, resolver capguard.Resolver) {
	// Authed (vault-scoped) endpoints.
	authedGroup.Post("/vaults/:vault/invites",
		capguard.RequireCapability(resolver, domain.CapMembersInvite),
		h.create,
	)
	authedGroup.Get("/vaults/:vault/invites",
		capguard.RequireCapability(resolver, domain.CapMembersInvite),
		h.list,
	)
	authedGroup.Delete("/vaults/:vault/invites/:token",
		capguard.RequireCapability(resolver, domain.CapMembersInvite),
		h.revoke,
	)
	// Public endpoints.
	app.Get("/api/invites/:token", h.info)
	app.Post("/api/invites/:token/accept", h.accept)
}

type createReq struct {
	RoleID    string    `json:"role_id"`
	MaxUses   int       `json:"max_uses"`
	ExpiresAt time.Time `json:"expires_at"`
	EmailHint string    `json:"email_hint,omitempty"`
}

type createResp struct {
	Token     string    `json:"token"`
	URL       string    `json:"url,omitempty"`
	ExpiresAt time.Time `json:"expires_at"`
	MaxUses   int       `json:"max_uses"`
	UseCount  int       `json:"use_count"`
}

func (h *Handlers) create(c *fiber.Ctx) error {
	vaultID, err := capguard.WithVaultID(c)
	if err != nil {
		return nil
	}
	uid, _ := capguard.UserIDFrom(c)
	var req createReq
	if err := c.BodyParser(&req); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "invalid_body"})
	}
	roleID, err := uuid.Parse(req.RoleID)
	if err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "invalid_role_id"})
	}
	inv, err := h.svc.Create(c.UserContext(), CreateInput{
		VaultID:   vaultID,
		RoleID:    roleID,
		InviterID: uid,
		MaxUses:   req.MaxUses,
		ExpiresAt: req.ExpiresAt,
		EmailHint: req.EmailHint,
		IP:        c.IP(),
		UA:        string(c.Request().Header.UserAgent()),
	})
	if err != nil {
		return statusFromErr(c, err)
	}
	return c.Status(http.StatusCreated).JSON(createResp{
		Token:     inv.Token,
		URL:       h.svc.PublicURL(inv.Token),
		ExpiresAt: inv.ExpiresAt,
		MaxUses:   inv.MaxUses,
		UseCount:  inv.UseCount,
	})
}

func (h *Handlers) list(c *fiber.Ctx) error {
	vaultID, err := capguard.WithVaultID(c)
	if err != nil {
		return nil
	}
	rows, err := h.svc.List(c.UserContext(), vaultID)
	if err != nil {
		return statusFromErr(c, err)
	}
	out := make([]map[string]any, 0, len(rows))
	for _, r := range rows {
		out = append(out, map[string]any{
			"token":           r.Token,
			"vault_id":        r.VaultID.String(),
			"role_id":         r.RoleID.String(),
			"inviter_user_id": r.InviterUserID.String(),
			"email_hint":      r.EmailHint,
			"max_uses":        r.MaxUses,
			"use_count":       r.UseCount,
			"expires_at":      r.ExpiresAt,
			"created_at":      r.CreatedAt,
			"revoked_at":      r.RevokedAt,
		})
	}
	return c.JSON(fiber.Map{"invites": out})
}

func (h *Handlers) revoke(c *fiber.Ctx) error {
	vaultID, err := capguard.WithVaultID(c)
	if err != nil {
		return nil
	}
	uid, _ := capguard.UserIDFrom(c)
	token := c.Params("token")
	if err := h.svc.Revoke(c.UserContext(), vaultID, token, uid, c.IP(), string(c.Request().Header.UserAgent())); err != nil {
		return statusFromErr(c, err)
	}
	return c.SendStatus(http.StatusNoContent)
}

func (h *Handlers) info(c *fiber.Ctx) error {
	token := c.Params("token")
	info, err := h.svc.Info(c.UserContext(), token)
	if err != nil {
		return statusFromErr(c, err)
	}
	return c.JSON(fiber.Map{
		"vault_id":        info.VaultID.String(),
		"vault_name":      info.VaultName,
		"vault_slug":      info.VaultSlug,
		"role_id":         info.RoleID.String(),
		"role_name":       info.RoleName,
		"inviter_user_id": info.InviterUserID.String(),
		"expires_at":      info.ExpiresAt,
		"max_uses":        info.MaxUses,
		"use_count":       info.UseCount,
		"email_hint":      info.EmailHint,
		"requires_signup": !hasAuthHeader(c),
	})
}

type acceptSignupReq struct {
	Username    string  `json:"username"`
	Password    string  `json:"password"`
	DisplayName string  `json:"display_name,omitempty"`
	Consent     consent `json:"consent"`
}

type consent struct {
	TosVersion     string    `json:"tos_version"`
	PrivacyVersion string    `json:"privacy_version"`
	AcceptedAt     time.Time `json:"accepted_at"`
}

func (h *Handlers) accept(c *fiber.Ctx) error {
	token := c.Params("token")
	if token == "" {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "missing_token"})
	}
	ip := c.IP()
	ua := string(c.Request().Header.UserAgent())

	if hasAuthHeader(c) {
		v := c.Locals(userIDKey)
		u, _ := v.(*domain.User)
		if u == nil {
			return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized"})
		}
		if err := h.svc.AcceptAsExistingUser(c.UserContext(), AcceptExistingInput{
			Token: token, UserID: u.ID, IP: ip, UA: ua,
		}); err != nil {
			return statusFromErr(c, err)
		}
		info, _ := h.svc.Info(c.UserContext(), token)
		return c.JSON(fiber.Map{"vault": fiber.Map{
			"id": info.VaultID.String(), "slug": info.VaultSlug, "name": info.VaultName,
		}})
	}

	var req acceptSignupReq
	if err := c.BodyParser(&req); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "invalid_body"})
	}
	preview, _ := h.svc.Info(c.UserContext(), token)
	session, err := h.svc.AcceptWithSignup(c.UserContext(), AcceptSignupInput{
		Token:       token,
		Username:    req.Username,
		Password:    req.Password,
		DisplayName: req.DisplayName,
		Consent: ConsentInput{
			TosVersion:     req.Consent.TosVersion,
			PrivacyVersion: req.Consent.PrivacyVersion,
			AcceptedAt:     req.Consent.AcceptedAt,
		},
		IP: ip, UA: ua,
	})
	if err != nil {
		return statusFromErr(c, err)
	}
	return c.Status(http.StatusCreated).JSON(fiber.Map{
		"token":      session.Token,
		"expires_at": session.ExpiresAt,
		"vault": fiber.Map{
			"id":   preview.VaultID.String(),
			"slug": preview.VaultSlug,
			"name": preview.VaultName,
		},
	})
}

func hasAuthHeader(c *fiber.Ctx) bool {
	if v := strings.TrimSpace(c.Get("X-Lumi-Token")); v != "" {
		return true
	}
	if v := strings.TrimSpace(c.Get("Authorization")); v != "" {
		return true
	}
	return false
}

func statusFromErr(c *fiber.Ctx, err error) error {
	switch {
	case errors.Is(err, domain.ErrInviteExpired),
		errors.Is(err, domain.ErrInviteRevoked),
		errors.Is(err, domain.ErrInviteExhausted):
		return c.Status(http.StatusGone).JSON(fiber.Map{"error": err.Error()})
	case errors.Is(err, domain.ErrConflict):
		return c.Status(http.StatusConflict).JSON(fiber.Map{"error": err.Error()})
	case errors.Is(err, domain.ErrConsentRequired):
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "consent_required"})
	case errors.Is(err, domain.ErrValidation):
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	case errors.Is(err, domain.ErrUnauthorized), errors.Is(err, domain.ErrTokenInvalid), errors.Is(err, domain.ErrTokenExpired):
		return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized"})
	case errors.Is(err, domain.ErrForbidden), errors.Is(err, domain.ErrCapabilityMissing):
		return c.Status(http.StatusForbidden).JSON(fiber.Map{"error": "forbidden"})
	case errors.Is(err, domain.ErrNotFound):
		return c.Status(http.StatusNotFound).JSON(fiber.Map{"error": "not_found"})
	default:
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "internal"})
	}
}
