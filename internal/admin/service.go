package admin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/ViniZap4/lumi-server/internal/auth"
	"github.com/ViniZap4/lumi-server/internal/domain"
	"github.com/ViniZap4/lumi-server/internal/users"
)

// Audit actions written by the admin surface. They live in audit_log next
// to the domain events, with the admin token (never its value) in payload.
const (
	ActionTokenCreate      = "admin.token.create"
	ActionTokenRevoke      = "admin.token.revoke"
	ActionUserCreate       = "admin.user.create"
	ActionUserPassword     = "admin.user.password"
	ActionUserDisable      = "admin.user.disable"
	ActionUserEnable       = "admin.user.enable"
	ActionUserUnlock       = "admin.user.unlock"
	ActionUserDelete       = "admin.user.delete"
	ActionSessionRevoke    = "admin.session.revoke"
	ActionVaultDelete      = "admin.vault.delete"
	ActionFederationRevoke = "admin.federation.revoke"
	ActionUserLogout       = "admin.user.logout"
	ActionInviteRevoke     = "admin.invite.revoke"
	// Admin login with a user account (SPEC-PARTE2 §10).
	ActionSessionCreate   = "admin.session.create"
	ActionSessionLogout   = "admin.session.logout"
	ActionLoginFailed     = domain.ActionAdminLoginFailed
	ActionUserServerAdmin = "admin.user.server_admin"
)

// sessionTokenName is admin_tokens.name of every admin session. The
// user is admin_tokens.user_id, so the name (copied into audit payloads
// as token_name) carries no personal data.
const sessionTokenName = "session"

// Actor is who performs an admin action: an admin token over the API, or
// the CLI (TokenID nil, TokenName "cli").
type Actor struct {
	TokenID   *uuid.UUID
	TokenName string
	IP        string
}

// CLI is the actor of the terminal subcommands.
var CLI = Actor{TokenName: "cli"}

// ---- rows ---------------------------------------------------------------------

type Token struct {
	ID         uuid.UUID
	Name       string
	CreatedAt  time.Time
	LastUsedAt *time.Time
	ExpiresAt  time.Time
	RevokedAt  *time.Time

	// Kind is KindToken ("lpa_", CLI-made) or KindSession ("lps_", made
	// by a password login); empty reads as KindToken.
	Kind string
	// Sessions only: the signed-in user, and whether that account is
	// still a server admin and not disabled (checked on every call).
	UserID     *uuid.UUID
	Username   string
	UserActive bool
}

// IsSession reports whether t is an admin session ("lps_").
func (t Token) IsSession() bool { return t.Kind == KindSession }

// State is "active", "expired" or "revoked".
func (t Token) State(now time.Time) string {
	switch {
	case t.RevokedAt != nil:
		return "revoked"
	case !t.ExpiresAt.After(now):
		return "expired"
	}
	return "active"
}

type User struct {
	ID           uuid.UUID
	Username     string
	DisplayName  string
	CreatedAt    time.Time
	DisabledAt   *time.Time
	FailedLogins int
	LockedUntil  *time.Time
	Sessions     int // live (unexpired) sessions
	OwnedVaults  int
	Vaults       int        // memberships, owned included
	LastLoginAt  *time.Time // newest auth.login audit row
	LastSeenAt   *time.Time // newest session use
	ServerAdmin  bool       // may sign in to the admin panel
}

// State is "disabled", "locked" or "active" (disabled wins).
func (u User) State(now time.Time) string {
	switch {
	case u.DisabledAt != nil:
		return "disabled"
	case u.LockedUntil != nil && u.LockedUntil.After(now):
		return "locked"
	}
	return "active"
}

// Session is a user session as the operator sees it. ID is the stored
// SHA-256 of the bearer token: it identifies the row but cannot be used
// to authenticate.
type Session struct {
	ID         string
	UserID     uuid.UUID
	Username   string
	CreatedAt  time.Time
	LastUsedAt time.Time
	ExpiresAt  time.Time
}

type Vault struct {
	ID                uuid.UUID
	Slug              string
	Name              string
	OwnerID           uuid.UUID
	OwnerUsername     string
	Members           int // local members, owner included
	FederatedMembers  int // home side: members living on other servers
	Notes             int
	CRDTBytes         int64 // stored Yjs snapshots + pending updates
	FederationRole    *string
	ActiveFederations int
	HeadSeq           int64      // vault_heads.seq, 0 without a head
	LastChangeAt      *time.Time // vault_heads.updated_at
	InvitesActive     int
	CreatedAt         time.Time
}

// Member is a local vault membership as the operator sees it.
type Member struct {
	UserID      uuid.UUID
	Username    string
	DisplayName string
	RoleID      uuid.UUID
	RoleName    string
	Owner       bool
	JoinedAt    time.Time
}

// Role is a vault role with its member count.
type Role struct {
	ID      uuid.UUID
	Name    string
	Seed    bool
	Members int
}

// Invite is a vault join link. ID is the hex SHA-256 of the token: it
// names the row but cannot be used to join.
type Invite struct {
	ID              string
	VaultID         uuid.UUID
	VaultSlug       string
	VaultName       string
	InviterID       uuid.UUID
	InviterUsername string
	RoleID          uuid.UUID
	RoleName        string
	EmailHint       *string
	MaxUses         int
	UseCount        int
	ExpiresAt       time.Time
	CreatedAt       time.Time
	RevokedAt       *time.Time
}

// State is "revoked", "expired", "exhausted" or "active", in that order.
func (i Invite) State(now time.Time) string {
	switch {
	case i.RevokedAt != nil:
		return "revoked"
	case !i.ExpiresAt.After(now):
		return "expired"
	case i.UseCount >= i.MaxUses:
		return "exhausted"
	}
	return "active"
}

// UserFilter narrows the user list: Query is a case-insensitive substring
// of username or display name; State is "", "active", "disabled" or "locked".
type UserFilter struct {
	Query string
	State string
	// ServerAdmin keeps only the accounts flagged server_admin.
	ServerAdmin bool
}

// VaultFilter narrows the vault list: UserID keeps the vaults the user owns
// or belongs to; Query is a case-insensitive substring of slug or name.
type VaultFilter struct {
	UserID *uuid.UUID
	Query  string
}

// InviteFilter narrows the invite list.
type InviteFilter struct {
	VaultID    *uuid.UUID
	ActiveOnly bool
}

type Federation struct {
	ID           uuid.UUID
	VaultID      uuid.UUID
	VaultSlug    string
	VaultName    string
	Role         string
	PeerURL      string
	Jurisdiction *string
	Status       string
	LastAckedSeq int64
	ControlSeq   *int64
	CreatedAt    time.Time
	RevokedAt    *time.Time

	// One-way mirrors (docs/SPEC-ESPELHO-SELADO.md §A13).
	Mode           string // "replica" | "mirror"
	SeverPolicy    string // "keep" | "purge"
	MirrorAckedSeq int64  // home side
	HomeSeq        int64  // mirror side
	HeadSeq        int64  // this server's vault seq
	LastContactAt  *time.Time
	PausedAt       *time.Time
	PromotedAt     *time.Time
	// Home side of a mirror link: tombstones the mirror has not
	// acknowledged, and the oldest one's time.
	PendingDeletes        int64
	OldestPendingDeleteAt *time.Time
	Violations24h         int64
	// Backfill is the live catch-up of a mirror link on this (mirror)
	// server; nil when unknown (CLI, no session up).
	Backfill *BackfillProgress
}

// BackfillProgress is a mirror link's catch-up state.
type BackfillProgress struct {
	Active bool
	Synced int
	Total  int
}

// LagSeq is how many home seqs a mirror is behind (home side).
func (f Federation) LagSeq() int64 {
	if f.Role != "home" || f.Mode != "mirror" || f.HeadSeq <= f.MirrorAckedSeq {
		return 0
	}
	return f.HeadSeq - f.MirrorAckedSeq
}

// FederationFilter narrows a federation listing.
type FederationFilter struct {
	VaultID *uuid.UUID
	Mode    string // "" = any
}

type Counts struct {
	Users         int64
	Sessions      int64
	Vaults        int64
	Notes         int64
	Federations   int64 // active links
	SchemaVersion int64
	SchemaDirty   bool

	UsersDisabled    int64
	UsersLocked      int64 // locked and not disabled
	CRDTBytes        int64
	Logins24h        int64
	LoginFailures24h int64
	InvitesActive    int64
}

// AuditQuery pages audit_log newest first. Before is an exclusive id bound
// (0 = from the newest). Scope "admin" keeps only admin.* actions.
type AuditQuery struct {
	Before  int64
	Limit   int
	AdminOn bool
	UserID  *uuid.UUID
	VaultID *uuid.UUID
	// Action matches exactly, or as a prefix when ActionPrefix is set
	// ("auth." for the "auth.*" form).
	Action       string
	ActionPrefix bool
	Since        *time.Time // created_at >= Since
	Until        *time.Time // created_at < Until
}

// Cursor pages list routes ordered by (Time, Key).
type Cursor struct {
	Time time.Time
	Key  string
}

// ---- collaborators -------------------------------------------------------------

// Store is the admin persistence boundary (implemented by *pg.AdminStore).
// Every method that takes a domain.AuditEntry writes it in the same
// transaction as the change: if the row cannot be written, nothing changes.
type Store interface {
	CreateToken(ctx context.Context, t Token, digest []byte, e domain.AuditEntry) error
	TokenByDigest(ctx context.Context, digest []byte) (Token, error)
	GetToken(ctx context.Context, id uuid.UUID) (Token, error)
	TouchToken(ctx context.Context, id uuid.UUID, at time.Time) error
	ListTokens(ctx context.Context, after *Cursor, limit int) ([]Token, bool, error)
	RevokeToken(ctx context.Context, id uuid.UUID, at time.Time, e domain.AuditEntry) error

	Counts(ctx context.Context) (Counts, error)
	Ping(ctx context.Context) error

	ListUsers(ctx context.Context, f UserFilter, afterUsername string, limit int) ([]User, bool, error)
	GetUser(ctx context.Context, id uuid.UUID) (User, error)
	GetUserByUsername(ctx context.Context, username string) (User, error)
	OwnedVaultIDs(ctx context.Context, id uuid.UUID) ([]uuid.UUID, error)
	CreateUser(ctx context.Context, u domain.User, e domain.AuditEntry) error
	SetPassword(ctx context.Context, id uuid.UUID, hash string, e domain.AuditEntry) error
	SetDisabled(ctx context.Context, id uuid.UUID, disabled bool, e domain.AuditEntry) error
	Unlock(ctx context.Context, id uuid.UUID, e domain.AuditEntry) error
	// SetServerAdmin sets the flag with its audit row in one transaction.
	// Clearing it refuses with ErrLastServerAdmin when no other active
	// (not disabled) server admin would remain, and revokes the user's
	// admin sessions. Idempotent.
	SetServerAdmin(ctx context.Context, id uuid.UUID, enabled bool, e domain.AuditEntry) error

	ListSessions(ctx context.Context, userID *uuid.UUID, after *Cursor, limit int) ([]Session, bool, error)
	GetSession(ctx context.Context, id string) (Session, error)
	DeleteSession(ctx context.Context, id string, e domain.AuditEntry) error
	// EndUserSessions deletes every session of the user and writes the
	// audit row built from the count, in one transaction.
	EndUserSessions(ctx context.Context, userID uuid.UUID, e func(n int) domain.AuditEntry) (int, error)

	ListVaults(ctx context.Context, f VaultFilter, afterSlug string, limit int) ([]Vault, bool, error)
	GetVault(ctx context.Context, id uuid.UUID) (Vault, error)
	GetVaultBySlug(ctx context.Context, slug string) (Vault, error)
	VaultMembers(ctx context.Context, vaultID uuid.UUID) ([]Member, []Role, error)

	ListInvites(ctx context.Context, f InviteFilter, after *Cursor, limit int) ([]Invite, bool, error)
	GetInvite(ctx context.Context, id string) (Invite, error)
	RevokeInvite(ctx context.Context, id string, at time.Time, e domain.AuditEntry) error

	ListFederations(ctx context.Context, f FederationFilter, after *Cursor, limit int) ([]Federation, bool, error)
	GetFederation(ctx context.Context, id uuid.UUID) (Federation, error)
	// PromoteMirror turns a mirror into an independent home in one
	// transaction (see Service.PromoteMirror).
	PromoteMirror(ctx context.Context, vaultID uuid.UUID, now time.Time, plan func(state []byte) (Promotion, error), entry func(PromoteResult) domain.AuditEntry) (PromoteResult, error)

	RecordAudit(ctx context.Context, e domain.AuditEntry) error
	ListAudit(ctx context.Context, q AuditQuery) ([]domain.AuditEntry, bool, error)
}

// UserEraser is the LGPD erasure flow (*users.Service).
type UserEraser interface {
	Delete(ctx context.Context, id uuid.UUID, forceVaults bool, ip, ua *string) error
}

// VaultDeleter is the vault deletion flow (*vaults.Service).
type VaultDeleter interface {
	Delete(ctx context.Context, vaultID, actor uuid.UUID, ip, ua string) error
}

// FederationRevoker is the federation revoke flow (*federation.Service).
type FederationRevoker interface {
	RevokeFederation(ctx context.Context, vaultID, fedID, actor uuid.UUID, ip, ua string) error
}

// PasswordLogin verifies a panel password login with the public login's
// rules (*auth.Service.AdminLogin): bcrypt, per-IP and per-user rate
// limits, persistent lockout, failed-login accounting, server_admin
// required. Every refusal is domain.ErrInvalidCredentials (or
// domain.ErrRateLimited), already audited as admin.login_failed.
type PasswordLogin interface {
	AdminLogin(ctx context.Context, in auth.LoginInput) (domain.User, error)
}

// PasswordHasher hashes with the server's bcrypt cost (*auth.Service).
type PasswordHasher interface {
	HashPassword(plaintext string) (string, error)
}

// Live reaches the long-lived streams of the running server (*feed.Broker).
// Nil in the CLI: there, open streams close at their next periodic
// re-check, since their sessions are gone from the database.
type Live interface {
	UserSessionsEnded(userID uuid.UUID, reason string)
	SessionKeyEnded(key, reason string)
}

// Service is shared by the admin API and the CLI.
type Service struct {
	Store       Store
	Users       UserEraser
	Vaults      VaultDeleter
	Federations FederationRevoker
	Hasher      PasswordHasher
	Login       PasswordLogin // nil: POST /admin/v1/session is refused
	Live        Live
	Log         zerolog.Logger

	// One-way mirrors (mirror.go); nil refuses the operations.
	Mirrors MirrorOps
	// Progress reports a mirror link's live backfill (running server).
	Progress func(vaultID uuid.UUID) (BackfillProgress, bool)
	// Planner turns home's replicated control state into a promotion.
	Planner func(state []byte) (Promotion, error)

	Version       string
	MigrationsDir string

	now func() time.Time
}

func (s *Service) clock() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now()
}

// ---- errors ----------------------------------------------------------------------

// InvalidError is a 400 naming the offending field.
type InvalidError struct {
	Field  string
	Detail string
}

func (e *InvalidError) Error() string { return e.Field + ": " + e.Detail }
func (e *InvalidError) Unwrap() error { return domain.ErrValidation }

func invalid(field, detail string) error { return &InvalidError{Field: field, Detail: detail} }

// cleanDetail turns "auth: password shorter than 8 characters: validation
// failed" into "password shorter than 8 characters".
func cleanDetail(err error) string {
	msg := err.Error()
	msg = strings.TrimPrefix(msg, "auth: ")
	msg = strings.TrimSuffix(msg, ": "+domain.ErrValidation.Error())
	return msg
}

// ---- tokens ---------------------------------------------------------------------

// Authenticate resolves a raw bearer token. Every failure (malformed,
// unknown, expired, revoked) is domain.ErrUnauthorized, so callers answer
// them identically. Other errors are infrastructure failures.
//
// An admin session ("lps_") also needs its user to still be a server admin
// and not disabled: revoking the flag or disabling the account ends the
// session at its next call.
func (s *Service) Authenticate(ctx context.Context, raw string) (Token, error) {
	digest, kind, err := ParseCredential(raw)
	if err != nil {
		return Token{}, domain.ErrUnauthorized
	}
	t, err := s.Store.TokenByDigest(ctx, digest)
	if errors.Is(err, domain.ErrNotFound) {
		return Token{}, domain.ErrUnauthorized
	}
	if err != nil {
		return Token{}, err
	}
	if t.Kind == "" {
		t.Kind = KindToken
	}
	if t.Kind != kind || (t.IsSession() && !t.UserActive) {
		return Token{}, domain.ErrUnauthorized
	}
	now := s.clock()
	if t.State(now) != "active" {
		return Token{}, domain.ErrUnauthorized
	}
	if t.LastUsedAt == nil || now.Sub(*t.LastUsedAt) >= TouchInterval {
		if err := s.Store.TouchToken(ctx, t.ID, now); err != nil {
			s.Log.Warn().Err(err).Str("token_id", t.ID.String()).Msg("admin: touch token")
		} else {
			t.LastUsedAt = &now
		}
	}
	return t, nil
}

// ValidateTokenName applies the token naming rule: 1-64 characters, no
// control characters, surrounding space trimmed.
func ValidateTokenName(raw string) (string, error) {
	name := strings.TrimSpace(raw)
	if name == "" || utf8.RuneCountInString(name) > maxTokenName {
		return "", invalid("name", fmt.Sprintf("must have 1 to %d characters", maxTokenName))
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return "", invalid("name", "must not contain control characters")
		}
	}
	return name, nil
}

// CreateToken mints an admin token. Only the CLI calls it: the API has no
// route that creates tokens, so a leaked token cannot perpetuate itself.
func (s *Service) CreateToken(ctx context.Context, a Actor, name string, ttl time.Duration) (string, Token, error) {
	name, err := ValidateTokenName(name)
	if err != nil {
		return "", Token{}, err
	}
	if ttl < MinTokenTTL || ttl > MaxTokenTTL {
		return "", Token{}, invalid("ttl", fmt.Sprintf("must be between %s and %s", MinTokenTTL, MaxTokenTTL))
	}
	raw, digest := NewToken()
	now := s.clock().UTC()
	t := Token{ID: uuid.New(), Name: name, CreatedAt: now, ExpiresAt: now.Add(ttl)}
	e := s.entry(a, ActionTokenCreate, nil, nil, map[string]any{
		"target_token_id":   t.ID,
		"target_token_name": t.Name,
		"expires_at":        t.ExpiresAt.Format(time.RFC3339),
	})
	if err := s.Store.CreateToken(ctx, t, digest, e); err != nil {
		return "", Token{}, err
	}
	s.logAction(a, ActionTokenCreate).Str("target_token_id", t.ID.String()).Str("target_token_name", t.Name).Msg("admin action")
	return raw, t, nil
}

func (s *Service) ListTokens(ctx context.Context, after *Cursor, limit int) ([]Token, bool, error) {
	return s.Store.ListTokens(ctx, after, limit)
}

// RevokeToken revokes any token, the caller's own included (effective on
// its next call). Revoking an already revoked token is a no-op success
// that is still audited.
func (s *Service) RevokeToken(ctx context.Context, a Actor, id uuid.UUID) error {
	t, err := s.Store.GetToken(ctx, id)
	if err != nil {
		return err
	}
	e := s.entry(a, ActionTokenRevoke, nil, nil, map[string]any{
		"target_token_id":   t.ID,
		"target_token_name": t.Name,
	})
	if err := s.Store.RevokeToken(ctx, id, s.clock().UTC(), e); err != nil {
		return err
	}
	s.logAction(a, ActionTokenRevoke).Str("target_token_id", id.String()).Msg("admin action")
	return nil
}

// ---- admin sessions (password login) --------------------------------------------

// ErrLastServerAdmin refuses to clear the flag of the last active server
// admin (409 conflict, detail "last_server_admin").
var ErrLastServerAdmin = fmt.Errorf("%w: last_server_admin", domain.ErrConflict)

// errSessionLoginOff: the server was built without a PasswordLogin.
var errSessionLoginOff = errors.New("admin: password login not configured")

// CreateSession signs a server admin in with username and password and
// mints an admin session token ("lps_…", SessionTTL, shown once). The
// credential checks, rate limits, lockout and failure audit are the
// PasswordLogin's; every refusal is domain.ErrInvalidCredentials or
// domain.ErrRateLimited, never a hint that the user exists. ip and ua are
// the panel user's, as the panel forwards them.
func (s *Service) CreateSession(ctx context.Context, ip, ua, username, password string) (string, Token, error) {
	if s.Login == nil {
		return "", Token{}, errSessionLoginOff
	}
	u, err := s.Login.AdminLogin(ctx, auth.LoginInput{Username: username, Password: password, IP: ip, UserAgent: ua})
	if err != nil {
		return "", Token{}, err
	}
	raw, digest := NewSessionToken()
	now := s.clock().UTC()
	uid := u.ID
	t := Token{
		ID: uuid.New(), Name: sessionTokenName, Kind: KindSession,
		CreatedAt: now, ExpiresAt: now.Add(SessionTTL),
		UserID: &uid, Username: u.Username, UserActive: true,
	}
	a := Actor{TokenID: &t.ID, TokenName: t.Name, IP: ip}
	e := s.entry(a, ActionSessionCreate, &uid, nil, map[string]any{
		"username":   u.Username,
		"expires_at": t.ExpiresAt.Format(time.RFC3339),
	})
	if ua != "" {
		e.UserAgent = &ua
	}
	if err := s.Store.CreateToken(ctx, t, digest, e); err != nil {
		return "", Token{}, err
	}
	s.logAction(a, ActionSessionCreate).Str("user_id", uid.String()).Msg("admin action")
	return raw, t, nil
}

// EndSession revokes the caller's own admin session (panel "Sair").
// Only sessions sign out this way: an "lpa_" token is revoked by id
// (DELETE /tokens/{id}) or in the terminal.
func (s *Service) EndSession(ctx context.Context, a Actor, t Token) error {
	if !t.IsSession() {
		return fmt.Errorf("%w: not an admin session (revoke tokens by id)", domain.ErrConflict)
	}
	e := s.entry(a, ActionSessionLogout, t.UserID, nil, map[string]any{"username": t.Username})
	if err := s.Store.RevokeToken(ctx, t.ID, s.clock().UTC(), e); err != nil {
		return err
	}
	s.logAction(a, ActionSessionLogout).Msg("admin action")
	return nil
}

// SetServerAdmin grants or removes the server_admin flag. Removing it from
// the last active server admin is refused (ErrLastServerAdmin), whoever
// asks, so the panel's password login always keeps one account; removing
// it revokes that user's admin sessions. Idempotent and audited.
func (s *Service) SetServerAdmin(ctx context.Context, a Actor, id uuid.UUID, enabled bool) error {
	u, err := s.Store.GetUser(ctx, id)
	if err != nil {
		return err
	}
	e := s.entry(a, ActionUserServerAdmin, &u.ID, nil, map[string]any{"username": u.Username, "enabled": enabled})
	if err := s.Store.SetServerAdmin(ctx, id, enabled, e); err != nil {
		return err
	}
	s.logAction(a, ActionUserServerAdmin).Str("user_id", id.String()).Bool("enabled", enabled).Msg("admin action")
	return nil
}

// ---- status ------------------------------------------------------------------------

type Status struct {
	Version           string
	SchemaVersion     int64
	SchemaDirty       bool
	PendingMigrations int
	DBLatency         time.Duration
	GoVersion         string
	Counts
}

func (s *Service) Status(ctx context.Context) (Status, error) {
	start := time.Now()
	if err := s.Store.Ping(ctx); err != nil {
		return Status{}, err
	}
	latency := time.Since(start)
	c, err := s.Store.Counts(ctx)
	if err != nil {
		return Status{}, err
	}
	pending, err := PendingMigrations(s.MigrationsDir, c.SchemaVersion)
	if err != nil {
		s.Log.Warn().Err(err).Msg("admin: count pending migrations")
		pending = -1
	}
	return Status{
		Version:           s.Version,
		SchemaVersion:     c.SchemaVersion,
		SchemaDirty:       c.SchemaDirty,
		PendingMigrations: pending,
		DBLatency:         latency,
		GoVersion:         runtime.Version(),
		Counts:            c,
	}, nil
}

var migrationFile = regexp.MustCompile(`^(\d+)_.+\.up\.sql$`)

// PendingMigrations counts the up-migrations in dir newer than current.
func PendingMigrations(dir string, current int64) (int, error) {
	if dir == "" {
		return 0, errors.New("no migrations directory")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, e := range entries {
		m := migrationFile.FindStringSubmatch(filepath.Base(e.Name()))
		if m == nil {
			continue
		}
		v, err := strconv.ParseInt(m[1], 10, 64)
		if err == nil && v > current {
			n++
		}
	}
	return n, nil
}

// ---- users --------------------------------------------------------------------------

func (s *Service) ListUsers(ctx context.Context, after string, limit int) ([]User, bool, error) {
	return s.Store.ListUsers(ctx, UserFilter{}, after, limit)
}

// SearchUsers is ListUsers with a filter (validated by the caller).
func (s *Service) SearchUsers(ctx context.Context, f UserFilter, after string, limit int) ([]User, bool, error) {
	return s.Store.ListUsers(ctx, f, after, limit)
}

func (s *Service) GetUser(ctx context.Context, id uuid.UUID) (User, error) {
	return s.Store.GetUser(ctx, id)
}

// ResolveUser accepts a user id or a username (CLI convenience).
func (s *Service) ResolveUser(ctx context.Context, ref string) (User, error) {
	if id, err := uuid.Parse(ref); err == nil {
		return s.Store.GetUser(ctx, id)
	}
	name, err := auth.CanonicaliseUsername(ref)
	if err != nil {
		return User{}, fmt.Errorf("user %q: %w", ref, domain.ErrNotFound)
	}
	return s.Store.GetUserByUsername(ctx, name)
}

// ValidatePassword applies the registration password rules.
func ValidatePassword(pw string) error {
	if err := auth.ValidatePassword(pw); err != nil {
		return invalid("password", cleanDetail(err))
	}
	return nil
}

// CreateUser creates an account under the registration rules. No consent
// is recorded on the user's behalf: the operator cannot consent for them.
func (s *Service) CreateUser(ctx context.Context, a Actor, username, password, displayName string) (User, error) {
	name, err := auth.CanonicaliseUsername(username)
	if err != nil {
		return User{}, invalid("username", cleanDetail(err))
	}
	if err := ValidatePassword(password); err != nil {
		return User{}, err
	}
	displayName = strings.TrimSpace(displayName)
	if utf8.RuneCountInString(displayName) > users.MaxDisplayNameLen {
		return User{}, invalid("display_name", fmt.Sprintf("must have at most %d characters", users.MaxDisplayNameLen))
	}
	for _, r := range displayName {
		if unicode.IsControl(r) {
			return User{}, invalid("display_name", "must not contain control characters")
		}
	}
	hash, err := s.Hasher.HashPassword(password)
	if err != nil {
		return User{}, err
	}
	u := domain.User{
		ID:           uuid.New(),
		Username:     name,
		PasswordHash: hash,
		DisplayName:  displayName,
		CreatedAt:    s.clock().UTC(),
	}
	e := s.entry(a, ActionUserCreate, &u.ID, nil, map[string]any{"username": name})
	if err := s.Store.CreateUser(ctx, u, e); err != nil {
		if errors.Is(err, domain.ErrConflict) {
			return User{}, fmt.Errorf("username taken: %w", domain.ErrConflict)
		}
		return User{}, err
	}
	s.logAction(a, ActionUserCreate).Str("user_id", u.ID.String()).Msg("admin action")
	return s.Store.GetUser(ctx, u.ID)
}

// SetPassword replaces the password, clears the lockout and ends every
// session of the user.
func (s *Service) SetPassword(ctx context.Context, a Actor, id uuid.UUID, password string) error {
	if err := ValidatePassword(password); err != nil {
		return err
	}
	u, err := s.Store.GetUser(ctx, id)
	if err != nil {
		return err
	}
	hash, err := s.Hasher.HashPassword(password)
	if err != nil {
		return err
	}
	e := s.entry(a, ActionUserPassword, &u.ID, nil, map[string]any{"username": u.Username})
	if err := s.Store.SetPassword(ctx, id, hash, e); err != nil {
		return err
	}
	s.endUserSessions(id)
	s.logAction(a, ActionUserPassword).Str("user_id", id.String()).Msg("admin action")
	return nil
}

// Disable blocks login and ends every session. Idempotent.
func (s *Service) Disable(ctx context.Context, a Actor, id uuid.UUID) error {
	return s.setDisabled(ctx, a, id, true)
}

// Enable lifts a disable. Idempotent.
func (s *Service) Enable(ctx context.Context, a Actor, id uuid.UUID) error {
	return s.setDisabled(ctx, a, id, false)
}

func (s *Service) setDisabled(ctx context.Context, a Actor, id uuid.UUID, disabled bool) error {
	u, err := s.Store.GetUser(ctx, id)
	if err != nil {
		return err
	}
	action := ActionUserEnable
	if disabled {
		action = ActionUserDisable
	}
	e := s.entry(a, action, &u.ID, nil, map[string]any{"username": u.Username})
	if err := s.Store.SetDisabled(ctx, id, disabled, e); err != nil {
		return err
	}
	if disabled {
		s.endUserSessions(id)
	}
	s.logAction(a, action).Str("user_id", id.String()).Msg("admin action")
	return nil
}

// Unlock clears the failed-login counter and the lock.
func (s *Service) Unlock(ctx context.Context, a Actor, id uuid.UUID) error {
	u, err := s.Store.GetUser(ctx, id)
	if err != nil {
		return err
	}
	e := s.entry(a, ActionUserUnlock, &u.ID, nil, map[string]any{"username": u.Username})
	if err := s.Store.Unlock(ctx, id, e); err != nil {
		return err
	}
	s.logAction(a, ActionUserUnlock).Str("user_id", id.String()).Msg("admin action")
	return nil
}

// DeleteUser is the LGPD erasure of the users service, with its rules:
// a user who owns vaults is refused (users.SoleAdminError, listing them)
// unless deleteOwnedVaults opts into deleting those vaults too. Shared
// vaults the user merely belongs to survive without them; their audit
// rows are anonymised; federated followers hear the membership change.
//
// The admin audit row is written before the erasure and carries the
// target in user_id, so the erasure anonymises it like every other row
// about that user.
func (s *Service) DeleteUser(ctx context.Context, a Actor, id uuid.UUID, deleteOwnedVaults bool) error {
	u, err := s.Store.GetUser(ctx, id)
	if err != nil {
		return err
	}
	owned, err := s.Store.OwnedVaultIDs(ctx, id)
	if err != nil {
		return err
	}
	if len(owned) > 0 && !deleteOwnedVaults {
		return users.SoleAdminError{VaultIDs: owned}
	}
	e := s.entry(a, ActionUserDelete, &u.ID, nil, map[string]any{
		"username":            u.Username,
		"delete_owned_vaults": deleteOwnedVaults,
		"owned_vault_ids":     owned,
	})
	if err := s.Store.RecordAudit(ctx, e); err != nil {
		return fmt.Errorf("audit %s: %w", ActionUserDelete, err)
	}
	if err := s.Users.Delete(ctx, id, deleteOwnedVaults, ipPtr(a.IP), nil); err != nil {
		s.logFailure(a, ActionUserDelete, err).Str("user_id", id.String()).Msg("admin action failed after audit")
		return err
	}
	s.logAction(a, ActionUserDelete).Str("user_id", id.String()).Int("owned_vaults_deleted", len(owned)).Msg("admin action")
	return nil
}

// ---- sessions ------------------------------------------------------------------------

func (s *Service) ListSessions(ctx context.Context, userID *uuid.UUID, after *Cursor, limit int) ([]Session, bool, error) {
	return s.Store.ListSessions(ctx, userID, after, limit)
}

var sessionIDPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// RevokeSession deletes one session by its id (the stored token hash).
func (s *Service) RevokeSession(ctx context.Context, a Actor, id string) error {
	if !sessionIDPattern.MatchString(id) {
		return fmt.Errorf("session: %w", domain.ErrNotFound)
	}
	sess, err := s.Store.GetSession(ctx, id)
	if err != nil {
		return err
	}
	e := s.entry(a, ActionSessionRevoke, &sess.UserID, nil, map[string]any{
		"username":   sess.Username,
		"session_id": id[:12],
	})
	if err := s.Store.DeleteSession(ctx, id, e); err != nil {
		return err
	}
	if s.Live != nil {
		s.Live.SessionKeyEnded(id, "revoked")
	}
	s.logAction(a, ActionSessionRevoke).Str("user_id", sess.UserID.String()).Str("session_id", id[:12]).Msg("admin action")
	return nil
}

// EndUserSessions signs the user out everywhere: every session is
// deleted and the live streams are told. Audited even when there were none.
func (s *Service) EndUserSessions(ctx context.Context, a Actor, id uuid.UUID) (int, error) {
	u, err := s.Store.GetUser(ctx, id)
	if err != nil {
		return 0, err
	}
	n, err := s.Store.EndUserSessions(ctx, id, func(n int) domain.AuditEntry {
		return s.entry(a, ActionUserLogout, &u.ID, nil, map[string]any{"username": u.Username, "sessions": n})
	})
	if err != nil {
		return 0, err
	}
	s.endUserSessions(id)
	s.logAction(a, ActionUserLogout).Str("user_id", id.String()).Int("sessions", n).Msg("admin action")
	return n, nil
}

// ---- vaults ---------------------------------------------------------------------------

func (s *Service) ListVaults(ctx context.Context, userID *uuid.UUID, after string, limit int) ([]Vault, bool, error) {
	return s.Store.ListVaults(ctx, VaultFilter{UserID: userID}, after, limit)
}

// SearchVaults is ListVaults with a filter (validated by the caller).
func (s *Service) SearchVaults(ctx context.Context, f VaultFilter, after string, limit int) ([]Vault, bool, error) {
	return s.Store.ListVaults(ctx, f, after, limit)
}

// VaultMembers lists the local members (owner first) and the roles.
func (s *Service) VaultMembers(ctx context.Context, id uuid.UUID) ([]Member, []Role, error) {
	if _, err := s.Store.GetVault(ctx, id); err != nil {
		return nil, nil, err
	}
	return s.Store.VaultMembers(ctx, id)
}

// ---- invites -----------------------------------------------------------------------------

func (s *Service) ListInvites(ctx context.Context, f InviteFilter, after *Cursor, limit int) ([]Invite, bool, error) {
	return s.Store.ListInvites(ctx, f, after, limit)
}

// RevokeInvite revokes a vault join link by its id (the token hash).
// Revoking an already revoked link is a no-op success that is still
// audited, like tokens.
func (s *Service) RevokeInvite(ctx context.Context, a Actor, id string) error {
	if !sessionIDPattern.MatchString(id) {
		return fmt.Errorf("invite: %w", domain.ErrNotFound)
	}
	inv, err := s.Store.GetInvite(ctx, id)
	if err != nil {
		return err
	}
	e := s.entry(a, ActionInviteRevoke, nil, &inv.VaultID, map[string]any{
		"invite_id":  id[:12],
		"vault_slug": inv.VaultSlug,
	})
	if err := s.Store.RevokeInvite(ctx, id, s.clock().UTC(), e); err != nil {
		return err
	}
	s.logAction(a, ActionInviteRevoke).Str("vault_id", inv.VaultID.String()).Str("invite_id", id[:12]).Msg("admin action")
	return nil
}

func (s *Service) GetVault(ctx context.Context, id uuid.UUID) (Vault, error) {
	return s.Store.GetVault(ctx, id)
}

// ResolveVault accepts a vault id or slug (CLI convenience).
func (s *Service) ResolveVault(ctx context.Context, ref string) (Vault, error) {
	if id, err := uuid.Parse(ref); err == nil {
		return s.Store.GetVault(ctx, id)
	}
	return s.Store.GetVaultBySlug(ctx, ref)
}

// DeleteVault deletes the vault through the vaults service, as its owner
// would: rows (notes, roles, members, invites, federation links) cascade,
// the directory is removed and members' feeds are told.
func (s *Service) DeleteVault(ctx context.Context, a Actor, id uuid.UUID) error {
	v, err := s.Store.GetVault(ctx, id)
	if err != nil {
		return err
	}
	e := s.entry(a, ActionVaultDelete, nil, &v.ID, map[string]any{
		"slug":     v.Slug,
		"owner_id": v.OwnerID,
	})
	if err := s.Store.RecordAudit(ctx, e); err != nil {
		return fmt.Errorf("audit %s: %w", ActionVaultDelete, err)
	}
	if err := s.Vaults.Delete(ctx, id, uuid.Nil, a.IP, ""); err != nil {
		s.logFailure(a, ActionVaultDelete, err).Str("vault_id", id.String()).Msg("admin action failed after audit")
		return err
	}
	s.logAction(a, ActionVaultDelete).Str("vault_id", id.String()).Str("slug", v.Slug).Msg("admin action")
	return nil
}

// ---- federations ------------------------------------------------------------------------

func (s *Service) ListFederations(ctx context.Context, f FederationFilter, after *Cursor, limit int) ([]Federation, bool, error) {
	if f.Mode != "" && f.Mode != "replica" && f.Mode != "mirror" {
		return nil, false, invalid("mode", "replica or mirror")
	}
	list, more, err := s.Store.ListFederations(ctx, f, after, limit)
	if err != nil {
		return nil, false, err
	}
	for i := range list {
		s.fillProgress(&list[i])
	}
	return list, more, nil
}

// RevokeFederation revokes an active link through the federation service,
// with its rule: a link that is not active is refused (409). The local
// vault stays; the relay link stops.
func (s *Service) RevokeFederation(ctx context.Context, a Actor, id uuid.UUID) error {
	f, err := s.Store.GetFederation(ctx, id)
	if err != nil {
		return err
	}
	if f.Status != "active" {
		return fmt.Errorf("%w: federation already %s", domain.ErrConflict, f.Status)
	}
	e := s.entry(a, ActionFederationRevoke, nil, &f.VaultID, map[string]any{
		"federation_id": f.ID,
		"peer_url":      f.PeerURL,
		"role":          f.Role,
	})
	if err := s.Store.RecordAudit(ctx, e); err != nil {
		return fmt.Errorf("audit %s: %w", ActionFederationRevoke, err)
	}
	if err := s.Federations.RevokeFederation(ctx, f.VaultID, f.ID, uuid.Nil, a.IP, ""); err != nil {
		s.logFailure(a, ActionFederationRevoke, err).Str("federation_id", id.String()).Msg("admin action failed after audit")
		return err
	}
	s.logAction(a, ActionFederationRevoke).Str("federation_id", id.String()).Str("peer_url", f.PeerURL).Msg("admin action")
	return nil
}

// ---- audit ------------------------------------------------------------------------------

func (s *Service) ListAudit(ctx context.Context, q AuditQuery) ([]domain.AuditEntry, bool, error) {
	return s.Store.ListAudit(ctx, q)
}

// ---- helpers ----------------------------------------------------------------------------

// entry builds the audit row of an admin action. user_id carries the
// target user when there is one, so LGPD erasure anonymises it; ip is
// the admin client's address (empty for the CLI).
func (s *Service) entry(a Actor, action string, userID, vaultID *uuid.UUID, fields map[string]any) domain.AuditEntry {
	payload := map[string]any{"actor": "admin", "token_name": a.TokenName}
	if a.TokenID != nil {
		payload["token_id"] = a.TokenID.String()
	} else {
		payload["token_id"] = nil
	}
	for k, v := range fields {
		payload[k] = v
	}
	body, err := json.Marshal(payload)
	if err != nil {
		body = []byte(`{}`)
	}
	return domain.AuditEntry{
		UserID:    userID,
		VaultID:   vaultID,
		Action:    action,
		Payload:   body,
		IP:        ipPtr(a.IP),
		CreatedAt: s.clock().UTC(),
	}
}

func (s *Service) endUserSessions(id uuid.UUID) {
	if s.Live != nil {
		s.Live.UserSessionsEnded(id, "revoked")
	}
}

func (s *Service) logAction(a Actor, action string) *zerolog.Event {
	return s.actorEvent(s.Log.Info(), a, action)
}

func (s *Service) logFailure(a Actor, action string, err error) *zerolog.Event {
	return s.actorEvent(s.Log.Error().Err(err), a, action)
}

func (s *Service) actorEvent(ev *zerolog.Event, a Actor, action string) *zerolog.Event {
	ev = ev.Str("component", "admin").Str("action", action).Str("token_name", a.TokenName)
	if a.TokenID != nil {
		ev = ev.Str("token_id", a.TokenID.String())
	}
	if a.IP != "" {
		ev = ev.Str("ip", a.IP)
	}
	return ev
}

func ipPtr(ip string) *string {
	if ip == "" {
		return nil
	}
	return &ip
}
