package admin

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"mime"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/gofiber/fiber/v2/middleware/requestid"
	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/ViniZap4/lumi-server/internal/domain"
	"github.com/ViniZap4/lumi-server/internal/users"
)

const (
	// BodyLimit fits the largest admin body (user create with a 72-byte
	// password and an 80-character display name) many times over.
	BodyLimit = 16 << 10

	// Same timeouts as the public API.
	ReadTimeout  = 30 * time.Second
	WriteTimeout = 60 * time.Second
	IdleTimeout  = 120 * time.Second

	maxListLimit  = 200
	maxAuditLimit = 100

	basePath = "/admin/v1"
)

// Conns reports live connection counts of the running server.
type Conns interface {
	FeedStreams() int
	WSConnections() int
}

// HTTP is the admin API of docs/ADMIN.md, served on its own listener.
type HTTP struct {
	Service        *Service
	Limiter        *FailureLimiter
	TrustedProxies []netip.Prefix
	Conns          Conns
	StartedAt      time.Time
	Log            zerolog.Logger
	AppName        string
}

type ctxKey int

const (
	keyToken ctxKey = iota
	keyActor
)

// App builds the Fiber app: same timeouts and security headers as the
// public API, a small body limit, JSON errors, and no CORS (the panel's
// server calls this API; a browser never does).
func (h *HTTP) App() *fiber.App {
	if h.Limiter == nil {
		h.Limiter = NewFailureLimiter(10, 6*time.Second, 10_000)
	}
	if h.StartedAt.IsZero() {
		h.StartedAt = time.Now()
	}
	app := fiber.New(fiber.Config{
		AppName:               h.AppName,
		BodyLimit:             BodyLimit,
		ReadTimeout:           ReadTimeout,
		WriteTimeout:          WriteTimeout,
		IdleTimeout:           IdleTimeout,
		DisableStartupMessage: true,
		ErrorHandler:          h.errorHandler,
		Immutable:             true, // copies instead of views into fasthttp buffers
	})
	app.Use(requestid.New())
	app.Use(recover.New())
	app.Use(securityHeaders)
	app.Use(h.accessLog)

	app.Get("/admin/healthz", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"status": "ok"})
	})
	// The password login is the one /admin/v1 route without a bearer
	// token. Registered before the group: Fiber runs routes in order and
	// this handler ends the chain, so h.authed never runs for it.
	app.Post(basePath+"/session", h.createSession)

	v1 := app.Group(basePath, h.authed)
	v1.Get("/status", h.status)
	v1.Get("/users", h.listUsers)
	v1.Post("/users", h.createUser)
	v1.Get("/users/:id", h.getUser)
	v1.Delete("/users/:id", h.deleteUser)
	v1.Post("/users/:id/password", h.setPassword)
	v1.Post("/users/:id/disable", h.userOp((*Service).Disable))
	v1.Post("/users/:id/enable", h.userOp((*Service).Enable))
	v1.Post("/users/:id/unlock", h.userOp((*Service).Unlock))
	v1.Post("/users/:id/server-admin", h.setServerAdmin)
	v1.Delete("/users/:id/sessions", h.endUserSessions)
	v1.Get("/sessions", h.listSessions)
	v1.Delete("/sessions/:id", h.revokeSession)
	v1.Get("/vaults", h.listVaults)
	v1.Get("/vaults/:id", h.getVault)
	v1.Get("/vaults/:id/members", h.vaultMembers)
	v1.Delete("/vaults/:id", h.deleteVault)
	v1.Get("/federations", h.listFederations)
	v1.Get("/federations/:id", h.getFederation)
	v1.Delete("/federations/:id", h.revokeFederation)
	// One-way mirrors (§A13). Promotion is CLI-only on purpose: an admin
	// token alone must not be able to fork a book.
	v1.Post("/federations/:id/pause", h.federationOp((*Service).PauseFederation))
	v1.Post("/federations/:id/resume", h.federationOp((*Service).ResumeFederation))
	v1.Post("/federations/:id/resync", h.resyncFederation)
	v1.Get("/invites", h.listInvites)
	v1.Delete("/invites/:id", h.revokeInvite)
	v1.Delete("/session", h.endSession)
	v1.Get("/tokens", h.listTokens)
	v1.Delete("/tokens/:id", h.revokeToken)
	v1.Get("/audit", h.audit)
	// Unknown /admin/v1 paths answer 404 only after authentication, so
	// the route table is not discoverable without a token.
	v1.Use(func(c *fiber.Ctx) error { return errorJSON(c, fiber.StatusNotFound, "not_found", "") })
	return app
}

// ---- middleware ---------------------------------------------------------------

func securityHeaders(c *fiber.Ctx) error {
	c.Set("X-Content-Type-Options", "nosniff")
	c.Set("Referrer-Policy", "strict-origin-when-cross-origin")
	c.Set("X-Frame-Options", "DENY")
	c.Set("Permissions-Policy", "geolocation=(), microphone=(), camera=(), payment=()")
	c.Set(fiber.HeaderCacheControl, "no-store")
	return c.Next()
}

func (h *HTTP) accessLog(c *fiber.Ctx) error {
	start := time.Now()
	// Render errors here so the logged status is the one sent.
	if err := c.Next(); err != nil {
		if herr := h.errorHandler(c, err); herr != nil {
			return herr
		}
	}
	h.Log.Info().Str("component", "admin").
		Str("method", c.Method()).
		Str("path", c.Path()).
		Int("status", c.Response().StatusCode()).
		Dur("duration", time.Since(start)).
		Str("ip", h.clientIP(c).String()).
		Str("request_id", string(c.Response().Header.Peek(fiber.HeaderXRequestID))).
		Msg("admin_request")
	return nil
}

func (h *HTTP) clientIP(c *fiber.Ctx) netip.Addr {
	var remote netip.Addr
	if ip := c.Context().RemoteIP(); ip != nil {
		remote, _ = netip.AddrFromSlice(ip)
	}
	var xff []string
	for _, v := range c.Request().Header.PeekAll(fiber.HeaderXForwardedFor) {
		xff = append(xff, string(v))
	}
	return ClientIP(remote, xff, h.TrustedProxies)
}

// limiterKey groups IPv6 clients by /64, the smallest block one host
// usually controls.
func limiterKey(a netip.Addr) string {
	if a.Is6() {
		p, _ := a.Prefix(64)
		return p.String()
	}
	return a.String()
}

// authed answers every bad token (absent, malformed, unknown, expired,
// revoked) with the same 401. Only failures spend and check the per-IP
// budget; above it, failures get 429 with Retry-After.
func (h *HTTP) authed(c *fiber.Ctx) error {
	ip := h.clientIP(c)
	raw, ok := BearerToken(c.Get(fiber.HeaderAuthorization))
	err := domain.ErrUnauthorized
	var t Token
	if ok {
		t, err = h.Service.Authenticate(c.UserContext(), raw)
	}
	if errors.Is(err, domain.ErrUnauthorized) {
		if allowed, wait := h.Limiter.Allow(limiterKey(ip)); !allowed {
			return rateLimited(c, wait)
		}
		c.Set(fiber.HeaderWWWAuthenticate, `Bearer realm="lumi-admin"`)
		return errorJSON(c, fiber.StatusUnauthorized, "unauthorized", "")
	}
	if err != nil {
		return h.internal(c, err)
	}
	id := t.ID
	c.Locals(keyToken, t)
	c.Locals(keyActor, Actor{TokenID: &id, TokenName: t.Name, IP: ipString(ip)})
	return c.Next()
}

func rateLimited(c *fiber.Ctx, wait time.Duration) error {
	secs := int(math.Ceil(wait.Seconds()))
	if secs < 1 {
		secs = 1
	}
	c.Set(fiber.HeaderRetryAfter, strconv.Itoa(secs))
	return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{"error": "rate_limited", "retry_after_s": secs})
}

func ipString(a netip.Addr) string {
	if !a.IsValid() {
		return ""
	}
	return a.String()
}

func actorOf(c *fiber.Ctx) Actor {
	a, _ := c.Locals(keyActor).(Actor)
	return a
}

func tokenOf(c *fiber.Ctx) Token {
	t, _ := c.Locals(keyToken).(Token)
	return t
}

// ---- errors -----------------------------------------------------------------------

// errorJSON matches the public API's error body: {"error": code, "detail"?}.
func errorJSON(c *fiber.Ctx, status int, code, detail string) error {
	body := fiber.Map{"error": code}
	if detail != "" {
		body["detail"] = detail
	}
	return c.Status(status).JSON(body)
}

func (h *HTTP) errorHandler(c *fiber.Ctx, err error) error {
	var re *requestError
	if errors.As(err, &re) {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "validation_failed", "field": re.field, "detail": re.Error()})
	}
	var fe *fiber.Error
	if errors.As(err, &fe) {
		switch fe.Code {
		case fiber.StatusNotFound:
			return errorJSON(c, fe.Code, "not_found", "")
		case fiber.StatusMethodNotAllowed:
			return errorJSON(c, fe.Code, "method_not_allowed", "")
		case fiber.StatusRequestEntityTooLarge:
			return errorJSON(c, fe.Code, "payload_too_large", "")
		case fiber.StatusBadRequest:
			return errorJSON(c, fe.Code, "validation_failed", "")
		}
		if fe.Code < 500 {
			return errorJSON(c, fe.Code, strings.ReplaceAll(strings.ToLower(fe.Message), " ", "_"), "")
		}
	}
	return h.internal(c, err)
}

func (h *HTTP) internal(c *fiber.Ctx, err error) error {
	h.Log.Error().Err(err).Str("component", "admin").Str("path", c.Path()).Msg("admin: internal error")
	return errorJSON(c, fiber.StatusInternalServerError, "internal", "")
}

// fail maps service errors onto the public API's codes.
func (h *HTTP) fail(c *fiber.Ctx, err error) error {
	var ie *InvalidError
	if errors.As(err, &ie) {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "validation_failed", "field": ie.Field, "detail": ie.Error()})
	}
	var sole users.SoleAdminError
	if errors.As(err, &sole) {
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{"error": "sole_admin_vaults", "vault_ids": sole.VaultIDs})
	}
	switch {
	case errors.Is(err, domain.ErrNotFound):
		return errorJSON(c, fiber.StatusNotFound, "not_found", "")
	case errors.Is(err, domain.ErrConflict):
		return errorJSON(c, fiber.StatusConflict, "conflict", conflictDetail(err))
	case errors.Is(err, domain.ErrValidation):
		return errorJSON(c, fiber.StatusBadRequest, "validation_failed", "")
	}
	return h.internal(c, err)
}

func conflictDetail(err error) string {
	msg := err.Error()
	if i := strings.Index(msg, domain.ErrConflict.Error()+": "); i >= 0 {
		return msg[i+len(domain.ErrConflict.Error())+2:]
	}
	if strings.HasSuffix(msg, ": "+domain.ErrConflict.Error()) {
		return strings.TrimSuffix(msg, ": "+domain.ErrConflict.Error())
	}
	return ""
}

// requestError is a 400 raised by the request helpers; returning it ends
// the handler and the error handler renders it.
type requestError struct{ field, detail string }

func (e *requestError) Error() string { return e.field + ": " + e.detail }

func badRequest(_ *fiber.Ctx, field, detail string) error {
	return &requestError{field: field, detail: detail}
}

// decode is strict: JSON content type, no unknown fields, one value.
func decode(c *fiber.Ctx, v any) error {
	mt, _, err := mime.ParseMediaType(c.Get(fiber.HeaderContentType))
	if err != nil || mt != fiber.MIMEApplicationJSON {
		return badRequest(c, "body", "Content-Type must be application/json")
	}
	dec := json.NewDecoder(bytes.NewReader(c.Body()))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return badRequest(c, "body", "invalid JSON: "+jsonDetail(err))
	}
	if _, err := dec.Token(); err != io.EOF {
		return badRequest(c, "body", "invalid JSON: trailing data")
	}
	return nil
}

func jsonDetail(err error) string {
	var ute *json.UnmarshalTypeError
	if errors.As(err, &ute) {
		return fmt.Sprintf("%s has the wrong type", ute.Field)
	}
	if strings.HasPrefix(err.Error(), "json: unknown field ") {
		return strings.TrimPrefix(err.Error(), "json: ")
	}
	return "malformed"
}

// ---- pagination ------------------------------------------------------------------------

type page[T any] struct {
	Items []T     `json:"items"`
	More  bool    `json:"more"`
	Next  *string `json:"next"`
}

func newPage[S, T any](list []S, more bool, out func(S) T, cursor func(S) string) page[T] {
	p := page[T]{Items: make([]T, 0, len(list)), More: more}
	for _, v := range list {
		p.Items = append(p.Items, out(v))
	}
	if more && len(list) > 0 {
		cur := cursor(list[len(list)-1])
		p.Next = &cur
	}
	return p
}

func queryLimit(c *fiber.Ctx, def, max int) (int, error) {
	raw := c.Query("limit")
	if raw == "" {
		return def, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 || n > max {
		return 0, badRequest(c, "limit", fmt.Sprintf("must be an integer from 1 to %d", max))
	}
	return n, nil
}

func encodeKey(k string) string { return base64.RawURLEncoding.EncodeToString([]byte(k)) }

func decodeKey(c *fiber.Ctx) (string, error) {
	raw := c.Query("after")
	if raw == "" {
		return "", nil
	}
	b, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil || len(b) == 0 {
		return "", badRequest(c, "after", "must be the next cursor of the previous page")
	}
	return string(b), nil
}

func encodeCursor(t time.Time, key string) string {
	return encodeKey(t.UTC().Format(time.RFC3339Nano) + "|" + key)
}

func decodeCursor(c *fiber.Ctx) (*Cursor, error) {
	k, err := decodeKey(c)
	if err != nil || k == "" {
		return nil, err
	}
	ts, key, ok := strings.Cut(k, "|")
	t, perr := time.Parse(time.RFC3339Nano, ts)
	if !ok || perr != nil || key == "" {
		return nil, badRequest(c, "after", "must be the next cursor of the previous page")
	}
	return &Cursor{Time: t, Key: key}, nil
}

func queryUUID(c *fiber.Ctx, name string) (*uuid.UUID, error) {
	raw := c.Query(name)
	if raw == "" {
		return nil, nil
	}
	id, err := uuid.Parse(raw)
	if err != nil {
		return nil, badRequest(c, name, "must be a UUID")
	}
	return &id, nil
}

const maxSearchLen = 64

// querySearch reads ?q=: empty means no filter; otherwise 1 to 64
// characters without control characters.
func querySearch(c *fiber.Ctx) (string, error) {
	q := strings.TrimSpace(c.Query("q"))
	if q == "" {
		return "", nil
	}
	if utf8.RuneCountInString(q) > maxSearchLen {
		return "", badRequest(c, "q", fmt.Sprintf("must have 1 to %d characters", maxSearchLen))
	}
	for _, r := range q {
		if unicode.IsControl(r) {
			return "", badRequest(c, "q", "must not contain control characters")
		}
	}
	return strings.Clone(q), nil
}

func queryTime(c *fiber.Ctx, name string) (*time.Time, error) {
	raw := c.Query(name)
	if raw == "" {
		return nil, nil
	}
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return nil, badRequest(c, name, "must be an RFC 3339 timestamp")
	}
	return &t, nil
}

var auditActionPattern = regexp.MustCompile(`^[a-z_]+(\.[a-z_]+)*(\.\*)?$`)

// pathUUID: a malformed id is a 404, like an unknown one.
func pathUUID(c *fiber.Ctx) (uuid.UUID, bool) {
	id, err := uuid.Parse(c.Params("id"))
	return id, err == nil
}

// ---- DTOs ---------------------------------------------------------------------------------

func ts(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

func tsPtr(t *time.Time) *string {
	if t == nil {
		return nil
	}
	s := ts(*t)
	return &s
}

type UserJSON struct {
	ID            uuid.UUID   `json:"id"`
	Username      string      `json:"username"`
	DisplayName   string      `json:"display_name"`
	State         string      `json:"state"`
	DisabledAt    *string     `json:"disabled_at"`
	FailedLogins  int         `json:"failed_logins"`
	LockedUntil   *string     `json:"locked_until"`
	Sessions      int         `json:"sessions"`
	OwnedVaults   int         `json:"owned_vaults"`
	Vaults        int         `json:"vaults"`
	CreatedAt     string      `json:"created_at"`
	LastLoginAt   *string     `json:"last_login_at"`
	LastSeenAt    *string     `json:"last_seen_at"`
	ServerAdmin   bool        `json:"server_admin"`
	OwnedVaultIDs []uuid.UUID `json:"owned_vault_ids,omitempty"`
}

func ToUserJSON(now time.Time) func(User) UserJSON {
	return func(u User) UserJSON {
		return UserJSON{
			ID: u.ID, Username: u.Username, DisplayName: u.DisplayName, State: u.State(now),
			DisabledAt: tsPtr(u.DisabledAt), FailedLogins: u.FailedLogins, LockedUntil: tsPtr(u.LockedUntil),
			Sessions: u.Sessions, OwnedVaults: u.OwnedVaults, Vaults: u.Vaults, CreatedAt: ts(u.CreatedAt),
			LastLoginAt: tsPtr(u.LastLoginAt), LastSeenAt: tsPtr(u.LastSeenAt), ServerAdmin: u.ServerAdmin,
		}
	}
}

type SessionJSON struct {
	ID         string    `json:"id"`
	UserID     uuid.UUID `json:"user_id"`
	Username   string    `json:"username"`
	CreatedAt  string    `json:"created_at"`
	LastUsedAt string    `json:"last_used_at"`
	ExpiresAt  string    `json:"expires_at"`
}

func ToSessionJSON(s Session) SessionJSON {
	return SessionJSON{ID: s.ID, UserID: s.UserID, Username: s.Username,
		CreatedAt: ts(s.CreatedAt), LastUsedAt: ts(s.LastUsedAt), ExpiresAt: ts(s.ExpiresAt)}
}

type RefJSON struct {
	ID       uuid.UUID `json:"id"`
	Username string    `json:"username"`
}

type VaultFedJSON struct {
	Role        string `json:"role"`
	ActiveLinks int    `json:"active_links"`
}

type VaultJSON struct {
	ID               uuid.UUID     `json:"id"`
	Slug             string        `json:"slug"`
	Name             string        `json:"name"`
	Owner            RefJSON       `json:"owner"`
	Members          int           `json:"members"`
	FederatedMembers int           `json:"federated_members"`
	Notes            int           `json:"notes"`
	CRDTBytes        int64         `json:"crdt_bytes"`
	Federation       *VaultFedJSON `json:"federation"`
	HeadSeq          int64         `json:"head_seq"`
	LastChangeAt     *string       `json:"last_change_at"`
	InvitesActive    int           `json:"invites_active"`
	CreatedAt        string        `json:"created_at"`
}

func ToVaultJSON(v Vault) VaultJSON {
	out := VaultJSON{ID: v.ID, Slug: v.Slug, Name: v.Name, Owner: RefJSON{ID: v.OwnerID, Username: v.OwnerUsername},
		Members: v.Members, FederatedMembers: v.FederatedMembers, Notes: v.Notes, CRDTBytes: v.CRDTBytes, CreatedAt: ts(v.CreatedAt),
		HeadSeq: v.HeadSeq, LastChangeAt: tsPtr(v.LastChangeAt), InvitesActive: v.InvitesActive}
	if v.FederationRole != nil {
		out.Federation = &VaultFedJSON{Role: *v.FederationRole, ActiveLinks: v.ActiveFederations}
	}
	return out
}

type VaultRefJSON struct {
	ID   uuid.UUID `json:"id"`
	Slug string    `json:"slug"`
	Name string    `json:"name"`
}

type RoleRefJSON struct {
	ID   uuid.UUID `json:"id"`
	Name string    `json:"name"`
}

type MemberJSON struct {
	User        RefJSON     `json:"user"`
	DisplayName string      `json:"display_name"`
	Role        RoleRefJSON `json:"role"`
	Owner       bool        `json:"owner"`
	JoinedAt    string      `json:"joined_at"`
}

func ToMemberJSON(m Member) MemberJSON {
	return MemberJSON{User: RefJSON{ID: m.UserID, Username: m.Username}, DisplayName: m.DisplayName,
		Role: RoleRefJSON{ID: m.RoleID, Name: m.RoleName}, Owner: m.Owner, JoinedAt: ts(m.JoinedAt)}
}

type RoleJSON struct {
	ID      uuid.UUID `json:"id"`
	Name    string    `json:"name"`
	Seed    bool      `json:"seed"`
	Members int       `json:"members"`
}

// InviteJSON never carries the token: id is its SHA-256.
type InviteJSON struct {
	ID        string       `json:"id"`
	Vault     VaultRefJSON `json:"vault"`
	Inviter   RefJSON      `json:"inviter"`
	Role      RoleRefJSON  `json:"role"`
	EmailHint *string      `json:"email_hint"`
	MaxUses   int          `json:"max_uses"`
	UseCount  int          `json:"use_count"`
	State     string       `json:"state"`
	ExpiresAt string       `json:"expires_at"`
	CreatedAt string       `json:"created_at"`
	RevokedAt *string      `json:"revoked_at"`
}

func ToInviteJSON(now time.Time) func(Invite) InviteJSON {
	return func(i Invite) InviteJSON {
		return InviteJSON{ID: i.ID, Vault: VaultRefJSON{ID: i.VaultID, Slug: i.VaultSlug, Name: i.VaultName},
			Inviter: RefJSON{ID: i.InviterID, Username: i.InviterUsername}, Role: RoleRefJSON{ID: i.RoleID, Name: i.RoleName},
			EmailHint: i.EmailHint, MaxUses: i.MaxUses, UseCount: i.UseCount, State: i.State(now),
			ExpiresAt: ts(i.ExpiresAt), CreatedAt: ts(i.CreatedAt), RevokedAt: tsPtr(i.RevokedAt)}
	}
}

type FederationJSON struct {
	ID           uuid.UUID    `json:"id"`
	Vault        VaultRefJSON `json:"vault"`
	Role         string       `json:"role"`
	PeerURL      string       `json:"peer_url"`
	Jurisdiction *string      `json:"jurisdiction"`
	Status       string       `json:"status"`
	LastAckedSeq int64        `json:"last_acked_seq"`
	ControlSeq   *int64       `json:"control_seq"`
	CreatedAt    string       `json:"created_at"`
	RevokedAt    *string      `json:"revoked_at"`

	Mode                  string        `json:"mode"`
	SeverPolicy           string        `json:"sever_policy"`
	HeadSeq               int64         `json:"head_seq"`
	MirrorAckedSeq        int64         `json:"mirror_acked_seq"`
	HomeSeq               int64         `json:"home_seq"`
	LagSeq                int64         `json:"lag_seq"`
	PendingDeletes        int64         `json:"pending_deletes"`
	OldestPendingDeleteAt *string       `json:"oldest_pending_delete_at"`
	LastContactAt         *string       `json:"last_contact_at"`
	PausedAt              *string       `json:"paused_at"`
	PromotedAt            *string       `json:"promoted_at"`
	Violations24h         int64         `json:"violations_24h"`
	Backfill              *BackfillJSON `json:"backfill"`
}

type BackfillJSON struct {
	Active bool `json:"active"`
	Synced int  `json:"synced"`
	Total  int  `json:"total"`
}

func ToFederationJSON(f Federation) FederationJSON {
	out := FederationJSON{ID: f.ID, Vault: VaultRefJSON{ID: f.VaultID, Slug: f.VaultSlug, Name: f.VaultName},
		Role: f.Role, PeerURL: f.PeerURL, Jurisdiction: f.Jurisdiction, Status: f.Status,
		LastAckedSeq: f.LastAckedSeq, ControlSeq: f.ControlSeq, CreatedAt: ts(f.CreatedAt), RevokedAt: tsPtr(f.RevokedAt),
		Mode: f.Mode, SeverPolicy: f.SeverPolicy, HeadSeq: f.HeadSeq, MirrorAckedSeq: f.MirrorAckedSeq,
		HomeSeq: f.HomeSeq, LagSeq: f.LagSeq(), PendingDeletes: f.PendingDeletes,
		OldestPendingDeleteAt: tsPtr(f.OldestPendingDeleteAt), LastContactAt: tsPtr(f.LastContactAt),
		PausedAt: tsPtr(f.PausedAt), PromotedAt: tsPtr(f.PromotedAt), Violations24h: f.Violations24h}
	if out.Mode == "" {
		out.Mode = "replica"
	}
	if out.SeverPolicy == "" {
		out.SeverPolicy = "keep"
	}
	if f.Backfill != nil {
		out.Backfill = &BackfillJSON{Active: f.Backfill.Active, Synced: f.Backfill.Synced, Total: f.Backfill.Total}
	}
	return out
}

type TokenJSON struct {
	ID         uuid.UUID `json:"id"`
	Name       string    `json:"name"`
	State      string    `json:"state"`
	CreatedAt  string    `json:"created_at"`
	LastUsedAt *string   `json:"last_used_at"`
	ExpiresAt  string    `json:"expires_at"`
	RevokedAt  *string   `json:"revoked_at"`
	Current    bool      `json:"current"`
	// Kind is "token" (lpa_) or "session" (lps_); User is the signed-in
	// user of a session, null for a token.
	Kind string   `json:"kind"`
	User *RefJSON `json:"user"`
}

// ToTokenJSON renders tokens; current marks the caller's own.
func ToTokenJSON(now time.Time, current uuid.UUID) func(Token) TokenJSON {
	return func(t Token) TokenJSON {
		out := TokenJSON{ID: t.ID, Name: t.Name, State: t.State(now), CreatedAt: ts(t.CreatedAt),
			LastUsedAt: tsPtr(t.LastUsedAt), ExpiresAt: ts(t.ExpiresAt), RevokedAt: tsPtr(t.RevokedAt), Current: t.ID == current,
			Kind: KindToken}
		if t.IsSession() {
			out.Kind = KindSession
			if t.UserID != nil {
				out.User = &RefJSON{ID: *t.UserID, Username: t.Username}
			}
		}
		return out
	}
}

type AuditJSON struct {
	ID        int64           `json:"id"`
	CreatedAt string          `json:"created_at"`
	Action    string          `json:"action"`
	UserID    *uuid.UUID      `json:"user_id"`
	VaultID   *uuid.UUID      `json:"vault_id"`
	IP        *string         `json:"ip"`
	UserAgent *string         `json:"user_agent"`
	Payload   json.RawMessage `json:"payload"`
}

func ToAuditJSON(e domain.AuditEntry) AuditJSON {
	out := AuditJSON{ID: e.ID, CreatedAt: ts(e.CreatedAt), Action: e.Action, UserID: e.UserID,
		VaultID: e.VaultID, IP: e.IP, UserAgent: e.UserAgent, Payload: json.RawMessage("null")}
	if len(e.Payload) > 0 && json.Valid(e.Payload) {
		out.Payload = json.RawMessage(e.Payload)
	}
	return out
}

// ---- handlers --------------------------------------------------------------------------

func (h *HTTP) status(c *fiber.Ctx) error {
	st, err := h.Service.Status(c.UserContext())
	if err != nil {
		return h.internal(c, err)
	}
	feedN, wsN := 0, 0
	if h.Conns != nil {
		feedN, wsN = h.Conns.FeedStreams(), h.Conns.WSConnections()
	}
	t := tokenOf(c)
	return c.JSON(fiber.Map{
		"version":            st.Version,
		"schema_version":     st.SchemaVersion,
		"schema_dirty":       st.SchemaDirty,
		"pending_migrations": st.PendingMigrations,
		"users":              st.Users,
		"sessions":           st.Sessions,
		"vaults":             st.Vaults,
		"notes":              st.Notes,
		"federations":        st.Federations,
		"feed_connections":   feedN,
		"ws_connections":     wsN,
		"started_at":         ts(h.StartedAt),
		"db_latency_ms":      float64(st.DBLatency.Microseconds()) / 1000,
		"users_disabled":     st.UsersDisabled,
		"users_locked":       st.UsersLocked,
		"crdt_bytes":         st.CRDTBytes,
		"logins_24h":         st.Logins24h,
		"login_failures_24h": st.LoginFailures24h,
		"invites_active":     st.InvitesActive,
		"go_version":         st.GoVersion,
		"token":              tokenRef(t),
	})
}

func (h *HTTP) listUsers(c *fiber.Ctx) error {
	limit, err := queryLimit(c, maxListLimit, maxListLimit)
	if err != nil {
		return err
	}
	after, err := decodeKey(c)
	if err != nil {
		return err
	}
	var f UserFilter
	if f.Query, err = querySearch(c); err != nil {
		return err
	}
	switch st := c.Query("state"); st {
	case "":
	case "active", "disabled", "locked":
		f.State = strings.Clone(st)
	default:
		return badRequest(c, "state", "must be active, disabled or locked")
	}
	switch c.Query("server_admin") {
	case "", "false":
	case "true":
		f.ServerAdmin = true
	default:
		return badRequest(c, "server_admin", "must be true or false")
	}
	list, more, err := h.Service.SearchUsers(c.UserContext(), f, after, limit)
	if err != nil {
		return h.fail(c, err)
	}
	return c.JSON(newPage(list, more, ToUserJSON(time.Now()), func(u User) string { return encodeKey(u.Username) }))
}

func (h *HTTP) getUser(c *fiber.Ctx) error {
	id, ok := pathUUID(c)
	if !ok {
		return errorJSON(c, fiber.StatusNotFound, "not_found", "")
	}
	u, err := h.Service.GetUser(c.UserContext(), id)
	if err != nil {
		return h.fail(c, err)
	}
	out := ToUserJSON(time.Now())(u)
	owned, err := h.Service.Store.OwnedVaultIDs(c.UserContext(), id)
	if err != nil {
		return h.fail(c, err)
	}
	out.OwnedVaultIDs = owned
	if out.OwnedVaultIDs == nil {
		out.OwnedVaultIDs = []uuid.UUID{}
	}
	return c.JSON(out)
}

type createUserReq struct {
	Username    string `json:"username"`
	Password    string `json:"password"`
	DisplayName string `json:"display_name"`
}

func (h *HTTP) createUser(c *fiber.Ctx) error {
	var req createUserReq
	if err := decode(c, &req); err != nil {
		return err
	}
	u, err := h.Service.CreateUser(c.UserContext(), actorOf(c), req.Username, req.Password, req.DisplayName)
	if err != nil {
		return h.fail(c, err)
	}
	return c.Status(fiber.StatusCreated).JSON(ToUserJSON(time.Now())(u))
}

type passwordReq struct {
	Password string `json:"password"`
}

// tokenRef is the caller's credential in GET /status and the session
// login response: kind, and the user for a session.
func tokenRef(t Token) fiber.Map {
	m := fiber.Map{"id": t.ID, "name": t.Name, "expires_at": ts(t.ExpiresAt), "kind": KindToken, "user": nil}
	if t.IsSession() {
		m["kind"] = KindSession
		if t.UserID != nil {
			m["user"] = RefJSON{ID: *t.UserID, Username: t.Username}
		}
	}
	return m
}

type sessionReq struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// createSession — POST /admin/v1/session {username, password}, no token.
//
// 201 {"token": "lps_…", "id", "name", "kind": "session", "expires_at",
// "user": {"id","username"}}. Every refusal (unknown user, wrong password,
// locked or disabled account, not a server admin) is the same
// 401 {"error":"invalid_credentials"}; the per-IP failure budget of the
// admin listener applies on top of the login's own per-IP and per-user
// limits (429 rate_limited with Retry-After either way).
func (h *HTTP) createSession(c *fiber.Ctx) error {
	ip := h.clientIP(c)
	key := limiterKey(ip)
	if ok, wait := h.Limiter.Peek(key); !ok {
		return rateLimited(c, wait)
	}
	var req sessionReq
	if err := decode(c, &req); err != nil {
		return err
	}
	raw, t, err := h.Service.CreateSession(c.UserContext(), ipString(ip), c.Get(fiber.HeaderUserAgent), req.Username, req.Password)
	switch {
	case err == nil:
		out := tokenRef(t)
		out["token"] = raw
		return c.Status(fiber.StatusCreated).JSON(out)
	case errors.Is(err, domain.ErrRateLimited):
		return rateLimited(c, time.Minute)
	case errors.Is(err, domain.ErrInvalidCredentials):
		if ok, wait := h.Limiter.Allow(key); !ok {
			return rateLimited(c, wait)
		}
		return errorJSON(c, fiber.StatusUnauthorized, "invalid_credentials", "")
	case errors.Is(err, errSessionLoginOff):
		return errorJSON(c, fiber.StatusNotFound, "not_found", "")
	}
	return h.internal(c, err)
}

// endSession — DELETE /admin/v1/session: revokes the caller's own admin
// session (204); 409 for an lpa_ token.
func (h *HTTP) endSession(c *fiber.Ctx) error {
	if err := h.Service.EndSession(c.UserContext(), actorOf(c), tokenOf(c)); err != nil {
		return h.fail(c, err)
	}
	return c.SendStatus(fiber.StatusNoContent)
}

type serverAdminReq struct {
	Enabled *bool `json:"enabled"`
}

// setServerAdmin — POST /admin/v1/users/{id}/server-admin {"enabled"}:
// 204; 409 {"error":"conflict","detail":"last_server_admin"} when it would
// clear the last active server admin.
func (h *HTTP) setServerAdmin(c *fiber.Ctx) error {
	id, ok := pathUUID(c)
	if !ok {
		return errorJSON(c, fiber.StatusNotFound, "not_found", "")
	}
	var req serverAdminReq
	if err := decode(c, &req); err != nil {
		return err
	}
	if req.Enabled == nil {
		return badRequest(c, "enabled", "is required")
	}
	if err := h.Service.SetServerAdmin(c.UserContext(), actorOf(c), id, *req.Enabled); err != nil {
		return h.fail(c, err)
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *HTTP) setPassword(c *fiber.Ctx) error {
	id, ok := pathUUID(c)
	if !ok {
		return errorJSON(c, fiber.StatusNotFound, "not_found", "")
	}
	var req passwordReq
	if err := decode(c, &req); err != nil {
		return err
	}
	if err := h.Service.SetPassword(c.UserContext(), actorOf(c), id, req.Password); err != nil {
		return h.fail(c, err)
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *HTTP) userOp(op func(*Service, context.Context, Actor, uuid.UUID) error) fiber.Handler {
	return func(c *fiber.Ctx) error {
		id, ok := pathUUID(c)
		if !ok {
			return errorJSON(c, fiber.StatusNotFound, "not_found", "")
		}
		if err := op(h.Service, c.UserContext(), actorOf(c), id); err != nil {
			return h.fail(c, err)
		}
		return c.SendStatus(fiber.StatusNoContent)
	}
}

func (h *HTTP) deleteUser(c *fiber.Ctx) error {
	id, ok := pathUUID(c)
	if !ok {
		return errorJSON(c, fiber.StatusNotFound, "not_found", "")
	}
	force := false
	switch c.Query("delete_owned_vaults") {
	case "", "false":
	case "true":
		force = true
	default:
		return badRequest(c, "delete_owned_vaults", "must be true or false")
	}
	if err := h.Service.DeleteUser(c.UserContext(), actorOf(c), id, force); err != nil {
		return h.fail(c, err)
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *HTTP) listSessions(c *fiber.Ctx) error {
	limit, err := queryLimit(c, maxListLimit, maxListLimit)
	if err != nil {
		return err
	}
	user, err := queryUUID(c, "user")
	if err != nil {
		return err
	}
	after, err := decodeCursor(c)
	if err != nil {
		return err
	}
	list, more, err := h.Service.ListSessions(c.UserContext(), user, after, limit)
	if err != nil {
		return h.fail(c, err)
	}
	return c.JSON(newPage(list, more, ToSessionJSON, func(s Session) string { return encodeCursor(s.CreatedAt, s.ID) }))
}

// revokeSession clones the id: Fiber's param strings alias the reusable
// request buffer, and this one reaches the audit row and the feed.
func (h *HTTP) revokeSession(c *fiber.Ctx) error {
	if err := h.Service.RevokeSession(c.UserContext(), actorOf(c), strings.Clone(c.Params("id"))); err != nil {
		return h.fail(c, err)
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *HTTP) listVaults(c *fiber.Ctx) error {
	limit, err := queryLimit(c, maxListLimit, maxListLimit)
	if err != nil {
		return err
	}
	user, err := queryUUID(c, "user")
	if err != nil {
		return err
	}
	after, err := decodeKey(c)
	if err != nil {
		return err
	}
	q, err := querySearch(c)
	if err != nil {
		return err
	}
	list, more, err := h.Service.SearchVaults(c.UserContext(), VaultFilter{UserID: user, Query: q}, after, limit)
	if err != nil {
		return h.fail(c, err)
	}
	return c.JSON(newPage(list, more, ToVaultJSON, func(v Vault) string { return encodeKey(v.Slug) }))
}

func (h *HTTP) getVault(c *fiber.Ctx) error {
	id, ok := pathUUID(c)
	if !ok {
		return errorJSON(c, fiber.StatusNotFound, "not_found", "")
	}
	v, err := h.Service.GetVault(c.UserContext(), id)
	if err != nil {
		return h.fail(c, err)
	}
	return c.JSON(ToVaultJSON(v))
}

func (h *HTTP) deleteVault(c *fiber.Ctx) error {
	id, ok := pathUUID(c)
	if !ok {
		return errorJSON(c, fiber.StatusNotFound, "not_found", "")
	}
	if err := h.Service.DeleteVault(c.UserContext(), actorOf(c), id); err != nil {
		return h.fail(c, err)
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *HTTP) listFederations(c *fiber.Ctx) error {
	limit, err := queryLimit(c, maxListLimit, maxListLimit)
	if err != nil {
		return err
	}
	vault, err := queryUUID(c, "vault")
	if err != nil {
		return err
	}
	after, err := decodeCursor(c)
	if err != nil {
		return err
	}
	filter := FederationFilter{VaultID: vault, Mode: c.Query("mode")}
	list, more, err := h.Service.ListFederations(c.UserContext(), filter, after, limit)
	if err != nil {
		return h.fail(c, err)
	}
	return c.JSON(newPage(list, more, ToFederationJSON, func(f Federation) string { return encodeCursor(f.CreatedAt, f.ID.String()) }))
}

func (h *HTTP) getFederation(c *fiber.Ctx) error {
	id, ok := pathUUID(c)
	if !ok {
		return errorJSON(c, fiber.StatusNotFound, "not_found", "")
	}
	f, err := h.Service.GetFederation(c.UserContext(), id)
	if err != nil {
		return h.fail(c, err)
	}
	return c.JSON(ToFederationJSON(f))
}

func (h *HTTP) federationOp(op func(*Service, context.Context, Actor, uuid.UUID) (Federation, error)) fiber.Handler {
	return func(c *fiber.Ctx) error {
		id, ok := pathUUID(c)
		if !ok {
			return errorJSON(c, fiber.StatusNotFound, "not_found", "")
		}
		f, err := op(h.Service, c.UserContext(), actorOf(c), id)
		if err != nil {
			return h.fail(c, err)
		}
		return c.JSON(ToFederationJSON(f))
	}
}

func (h *HTTP) resyncFederation(c *fiber.Ctx) error {
	var body struct {
		NoteID string `json:"note_id"`
	}
	if len(c.Body()) > 0 {
		if err := c.BodyParser(&body); err != nil {
			return errorJSON(c, fiber.StatusBadRequest, "invalid_body", "")
		}
	}
	if body.NoteID != "" {
		return errorJSON(c, fiber.StatusBadRequest, "validation", "note_id: single-note rebuild is not supported yet (full resync only)")
	}
	return h.federationOp((*Service).ResyncMirror)(c)
}

func (h *HTTP) revokeFederation(c *fiber.Ctx) error {
	id, ok := pathUUID(c)
	if !ok {
		return errorJSON(c, fiber.StatusNotFound, "not_found", "")
	}
	if err := h.Service.RevokeFederation(c.UserContext(), actorOf(c), id); err != nil {
		return h.fail(c, err)
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *HTTP) listTokens(c *fiber.Ctx) error {
	limit, err := queryLimit(c, maxListLimit, maxListLimit)
	if err != nil {
		return err
	}
	after, err := decodeCursor(c)
	if err != nil {
		return err
	}
	list, more, err := h.Service.ListTokens(c.UserContext(), after, limit)
	if err != nil {
		return h.fail(c, err)
	}
	return c.JSON(newPage(list, more, ToTokenJSON(time.Now(), tokenOf(c).ID),
		func(t Token) string { return encodeCursor(t.CreatedAt, t.ID.String()) }))
}

func (h *HTTP) revokeToken(c *fiber.Ctx) error {
	id, ok := pathUUID(c)
	if !ok {
		return errorJSON(c, fiber.StatusNotFound, "not_found", "")
	}
	if err := h.Service.RevokeToken(c.UserContext(), actorOf(c), id); err != nil {
		return h.fail(c, err)
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *HTTP) audit(c *fiber.Ctx) error {
	limit, err := queryLimit(c, maxAuditLimit, maxAuditLimit)
	if err != nil {
		return err
	}
	q := AuditQuery{Limit: limit}
	if raw := c.Query("before"); raw != "" {
		n, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || n < 1 {
			return badRequest(c, "before", "must be a positive audit entry id")
		}
		q.Before = n
	}
	switch c.Query("scope") {
	case "", "all":
	case "admin":
		q.AdminOn = true
	default:
		return badRequest(c, "scope", "must be all or admin")
	}
	if q.UserID, err = queryUUID(c, "user"); err != nil {
		return err
	}
	if q.VaultID, err = queryUUID(c, "vault"); err != nil {
		return err
	}
	if raw := c.Query("action"); raw != "" {
		if len(raw) > 64 || !auditActionPattern.MatchString(raw) {
			return badRequest(c, "action", `must be an action like auth.login, or a prefix like auth.*`)
		}
		if strings.HasSuffix(raw, ".*") {
			q.Action, q.ActionPrefix = strings.Clone(strings.TrimSuffix(raw, "*")), true
		} else {
			q.Action = strings.Clone(raw)
		}
	}
	if q.Since, err = queryTime(c, "since"); err != nil {
		return err
	}
	if q.Until, err = queryTime(c, "until"); err != nil {
		return err
	}
	if q.Since != nil && q.Until != nil && !q.Until.After(*q.Since) {
		return badRequest(c, "until", "must be after since")
	}
	list, more, err := h.Service.ListAudit(c.UserContext(), q)
	if err != nil {
		return h.fail(c, err)
	}
	out := make([]AuditJSON, 0, len(list))
	for _, e := range list {
		out = append(out, ToAuditJSON(e))
	}
	var next *string
	if more && len(list) > 0 {
		n := strconv.FormatInt(list[len(list)-1].ID, 10)
		next = &n
	}
	return c.JSON(fiber.Map{"entries": out, "more": more, "next": next})
}

func (h *HTTP) endUserSessions(c *fiber.Ctx) error {
	id, ok := pathUUID(c)
	if !ok {
		return errorJSON(c, fiber.StatusNotFound, "not_found", "")
	}
	n, err := h.Service.EndUserSessions(c.UserContext(), actorOf(c), id)
	if err != nil {
		return h.fail(c, err)
	}
	return c.JSON(fiber.Map{"revoked": n})
}

func (h *HTTP) vaultMembers(c *fiber.Ctx) error {
	id, ok := pathUUID(c)
	if !ok {
		return errorJSON(c, fiber.StatusNotFound, "not_found", "")
	}
	members, roles, err := h.Service.VaultMembers(c.UserContext(), id)
	if err != nil {
		return h.fail(c, err)
	}
	outM := make([]MemberJSON, 0, len(members))
	for _, m := range members {
		outM = append(outM, ToMemberJSON(m))
	}
	outR := make([]RoleJSON, 0, len(roles))
	for _, r := range roles {
		outR = append(outR, RoleJSON{ID: r.ID, Name: r.Name, Seed: r.Seed, Members: r.Members})
	}
	return c.JSON(fiber.Map{"members": outM, "roles": outR})
}

func (h *HTTP) listInvites(c *fiber.Ctx) error {
	limit, err := queryLimit(c, maxListLimit, maxListLimit)
	if err != nil {
		return err
	}
	vault, err := queryUUID(c, "vault")
	if err != nil {
		return err
	}
	f := InviteFilter{VaultID: vault}
	switch c.Query("state") {
	case "", "all":
	case "active":
		f.ActiveOnly = true
	default:
		return badRequest(c, "state", "must be active or all")
	}
	after, err := decodeCursor(c)
	if err != nil {
		return err
	}
	list, more, err := h.Service.ListInvites(c.UserContext(), f, after, limit)
	if err != nil {
		return h.fail(c, err)
	}
	return c.JSON(newPage(list, more, ToInviteJSON(time.Now()), func(i Invite) string { return encodeCursor(i.CreatedAt, i.ID) }))
}

// revokeInvite clones the id for the same reason as revokeSession.
func (h *HTTP) revokeInvite(c *fiber.Ctx) error {
	if err := h.Service.RevokeInvite(c.UserContext(), actorOf(c), strings.Clone(c.Params("id"))); err != nil {
		return h.fail(c, err)
	}
	return c.SendStatus(fiber.StatusNoContent)
}
