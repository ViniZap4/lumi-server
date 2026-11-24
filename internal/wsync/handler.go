package wsync

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/websocket/v2"
	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/ViniZap4/lumi-server/internal/auth"
	"github.com/ViniZap4/lumi-server/internal/capguard"
	"github.com/ViniZap4/lumi-server/internal/domain"
)

// pongTimeout bounds how long the server will wait between client
// frames before assuming the connection is dead. Combined with the
// websocket package's automatic pong reply, this gives us idle
// detection without an explicit heartbeat protocol.
const pongTimeout = 60 * time.Second

// MaxFrameBytes is the per-frame hard cap. fasthttp/websocket's
// default is 0 (unlimited) — a single attacker frame would otherwise
// be read fully into memory before any size check. A Yjs update for a
// busy doc tops out around a few hundred KiB; 1 MiB gives ~5x headroom
// while keeping the worst-case allocation bounded.
const MaxFrameBytes int64 = 1 << 20

// HandshakeTimeout bounds the HTTP→WS upgrade negotiation. Defaults to
// 10s — generous on a healthy network, short enough to release the
// goroutine if a peer hangs mid-handshake.
const HandshakeTimeout = 10 * time.Second

// MaxUserConnections is the per-user concurrent-WS cap. Beyond it,
// new upgrades are refused with a CloseGoingAway (1001) frame so the
// client can react. Sized for the realistic "one tab per workspace +
// a couple of background tools" pattern; raise if telemetry shows
// legitimate users hitting it.
const MaxUserConnections = 10

// Close codes for rejected or revoked sync sessions (CRDT client
// protocol §5, §10 S6). Browsers cannot read the status of a failed HTTP
// upgrade (they report close 1006), so the server completes the upgrade
// and closes immediately with one of these:
//
//	4401 credential missing, invalid or expired, or ws ticket unknown,
//	     expired, reused or minted for another note → mint a fresh ticket
//	     once; if that fails too, clear the session and re-login
//	4403 caller lacks note.edit on the vault → read-only, stop reconnecting
//	4404 vault or note does not exist, or the note was deleted while
//	     the socket was open                → stop reconnecting
//
// A ticket minted for a note whose CRDT epoch changed before the upgrade
// (delete+recreate, seeding) is refused with 4401 "ticket_stale": the
// client mints a fresh ticket and learns the new epoch from it.
// 4409 ("lineage changed") is client-side only: never sent by the server.
//
//	1008 per-user concurrent-socket cap    (policy violation)
//	1011 internal error while authorising  (transient, may retry)
//
// Long-lived sockets are re-authorised every RevalidateInterval and
// closed with 4401/4403/4404 once the session or capability is gone.
const (
	CloseUnauthorized = 4401
	CloseForbidden    = 4403
	CloseNotFound     = 4404
)

// RevalidateInterval is how often a live socket re-checks its session and
// note.edit capability.
var RevalidateInterval = 2 * time.Minute

// Authenticator validates a session token and returns the user id. It
// should wrap domain.ErrTokenInvalid / ErrTokenExpired for bad tokens;
// any other error is treated as an internal failure.
type Authenticator func(ctx context.Context, token string) (uuid.UUID, error)

// NoteLookup reports whether the note exists (domain.ErrNotFound if not).
type NoteLookup func(ctx context.Context, vaultID uuid.UUID, noteID string) error

// EpochLookup returns the note's current CRDT epoch (domain.ErrNotFound if
// the note does not exist).
type EpochLookup func(ctx context.Context, vaultID uuid.UUID, noteID string) (string, error)

// Handler bundles the dependencies a WS sync endpoint needs.
type Handler struct {
	hub            *Hub
	resolver       capguard.Resolver
	allowedOrigins []string
	authenticate   Authenticator
	noteExists     NoteLookup
	epochOf        EpochLookup
	tickets        *TicketStore
	log            zerolog.Logger
}

// NewHandler constructs a Handler. resolver is the capguard resolver
// (typically the members service) used for the note.edit gate.
// authenticate validates the session token itself: the route must be
// mounted OUTSIDE the auth-middleware group so failures become close
// codes instead of HTTP 401s. noteExists may be nil (no existence check).
// allowedOrigins is the WS Origin allow-list; pass an empty slice to
// allow any origin (dev/loopback). Browsers send Origin on WS upgrades;
// native clients (apple, tui) typically do not — empty Origin is always
// allowed because the auth token gate is the primary defense for those.
func NewHandler(hub *Hub, resolver capguard.Resolver, allowedOrigins []string, authenticate Authenticator, noteExists NoteLookup) *Handler {
	if hub == nil || resolver == nil || authenticate == nil {
		panic("wsync.NewHandler: missing dependency")
	}
	return &Handler{
		hub: hub, resolver: resolver, allowedOrigins: allowedOrigins,
		authenticate: authenticate, noteExists: noteExists,
		tickets: NewTicketStore(), log: zerolog.Nop(),
	}
}

// SetLogger installs the handler's logger (default: discard).
func (h *Handler) SetLogger(l zerolog.Logger) { h.log = l }

// SetEpochLookup enables CRDT-epoch support: ws-ticket responses carry
// the note's crdt_epoch (after pre-warming the room so lazy init has
// already settled it) and a ticket is refused if the epoch changed
// before redeem. nil disables.
func (h *Handler) SetEpochLookup(fn EpochLookup) { h.epochOf = fn }

// Tickets exposes the ticket table (tests, metrics).
func (h *Handler) Tickets() *TicketStore { return h.tickets }

// Register attaches the upgrade route and the WebSocket handler to the
// supplied router (expected to be rooted at /api and NOT behind the auth
// middleware — the handler authenticates on its own).
func (h *Handler) Register(r fiber.Router) {
	const path = "/vaults/:vault/notes/:id/sync"
	cfg := websocket.Config{
		HandshakeTimeout: HandshakeTimeout,
		// EnableCompression: false is the package default. We keep it
		// off deliberately: perMessageDeflate adds a compression-bomb
		// attack surface and Yjs binary updates are already
		// well-compressed by lib0 v1 encoding.
		EnableCompression: false,
		// Origin is enforced in upgradeGuard (originAllowed), not here:
		// the library rejects an ABSENT Origin whenever a list is set,
		// which locked out native clients (Apple, TUI) in production.
		Origins: []string{"*"},
	}
	r.Use(path, h.upgradeGuard)
	r.Get(path, websocket.New(h.handleConn, cfg))
}

// RegisterTicket mounts POST /vaults/:vault/notes/:id/ws-ticket. r must be
// the authenticated /api group (auth.Required ran: user + session bound).
func (h *Handler) RegisterTicket(r fiber.Router) {
	r.Post("/vaults/:vault/notes/:id/ws-ticket", h.issueTicket)
}

type rejection struct {
	code   int
	reason string
}

// authorize runs every gate and returns the user id or the close code.
func (h *Handler) authorize(ctx context.Context, token string, vaultID uuid.UUID, noteID string) (uuid.UUID, *rejection) {
	if token == "" {
		return uuid.Nil, &rejection{CloseUnauthorized, "unauthorized"}
	}
	uid, err := h.authenticate(ctx, token)
	if err != nil {
		switch {
		case errors.Is(err, domain.ErrTokenExpired):
			return uuid.Nil, &rejection{CloseUnauthorized, "token_expired"}
		case errors.Is(err, domain.ErrTokenInvalid), errors.Is(err, domain.ErrUnauthorized), errors.Is(err, domain.ErrNotFound):
			return uuid.Nil, &rejection{CloseUnauthorized, "unauthorized"}
		default:
			return uuid.Nil, &rejection{websocket.CloseInternalServerErr, "auth_unavailable"}
		}
	}
	if rej := h.authorizeUser(ctx, uid, vaultID, noteID); rej != nil {
		return uuid.Nil, rej
	}
	return uid, nil
}

// authorizeUser runs the capability and existence gates for an already
// authenticated user.
func (h *Handler) authorizeUser(ctx context.Context, uid, vaultID uuid.UUID, noteID string) *rejection {
	role, err := h.resolver.RoleForUser(ctx, vaultID, uid)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return &rejection{CloseForbidden, "capability_missing"}
		}
		return &rejection{websocket.CloseInternalServerErr, "authz_unavailable"}
	}
	if !role.Capabilities.Has(domain.CapNoteEdit) {
		if role.MirrorReadOnly {
			return &rejection{CloseForbidden, "mirror_read_only"}
		}
		return &rejection{CloseForbidden, "capability_missing"}
	}
	if h.noteExists != nil {
		if err := h.noteExists(ctx, vaultID, noteID); err != nil {
			if errors.Is(err, domain.ErrNotFound) {
				return &rejection{CloseNotFound, "note_not_found"}
			}
			return &rejection{websocket.CloseInternalServerErr, "lookup_failed"}
		}
	}
	return nil
}

// upgradeGuard runs before the WS upgrade. Non-WS requests get 426. For
// WS requests every auth/permission/existence failure is recorded and the
// upgrade proceeds, so handleConn can close with the specific code.
func (h *Handler) upgradeGuard(c *fiber.Ctx) error {
	if !websocket.IsWebSocketUpgrade(c) {
		return fiber.ErrUpgradeRequired
	}
	if !originAllowed(h.allowedOrigins, c.Get(fiber.HeaderOrigin)) {
		return fiber.ErrForbidden
	}
	// Clone: Fiber strings alias the reusable request buffer and these
	// values outlive the handler (Locals read by the socket goroutine).
	noteID := strings.Clone(strings.TrimSpace(c.Params("id")))
	vaultID, verr := uuid.Parse(c.Params("vault"))
	var rej *rejection
	var uid uuid.UUID
	var token string
	switch ticket := strings.TrimSpace(c.Query("ticket")); {
	case ticket != "":
		// A presented ticket is consumed here whatever happens next;
		// it is the only credential considered for this upgrade.
		token, uid, rej = h.redeemTicket(c, ticket, vaultID, verr == nil, noteID)
	default:
		token = auth.ExtractToken(c)
		if token != "" && headerToken(c) == "" {
			// Deprecated: session token in the query string. Kept for
			// clients predating ws-ticket; removal plan in ticket docs.
			h.log.Debug().Str("path", c.Path()).Msg("wsync: deprecated ?token= on sync upgrade; use POST .../ws-ticket")
		}
		uid, rej = h.authorizeLegacy(c.UserContext(), token, vaultID, verr == nil, noteID)
	}
	c.Locals("wsync.reject", rej)
	c.Locals("wsync.token", strings.Clone(token))
	c.Locals("wsync.vault", vaultID)
	c.Locals("wsync.note", noteID)
	c.Locals("wsync.user", uid)
	c.Locals("wsync.client", clientIDFromQuery(c))
	return c.Next()
}

// redeemTicket consumes ticket and checks it against the requested route.
// It returns the session token the socket re-validates against.
func (h *Handler) redeemTicket(c *fiber.Ctx, ticket string, vaultID uuid.UUID, vaultOK bool, noteID string) (string, uuid.UUID, *rejection) {
	invalid := &rejection{CloseUnauthorized, "ticket_invalid"}
	b, err := h.tickets.Consume(ticket)
	if err != nil {
		return "", uuid.Nil, invalid
	}
	if !vaultOK || b.VaultID != vaultID || b.NoteID != noteID {
		return "", uuid.Nil, invalid
	}
	ctx := c.UserContext()
	// The minting session must still be live and still belong to the
	// bound user (logout between mint and upgrade invalidates).
	uid, err := h.authenticate(ctx, b.Session)
	if err != nil || uid != b.UserID {
		return "", uuid.Nil, invalid
	}
	// A header credential for a different user alongside the ticket is a
	// confused request: refuse rather than guess whose socket this is.
	if hdr := headerToken(c); hdr != "" {
		other, err := h.authenticate(ctx, hdr)
		if err != nil || other != b.UserID {
			return "", uuid.Nil, invalid
		}
	}
	if rej := h.authorizeUser(ctx, uid, vaultID, noteID); rej != nil {
		return "", uuid.Nil, rej
	}
	if b.CRDTEpoch != "" && h.epochOf != nil {
		cur, err := h.epochOf(ctx, vaultID, noteID)
		switch {
		case errors.Is(err, domain.ErrNotFound):
			return "", uuid.Nil, &rejection{CloseNotFound, "note_not_found"}
		case err != nil:
			return "", uuid.Nil, &rejection{websocket.CloseInternalServerErr, "lookup_failed"}
		case cur != b.CRDTEpoch:
			return "", uuid.Nil, &rejection{CloseUnauthorized, "ticket_stale"}
		}
	}
	return b.Session, uid, nil
}

// authorizeLegacy is the token (header or deprecated ?token=) path.
func (h *Handler) authorizeLegacy(ctx context.Context, token string, vaultID uuid.UUID, vaultOK bool, noteID string) (uuid.UUID, *rejection) {
	switch {
	case !vaultOK, noteID == "", strings.ContainsAny(noteID, "/\\"):
		// Still require a valid token first so the code doesn't leak
		// existence to anonymous callers.
		if _, r := h.authorizeTokenOnly(ctx, token); r != nil {
			return uuid.Nil, r
		}
		return uuid.Nil, &rejection{CloseNotFound, "note_not_found"}
	default:
		return h.authorize(ctx, token, vaultID, noteID)
	}
}

// headerToken returns a session token sent in a header (never the query).
func headerToken(c *fiber.Ctx) string {
	if t := strings.TrimSpace(c.Get(auth.HeaderToken)); t != "" {
		return t
	}
	if a := strings.TrimSpace(c.Get(auth.HeaderAuthBearer)); len(a) > 7 && strings.EqualFold(a[:7], "Bearer ") {
		return strings.TrimSpace(a[7:])
	}
	return ""
}

// clientIDFromQuery is the optional presence identity (legacy JSON presence).
func clientIDFromQuery(c *fiber.Ctx) uuid.UUID {
	if raw := strings.TrimSpace(c.Query("client_id")); raw != "" {
		if id, err := uuid.Parse(raw); err == nil {
			return id
		}
	}
	return uuid.Nil
}

func (h *Handler) authorizeTokenOnly(ctx context.Context, token string) (uuid.UUID, *rejection) {
	if token == "" {
		return uuid.Nil, &rejection{CloseUnauthorized, "unauthorized"}
	}
	uid, err := h.authenticate(ctx, token)
	if err != nil {
		if errors.Is(err, domain.ErrTokenExpired) {
			return uuid.Nil, &rejection{CloseUnauthorized, "token_expired"}
		}
		return uuid.Nil, &rejection{CloseUnauthorized, "unauthorized"}
	}
	return uid, nil
}

// ticketResponse is the 201 body of POST .../ws-ticket.
type ticketResponse struct {
	Ticket    string `json:"ticket"`
	ExpiresAt string `json:"expires_at"` // RFC 3339, UTC
	// CRDTEpoch is the lineage of the doc the socket will join (protocol
	// §12). Omitted when the server runs without epoch support.
	CRDTEpoch string `json:"crdt_epoch,omitempty"`
}

// issueTicket mints a single-use WS ticket for the caller's current
// session. It applies exactly the gates the upgrade applies (note.edit on
// the vault, note exists), so a ticket is only handed out for a socket
// that would be accepted right now.
func (h *Handler) issueTicket(c *fiber.Ctx) error {
	sess, user := auth.SessionFromCtx(c), auth.UserFromCtx(c)
	if sess == nil || user == nil || sess.Token == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized"})
	}
	vaultID, err := uuid.Parse(c.Params("vault"))
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid_vault_id"})
	}
	noteID := strings.TrimSpace(c.Params("id"))
	if noteID == "" || strings.ContainsAny(noteID, "/\\") {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "not_found"})
	}
	if rej := h.authorizeUser(c.UserContext(), user.ID, vaultID, noteID); rej != nil {
		switch rej.code {
		case CloseForbidden:
			if rej.reason == "mirror_read_only" {
				return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "mirror_read_only"})
			}
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "forbidden"})
		case CloseNotFound:
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "not_found"})
		default:
			return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{"error": "unavailable"})
		}
	}
	var epoch string
	if h.epochOf != nil {
		// Load the room first: a never-seeded note is lazily initialised
		// now (rotating its epoch), not at join time, so the epoch below
		// is the lineage the socket will actually join. The room lingers
		// for the idle TTL, so the upgrade that follows is warm.
		ctx := c.UserContext()
		if err := h.hub.Prewarm(ctx, vaultID, noteID); err != nil {
			if errors.Is(err, domain.ErrNotFound) {
				return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "not_found"})
			}
			return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{"error": "unavailable"})
		}
		if epoch, err = h.epochOf(ctx, vaultID, noteID); err != nil {
			if errors.Is(err, domain.ErrNotFound) {
				return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "not_found"})
			}
			return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{"error": "unavailable"})
		}
	}
	// Fiber strings alias the request buffer, which fasthttp reuses after
	// the handler returns: clone everything the table outlives us with.
	ticket, exp, err := h.tickets.Issue(TicketBinding{
		UserID: user.ID, Session: strings.Clone(sess.Token), VaultID: vaultID, NoteID: strings.Clone(noteID),
		CRDTEpoch: epoch,
	})
	switch {
	case errors.Is(err, ErrTicketUserLimit):
		c.Set(fiber.HeaderRetryAfter, "30")
		return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{"error": "too_many_tickets"})
	case errors.Is(err, ErrTicketCapacity):
		c.Set(fiber.HeaderRetryAfter, "5")
		return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{"error": "unavailable"})
	case err != nil:
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "internal"})
	}
	c.Set(fiber.HeaderCacheControl, "no-store")
	return c.Status(fiber.StatusCreated).JSON(ticketResponse{
		Ticket:    ticket,
		ExpiresAt: exp.UTC().Format(time.RFC3339),
		CRDTEpoch: epoch,
	})
}

// handleConn is the per-connection lifecycle: join the room, send our
// initial SyncStep1, spawn a writer pump, then drain inbound messages
// until the connection closes.
func (h *Handler) handleConn(c *websocket.Conn) {
	if rej, _ := c.Locals("wsync.reject").(*rejection); rej != nil {
		_ = writeCloseCode(c, rej.code, rej.reason)
		return
	}
	vaultID, ok := c.Locals("wsync.vault").(uuid.UUID)
	if !ok {
		_ = c.Close()
		return
	}
	token, _ := c.Locals("wsync.token").(string)
	noteID, _ := c.Locals("wsync.note").(string)
	if noteID == "" {
		_ = c.Close()
		return
	}
	userID, _ := c.Locals("wsync.user").(uuid.UUID)
	clientID, _ := c.Locals("wsync.client").(uuid.UUID)

	// Cap memory growth from a hostile peer. Default is unlimited.
	c.SetReadLimit(MaxFrameBytes)

	// Per-user concurrent connection cap. Enforced inside handleConn
	// (after the upgrade succeeded) so the slot lifecycle is bracketed
	// by a single goroutine and cannot leak on upgrade failure.
	if !h.hub.TryAcquireUserSlot(userID) {
		_ = writeCloseCode(c, websocket.ClosePolicyViolation, "concurrent_limit_exceeded")
		return
	}
	defer h.hub.ReleaseUserSlot(userID)

	sub := h.hub.NewSubscriberWithClient(userID, clientID)
	// websocket.Conn doesn't expose UserContext — use a background ctx
	// for the synchronous Join call (it returns quickly after LoadDoc).
	room, err := h.hub.Join(context.Background(), vaultID, noteID, sub)
	if err != nil {
		_ = writeClose(c, fmt.Sprintf("join: %v", err))
		return
	}
	defer h.hub.Leave(room, sub)

	// Send our state vector so the client knows what it needs to ship.
	if sv, err := room.Doc().StateVectorV1(); err == nil {
		_ = c.WriteMessage(websocket.BinaryMessage, EncodeSyncStep1(sv))
	}

	// Writer pump: ranges over sub.Out, exits on sub.Done. Errors on the
	// socket trigger close of the read side via c.Close.
	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		for {
			select {
			case msg, ok := <-sub.Out:
				if !ok {
					return
				}
				if err := c.WriteMessage(websocket.BinaryMessage, msg); err != nil {
					_ = c.Close()
					return
				}
			case <-sub.Done:
				return
			}
		}
	}()

	// Shutdown propagation: when the subscriber's Done channel is
	// closed (either because Leave was called or because the hub is
	// tearing down via evict→CloseSubscriber), force the connection
	// shut. Without this the reader loop below stays blocked on
	// c.ReadMessage forever — leaking a goroutine per never-disconnecting
	// client across a server shutdown.
	closerDone := make(chan struct{})
	go func() {
		defer close(closerDone)
		<-sub.Done
		if code, reason := sub.CloseCode(); code != 0 {
			// Server-ended subscription (e.g. 4404 note deleted).
			_ = writeCloseCode(c, code, reason)
			return
		}
		_ = c.Close()
	}()

	// Periodic re-authorisation: a revoked session, removed capability or
	// deleted note ends the socket with the matching close code.
	revalDone := make(chan struct{})
	go func() {
		defer close(revalDone)
		if RevalidateInterval <= 0 {
			return
		}
		t := time.NewTicker(RevalidateInterval)
		defer t.Stop()
		for {
			select {
			case <-sub.Done:
				return
			case <-t.C:
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				_, rej := h.authorize(ctx, token, vaultID, noteID)
				cancel()
				if rej != nil && rej.code != websocket.CloseInternalServerErr {
					_ = writeCloseCode(c, rej.code, rej.reason)
					sub.CloseSubscriber()
					return
				}
			}
		}
	}()

	// Reader loop.
	_ = c.SetReadDeadline(time.Now().Add(pongTimeout))
	c.SetPongHandler(func(string) error {
		return c.SetReadDeadline(time.Now().Add(pongTimeout))
	})

	for {
		mt, frame, err := c.ReadMessage()
		if err != nil {
			break
		}
		if mt != websocket.BinaryMessage {
			// Yjs sync is strictly binary. Ignore text frames so legacy
			// clients trying to send JSON don't kill the session.
			continue
		}
		_ = c.SetReadDeadline(time.Now().Add(pongTimeout))

		msg, derr := DecodeMessage(frame)
		if derr != nil {
			// Malformed frame — keep the session open, drop the frame.
			continue
		}
		h.handleMessage(room, sub, userID, msg)
	}

	// Read loop exited — tear down the writer + closer pumps.
	sub.CloseSubscriber()
	<-writerDone
	<-closerDone
	<-revalDone
}

func (h *Handler) handleMessage(room *Room, sub *Subscriber, userID uuid.UUID, msg ParsedMessage) {
	switch msg.Type {
	case MessageSync:
		switch msg.SyncSub {
		case SyncStep1:
			// Client's state vector — answer with our diff.
			diff, err := room.Doc().EncodeDiffSince(msg.Body)
			if err != nil {
				return
			}
			select {
			case sub.Out <- EncodeSyncStep2(diff):
			default:
				sub.CloseSubscriber()
			}
		case SyncStep2, SyncUpdate:
			// Both carry an update blob the server should adopt and
			// fan out. The distinction matters only to the client.
			if len(msg.Body) == 0 {
				return
			}
			if err := room.ApplyAndBroadcast(msg.Body, sub, userID); err != nil {
				return
			}
		}
	case MessageAwareness:
		if len(msg.Body) == 0 {
			return
		}
		room.handleAwareness(msg.Body, sub)
	case MessageQueryAwareness:
		room.queryAwareness(sub)
	case MessageAuth:
		// Yjs's auth message has no agreed semantics across clients;
		// our gate runs at upgrade time. Drop.
	}
}

func writeClose(c *websocket.Conn, reason string) error {
	return writeCloseCode(c, websocket.CloseInternalServerErr, reason)
}

func writeCloseCode(c *websocket.Conn, code int, reason string) error {
	deadline := time.Now().Add(2 * time.Second)
	msg := websocket.FormatCloseMessage(code, truncate(reason, 100))
	_ = c.WriteControl(websocket.CloseMessage, msg, deadline)
	return c.Close()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// Compile-time assertions that we use what we import.
var (
	_ = errors.New
)

// originAllowed is the WS Origin policy. Browsers always send Origin on a
// WebSocket upgrade, so a present Origin must be on the allow-list (CSWSH
// defense). Native clients (Apple, TUI) send none; they are admitted and
// gated by the ticket/token like any other request. An empty list (dev,
// loopback) or "*" allows every origin.
func originAllowed(allowed []string, origin string) bool {
	if origin == "" || len(allowed) == 0 {
		return true
	}
	for _, a := range allowed {
		if a == "*" || a == origin {
			return true
		}
	}
	return false
}
