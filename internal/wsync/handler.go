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
//	4401 token missing, invalid or expired → client clears session, re-login
//	4403 caller lacks note.edit on the vault → read-only, stop reconnecting
//	4404 vault or note does not exist      → stop reconnecting
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

// Handler bundles the dependencies a WS sync endpoint needs.
type Handler struct {
	hub            *Hub
	resolver       capguard.Resolver
	allowedOrigins []string
	authenticate   Authenticator
	noteExists     NoteLookup
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
	return &Handler{hub: hub, resolver: resolver, allowedOrigins: allowedOrigins, authenticate: authenticate, noteExists: noteExists}
}

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
		Origins:           h.allowedOrigins,
	}
	r.Use(path, h.upgradeGuard)
	r.Get(path, websocket.New(h.handleConn, cfg))
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
	role, err := h.resolver.RoleForUser(ctx, vaultID, uid)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return uuid.Nil, &rejection{CloseForbidden, "capability_missing"}
		}
		return uuid.Nil, &rejection{websocket.CloseInternalServerErr, "authz_unavailable"}
	}
	if !role.Capabilities.Has(domain.CapNoteEdit) {
		return uuid.Nil, &rejection{CloseForbidden, "capability_missing"}
	}
	if h.noteExists != nil {
		if err := h.noteExists(ctx, vaultID, noteID); err != nil {
			if errors.Is(err, domain.ErrNotFound) {
				return uuid.Nil, &rejection{CloseNotFound, "note_not_found"}
			}
			return uuid.Nil, &rejection{websocket.CloseInternalServerErr, "lookup_failed"}
		}
	}
	return uid, nil
}

// upgradeGuard runs before the WS upgrade. Non-WS requests get 426. For
// WS requests every auth/permission/existence failure is recorded and the
// upgrade proceeds, so handleConn can close with the specific code.
func (h *Handler) upgradeGuard(c *fiber.Ctx) error {
	if !websocket.IsWebSocketUpgrade(c) {
		return fiber.ErrUpgradeRequired
	}
	token := auth.ExtractToken(c)
	noteID := strings.TrimSpace(c.Params("id"))
	vaultID, verr := uuid.Parse(c.Params("vault"))
	var rej *rejection
	var uid uuid.UUID
	switch {
	case verr != nil, noteID == "", strings.ContainsAny(noteID, "/\\"):
		// Still require a valid token first so the code doesn't leak
		// existence to anonymous callers.
		if _, r := h.authorizeTokenOnly(c.UserContext(), token); r != nil {
			rej = r
		} else {
			rej = &rejection{CloseNotFound, "note_not_found"}
		}
	default:
		uid, rej = h.authorize(c.UserContext(), token, vaultID, noteID)
	}
	// Optional presence identity (legacy JSON presence).
	var clientID uuid.UUID
	if raw := strings.TrimSpace(c.Query("client_id")); raw != "" {
		if id, err := uuid.Parse(raw); err == nil {
			clientID = id
		}
	}
	c.Locals("wsync.reject", rej)
	c.Locals("wsync.token", token)
	c.Locals("wsync.vault", vaultID)
	c.Locals("wsync.note", noteID)
	c.Locals("wsync.user", uid)
	c.Locals("wsync.client", clientID)
	return c.Next()
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
