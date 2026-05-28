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

// Handler bundles the dependencies a WS sync endpoint needs.
type Handler struct {
	hub             *Hub
	resolver        capguard.Resolver
	allowedOrigins  []string
}

// NewHandler constructs a Handler. resolver is the capguard resolver
// (typically the members service) used for the note.edit gate at
// upgrade time. allowedOrigins is the WS Origin allow-list; pass an
// empty slice to allow any origin (dev/loopback). Browsers send
// Origin on WS upgrades; native clients (apple, tui) typically do
// not — empty Origin is always allowed because the auth token gate
// is the primary defense for those.
func NewHandler(hub *Hub, resolver capguard.Resolver, allowedOrigins []string) *Handler {
	if hub == nil || resolver == nil {
		panic("wsync.NewHandler: missing dependency")
	}
	return &Handler{hub: hub, resolver: resolver, allowedOrigins: allowedOrigins}
}

// Register attaches the upgrade route and the WebSocket handler to the
// supplied router. The route is intentionally a plain GET so Fiber's
// upgrade negotiation runs through the existing middleware chain.
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

// upgradeGuard runs before the WS upgrade. Rejects non-WS requests,
// enforces the note.edit capability (write access is required to send
// updates; the few read-only viewers can still poll /content), and
// reflects the vault+note params + user id into Locals so the WS
// handler has them.
func (h *Handler) upgradeGuard(c *fiber.Ctx) error {
	if !websocket.IsWebSocketUpgrade(c) {
		return fiber.ErrUpgradeRequired
	}
	vaultID, err := capguard.WithVaultID(c)
	if err != nil {
		return nil
	}
	if err := capguard.Require(c, h.resolver, vaultID, domain.CapNoteEdit); err != nil {
		return nil
	}
	noteID := strings.TrimSpace(c.Params("id"))
	if noteID == "" || strings.ContainsAny(noteID, "/\\") {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid_note_id"})
	}
	uid, _ := capguard.UserIDFrom(c)
	// Optional presence identity. When the client supplies a valid
	// UUID we stamp it on the Subscriber so Leave can fan out a
	// "left" awareness frame. A missing or malformed value is silently
	// treated as "no presence" — clients without awareness still work.
	var clientID uuid.UUID
	if raw := strings.TrimSpace(c.Query("client_id")); raw != "" {
		if id, err := uuid.Parse(raw); err == nil {
			clientID = id
		}
	}
	c.Locals("wsync.vault", vaultID)
	c.Locals("wsync.note", noteID)
	c.Locals("wsync.user", uid)
	c.Locals("wsync.client", clientID)
	return c.Next()
}

// handleConn is the per-connection lifecycle: join the room, send our
// initial SyncStep1, spawn a writer pump, then drain inbound messages
// until the connection closes.
func (h *Handler) handleConn(c *websocket.Conn) {
	vaultID, ok := c.Locals("wsync.vault").(uuid.UUID)
	if !ok {
		_ = c.Close()
		return
	}
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
		room.BroadcastAwareness(msg.Body, sub)
	case MessageQueryAwareness:
		// We don't keep a server-side awareness register; nothing to
		// reply with. Slice 2.3 tradeoff.
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
