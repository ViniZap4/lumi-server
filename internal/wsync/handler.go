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

// Handler bundles the dependencies a WS sync endpoint needs.
type Handler struct {
	hub      *Hub
	resolver capguard.Resolver
}

// NewHandler constructs a Handler. resolver is the capguard resolver
// (typically the members service) used for the note.edit gate at
// upgrade time.
func NewHandler(hub *Hub, resolver capguard.Resolver) *Handler {
	if hub == nil || resolver == nil {
		panic("wsync.NewHandler: missing dependency")
	}
	return &Handler{hub: hub, resolver: resolver}
}

// Register attaches the upgrade route and the WebSocket handler to the
// supplied router. The route is intentionally a plain GET so Fiber's
// upgrade negotiation runs through the existing middleware chain.
func (h *Handler) Register(r fiber.Router) {
	const path = "/vaults/:vault/notes/:id/sync"
	r.Use(path, h.upgradeGuard)
	r.Get(path, websocket.New(h.handleConn))
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
	c.Locals("wsync.vault", vaultID)
	c.Locals("wsync.note", noteID)
	c.Locals("wsync.user", uid)
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

	sub := h.hub.NewSubscriber(userID)
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

	// Read loop exited — tear down the writer pump.
	sub.CloseSubscriber()
	<-writerDone
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
	deadline := time.Now().Add(2 * time.Second)
	msg := websocket.FormatCloseMessage(websocket.CloseInternalServerErr, truncate(reason, 100))
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
