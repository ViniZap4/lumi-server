package federation

import (
	"crypto/ed25519"
	"encoding/hex"
	"net/http"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/websocket/v2"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

// RelayHandlers is the home-side HTTP surface of the F2 relay: the
// sync-challenge endpoint and the authenticated WS upgrade.
type RelayHandlers struct {
	svc    *Service
	links  *Links
	nonces *nonceStore
	log    zerolog.Logger
}

func NewRelayHandlers(svc *Service, links *Links, log zerolog.Logger) *RelayHandlers {
	return &RelayHandlers{svc: svc, links: links, nonces: newNonceStore(), log: log}
}

// Register attaches the public relay routes. Both are unauthenticated in
// the session sense: authorisation is the active federation row plus the
// Ed25519 signature over the single-use nonce.
func (h *RelayHandlers) Register(app *fiber.App) {
	app.Post("/api/federation/sync-challenge", h.challenge)

	const path = "/api/federation/vaults/:vault/sync"
	cfg := websocket.Config{
		HandshakeTimeout: 10 * time.Second,
		// Compression off for the same reason as wsync: no
		// perMessageDeflate bomb surface; lib0 frames are dense already.
		EnableCompression: false,
	}
	app.Use(path, h.upgradeGuard)
	app.Get(path, websocket.New(h.handleConn, cfg))
}

type challengeReq struct {
	VaultID string `json:"vault_id"`
	PeerURL string `json:"peer_url"`
}

// challenge mints a single-use nonce bound to (vault, peer). Only issued
// when an active home-role federation row exists for the pair, so it also
// cheaply answers "is this link live" without leaking anything else.
func (h *RelayHandlers) challenge(c *fiber.Ctx) error {
	var req challengeReq
	if err := c.BodyParser(&req); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "invalid_body"})
	}
	vaultID, err := uuid.Parse(req.VaultID)
	if err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "invalid_vault_id"})
	}
	peerURL := normalizeServerURL(req.PeerURL)
	fed, err := h.svc.federations.GetActiveByVaultAndPeer(c.UserContext(), vaultID, peerURL)
	if err != nil || fed.Role != "home" {
		// Uniform 403: no oracle distinguishing "unknown vault" from
		// "not federated with you".
		return c.Status(http.StatusForbidden).JSON(fiber.Map{"error": "forbidden"})
	}
	return c.JSON(fiber.Map{"nonce": h.nonces.mint(vaultID, peerURL)})
}

const (
	relayVaultKey = "federation.vault"
	relayPeerKey  = "federation.peer"
)

// upgradeGuard authenticates the WS upgrade: single-use nonce bound to
// (vault, peer) plus an Ed25519 signature by the enrolled peer key over
// SyncAuthMessage(nonce, vault, peer).
func (h *RelayHandlers) upgradeGuard(c *fiber.Ctx) error {
	if !websocket.IsWebSocketUpgrade(c) {
		return fiber.ErrUpgradeRequired
	}
	vaultID, err := uuid.Parse(c.Params("vault"))
	if err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "invalid_vault_id"})
	}
	peerURL := normalizeServerURL(c.Query("peer_url"))
	nonce := strings.TrimSpace(c.Query("nonce"))
	sigHex := strings.TrimSpace(c.Query("sig"))
	if peerURL == "" || nonce == "" || sigHex == "" {
		return c.Status(http.StatusForbidden).JSON(fiber.Map{"error": "forbidden"})
	}
	if !h.nonces.consume(nonce, vaultID, peerURL) {
		return c.Status(http.StatusForbidden).JSON(fiber.Map{"error": "forbidden"})
	}
	fed, err := h.svc.federations.GetActiveByVaultAndPeer(c.UserContext(), vaultID, peerURL)
	if err != nil || fed.Role != "home" {
		return c.Status(http.StatusForbidden).JSON(fiber.Map{"error": "forbidden"})
	}
	sig, err := hex.DecodeString(sigHex)
	if err != nil || len(sig) != ed25519.SignatureSize ||
		!ed25519.Verify(ed25519.PublicKey(fed.PeerPubKey), SyncAuthMessage(nonce, vaultID.String(), peerURL), sig) {
		return c.Status(http.StatusForbidden).JSON(fiber.Map{"error": "forbidden"})
	}
	c.Locals(relayVaultKey, vaultID)
	c.Locals(relayPeerKey, peerURL)
	return c.Next()
}

func (h *RelayHandlers) handleConn(conn *websocket.Conn) {
	vaultID, _ := conn.Locals(relayVaultKey).(uuid.UUID)
	peerURL, _ := conn.Locals(relayPeerKey).(string)
	if vaultID == uuid.Nil || peerURL == "" {
		_ = conn.Close()
		return
	}
	h.log.Info().Str("peer", peerURL).Str("vault", vaultID.String()).Msg("federation: follower connected")
	sess := h.links.NewSession(nil, conn, vaultID, peerURL, "home")
	if err := sess.Run(); err != nil {
		h.log.Warn().Err(err).Str("peer", peerURL).Msg("federation: relay session ended")
	}
}
