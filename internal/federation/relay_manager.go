package federation

import (
	"context"
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"math/rand"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

// Reconnect policy for follower dial loops: exponential backoff with ±20%
// jitter, capped. Mirrors the Apple client's reconnect curve.
const (
	reconnectBase = 2 * time.Second
	reconnectMax  = 64 * time.Second
)

// nonceTTL bounds the window between challenge issuance and WS upgrade.
const nonceTTL = 60 * time.Second

// Dialer opens the relay WebSocket to a peer. Default wraps
// fasthttp/websocket; tests substitute an in-memory pipe.
type Dialer func(ctx context.Context, wsURL string) (wsConn, error)

// Manager runs the follower side of every active federation link: one
// reconnecting dial loop per (vault, home) row. The home side is passive —
// its sessions are born in the WS handler.
type Manager struct {
	svc    *Service
	links  *Links
	dialer Dialer
	log    zerolog.Logger

	mu    sync.Mutex
	loops map[string]context.CancelFunc // key vaultID|peerURL
}

func NewManager(svc *Service, links *Links, dialer Dialer, log zerolog.Logger) *Manager {
	if dialer == nil {
		dialer = defaultDialer
	}
	return &Manager{svc: svc, links: links, dialer: dialer, log: log, loops: map[string]context.CancelFunc{}}
}

func loopKey(vaultID uuid.UUID, peerURL string) string { return vaultID.String() + "|" + peerURL }

// Start launches dial loops for every active follower row. Call once at
// boot after migrations.
func (m *Manager) Start(ctx context.Context) error {
	rows, err := m.svc.federations.ListActiveByRole(ctx, "follower")
	if err != nil {
		return err
	}
	for _, row := range rows {
		m.StartLink(ctx, row.VaultID, row.PeerURL)
	}
	return nil
}

// StartLink launches (or restarts) the dial loop for one follower link.
// Idempotent per (vault, peer).
func (m *Manager) StartLink(ctx context.Context, vaultID uuid.UUID, homeURL string) {
	key := loopKey(vaultID, homeURL)
	m.mu.Lock()
	if _, running := m.loops[key]; running {
		m.mu.Unlock()
		return
	}
	loopCtx, cancel := context.WithCancel(ctx)
	m.loops[key] = cancel
	m.mu.Unlock()

	go func() {
		defer func() {
			m.mu.Lock()
			delete(m.loops, key)
			m.mu.Unlock()
		}()
		m.runLoop(loopCtx, vaultID, homeURL)
	}()
}

// StopLink cancels the dial loop and closes any live session for the link.
// Called on federation revoke/sever.
func (m *Manager) StopLink(vaultID uuid.UUID, peerURL string) {
	m.mu.Lock()
	cancel := m.loops[loopKey(vaultID, peerURL)]
	m.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	m.links.ClosePeer(vaultID, peerURL)
}

func (m *Manager) runLoop(ctx context.Context, vaultID uuid.UUID, homeURL string) {
	attempt := 0
	for {
		if ctx.Err() != nil {
			return
		}
		start := time.Now()
		err := m.connectOnce(ctx, vaultID, homeURL)
		if ctx.Err() != nil {
			return
		}
		// A connection that survived a while earns a fresh backoff.
		if time.Since(start) > 30*time.Second {
			attempt = 0
		}
		attempt++
		delay := backoff(attempt)
		m.log.Warn().Err(err).Str("home", homeURL).Dur("retry_in", delay).
			Msg("federation: relay link down")
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
	}
}

func (m *Manager) connectOnce(ctx context.Context, vaultID uuid.UUID, homeURL string) error {
	// The link may have been revoked from our side while we slept.
	rows, err := m.svc.federations.ListForVault(ctx, vaultID)
	if err != nil {
		return err
	}
	active := false
	for _, r := range rows {
		if r.Role == "follower" && r.PeerURL == homeURL && r.Status == "active" {
			active = true
			break
		}
	}
	if !active {
		return fmt.Errorf("federation: link no longer active")
	}

	nonce, err := m.svc.client.SyncChallenge(ctx, homeURL, vaultID, m.svc.baseURL)
	if err != nil {
		return fmt.Errorf("sync challenge: %w", err)
	}
	sig := ed25519.Sign(m.svc.priv, SyncAuthMessage(nonce, vaultID.String(), m.svc.baseURL))
	wsURL, err := relayWSURL(homeURL, vaultID, m.svc.baseURL, nonce, hex.EncodeToString(sig))
	if err != nil {
		return err
	}
	conn, err := m.dialer(ctx, wsURL)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	m.log.Info().Str("home", homeURL).Str("vault", vaultID.String()).Msg("federation: relay link up")
	sess := m.links.NewSession(ctx, conn, vaultID, homeURL, "follower")
	return sess.Run()
}

func backoff(attempt int) time.Duration {
	d := reconnectBase << (attempt - 1)
	if attempt > 6 || d > reconnectMax {
		d = reconnectMax
	}
	jitter := time.Duration(rand.Int63n(int64(d) / 5)) // #nosec G404 — jitter only
	return d - d/10 + jitter
}

func relayWSURL(homeURL string, vaultID uuid.UUID, peerURL, nonce, sigHex string) (string, error) {
	u, err := url.Parse(homeURL)
	if err != nil {
		return "", err
	}
	switch u.Scheme {
	case "https":
		u.Scheme = "wss"
	case "http":
		u.Scheme = "ws"
	default:
		return "", fmt.Errorf("federation: unsupported scheme %q", u.Scheme)
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/api/federation/vaults/" + vaultID.String() + "/sync"
	q := u.Query()
	q.Set("peer_url", peerURL)
	q.Set("nonce", nonce)
	q.Set("sig", sigHex)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// ---- nonce store (home side) ------------------------------------------------------

type nonceEntry struct {
	vaultID uuid.UUID
	peerURL string
	expires time.Time
}

// nonceStore is the home-side single-use challenge registry.
type nonceStore struct {
	mu    sync.Mutex
	byVal map[string]nonceEntry
	now   func() time.Time
}

func newNonceStore() *nonceStore {
	return &nonceStore{byVal: map[string]nonceEntry{}, now: time.Now}
}

func (n *nonceStore) mint(vaultID uuid.UUID, peerURL string) string {
	nonce := newToken()
	n.mu.Lock()
	defer n.mu.Unlock()
	// Opportunistic sweep keeps the map bounded without a janitor.
	for k, e := range n.byVal {
		if e.expires.Before(n.now()) {
			delete(n.byVal, k)
		}
	}
	n.byVal[nonce] = nonceEntry{vaultID: vaultID, peerURL: peerURL, expires: n.now().Add(nonceTTL)}
	return nonce
}

// consume validates and burns a nonce. Constant-time on the token compare
// is unnecessary (map lookup by full value), but expiry and binding are
// strict: wrong vault or peer burns the nonce too.
func (n *nonceStore) consume(nonce string, vaultID uuid.UUID, peerURL string) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	e, ok := n.byVal[nonce]
	if !ok {
		return false
	}
	delete(n.byVal, nonce)
	if e.expires.Before(n.now()) {
		return false
	}
	vaultOK := e.vaultID == vaultID
	peerOK := subtle.ConstantTimeCompare([]byte(e.peerURL), []byte(peerURL)) == 1
	return vaultOK && peerOK
}
