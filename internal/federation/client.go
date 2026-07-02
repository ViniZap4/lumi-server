package federation

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	fws "github.com/fasthttp/websocket"
	"github.com/google/uuid"
)

// httpClient is the default HomeClient: plain JSON over HTTP(S) with tight
// timeouts. TLS enforcement mirrors the rest of lumi — production deploys
// terminate TLS upstream and set https base URLs; http is tolerated for
// loopback/dev.
type httpClient struct {
	c *http.Client
}

func newHTTPClient() *httpClient {
	return &httpClient{c: &http.Client{Timeout: 15 * time.Second}}
}

// maxPeerResponse caps how much of a peer's response we read: identity and
// accept payloads are tiny, anything larger is hostile or broken.
const maxPeerResponse = 1 << 20

func (h *httpClient) Identity(ctx context.Context, homeURL string) (Identity, error) {
	var out Identity
	if err := h.getJSON(ctx, homeURL+"/api/federation/identity", &out); err != nil {
		return Identity{}, err
	}
	return out, nil
}

func (h *httpClient) Accept(ctx context.Context, homeURL string, req AcceptRequest) (AcceptResponse, error) {
	var out AcceptResponse
	if err := h.postJSON(ctx, homeURL+"/api/federation/accept", req, &out); err != nil {
		return AcceptResponse{}, err
	}
	return out, nil
}

func (h *httpClient) SyncChallenge(ctx context.Context, homeURL string, vaultID uuid.UUID, peerURL string) (string, error) {
	var out struct {
		Nonce string `json:"nonce"`
	}
	req := map[string]string{"vault_id": vaultID.String(), "peer_url": peerURL}
	if err := h.postJSON(ctx, homeURL+"/api/federation/sync-challenge", req, &out); err != nil {
		return "", err
	}
	if out.Nonce == "" {
		return "", fmt.Errorf("federation: home returned empty nonce")
	}
	return out.Nonce, nil
}

// defaultDialer opens the relay WebSocket via fasthttp/websocket (the same
// stack the server side uses).
func defaultDialer(ctx context.Context, wsURL string) (wsConn, error) {
	d := &fws.Dialer{HandshakeTimeout: 15 * time.Second}
	conn, resp, err := d.DialContext(ctx, wsURL, nil)
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func (h *httpClient) getJSON(ctx context.Context, url string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	return h.do(req, out)
}

func (h *httpClient) postJSON(ctx context.Context, url string, body, out any) error {
	payload, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	return h.do(req, out)
}

func (h *httpClient) do(req *http.Request, out any) error {
	resp, err := h.c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxPeerResponse))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("peer answered %d: %s", resp.StatusCode, truncate(string(body), 200))
	}
	return json.Unmarshal(body, out)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func marshalPayload(payload map[string]any) ([]byte, error) {
	return json.Marshal(payload)
}
