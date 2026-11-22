package wsync

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	fws "github.com/fasthttp/websocket"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"

	"github.com/ViniZap4/lumi-server/internal/crdt"
	"github.com/ViniZap4/lumi-server/internal/domain"
)

type stubResolver map[uuid.UUID]domain.CapabilitySet

var stubMu sync.Mutex

func (s stubResolver) set(user uuid.UUID, caps domain.CapabilitySet) {
	stubMu.Lock()
	defer stubMu.Unlock()
	s[user] = caps
}

func (s stubResolver) RoleForUser(_ context.Context, _ uuid.UUID, user uuid.UUID) (domain.Role, error) {
	stubMu.Lock()
	defer stubMu.Unlock()
	caps, ok := s[user]
	if !ok {
		return domain.Role{}, domain.ErrNotFound
	}
	return domain.Role{Capabilities: caps}, nil
}

func startSyncServer(t *testing.T, tokens map[string]uuid.UUID, res stubResolver, notes map[string]bool) string {
	t.Helper()
	reg := crdt.NewRegistry(newMemRepo())
	hub := NewHub(reg)
	t.Cleanup(hub.Close)
	authn := func(_ context.Context, tok string) (uuid.UUID, error) {
		if tok == "expired" {
			return uuid.Nil, domain.ErrTokenExpired
		}
		if uid, ok := tokens[tok]; ok {
			return uid, nil
		}
		return uuid.Nil, domain.ErrTokenInvalid
	}
	exists := func(_ context.Context, _ uuid.UUID, id string) error {
		if notes[id] {
			return nil
		}
		return domain.ErrNotFound
	}
	app := fiber.New(fiber.Config{DisableStartupMessage: true})
	NewHandler(hub, res, nil, authn, exists).Register(app.Group("/api"))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = app.Listener(ln) }()
	t.Cleanup(func() { _ = app.Shutdown() })
	return "ws://" + ln.Addr().String()
}

// dial returns the close code the server ends the session with, or 0 if
// the first frame is a SyncStep1 (session accepted).
func dial(t *testing.T, base, vault, note, token string) int {
	t.Helper()
	url := base + "/api/vaults/" + vault + "/notes/" + note + "/sync"
	if token != "" {
		url += "?token=" + token
	}
	d := fws.Dialer{HandshakeTimeout: 2 * time.Second}
	conn, resp, err := d.Dial(url, nil)
	if err != nil {
		code := 0
		if resp != nil {
			code = resp.StatusCode
		}
		t.Fatalf("dial failed (HTTP %d): %v — upgrade must complete so the client sees a close code", code, err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, msg, err := conn.ReadMessage()
	if err != nil {
		var ce *fws.CloseError
		if errors.As(err, &ce) {
			return ce.Code
		}
		t.Fatalf("read: %v", err)
	}
	m, derr := DecodeMessage(msg)
	if derr != nil || m.Type != MessageSync || m.SyncSub != SyncStep1 {
		t.Fatalf("first frame %+v (%v), want SyncStep1", m, derr)
	}
	return 0
}

// S6: auth/permission/not-found failures complete the upgrade and close
// with 4401/4403/4404 instead of an HTTP error the browser sees as 1006.
func TestSyncUpgradeCloseCodes(t *testing.T) {
	editor, viewer := uuid.New(), uuid.New()
	base := startSyncServer(t,
		map[string]uuid.UUID{"ed": editor, "vw": viewer, "stranger": uuid.New()},
		stubResolver{editor: {domain.CapNoteEdit}, viewer: {domain.CapNoteRead}},
		map[string]bool{"n1": true})
	vault := uuid.NewString()

	cases := []struct {
		name, vault, note, token string
		want                     int
	}{
		{"accepted", vault, "n1", "ed", 0},
		{"no token", vault, "n1", "", CloseUnauthorized},
		{"bad token", vault, "n1", "nope", CloseUnauthorized},
		{"expired token", vault, "n1", "expired", CloseUnauthorized},
		{"viewer lacks note.edit", vault, "n1", "vw", CloseForbidden},
		{"non-member", vault, "n1", "stranger", CloseForbidden},
		{"unknown note", vault, "missing", "ed", CloseNotFound},
		{"bad vault id", "not-a-uuid", "n1", "ed", CloseNotFound},
		{"bad vault id, no token", "not-a-uuid", "n1", "", CloseUnauthorized},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := dial(t, base, tc.vault, tc.note, tc.token); got != tc.want {
				t.Fatalf("close code = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestSyncRouteRejectsPlainHTTP(t *testing.T) {
	base := startSyncServer(t, nil, stubResolver{}, nil)
	resp, err := http.Get("http" + base[2:] + "/api/vaults/" + uuid.NewString() + "/notes/n/sync")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUpgradeRequired {
		t.Fatalf("status %d, want 426", resp.StatusCode)
	}
}

// A capability revoked mid-session closes the socket with 4403.
func TestSyncRevalidationClosesRevokedSession(t *testing.T) {
	RevalidateInterval = 50 * time.Millisecond // test binary only

	editor := uuid.New()
	res := stubResolver{editor: {domain.CapNoteEdit}}
	base := startSyncServer(t, map[string]uuid.UUID{"ed": editor}, res, map[string]bool{"n1": true})
	conn, _, err := (&fws.Dialer{}).Dial(base+"/api/vaults/"+uuid.NewString()+"/notes/n1/sync?token=ed", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, _, _ = conn.ReadMessage() // SyncStep1
	res.set(editor, domain.CapabilitySet{domain.CapNoteRead})
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	for {
		_, _, err := conn.ReadMessage()
		if err == nil {
			continue
		}
		var ce *fws.CloseError
		if !errors.As(err, &ce) || ce.Code != CloseForbidden {
			t.Fatalf("got %v, want close %d", err, CloseForbidden)
		}
		return
	}
}
