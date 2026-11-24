package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"

	"github.com/ViniZap4/lumi-server/internal/domain"
)

// memLinks is an in-memory DeviceLinkStore over memSessions, mirroring
// the pg store's contract (issuer liveness on consume, link groups).
type memLinks struct {
	mu       sync.Mutex
	sessions *memSessions
	codes    map[string]LinkCode
	groups   map[string]uuid.UUID // SessionRef -> group
}

func newMemLinks(s *memSessions) *memLinks {
	return &memLinks{sessions: s, codes: map[string]LinkCode{}, groups: map[string]uuid.UUID{}}
}

func (m *memLinks) liveSession(ref string, uid uuid.UUID) bool {
	m.sessions.mu.Lock()
	defer m.sessions.mu.Unlock()
	for tok, s := range m.sessions.m {
		if SessionRef(tok) == ref && s.UserID == uid && s.ExpiresAt.After(time.Now()) {
			return true
		}
	}
	return false
}

func (m *memLinks) CreateLinkCode(_ context.Context, c LinkCode) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.codes[c.CodeHash] = c
	return nil
}

func (m *memLinks) ConsumeLinkCode(_ context.Context, h string) (LinkCode, error) {
	m.mu.Lock()
	c, ok := m.codes[h]
	delete(m.codes, h)
	m.mu.Unlock()
	if !ok || !m.liveSession(c.Issuer, c.UserID) {
		return LinkCode{}, domain.ErrNotFound
	}
	return c, nil
}

func (m *memLinks) LinkSessions(_ context.Context, issuer, newToken string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	g, ok := m.groups[issuer]
	if !ok {
		g = uuid.New()
		m.groups[issuer] = g
	}
	m.groups[SessionRef(newToken)] = g
	return nil
}

func (m *memLinks) DeleteLinkedSessions(_ context.Context, uid uuid.UUID, token string) (int, error) {
	m.mu.Lock()
	g, ok := m.groups[SessionRef(token)]
	m.mu.Unlock()
	if !ok {
		return 0, nil
	}
	m.sessions.mu.Lock()
	defer m.sessions.mu.Unlock()
	n := 0
	for tok, s := range m.sessions.m {
		if tok == token || s.UserID != uid {
			continue
		}
		m.mu.Lock()
		same := m.groups[SessionRef(tok)] == g
		m.mu.Unlock()
		if same {
			delete(m.sessions.m, tok)
			n++
		}
	}
	return n, nil
}

const (
	rfcVerifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	rfcChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
)

func newLinkService(t *testing.T) (*Service, *memSessions, *memLinks, *recAudit, *domain.User) {
	t.Helper()
	svc, _, sess, u := newLockoutService(t)
	links := newMemLinks(sess)
	svc.SetDeviceLinkStore(links)
	audit := &recAudit{}
	svc.audit = audit
	return svc, sess, links, audit, u
}

func login(t *testing.T, svc *Service) domain.Session {
	t.Helper()
	s, err := svc.Login(context.Background(), LoginInput{Username: "alice", Password: "correct horse 9", IP: "198.51.100.1"})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestPKCEChallengeRFC7636(t *testing.T) {
	if got := PKCEChallenge(rfcVerifier); got != rfcChallenge {
		t.Fatalf("challenge = %s", got)
	}
}

func TestDeviceLinkIssueRedeem(t *testing.T) {
	svc, sess, _, audit, u := newLinkService(t)
	ctx := context.Background()
	issuer := login(t, svc)

	code, exp, err := svc.IssueDeviceLink(ctx, issuer, rfcChallenge, "Lumi.app")
	if err != nil {
		t.Fatal(err)
	}
	if len(code) != 64 || time.Until(exp) > DeviceLinkTTL || time.Until(exp) < DeviceLinkTTL-5*time.Second {
		t.Fatalf("code=%q exp=%v", code, exp)
	}
	got, err := svc.RedeemDeviceLink(ctx, code, rfcVerifier, "lumi TUI", "198.51.100.2", "test")
	if err != nil {
		t.Fatal(err)
	}
	if got.UserID != u.ID || got.Token == issuer.Token || got.Token == "" {
		t.Fatalf("redeemed session %+v", got)
	}
	if _, ok := sess.m[got.Token]; !ok {
		t.Fatal("new session not persisted")
	}
	e, p := audit.last(t)
	if e.Action != ActionDeviceLinkRedeem || p["label"] != "lumi TUI" || p["issuer_label"] != "Lumi.app" {
		t.Fatalf("audit %+v %v", e, p)
	}
	raw, _ := json.Marshal(audit.entries)
	if bytes.Contains(raw, []byte(code)) || bytes.Contains(raw, []byte(got.Token)) || bytes.Contains(raw, []byte(issuer.Token)) {
		t.Fatal("audit leaked a secret")
	}

	// Single use.
	if _, err := svc.RedeemDeviceLink(ctx, code, rfcVerifier, "", "198.51.100.2", ""); !errors.Is(err, ErrInvalidLink) {
		t.Fatalf("reuse: %v", err)
	}
}

func TestDeviceLinkWrongVerifierBurnsCode(t *testing.T) {
	svc, _, _, _, _ := newLinkService(t)
	ctx := context.Background()
	issuer := login(t, svc)
	code, _, err := svc.IssueDeviceLink(ctx, issuer, rfcChallenge, "")
	if err != nil {
		t.Fatal(err)
	}
	wrong := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	if _, err := svc.RedeemDeviceLink(ctx, code, wrong, "", "ip", ""); !errors.Is(err, ErrInvalidLink) {
		t.Fatalf("wrong verifier: %v", err)
	}
	if _, err := svc.RedeemDeviceLink(ctx, code, rfcVerifier, "", "ip", ""); !errors.Is(err, ErrInvalidLink) {
		t.Fatalf("code survived a failed attempt: %v", err)
	}
}

func TestDeviceLinkExpiredAndIssuerEnded(t *testing.T) {
	svc, _, links, _, _ := newLinkService(t)
	ctx := context.Background()
	issuer := login(t, svc)

	code, _, _ := svc.IssueDeviceLink(ctx, issuer, rfcChallenge, "")
	h := HashLinkCode(code)
	c := links.codes[h]
	c.ExpiresAt = time.Now().Add(-time.Second)
	links.codes[h] = c
	if _, err := svc.RedeemDeviceLink(ctx, code, rfcVerifier, "", "ip", ""); !errors.Is(err, ErrInvalidLink) {
		t.Fatalf("expired: %v", err)
	}

	code2, _, _ := svc.IssueDeviceLink(ctx, issuer, rfcChallenge, "")
	if err := svc.Logout(ctx, issuer.Token); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.RedeemDeviceLink(ctx, code2, rfcVerifier, "", "ip", ""); !errors.Is(err, ErrInvalidLink) {
		t.Fatalf("issuer logged out: %v", err)
	}
}

func TestDeviceLinkValidation(t *testing.T) {
	svc, _, _, _, _ := newLinkService(t)
	ctx := context.Background()
	issuer := login(t, svc)
	for _, ch := range []string{"", "short", rfcChallenge + "x", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw+cM"} {
		if _, _, err := svc.IssueDeviceLink(ctx, issuer, ch, ""); !errors.Is(err, domain.ErrValidation) {
			t.Fatalf("challenge %q: %v", ch, err)
		}
	}
	if _, err := svc.RedeemDeviceLink(ctx, "", rfcVerifier, "", "ip", ""); !errors.Is(err, ErrInvalidLink) {
		t.Fatal(err)
	}
	if _, err := svc.RedeemDeviceLink(ctx, "abc", "short", "", "ip", ""); !errors.Is(err, ErrInvalidLink) {
		t.Fatal(err)
	}
	if cleanLabel("a\x00b\nc") != "abc" || len([]rune(cleanLabel(string(bytes.Repeat([]byte("é"), 200))))) != maxLinkLabel {
		t.Fatal("cleanLabel")
	}
}

func TestDeviceLinkIssueRateLimited(t *testing.T) {
	svc, _, _, _, _ := newLinkService(t)
	ctx := context.Background()
	issuer := login(t, svc)
	var err error
	for i := 0; i < 11; i++ {
		_, _, err = svc.IssueDeviceLink(ctx, issuer, rfcChallenge, "")
	}
	if !errors.Is(err, domain.ErrRateLimited) {
		t.Fatalf("11th issue: %v", err)
	}
}

func TestDeviceLinksDisabledWithoutStore(t *testing.T) {
	svc, _, _, u := newLockoutService(t)
	_, _, err := svc.IssueDeviceLink(context.Background(), domain.Session{Token: "t", UserID: u.ID}, rfcChallenge, "")
	if !errors.Is(err, ErrDeviceLinksDisabled) {
		t.Fatal(err)
	}
}

func TestLogoutDeviceEndsOnlyTheLinkGroup(t *testing.T) {
	svc, sess, _, _, _ := newLinkService(t)
	ctx := context.Background()
	app := login(t, svc)   // "Lumi.app", password
	other := login(t, svc) // another machine, password — not linked
	code, _, _ := svc.IssueDeviceLink(ctx, app, rfcChallenge, "Lumi.app")
	tui, err := svc.RedeemDeviceLink(ctx, code, rfcVerifier, "lumi TUI", "ip", "")
	if err != nil {
		t.Fatal(err)
	}

	// Sign out on this Mac from the TUI side ends the app session too.
	n, err := svc.LogoutDevice(ctx, tui.Token)
	if err != nil || n != 2 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	for _, tok := range []string{app.Token, tui.Token} {
		if _, ok := sess.m[tok]; ok {
			t.Fatal("linked session survived")
		}
	}
	if _, ok := sess.m[other.Token]; !ok {
		t.Fatal("unlinked session of the same user was revoked")
	}

	// An unlinked session: scope=device behaves like plain logout.
	if n, err := svc.LogoutDevice(ctx, other.Token); err != nil || n != 1 {
		t.Fatalf("unlinked n=%d err=%v", n, err)
	}
}

// --- HTTP ---------------------------------------------------------------

func linkApp(t *testing.T, svc *Service) *fiber.App {
	t.Helper()
	app := fiber.New()
	NewHandlers(svc).Register(app)
	return app
}

func doJSON(t *testing.T, app *fiber.App, method, path, token string, body any) (int, map[string]any) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, rd)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set(HeaderToken, token)
	}
	resp, err := app.Test(req, -1)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	out := map[string]any{}
	_ = json.Unmarshal(raw, &out)
	if resp.StatusCode == http.StatusCreated || resp.StatusCode == http.StatusOK {
		if cc := resp.Header.Get("Cache-Control"); path != "/api/users/me" && cc != "no-store" {
			t.Fatalf("%s: Cache-Control=%q", path, cc)
		}
	}
	return resp.StatusCode, out
}

func TestDeviceLinkHTTP(t *testing.T) {
	svc, sess, _, _, _ := newLinkService(t)
	app := linkApp(t, svc)
	issuer := login(t, svc)

	if st, _ := doJSON(t, app, "POST", "/api/auth/device-links", "", map[string]string{"challenge": rfcChallenge}); st != 401 {
		t.Fatalf("unauthenticated issue: %d", st)
	}
	st, out := doJSON(t, app, "POST", "/api/auth/device-links", issuer.Token, map[string]string{"challenge": rfcChallenge, "label": "Lumi.app"})
	if st != 201 {
		t.Fatalf("issue: %d %v", st, out)
	}
	code, _ := out["code"].(string)
	if code == "" || out["expires_at"] == nil {
		t.Fatalf("issue body %v", out)
	}
	st, out = doJSON(t, app, "POST", "/api/auth/device-links/redeem", "", map[string]string{"code": code, "verifier": rfcVerifier, "label": "lumi TUI"})
	if st != 200 {
		t.Fatalf("redeem: %d %v", st, out)
	}
	tok, _ := out["token"].(string)
	user, _ := out["user"].(map[string]any)
	if tok == "" || user["username"] != "alice" {
		t.Fatalf("redeem body %v", out)
	}
	if st, out := doJSON(t, app, "POST", "/api/auth/device-links/redeem", "", map[string]string{"code": code, "verifier": rfcVerifier}); st != 401 || out["error"] != "invalid_link" {
		t.Fatalf("reuse: %d %v", st, out)
	}
	if st, _ := doJSON(t, app, "POST", "/api/auth/device-links", issuer.Token, map[string]string{"challenge": "nope"}); st != 400 {
		t.Fatalf("bad challenge: %d", st)
	}

	// Logout scope validation, then scope=device revokes both.
	if st, _ := doJSON(t, app, "POST", "/api/auth/logout", tok, map[string]string{"scope": "everything"}); st != 400 {
		t.Fatalf("bad scope: %d", st)
	}
	if st, _ := doJSON(t, app, "POST", "/api/auth/logout", tok, map[string]string{"scope": "device"}); st != 204 {
		t.Fatalf("logout device: %d", st)
	}
	if _, ok := sess.m[issuer.Token]; ok {
		t.Fatal("issuer survived logout scope=device")
	}
}

func TestLogoutWithoutBodyUnchanged(t *testing.T) {
	svc, sess, _, _, _ := newLinkService(t)
	app := linkApp(t, svc)
	a := login(t, svc)
	code, _, _ := svc.IssueDeviceLink(context.Background(), a, rfcChallenge, "")
	b, err := svc.RedeemDeviceLink(context.Background(), code, rfcVerifier, "", "ip", "")
	if err != nil {
		t.Fatal(err)
	}
	if st, _ := doJSON(t, app, "POST", "/api/auth/logout", b.Token, nil); st != 204 {
		t.Fatalf("logout: %d", st)
	}
	if _, ok := sess.m[b.Token]; ok {
		t.Fatal("caller not logged out")
	}
	if _, ok := sess.m[a.Token]; !ok {
		t.Fatal("plain logout ended a linked session")
	}
}
