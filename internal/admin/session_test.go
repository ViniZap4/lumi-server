package admin

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ViniZap4/lumi-server/internal/auth"
	"github.com/ViniZap4/lumi-server/internal/domain"
)

// fakeLogin plays auth.Service.AdminLogin: the right password of a
// server admin passes; everything else is the one generic refusal.
type fakeLogin struct {
	mu        sync.Mutex
	store     *fakeStore
	passwords map[string]string
	limited   bool
	calls     []auth.LoginInput
}

func (l *fakeLogin) AdminLogin(_ context.Context, in auth.LoginInput) (domain.User, error) {
	l.mu.Lock()
	l.calls = append(l.calls, in)
	limited := l.limited
	l.mu.Unlock()
	if limited {
		return domain.User{}, domain.ErrRateLimited
	}
	u, err := l.store.GetUserByUsername(context.Background(), strings.ToLower(in.Username))
	if err != nil || l.passwords[u.Username] != in.Password || !u.ServerAdmin || u.DisabledAt != nil {
		return domain.User{}, domain.ErrInvalidCredentials
	}
	return domain.User{ID: u.ID, Username: u.Username, ServerAdmin: true}, nil
}

func newSessionHarness(t *testing.T) (*harness, *fakeLogin, *User) {
	t.Helper()
	h := newHarness(t)
	alice := h.addUser("alice")
	alice.ServerAdmin = true
	h.addUser("bob") // not a server admin
	login := &fakeLogin{store: h.store, passwords: map[string]string{"alice": "correct horse 9", "bob": "bob password 1"}}
	h.svc.Login = login
	return h, login, alice
}

func (h *harness) login(t *testing.T, user, pw string, hdr ...string) resp {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"username": user, "password": pw})
	return h.do(t, "POST", "/admin/v1/session", "", string(body), hdr...)
}

func TestSessionLogin_Success(t *testing.T) {
	h, login, alice := newSessionHarness(t)
	r := h.login(t, "alice", "correct horse 9", "User-Agent", "panel-browser/1")
	if r.status != 201 {
		t.Fatalf("login: %d %s", r.status, r.body)
	}
	m := r.json(t)
	tok, _ := m["token"].(string)
	if !strings.HasPrefix(tok, SessionPrefix) || len(tok) != tokenLen || m["kind"] != "session" {
		t.Fatalf("response %v", m)
	}
	if u, _ := m["user"].(map[string]any); u["username"] != "alice" || u["id"] != alice.ID.String() {
		t.Fatalf("user %v", m["user"])
	}
	exp, err := time.Parse(time.RFC3339Nano, m["expires_at"].(string))
	if err != nil || time.Until(exp) > SessionTTL || time.Until(exp) < SessionTTL-time.Minute {
		t.Fatalf("expires_at %v (%v)", m["expires_at"], err)
	}
	if r.header.Get("Cache-Control") != "no-store" {
		t.Fatal("login response must not be cached")
	}
	if login.calls[0].UserAgent != "panel-browser/1" || login.calls[0].IP == "" {
		t.Fatalf("login input %+v", login.calls[0])
	}

	// Stored hashed, audited with the user and the session as actor.
	id := uuid.MustParse(m["id"].(string))
	if d := h.store.digests[id]; string(d) != string(Digest(tok)) {
		t.Fatal("session not stored as its digest")
	}
	a := h.store.lastAudit()
	var p map[string]any
	_ = json.Unmarshal(a.Payload, &p)
	if a.Action != ActionSessionCreate || a.UserID == nil || *a.UserID != alice.ID || p["token_id"] != id.String() ||
		p["token_name"] != "session" || p["username"] != "alice" || a.UserAgent == nil {
		t.Fatalf("audit %s %+v %s", a.Action, a, a.Payload)
	}
	if strings.Contains(string(a.Payload), tok) {
		t.Fatal("token in the audit payload")
	}

	// The session works on every route and reports who is signed in.
	st := h.do(t, "GET", "/admin/v1/status", tok, "")
	if st.status != 200 {
		t.Fatalf("status with session: %d %s", st.status, st.body)
	}
	ref := st.json(t)["token"].(map[string]any)
	if ref["kind"] != "session" || ref["user"].(map[string]any)["username"] != "alice" {
		t.Fatalf("status token %v", ref)
	}
	// Listed with the tokens, with its kind and user.
	list := h.do(t, "GET", "/admin/v1/tokens", tok, "").json(t)["items"].([]any)
	var seen bool
	for _, it := range list {
		x := it.(map[string]any)
		if x["id"] == id.String() {
			seen = x["kind"] == "session" && x["current"] == true && x["user"].(map[string]any)["username"] == "alice"
		} else if x["kind"] != "token" || x["user"] != nil {
			t.Fatalf("lpa token rendered as %v", x)
		}
	}
	if !seen {
		t.Fatalf("session missing from /tokens: %v", list)
	}
	// Admin actions done with it name the session as the actor.
	h.do(t, "POST", "/admin/v1/users/"+alice.ID.String()+"/unlock", tok, "")
	_ = json.Unmarshal(h.store.lastAudit().Payload, &p)
	if p["token_id"] != id.String() || p["token_name"] != "session" {
		t.Fatalf("actor %v", p)
	}
}

func TestSessionLogin_GenericRefusalsAndRateLimit(t *testing.T) {
	h, login, _ := newSessionHarness(t) // failure budget: 3, refill 1/hour
	for _, c := range [][2]string{{"nobody", "x"}, {"alice", "wrong"}, {"bob", "bob password 1"}} {
		r := h.login(t, c[0], c[1])
		if r.status != 401 || r.body != `{"error":"invalid_credentials"}` {
			t.Fatalf("%s: %d %s", c[0], r.status, r.body)
		}
	}
	// Budget spent: refused before the password is even checked.
	n := len(login.calls)
	r := h.login(t, "alice", "correct horse 9")
	if r.status != 429 || r.header.Get("Retry-After") == "" || r.json(t)["error"] != "rate_limited" {
		t.Fatalf("over budget: %d %s", r.status, r.body)
	}
	if len(login.calls) != n {
		t.Fatal("throttled attempt still reached the password check")
	}
	// The per-IP budget is per address (X-Forwarded-For is not trusted
	// without LUMI_ADMIN_TRUSTED_PROXIES, so it cannot be used to dodge).
	if r := h.login(t, "alice", "correct horse 9", "X-Forwarded-For", "198.51.100.9"); r.status != 429 {
		t.Fatalf("spoofed XFF: %d", r.status)
	}
	// Valid lpa_ tokens are unaffected.
	if r := h.do(t, "GET", "/admin/v1/status", h.token, ""); r.status != 200 {
		t.Fatalf("token from throttled ip: %d", r.status)
	}
}

func TestSessionLogin_LoginRateLimitAndBadBodies(t *testing.T) {
	h, login, _ := newSessionHarness(t)
	login.limited = true
	if r := h.login(t, "alice", "correct horse 9"); r.status != 429 || r.header.Get("Retry-After") == "" {
		t.Fatalf("login limiter: %d %s", r.status, r.body)
	}
	login.limited = false
	for _, body := range []string{"", "{", `{"username":"alice","password":"x","extra":1}`, `{"username":"alice"} {}`} {
		if r := h.do(t, "POST", "/admin/v1/session", "", body); r.status != 400 {
			t.Errorf("body %q: %d %s", body, r.status, r.body)
		}
	}
	h.svc.Login = nil
	if r := h.login(t, "alice", "correct horse 9"); r.status != 404 {
		t.Fatalf("login not configured: %d", r.status)
	}
}

func TestSessionLogout_AndEndsWithTheAccount(t *testing.T) {
	h, _, alice := newSessionHarness(t)
	h.api.Limiter = NewFailureLimiter(100, time.Hour, 100) // 401s below spend it
	tok := h.login(t, "alice", "correct horse 9").json(t)["token"].(string)

	// An lpa_ token cannot "log out": it is revoked by id.
	if r := h.do(t, "DELETE", "/admin/v1/session", h.token, ""); r.status != 409 {
		t.Fatalf("logout with lpa_: %d %s", r.status, r.body)
	}
	if r := h.do(t, "DELETE", "/admin/v1/session", tok, ""); r.status != 204 {
		t.Fatalf("logout: %d %s", r.status, r.body)
	}
	if a := h.store.lastAudit(); a.Action != ActionSessionLogout || a.UserID == nil || *a.UserID != alice.ID {
		t.Fatalf("logout audit %+v", a)
	}
	if r := h.do(t, "GET", "/admin/v1/status", tok, ""); r.status != 401 {
		t.Fatalf("after logout: %d", r.status)
	}

	// Disabling the account or clearing its flag ends a live session at
	// its next call, even before the stored row is revoked.
	for name, breakIt := range map[string]func(){
		"disabled":         func() { now := time.Now(); alice.DisabledAt = &now },
		"not server admin": func() { alice.ServerAdmin = false },
		"expired": func() {
			for _, x := range h.store.tokens {
				if x.IsSession() {
					x.ExpiresAt = time.Now().Add(-time.Second)
				}
			}
		},
	} {
		alice.DisabledAt, alice.ServerAdmin = nil, true
		tok := h.login(t, "alice", "correct horse 9").json(t)["token"].(string)
		breakIt()
		if r := h.do(t, "GET", "/admin/v1/status", tok, ""); r.status != 401 {
			t.Errorf("%s: %d", name, r.status)
		}
	}
}

func TestServerAdminFlagRoute(t *testing.T) {
	h, _, alice := newSessionHarness(t)
	h.api.Limiter = NewFailureLimiter(100, time.Hour, 100)
	bob, _ := h.store.GetUserByUsername(context.Background(), "bob")
	path := func(id uuid.UUID) string { return "/admin/v1/users/" + id.String() + "/server-admin" }

	if r := h.do(t, "POST", path(bob.ID), h.token, `{}`); r.status != 400 || r.json(t)["field"] != "enabled" {
		t.Fatalf("missing enabled: %d %s", r.status, r.body)
	}
	if r := h.do(t, "POST", path(uuid.New()), h.token, `{"enabled":true}`); r.status != 404 {
		t.Fatalf("unknown user: %d", r.status)
	}
	// Alice is the only server admin: removing her flag is refused.
	r := h.do(t, "POST", path(alice.ID), h.token, `{"enabled":false}`)
	if r.status != 409 || r.json(t)["detail"] != "last_server_admin" || !alice.ServerAdmin {
		t.Fatalf("last admin: %d %s", r.status, r.body)
	}
	if r := h.do(t, "POST", path(bob.ID), h.token, `{"enabled":true}`); r.status != 204 {
		t.Fatalf("grant: %d %s", r.status, r.body)
	}
	a := checkAdminAudit(t, h, ActionUserServerAdmin, &bob.ID)
	if !strings.Contains(string(a.Payload), `"enabled":true`) {
		t.Fatalf("payload %s", a.Payload)
	}
	if u := h.do(t, "GET", "/admin/v1/users/"+bob.ID.String(), h.token, "").json(t); u["server_admin"] != true {
		t.Fatalf("user json %v", u)
	}
	if l := h.do(t, "GET", "/admin/v1/users?server_admin=true", h.token, "").json(t)["items"].([]any); len(l) != 2 {
		t.Fatalf("server_admin filter: %v", l)
	}

	// Now alice may drop her own flag from her own session; the session
	// ends with it.
	tok := h.login(t, "alice", "correct horse 9").json(t)["token"].(string)
	if r := h.do(t, "POST", path(alice.ID), tok, `{"enabled":false}`); r.status != 204 {
		t.Fatalf("self revoke: %d %s", r.status, r.body)
	}
	if r := h.do(t, "GET", "/admin/v1/status", tok, ""); r.status != 401 {
		t.Fatalf("session after losing the flag: %d", r.status)
	}
	for _, x := range h.store.tokens {
		if x.IsSession() && x.RevokedAt == nil {
			t.Fatal("admin session not revoked with the flag")
		}
	}
	// Bob is now the last one.
	if r := h.do(t, "POST", path(bob.ID), h.token, `{"enabled":false}`); r.status != 409 {
		t.Fatalf("bob last admin: %d", r.status)
	}
}

func TestCredentialParsing(t *testing.T) {
	tok, digest := NewSessionToken()
	d, kind, err := ParseCredential(tok)
	if err != nil || kind != KindSession || string(d) != string(digest) {
		t.Fatalf("session: %v %s", err, kind)
	}
	if _, err := ParseToken(tok); err == nil {
		t.Fatal("ParseToken accepted an lps_ session")
	}
	lpa, _ := NewToken()
	if _, kind, err := ParseCredential(lpa); err != nil || kind != KindToken {
		t.Fatalf("token: %v %s", err, kind)
	}
	for _, bad := range []string{"lpx_" + tok[4:], tok + "A", strings.Repeat("ab", 32)} {
		if _, _, err := ParseCredential(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}
