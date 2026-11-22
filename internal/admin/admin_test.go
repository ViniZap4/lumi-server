package admin

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ViniZap4/lumi-server/internal/domain"
)

// ---- tokens -------------------------------------------------------------------------

func TestTokenFormat(t *testing.T) {
	raw, digest := NewToken()
	if !strings.HasPrefix(raw, "lpa_") || len(raw) != 4+43 {
		t.Fatalf("token %q: want lpa_ + 43 base64url chars", raw)
	}
	got, err := ParseToken(raw)
	if err != nil || string(got) != string(digest) || len(digest) != 32 {
		t.Fatalf("ParseToken: %v", err)
	}
	other, _ := NewToken()
	if other == raw {
		t.Fatal("two tokens are equal")
	}
	bad := []string{
		"", "lpa_", raw[:len(raw)-1], raw + "A",
		"lps_" + raw[4:],                       // wrong prefix
		strings.Repeat("a", 64),                // a session token (hex)
		"lpa_" + strings.Repeat("!", 43),       // not base64url
		"lpa_" + strings.Repeat("A", 42) + "B", // non-canonical trailing bits
		"Bearer " + raw,
	}
	for _, b := range bad {
		if _, err := ParseToken(b); err == nil {
			t.Errorf("ParseToken(%q) accepted", b)
		}
	}
}

func TestTokenLifecycle(t *testing.T) {
	f := newFixture()
	ctx := context.Background()
	now := time.Now()
	f.svc.now = func() time.Time { return now }

	for _, ttl := range []time.Duration{0, time.Second, MaxTokenTTL + time.Hour} {
		if _, _, err := f.svc.CreateToken(ctx, CLI, "panel", ttl); !isInvalid(err, "ttl") {
			t.Errorf("ttl %s: want invalid ttl, got %v", ttl, err)
		}
	}
	for _, name := range []string{"", "   ", strings.Repeat("x", 65), "a\nb"} {
		if _, _, err := f.svc.CreateToken(ctx, CLI, name, DefaultTokenTTL); !isInvalid(err, "name") {
			t.Errorf("name %q: want invalid name, got %v", name, err)
		}
	}

	raw, tok, err := f.svc.CreateToken(ctx, CLI, " panel ", DefaultTokenTTL)
	if err != nil {
		t.Fatal(err)
	}
	if tok.Name != "panel" || !tok.ExpiresAt.Equal(now.UTC().Add(30*24*time.Hour)) {
		t.Fatalf("token %+v", tok)
	}
	if a := f.store.lastAudit(); a.Action != ActionTokenCreate || !strings.Contains(string(a.Payload), `"token_name":"cli"`) {
		t.Fatalf("create audit %s %s", a.Action, a.Payload)
	}
	if strings.Contains(string(f.store.lastAudit().Payload), raw) {
		t.Fatal("audit payload holds the token value")
	}

	got, err := f.svc.Authenticate(ctx, raw)
	if err != nil || got.ID != tok.ID {
		t.Fatalf("Authenticate: %v", err)
	}
	// last_used_at is written at most once per TouchInterval.
	for i := 0; i < 3; i++ {
		if _, err := f.svc.Authenticate(ctx, raw); err != nil {
			t.Fatal(err)
		}
	}
	if f.store.touches != 1 {
		t.Fatalf("touches = %d, want 1", f.store.touches)
	}
	now = now.Add(TouchInterval)
	_, _ = f.svc.Authenticate(ctx, raw)
	if f.store.touches != 2 {
		t.Fatalf("touches = %d after interval, want 2", f.store.touches)
	}

	// Unknown and malformed tokens.
	other, _ := NewToken()
	for _, r := range []string{other, "nope", ""} {
		if _, err := f.svc.Authenticate(ctx, r); !errors.Is(err, domain.ErrUnauthorized) {
			t.Errorf("Authenticate(%q) = %v", r, err)
		}
	}

	// Expiry.
	now = tok.ExpiresAt
	if _, err := f.svc.Authenticate(ctx, raw); !errors.Is(err, domain.ErrUnauthorized) {
		t.Fatalf("expired token: %v", err)
	}
	now = tok.ExpiresAt.Add(-time.Hour)

	// Revocation, idempotent and audited each time.
	if err := f.svc.RevokeToken(ctx, CLI, tok.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Authenticate(ctx, raw); !errors.Is(err, domain.ErrUnauthorized) {
		t.Fatalf("revoked token: %v", err)
	}
	n := f.store.auditCount()
	if err := f.svc.RevokeToken(ctx, CLI, tok.ID); err != nil || f.store.auditCount() != n+1 {
		t.Fatalf("second revoke: %v", err)
	}
	if err := f.svc.RevokeToken(ctx, CLI, uuid.New()); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("revoke unknown: %v", err)
	}
}

func isInvalid(err error, field string) bool {
	var ie *InvalidError
	return errors.As(err, &ie) && ie.Field == field
}

// ---- HTTP harness -------------------------------------------------------------------

type harness struct {
	*fixture
	api   *HTTP
	token string
	tok   Token
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	f := newFixture()
	raw, tok, err := f.svc.CreateToken(context.Background(), CLI, "panel", DefaultTokenTTL)
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{fixture: f, token: raw, tok: tok}
	h.api = &HTTP{Service: f.svc, Limiter: NewFailureLimiter(3, time.Hour, 100)}
	return h
}

type resp struct {
	status int
	header http.Header
	body   string
}

func (h *harness) do(t *testing.T, method, path, token, body string, hdr ...string) resp {
	t.Helper()
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, r)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	res, err := h.api.App().Test(req, -1)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return resp{status: res.StatusCode, header: res.Header, body: string(b)}
}

func (r resp) json(t *testing.T) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(r.body), &m); err != nil {
		t.Fatalf("body %q: %v", r.body, err)
	}
	return m
}

// ---- authentication -----------------------------------------------------------------

func TestUniform401(t *testing.T) {
	h := newHarness(t)
	h.api.Limiter = NewFailureLimiter(100, time.Hour, 100)
	ctx := context.Background()

	expiredRaw, expired, _ := h.svc.CreateToken(ctx, CLI, "old", time.Hour)
	h.store.tokens[expired.ID].ExpiresAt = time.Now().Add(-time.Minute)
	revokedRaw, revoked, _ := h.svc.CreateToken(ctx, CLI, "gone", time.Hour)
	_ = h.svc.RevokeToken(ctx, CLI, revoked.ID)
	unknown, _ := NewToken()

	cases := map[string]string{
		"absent": "", "malformed": "abc", "unknown": unknown, "expired": expiredRaw,
		"revoked": revokedRaw, "session token": strings.Repeat("ab", 32),
	}
	var first *resp
	for name, tok := range cases {
		r := h.do(t, "GET", "/admin/v1/status", tok, "")
		if r.status != 401 || r.body != `{"error":"unauthorized"}` {
			t.Errorf("%s: %d %s", name, r.status, r.body)
		}
		if first == nil {
			first = &r
		} else if r.header.Get("WWW-Authenticate") != first.header.Get("WWW-Authenticate") {
			t.Errorf("%s: header differs", name)
		}
	}
	// Non-Bearer schemes are failures too.
	r := h.do(t, "GET", "/admin/v1/status", "", "", "Authorization", "Basic "+h.token)
	if r.status != 401 {
		t.Fatalf("basic scheme: %d", r.status)
	}
	if r := h.do(t, "GET", "/admin/v1/status", h.token, ""); r.status != 200 {
		t.Fatalf("valid token: %d %s", r.status, r.body)
	}
}

func TestFailureRateLimit(t *testing.T) {
	h := newHarness(t) // burst 3, refill 1/hour
	for i := 0; i < 3; i++ {
		if r := h.do(t, "GET", "/admin/v1/status", "bad", ""); r.status != 401 {
			t.Fatalf("failure %d: %d", i, r.status)
		}
	}
	r := h.do(t, "GET", "/admin/v1/status", "bad", "")
	if r.status != 429 || r.json(t)["error"] != "rate_limited" {
		t.Fatalf("over budget: %d %s", r.status, r.body)
	}
	if ra := r.header.Get("Retry-After"); ra == "" || ra == "0" {
		t.Fatalf("Retry-After %q", ra)
	}
	// A valid token always passes, even from the throttled address.
	if r := h.do(t, "GET", "/admin/v1/status", h.token, ""); r.status != 200 {
		t.Fatalf("valid token from throttled ip: %d", r.status)
	}
}

func TestFailureLimiterRefill(t *testing.T) {
	l := NewFailureLimiter(2, 10*time.Second, 10)
	now := time.Unix(0, 0)
	l.now = func() time.Time { return now }
	l.Allow("a")
	l.Allow("a")
	ok, wait := l.Allow("a")
	if ok || wait != 10*time.Second {
		t.Fatalf("third: %v %s", ok, wait)
	}
	if ok, _ := l.Allow("b"); !ok {
		t.Fatal("other key throttled")
	}
	now = now.Add(4 * time.Second)
	if _, wait := l.Allow("a"); wait != 6*time.Second {
		t.Fatalf("wait %s, want 6s", wait)
	}
	now = now.Add(6 * time.Second)
	if ok, _ := l.Allow("a"); !ok {
		t.Fatal("not refilled")
	}
	// The key table never grows past maxKeys.
	for i := 0; i < 50; i++ {
		l.Allow(uuid.NewString())
	}
	if len(l.buckets) > 10 {
		t.Fatalf("%d buckets", len(l.buckets))
	}
}

func TestEveryRouteRequiresToken(t *testing.T) {
	h := newHarness(t)
	h.api.Limiter = NewFailureLimiter(1000, time.Hour, 100)
	id := uuid.NewString()
	routes := [][2]string{
		{"GET", "/admin/v1/status"},
		{"GET", "/admin/v1/users"}, {"POST", "/admin/v1/users"},
		{"GET", "/admin/v1/users/" + id}, {"DELETE", "/admin/v1/users/" + id},
		{"POST", "/admin/v1/users/" + id + "/password"}, {"POST", "/admin/v1/users/" + id + "/disable"},
		{"POST", "/admin/v1/users/" + id + "/enable"}, {"POST", "/admin/v1/users/" + id + "/unlock"},
		{"GET", "/admin/v1/sessions"}, {"DELETE", "/admin/v1/sessions/" + strings.Repeat("a", 64)},
		{"GET", "/admin/v1/vaults"}, {"GET", "/admin/v1/vaults/" + id}, {"DELETE", "/admin/v1/vaults/" + id},
		{"GET", "/admin/v1/federations"}, {"DELETE", "/admin/v1/federations/" + id},
		{"GET", "/admin/v1/tokens"}, {"DELETE", "/admin/v1/tokens/" + id},
		{"GET", "/admin/v1/audit"},
		{"GET", "/admin/v1/nonexistent"}, {"PUT", "/admin/v1/users"},
	}
	for _, rt := range routes {
		if r := h.do(t, rt[0], rt[1], "", ""); r.status != 401 {
			t.Errorf("%s %s without token: %d", rt[0], rt[1], r.status)
		}
		if r := h.do(t, rt[0], rt[1], h.token, ""); r.status == 401 || r.status == 500 {
			t.Errorf("%s %s with token: %d %s", rt[0], rt[1], r.status, r.body)
		}
	}
	r := h.do(t, "GET", "/admin/healthz", "", "")
	if r.status != 200 || r.body != `{"status":"ok"}` {
		t.Fatalf("healthz: %d %s", r.status, r.body)
	}
	// No CORS, ever.
	r = h.do(t, "GET", "/admin/v1/status", h.token, "", "Origin", "https://evil.example")
	if r.header.Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("CORS header on the admin API")
	}
	if r.header.Get("X-Content-Type-Options") != "nosniff" || r.header.Get("Cache-Control") != "no-store" {
		t.Fatalf("security headers: %v", r.header)
	}
}

// ---- users ---------------------------------------------------------------------------

func checkAdminAudit(t *testing.T, h *harness, action string, userID *uuid.UUID) domain.AuditEntry {
	t.Helper()
	a := h.store.lastAudit()
	if a.Action != action {
		t.Fatalf("audit action %q, want %q", a.Action, action)
	}
	var p map[string]any
	_ = json.Unmarshal(a.Payload, &p)
	if p["actor"] != "admin" || p["token_name"] != "panel" || p["token_id"] != h.tok.ID.String() {
		t.Fatalf("audit payload %s", a.Payload)
	}
	if a.IP == nil || *a.IP == "" {
		t.Fatalf("audit without ip")
	}
	if userID != nil && (a.UserID == nil || *a.UserID != *userID) {
		t.Fatalf("audit user_id %v, want %v", a.UserID, userID)
	}
	return a
}

func TestUserRoutes(t *testing.T) {
	h := newHarness(t)

	r := h.do(t, "POST", "/admin/v1/users", h.token, `{"username":"Alice","password":"correct horse 9","display_name":"Alice A."}`)
	if r.status != 201 {
		t.Fatalf("create: %d %s", r.status, r.body)
	}
	m := r.json(t)
	if m["username"] != "alice" || m["state"] != "active" {
		t.Fatalf("created %v", m)
	}
	alice := uuid.MustParse(m["id"].(string))
	checkAdminAudit(t, h, ActionUserCreate, &alice)

	// Same rules as registration.
	for body, field := range map[string]string{
		`{"username":"a","password":"correct horse 9"}`:         "username",
		`{"username":"bob","password":"short1"}`:                "password",
		`{"username":"bob","password":"12345678901"}`:           "password",
		`{"username":"bob","password":"correct horse 9","x":1}`: "body",
	} {
		r := h.do(t, "POST", "/admin/v1/users", h.token, body)
		if r.status != 400 || r.json(t)["field"] != field {
			t.Errorf("%s: %d %s", body, r.status, r.body)
		}
	}
	if r := h.do(t, "POST", "/admin/v1/users", h.token, `{"username":"alice","password":"correct horse 9"}`); r.status != 409 {
		t.Fatalf("duplicate: %d", r.status)
	}
	// Strict content type and body limit.
	r = h.do(t, "POST", "/admin/v1/users", h.token, "", "Content-Type", "text/plain")
	if r.status != 400 {
		t.Fatalf("no json: %d", r.status)
	}
	// Body limit: fasthttp refuses before any handler (needs a real listener).
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	app := h.api.App()
	go func() { _ = app.Listener(ln) }()
	defer func() { _ = app.Shutdown() }()
	big := `{"username":"bob","password":"` + strings.Repeat("x", BodyLimit) + `"}`
	req, _ := http.NewRequest("POST", "http://"+ln.Addr().String()+"/admin/v1/users", strings.NewReader(big))
	req.Header.Set("Authorization", "Bearer "+h.token)
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 413 {
		t.Fatalf("big body: %d", res.StatusCode)
	}

	// Sessions end on password reset and disable.
	h.store.sessions[strings.Repeat("a", 64)] = &Session{ID: strings.Repeat("a", 64), UserID: alice, Username: "alice"}
	if r := h.do(t, "POST", "/admin/v1/users/"+alice.String()+"/password", h.token, `{"password":"another pass 7"}`); r.status != 204 {
		t.Fatalf("password: %d %s", r.status, r.body)
	}
	checkAdminAudit(t, h, ActionUserPassword, &alice)
	if len(h.store.sessions) != 0 || len(h.live.users) != 1 {
		t.Fatalf("password reset left sessions %d / live %d", len(h.store.sessions), len(h.live.users))
	}
	if r := h.do(t, "POST", "/admin/v1/users/"+alice.String()+"/password", h.token, `{"password":"x"}`); r.status != 400 {
		t.Fatalf("weak password reset: %d", r.status)
	}

	for _, op := range []struct{ path, action, state string }{
		{"disable", ActionUserDisable, "disabled"},
		{"disable", ActionUserDisable, "disabled"}, // idempotent
		{"enable", ActionUserEnable, "active"},
		{"unlock", ActionUserUnlock, "active"},
	} {
		if r := h.do(t, "POST", "/admin/v1/users/"+alice.String()+"/"+op.path, h.token, ""); r.status != 204 {
			t.Fatalf("%s: %d %s", op.path, r.status, r.body)
		}
		checkAdminAudit(t, h, op.action, &alice)
		if got := h.do(t, "GET", "/admin/v1/users/"+alice.String(), h.token, "").json(t)["state"]; got != op.state {
			t.Fatalf("after %s: state %v", op.path, got)
		}
	}

	// Locked state is reported and cleared by unlock.
	until := time.Now().Add(time.Hour)
	h.store.users[alice].LockedUntil, h.store.users[alice].FailedLogins = &until, 12
	if got := h.do(t, "GET", "/admin/v1/users/"+alice.String(), h.token, "").json(t)["state"]; got != "locked" {
		t.Fatalf("locked state: %v", got)
	}
	h.do(t, "POST", "/admin/v1/users/"+alice.String()+"/unlock", h.token, "")
	if u := h.store.users[alice]; u.LockedUntil != nil || u.FailedLogins != 0 {
		t.Fatal("unlock did not clear")
	}

	for _, p := range []string{"/admin/v1/users/" + uuid.NewString(), "/admin/v1/users/not-a-uuid"} {
		if r := h.do(t, "GET", p, h.token, ""); r.status != 404 || r.body != `{"error":"not_found"}` {
			t.Fatalf("%s: %d %s", p, r.status, r.body)
		}
	}
	if r := h.do(t, "POST", "/admin/v1/users/"+uuid.NewString()+"/disable", h.token, ""); r.status != 404 {
		t.Fatalf("disable unknown: %d", r.status)
	}
}

func TestUserListPaging(t *testing.T) {
	h := newHarness(t)
	for _, n := range []string{"carol", "alice", "bob"} {
		h.addUser(n)
	}
	r := h.do(t, "GET", "/admin/v1/users?limit=2", h.token, "").json(t)
	items := r["items"].([]any)
	if len(items) != 2 || items[0].(map[string]any)["username"] != "alice" || r["more"] != true {
		t.Fatalf("page 1: %v", r)
	}
	next := r["next"].(string)
	r = h.do(t, "GET", "/admin/v1/users?limit=2&after="+next, h.token, "").json(t)
	items = r["items"].([]any)
	if len(items) != 1 || items[0].(map[string]any)["username"] != "carol" || r["more"] != false || r["next"] != nil {
		t.Fatalf("page 2: %v", r)
	}
	for _, q := range []string{"limit=0", "limit=201", "limit=x", "after=%%%"} {
		if r := h.do(t, "GET", "/admin/v1/users?"+q, h.token, ""); r.status != 400 {
			t.Errorf("%s: %d", q, r.status)
		}
	}
}

func TestUserDeleteSemantics(t *testing.T) {
	h := newHarness(t)
	u := h.addUser("dora")
	v1, v2 := uuid.New(), uuid.New()
	h.store.owned[u.ID] = []uuid.UUID{v1, v2}
	before := h.store.auditCount()

	// Owner of vaults: refused like DELETE /api/users/me, nothing happens.
	r := h.do(t, "DELETE", "/admin/v1/users/"+u.ID.String(), h.token, "")
	if r.status != 409 || r.json(t)["error"] != "sole_admin_vaults" {
		t.Fatalf("owner delete: %d %s", r.status, r.body)
	}
	if ids := r.json(t)["vault_ids"].([]any); len(ids) != 2 || ids[0] != v1.String() {
		t.Fatalf("vault_ids %v", ids)
	}
	if len(h.eraser.calls) != 0 || h.store.auditCount() != before {
		t.Fatal("refused delete erased or audited")
	}
	if r := h.do(t, "DELETE", "/admin/v1/users/"+u.ID.String()+"?delete_owned_vaults=yes", h.token, ""); r.status != 400 {
		t.Fatalf("bad flag: %d", r.status)
	}

	// Opting in deletes the owned vaults through the erasure flow.
	if r := h.do(t, "DELETE", "/admin/v1/users/"+u.ID.String()+"?delete_owned_vaults=true", h.token, ""); r.status != 204 {
		t.Fatalf("forced delete: %d %s", r.status, r.body)
	}
	if len(h.eraser.calls) != 1 || !h.eraser.calls[0].force || h.eraser.calls[0].ip == "" {
		t.Fatalf("eraser calls %+v", h.eraser.calls)
	}
	a := checkAdminAudit(t, h, ActionUserDelete, &u.ID)
	if !strings.Contains(string(a.Payload), `"username":"dora"`) || !strings.Contains(string(a.Payload), v1.String()) {
		t.Fatalf("delete audit %s", a.Payload)
	}

	// No owned vaults: plain erasure.
	w := h.addUser("walt")
	if r := h.do(t, "DELETE", "/admin/v1/users/"+w.ID.String(), h.token, ""); r.status != 204 {
		t.Fatalf("plain delete: %d", r.status)
	}
	if h.eraser.calls[1].force {
		t.Fatal("plain delete forced")
	}
	if r := h.do(t, "DELETE", "/admin/v1/users/"+w.ID.String(), h.token, ""); r.status != 404 {
		t.Fatalf("delete twice: %d", r.status)
	}

	// Audit down: the erasure does not happen.
	x := h.addUser("xena")
	h.store.failAudit = true
	if r := h.do(t, "DELETE", "/admin/v1/users/"+x.ID.String(), h.token, ""); r.status != 500 {
		t.Fatalf("audit down: %d", r.status)
	}
	if len(h.eraser.calls) != 2 {
		t.Fatal("erased without an audit row")
	}
}

// ---- sessions, vaults, federations, tokens, audit -----------------------------------------

func TestSessionVaultFederationTokenRoutes(t *testing.T) {
	h := newHarness(t)
	u := h.addUser("erin")
	sid := strings.Repeat("c", 64)
	h.store.sessions[sid] = &Session{ID: sid, UserID: u.ID, Username: "erin", CreatedAt: time.Now()}

	r := h.do(t, "GET", "/admin/v1/sessions?user="+u.ID.String(), h.token, "").json(t)
	if items := r["items"].([]any); len(items) != 1 || items[0].(map[string]any)["id"] != sid {
		t.Fatalf("sessions %v", r)
	}
	if r := h.do(t, "GET", "/admin/v1/sessions?user=nope", h.token, ""); r.status != 400 {
		t.Fatalf("bad user filter: %d", r.status)
	}
	if r := h.do(t, "DELETE", "/admin/v1/sessions/"+sid, h.token, ""); r.status != 204 {
		t.Fatalf("revoke session: %d %s", r.status, r.body)
	}
	checkAdminAudit(t, h, ActionSessionRevoke, &u.ID)
	if len(h.live.sessKeys) != 1 || h.live.sessKeys[0] != sid {
		t.Fatalf("live session end %v", h.live.sessKeys)
	}
	for _, id := range []string{sid, "short", strings.Repeat("Z", 64)} {
		if r := h.do(t, "DELETE", "/admin/v1/sessions/"+id, h.token, ""); r.status != 404 {
			t.Errorf("revoke %s: %d", id, r.status)
		}
	}

	role := "home"
	v := &Vault{ID: uuid.New(), Slug: "notes", Name: "Notes", OwnerID: u.ID, OwnerUsername: "erin", Members: 2,
		FederationRole: &role, ActiveFederations: 1, CreatedAt: time.Now()}
	h.store.vaults[v.ID] = v
	got := h.do(t, "GET", "/admin/v1/vaults/"+v.ID.String(), h.token, "").json(t)
	if got["owner"].(map[string]any)["username"] != "erin" || got["federation"].(map[string]any)["role"] != "home" {
		t.Fatalf("vault %v", got)
	}
	if r := h.do(t, "DELETE", "/admin/v1/vaults/"+v.ID.String(), h.token, ""); r.status != 204 {
		t.Fatalf("delete vault: %d", r.status)
	}
	a := checkAdminAudit(t, h, ActionVaultDelete, nil)
	if a.VaultID == nil || *a.VaultID != v.ID || len(h.vaults.deleted) != 1 {
		t.Fatalf("vault delete audit/flow %v %v", a.VaultID, h.vaults.deleted)
	}

	fed := &Federation{ID: uuid.New(), VaultID: v.ID, Role: "home", PeerURL: "https://peer.example", Status: "active", CreatedAt: time.Now()}
	h.store.feds[fed.ID] = fed
	if r := h.do(t, "GET", "/admin/v1/federations", h.token, ""); !strings.Contains(r.body, "peer.example") {
		t.Fatalf("federations %s", r.body)
	}
	if r := h.do(t, "DELETE", "/admin/v1/federations/"+fed.ID.String(), h.token, ""); r.status != 204 {
		t.Fatalf("revoke federation: %d", r.status)
	}
	checkAdminAudit(t, h, ActionFederationRevoke, nil)
	fed.Status = "revoked"
	n := h.store.auditCount()
	r2 := h.do(t, "DELETE", "/admin/v1/federations/"+fed.ID.String(), h.token, "")
	if r2.status != 409 || r2.json(t)["error"] != "conflict" || h.store.auditCount() != n {
		t.Fatalf("revoke twice: %d %s", r2.status, r2.body)
	}

	toks := h.do(t, "GET", "/admin/v1/tokens", h.token, "").json(t)["items"].([]any)
	if len(toks) != 1 || toks[0].(map[string]any)["current"] != true || toks[0].(map[string]any)["state"] != "active" {
		t.Fatalf("tokens %v", toks)
	}
	// Revoking its own token: 204, and the next call is 401.
	if r := h.do(t, "DELETE", "/admin/v1/tokens/"+h.tok.ID.String(), h.token, ""); r.status != 204 {
		t.Fatalf("self revoke: %d", r.status)
	}
	checkAdminAudit(t, h, ActionTokenRevoke, nil)
	if r := h.do(t, "GET", "/admin/v1/status", h.token, ""); r.status != 401 {
		t.Fatalf("after self revoke: %d", r.status)
	}
}

func TestAuditAndStatus(t *testing.T) {
	h := newHarness(t)
	for i := 0; i < 5; i++ {
		h.addUser("user" + string(rune('a'+i)))
	}
	st := h.do(t, "GET", "/admin/v1/status", h.token, "").json(t)
	if st["users"].(float64) != 5 || st["version"] != "test" || st["token"].(map[string]any)["name"] != "panel" {
		t.Fatalf("status %v", st)
	}
	for _, u := range h.store.users {
		h.do(t, "POST", "/admin/v1/users/"+u.ID.String()+"/unlock", h.token, "")
	}
	r := h.do(t, "GET", "/admin/v1/audit?limit=2", h.token, "").json(t)
	entries := r["entries"].([]any)
	if len(entries) != 2 || r["more"] != true {
		t.Fatalf("audit page %v", r)
	}
	first := entries[0].(map[string]any)
	if first["action"] != ActionUserUnlock || first["payload"].(map[string]any)["token_name"] != "panel" {
		t.Fatalf("audit entry %v", first)
	}
	r = h.do(t, "GET", "/admin/v1/audit?before="+r["next"].(string), h.token, "").json(t)
	if len(r["entries"].([]any)) != 4 { // 3 more unlocks + token.create
		t.Fatalf("audit page 2 %v", r)
	}
	for _, q := range []string{"limit=101", "before=0", "scope=x", "user=1"} {
		if r := h.do(t, "GET", "/admin/v1/audit?"+q, h.token, ""); r.status != 400 {
			t.Errorf("audit %s: %d", q, r.status)
		}
	}
}

// ---- listener rules -------------------------------------------------------------------------

func TestSameListener(t *testing.T) {
	cases := []struct {
		a, b string
		same bool
	}{
		{"127.0.0.1:8080", "127.0.0.1:8080", true},
		{"localhost:8080", "127.0.0.1:8080", true},
		{"[::1]:8080", "localhost:8080", true},
		{"[::ffff:127.0.0.1]:8080", "127.0.0.1:8080", true},
		{"0.0.0.0:8080", "127.0.0.1:8080", true},
		{":8080", "10.0.0.5:8080", true},
		{"[::]:8080", "127.0.0.1:8080", true},
		{"admin.internal:8080", "10.0.0.5:8080", true},
		{"127.0.0.1:8081", "0.0.0.0:8080", false},
		{"10.0.0.5:8080", "127.0.0.1:8080", false},
		{"10.0.0.5:8080", "10.0.0.6:8080", false},
		{"127.0.0.1:0", "127.0.0.1:0", true}, // literally equal
		{"127.0.0.1:0", "localhost:0", false},
	}
	for _, c := range cases {
		if got := SameListener(c.a, c.b); got != c.same {
			t.Errorf("SameListener(%q, %q) = %v", c.a, c.b, got)
		}
		if got := SameListener(c.b, c.a); got != c.same {
			t.Errorf("SameListener(%q, %q) = %v (reversed)", c.b, c.a, got)
		}
	}
	for addr, want := range map[string]bool{"127.0.0.1:1": true, "localhost:1": true, "[::1]:1": true, "0.0.0.0:1": false, ":1": false, "10.0.0.1:1": false} {
		if LoopbackOnly(addr) != want {
			t.Errorf("LoopbackOnly(%q) != %v", addr, want)
		}
	}
	if ValidateListenAddr("8081") == nil || ValidateListenAddr("x:99999") == nil || ValidateListenAddr("0.0.0.0:8081") != nil {
		t.Error("ValidateListenAddr")
	}
}

func TestClientIP(t *testing.T) {
	proxies, err := ParseTrustedProxies("172.16.0.0/12, 10.0.0.1")
	if err != nil || len(proxies) != 2 {
		t.Fatal(err)
	}
	if _, err := ParseTrustedProxies("nope"); err == nil {
		t.Fatal("bad proxy list accepted")
	}
	a := netip.MustParseAddr
	cases := []struct {
		remote string
		xff    []string
		want   string
	}{
		{"203.0.113.9", []string{"1.2.3.4"}, "203.0.113.9"},               // untrusted peer: header ignored
		{"172.18.0.2", nil, "172.18.0.2"},                                 // trusted, no header
		{"172.18.0.2", []string{"198.51.100.7"}, "198.51.100.7"},          // panel forwards the user
		{"172.18.0.2", []string{"6.6.6.6, 198.51.100.7"}, "198.51.100.7"}, // spoofed left hop ignored
		{"172.18.0.2", []string{"6.6.6.6", "198.51.100.7, 10.0.0.1"}, "198.51.100.7"},
		{"172.18.0.2", []string{"garbage, 198.51.100.7"}, "198.51.100.7"},
		{"172.18.0.2", []string{"198.51.100.7, garbage"}, "172.18.0.2"},
		{"::ffff:172.18.0.2", []string{"198.51.100.7"}, "198.51.100.7"},
	}
	for _, c := range cases {
		if got := ClientIP(a(c.remote), c.xff, proxies); got != a(c.want) {
			t.Errorf("ClientIP(%s, %v) = %s, want %s", c.remote, c.xff, got, c.want)
		}
	}
	if got := ClientIP(a("172.18.0.2"), []string{"1.1.1.1"}, nil); got != a("172.18.0.2") {
		t.Errorf("no proxies configured: %s", got)
	}
	if limiterKey(a("2001:db8::1")) != limiterKey(a("2001:db8::ffff")) {
		t.Error("IPv6 /64 not grouped")
	}
}
