package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"io"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/ViniZap4/lumi-server/internal/admin"
	"github.com/ViniZap4/lumi-server/internal/auth"
	"github.com/ViniZap4/lumi-server/internal/domain"
	"github.com/ViniZap4/lumi-server/internal/storage/fs"
	"github.com/ViniZap4/lumi-server/internal/storage/pg"
)

// TestAdminSessionLoginAgainstPostgres walks the panel password login
// (SPEC-PARTE2 §10) on a real database with the real auth service: the
// server_admin flag (CLI + API), lockout accounting, the lps_ session row
// and its constraints, revocation paths and LGPD cascade. Needs
// LUMI_TEST_DATABASE_URL (a disposable database); skipped otherwise.
func TestAdminSessionLoginAgainstPostgres(t *testing.T) {
	dsn := os.Getenv("LUMI_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("LUMI_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	if err := pg.Migrate(ctx, dsn, "../../migrations"); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LUMI_MIGRATIONS_DIR", "../../migrations")
	pool, err := pg.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	fsMgr, err := fs.NewManager(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	svc, err := buildCLIAdmin(ctx, config{publicBaseURL: "https://lumi.example"}, zerolog.Nop(), pool, fsMgr)
	if err != nil {
		t.Fatal(err)
	}
	userStore := pg.NewUserStore(pool)
	sessionStore := pg.NewSessionStore(pool)
	authSvc, err := auth.NewService(authUserRepoAdapter{userStore}, sessionStore, pg.NewConsentStore(pool), pg.NewAuditStore(pool),
		auth.Config{Logger: zerolog.Nop()})
	if err != nil {
		t.Fatal(err)
	}
	svc.Login = authSvc
	svc.Hasher = authSvc
	suffix := strings.ReplaceAll(uuid.NewString()[:8], "-", "")

	cli := func(stdin string, args ...string) (string, string, int) {
		var out, errb bytes.Buffer
		e := &cliEnv{in: strings.NewReader(stdin), out: &out, err: &errb,
			open: func(context.Context) (*admin.Service, func(), error) { return svc, func() {}, nil }}
		code := e.run(ctx, args)
		return out.String(), errb.String(), code
	}
	api := &admin.HTTP{Service: svc, StartedAt: time.Now(), Limiter: admin.NewFailureLimiter(100, time.Hour, 100)}
	app := api.App()
	call := func(method, path, token, body string) (int, map[string]any) {
		t.Helper()
		var r io.Reader
		if body != "" {
			r = strings.NewReader(body)
		}
		req := httptest.NewRequest(method, path, r)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		res, err := app.Test(req, -1)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		b, _ := io.ReadAll(res.Body)
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		return res.StatusCode, m
	}
	login := func(user, pw string) (int, map[string]any) {
		b, _ := json.Marshal(map[string]string{"username": user, "password": pw})
		return call("POST", "/admin/v1/session", "", string(b))
	}

	carol := "carol" + suffix
	if _, stderr, code := cli("correct horse 9\n", "user", "create", carol, "--password-stdin"); code != 0 {
		t.Fatalf("user create: %s", stderr)
	}
	u, err := userStore.GetByUsername(ctx, carol)
	if err != nil || u.ServerAdmin {
		t.Fatalf("new user: %+v %v", u, err)
	}

	// Not a server admin yet: the generic refusal, audited with the user.
	if code, m := login(carol, "correct horse 9"); code != 401 || m["error"] != "invalid_credentials" {
		t.Fatalf("non-admin login: %d %v", code, m)
	}
	var reason string
	if err := pool.QueryRow(ctx, `SELECT payload->>'reason' FROM audit_log WHERE action = 'admin.login_failed' AND user_id = $1 ORDER BY id DESC LIMIT 1`, u.ID).Scan(&reason); err != nil || reason != "not_server_admin" {
		t.Fatalf("login_failed audit: %q %v", reason, err)
	}

	// CLI grant; this test database may hold admins from earlier runs:
	// make carol the only one so the last-admin rule is deterministic.
	if _, stderr, code := cli("", "admin", "grant", carol); code != 0 {
		t.Fatalf("admin grant: %s", stderr)
	}
	if _, err := pool.Exec(ctx, `UPDATE users SET server_admin = false WHERE id <> $1`, u.ID); err != nil {
		t.Fatal(err)
	}
	if out, _, code := cli("", "admin", "list"); code != 0 || !strings.Contains(out, carol) {
		t.Fatalf("admin list: %s", out)
	}
	if _, stderr, code := cli("", "admin", "revoke", carol); code != 1 || !strings.Contains(stderr, "last active server admin") {
		t.Fatalf("revoke last admin: %d %s", code, stderr)
	}

	// Wrong passwords count toward the persistent lockout; success resets.
	for i := 0; i < 2; i++ {
		if code, _ := login(carol, "wrong pass 1"); code != 401 {
			t.Fatalf("wrong password: %d", code)
		}
	}
	if u, _ = userStore.GetByUsername(ctx, carol); u.FailedLogins != 2 {
		t.Fatalf("failed_logins = %d", u.FailedLogins)
	}
	code, m := login(strings.ToUpper(carol), "correct horse 9")
	if code != 201 {
		t.Fatalf("admin login: %d %v", code, m)
	}
	tok := m["token"].(string)
	if !strings.HasPrefix(tok, admin.SessionPrefix) {
		t.Fatalf("token %q", tok)
	}
	if u, _ = userStore.GetByUsername(ctx, carol); u.FailedLogins != 0 {
		t.Fatalf("failed_logins after success = %d", u.FailedLogins)
	}

	// Stored hashed, as a session of carol, within 12 h.
	sum := sha256.Sum256([]byte(tok))
	var kind string
	var owner uuid.UUID
	var ttl time.Duration
	if err := pool.QueryRow(ctx, `SELECT kind, user_id, (EXTRACT(EPOCH FROM expires_at - created_at) * 1e9)::bigint FROM admin_tokens WHERE token_hash = $1`, sum[:]).
		Scan(&kind, &owner, &ttl); err != nil || kind != "session" || owner != u.ID || ttl > 12*time.Hour {
		t.Fatalf("row kind=%s owner=%s ttl=%s err=%v", kind, owner, ttl, err)
	}
	// The schema refuses longer sessions and sessions without a user.
	for _, q := range []string{
		`INSERT INTO admin_tokens (name, token_hash, expires_at, kind, user_id) VALUES ('x', $1, NOW() + interval '13 hours', 'session', $2)`,
		`INSERT INTO admin_tokens (name, token_hash, expires_at, kind, user_id) VALUES ('x', $1, NOW() + interval '1 hour', 'token', $2)`,
	} {
		junk := sha256.Sum256([]byte(uuid.NewString()))
		if _, err := pool.Exec(ctx, q, junk[:], u.ID); err == nil {
			t.Fatalf("constraint missing for %s", q)
		}
	}
	junk := sha256.Sum256([]byte(uuid.NewString()))
	if _, err := pool.Exec(ctx, `INSERT INTO admin_tokens (name, token_hash, expires_at, kind) VALUES ('x', $1, NOW() + interval '1 hour', 'session')`, junk[:]); err == nil {
		t.Fatal("session without user accepted")
	}

	// The session works and is listed with its kind and user.
	if code, st := call("GET", "/admin/v1/status", tok, ""); code != 200 || st["token"].(map[string]any)["kind"] != "session" {
		t.Fatalf("status with session: %d %v", code, st)
	}
	_, page := call("GET", "/admin/v1/tokens", tok, "")
	found := false
	for _, x := range page["items"].([]any) {
		it := x.(map[string]any)
		if it["current"] == true {
			found = it["kind"] == "session" && it["user"].(map[string]any)["username"] == carol
		}
	}
	if !found {
		t.Fatalf("session not listed: %v", page)
	}
	if code, _ := call("POST", "/admin/v1/users/"+u.ID.String()+"/server-admin", tok, `{"enabled":false}`); code != 409 {
		t.Fatalf("self revoke as last admin: %d", code)
	}
	var created int
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE action = 'admin.session.create' AND user_id = $1`, u.ID).Scan(&created)
	if created != 1 {
		t.Fatalf("admin.session.create rows = %d", created)
	}

	// A password change (public flow) signs the account out of the panel.
	if err := authSvc.ChangePassword(ctx, u.ID, "correct horse 9", "brand new pass 4"); err != nil {
		t.Fatal(err)
	}
	if code, _ := call("GET", "/admin/v1/status", tok, ""); code != 401 {
		t.Fatalf("session after password change: %d", code)
	}

	// Logout revokes server-side.
	_, m = login(carol, "brand new pass 4")
	tok = m["token"].(string)
	if code, _ := call("DELETE", "/admin/v1/session", tok, ""); code != 204 {
		t.Fatalf("logout: %d", code)
	}
	if code, _ := call("GET", "/admin/v1/status", tok, ""); code != 401 {
		t.Fatalf("after logout: %d", code)
	}

	// Disable ends a fresh session at once.
	_, m = login(carol, "brand new pass 4")
	tok = m["token"].(string)
	if _, stderr, code := cli("", "user", "disable", carol); code != 0 {
		t.Fatal(stderr)
	}
	if code, _ := call("GET", "/admin/v1/status", tok, ""); code != 401 {
		t.Fatalf("session of disabled user: %d", code)
	}
	if _, stderr, code := cli("", "user", "enable", carol); code != 0 {
		t.Fatal(stderr)
	}

	// Bootstrap-style grant (GrantServerAdmin) and the store counter.
	dave := "dave" + suffix
	if _, stderr, code := cli("correct horse 9\n", "user", "create", dave, "--password-stdin"); code != 0 {
		t.Fatal(stderr)
	}
	d, _ := userStore.GetByUsername(ctx, dave)
	if err := userStore.GrantServerAdmin(ctx, d.ID, domain.AuditEntry{UserID: &d.ID, Action: admin.ActionUserServerAdmin, Payload: []byte(`{"actor":"bootstrap"}`)}); err != nil {
		t.Fatal(err)
	}
	if n, err := userStore.CountServerAdmins(ctx); err != nil || n != 2 {
		t.Fatalf("server admins = %d %v", n, err)
	}
	// With dave around, carol may drop the flag (API, from an lpa_ token).
	lpa, _, err := svc.CreateToken(ctx, admin.CLI, "test-"+suffix, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if code, _ := call("POST", "/admin/v1/users/"+u.ID.String()+"/server-admin", lpa, `{"enabled":false}`); code != 204 {
		t.Fatalf("revoke with another admin: %d", code)
	}
	if code, _ := login(carol, "brand new pass 4"); code != 401 {
		t.Fatalf("login after losing the flag: %d", code)
	}

	// LGPD erasure deletes the user's admin sessions with it.
	_, m = login(dave, "correct horse 9")
	if m["token"] == nil {
		t.Fatalf("dave login: %v", m)
	}
	if code, _ := call("DELETE", "/admin/v1/users/"+d.ID.String(), lpa, ""); code != 204 {
		t.Fatalf("erase dave: %d", code)
	}
	var left int
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM admin_tokens WHERE user_id = $1`, d.ID).Scan(&left)
	if left != 0 {
		t.Fatalf("admin sessions of an erased user: %d", left)
	}
}
