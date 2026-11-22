package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/ViniZap4/lumi-server/internal/admin"
	"github.com/ViniZap4/lumi-server/internal/auth"
	"github.com/ViniZap4/lumi-server/internal/federation"
	"github.com/ViniZap4/lumi-server/internal/members"
	"github.com/ViniZap4/lumi-server/internal/storage/fs"
	"github.com/ViniZap4/lumi-server/internal/storage/pg"
	"github.com/ViniZap4/lumi-server/internal/vaults"
)

// TestAdminAgainstPostgres runs the CLI and the admin API end to end on a
// real database. It needs LUMI_TEST_DATABASE_URL (a disposable database:
// migrations are applied to it) and is skipped otherwise.
func TestAdminAgainstPostgres(t *testing.T) {
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
	root := t.TempDir()
	fsMgr, err := fs.NewManager(root)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config{publicBaseURL: "https://lumi.example"}
	svc, err := buildCLIAdmin(ctx, cfg, zerolog.Nop(), pool, fsMgr)
	if err != nil {
		t.Fatal(err)
	}
	suffix := strings.ReplaceAll(uuid.NewString()[:8], "-", "")

	cli := func(stdin string, args ...string) (string, string, int) {
		var out, errb bytes.Buffer
		e := &cliEnv{in: strings.NewReader(stdin), out: &out, err: &errb,
			open: func(context.Context) (*admin.Service, func(), error) { return svc, func() {}, nil }}
		code := e.run(ctx, args)
		return out.String(), errb.String(), code
	}

	// ---- token lifecycle through the CLI.
	stdout, stderr, code := cli("", "token", "create", "panel-"+suffix, "--ttl", "2h")
	if code != 0 {
		t.Fatalf("token create: %d %s", code, stderr)
	}
	token := strings.TrimSpace(stdout)
	if !strings.HasPrefix(token, admin.TokenPrefix) || strings.Count(stdout, "\n") != 1 {
		t.Fatalf("stdout must hold only the token: %q", stdout)
	}
	if _, stderr, code := cli("", "token", "create", "x", "--ttl", "400d"); code != 1 || !strings.Contains(stderr, "ttl") {
		t.Fatalf("ttl over a year: %d %s", code, stderr)
	}

	// ---- admin API on the real store.
	broker := &recLive{}
	svc.Live = broker
	api := &admin.HTTP{Service: svc, StartedAt: time.Now()}
	app := api.App()
	call := func(method, path, body string) (int, map[string]any) {
		t.Helper()
		var r io.Reader
		if body != "" {
			r = strings.NewReader(body)
		}
		req := httptest.NewRequest(method, path, r)
		req.Header.Set("Authorization", "Bearer "+token)
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

	code, st := call("GET", "/admin/v1/status", "")
	if code != 200 || st["schema_version"].(float64) < 7 || st["pending_migrations"].(float64) != 0 {
		t.Fatalf("status %d %v", code, st)
	}

	// ---- users: create (CLI), login, disable, lock, password, delete.
	bob := "bob" + suffix
	if _, stderr, code := cli("weak\n", "user", "create", bob, "--password-stdin"); code != 1 || !strings.Contains(stderr, "password") {
		t.Fatalf("weak password: %d %s", code, stderr)
	}
	if _, stderr, code := cli("correct horse 9\n", "user", "create", bob, "--password-stdin"); code != 0 {
		t.Fatalf("user create: %s", stderr)
	}
	userStore := pg.NewUserStore(pool)
	sessionStore := pg.NewSessionStore(pool)
	authSvc, err := auth.NewService(authUserRepoAdapter{userStore}, sessionStore, pg.NewConsentStore(pool), pg.NewAuditStore(pool),
		auth.Config{Logger: zerolog.Nop()})
	if err != nil {
		t.Fatal(err)
	}
	login := func(pw string) error {
		_, err := authSvc.Login(ctx, auth.LoginInput{Username: bob, Password: pw, IP: "198.51.100.4"})
		return err
	}
	if err := login("correct horse 9"); err != nil {
		t.Fatalf("login: %v", err)
	}
	u, err := userStore.GetByUsername(ctx, bob)
	if err != nil {
		t.Fatal(err)
	}
	uid := u.ID.String()

	code, page := call("GET", "/admin/v1/sessions?user="+uid, "")
	if code != 200 || len(page["items"].([]any)) != 1 {
		t.Fatalf("sessions %d %v", code, page)
	}
	if code, _ := call("POST", "/admin/v1/users/"+uid+"/disable", ""); code != 204 {
		t.Fatalf("disable %d", code)
	}
	if _, page = call("GET", "/admin/v1/sessions?user="+uid, ""); len(page["items"].([]any)) != 0 {
		t.Fatal("disable kept sessions")
	}
	if err := login("correct horse 9"); err == nil {
		t.Fatal("disabled user logged in")
	}
	if _, stderr, code := cli("", "user", "enable", bob); code != 0 {
		t.Fatalf("enable: %s", stderr)
	}
	for i := 0; i < auth.LockoutThreshold; i++ {
		if err := userStore.RecordLoginFailure(ctx, u.ID, auth.LockoutThreshold, auth.LockoutMax); err != nil {
			t.Fatal(err)
		}
	}
	if _, got := call("GET", "/admin/v1/users/"+uid, ""); got["state"] != "locked" || got["failed_logins"].(float64) != 10 {
		t.Fatalf("locked user %v", got)
	}
	if err := login("correct horse 9"); err == nil {
		t.Fatal("locked user logged in")
	}
	if code, _ := call("POST", "/admin/v1/users/"+uid+"/unlock", ""); code != 204 {
		t.Fatal("unlock")
	}
	if err := login("correct horse 9"); err != nil {
		t.Fatalf("login after unlock: %v", err)
	}
	if code, _ := call("POST", "/admin/v1/users/"+uid+"/password", `{"password":"brand new pass 3"}`); code != 204 {
		t.Fatal("password reset")
	}
	if _, page = call("GET", "/admin/v1/sessions?user="+uid, ""); len(page["items"].([]any)) != 0 || len(broker.users) == 0 {
		t.Fatal("password reset kept sessions or skipped the feed")
	}
	if login("correct horse 9") == nil || login("brand new pass 3") != nil {
		t.Fatal("password reset did not take")
	}
	_, page = call("GET", "/admin/v1/sessions?user="+uid, "")
	sid := page["items"].([]any)[0].(map[string]any)["id"].(string)
	if code, _ := call("DELETE", "/admin/v1/sessions/"+sid, ""); code != 204 || broker.keys[len(broker.keys)-1] != sid {
		t.Fatal("session revoke")
	}

	// ---- a vault the user owns blocks erasure until opted in.
	memberStore := pg.NewMemberStore(pool)
	membersSvc := members.NewService(memberRepoAdapter{memberStore}, pg.NewAuditStore(pool))
	vaultsSvc := vaults.NewService(pg.NewVaultStore(pool), pg.NewRoleStore(pool), memberStore, fsMgr, pg.NewAuditStore(pool),
		federation.NewControlResolver(membersSvc, userStore))
	v, err := vaultsSvc.Create(ctx, vaults.CreateInput{Name: "Bob notes", Slug: "bob-" + suffix, CreatedBy: u.ID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, v.Slug)); err != nil {
		t.Fatalf("vault dir: %v", err)
	}
	code, got := call("GET", "/admin/v1/vaults/"+v.ID.String(), "")
	if code != 200 || got["members"].(float64) != 1 || got["owner"].(map[string]any)["username"] != bob {
		t.Fatalf("vault %d %v", code, got)
	}
	code, got = call("DELETE", "/admin/v1/users/"+uid, "")
	if code != 409 || got["error"] != "sole_admin_vaults" {
		t.Fatalf("delete owner: %d %v", code, got)
	}
	if _, stderr, code := cli("", "user", "delete", bob, "--yes"); code != 1 || !strings.Contains(stderr, "--delete-owned-vaults") {
		t.Fatalf("cli delete owner: %d %s", code, stderr)
	}
	if code, _ := call("DELETE", "/admin/v1/users/"+uid+"?delete_owned_vaults=true", ""); code != 204 {
		t.Fatal("forced delete")
	}
	if _, err := userStore.GetByID(ctx, u.ID); err == nil {
		t.Fatal("user survived erasure")
	}
	if _, err := os.Stat(filepath.Join(root, v.Slug)); !os.IsNotExist(err) {
		t.Fatalf("owned vault dir survived: %v", err)
	}
	if code, _ := call("GET", "/admin/v1/vaults/"+v.ID.String(), ""); code != 404 {
		t.Fatal("owned vault survived")
	}
	// The admin rows about the erased user were anonymised with the rest.
	_, aud := call("GET", "/admin/v1/audit?scope=admin&limit=100", "")
	sawDelete := false
	for _, x := range aud["entries"].([]any) {
		e := x.(map[string]any)
		p := e["payload"].(map[string]any)
		if p["username"] == bob {
			t.Fatalf("erased username left in audit: %v", e)
		}
		if e["action"] == admin.ActionUserDelete && p["username"] == "<redacted>" {
			sawDelete = true
			if e["user_id"] != nil || e["ip"] != nil {
				t.Fatalf("delete row not anonymised: %v", e)
			}
		}
	}
	if !sawDelete {
		t.Fatal("no admin.user.delete row")
	}
	var leaks int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE payload::text LIKE '%'||$1||'%'`, bob).Scan(&leaks); err != nil || leaks != 0 {
		t.Fatalf("username still in audit_log: %d %v", leaks, err)
	}

	// ---- listings and token revoke.
	for _, p := range []string{"/admin/v1/users?limit=1", "/admin/v1/vaults", "/admin/v1/federations", "/admin/v1/tokens", "/admin/v1/sessions"} {
		if code, _ := call("GET", p, ""); code != 200 {
			t.Fatalf("%s: %d", p, code)
		}
	}
	_, toks := call("GET", "/admin/v1/tokens", "")
	var myID string
	for _, x := range toks["items"].([]any) {
		if x.(map[string]any)["current"] == true {
			myID = x.(map[string]any)["id"].(string)
		}
	}
	if _, stderr, code := cli("", "token", "revoke", myID); code != 0 {
		t.Fatalf("token revoke: %s", stderr)
	}
	if code, _ := call("GET", "/admin/v1/status", ""); code != 401 {
		t.Fatalf("revoked token: %d", code)
	}
	if out, _, code := cli("", "audit", "--scope", "admin", "--limit", "5"); code != 0 || !strings.Contains(out, admin.ActionTokenRevoke) {
		t.Fatalf("cli audit: %s", out)
	}
}

type recLive struct {
	users []uuid.UUID
	keys  []string
}

func (r *recLive) UserSessionsEnded(id uuid.UUID, _ string) { r.users = append(r.users, id) }
func (r *recLive) SessionKeyEnded(k, _ string)              { r.keys = append(r.keys, k) }
