package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"golang.org/x/crypto/bcrypt"

	"github.com/ViniZap4/lumi-server/internal/admin"
	"github.com/ViniZap4/lumi-server/internal/domain"
	"github.com/ViniZap4/lumi-server/internal/storage/fs"
	"github.com/ViniZap4/lumi-server/internal/storage/pg"
)

// mirrorRouteExceptions are the write routes that may succeed on a mirror
// vault, with the reason. Everything else must answer 403
// mirror_read_only. A new route lands here only after a deliberate review.
var mirrorRouteExceptions = map[string]string{
	// A copy FROM a mirror into a new local vault is a read (vault.export
	// survives the clamp, §A6.5).
	"POST /api/vaults/:vault/copies": "read: copy out of the mirror",
}

// TestMirrorVault_EveryWriteRouteIsReadOnly is the §A6 route-table test:
// it builds the real application (every handler, the real resolver chain)
// on Postgres, makes one vault a mirror, and runs every non-GET route
// that names a vault as an Admin member who is also the vault's owner.
// Each must answer 403 {"error":"mirror_read_only"}, so a route added
// later cannot bypass the clamp silently. Needs LUMI_TEST_DATABASE_URL.
func TestMirrorVault_EveryWriteRouteIsReadOnly(t *testing.T) {
	dsn := os.Getenv("LUMI_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("LUMI_TEST_DATABASE_URL not set")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := pg.Migrate(ctx, dsn, "../../migrations"); err != nil {
		t.Fatal(err)
	}
	pool, err := pg.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	fsMgr, err := fs.NewManager(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cfg := config{publicBaseURL: "https://mirror.test", registration: "invite-only", auditRetentionDays: 30}
	app, drain, shutdown, err := buildApp(ctx, cfg, zerolog.Nop(), pool, fsMgr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { drain(); _ = shutdown(context.Background()) }()

	// An account (bcrypt cost 4: tests only) that will own the mirror.
	users := pg.NewUserStore(pool)
	suffix := strings.ReplaceAll(uuid.NewString()[:8], "-", "")
	hash, _ := bcrypt.GenerateFromPassword([]byte("route-table-pass"), 4)
	owner := domain.User{ID: uuid.New(), Username: "mirrorowner" + suffix, PasswordHash: string(hash), CreatedAt: time.Now()}
	if err := users.Create(ctx, owner); err != nil {
		t.Fatal(err)
	}
	call := func(method, path, token string, body any) (int, map[string]any) {
		t.Helper()
		var rdr io.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			rdr = bytes.NewReader(b)
		}
		req := httptest.NewRequest(method, path, rdr)
		req.Header.Set("Content-Type", "application/json")
		if token != "" {
			req.Header.Set("X-Lumi-Token", token)
		}
		resp, err := app.Test(req, -1)
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		var out map[string]any
		_ = json.Unmarshal(raw, &out)
		return resp.StatusCode, out
	}
	status, login := call(http.MethodPost, "/api/auth/login", "", map[string]string{"username": owner.Username, "password": "route-table-pass"})
	if status != http.StatusOK {
		t.Fatalf("login: %d %v", status, login)
	}
	token := login["token"].(string)

	// The vault, its seed roles, the owner as Admin and one note, written
	// straight to the stores (as a join provisions it): no resolver has
	// cached the vault before it becomes a mirror.
	vaultID := uuid.New()
	slug := "mirror-" + suffix
	if _, err := pg.NewVaultStore(pool).Create(ctx, domain.Vault{ID: vaultID, Slug: slug, Name: "Mirror " + suffix,
		CreatedBy: owner.ID, OwnerUserID: owner.ID, CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	roles, err := pg.NewRoleStore(pool).SeedForVault(ctx, vaultID)
	if err != nil {
		t.Fatal(err)
	}
	var roleID string
	for _, r := range roles {
		switch r.Name {
		case "Admin":
			if err := pg.NewMemberStore(pool).Add(ctx, domain.Member{VaultID: vaultID, UserID: owner.ID, RoleID: r.ID, JoinedAt: time.Now()}); err != nil {
				t.Fatal(err)
			}
		case "Viewer":
			roleID = r.ID.String()
		}
	}
	if _, err := fsMgr.EnsureVaultDir(slug); err != nil {
		t.Fatal(err)
	}
	const noteID = "chapter"
	if err := fsMgr.WriteNote(slug, "chapter.md", map[string]any{"id": noteID, "title": "Chapter"}, []byte("text")); err != nil {
		t.Fatal(err)
	}
	if _, err := pg.NewNoteStore(pool).Upsert(ctx, domain.Note{ID: noteID, VaultID: vaultID, Path: "chapter.md", Title: "Chapter",
		CreatedAt: time.Now(), UpdatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}

	// Make it a mirror: a follower-side mirror link (severed, so the relay
	// manager never dials; the clamp holds whatever the status).
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := pg.NewFederationStore(pool).Insert(ctx, domain.Federation{
		VaultID: vaultID, Role: "follower", Mode: "mirror", PeerURL: "https://home.test", PeerPubKey: pub,
		Status: "severed", CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	// A note whose content has not arrived yet (row, no file).
	if _, err := pg.NewNoteStore(pool).Upsert(ctx, domain.Note{ID: "pending", VaultID: vaultID, Path: "pending.md", Title: "Pending",
		CreatedAt: time.Now(), UpdatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}

	// Client-facing flags.
	status, view := call(http.MethodGet, "/api/vaults/"+vaultID.String(), token, nil)
	fed, _ := view["federation"].(map[string]any)
	if status != http.StatusOK || view["mirror"] != true || view["can_edit"] != false || fed["role"] != "mirror" || fed["mode"] != "mirror" {
		t.Fatalf("mirror view: %d %v", status, view)
	}
	if status, body := call(http.MethodGet, "/api/vaults/"+vaultID.String()+"/notes/"+noteID+"/content", token, nil); status != http.StatusOK {
		t.Fatalf("read on a mirror: %d %v", status, body)
	}
	if status, body := call(http.MethodGet, "/api/vaults/"+vaultID.String()+"/notes/pending/content", token, nil); status != http.StatusConflict || body["error"] != "mirror_syncing" {
		t.Fatalf("content not landed yet: %d %v", status, body)
	}

	// Every write route that names a vault.
	body := map[string]any{
		"title": "x", "body": "y", "name": "renamed", "tags": []string{"t"}, "path": "moved.md",
		"user_id": owner.ID, "role_id": roleID, "member_key": "eve@https://other.test",
		"capabilities": []string{"note.read"}, "max_uses": 1, "expires_at": time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
		"text": "y", "origin": "web", "mode": "mirror",
	}
	params := strings.NewReplacer(":vault", vaultID.String(), ":id", noteID, ":user", owner.ID.String(),
		":role", roleID, ":token", "sometoken")
	seen := map[string]bool{}
	var checked []string
	for _, r := range app.GetRoutes(true) {
		if !strings.HasPrefix(r.Path, "/api/") || !strings.Contains(r.Path, ":vault") {
			continue
		}
		switch r.Method {
		case fiber.MethodPost, fiber.MethodPatch, fiber.MethodPut, fiber.MethodDelete:
		default:
			continue
		}
		key := r.Method + " " + r.Path
		if seen[key] {
			continue
		}
		seen[key] = true
		checked = append(checked, key)
		status, out := call(r.Method, params.Replace(r.Path), token, body)
		if why, ok := mirrorRouteExceptions[key]; ok {
			if out["error"] == "mirror_read_only" {
				t.Errorf("%s (%s) refused as mirror_read_only", key, why)
			}
			continue
		}
		if status != http.StatusForbidden || out["error"] != "mirror_read_only" {
			t.Errorf("%s on a mirror: %d %v, want 403 mirror_read_only", key, status, out)
		}
	}
	sort.Strings(checked)
	t.Logf("checked %d write routes:\n%s", len(checked), strings.Join(checked, "\n"))
	if len(checked) < 20 {
		t.Fatalf("only %d write routes found: route discovery broken", len(checked))
	}
	// Nothing changed underneath.
	if status, body := call(http.MethodGet, "/api/vaults/"+vaultID.String()+"/notes/"+noteID+"/content", token, nil); status != http.StatusOK || body["body"] != "text" {
		t.Fatalf("note changed on a mirror: %d %v", status, body)
	}
	status, view = call(http.MethodGet, "/api/vaults/"+vaultID.String(), token, nil)
	if status != http.StatusOK || view["name"] != "Mirror "+suffix {
		t.Fatalf("vault changed on a mirror: %v", view)
	}

	// Promotion (CLI) lifts the clamp: the same owner may write again.
	svc, err := buildCLIAdmin(ctx, cfg, zerolog.Nop(), pool, fsMgr)
	if err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	e := &cliEnv{in: strings.NewReader(""), out: &out, err: &errb,
		open: func(context.Context) (*admin.Service, func(), error) { return svc, func() {}, nil }}
	if code := e.run(ctx, []string{"mirror", "promote", vaultID.String()}); code == 0 {
		t.Fatal("promote without --confirm accepted")
	}
	if code := e.run(ctx, []string{"mirror", "promote", vaultID.String(), "--confirm"}); code != 0 {
		t.Fatalf("promote: %d %s", code, errb.String())
	}
	if !strings.Contains(out.String(), "promoted mirror") {
		t.Fatalf("promote output %q", out.String())
	}
	// The running app's caches expire within their TTLs (15 s / 30 s).
	deadline := time.Now().Add(45 * time.Second)
	for {
		status, view = call(http.MethodGet, "/api/vaults/"+vaultID.String(), token, nil)
		if status == http.StatusOK && view["mirror"] == false && view["can_edit"] == true {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("promoted vault still read-only: %v", view)
		}
		time.Sleep(time.Second)
	}
	if status, body := call(http.MethodPatch, "/api/vaults/"+vaultID.String()+"/notes/"+noteID, token, map[string]string{"body": "after promote"}); status != http.StatusOK {
		t.Fatalf("write after promote: %d %v", status, body)
	}
}
