package vaults

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"

	"github.com/ViniZap4/lumi-server/internal/domain"
	"github.com/ViniZap4/lumi-server/internal/storage/fs"
)

// memberResolver resolves roles from the fixture's member + role fakes, the
// way the real members service does.
type memberResolver struct {
	members *fakeMembers
	roles   *fakeRoles
}

func (r memberResolver) RoleForUser(ctx context.Context, vaultID, userID uuid.UUID) (domain.Role, error) {
	if _, err := r.members.Get(ctx, vaultID, userID); err != nil {
		return domain.Role{}, err
	}
	return r.roles.GetByName(ctx, vaultID, "Admin")
}

type fixedHeads struct{ head int64 }

func (f fixedHeads) Heads(_ context.Context, ids []uuid.UUID) (map[uuid.UUID]int64, error) {
	out := make(map[uuid.UUID]int64, len(ids))
	for _, id := range ids {
		out[id] = f.head
	}
	return out, nil
}

type noFederations struct{}

func (noFederations) ListForVault(context.Context, uuid.UUID) ([]domain.Federation, error) {
	return nil, nil
}

func TestCreateHandler_ReturnsViewShape(t *testing.T) {
	mgr, err := fs.NewManager(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	repo, roles, members := newFakeVaultRepo(), newFakeRoles(), newFakeMembers()
	svc := NewService(repo, roles, members, mgr, &captureAudit{}, memberResolver{members, roles})
	svc.SetFeedDeps(fixedHeads{head: 0}, noFederations{}, "https://a.example", nil)

	user := &domain.User{ID: uuid.New(), Username: "alice"}
	app := fiber.New()
	app.Use(func(c *fiber.Ctx) error {
		c.Locals(userIDKey, user)
		return c.Next()
	})
	NewHandlers(svc).Register(app.Group("/api"))

	req := httptest.NewRequest(http.MethodPost, "/api/vaults", strings.NewReader(`{"name":"Livro"}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, -1)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d, body %s", resp.StatusCode, body)
	}
	var created map[string]any
	if err := json.Unmarshal(body, &created); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"id", "slug", "name", "owner_user_id", "created_at", "head", "role", "can_edit", "federation"} {
		if _, ok := created[k]; !ok {
			t.Errorf("create response missing %q: %s", k, body)
		}
	}
	if created["role"] != "Admin" || created["can_edit"] != true {
		t.Errorf("role/can_edit = %v/%v, want Admin/true", created["role"], created["can_edit"])
	}
	fed, ok := created["federation"].(map[string]any)
	if !ok || fed["role"] != nil || fed["home_url"] != nil || fed["status"] != nil {
		t.Errorf("federation = %#v, want all-null object", created["federation"])
	}

	// Same keys as GET /api/vaults/:id.
	detailReq := httptest.NewRequest(http.MethodGet, "/api/vaults/"+created["id"].(string), nil)
	dresp, err := app.Test(detailReq, -1)
	if err != nil {
		t.Fatal(err)
	}
	dbody, _ := io.ReadAll(dresp.Body)
	var detail map[string]any
	if err := json.Unmarshal(dbody, &detail); err != nil {
		t.Fatal(err)
	}
	if len(detail) != len(created) {
		t.Errorf("detail has %d keys, create %d:\n detail %s\n create %s", len(detail), len(created), dbody, body)
	}
	for k := range detail {
		if _, ok := created[k]; !ok {
			t.Errorf("create response lacks detail key %q", k)
		}
	}
}
