package federation

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"

	"github.com/ViniZap4/lumi-server/internal/capguard"
	"github.com/ViniZap4/lumi-server/internal/domain"
)

type capsResolver domain.CapabilitySet

func (r capsResolver) RoleForUser(context.Context, uuid.UUID, uuid.UUID) (domain.Role, error) {
	return domain.Role{Name: "r", Capabilities: domain.CapabilitySet(r)}, nil
}

// §A15.1: publishing is an owner decision: vault.manage on top of
// vault.federate. A plain mirror invite needs only vault.federate.
func TestCreateInvite_PublishNeedsVaultManage(t *testing.T) {
	fx := newFedFixture(t, "https://home.example")
	post := func(caps domain.CapabilitySet, body string) int {
		app := fiber.New()
		app.Use(func(c *fiber.Ctx) error { capguard.SetUserID(c, fx.vault.OwnerUserID); return c.Next() })
		NewHandlers(fx.svc, capsResolver(caps)).RegisterAuthed(app.Group("/api"))
		req := httptest.NewRequest("POST", "/api/vaults/"+fx.vault.ID.String()+"/federation-invites", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		resp, err := app.Test(req, -1)
		if err != nil {
			t.Fatal(err)
		}
		return resp.StatusCode
	}
	federateOnly := domain.CapabilitySet{domain.CapVaultFederate}
	both := domain.CapabilitySet{domain.CapVaultFederate, domain.CapVaultManage}
	publish := `{"mode":"mirror","publish":{"allowed":true,"scope":"flagged"}}`
	if got := post(federateOnly, publish); got != 403 {
		t.Fatalf("publish invite with vault.federate only: %d", got)
	}
	if got := post(federateOnly, `{"mode":"mirror"}`); got != 201 {
		t.Fatalf("private mirror invite: %d", got)
	}
	if got := post(both, publish); got != 201 {
		t.Fatalf("publish invite with vault.manage: %d", got)
	}
	if got := post(both, `{"mode":"mirror","publish":{"allowed":true,"scope":"folder:../x"}}`); got != 400 {
		t.Fatalf("bad scope: %d", got)
	}
}
