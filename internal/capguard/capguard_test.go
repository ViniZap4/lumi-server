package capguard

import (
	"context"
	"errors"
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"

	"github.com/google/uuid"

	"github.com/ViniZap4/lumi-server/internal/domain"
)

type mapResolver map[uuid.UUID]domain.Role

func (m mapResolver) RoleForUser(_ context.Context, _ uuid.UUID, userID uuid.UUID) (domain.Role, error) {
	r, ok := m[userID]
	if !ok {
		return domain.Role{}, domain.ErrNotFound
	}
	return r, nil
}

func TestAuthorizeGrant(t *testing.T) {
	vaultID, owner, inviter, manager, stranger := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	vault := domain.Vault{ID: vaultID, OwnerUserID: owner}
	admin := domain.Role{ID: uuid.New(), VaultID: vaultID, Name: "Admin", Capabilities: domain.CapabilitySet{domain.CapAll}}
	editor := domain.Role{ID: uuid.New(), VaultID: vaultID, Name: "Editor", Capabilities: domain.CapabilitySet{domain.CapNoteRead, domain.CapNoteEdit}}
	viewer := domain.Role{ID: uuid.New(), VaultID: vaultID, Name: "Viewer", Capabilities: domain.CapabilitySet{domain.CapNoteRead}}
	inviterRole := domain.Role{ID: uuid.New(), VaultID: vaultID, Capabilities: domain.CapabilitySet{domain.CapMembersInvite, domain.CapNoteRead}}
	managerRole := domain.Role{ID: uuid.New(), VaultID: vaultID, Capabilities: domain.CapabilitySet{domain.CapMembersManage, domain.CapNoteAll}}
	foreign := domain.Role{ID: uuid.New(), VaultID: uuid.New(), Capabilities: domain.CapabilitySet{domain.CapNoteRead}}

	res := mapResolver{inviter: inviterRole, manager: managerRole}

	cases := []struct {
		name    string
		actor   uuid.UUID
		target  domain.Role
		r       Resolver
		wantErr error
	}{
		{"owner grants admin", owner, admin, res, nil},
		{"owner exempt even without resolver", owner, admin, nil, nil},
		{"inviter grants viewer", inviter, viewer, res, nil},
		{"inviter cannot grant admin", inviter, admin, res, domain.ErrForbidden},
		{"inviter cannot grant editor", inviter, editor, res, domain.ErrForbidden},
		{"manager grants editor", manager, editor, res, nil},
		{"manager cannot grant admin", manager, admin, res, domain.ErrForbidden},
		{"non-member", stranger, viewer, res, domain.ErrForbidden},
		{"no resolver fails closed", inviter, viewer, nil, domain.ErrForbidden},
		{"foreign role rejected even for owner", owner, foreign, res, domain.ErrValidation},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := AuthorizeGrant(context.Background(), tc.r, vault, tc.actor, tc.target)
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("got %v, want %v", err, tc.wantErr)
			}
		})
	}
}

// A role clamped on a mirror vault answers mirror_read_only, not the
// generic capability_missing.
func TestRequire_MirrorReadOnlyBody(t *testing.T) {
	vaultID, uid := uuid.New(), uuid.New()
	admin := domain.Role{Name: "Admin", Capabilities: domain.CapabilitySet{domain.CapAll}}
	res := mapResolver{uid: admin.ClampToMirror()}
	app := fiber.New()
	app.Use(func(c *fiber.Ctx) error { SetUserID(c, uid); return c.Next() })
	app.Post("/vaults/:vault/x", RequireCapability(res, domain.CapNoteEdit), func(c *fiber.Ctx) error { return c.SendStatus(204) })
	app.Get("/vaults/:vault/x", RequireCapability(res, domain.CapNoteRead), func(c *fiber.Ctx) error { return c.SendStatus(204) })

	resp, _ := app.Test(httptest.NewRequest("POST", "/vaults/"+vaultID.String()+"/x", nil))
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 403 || !strings.Contains(string(body), `"error":"mirror_read_only"`) || !strings.Contains(string(body), `"capability":"note.edit"`) {
		t.Fatalf("write: %d %s", resp.StatusCode, body)
	}
	resp, _ = app.Test(httptest.NewRequest("GET", "/vaults/"+vaultID.String()+"/x", nil))
	if resp.StatusCode != 204 {
		t.Fatalf("read on a mirror: %d", resp.StatusCode)
	}
}
