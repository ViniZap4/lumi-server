package members

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/ViniZap4/lumi-server/internal/domain"
)

type fakeRoleLookup map[uuid.UUID]domain.Role

func (f fakeRoleLookup) GetByID(_ context.Context, id uuid.UUID) (domain.Role, error) {
	r, ok := f[id]
	if !ok {
		return domain.Role{}, domain.ErrNotFound
	}
	return r, nil
}

// TestChangeRole_NoEscalation is the regression test for the members.manage
// -> Admin escalation and for assigning roles from another vault.
func TestChangeRole_NoEscalation(t *testing.T) {
	type setup struct {
		fx             *guardFixture
		manager        uuid.UUID
		otherVaultRole domain.Role
		viewerRole     domain.Role
		managerRole    domain.Role
	}
	build := func(t *testing.T, withRoleLookup bool) setup {
		fx := newGuardFixture(t)
		manager := uuid.New()
		managerRole := domain.Role{ID: uuid.New(), VaultID: fx.vaultID, Name: "Manager",
			Capabilities: domain.CapabilitySet{domain.CapMembersManage, domain.CapNoteAll}}
		viewer := domain.Role{ID: uuid.New(), VaultID: fx.vaultID, Name: "Viewer", IsSeed: true,
			Capabilities: domain.CapabilitySet{domain.CapNoteRead}}
		other := domain.Role{ID: uuid.New(), VaultID: uuid.New(), Name: "Admin", IsSeed: true,
			Capabilities: domain.CapabilitySet{domain.CapAll}}
		fx.repo.roles[managerRole.ID] = managerRole
		fx.repo.roles[viewer.ID] = viewer
		fx.repo.members[key(fx.vaultID, manager)] = domain.Member{VaultID: fx.vaultID, UserID: manager, RoleID: managerRole.ID}
		if withRoleLookup {
			lk := fakeRoleLookup{}
			for id, r := range fx.repo.roles {
				lk[id] = r
			}
			lk[other.ID] = other
			fx.svc.SetRoleLookup(lk)
		}
		return setup{fx: fx, manager: manager, otherVaultRole: other, viewerRole: viewer, managerRole: managerRole}
	}

	for _, withLookup := range []bool{false, true} {
		name := "fallback"
		if withLookup {
			name = "role-lookup"
		}
		t.Run(name, func(t *testing.T) {
			cases := []struct {
				name    string
				actor   func(s setup) uuid.UUID
				target  func(s setup) uuid.UUID
				role    func(s setup) uuid.UUID
				wantErr error
			}{
				{"manager promotes editor to admin",
					func(s setup) uuid.UUID { return s.manager },
					func(s setup) uuid.UUID { return s.fx.editor },
					func(s setup) uuid.UUID { return s.fx.adminRole.ID }, domain.ErrForbidden},
				{"manager promotes self to admin",
					func(s setup) uuid.UUID { return s.manager },
					func(s setup) uuid.UUID { return s.manager },
					func(s setup) uuid.UUID { return s.fx.adminRole.ID }, domain.ErrForbidden},
				{"manager assigns foreign-vault role",
					func(s setup) uuid.UUID { return s.manager },
					func(s setup) uuid.UUID { return s.fx.editor },
					func(s setup) uuid.UUID { return s.otherVaultRole.ID }, domain.ErrValidation},
				{"owner assigns foreign-vault role",
					func(s setup) uuid.UUID { return s.fx.owner },
					func(s setup) uuid.UUID { return s.fx.editor },
					func(s setup) uuid.UUID { return s.otherVaultRole.ID }, domain.ErrValidation},
				{"manager demotes editor to viewer",
					func(s setup) uuid.UUID { return s.manager },
					func(s setup) uuid.UUID { return s.fx.editor },
					func(s setup) uuid.UUID { return s.viewerRole.ID }, nil},
				{"owner promotes editor to admin",
					func(s setup) uuid.UUID { return s.fx.owner },
					func(s setup) uuid.UUID { return s.fx.editor },
					func(s setup) uuid.UUID { return s.fx.adminRole.ID }, nil},
			}
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					s := build(t, withLookup)
					err := s.fx.svc.ChangeRole(context.Background(), s.fx.vaultID, tc.target(s), tc.role(s), tc.actor(s), "", "")
					if tc.wantErr == nil {
						if err != nil {
							t.Fatalf("unexpected error: %v", err)
						}
						return
					}
					if !errors.Is(err, tc.wantErr) {
						t.Fatalf("got %v, want %v", err, tc.wantErr)
					}
					if len(s.fx.repo.changed) != 0 {
						t.Fatalf("role was changed despite error: %v", s.fx.repo.changed)
					}
				})
			}
		})
	}
}

// A members.manage holder must not demote a member who holds more than
// they do (e.g. a second Admin).
func TestChangeRole_CannotDemoteSuperior(t *testing.T) {
	fx := newGuardFixture(t)
	manager, admin2 := uuid.New(), uuid.New()
	managerRole := domain.Role{ID: uuid.New(), VaultID: fx.vaultID, Name: "Manager",
		Capabilities: domain.CapabilitySet{domain.CapMembersManage, domain.CapNoteAll}}
	fx.repo.roles[managerRole.ID] = managerRole
	fx.repo.members[key(fx.vaultID, manager)] = domain.Member{VaultID: fx.vaultID, UserID: manager, RoleID: managerRole.ID}
	fx.repo.members[key(fx.vaultID, admin2)] = domain.Member{VaultID: fx.vaultID, UserID: admin2, RoleID: fx.adminRole.ID}

	err := fx.svc.ChangeRole(context.Background(), fx.vaultID, admin2, fx.editRole.ID, manager, "", "")
	if !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("want ErrForbidden demoting a superior, got %v", err)
	}
}

// A members.manage holder must not remove a member who holds capabilities
// they lack (a second Admin); the owner may, and anyone may leave.
func TestRemove_NoRemovingSuperiors(t *testing.T) {
	setup := func(t *testing.T) (*guardFixture, uuid.UUID, uuid.UUID) {
		fx := newGuardFixture(t)
		manager, admin2 := uuid.New(), uuid.New()
		managerRole := domain.Role{ID: uuid.New(), VaultID: fx.vaultID, Name: "Manager",
			Capabilities: domain.CapabilitySet{domain.CapMembersManage, domain.CapNoteAll}}
		fx.repo.roles[managerRole.ID] = managerRole
		fx.repo.members[key(fx.vaultID, manager)] = domain.Member{VaultID: fx.vaultID, UserID: manager, RoleID: managerRole.ID}
		fx.repo.members[key(fx.vaultID, admin2)] = domain.Member{VaultID: fx.vaultID, UserID: admin2, RoleID: fx.adminRole.ID}
		return fx, manager, admin2
	}
	t.Run("manager removes admin", func(t *testing.T) {
		fx, manager, admin2 := setup(t)
		err := fx.svc.Remove(context.Background(), fx.vaultID, admin2, manager, "", "")
		if !errors.Is(err, domain.ErrForbidden) || len(fx.repo.removed) != 0 {
			t.Fatalf("got %v removed=%v, want ErrForbidden", err, fx.repo.removed)
		}
	})
	t.Run("manager removes editor", func(t *testing.T) {
		fx, manager, _ := setup(t)
		if err := fx.svc.Remove(context.Background(), fx.vaultID, fx.editor, manager, "", ""); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("owner removes admin", func(t *testing.T) {
		fx, _, admin2 := setup(t)
		if err := fx.svc.Remove(context.Background(), fx.vaultID, admin2, fx.owner, "", ""); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("admin leaves", func(t *testing.T) {
		fx, _, admin2 := setup(t)
		if err := fx.svc.Remove(context.Background(), fx.vaultID, admin2, admin2, "", ""); err != nil {
			t.Fatal(err)
		}
	})
}
