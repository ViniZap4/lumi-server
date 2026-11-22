package roles

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/ViniZap4/lumi-server/internal/domain"
)

type fakeRoleRepo struct{ roles map[uuid.UUID]domain.Role }

func (f *fakeRoleRepo) Create(_ context.Context, r domain.Role) (domain.Role, error) {
	r.ID = uuid.New()
	f.roles[r.ID] = r
	return r, nil
}
func (f *fakeRoleRepo) Get(_ context.Context, _ uuid.UUID, id uuid.UUID) (domain.Role, error) {
	r, ok := f.roles[id]
	if !ok {
		return domain.Role{}, domain.ErrNotFound
	}
	return r, nil
}
func (f *fakeRoleRepo) GetByName(context.Context, uuid.UUID, string) (domain.Role, error) {
	return domain.Role{}, domain.ErrNotFound
}
func (f *fakeRoleRepo) ListForVault(context.Context, uuid.UUID) ([]domain.Role, error) { return nil, nil }
func (f *fakeRoleRepo) Update(_ context.Context, r domain.Role) error {
	f.roles[r.ID] = r
	return nil
}
func (f *fakeRoleRepo) Delete(context.Context, uuid.UUID, uuid.UUID) error { return nil }
func (f *fakeRoleRepo) SeedForVault(context.Context, uuid.UUID) ([]domain.Role, error) {
	return nil, nil
}
func (f *fakeRoleRepo) CountMembersWithRole(context.Context, uuid.UUID) (int, error) { return 0, nil }
func (f *fakeRoleRepo) MembersWithRole(context.Context, uuid.UUID) ([]uuid.UUID, error) {
	return nil, nil
}

type fakeResolver map[uuid.UUID]domain.Role

func (f fakeResolver) RoleForUser(_ context.Context, _ uuid.UUID, u uuid.UUID) (domain.Role, error) {
	r, ok := f[u]
	if !ok {
		return domain.Role{}, domain.ErrNotFound
	}
	return r, nil
}

type fakeVaults map[uuid.UUID]domain.Vault

func (f fakeVaults) GetByID(_ context.Context, id uuid.UUID) (domain.Vault, error) {
	v, ok := f[id]
	if !ok {
		return domain.Vault{}, domain.ErrNotFound
	}
	return v, nil
}

func TestRoles_NoCapabilityEscalation(t *testing.T) {
	vaultID, owner, manager := uuid.New(), uuid.New(), uuid.New()
	managerCaps := domain.CapabilitySet{domain.CapRolesManage, domain.CapNoteRead, domain.CapNoteEdit}
	repo := &fakeRoleRepo{roles: map[uuid.UUID]domain.Role{}}
	strong := domain.Role{ID: uuid.New(), VaultID: vaultID, Name: "Strong",
		Capabilities: domain.CapabilitySet{domain.CapVaultManage, domain.CapNoteRead}}
	weak := domain.Role{ID: uuid.New(), VaultID: vaultID, Name: "Weak",
		Capabilities: domain.CapabilitySet{domain.CapNoteRead}}
	repo.roles[strong.ID], repo.roles[weak.ID] = strong, weak

	svc := NewService(repo, nil)
	svc.SetGrantDeps(fakeResolver{manager: {VaultID: vaultID, Capabilities: managerCaps}},
		fakeVaults{vaultID: {ID: vaultID, OwnerUserID: owner}})
	ctx := context.Background()

	if _, err := svc.Create(ctx, vaultID, "Root", domain.CapabilitySet{domain.CapAll}, manager, "", ""); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("manager creating '*' role: %v, want ErrForbidden", err)
	}
	if _, err := svc.Create(ctx, vaultID, "Mods", domain.CapabilitySet{domain.CapMembersManage}, manager, "", ""); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("manager creating members.manage role: %v, want ErrForbidden", err)
	}
	if _, err := svc.Create(ctx, vaultID, "Writers", domain.CapabilitySet{domain.CapNoteEdit}, manager, "", ""); err != nil {
		t.Fatalf("covered role: %v", err)
	}
	if _, err := svc.Create(ctx, vaultID, "Root", domain.CapabilitySet{domain.CapAll}, owner, "", ""); err != nil {
		t.Fatalf("owner may create any role: %v", err)
	}

	all := domain.CapabilitySet{domain.CapAll}
	if err := svc.Update(ctx, vaultID, weak.ID, nil, &all, manager, "", ""); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("manager widening role to '*': %v", err)
	}
	if repo.roles[weak.ID].Capabilities.Has(domain.CapVaultManage) {
		t.Fatal("role was widened despite error")
	}
	readOnly := domain.CapabilitySet{domain.CapNoteRead}
	if err := svc.Update(ctx, vaultID, strong.ID, nil, &readOnly, manager, "", ""); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("manager editing a role that outranks them: %v", err)
	}
	if err := svc.Update(ctx, vaultID, weak.ID, nil, &domain.CapabilitySet{domain.CapNoteEdit}, manager, "", ""); err != nil {
		t.Fatalf("covered edit: %v", err)
	}
}

func TestRoles_UnconfiguredGrantDepsFailClosed(t *testing.T) {
	svc := NewService(&fakeRoleRepo{roles: map[uuid.UUID]domain.Role{}}, nil)
	if _, err := svc.Create(context.Background(), uuid.New(), "X", domain.CapabilitySet{domain.CapNoteRead}, uuid.New(), "", ""); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("got %v, want ErrForbidden", err)
	}
}
