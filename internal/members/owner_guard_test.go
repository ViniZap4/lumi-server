package members

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/ViniZap4/lumi-server/internal/domain"
)

type fakeRepo struct {
	members   map[string]domain.Member
	roles     map[uuid.UUID]domain.Role // roleID -> role
	soleAdmin map[string]bool           // vaultID/userID -> sole
	removed   []string
	changed   []string
}

func key(vaultID, userID uuid.UUID) string { return vaultID.String() + "/" + userID.String() }

func newFakeRepo() *fakeRepo {
	return &fakeRepo{
		members:   map[string]domain.Member{},
		roles:     map[uuid.UUID]domain.Role{},
		soleAdmin: map[string]bool{},
	}
}

func (f *fakeRepo) Add(_ context.Context, m domain.Member) error {
	f.members[key(m.VaultID, m.UserID)] = m
	return nil
}

func (f *fakeRepo) Remove(_ context.Context, vaultID, userID uuid.UUID) error {
	k := key(vaultID, userID)
	delete(f.members, k)
	f.removed = append(f.removed, k)
	return nil
}

func (f *fakeRepo) ChangeRole(_ context.Context, vaultID, userID, newRoleID uuid.UUID) error {
	k := key(vaultID, userID)
	m := f.members[k]
	m.RoleID = newRoleID
	f.members[k] = m
	f.changed = append(f.changed, k)
	return nil
}

func (f *fakeRepo) Get(_ context.Context, vaultID, userID uuid.UUID) (domain.Member, error) {
	m, ok := f.members[key(vaultID, userID)]
	if !ok {
		return domain.Member{}, domain.ErrNotFound
	}
	return m, nil
}

func (f *fakeRepo) ListForVault(_ context.Context, vaultID uuid.UUID) ([]MemberJoined, error) {
	var out []MemberJoined
	for _, m := range f.members {
		if m.VaultID != vaultID {
			continue
		}
		out = append(out, MemberJoined{Member: m, Role: f.roles[m.RoleID]})
	}
	// Include every known role so role-lookup-by-id in ChangeRole works even
	// when no member currently holds it.
	for id, r := range f.roles {
		found := false
		for _, mj := range out {
			if mj.Role.ID == id {
				found = true
				break
			}
		}
		if !found {
			out = append(out, MemberJoined{Role: r})
		}
	}
	return out, nil
}

func (f *fakeRepo) IsSoleAdmin(_ context.Context, vaultID, userID uuid.UUID) (bool, error) {
	return f.soleAdmin[key(vaultID, userID)], nil
}

func (f *fakeRepo) RoleForUser(_ context.Context, vaultID, userID uuid.UUID) (domain.Role, error) {
	m, ok := f.members[key(vaultID, userID)]
	if !ok {
		return domain.Role{}, domain.ErrNotFound
	}
	return f.roles[m.RoleID], nil
}

type fakeVaults struct {
	owners map[uuid.UUID]uuid.UUID // vaultID -> owner
}

func (f *fakeVaults) GetByID(_ context.Context, id uuid.UUID) (domain.Vault, error) {
	owner, ok := f.owners[id]
	if !ok {
		return domain.Vault{}, domain.ErrNotFound
	}
	return domain.Vault{ID: id, OwnerUserID: owner}, nil
}

type guardFixture struct {
	svc       *Service
	repo      *fakeRepo
	vaultID   uuid.UUID
	owner     uuid.UUID
	editor    uuid.UUID
	adminRole domain.Role
	editRole  domain.Role
}

func newGuardFixture(t *testing.T) *guardFixture {
	t.Helper()
	repo := newFakeRepo()
	vaultID, owner, editor := uuid.New(), uuid.New(), uuid.New()

	admin := domain.Role{ID: uuid.New(), VaultID: vaultID, Name: "Admin", IsSeed: true}
	editRole := domain.Role{ID: uuid.New(), VaultID: vaultID, Name: "Editor", IsSeed: true}
	repo.roles[admin.ID] = admin
	repo.roles[editRole.ID] = editRole
	repo.members[key(vaultID, owner)] = domain.Member{VaultID: vaultID, UserID: owner, RoleID: admin.ID}
	repo.members[key(vaultID, editor)] = domain.Member{VaultID: vaultID, UserID: editor, RoleID: editRole.ID}

	svc := NewService(repo, nil)
	svc.SetVaultLookup(&fakeVaults{owners: map[uuid.UUID]uuid.UUID{vaultID: owner}})
	return &guardFixture{svc: svc, repo: repo, vaultID: vaultID, owner: owner, editor: editor, adminRole: admin, editRole: editRole}
}

func TestRemove_OwnerProtected(t *testing.T) {
	fx := newGuardFixture(t)
	err := fx.svc.Remove(context.Background(), fx.vaultID, fx.owner, fx.editor, "", "")
	if !IsOwnerProtection(err) {
		t.Fatalf("want ErrOwnerProtection, got %v", err)
	}
	if len(fx.repo.removed) != 0 {
		t.Fatalf("owner was removed: %v", fx.repo.removed)
	}
}

func TestRemove_NonOwnerStillWorks(t *testing.T) {
	fx := newGuardFixture(t)
	if err := fx.svc.Remove(context.Background(), fx.vaultID, fx.editor, fx.owner, "", ""); err != nil {
		t.Fatalf("remove editor: %v", err)
	}
	if len(fx.repo.removed) != 1 {
		t.Fatalf("editor not removed")
	}
}

func TestChangeRole_OwnerDemotionBlocked(t *testing.T) {
	fx := newGuardFixture(t)
	err := fx.svc.ChangeRole(context.Background(), fx.vaultID, fx.owner, fx.editRole.ID, fx.owner, "", "")
	if !IsOwnerProtection(err) {
		t.Fatalf("want ErrOwnerProtection on owner demotion, got %v", err)
	}
	if len(fx.repo.changed) != 0 {
		t.Fatalf("owner role changed: %v", fx.repo.changed)
	}
}

func TestChangeRole_OwnerToAdminSeedAllowed(t *testing.T) {
	fx := newGuardFixture(t)
	// Move the owner off Admin first in the fixture data (simulate a custom
	// state), then confirm changing them TO the seed Admin role is allowed.
	fx.repo.members[key(fx.vaultID, fx.owner)] = domain.Member{VaultID: fx.vaultID, UserID: fx.owner, RoleID: fx.editRole.ID}
	if err := fx.svc.ChangeRole(context.Background(), fx.vaultID, fx.owner, fx.adminRole.ID, fx.owner, "", ""); err != nil {
		t.Fatalf("owner -> Admin should be allowed: %v", err)
	}
}

func TestChangeRole_NonOwnerUnaffected(t *testing.T) {
	fx := newGuardFixture(t)
	if err := fx.svc.ChangeRole(context.Background(), fx.vaultID, fx.editor, fx.adminRole.ID, fx.owner, "", ""); err != nil {
		t.Fatalf("promote editor: %v", err)
	}
}

func TestGuards_NoVaultLookupFallsBackToSoleAdmin(t *testing.T) {
	fx := newGuardFixture(t)
	fx.svc.SetVaultLookup(nil)
	fx.repo.soleAdmin[key(fx.vaultID, fx.owner)] = true

	err := fx.svc.Remove(context.Background(), fx.vaultID, fx.owner, fx.editor, "", "")
	if !IsSoleAdminProtection(err) {
		t.Fatalf("want sole-admin protection without vault lookup, got %v", err)
	}
}
