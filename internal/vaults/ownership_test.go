package vaults

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ViniZap4/lumi-server/internal/domain"
	"github.com/ViniZap4/lumi-server/internal/storage/fs"
)

// ---- fakes -------------------------------------------------------------------

type fakeVaultRepo struct {
	mu      sync.Mutex
	rows    map[uuid.UUID]domain.Vault
	deleted []uuid.UUID
}

func newFakeVaultRepo() *fakeVaultRepo {
	return &fakeVaultRepo{rows: map[uuid.UUID]domain.Vault{}}
}

func (f *fakeVaultRepo) Create(_ context.Context, v domain.Vault) (domain.Vault, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, existing := range f.rows {
		if existing.Slug == v.Slug {
			return domain.Vault{}, fmt.Errorf("dup slug: %w", domain.ErrConflict)
		}
	}
	f.rows[v.ID] = v
	return v, nil
}

func (f *fakeVaultRepo) GetByID(_ context.Context, id uuid.UUID) (domain.Vault, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.rows[id]
	if !ok {
		return domain.Vault{}, domain.ErrNotFound
	}
	return v, nil
}

func (f *fakeVaultRepo) GetBySlug(_ context.Context, slug string) (domain.Vault, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, v := range f.rows {
		if v.Slug == slug {
			return v, nil
		}
	}
	return domain.Vault{}, domain.ErrNotFound
}

func (f *fakeVaultRepo) ListForUser(context.Context, uuid.UUID) ([]domain.Vault, error) {
	return nil, nil
}

func (f *fakeVaultRepo) UpdateName(_ context.Context, id uuid.UUID, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	v := f.rows[id]
	v.Name = name
	f.rows[id] = v
	return nil
}

func (f *fakeVaultRepo) UpdateOwner(_ context.Context, id, newOwner uuid.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.rows[id]
	if !ok {
		return domain.ErrNotFound
	}
	v.OwnerUserID = newOwner
	f.rows[id] = v
	return nil
}

func (f *fakeVaultRepo) SetCopiedFrom(_ context.Context, id uuid.UUID, provenance []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.rows[id]
	if !ok {
		return domain.ErrNotFound
	}
	v.CopiedFrom = provenance
	f.rows[id] = v
	return nil
}

func (f *fakeVaultRepo) Delete(_ context.Context, id uuid.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.rows[id]; !ok {
		return domain.ErrNotFound
	}
	delete(f.rows, id)
	f.deleted = append(f.deleted, id)
	return nil
}

type fakeRoles struct {
	adminByVault map[uuid.UUID]domain.Role
}

func newFakeRoles() *fakeRoles { return &fakeRoles{adminByVault: map[uuid.UUID]domain.Role{}} }

func (f *fakeRoles) SeedForVault(_ context.Context, vaultID uuid.UUID) ([]domain.Role, error) {
	admin := domain.Role{ID: uuid.New(), VaultID: vaultID, Name: "Admin", Capabilities: domain.CapabilitySet{domain.CapAll}, IsSeed: true}
	f.adminByVault[vaultID] = admin
	return []domain.Role{admin}, nil
}

func (f *fakeRoles) GetByName(_ context.Context, vaultID uuid.UUID, name string) (domain.Role, error) {
	if name != "Admin" {
		return domain.Role{}, domain.ErrNotFound
	}
	r, ok := f.adminByVault[vaultID]
	if !ok {
		return domain.Role{}, domain.ErrNotFound
	}
	return r, nil
}

type fakeMembers struct {
	mu          sync.Mutex
	members     map[string]domain.Member // key vaultID/userID
	roleChanges []string
}

func newFakeMembers() *fakeMembers { return &fakeMembers{members: map[string]domain.Member{}} }

func memberKey(vaultID, userID uuid.UUID) string { return vaultID.String() + "/" + userID.String() }

func (f *fakeMembers) Add(_ context.Context, m domain.Member) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.members[memberKey(m.VaultID, m.UserID)] = m
	return nil
}

func (f *fakeMembers) Get(_ context.Context, vaultID, userID uuid.UUID) (domain.Member, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	m, ok := f.members[memberKey(vaultID, userID)]
	if !ok {
		return domain.Member{}, domain.ErrNotFound
	}
	return m, nil
}

func (f *fakeMembers) ChangeRole(_ context.Context, vaultID, userID, newRoleID uuid.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	k := memberKey(vaultID, userID)
	m := f.members[k]
	m.RoleID = newRoleID
	f.members[k] = m
	f.roleChanges = append(f.roleChanges, k)
	return nil
}

type fakeUsers struct {
	byName map[string]domain.User
}

func (f *fakeUsers) GetByUsername(_ context.Context, username string) (domain.User, error) {
	u, ok := f.byName[username]
	if !ok {
		return domain.User{}, domain.ErrNotFound
	}
	return u, nil
}

type fakeCopier struct {
	calls int
	fail  bool
}

func (f *fakeCopier) CopyVaultNotes(context.Context, uuid.UUID, uuid.UUID, uuid.UUID) (int, error) {
	f.calls++
	if f.fail {
		return 0, fmt.Errorf("boom")
	}
	return 3, nil
}

type fakeResolver struct{}

func (fakeResolver) RoleForUser(context.Context, uuid.UUID, uuid.UUID) (domain.Role, error) {
	return domain.Role{Capabilities: domain.CapabilitySet{domain.CapAll}}, nil
}

type captureAudit struct {
	mu      sync.Mutex
	entries []domain.AuditEntry
}

func (c *captureAudit) Record(_ context.Context, e domain.AuditEntry) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = append(c.entries, e)
	return nil
}

func (c *captureAudit) actions() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]string, len(c.entries))
	for i, e := range c.entries {
		out[i] = e.Action
	}
	return out
}

// ---- harness -----------------------------------------------------------------

type ownershipFixture struct {
	svc     *Service
	repo    *fakeVaultRepo
	roles   *fakeRoles
	members *fakeMembers
	users   *fakeUsers
	copier  *fakeCopier
	audit   *captureAudit
}

func newOwnershipFixture(t *testing.T) *ownershipFixture {
	t.Helper()
	mgr, err := fs.NewManager(t.TempDir())
	if err != nil {
		t.Fatalf("fs manager: %v", err)
	}
	repo := newFakeVaultRepo()
	roles := newFakeRoles()
	members := newFakeMembers()
	users := &fakeUsers{byName: map[string]domain.User{}}
	copier := &fakeCopier{}
	rec := &captureAudit{}

	svc := NewService(repo, roles, members, mgr, rec, fakeResolver{})
	svc.SetOwnershipDeps(members, users, copier)
	svc.now = func() time.Time { return time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC) }
	return &ownershipFixture{svc: svc, repo: repo, roles: roles, members: members, users: users, copier: copier, audit: rec}
}

func (fx *ownershipFixture) createVault(t *testing.T, owner uuid.UUID, name string) domain.Vault {
	t.Helper()
	v, err := fx.svc.Create(context.Background(), CreateInput{Name: name, CreatedBy: owner})
	if err != nil {
		t.Fatalf("create vault: %v", err)
	}
	return v
}

// ---- transfer ----------------------------------------------------------------

func TestTransferOwnership_NonOwnerForbidden(t *testing.T) {
	fx := newOwnershipFixture(t)
	owner, stranger, target := uuid.New(), uuid.New(), uuid.New()
	v := fx.createVault(t, owner, "Team")

	_, err := fx.svc.TransferOwnership(context.Background(), v.ID, target, stranger, "", "")
	if !errorsIs(err, domain.ErrForbidden) {
		t.Fatalf("want ErrForbidden, got %v", err)
	}
}

func TestTransferOwnership_TargetMustBeMember(t *testing.T) {
	fx := newOwnershipFixture(t)
	owner, target := uuid.New(), uuid.New()
	v := fx.createVault(t, owner, "Team")

	_, err := fx.svc.TransferOwnership(context.Background(), v.ID, target, owner, "", "")
	if !errorsIs(err, domain.ErrValidation) {
		t.Fatalf("want ErrValidation for non-member target, got %v", err)
	}
}

func TestTransferOwnership_Success_PromotesAndAudits(t *testing.T) {
	fx := newOwnershipFixture(t)
	owner, target := uuid.New(), uuid.New()
	v := fx.createVault(t, owner, "Team")

	// Target joins with a non-admin role id.
	if err := fx.members.Add(context.Background(), domain.Member{VaultID: v.ID, UserID: target, RoleID: uuid.New()}); err != nil {
		t.Fatal(err)
	}

	got, err := fx.svc.TransferOwnership(context.Background(), v.ID, target, owner, "1.2.3.4", "ua")
	if err != nil {
		t.Fatalf("transfer: %v", err)
	}
	if got.OwnerUserID != target {
		t.Fatalf("owner not updated: %v", got.OwnerUserID)
	}
	stored, _ := fx.repo.GetByID(context.Background(), v.ID)
	if stored.OwnerUserID != target {
		t.Fatalf("repo owner not updated: %v", stored.OwnerUserID)
	}
	admin, _ := fx.roles.GetByName(context.Background(), v.ID, "Admin")
	m, _ := fx.members.Get(context.Background(), v.ID, target)
	if m.RoleID != admin.ID {
		t.Fatalf("target not promoted to Admin: role %v want %v", m.RoleID, admin.ID)
	}
	if !containsAction(fx.audit.actions(), domain.ActionVaultTransfer) {
		t.Fatalf("vault.transfer not audited: %v", fx.audit.actions())
	}
}

func TestTransferOwnership_SelfTransferNoop(t *testing.T) {
	fx := newOwnershipFixture(t)
	owner := uuid.New()
	v := fx.createVault(t, owner, "Team")

	got, err := fx.svc.TransferOwnership(context.Background(), v.ID, owner, owner, "", "")
	if err != nil {
		t.Fatalf("self transfer: %v", err)
	}
	if got.OwnerUserID != owner {
		t.Fatalf("owner changed on self transfer")
	}
	if containsAction(fx.audit.actions(), domain.ActionVaultTransfer) {
		t.Fatalf("self transfer must not audit a transfer")
	}
}

// ---- copy --------------------------------------------------------------------

func TestCopyToUser_RecipientNotFound(t *testing.T) {
	fx := newOwnershipFixture(t)
	owner := uuid.New()
	v := fx.createVault(t, owner, "Team")

	_, err := fx.svc.CopyToUser(context.Background(), v.ID, CopyInput{RecipientUsername: "ghost", Actor: owner})
	if !errorsIs(err, ErrRecipientNotFound) {
		t.Fatalf("want ErrRecipientNotFound, got %v", err)
	}
}

func TestCopyToUser_Success(t *testing.T) {
	fx := newOwnershipFixture(t)
	owner, recipientID := uuid.New(), uuid.New()
	fx.users.byName["bob"] = domain.User{ID: recipientID, Username: "bob"}
	src := fx.createVault(t, owner, "Team")

	dst, err := fx.svc.CopyToUser(context.Background(), src.ID, CopyInput{RecipientUsername: "bob", Actor: owner})
	if err != nil {
		t.Fatalf("copy: %v", err)
	}
	if dst.OwnerUserID != recipientID {
		t.Fatalf("copy owner = %v, want recipient %v", dst.OwnerUserID, recipientID)
	}
	if dst.ID == src.ID || dst.Slug == src.Slug {
		t.Fatalf("copy must mint a new identity: %v %v", dst.ID, dst.Slug)
	}
	if fx.copier.calls != 1 {
		t.Fatalf("copier calls = %d, want 1", fx.copier.calls)
	}
	var prov map[string]any
	if err := json.Unmarshal(dst.CopiedFrom, &prov); err != nil {
		t.Fatalf("copied_from not valid JSON: %v", err)
	}
	if prov["slug"] != src.Slug {
		t.Fatalf("provenance slug = %v, want %v", prov["slug"], src.Slug)
	}
	// Recipient is sole Admin member of the fork.
	admin, _ := fx.roles.GetByName(context.Background(), dst.ID, "Admin")
	m, err := fx.members.Get(context.Background(), dst.ID, recipientID)
	if err != nil || m.RoleID != admin.ID {
		t.Fatalf("recipient not Admin member of fork: %v %v", err, m)
	}
	if !containsAction(fx.audit.actions(), domain.ActionVaultCopy) {
		t.Fatalf("vault.copy not audited: %v", fx.audit.actions())
	}
}

func TestCopyToUser_RollbackOnCopierFailure(t *testing.T) {
	fx := newOwnershipFixture(t)
	owner, recipientID := uuid.New(), uuid.New()
	fx.users.byName["bob"] = domain.User{ID: recipientID, Username: "bob"}
	fx.copier.fail = true
	src := fx.createVault(t, owner, "Team")

	_, err := fx.svc.CopyToUser(context.Background(), src.ID, CopyInput{RecipientUsername: "bob", Actor: owner})
	if err == nil {
		t.Fatalf("want error from failing copier")
	}
	if len(fx.repo.deleted) != 1 {
		t.Fatalf("fork not rolled back: deleted=%v", fx.repo.deleted)
	}
	if containsAction(fx.audit.actions(), domain.ActionVaultCopy) {
		t.Fatalf("failed copy must not audit vault.copy")
	}
}

func TestCopyToUser_SlugCollisionRetries(t *testing.T) {
	fx := newOwnershipFixture(t)
	owner, recipientID := uuid.New(), uuid.New()
	fx.users.byName["bob"] = domain.User{ID: recipientID, Username: "bob"}
	src := fx.createVault(t, owner, "Team")
	// Occupy the natural fork slug so CopyToUser has to fall back.
	fx.createVault(t, owner, "Team (copy)")

	dst, err := fx.svc.CopyToUser(context.Background(), src.ID, CopyInput{RecipientUsername: "bob", Actor: owner})
	if err != nil {
		t.Fatalf("copy with collision: %v", err)
	}
	if dst.Slug == "team-copy" {
		t.Fatalf("expected an alternative slug, got the occupied one")
	}
}

// ---- helpers -----------------------------------------------------------------

func errorsIs(err, target error) bool { return errors.Is(err, target) }

func containsAction(actions []string, want string) bool {
	for _, a := range actions {
		if a == want {
			return true
		}
	}
	return false
}
