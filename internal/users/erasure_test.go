package users

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/ViniZap4/lumi-server/internal/domain"
)

type fakeUserRepo struct {
	owned       []domain.Vault
	deleteCalls []bool // force flag per call
}

func (f *fakeUserRepo) GetByID(context.Context, uuid.UUID) (domain.User, error) {
	return domain.User{}, nil
}
func (f *fakeUserRepo) GetByUsername(context.Context, string) (domain.User, error) {
	return domain.User{}, nil
}
func (f *fakeUserRepo) UpdateDisplayName(context.Context, uuid.UUID, string) error { return nil }
func (f *fakeUserRepo) Delete(_ context.Context, _ uuid.UUID, force bool) error {
	f.deleteCalls = append(f.deleteCalls, force)
	return nil
}
func (f *fakeUserRepo) OwnedVaults(context.Context, uuid.UUID) ([]domain.Vault, error) {
	return f.owned, nil
}

type fakeConsents struct{}

func (fakeConsents) ListForUser(context.Context, uuid.UUID) ([]domain.Consent, error) {
	return nil, nil
}

type fakeAuditReader struct{}

func (fakeAuditReader) ListForUser(context.Context, uuid.UUID, int, int) ([]domain.AuditEntry, error) {
	return nil, nil
}
func (fakeAuditReader) LatestActionAt(context.Context, uuid.UUID, string) (any, error) {
	return nil, domain.ErrNotFound
}

type fakeRecorder struct{ entries []domain.AuditEntry }

func (f *fakeRecorder) Record(_ context.Context, e domain.AuditEntry) error {
	f.entries = append(f.entries, e)
	return nil
}

type fakeVaultLister struct{}

func (fakeVaultLister) ListForUser(context.Context, uuid.UUID) ([]domain.Vault, error) {
	return nil, nil
}

type fakeDirRemover struct{ removed []string }

func (f *fakeDirRemover) RemoveVaultDir(slug string) error {
	f.removed = append(f.removed, slug)
	return nil
}

func newErasureFixture(owned []domain.Vault) (*Service, *fakeUserRepo, *fakeRecorder, *fakeDirRemover) {
	repo := &fakeUserRepo{owned: owned}
	rec := &fakeRecorder{}
	svc := NewService(repo, fakeConsents{}, fakeAuditReader{}, rec, fakeVaultLister{})
	remover := &fakeDirRemover{}
	svc.SetVaultDirRemover(remover)
	return svc, repo, rec, remover
}

func TestDelete_OwnedVaultsBlockWithoutForce(t *testing.T) {
	ownedID := uuid.New()
	svc, repo, _, _ := newErasureFixture([]domain.Vault{{ID: ownedID, Slug: "mine"}})

	err := svc.Delete(context.Background(), uuid.New(), false, nil, nil)
	var soleErr SoleAdminError
	if !errors.As(err, &soleErr) {
		t.Fatalf("want SoleAdminError, got %v", err)
	}
	if len(soleErr.VaultIDs) != 1 || soleErr.VaultIDs[0] != ownedID {
		t.Fatalf("error must list the owned vault, got %v", soleErr.VaultIDs)
	}
	if !errors.Is(err, domain.ErrSoleAdminVaults) {
		t.Fatalf("must unwrap to ErrSoleAdminVaults")
	}
	if len(repo.deleteCalls) != 0 {
		t.Fatalf("repo.Delete must not run when blocked")
	}
}

func TestDelete_ForceRemovesOwnedVaultDirs(t *testing.T) {
	svc, repo, rec, remover := newErasureFixture([]domain.Vault{
		{ID: uuid.New(), Slug: "personal"},
		{ID: uuid.New(), Slug: "scratch"},
	})

	if err := svc.Delete(context.Background(), uuid.New(), true, nil, nil); err != nil {
		t.Fatalf("forced delete: %v", err)
	}
	if len(repo.deleteCalls) != 1 || !repo.deleteCalls[0] {
		t.Fatalf("repo.Delete not called with force: %v", repo.deleteCalls)
	}
	if len(remover.removed) != 2 {
		t.Fatalf("owned vault dirs not removed: %v", remover.removed)
	}
	if len(rec.entries) != 1 || rec.entries[0].Action != domain.ActionUserDelete {
		t.Fatalf("user.delete not audited: %+v", rec.entries)
	}
}

func TestDelete_NoOwnedVaultsNoDirRemoval(t *testing.T) {
	svc, repo, _, remover := newErasureFixture(nil)

	if err := svc.Delete(context.Background(), uuid.New(), false, nil, nil); err != nil {
		t.Fatalf("delete without owned vaults: %v", err)
	}
	if len(repo.deleteCalls) != 1 {
		t.Fatalf("repo.Delete not called")
	}
	if len(remover.removed) != 0 {
		t.Fatalf("no dirs should be removed: %v", remover.removed)
	}
}
