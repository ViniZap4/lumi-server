package notes

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/ViniZap4/lumi-server/internal/domain"
	"github.com/ViniZap4/lumi-server/internal/storage/fs"
)

type fakeNoteRepo struct {
	byVault map[uuid.UUID][]domain.Note
}

func (f *fakeNoteRepo) Upsert(_ context.Context, n domain.Note) error {
	f.byVault[n.VaultID] = append(f.byVault[n.VaultID], n)
	return nil
}

func (f *fakeNoteRepo) Get(_ context.Context, vaultID uuid.UUID, id string) (domain.Note, error) {
	for _, n := range f.byVault[vaultID] {
		if n.ID == id {
			return n, nil
		}
	}
	return domain.Note{}, domain.ErrNotFound
}

func (f *fakeNoteRepo) GetByPath(_ context.Context, vaultID uuid.UUID, path string) (domain.Note, error) {
	for _, n := range f.byVault[vaultID] {
		if n.Path == path {
			return n, nil
		}
	}
	return domain.Note{}, domain.ErrNotFound
}

func (f *fakeNoteRepo) ListForVault(_ context.Context, vaultID uuid.UUID, limit, offset int) ([]domain.Note, error) {
	all := f.byVault[vaultID]
	if offset >= len(all) {
		return nil, nil
	}
	end := offset + limit
	if end > len(all) {
		end = len(all)
	}
	return all[offset:end], nil
}

func (f *fakeNoteRepo) Delete(_ context.Context, vaultID uuid.UUID, id string) error { return nil }

type fakeVaultLookup struct {
	byID map[uuid.UUID]domain.Vault
}

func (f *fakeVaultLookup) GetByID(_ context.Context, id uuid.UUID) (domain.Vault, error) {
	v, ok := f.byID[id]
	if !ok {
		return domain.Vault{}, domain.ErrNotFound
	}
	return v, nil
}

type fakeCopyResolver struct{}

func (fakeCopyResolver) RoleForUser(context.Context, uuid.UUID, uuid.UUID) (domain.Role, error) {
	return domain.Role{Capabilities: domain.CapabilitySet{domain.CapAll}}, nil
}

func TestCopyVaultNotes_CopiesFilesAndRows(t *testing.T) {
	mgr, err := fs.NewManager(t.TempDir())
	if err != nil {
		t.Fatalf("fs manager: %v", err)
	}
	srcID, dstID := uuid.New(), uuid.New()
	lookup := &fakeVaultLookup{byID: map[uuid.UUID]domain.Vault{
		srcID: {ID: srcID, Slug: "src-vault"},
		dstID: {ID: dstID, Slug: "dst-vault"},
	}}
	if _, err := mgr.EnsureVaultDir("src-vault"); err != nil {
		t.Fatal(err)
	}
	if _, err := mgr.EnsureVaultDir("dst-vault"); err != nil {
		t.Fatal(err)
	}

	repo := &fakeNoteRepo{byVault: map[uuid.UUID][]domain.Note{}}
	// Seed three source notes, one inside a subfolder, one with frontmatter.
	seed := []struct {
		id, path, body string
		front          map[string]any
	}{
		{"alpha", "alpha.md", "# Alpha\n", map[string]any{"id": "alpha", "title": "Alpha"}},
		{"beta", "beta.md", "plain body, no frontmatter\n", nil},
		{"gamma", "sub/gamma.md", "# Gamma\n", map[string]any{"id": "gamma", "title": "Gamma"}},
	}
	for _, s := range seed {
		if err := mgr.WriteNote("src-vault", s.path, s.front, []byte(s.body)); err != nil {
			t.Fatalf("seed %s: %v", s.path, err)
		}
		repo.byVault[srcID] = append(repo.byVault[srcID], domain.Note{ID: s.id, VaultID: srcID, Path: s.path, Title: s.id})
	}

	svc := NewService(repo, lookup, mgr, nil, fakeCopyResolver{}, nil, nil)

	copied, err := svc.CopyVaultNotes(context.Background(), srcID, dstID, uuid.New())
	if err != nil {
		t.Fatalf("CopyVaultNotes: %v", err)
	}
	if copied != 3 {
		t.Fatalf("copied = %d, want 3", copied)
	}
	if len(repo.byVault[dstID]) != 3 {
		t.Fatalf("dst rows = %d, want 3", len(repo.byVault[dstID]))
	}
	for _, n := range repo.byVault[dstID] {
		if n.VaultID != dstID {
			t.Fatalf("row %s kept source vault id", n.ID)
		}
	}
	// Files landed under the destination slug with content intact.
	_, body, err := mgr.ReadNote("dst-vault", "sub/gamma.md")
	if err != nil {
		t.Fatalf("read copied nested note: %v", err)
	}
	if !strings.Contains(string(body), "Gamma") {
		t.Fatalf("copied body lost content: %q", body)
	}
}

func TestCopyVaultNotes_SourceVaultMissing(t *testing.T) {
	mgr, err := fs.NewManager(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	repo := &fakeNoteRepo{byVault: map[uuid.UUID][]domain.Note{}}
	lookup := &fakeVaultLookup{byID: map[uuid.UUID]domain.Vault{}}
	svc := NewService(repo, lookup, mgr, nil, fakeCopyResolver{}, nil, nil)

	if _, err := svc.CopyVaultNotes(context.Background(), uuid.New(), uuid.New(), uuid.New()); err == nil {
		t.Fatalf("want error for missing source vault")
	}
}
