package fs

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ViniZap4/lumi-server/internal/domain"
)

func newManager(t *testing.T) *Manager {
	t.Helper()
	root := resolveTempRoot(t)
	m, err := NewManager(root)
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	if err := m.EnsureRootDir(); err != nil {
		t.Fatalf("ensure root: %v", err)
	}
	return m
}

func TestManager_EnsureVaultDir_CreatesLayout(t *testing.T) {
	m := newManager(t)
	dir, err := m.EnsureVaultDir("personal")
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}
	if dir != filepath.Join(m.Root, "personal") {
		t.Fatalf("dir = %q", dir)
	}
	for _, sub := range []string{".lumi", filepath.Join(".lumi", "cache")} {
		st, err := os.Stat(filepath.Join(dir, sub))
		if err != nil {
			t.Fatalf("stat %s: %v", sub, err)
		}
		if !st.IsDir() {
			t.Fatalf("%s is not a dir", sub)
		}
	}

	if runtime.GOOS != "windows" {
		st, err := os.Stat(filepath.Join(dir, ".lumi"))
		if err != nil {
			t.Fatalf("stat .lumi: %v", err)
		}
		if st.Mode().Perm() != 0o700 {
			t.Fatalf(".lumi perm = %o, want 0700", st.Mode().Perm())
		}
	}
}

func TestManager_EnsureVaultDir_RejectsTraversal(t *testing.T) {
	m := newManager(t)
	if _, err := m.EnsureVaultDir("../escape"); err == nil {
		t.Fatal("expected ErrPathEscape")
	} else if !errors.Is(err, domain.ErrPathEscape) {
		t.Fatalf("err = %v", err)
	}
}

func TestManager_WriteAndReadVaultYAML(t *testing.T) {
	m := newManager(t)
	id := uuid.New()
	srvID := uuid.New()
	created := time.Date(2026, 4, 28, 10, 0, 0, 0, time.UTC)
	meta := VaultMetadata{
		ID:        id,
		Name:      "Work team",
		Slug:      "work-team",
		CreatedAt: created,
		Server: &VaultServerLink{
			URL:          "https://lumi.work.com",
			VaultID:      srvID,
			LastSyncedAt: created.Add(5 * time.Minute),
		},
		Members: []MemberSnapshot{
			{Username: "alice", Role: "Admin"},
			{Username: "bob", Role: "Editor"},
		},
		Roles: []RoleSnapshot{
			{Name: "Admin", Capabilities: []string{"*"}, IsSeed: true},
		},
	}
	if err := m.WriteVaultYAML("work-team", meta); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := m.ReadVaultYAML("work-team")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got.ID != id || got.Name != "Work team" || got.Slug != "work-team" {
		t.Fatalf("scalar mismatch: %#v", got)
	}
	if got.Server == nil || got.Server.URL != "https://lumi.work.com" || got.Server.VaultID != srvID {
		t.Fatalf("server mismatch: %#v", got.Server)
	}
	if len(got.Members) != 2 || got.Members[0].Username != "alice" {
		t.Fatalf("members mismatch: %#v", got.Members)
	}
	if len(got.Roles) != 1 || !got.Roles[0].IsSeed {
		t.Fatalf("roles mismatch: %#v", got.Roles)
	}

	if runtime.GOOS != "windows" {
		st, err := os.Stat(filepath.Join(m.Root, "work-team", ".lumi", "vault.yaml"))
		if err != nil {
			t.Fatalf("stat: %v", err)
		}
		if st.Mode().Perm() != 0o600 {
			t.Fatalf("vault.yaml perm = %o, want 0600", st.Mode().Perm())
		}
	}
}

func TestManager_ReadVaultYAML_NotFound(t *testing.T) {
	m := newManager(t)
	if _, err := m.ReadVaultYAML("ghost"); err == nil {
		t.Fatal("expected error")
	} else if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
}

func TestManager_RemoveVaultDir(t *testing.T) {
	m := newManager(t)
	if _, err := m.EnsureVaultDir("doomed"); err != nil {
		t.Fatalf("ensure: %v", err)
	}
	if err := m.RemoveVaultDir("doomed"); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if _, err := os.Stat(filepath.Join(m.Root, "doomed")); !os.IsNotExist(err) {
		t.Fatalf("expected removal, stat err = %v", err)
	}
	if err := m.RemoveVaultDir("doomed"); err != nil {
		t.Fatalf("second remove: %v", err)
	}
}

func TestManager_RemoveVaultDir_RejectsRoot(t *testing.T) {
	m := newManager(t)
	if err := m.RemoveVaultDir("."); err == nil {
		t.Fatal("expected error when slug resolves to root")
	} else if !errors.Is(err, domain.ErrPathEscape) {
		t.Fatalf("err = %v", err)
	}
	if _, err := os.Stat(m.Root); err != nil {
		t.Fatalf("root vanished: %v", err)
	}
}

func TestManager_NotePath_RejectsCrossVaultEscape(t *testing.T) {
	m := newManager(t)
	if _, err := m.EnsureVaultDir("a"); err != nil {
		t.Fatalf("ensure a: %v", err)
	}
	if _, err := m.EnsureVaultDir("b"); err != nil {
		t.Fatalf("ensure b: %v", err)
	}
	if _, err := m.NotePath("a", "../b/note.md"); err == nil {
		t.Fatal("expected ErrPathEscape across vaults")
	} else if !errors.Is(err, domain.ErrPathEscape) {
		t.Fatalf("err = %v", err)
	}
}

func TestManager_WriteReadDeleteNote(t *testing.T) {
	m := newManager(t)
	if _, err := m.EnsureVaultDir("personal"); err != nil {
		t.Fatalf("ensure: %v", err)
	}
	front := map[string]any{"id": "hello", "title": "Hello"}
	body := []byte("# Hi\n\nbody\n")
	if err := m.WriteNote("personal", "hello.md", front, body); err != nil {
		t.Fatalf("write: %v", err)
	}
	gotFront, gotBody, err := m.ReadNote("personal", "hello.md")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if gotFront["title"] != "Hello" {
		t.Fatalf("title = %#v", gotFront["title"])
	}
	if string(gotBody) == "" {
		t.Fatal("body empty")
	}

	if err := m.DeleteNote("personal", "hello.md"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if err := m.DeleteNote("personal", "hello.md"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("expected ErrNotFound on second delete, got %v", err)
	}
}

func TestManager_MoveNote(t *testing.T) {
	m := newManager(t)
	if _, err := m.EnsureVaultDir("personal"); err != nil {
		t.Fatalf("ensure: %v", err)
	}
	if err := m.WriteNote("personal", "src.md", map[string]any{"id": "src"}, []byte("x")); err != nil {
		t.Fatalf("write src: %v", err)
	}
	if err := m.MoveNote("personal", "src.md", "dst.md"); err != nil {
		t.Fatalf("move: %v", err)
	}
	if _, _, err := m.ReadNote("personal", "dst.md"); err != nil {
		t.Fatalf("read dst: %v", err)
	}
	if _, _, err := m.ReadNote("personal", "src.md"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("src still exists: %v", err)
	}
	if err := m.WriteNote("personal", "other.md", map[string]any{"id": "other"}, []byte("y")); err != nil {
		t.Fatalf("write other: %v", err)
	}
	if err := m.MoveNote("personal", "other.md", "dst.md"); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("expected ErrConflict, got %v", err)
	}
	if err := m.MoveNote("personal", "ghost.md", "wherever.md"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}
