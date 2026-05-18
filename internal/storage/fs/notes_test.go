package fs

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/ViniZap4/lumi-server/internal/domain"
)

// These tests cover the two-level (slug + relativePath) attack surface
// of Manager.WriteNote / ReadNote / DeleteNote / MoveNote. SafeJoin
// itself is already exhaustively tested in safejoin_test.go; here we
// confirm every Manager entrypoint funnels through it.

func newTestManager(t *testing.T) (*Manager, string) {
	t.Helper()
	root := t.TempDir()
	mgr, err := NewManager(root)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if err := mgr.EnsureRootDir(); err != nil {
		t.Fatalf("EnsureRootDir: %v", err)
	}
	if _, err := mgr.EnsureVaultDir("vault"); err != nil {
		t.Fatalf("EnsureVaultDir: %v", err)
	}
	return mgr, root
}

func TestManager_WriteNote_RejectsMaliciousSlugs(t *testing.T) {
	mgr, _ := newTestManager(t)
	cases := []struct {
		name, slug, path string
	}{
		{"parent traversal slug", "..", "note.md"},
		{"nested parent slug", "../etc", "note.md"},
		{"absolute slug", "/abs", "note.md"},
		{"null byte slug", "vault\x00ok", "note.md"},
		{"empty slug", "", "note.md"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := mgr.WriteNote(tc.slug, tc.path, map[string]any{}, []byte("x"))
			if err == nil {
				t.Fatalf("expected error for slug=%q", tc.slug)
			}
			// Slug "" is a validation error, the rest are path escapes.
			if tc.slug == "" {
				if !errors.Is(err, domain.ErrValidation) {
					t.Fatalf("expected ErrValidation for empty slug, got %v", err)
				}
				return
			}
			if !errors.Is(err, domain.ErrPathEscape) {
				t.Fatalf("expected ErrPathEscape, got %v", err)
			}
		})
	}
}

func TestManager_WriteNote_RejectsMaliciousRelPath(t *testing.T) {
	mgr, _ := newTestManager(t)
	cases := []string{
		"../escape.md",
		"sub/../../bypass.md",
		"/abs/escape.md",
		"\x00null.md",
		"..",
	}
	for _, p := range cases {
		t.Run(p, func(t *testing.T) {
			err := mgr.WriteNote("vault", p, map[string]any{}, []byte("x"))
			if err == nil {
				t.Fatalf("expected error for path=%q", p)
			}
			if !errors.Is(err, domain.ErrPathEscape) {
				t.Fatalf("expected ErrPathEscape, got %v", err)
			}
		})
	}
}

func TestManager_WriteNote_AllowsLegitimatePaths(t *testing.T) {
	mgr, root := newTestManager(t)
	good := []string{
		"note.md",
		"sub/note.md",
		"deep/nested/path/file.md",
		"unicode-ñòté.md",
	}
	for _, p := range good {
		t.Run(p, func(t *testing.T) {
			if err := mgr.WriteNote("vault", p, map[string]any{"title": "x"}, []byte("body")); err != nil {
				t.Fatalf("WriteNote(%q): %v", p, err)
			}
			abs := filepath.Join(root, "vault", filepath.FromSlash(p))
			if _, err := os.Stat(abs); err != nil {
				t.Fatalf("expected file at %s: %v", abs, err)
			}
		})
	}
}

func TestManager_ReadNote_DoesNotEscape(t *testing.T) {
	mgr, _ := newTestManager(t)
	if _, _, err := mgr.ReadNote("../", "passwd"); err == nil {
		t.Fatal("ReadNote with ../ slug should fail")
	}
	if _, _, err := mgr.ReadNote("vault", "../../etc/passwd"); err == nil {
		t.Fatal("ReadNote with traversal path should fail")
	}
}

func TestManager_DeleteNote_DoesNotEscape(t *testing.T) {
	mgr, _ := newTestManager(t)
	for _, slug := range []string{"..", "../etc", "/abs"} {
		if err := mgr.DeleteNote(slug, "x.md"); err == nil {
			t.Fatalf("DeleteNote with slug=%q should fail", slug)
		}
	}
	if err := mgr.DeleteNote("vault", "../escape.md"); err == nil {
		t.Fatal("DeleteNote with traversal path should fail")
	}
}

func TestManager_MoveNote_BothEndsValidated(t *testing.T) {
	mgr, _ := newTestManager(t)
	// Seed a legitimate note so the move has something to operate on.
	if err := mgr.WriteNote("vault", "src.md", map[string]any{}, []byte("x")); err != nil {
		t.Fatal(err)
	}

	// Malicious destination.
	if err := mgr.MoveNote("vault", "src.md", "../etc/passwd"); err == nil {
		t.Fatal("MoveNote should reject ../ destination")
	}
	// Malicious source.
	if err := mgr.MoveNote("vault", "../src.md", "dst.md"); err == nil {
		t.Fatal("MoveNote should reject ../ source")
	}
	// Malicious slug.
	if err := mgr.MoveNote("..", "src.md", "dst.md"); err == nil {
		t.Fatal("MoveNote should reject ../ slug")
	}
}

func TestManager_WriteNote_RejectsSymlinkEscape(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics differ on windows")
	}
	mgr, root := newTestManager(t)
	outside := t.TempDir()

	// Plant a symlink inside the vault pointing outside.
	link := filepath.Join(root, "vault", "trapdoor")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	// Writing through the symlink must be blocked. EvalSymlinks runs
	// at NotePath time so the joined path resolves to `outside/file.md`,
	// triggering ErrPathEscape.
	err := mgr.WriteNote("vault", "trapdoor/leak.md", map[string]any{}, []byte("evil"))
	if err == nil {
		t.Fatal("expected symlink escape to be blocked")
	}
	if !errors.Is(err, domain.ErrPathEscape) {
		t.Fatalf("expected ErrPathEscape, got %v", err)
	}
	// Confirm nothing was written outside.
	if _, statErr := os.Stat(filepath.Join(outside, "leak.md")); statErr == nil {
		t.Fatal("file written outside the root via symlink!")
	}
}

func TestManager_RemoveVaultDir_RefusesToDeleteRoot(t *testing.T) {
	mgr, _ := newTestManager(t)
	if err := mgr.RemoveVaultDir(""); err == nil || !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("expected validation error for empty slug, got %v", err)
	}
	if err := mgr.RemoveVaultDir(".."); err == nil {
		t.Fatal("RemoveVaultDir with .. should fail")
	}
	// A slug resolving to root itself (single dot) is malformed; the
	// underlying SafeJoin rejects ".." but allows "." → root. Manager
	// has an explicit guard for that case.
	if err := mgr.RemoveVaultDir("."); err == nil {
		t.Fatal("RemoveVaultDir resolving to root must fail")
	}
	if err := mgr.RemoveVaultDir("."); err != nil && !strings.Contains(err.Error(), "path escapes") {
		// Either ErrPathEscape (root resolve) or ErrValidation is fine.
	}
}
