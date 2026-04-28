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

func resolveTempRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatalf("eval symlinks on tempdir: %v", err)
	}
	return resolved
}

func TestSafeJoin_TableDriven(t *testing.T) {
	root := resolveTempRoot(t)
	if err := os.MkdirAll(filepath.Join(root, "ok"), 0o755); err != nil {
		t.Fatalf("mkdir ok: %v", err)
	}

	cases := []struct {
		name       string
		userPath   string
		wantErr    bool
		wantInside bool
	}{
		{name: "empty path resolves to root", userPath: "", wantErr: false, wantInside: true},
		{name: "dot resolves to root", userPath: ".", wantErr: false, wantInside: true},
		{name: "simple relative path", userPath: "ok/path", wantErr: false, wantInside: true},
		{name: "trailing slash allowed", userPath: "ok/path/", wantErr: false, wantInside: true},
		{name: "nested relative path", userPath: "a/b/c/d", wantErr: false, wantInside: true},
		{name: "self-referential dot in middle", userPath: "ok/./path", wantErr: false, wantInside: true},

		{name: "parent traversal rejected", userPath: "../escape", wantErr: true},
		{name: "embedded parent rejected", userPath: "ok/../../escape", wantErr: true},
		{name: "leaf parent rejected", userPath: "..", wantErr: true},
		{name: "absolute unix path rejected", userPath: "/abs/path", wantErr: true},
		{name: "null byte rejected", userPath: "ok\x00bad", wantErr: true},
		{name: "windows drive rejected", userPath: "C:\\windows", wantErr: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := SafeJoin(root, tc.userPath)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %q", got)
				}
				if !errors.Is(err, domain.ErrPathEscape) {
					t.Fatalf("expected ErrPathEscape, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !tc.wantInside {
				return
			}
			if !strings.HasPrefix(got, root) {
				t.Fatalf("result %q is not inside root %q", got, root)
			}
		})
	}
}

func TestSafeJoin_RejectsSymlinkEscape(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics differ on windows")
	}
	root := resolveTempRoot(t)
	outside := t.TempDir()
	outsideResolved, err := filepath.EvalSymlinks(outside)
	if err != nil {
		t.Fatalf("eval outside: %v", err)
	}
	link := filepath.Join(root, "trapdoor")
	if err := os.Symlink(outsideResolved, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if _, err := SafeJoin(root, "trapdoor/secret.txt"); err == nil {
		t.Fatal("expected ErrPathEscape on symlink traversal")
	} else if !errors.Is(err, domain.ErrPathEscape) {
		t.Fatalf("expected ErrPathEscape, got %v", err)
	}
	if _, err := SafeJoin(root, "trapdoor"); err == nil {
		t.Fatal("expected ErrPathEscape on direct symlink to outside")
	} else if !errors.Is(err, domain.ErrPathEscape) {
		t.Fatalf("expected ErrPathEscape, got %v", err)
	}
}

func TestSafeJoin_AllowsSymlinkInsideRoot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics differ on windows")
	}
	root := resolveTempRoot(t)
	target := filepath.Join(root, "real")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatalf("mkdir real: %v", err)
	}
	link := filepath.Join(root, "alias")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	got, err := SafeJoin(root, "alias/file.md")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(got, root) {
		t.Fatalf("result %q outside root %q", got, root)
	}
}

func TestSafeJoin_NonExistentLeafIsAllowed(t *testing.T) {
	root := resolveTempRoot(t)
	got, err := SafeJoin(root, "future/note.md")
	if err != nil {
		t.Fatalf("unexpected error for non-existent leaf: %v", err)
	}
	want := filepath.Join(root, "future", "note.md")
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestSafeJoin_RejectsRootSibling(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics differ on windows")
	}
	parent := resolveTempRoot(t)
	root := filepath.Join(parent, "vault")
	sibling := filepath.Join(parent, "vault-evil")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatalf("mkdir root: %v", err)
	}
	if err := os.MkdirAll(sibling, 0o755); err != nil {
		t.Fatalf("mkdir sibling: %v", err)
	}
	link := filepath.Join(root, "side")
	if err := os.Symlink(sibling, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if _, err := SafeJoin(root, "side/file.md"); err == nil {
		t.Fatal("expected ErrPathEscape via sibling symlink")
	} else if !errors.Is(err, domain.ErrPathEscape) {
		t.Fatalf("expected ErrPathEscape, got %v", err)
	}
}

func TestSafeJoin_RejectsRelativeRoot(t *testing.T) {
	if _, err := SafeJoin("relative/root", "x"); err == nil {
		t.Fatal("expected error on relative root")
	}
}

func TestSafeJoin_LexicallyInside(t *testing.T) {
	cases := []struct {
		parent, child string
		want          bool
	}{
		{"/a", "/a", true},
		{"/a", "/a/b", true},
		{"/a", "/a/b/c", true},
		{"/a", "/ab", false},
		{"/a/b", "/a/bc", false},
		{"/a", "/", false},
	}
	for _, tc := range cases {
		got := lexicallyInside(tc.parent, tc.child)
		if got != tc.want {
			t.Fatalf("lexicallyInside(%q, %q) = %v, want %v", tc.parent, tc.child, got, tc.want)
		}
	}
}
