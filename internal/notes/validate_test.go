package notes

import (
	"errors"
	"strings"
	"testing"

	"github.com/ViniZap4/lumi-server/internal/domain"
)

// These tests cover the user-input → safe-stem / safe-path conversion
// in the notes service. slugifyTitle and validateNoteRelPath sit in
// front of fs.SafeJoin and must not allow any path-shape that the
// downstream layer would still have to defend against on its own.

func TestSlugifyTitle(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{"plain ascii", "Hello World", "hello-world"},
		{"already lowercase", "todo", "todo"},
		{"path separators stripped", "../../etc/passwd", "etc-passwd"},
		{"backslash separators stripped", "..\\..\\evil", "evil"},
		{"unicode folded to hyphens", "café résumé", "caf-r-sum"},
		{"emoji folded to hyphens", "hello 👋 world", "hello-world"},
		{"runs of non-alphanum collapse", "a!!!@@@b", "a-b"},
		{"leading/trailing punctuation trimmed", "...hello world...", "hello-world"},
		{"empty title falls back to untitled", "", "untitled"},
		{"only-punctuation falls back to untitled", "!@#$%^", "untitled"},
		{"length cap at 80", strings.Repeat("a", 200), strings.Repeat("a", 80)},
		{"trim hyphens after cap", strings.Repeat("a", 79) + " bbb", strings.Repeat("a", 79)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := slugifyTitle(tc.in)
			if got != tc.want {
				t.Fatalf("slugifyTitle(%q) = %q, want %q", tc.in, got, tc.want)
			}
			// Critical invariants — regardless of input, the stem must
			// never carry a path separator and must never start with
			// a dot.
			if strings.ContainsAny(got, "/\\") {
				t.Fatalf("slug %q contains path separator", got)
			}
			if strings.HasPrefix(got, ".") {
				t.Fatalf("slug %q starts with dot (would be a hidden file)", got)
			}
			if got == "" {
				t.Fatalf("slug must never be empty")
			}
		})
	}
}

func TestValidateNoteRelPath_AcceptsLegitimate(t *testing.T) {
	good := []string{
		"note.md",
		"sub/note.md",
		"deep/nested/path.md",
		"hello-world.md",
		"with.dots.in.name.md",
	}
	for _, p := range good {
		t.Run(p, func(t *testing.T) {
			out, err := validateNoteRelPath(p)
			if err != nil {
				t.Fatalf("rejected legit path %q: %v", p, err)
			}
			if out == "" {
				t.Fatalf("expected non-empty output for %q", p)
			}
		})
	}
}

func TestValidateNoteRelPath_RejectsAdversarial(t *testing.T) {
	bad := []struct {
		name, in string
	}{
		{"empty", ""},
		{"whitespace only", "   "},
		{"absolute path", "/etc/passwd"},
		{"parent traversal at start", "../escape.md"},
		{"parent traversal in middle", "ok/../../escape.md"},
		{"current dir alone", "."},
		{"parent alone", ".."},
		{"non-md extension", "secrets.txt"},
		{"no extension", "notes"},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			_, err := validateNoteRelPath(tc.in)
			if err == nil {
				t.Fatalf("accepted bad path %q", tc.in)
			}
			if !errors.Is(err, domain.ErrValidation) {
				t.Fatalf("wrong error sentinel for %q: %v", tc.in, err)
			}
		})
	}
}

func TestValidateNoteRelPath_NormalisesCleanly(t *testing.T) {
	// path.Clean is part of the contract: callers can send /-prefix-
	// free paths with redundant components and we'll canonicalise.
	// Trailing slashes are stripped, "./" segments collapse, doubled
	// slashes fold — all without escape. The point of the test is to
	// pin the normalisation rules so a future refactor doesn't
	// accidentally turn "ok//note.md" into something fs.SafeJoin
	// rejects as malformed.
	cases := map[string]string{
		"note.md/":         "note.md",
		"sub/./note.md":    "sub/note.md",
		"sub//note.md":     "sub/note.md",
		"  trim.md  ":      "trim.md",
	}
	for in, want := range cases {
		t.Run(in, func(t *testing.T) {
			got, err := validateNoteRelPath(in)
			if err != nil {
				t.Fatalf("rejected %q: %v", in, err)
			}
			if got != want {
				t.Fatalf("validateNoteRelPath(%q) = %q, want %q", in, got, want)
			}
		})
	}
}

// noteIDParam shape check — this is the handler-side noteID filter
// guarding the URL :id parameter. It's deliberately stricter than the
// pg layer (which would accept any unique string) because the param
// flows into fs.NotePath downstream where a "../something" id would
// be rejected by SafeJoin anyway, but rejecting at the handler is
// cheaper and produces a friendlier 400.
func TestNoteIDValidation_RejectsSeparators(t *testing.T) {
	// We don't have a stand-alone noteIDParam validator function — the
	// check is inline in handlers.go. The slugifyTitle output is what
	// becomes a Note.ID, so its invariants (no separators, no empty,
	// no dot-prefix) ARE the noteID safety contract. Re-assert here so
	// a future slugify change doesn't quietly widen the attack surface.
	for _, in := range []string{
		"../",
		"foo/bar",
		"foo\\bar",
		"",
		".hidden",
		"..",
	} {
		got := slugifyTitle(in)
		if strings.ContainsAny(got, "/\\") || got == "" || strings.HasPrefix(got, ".") {
			t.Fatalf("slugifyTitle(%q) = %q violates noteID invariants", in, got)
		}
	}
}
