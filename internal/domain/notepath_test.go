package domain

import (
	"errors"
	"strings"
	"testing"
)

func TestValidateNotePath(t *testing.T) {
	good := []string{"note.md", "sub/note.md", "a/b/c/d.md", "with.dots.in.name.md", "dir.with.dots/n.md", "ünïcode.md"}
	for _, p := range good {
		if err := ValidateNotePath(p); err != nil {
			t.Errorf("rejected legit %q: %v", p, err)
		}
	}
	bad := []string{
		"", ".md", "a/.md", "/abs.md", "../escape.md", "a/../b.md", "./a.md", "a/./b.md",
		".lumi/vault.yaml", ".lumi/vault.md", ".lumi/x/y.md", "sub/.hidden.md", ".git/config.md",
		"a//b.md", "a/", "note.md/", "note.txt", "note", "a\\b.md", "..\\x.md", "a\x00.md",
		strings.Repeat("a", MaxNotePathBytes) + ".md",
	}
	for _, p := range bad {
		if err := ValidateNotePath(p); !errors.Is(err, ErrValidation) {
			t.Errorf("accepted bad %q (err=%v)", p, err)
		}
	}
}
