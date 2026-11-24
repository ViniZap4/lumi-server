package domain

import (
	"fmt"
	"strings"
)

// MaxNotePathBytes bounds a note's vault-relative path.
const MaxNotePathBytes = 1024

// MaxNoteBodyBytes bounds a note's text (markdown body or canvas JSON).
// It matches the public API's 4 MiB request limit.
const MaxNoteBodyBytes = 4 << 20

// Note kinds (SPEC-PARTE2 §6). The kind is derived from the path's
// extension and never stored: ".md" is markdown with optional YAML
// frontmatter, ".canvas" is a JSON Canvas 1.0 file with no frontmatter.
const (
	NoteKindMarkdown = "markdown"
	NoteKindCanvas   = "canvas"

	NoteExtMarkdown = ".md"
	NoteExtCanvas   = ".canvas"
)

// NoteKindOf returns the kind of a note path: NoteKindCanvas for a path
// ending in ".canvas", NoteKindMarkdown otherwise.
func NoteKindOf(p string) string {
	if strings.HasSuffix(p, NoteExtCanvas) {
		return NoteKindCanvas
	}
	return NoteKindMarkdown
}

// IsCanvasPath reports whether p names a canvas file.
func IsCanvasPath(p string) bool { return NoteKindOf(p) == NoteKindCanvas }

// NoteExt is the file extension of a kind.
func NoteExt(kind string) string {
	if kind == NoteKindCanvas {
		return NoteExtCanvas
	}
	return NoteExtMarkdown
}

// NoteStem is the file name of p without its directory and note extension
// ("boards/Plan.canvas" -> "Plan"). A canvas title is its stem.
func NoteStem(p string) string {
	base := p
	if i := strings.LastIndex(base, "/"); i >= 0 {
		base = base[i+1:]
	}
	if s, ok := strings.CutSuffix(base, NoteExtCanvas); ok {
		return s
	}
	return strings.TrimSuffix(base, NoteExtMarkdown)
}

// ValidateNotePath enforces the canonical shape of a vault-relative note
// path. It does not normalise: input must already be canonical, which is
// what peers and the fs layer exchange. Rules:
//
//   - non-empty, at most MaxNotePathBytes, no NUL, no backslash;
//   - relative (no leading "/"), no empty segments ("a//b", trailing "/");
//   - no dot-segments: ".", "..", or any segment starting with "." — this
//     keeps writes out of hidden/control directories such as .lumi/;
//   - ends in ".md" or ".canvas" with a non-empty stem.
//
// fs.SafeJoin remains the authoritative containment check on disk access;
// this is the policy gate in front of it.
func ValidateNotePath(p string) error {
	bad := func(why string) error {
		return fmt.Errorf("%w: invalid note path %q: %s", ErrValidation, p, why)
	}
	if p == "" {
		return bad("empty")
	}
	if len(p) > MaxNotePathBytes {
		return bad("too long")
	}
	if strings.ContainsAny(p, "\x00\\") {
		return bad("NUL or backslash")
	}
	if strings.HasPrefix(p, "/") {
		return bad("absolute")
	}
	segs := strings.Split(p, "/")
	for _, seg := range segs {
		switch {
		case seg == "":
			return bad("empty segment")
		case strings.HasPrefix(seg, "."):
			return bad("dot-segment")
		}
	}
	last := segs[len(segs)-1]
	ext := NoteExt(NoteKindOf(last))
	if !strings.HasSuffix(last, ext) || len(last) <= len(ext) {
		return bad("must end with .md or .canvas")
	}
	return nil
}
