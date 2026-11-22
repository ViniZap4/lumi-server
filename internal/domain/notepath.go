package domain

import (
	"fmt"
	"strings"
)

// MaxNotePathBytes bounds a note's vault-relative path.
const MaxNotePathBytes = 1024

// ValidateNotePath enforces the canonical shape of a vault-relative note
// path. It does not normalise: input must already be canonical, which is
// what peers and the fs layer exchange. Rules:
//
//   - non-empty, at most MaxNotePathBytes, no NUL, no backslash;
//   - relative (no leading "/"), no empty segments ("a//b", trailing "/");
//   - no dot-segments: ".", "..", or any segment starting with "." — this
//     keeps writes out of hidden/control directories such as .lumi/;
//   - ends in ".md" with a non-empty stem.
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
	if !strings.HasSuffix(last, ".md") || len(last) <= len(".md") {
		return bad("must end with .md")
	}
	return nil
}
