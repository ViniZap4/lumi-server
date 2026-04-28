// Package fs is the single I/O boundary for all on-disk vault state in
// lumi v2. Every path that touches the filesystem flows through SafeJoin,
// which is the project's only sanctioned defence against path traversal
// and symlink-escape attacks. Treat changes here as security-sensitive.
//
// Threat model
//
//   - Untrusted user input arrives as a relative path (a vault slug, a
//     note's relative path, an attachment name).
//   - The attacker's goal is to read or write a file outside the
//     configured root via "..", absolute paths, NUL injection, or symlinks
//     planted inside the root that resolve elsewhere.
//
// Defences (all mandatory; missing any one breaks the contract):
//
//  1. The user-supplied path is rejected if absolute, contains a NUL byte,
//     or contains a "../" segment after path.Clean.
//  2. The configured root is resolved with filepath.EvalSymlinks once at
//     SafeJoin time (callers are encouraged to keep the root canonical).
//  3. The joined result is re-resolved with EvalSymlinks. If the leaf
//     does not yet exist, the deepest existing ancestor is resolved
//     instead. The resolved path must be lexically contained inside the
//     resolved root. Any deviation returns domain.ErrPathEscape.
package fs

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ViniZap4/lumi-server/internal/domain"
)

// SafeJoin returns root joined with userPath, guaranteeing the result is
// strictly inside root after symlink resolution. The returned path is
// absolute and lexically clean. Any traversal attempt yields a wrapped
// domain.ErrPathEscape; the wrapping reason is for logs only and must
// not be surfaced to the API consumer verbatim.
//
// userPath semantics:
//
//   - Empty string is allowed and resolves to root itself.
//   - Trailing slashes are allowed and stripped.
//   - "/" or drive-letter prefixes (e.g. "C:\\foo") are rejected.
//   - "." segments are allowed; ".." segments are rejected after Clean.
//   - NUL bytes are rejected (prevents truncation tricks against C APIs).
//
// root MUST be an absolute path that exists on disk. Callers that want a
// stable canonical root should resolve it once at startup with
// filepath.EvalSymlinks and reuse that value; SafeJoin re-resolves
// defensively but constant-folding the root saves a syscall per call.
func SafeJoin(root, userPath string) (string, error) {
	if root == "" {
		return "", fmt.Errorf("%w: empty root", domain.ErrPathEscape)
	}
	if !filepath.IsAbs(root) {
		return "", fmt.Errorf("%w: root %q is not absolute", domain.ErrPathEscape, root)
	}
	if strings.ContainsRune(userPath, 0) {
		return "", fmt.Errorf("%w: NUL byte in user path", domain.ErrPathEscape)
	}
	if filepath.IsAbs(userPath) || hasWindowsDrive(userPath) {
		return "", fmt.Errorf("%w: user path %q is absolute", domain.ErrPathEscape, userPath)
	}

	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", fmt.Errorf("%w: cannot resolve root %q: %v", domain.ErrPathEscape, root, err)
	}
	resolvedRoot = filepath.Clean(resolvedRoot)

	cleanedUser := filepath.Clean(filepath.FromSlash(userPath))
	if cleanedUser == ".." || strings.HasPrefix(cleanedUser, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("%w: user path %q contains parent traversal", domain.ErrPathEscape, userPath)
	}

	joined := filepath.Join(resolvedRoot, cleanedUser)
	joined = filepath.Clean(joined)

	if !lexicallyInside(resolvedRoot, joined) {
		return "", fmt.Errorf("%w: joined path %q escapes root %q", domain.ErrPathEscape, joined, resolvedRoot)
	}

	resolved, err := evalSymlinksTolerant(joined)
	if err != nil {
		return "", fmt.Errorf("%w: cannot resolve %q: %v", domain.ErrPathEscape, joined, err)
	}
	resolved = filepath.Clean(resolved)
	if !lexicallyInside(resolvedRoot, resolved) {
		return "", fmt.Errorf("%w: resolved path %q escapes root %q", domain.ErrPathEscape, resolved, resolvedRoot)
	}

	return joined, nil
}

func lexicallyInside(parent, child string) bool {
	if parent == child {
		return true
	}
	prefix := parent
	if !strings.HasSuffix(prefix, string(filepath.Separator)) {
		prefix += string(filepath.Separator)
	}
	return strings.HasPrefix(child, prefix)
}

func evalSymlinksTolerant(p string) (string, error) {
	resolved, err := filepath.EvalSymlinks(p)
	if err == nil {
		return resolved, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}

	dir := p
	tail := ""
	for {
		parent := filepath.Dir(dir)
		if parent == dir {
			return filepath.Clean(p), nil
		}
		if tail == "" {
			tail = filepath.Base(dir)
		} else {
			tail = filepath.Join(filepath.Base(dir), tail)
		}
		dir = parent
		resolved, err = filepath.EvalSymlinks(dir)
		if err == nil {
			return filepath.Join(resolved, tail), nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
	}
}

func hasWindowsDrive(p string) bool {
	if len(p) < 2 {
		return false
	}
	c := p[0]
	if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) {
		return false
	}
	return p[1] == ':'
}
