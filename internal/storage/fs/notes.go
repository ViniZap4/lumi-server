package fs

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ViniZap4/lumi-server/internal/domain"
)

// NotePath returns the absolute path for a note inside the given vault.
// Enforces two boundaries: vault directory inside root, and relative path
// inside vault directory.
func (m *Manager) NotePath(slug, relativePath string) (string, error) {
	if slug == "" {
		return "", fmt.Errorf("%w: empty slug", domain.ErrValidation)
	}
	vaultDir, err := SafeJoin(m.Root, slug)
	if err != nil {
		return "", err
	}
	full, err := SafeJoin(vaultDir, relativePath)
	if err != nil {
		return "", err
	}
	return full, nil
}

func (m *Manager) WriteNote(slug, relativePath string, frontmatter map[string]any, body []byte) error {
	full, err := m.NotePath(slug, relativePath)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(full), noteDirPerm); err != nil {
		return fmt.Errorf("storage/fs: ensure note dir: %w", err)
	}
	data, err := WriteFrontmatter(frontmatter, body)
	if err != nil {
		return err
	}
	if err := AtomicWrite(full, data, noteFilePerm); err != nil {
		return fmt.Errorf("storage/fs: write note: %w", err)
	}
	return nil
}

func (m *Manager) ReadNote(slug, relativePath string) (map[string]any, []byte, error) {
	full, err := m.NotePath(slug, relativePath)
	if err != nil {
		return nil, nil, err
	}
	data, err := os.ReadFile(full)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil, fmt.Errorf("%w: note %q in vault %q", domain.ErrNotFound, relativePath, slug)
		}
		return nil, nil, fmt.Errorf("storage/fs: read note: %w", err)
	}
	front, body, err := ParseFrontmatter(data)
	if err != nil {
		return nil, nil, err
	}
	return front, body, nil
}

func (m *Manager) DeleteNote(slug, relativePath string) error {
	full, err := m.NotePath(slug, relativePath)
	if err != nil {
		return err
	}
	if err := os.Remove(full); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("%w: note %q in vault %q", domain.ErrNotFound, relativePath, slug)
		}
		return fmt.Errorf("storage/fs: remove note: %w", err)
	}
	return nil
}

func (m *Manager) MoveNote(slug, oldPath, newPath string) error {
	src, err := m.NotePath(slug, oldPath)
	if err != nil {
		return err
	}
	dst, err := m.NotePath(slug, newPath)
	if err != nil {
		return err
	}
	if src == dst {
		return nil
	}
	if _, err := os.Stat(src); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("%w: note %q in vault %q", domain.ErrNotFound, oldPath, slug)
		}
		return fmt.Errorf("storage/fs: stat source: %w", err)
	}
	if _, err := os.Stat(dst); err == nil {
		return fmt.Errorf("%w: note %q already exists in vault %q", domain.ErrConflict, newPath, slug)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("storage/fs: stat dest: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(dst), noteDirPerm); err != nil {
		return fmt.Errorf("storage/fs: ensure dest dir: %w", err)
	}
	if err := os.Rename(src, dst); err != nil {
		return fmt.Errorf("storage/fs: rename note: %w", err)
	}
	return nil
}
