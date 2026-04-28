package fs

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// AtomicWrite replaces the file at path with data using the standard
// temp-file + rename idiom. The temp file is created in the same
// directory as the destination (so the rename is guaranteed to be on
// the same filesystem and therefore atomic on POSIX).
//
// On failure at any stage, the temp file is best-effort removed. The
// destination file is therefore either fully replaced or untouched —
// callers never observe a half-written file.
//
// The caller-supplied perm is applied via fchmod *before* the rename so
// that the file appears at its final path with its final mode in a
// single inode swap.
func AtomicWrite(path string, data []byte, perm os.FileMode) error {
	return atomicWrite(path, perm, func(f *os.File) error {
		if _, err := f.Write(data); err != nil {
			return err
		}
		return nil
	})
}

// AtomicWriteReader is the streaming equivalent of AtomicWrite. It is
// preferred for note bodies and attachments to avoid loading the entire
// payload into memory.
func AtomicWriteReader(path string, r io.Reader, perm os.FileMode) error {
	return atomicWrite(path, perm, func(f *os.File) error {
		if _, err := io.Copy(f, r); err != nil {
			return err
		}
		return nil
	})
}

func atomicWrite(path string, perm os.FileMode, fill func(*os.File) error) error {
	dir := filepath.Dir(path)
	suffix, err := randHex(8)
	if err != nil {
		return fmt.Errorf("atomic write: random suffix: %w", err)
	}
	tmpPath := filepath.Join(dir, filepath.Base(path)+".tmp."+suffix)

	tmp, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return fmt.Errorf("atomic write: create temp: %w", err)
	}

	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
	}

	if err := tmp.Chmod(perm); err != nil {
		cleanup()
		return fmt.Errorf("atomic write: chmod temp: %w", err)
	}
	if err := fill(tmp); err != nil {
		cleanup()
		return fmt.Errorf("atomic write: fill temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return fmt.Errorf("atomic write: fsync temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("atomic write: close temp: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("atomic write: rename: %w", err)
	}
	if dirF, err := os.Open(dir); err == nil {
		_ = dirF.Sync()
		_ = dirF.Close()
	}
	return nil
}

func randHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
