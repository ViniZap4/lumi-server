package fs

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAtomicWrite_ReplacesAtomically(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "note.md")

	if err := AtomicWrite(path, []byte("first"), 0o600); err != nil {
		t.Fatalf("first write: %v", err)
	}
	if err := AtomicWrite(path, []byte("second"), 0o600); err != nil {
		t.Fatalf("second write: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(got) != "second" {
		t.Fatalf("got %q, want %q", got, "second")
	}
}

func TestAtomicWrite_AppliesPerm(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret")
	if err := AtomicWrite(path, []byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("perm = %o, want 0600", st.Mode().Perm())
	}
}

func TestAtomicWrite_CrashSimulation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "note.md")
	if err := os.WriteFile(path, []byte("ORIGINAL"), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	failing := &failingReader{good: []byte("PARTIAL"), err: errors.New("boom")}
	err := AtomicWriteReader(path, failing, 0o600)
	if err == nil {
		t.Fatal("expected error from failing reader")
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(got) != "ORIGINAL" {
		t.Fatalf("destination corrupted: %q", got)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp.") {
			t.Fatalf("temp file leaked: %s", e.Name())
		}
	}
}

func TestAtomicWriteReader_StreamsLargePayload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "big.bin")
	payload := bytes.Repeat([]byte("lumi"), 1<<16)
	if err := AtomicWriteReader(path, bytes.NewReader(payload), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload mismatch: %d vs %d bytes", len(got), len(payload))
	}
}

type failingReader struct {
	good []byte
	off  int
	err  error
}

func (f *failingReader) Read(p []byte) (int, error) {
	if f.off < len(f.good) {
		n := copy(p, f.good[f.off:])
		f.off += n
		return n, nil
	}
	return 0, f.err
}

var _ io.Reader = (*failingReader)(nil)
