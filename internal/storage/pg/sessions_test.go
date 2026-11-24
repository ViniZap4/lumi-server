package pg

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/ViniZap4/lumi-server/internal/auth"
)

func TestHashSessionToken(t *testing.T) {
	cases := map[string]string{
		"abc": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
		"":    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
	}
	for in, want := range cases {
		if got := hashSessionToken(in); got != want {
			t.Errorf("hashSessionToken(%q) = %s, want %s", in, got, want)
		}
	}
	if hashSessionToken("a") == "a" || len(hashSessionToken("deadbeef")) != 64 {
		t.Fatal("hash must be a 64-char hex digest distinct from the input")
	}
}

// No Postgres is available in unit tests, so pin the SQL contract
// statically: the store must never address sessions by a raw token column,
// and the migration must hash with the same encoding as hashSessionToken.
func TestSessionSQL_UsesTokenHashOnly(t *testing.T) {
	src, err := os.ReadFile("sessions.go")
	if err != nil {
		t.Fatal(err)
	}
	if regexp.MustCompile(`\btoken\s*=\s*\$`).Match(src) {
		t.Fatal("sessions.go filters on a raw token column")
	}
	if regexp.MustCompile(`(?i)INSERT INTO sessions \(token,`).Match(src) {
		t.Fatal("sessions.go inserts a raw token")
	}
	mig, err := os.ReadFile("../../../migrations/0005_session_token_hash.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(mig), "encode(sha256(convert_to(token_hash, 'UTF8')), 'hex')") {
		t.Fatal("migration hash expression drifted from hashSessionToken (hex sha256 of UTF-8)")
	}
}

// Device links key sessions by the same digest as the session store and
// never write a raw token or code (SPEC-LIVROS §8.4).
func TestDeviceLinkStore_HashesOnly(t *testing.T) {
	if auth.SessionRef("abc") != hashSessionToken("abc") {
		t.Fatal("auth.SessionRef must equal hashSessionToken")
	}
	src, err := os.ReadFile("device_links.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, re := range []string{`\btoken\s*=\s*\$`, `(?i)INSERT INTO session_links \(token,`, `(?i)\bcode\s*=\s*\$`} {
		if regexp.MustCompile(re).Match(src) {
			t.Fatalf("device_links.go matches %s", re)
		}
	}
	if !strings.Contains(string(src), "hashSessionToken(newToken)") || !strings.Contains(string(src), "hashSessionToken(token)") {
		t.Fatal("device_links.go must hash session tokens before use")
	}
	mig, err := os.ReadFile("../../../migrations/0011_device_links.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(mig), "REFERENCES sessions(token_hash) ON DELETE CASCADE") {
		t.Fatal("link rows must die with their session")
	}
}
