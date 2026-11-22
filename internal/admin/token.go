// Package admin is the server administration surface (docs/ADMIN.md): a
// service shared by the admin HTTP listener and the CLI subcommands, so both
// apply the same rules and the same refusals.
package admin

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"time"
)

const (
	// TokenPrefix is distinct from every other lumi credential (session
	// tokens are bare hex), so a session token can never pass as an admin
	// token, or the reverse.
	TokenPrefix    = "lpa_"
	tokenRandBytes = 32
	tokenLen       = len(TokenPrefix) + 43 // base64url(32 bytes), unpadded

	DefaultTokenTTL = 30 * 24 * time.Hour
	MaxTokenTTL     = 365 * 24 * time.Hour
	MinTokenTTL     = time.Minute

	// TouchInterval bounds last_used_at writes to one per minute per token.
	TouchInterval = time.Minute

	maxTokenName = 64
)

var errMalformedToken = errors.New("malformed admin token")

// NewToken returns the token handed to the operator (once) and the SHA-256
// digest that is stored.
func NewToken() (token string, digest []byte) {
	b := make([]byte, tokenRandBytes)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand unavailable: " + err.Error())
	}
	token = TokenPrefix + base64.RawURLEncoding.EncodeToString(b)
	return token, Digest(token)
}

// Digest is the at-rest form of an admin token.
func Digest(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

// ParseToken validates the shape before any database work. The digest is
// then looked up through a unique index: the caller controls the preimage,
// not the digest, so lookup timing reveals nothing useful.
func ParseToken(token string) ([]byte, error) {
	if len(token) != tokenLen || !strings.HasPrefix(token, TokenPrefix) {
		return nil, errMalformedToken
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(token[len(TokenPrefix):])
	if err != nil || len(raw) != tokenRandBytes {
		return nil, errMalformedToken
	}
	return Digest(token), nil
}

// BearerToken extracts the credential of an "Authorization: Bearer x" header.
func BearerToken(header string) (string, bool) {
	scheme, tok, ok := strings.Cut(header, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}
	tok = strings.TrimSpace(tok)
	return tok, tok != ""
}
