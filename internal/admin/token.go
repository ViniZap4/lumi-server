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
	TokenPrefix = "lpa_"
	// SessionPrefix marks an admin session token: minted by a password
	// login of a server admin (POST /admin/v1/session), tied to that
	// user, at most SessionTTL long.
	SessionPrefix  = "lps_"
	tokenRandBytes = 32
	tokenLen       = len(TokenPrefix) + 43 // base64url(32 bytes), unpadded

	DefaultTokenTTL = 30 * 24 * time.Hour
	MaxTokenTTL     = 365 * 24 * time.Hour
	MinTokenTTL     = time.Minute

	// SessionTTL is the fixed lifetime of an admin session (never
	// extended; the database refuses more than 12 hours).
	SessionTTL = 12 * time.Hour

	// TouchInterval bounds last_used_at writes to one per minute per token.
	TouchInterval = time.Minute

	maxTokenName = 64
)

var errMalformedToken = errors.New("malformed admin token")

// Credential kinds stored in admin_tokens.kind.
const (
	KindToken   = "token"
	KindSession = "session"
)

// NewToken returns the token handed to the operator (once) and the SHA-256
// digest that is stored.
func NewToken() (token string, digest []byte) { return newCredential(TokenPrefix) }

// NewSessionToken mints an admin session token ("lps_…").
func NewSessionToken() (token string, digest []byte) { return newCredential(SessionPrefix) }

func newCredential(prefix string) (string, []byte) {
	b := make([]byte, tokenRandBytes)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand unavailable: " + err.Error())
	}
	token := prefix + base64.RawURLEncoding.EncodeToString(b)
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
	if !strings.HasPrefix(token, TokenPrefix) {
		return nil, errMalformedToken
	}
	return parseCredential(token)
}

// ParseCredential accepts either kind of admin bearer credential and
// reports which one it is (KindToken for "lpa_", KindSession for "lps_").
func ParseCredential(token string) (digest []byte, kind string, err error) {
	switch {
	case strings.HasPrefix(token, TokenPrefix):
		kind = KindToken
	case strings.HasPrefix(token, SessionPrefix):
		kind = KindSession
	default:
		return nil, "", errMalformedToken
	}
	digest, err = parseCredential(token)
	return digest, kind, err
}

func parseCredential(token string) ([]byte, error) {
	if len(token) != tokenLen {
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
