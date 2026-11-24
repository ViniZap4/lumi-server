package domain

import (
	"errors"
	"fmt"
)

// Sentinel errors. HTTP layer maps these to status codes; service layer wraps
// them with %w. Never return raw infrastructure errors to handlers.
var (
	ErrNotFound           = errors.New("not found")
	ErrConflict           = errors.New("conflict")
	ErrValidation         = errors.New("validation failed")
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUnauthorized       = errors.New("unauthorized")
	ErrForbidden          = errors.New("forbidden")
	ErrCapabilityMissing  = errors.New("capability missing")
	ErrConsentRequired    = errors.New("consent required")
	ErrSoleAdminVaults    = errors.New("user is sole admin of one or more vaults")
	ErrTokenExpired       = errors.New("token expired")
	ErrTokenInvalid       = errors.New("token invalid")
	ErrInviteExpired      = errors.New("invite expired")
	ErrInviteExhausted    = errors.New("invite exhausted")
	ErrInviteRevoked      = errors.New("invite revoked")
	ErrPathEscape         = errors.New("path escapes allowed root")
	ErrSeedRoleProtected  = errors.New("seed role cannot be modified or deleted")
	ErrRateLimited        = errors.New("rate limited")
	ErrTLSRequired        = errors.New("TLS required")
	ErrResyncRequired     = errors.New("resync required")
)

// ErrMirrorReadOnly refuses a write to a vault this server only mirrors
// (docs/SPEC-ESPELHO-SELADO.md §A6). It is an ErrForbidden; HTTP layers
// answer 403 {"error":"mirror_read_only"}.
var ErrMirrorReadOnly = fmt.Errorf("%w: mirror_read_only", ErrForbidden)

// ErrMirrorUnsupported refuses a mirror invite to a follower that cannot
// sign the v2 accept (it would join as a writable replica).
var ErrMirrorUnsupported = fmt.Errorf("%w: mirror_unsupported", ErrConflict)

// ResyncRequiredError is returned by a change-log read whose cursor is
// below the vault's tombstone floor: deletions it would need were pruned.
// Head is the vault head to resume from after a full listing.
type ResyncRequiredError struct {
	Head int64
}

func (e *ResyncRequiredError) Error() string { return "resync required" }
func (e *ResyncRequiredError) Unwrap() error { return ErrResyncRequired }
