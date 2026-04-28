package domain

import "errors"

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
)
