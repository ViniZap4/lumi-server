// Package auth provides the username + password authentication subsystem:
// password hashing, session token issue/validation, login/logout/register
// flows, Fiber middleware for authenticated routes, and an in-memory rate
// limiter for failed-login mitigation.
package auth

import (
	"time"

	"github.com/rs/zerolog"
)

type RegistrationPolicy string

const (
	PolicyOpen        RegistrationPolicy = "open"
	PolicyInviteOnly  RegistrationPolicy = "invite-only"
	defaultBcryptCost                    = 12
	defaultSessionTTL                    = 30 * 24 * time.Hour
)

// Config bundles the tunables for the auth subsystem.
type Config struct {
	BcryptCost         int
	SessionTTL         time.Duration
	RegistrationPolicy RegistrationPolicy
	RequireConsent     bool
	TosVersion         string
	PrivacyVersion     string
	Logger             zerolog.Logger
}

func (cfg Config) withDefaults() Config {
	out := cfg
	if out.BcryptCost < defaultBcryptCost {
		out.BcryptCost = defaultBcryptCost
	}
	if out.SessionTTL <= 0 {
		out.SessionTTL = defaultSessionTTL
	}
	switch out.RegistrationPolicy {
	case PolicyOpen, PolicyInviteOnly:
	default:
		out.RegistrationPolicy = PolicyInviteOnly
	}
	return out
}
