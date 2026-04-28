package auth

import (
	"errors"
	"fmt"
	"unicode"

	"golang.org/x/crypto/bcrypt"

	"github.com/ViniZap4/lumi-server/internal/domain"
)

const (
	MinPasswordLength = 8
	maxPasswordBytes  = 72
)

// HashPassword produces a bcrypt hash. Refuses inputs > 72 bytes since
// bcrypt silently truncates them.
func HashPassword(plain string, cost int) (string, error) {
	if cost < bcrypt.MinCost {
		cost = bcrypt.DefaultCost
	}
	if len(plain) > maxPasswordBytes {
		return "", fmt.Errorf("auth: password exceeds %d bytes: %w", maxPasswordBytes, domain.ErrValidation)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(plain), cost)
	if err != nil {
		return "", fmt.Errorf("auth: hash password: %w", err)
	}
	return string(hash), nil
}

// CheckPassword verifies plain against a bcrypt hash. Any mismatch returns
// domain.ErrInvalidCredentials so callers cannot distinguish wrong-password
// from malformed-hash via the error.
func CheckPassword(hash, plain string) error {
	if hash == "" || plain == "" {
		return domain.ErrInvalidCredentials
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(plain)); err != nil {
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			return domain.ErrInvalidCredentials
		}
		return domain.ErrInvalidCredentials
	}
	return nil
}

// ValidatePassword runs structural checks. Does not enforce a dictionary.
func ValidatePassword(plain string) error {
	if len(plain) > maxPasswordBytes {
		return fmt.Errorf("auth: password exceeds %d bytes: %w", maxPasswordBytes, domain.ErrValidation)
	}
	runes := []rune(plain)
	if len(runes) < MinPasswordLength {
		return fmt.Errorf("auth: password shorter than %d characters: %w", MinPasswordLength, domain.ErrValidation)
	}
	allDigit, allAlpha := true, true
	for _, r := range runes {
		if !unicode.IsDigit(r) {
			allDigit = false
		}
		if !unicode.IsLetter(r) {
			allAlpha = false
		}
		if !allDigit && !allAlpha {
			break
		}
	}
	if allDigit {
		return fmt.Errorf("auth: password is all-numeric: %w", domain.ErrValidation)
	}
	if allAlpha && len(runes) < 10 {
		return fmt.Errorf("auth: password is all-alphabetic and shorter than 10: %w", domain.ErrValidation)
	}
	return nil
}
