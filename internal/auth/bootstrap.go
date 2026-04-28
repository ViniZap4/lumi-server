package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/ViniZap4/lumi-server/internal/domain"
)

// BootstrapConfig holds the values read from LUMI_ADMIN_USERNAME /
// LUMI_ADMIN_PASSWORD.
type BootstrapConfig struct {
	Username    string
	Password    string
	DisplayName string
}

// UserCounter is the minimal interface needed by Bootstrap to detect
// first-run state.
type UserCounter interface {
	CountUsers(ctx context.Context) (int, error)
}

// Bootstrap creates an initial admin if (and only if) the users table is
// empty AND credentials are supplied. Idempotent: re-running with users
// present is a no-op.
func Bootstrap(ctx context.Context, svc *Service, counter UserCounter, cfg BootstrapConfig) error {
	if svc == nil {
		return errors.New("auth.Bootstrap: nil service")
	}
	if counter == nil {
		return errors.New("auth.Bootstrap: nil user counter")
	}
	username := strings.TrimSpace(cfg.Username)
	password := cfg.Password
	if username == "" || password == "" {
		svc.cfg.Logger.Debug().Msg("auth.Bootstrap: no admin credentials in env; skipping")
		return nil
	}

	count, err := counter.CountUsers(ctx)
	if err != nil {
		return fmt.Errorf("auth.Bootstrap: count users: %w", err)
	}
	if count > 0 {
		svc.cfg.Logger.Debug().Int("user_count", count).Msg("auth.Bootstrap: users present; skipping")
		return nil
	}

	displayName := strings.TrimSpace(cfg.DisplayName)
	if displayName == "" {
		displayName = "Administrator"
	}
	in := RegisterInput{
		Username:    username,
		Password:    password,
		DisplayName: displayName,
		Consent: ConsentInput{
			TosVersion:     svc.cfg.TosVersion,
			PrivacyVersion: svc.cfg.PrivacyVersion,
		},
		IP:        "127.0.0.1",
		UserAgent: "lumi-bootstrap",
	}
	if _, err := svc.registerSkippingConsent(ctx, in); err != nil {
		if errors.Is(err, domain.ErrConflict) {
			svc.cfg.Logger.Warn().Msg("auth.Bootstrap: admin already created by concurrent caller")
			return nil
		}
		return fmt.Errorf("auth.Bootstrap: create admin: %w", err)
	}
	svc.cfg.Logger.Info().Str("username", username).Msg("auth.Bootstrap: admin created")
	return nil
}
