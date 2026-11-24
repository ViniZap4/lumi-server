package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"

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
		return adoptServerAdmin(ctx, svc, counter, username, password)
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
	sess, err := svc.registerSkippingConsent(ctx, in)
	if err != nil {
		if errors.Is(err, domain.ErrConflict) {
			svc.cfg.Logger.Warn().Msg("auth.Bootstrap: admin already created by concurrent caller")
			return nil
		}
		return fmt.Errorf("auth.Bootstrap: create admin: %w", err)
	}
	svc.cfg.Logger.Info().Str("username", username).Msg("auth.Bootstrap: admin created")
	if g, ok := counter.(ServerAdminGranter); ok {
		if err := grantServerAdmin(ctx, g, sess.UserID, "bootstrap"); err != nil {
			return fmt.Errorf("auth.Bootstrap: grant server admin: %w", err)
		}
	}
	return nil
}

// ServerAdminGranter is the optional server-admin surface of the
// bootstrap's UserCounter (implemented by *pg.UserStore).
type ServerAdminGranter interface {
	CountServerAdmins(ctx context.Context) (int, error)
	GrantServerAdmin(ctx context.Context, id uuid.UUID, e domain.AuditEntry) error
}

// grantServerAdmin sets the flag with an admin.user.server_admin audit row
// (actor "bootstrap", no token).
func grantServerAdmin(ctx context.Context, g ServerAdminGranter, id uuid.UUID, how string) error {
	payload := mustJSON(map[string]any{"actor": "bootstrap", "token_id": nil, "token_name": how, "enabled": true})
	return g.GrantServerAdmin(ctx, id, domain.AuditEntry{UserID: &id, Action: "admin.user.server_admin", Payload: payload})
}

// adoptServerAdmin upgrades a server that predates server_admin
// (migration 0009): when no account has the flag yet and the env still
// names the bootstrap admin with the password that account actually has,
// that account gets the flag. The password check proves the env names the
// operator's own account, not one someone else registered under that
// name; a mismatch (rotated password, deleted user) grants nothing and the
// operator uses `lumi-server admin grant <user>`.
func adoptServerAdmin(ctx context.Context, svc *Service, counter UserCounter, username, password string) error {
	g, ok := counter.(ServerAdminGranter)
	if !ok {
		return nil
	}
	n, err := g.CountServerAdmins(ctx)
	if err != nil {
		return fmt.Errorf("auth.Bootstrap: count server admins: %w", err)
	}
	if n > 0 {
		return nil
	}
	name, err := canonicaliseUsername(username)
	if err != nil {
		return nil
	}
	u, err := svc.users.GetByUsername(ctx, name)
	if err != nil || u.DisabledAt != nil || CheckPassword(u.PasswordHash, password) != nil {
		svc.cfg.Logger.Warn().Msg("auth.Bootstrap: no server admin yet and LUMI_ADMIN_USERNAME/LUMI_ADMIN_PASSWORD do not match an active account; grant one with `lumi-server admin grant <user>`")
		return nil
	}
	if err := grantServerAdmin(ctx, g, u.ID, "bootstrap-upgrade"); err != nil {
		return fmt.Errorf("auth.Bootstrap: grant server admin: %w", err)
	}
	svc.cfg.Logger.Info().Str("username", name).Msg("auth.Bootstrap: existing bootstrap admin is now a server admin")
	return nil
}
