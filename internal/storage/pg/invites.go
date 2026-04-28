package pg

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ViniZap4/lumi-server/internal/domain"
)

// InviteStore persists vault join tokens.
type InviteStore struct {
	pool *pgxpool.Pool
}

func NewInviteStore(pool *pgxpool.Pool) *InviteStore {
	return &InviteStore{pool: pool}
}

func (s *InviteStore) Create(ctx context.Context, i domain.Invite) error {
	const q = `
INSERT INTO invites (
  token, vault_id, inviter_user_id, role_id,
  email_hint, max_uses, use_count, expires_at, created_at, revoked_at
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`
	_, err := s.pool.Exec(ctx, q,
		i.Token, i.VaultID, i.InviterUserID, i.RoleID,
		nullableString(i.EmailHint), i.MaxUses, i.UseCount,
		i.ExpiresAt, i.CreatedAt, i.RevokedAt,
	)
	if err != nil {
		return fmt.Errorf("invite store: create: %w", errMap(err))
	}
	return nil
}

func (s *InviteStore) Get(ctx context.Context, token string) (domain.Invite, error) {
	const q = `
SELECT token, vault_id, inviter_user_id, role_id, email_hint,
       max_uses, use_count, expires_at, created_at, revoked_at
  FROM invites
 WHERE token = $1`
	var (
		inv       domain.Invite
		emailHint *string
	)
	err := s.pool.QueryRow(ctx, q, token).Scan(
		&inv.Token, &inv.VaultID, &inv.InviterUserID, &inv.RoleID, &emailHint,
		&inv.MaxUses, &inv.UseCount, &inv.ExpiresAt, &inv.CreatedAt, &inv.RevokedAt,
	)
	if err != nil {
		if errors.Is(errMap(err), domain.ErrNotFound) {
			return domain.Invite{}, fmt.Errorf("invite store: get: %w", domain.ErrNotFound)
		}
		return domain.Invite{}, fmt.Errorf("invite store: get: %w", errMap(err))
	}
	if emailHint != nil {
		inv.EmailHint = *emailHint
	}
	return inv, nil
}

// IncrementUse atomically claims one slot and returns the updated row.
// Discriminates revoked / expired / exhausted via a probe query when the
// CAS misses.
func (s *InviteStore) IncrementUse(ctx context.Context, token string, now time.Time) (domain.Invite, error) {
	const updQ = `
UPDATE invites
   SET use_count = use_count + 1
 WHERE token = $1
   AND revoked_at IS NULL
   AND expires_at > $2
   AND use_count < max_uses
RETURNING token, vault_id, inviter_user_id, role_id, email_hint,
          max_uses, use_count, expires_at, created_at, revoked_at`

	var (
		inv       domain.Invite
		emailHint *string
	)
	err := s.pool.QueryRow(ctx, updQ, token, now).Scan(
		&inv.Token, &inv.VaultID, &inv.InviterUserID, &inv.RoleID, &emailHint,
		&inv.MaxUses, &inv.UseCount, &inv.ExpiresAt, &inv.CreatedAt, &inv.RevokedAt,
	)
	if err == nil {
		if emailHint != nil {
			inv.EmailHint = *emailHint
		}
		return inv, nil
	}
	mapped := errMap(err)
	if !errors.Is(mapped, domain.ErrNotFound) {
		return domain.Invite{}, fmt.Errorf("invite store: increment: %w", mapped)
	}

	// CAS missed; probe for the precise reason.
	const probeQ = `
SELECT revoked_at IS NOT NULL,
       expires_at <= $2,
       use_count >= max_uses
  FROM invites
 WHERE token = $1`
	var revoked, expired, exhausted bool
	probeErr := s.pool.QueryRow(ctx, probeQ, token, now).Scan(&revoked, &expired, &exhausted)
	if probeErr != nil {
		if errors.Is(errMap(probeErr), domain.ErrNotFound) {
			return domain.Invite{}, fmt.Errorf("invite store: increment: %w", domain.ErrNotFound)
		}
		return domain.Invite{}, fmt.Errorf("invite store: increment: probe: %w", errMap(probeErr))
	}
	switch {
	case revoked:
		return domain.Invite{}, fmt.Errorf("invite store: increment: %w", domain.ErrInviteRevoked)
	case expired:
		return domain.Invite{}, fmt.Errorf("invite store: increment: %w", domain.ErrInviteExpired)
	case exhausted:
		return domain.Invite{}, fmt.Errorf("invite store: increment: %w", domain.ErrInviteExhausted)
	default:
		return domain.Invite{}, fmt.Errorf("invite store: increment: %w", domain.ErrConflict)
	}
}

func (s *InviteStore) Revoke(ctx context.Context, token string, now time.Time) error {
	const q = `
UPDATE invites
   SET revoked_at = $2
 WHERE token = $1 AND revoked_at IS NULL`
	tag, err := s.pool.Exec(ctx, q, token, now)
	if err != nil {
		return fmt.Errorf("invite store: revoke: %w", errMap(err))
	}
	if tag.RowsAffected() == 0 {
		var exists bool
		probeErr := s.pool.QueryRow(ctx,
			`SELECT TRUE FROM invites WHERE token = $1`, token,
		).Scan(&exists)
		if probeErr != nil {
			if errors.Is(errMap(probeErr), domain.ErrNotFound) {
				return fmt.Errorf("invite store: revoke: %w", domain.ErrNotFound)
			}
			return fmt.Errorf("invite store: revoke: probe: %w", errMap(probeErr))
		}
		return nil
	}
	return nil
}

func (s *InviteStore) ListForVault(ctx context.Context, vaultID uuid.UUID) ([]domain.Invite, error) {
	const q = `
SELECT token, vault_id, inviter_user_id, role_id, email_hint,
       max_uses, use_count, expires_at, created_at, revoked_at
  FROM invites
 WHERE vault_id = $1
 ORDER BY created_at DESC`
	rows, err := s.pool.Query(ctx, q, vaultID)
	if err != nil {
		return nil, fmt.Errorf("invite store: list: %w", errMap(err))
	}
	defer rows.Close()

	var out []domain.Invite
	for rows.Next() {
		var (
			inv       domain.Invite
			emailHint *string
		)
		if err := rows.Scan(
			&inv.Token, &inv.VaultID, &inv.InviterUserID, &inv.RoleID, &emailHint,
			&inv.MaxUses, &inv.UseCount, &inv.ExpiresAt, &inv.CreatedAt, &inv.RevokedAt,
		); err != nil {
			return nil, fmt.Errorf("invite store: list scan: %w", err)
		}
		if emailHint != nil {
			inv.EmailHint = *emailHint
		}
		out = append(out, inv)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("invite store: list rows: %w", err)
	}
	return out, nil
}

// PurgeExpired removes invites past expiry, revoked, or exhausted.
func (s *InviteStore) PurgeExpired(ctx context.Context) (int64, error) {
	const q = `
DELETE FROM invites
 WHERE expires_at <= NOW()
    OR revoked_at IS NOT NULL
    OR use_count >= max_uses`
	tag, err := s.pool.Exec(ctx, q)
	if err != nil {
		return 0, fmt.Errorf("invite store: purge: %w", errMap(err))
	}
	return tag.RowsAffected(), nil
}

func nullableString(s string) any {
	if s == "" {
		return nil
	}
	return s
}
