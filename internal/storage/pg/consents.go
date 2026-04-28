package pg

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ViniZap4/lumi-server/internal/domain"
)

// ConsentStore is the append-only ledger of user ToS / Privacy acceptances.
type ConsentStore struct {
	pool *pgxpool.Pool
}

func NewConsentStore(pool *pgxpool.Pool) *ConsentStore {
	return &ConsentStore{pool: pool}
}

// Record appends a consent entry.
func (s *ConsentStore) Record(ctx context.Context, c domain.Consent) error {
	const q = `
INSERT INTO user_consents (
  user_id, tos_version, privacy_version, accepted_at, ip, user_agent
) VALUES ($1, $2, $3, COALESCE($4, NOW()), $5::inet, $6)`

	var acceptedAt any
	if !c.AcceptedAt.IsZero() {
		acceptedAt = c.AcceptedAt
	}
	_, err := s.pool.Exec(ctx, q,
		c.UserID, c.TosVersion, c.PrivacyVersion, acceptedAt,
		nullableStringPtr(c.IP), nullableStringPtr(c.UserAgent),
	)
	if err != nil {
		return fmt.Errorf("consent store: record: %w", errMap(err))
	}
	return nil
}

// RecordConsent is the alias matching internal/auth.ConsentStore.
func (s *ConsentStore) RecordConsent(ctx context.Context, c domain.Consent) error {
	return s.Record(ctx, c)
}

func (s *ConsentStore) LatestForUser(ctx context.Context, userID uuid.UUID) (domain.Consent, error) {
	const q = `
SELECT id, user_id, tos_version, privacy_version, accepted_at,
       host(ip), user_agent
  FROM user_consents
 WHERE user_id = $1
 ORDER BY accepted_at DESC
 LIMIT 1`
	var (
		c     domain.Consent
		ipStr *string
		uaStr *string
	)
	err := s.pool.QueryRow(ctx, q, userID).Scan(
		&c.ID, &c.UserID, &c.TosVersion, &c.PrivacyVersion, &c.AcceptedAt,
		&ipStr, &uaStr,
	)
	if err != nil {
		if errors.Is(errMap(err), domain.ErrNotFound) {
			return domain.Consent{}, fmt.Errorf("consent store: latest: %w", domain.ErrNotFound)
		}
		return domain.Consent{}, fmt.Errorf("consent store: latest: %w", errMap(err))
	}
	c.IP = ipStr
	c.UserAgent = uaStr
	return c, nil
}

func (s *ConsentStore) ListForUser(ctx context.Context, userID uuid.UUID) ([]domain.Consent, error) {
	const q = `
SELECT id, user_id, tos_version, privacy_version, accepted_at,
       host(ip), user_agent
  FROM user_consents
 WHERE user_id = $1
 ORDER BY accepted_at DESC`
	rows, err := s.pool.Query(ctx, q, userID)
	if err != nil {
		return nil, fmt.Errorf("consent store: list: %w", errMap(err))
	}
	defer rows.Close()

	var out []domain.Consent
	for rows.Next() {
		var (
			c     domain.Consent
			ipStr *string
			uaStr *string
		)
		if err := rows.Scan(
			&c.ID, &c.UserID, &c.TosVersion, &c.PrivacyVersion, &c.AcceptedAt,
			&ipStr, &uaStr,
		); err != nil {
			return nil, fmt.Errorf("consent store: list scan: %w", err)
		}
		c.IP = ipStr
		c.UserAgent = uaStr
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("consent store: list rows: %w", err)
	}
	return out, nil
}

func nullableStringPtr(p *string) any {
	if p == nil {
		return nil
	}
	return *p
}
