package pg

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ViniZap4/lumi-server/internal/auth"
)

// DeviceLinkStore implements auth.DeviceLinkStore (SPEC-LIVROS §8.4).
// Like SessionStore it only stores hashes: link codes as
// auth.HashLinkCode and sessions by token_hash (= auth.SessionRef).
type DeviceLinkStore struct {
	pool *pgxpool.Pool
}

func NewDeviceLinkStore(pool *pgxpool.Pool) *DeviceLinkStore {
	return &DeviceLinkStore{pool: pool}
}

var _ auth.DeviceLinkStore = (*DeviceLinkStore)(nil)

// CreateLinkCode inserts a code and purges expired ones.
func (s *DeviceLinkStore) CreateLinkCode(ctx context.Context, c auth.LinkCode) error {
	return runTx(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM device_link_codes WHERE expires_at <= NOW()`); err != nil {
			return fmt.Errorf("device links: purge: %w", errMap(err))
		}
		_, err := tx.Exec(ctx, `
INSERT INTO device_link_codes (code_hash, user_id, issuer_token_hash, challenge, label, created_at, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7)`,
			c.CodeHash, c.UserID, c.Issuer, c.Challenge, c.Label, c.CreatedAt, c.ExpiresAt)
		if err != nil {
			return fmt.Errorf("device links: create: %w", errMap(err))
		}
		return nil
	})
}

// ConsumeLinkCode deletes and returns the code in one statement, so two
// concurrent redeems can't both win. The code is spent even when its
// issuer session has expired; it is only returned while that session is
// live (a revoked session already took its codes with it via CASCADE).
func (s *DeviceLinkStore) ConsumeLinkCode(ctx context.Context, codeHash string) (auth.LinkCode, error) {
	var out auth.LinkCode
	var issuerLive bool
	err := s.pool.QueryRow(ctx, `
WITH spent AS (
  DELETE FROM device_link_codes
   WHERE code_hash = $1
  RETURNING code_hash, user_id, issuer_token_hash, challenge, label, created_at, expires_at
)
SELECT spent.code_hash, spent.user_id, spent.issuer_token_hash, spent.challenge, spent.label,
       spent.created_at, spent.expires_at,
       EXISTS (SELECT 1 FROM sessions s
                WHERE s.token_hash = spent.issuer_token_hash
                  AND s.user_id = spent.user_id
                  AND s.expires_at > NOW())
  FROM spent`, codeHash).
		Scan(&out.CodeHash, &out.UserID, &out.Issuer, &out.Challenge, &out.Label,
			&out.CreatedAt, &out.ExpiresAt, &issuerLive)
	if err != nil {
		return auth.LinkCode{}, fmt.Errorf("device links: consume: %w", errMap(err))
	}
	if !issuerLive {
		return auth.LinkCode{}, fmt.Errorf("device links: consume: issuer ended: %w", errMap(pgx.ErrNoRows))
	}
	return out, nil
}

// LinkSessions adds newToken to the issuer's link group, creating the
// group (and the issuer's row) when the issuer has none.
func (s *DeviceLinkStore) LinkSessions(ctx context.Context, issuer, newToken string) error {
	return runTx(ctx, s.pool, func(tx pgx.Tx) error {
		var group uuid.UUID
		err := tx.QueryRow(ctx, `
INSERT INTO session_links (token_hash, link_group)
VALUES ($1, $2)
ON CONFLICT (token_hash) DO UPDATE SET token_hash = EXCLUDED.token_hash
RETURNING link_group`, issuer, uuid.New()).Scan(&group)
		if err != nil {
			return fmt.Errorf("device links: issuer group: %w", errMap(err))
		}
		if _, err := tx.Exec(ctx, `
INSERT INTO session_links (token_hash, link_group) VALUES ($1, $2)`,
			hashSessionToken(newToken), group); err != nil {
			return fmt.Errorf("device links: link: %w", errMap(err))
		}
		return nil
	})
}

// DeleteLinkedSessions deletes userID's sessions in token's link group,
// except token itself (the caller logs that one out the usual way).
func (s *DeviceLinkStore) DeleteLinkedSessions(ctx context.Context, userID uuid.UUID, token string) (int, error) {
	tag, err := s.pool.Exec(ctx, `
DELETE FROM sessions
 WHERE user_id = $1
   AND token_hash <> $2
   AND token_hash IN (
     SELECT l.token_hash FROM session_links l
      WHERE l.link_group = (SELECT link_group FROM session_links WHERE token_hash = $2))`,
		userID, hashSessionToken(token))
	if err != nil {
		return 0, fmt.Errorf("device links: delete linked: %w", errMap(err))
	}
	return int(tag.RowsAffected()), nil
}
