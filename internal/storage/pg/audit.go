package pg

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ViniZap4/lumi-server/internal/domain"
)

// AuditStore persists the audit log. Rows are retained after user erasure
// (PII fields nullified instead) for forensic and compliance reasons.
type AuditStore struct {
	pool *pgxpool.Pool
}

func NewAuditStore(pool *pgxpool.Pool) *AuditStore {
	return &AuditStore{pool: pool}
}

// Record appends a single audit entry. Payload is opaque JSON.
func (s *AuditStore) Record(ctx context.Context, e domain.AuditEntry) error {
	const q = `
INSERT INTO audit_log (user_id, vault_id, action, payload, ip, user_agent, created_at)
VALUES ($1, $2, $3, $4::jsonb, $5::inet, $6, COALESCE($7, NOW()))`

	var payloadArg any
	if len(e.Payload) > 0 {
		payloadArg = string(e.Payload)
	}
	var createdAt any
	if !e.CreatedAt.IsZero() {
		createdAt = e.CreatedAt
	}

	_, err := s.pool.Exec(ctx, q,
		uuidArg(e.UserID), uuidArg(e.VaultID), e.Action, payloadArg,
		nullableStringPtr(e.IP), nullableStringPtr(e.UserAgent), createdAt,
	)
	if err != nil {
		return fmt.Errorf("audit store: record: %w", errMap(err))
	}
	return nil
}

func (s *AuditStore) ListForUser(
	ctx context.Context, userID uuid.UUID, limit, offset int,
) ([]domain.AuditEntry, error) {
	if offset < 0 {
		offset = 0
	}
	var limitArg any
	if limit > 0 {
		limitArg = limit
	}

	const q = `
SELECT id, user_id, vault_id, action, payload, host(ip), user_agent, created_at
  FROM audit_log
 WHERE user_id = $1
 ORDER BY created_at DESC
 LIMIT $2 OFFSET $3`
	return s.queryEntries(ctx, q, userID, limitArg, offset)
}

func (s *AuditStore) ListForVault(
	ctx context.Context, vaultID uuid.UUID, limit, offset int,
) ([]domain.AuditEntry, error) {
	if offset < 0 {
		offset = 0
	}
	var limitArg any
	if limit > 0 {
		limitArg = limit
	}

	const q = `
SELECT id, user_id, vault_id, action, payload, host(ip), user_agent, created_at
  FROM audit_log
 WHERE vault_id = $1
 ORDER BY created_at DESC
 LIMIT $2 OFFSET $3`
	return s.queryEntries(ctx, q, vaultID, limitArg, offset)
}

// AnonymiseUser is the LGPD erasure routine for audit rows.
func (s *AuditStore) AnonymiseUser(ctx context.Context, userID uuid.UUID) error {
	return runTx(ctx, s.pool, func(tx pgx.Tx) error {
		return anonymiseUserAuditTx(ctx, tx, userID)
	})
}

func anonymiseUserAuditTx(ctx context.Context, tx pgx.Tx, userID uuid.UUID) error {
	// Step 1: nullify PII columns and scrub the username key in payload.
	const q = `
UPDATE audit_log
   SET user_id    = NULL,
       ip         = NULL,
       user_agent = NULL,
       payload    = CASE
         WHEN payload IS NULL THEN NULL
         WHEN jsonb_typeof(payload->'username') = 'string'
           THEN jsonb_set(payload, '{username}', '"<redacted>"'::jsonb, false)
         ELSE payload
       END
 WHERE user_id = $1`
	if _, err := tx.Exec(ctx, q, userID); err != nil {
		return fmt.Errorf("anonymise audit (username): %w", errMap(err))
	}

	// Step 2: scrub the remaining free-text PII keys. We can no longer
	// filter by user_id (already nulled), so we scrub any row whose
	// payload still contains the key as a string. Bounded by the explicit
	// key list.
	const scrubKey = `
UPDATE audit_log
   SET payload = jsonb_set(payload, ARRAY[$1]::text[], '"<redacted>"'::jsonb, false)
 WHERE user_id IS NULL
   AND payload IS NOT NULL
   AND jsonb_typeof(payload -> $1) = 'string'`
	for _, key := range []string{"email", "display_name", "ip"} {
		if _, err := tx.Exec(ctx, scrubKey, key); err != nil {
			return fmt.Errorf("anonymise audit (%s): %w", key, errMap(err))
		}
	}
	return nil
}

func (s *AuditStore) PurgeOlderThan(ctx context.Context, days int) (int64, error) {
	if days <= 0 {
		return 0, fmt.Errorf("audit store: purge: %w: days must be > 0", domain.ErrValidation)
	}
	const q = `DELETE FROM audit_log WHERE created_at < NOW() - ($1::int * INTERVAL '1 day')`
	tag, err := s.pool.Exec(ctx, q, days)
	if err != nil {
		return 0, fmt.Errorf("audit store: purge: %w", errMap(err))
	}
	return tag.RowsAffected(), nil
}

func (s *AuditStore) queryEntries(
	ctx context.Context, q string, args ...any,
) ([]domain.AuditEntry, error) {
	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("audit store: query: %w", errMap(err))
	}
	defer rows.Close()

	var out []domain.AuditEntry
	for rows.Next() {
		var (
			e       domain.AuditEntry
			userID  *uuid.UUID
			vaultID *uuid.UUID
			payload []byte
			ipStr   *string
			uaStr   *string
		)
		if err := rows.Scan(
			&e.ID, &userID, &vaultID, &e.Action, &payload, &ipStr, &uaStr, &e.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("audit store: scan: %w", err)
		}
		e.UserID = userID
		e.VaultID = vaultID
		e.Payload = payload
		e.IP = ipStr
		e.UserAgent = uaStr
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("audit store: rows: %w", err)
	}
	return out, nil
}

func uuidArg(id *uuid.UUID) any {
	if id == nil {
		return nil
	}
	return *id
}

// LatestActionAt returns created_at of the most recent audit entry matching
// (user_id, action). Used by the LGPD export rate limiter.
func (s *AuditStore) LatestActionAt(ctx context.Context, userID uuid.UUID, action string) (any, error) {
	const q = `
SELECT created_at
  FROM audit_log
 WHERE user_id = $1 AND action = $2
 ORDER BY created_at DESC
 LIMIT 1`
	var t any
	err := s.pool.QueryRow(ctx, q, userID, action).Scan(&t)
	if err != nil {
		return nil, fmt.Errorf("audit store: latest action: %w", errMap(err))
	}
	return t, nil
}
