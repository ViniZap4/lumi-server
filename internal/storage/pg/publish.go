package pg

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ViniZap4/lumi-server/internal/domain"
)

// PublishSetting is domain.PublishSetting (publish_settings, 0012).
type PublishSetting = domain.PublishSetting

// PublishStore persists publish_settings.
type PublishStore struct{ pool *pgxpool.Pool }

func NewPublishStore(pool *pgxpool.Pool) *PublishStore { return &PublishStore{pool: pool} }

const publishCols = `vault_id, base_path, robots, enabled_at`

func scanPublish(row pgx.Row) (PublishSetting, error) {
	var p PublishSetting
	if err := row.Scan(&p.VaultID, &p.BasePath, &p.Robots, &p.EnabledAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return PublishSetting{}, fmt.Errorf("publish store: %w", domain.ErrNotFound)
		}
		return PublishSetting{}, fmt.Errorf("publish store: %w", errMap(err))
	}
	return p, nil
}

// GetByBasePath looks a published book up by its base path.
func (s *PublishStore) GetByBasePath(ctx context.Context, basePath string) (PublishSetting, error) {
	return scanPublish(s.pool.QueryRow(ctx, `SELECT `+publishCols+` FROM publish_settings WHERE base_path = $1`, basePath))
}

// Get returns a vault's setting.
func (s *PublishStore) Get(ctx context.Context, vaultID uuid.UUID) (PublishSetting, error) {
	return scanPublish(s.pool.QueryRow(ctx, `SELECT `+publishCols+` FROM publish_settings WHERE vault_id = $1`, vaultID))
}

// Upsert enables (or updates) a vault's publication and writes the audit
// row in the same transaction.
func (s *PublishStore) Upsert(ctx context.Context, p PublishSetting, e domain.AuditEntry) error {
	err := runTx(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `
INSERT INTO publish_settings (vault_id, base_path, robots, enabled_at)
VALUES ($1, $2, $3, $4)
ON CONFLICT (vault_id) DO UPDATE SET base_path = EXCLUDED.base_path, robots = EXCLUDED.robots`,
			p.VaultID, p.BasePath, p.Robots, p.EnabledAt); err != nil {
			return err
		}
		return insertAudit(ctx, tx, e)
	})
	if err != nil {
		return fmt.Errorf("publish store: upsert: %w", errMap(err))
	}
	return nil
}

// Delete disables a vault's publication (audited in the same transaction).
func (s *PublishStore) Delete(ctx context.Context, vaultID uuid.UUID, e domain.AuditEntry) error {
	err := runTx(ctx, s.pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM publish_settings WHERE vault_id = $1`, vaultID)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return domain.ErrNotFound
		}
		return insertAudit(ctx, tx, e)
	})
	if err != nil {
		return fmt.Errorf("publish store: delete: %w", errMap(err))
	}
	return nil
}

// List returns every publication.
func (s *PublishStore) List(ctx context.Context) ([]PublishSetting, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+publishCols+` FROM publish_settings ORDER BY base_path`)
	if err != nil {
		return nil, fmt.Errorf("publish store: list: %w", errMap(err))
	}
	defer rows.Close()
	var out []PublishSetting
	for rows.Next() {
		var p PublishSetting
		if err := rows.Scan(&p.VaultID, &p.BasePath, &p.Robots, &p.EnabledAt); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}
