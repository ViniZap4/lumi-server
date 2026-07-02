package pg

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ViniZap4/lumi-server/internal/domain"
)

// VaultStore persists vault rows.
type VaultStore struct {
	pool *pgxpool.Pool
}

func NewVaultStore(pool *pgxpool.Pool) *VaultStore {
	return &VaultStore{pool: pool}
}

const vaultCols = `id, slug, name, created_by, owner_user_id, copied_from, created_at`

// Create inserts a new vault and returns the persisted row. Slug uniqueness
// is enforced at the DB level.
func (s *VaultStore) Create(ctx context.Context, v domain.Vault) (domain.Vault, error) {
	const q = `
INSERT INTO vaults (id, slug, name, created_by, owner_user_id, copied_from, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7)`
	var copiedFrom any
	if len(v.CopiedFrom) > 0 {
		copiedFrom = v.CopiedFrom
	}
	_, err := s.pool.Exec(ctx, q, v.ID, v.Slug, v.Name, v.CreatedBy, v.OwnerUserID, copiedFrom, v.CreatedAt)
	if err != nil {
		return domain.Vault{}, fmt.Errorf("vault store: create: %w", errMap(err))
	}
	return v, nil
}

func (s *VaultStore) GetByID(ctx context.Context, id uuid.UUID) (domain.Vault, error) {
	q := `SELECT ` + vaultCols + ` FROM vaults WHERE id = $1`
	return s.scanOne(ctx, q, id)
}

func (s *VaultStore) GetBySlug(ctx context.Context, slug string) (domain.Vault, error) {
	q := `SELECT ` + vaultCols + ` FROM vaults WHERE slug = $1`
	return s.scanOne(ctx, q, slug)
}

// ListForUser returns every vault the user is a member of, ordered by name.
func (s *VaultStore) ListForUser(ctx context.Context, userID uuid.UUID) ([]domain.Vault, error) {
	const q = `
SELECT v.id, v.slug, v.name, v.created_by, v.owner_user_id, v.copied_from, v.created_at
  FROM vaults v
  JOIN vault_members m ON m.vault_id = v.id
 WHERE m.user_id = $1
 ORDER BY v.name ASC`
	rows, err := s.pool.Query(ctx, q, userID)
	if err != nil {
		return nil, fmt.Errorf("vault store: list for user: %w", errMap(err))
	}
	defer rows.Close()

	var out []domain.Vault
	for rows.Next() {
		v, err := scanVault(rows.Scan)
		if err != nil {
			return nil, fmt.Errorf("vault store: list for user scan: %w", err)
		}
		out = append(out, v)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("vault store: list for user rows: %w", err)
	}
	return out, nil
}

func (s *VaultStore) UpdateName(ctx context.Context, id uuid.UUID, name string) error {
	const q = `UPDATE vaults SET name = $2 WHERE id = $1`
	tag, err := s.pool.Exec(ctx, q, id, name)
	if err != nil {
		return fmt.Errorf("vault store: update name: %w", errMap(err))
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("vault store: update name: %w", domain.ErrNotFound)
	}
	return nil
}

// UpdateOwner reassigns the vault owner. Callers enforce the actor-is-owner
// and new-owner-is-member invariants; this is a bare write.
func (s *VaultStore) UpdateOwner(ctx context.Context, id, newOwner uuid.UUID) error {
	const q = `UPDATE vaults SET owner_user_id = $2 WHERE id = $1`
	tag, err := s.pool.Exec(ctx, q, id, newOwner)
	if err != nil {
		return fmt.Errorf("vault store: update owner: %w", errMap(err))
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("vault store: update owner: %w", domain.ErrNotFound)
	}
	return nil
}

// SetCopiedFrom records share-a-copy provenance on a freshly forked vault.
func (s *VaultStore) SetCopiedFrom(ctx context.Context, id uuid.UUID, provenance []byte) error {
	const q = `UPDATE vaults SET copied_from = $2 WHERE id = $1`
	tag, err := s.pool.Exec(ctx, q, id, provenance)
	if err != nil {
		return fmt.Errorf("vault store: set copied_from: %w", errMap(err))
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("vault store: set copied_from: %w", domain.ErrNotFound)
	}
	return nil
}

// Delete drops a vault. ON DELETE CASCADE removes roles, members, invites,
// notes, snapshots and updates.
func (s *VaultStore) Delete(ctx context.Context, id uuid.UUID) error {
	const q = `DELETE FROM vaults WHERE id = $1`
	tag, err := s.pool.Exec(ctx, q, id)
	if err != nil {
		return fmt.Errorf("vault store: delete: %w", errMap(err))
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("vault store: delete: %w", domain.ErrNotFound)
	}
	return nil
}

// scanVault reads one row via the supplied Scan func. created_by is nullable
// post-0002 (LGPD-nullified provenance) and maps to uuid.Nil.
func scanVault(scan func(dest ...any) error) (domain.Vault, error) {
	var (
		v          domain.Vault
		createdBy  *uuid.UUID
		copiedFrom []byte
	)
	if err := scan(&v.ID, &v.Slug, &v.Name, &createdBy, &v.OwnerUserID, &copiedFrom, &v.CreatedAt); err != nil {
		return domain.Vault{}, err
	}
	if createdBy != nil {
		v.CreatedBy = *createdBy
	}
	v.CopiedFrom = copiedFrom
	return v, nil
}

func (s *VaultStore) scanOne(ctx context.Context, q string, args ...any) (domain.Vault, error) {
	row := s.pool.QueryRow(ctx, q, args...)
	v, err := scanVault(row.Scan)
	if err != nil {
		if errors.Is(errMap(err), domain.ErrNotFound) {
			return domain.Vault{}, fmt.Errorf("vault store: %w", domain.ErrNotFound)
		}
		return domain.Vault{}, fmt.Errorf("vault store: get: %w", errMap(err))
	}
	return v, nil
}
