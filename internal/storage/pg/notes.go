package pg

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ViniZap4/lumi-server/internal/domain"
)

// NoteStore persists note metadata. Note bodies live on the filesystem; CRDT
// state lives in note_yjs_snapshots / note_yjs_updates (Phase 2).
type NoteStore struct {
	pool *pgxpool.Pool
}

func NewNoteStore(pool *pgxpool.Pool) *NoteStore {
	return &NoteStore{pool: pool}
}

func (s *NoteStore) Upsert(ctx context.Context, n domain.Note) error {
	const q = `
INSERT INTO notes (id, vault_id, path, title, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (vault_id, id) DO UPDATE
   SET path       = EXCLUDED.path,
       title      = EXCLUDED.title,
       updated_at = EXCLUDED.updated_at`
	_, err := s.pool.Exec(ctx, q,
		n.ID, n.VaultID, n.Path, n.Title, n.CreatedAt, n.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("note store: upsert: %w", errMap(err))
	}
	return nil
}

func (s *NoteStore) Get(ctx context.Context, vaultID uuid.UUID, id string) (domain.Note, error) {
	const q = `
SELECT id, vault_id, path, title, created_at, updated_at
  FROM notes
 WHERE vault_id = $1 AND id = $2`
	return s.scanOne(ctx, q, vaultID, id)
}

func (s *NoteStore) GetByPath(ctx context.Context, vaultID uuid.UUID, path string) (domain.Note, error) {
	const q = `
SELECT id, vault_id, path, title, created_at, updated_at
  FROM notes
 WHERE vault_id = $1 AND path = $2`
	return s.scanOne(ctx, q, vaultID, path)
}

func (s *NoteStore) ListForVault(
	ctx context.Context, vaultID uuid.UUID, limit, offset int,
) ([]domain.Note, error) {
	if offset < 0 {
		offset = 0
	}
	var limitArg any
	if limit > 0 {
		limitArg = limit
	} else {
		limitArg = nil
	}

	const q = `
SELECT id, vault_id, path, title, created_at, updated_at
  FROM notes
 WHERE vault_id = $1
 ORDER BY updated_at DESC
 LIMIT $2 OFFSET $3`
	rows, err := s.pool.Query(ctx, q, vaultID, limitArg, offset)
	if err != nil {
		return nil, fmt.Errorf("note store: list: %w", errMap(err))
	}
	defer rows.Close()

	var out []domain.Note
	for rows.Next() {
		var n domain.Note
		if err := rows.Scan(
			&n.ID, &n.VaultID, &n.Path, &n.Title, &n.CreatedAt, &n.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("note store: list scan: %w", err)
		}
		out = append(out, n)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("note store: list rows: %w", err)
	}
	return out, nil
}

func (s *NoteStore) Delete(ctx context.Context, vaultID uuid.UUID, id string) error {
	const q = `DELETE FROM notes WHERE vault_id = $1 AND id = $2`
	tag, err := s.pool.Exec(ctx, q, vaultID, id)
	if err != nil {
		return fmt.Errorf("note store: delete: %w", errMap(err))
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("note store: delete: %w", domain.ErrNotFound)
	}
	return nil
}

func (s *NoteStore) scanOne(ctx context.Context, q string, args ...any) (domain.Note, error) {
	var n domain.Note
	err := s.pool.QueryRow(ctx, q, args...).Scan(
		&n.ID, &n.VaultID, &n.Path, &n.Title, &n.CreatedAt, &n.UpdatedAt,
	)
	if err != nil {
		if errors.Is(errMap(err), domain.ErrNotFound) {
			return domain.Note{}, fmt.Errorf("note store: %w", domain.ErrNotFound)
		}
		return domain.Note{}, fmt.Errorf("note store: get: %w", errMap(err))
	}
	return n, nil
}
