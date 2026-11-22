package pg

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ViniZap4/lumi-server/internal/domain"
)

// NoteStore persists note metadata. Note bodies live on the filesystem; CRDT
// state lives in note_yjs_snapshots / note_yjs_updates (Phase 2).
//
// Every write bumps the vault's change sequence (vault_heads.seq) in the
// same transaction and returns the new seq (SPEC-LIVROS §3.4). The head
// row is locked first in every write, so writers to one vault serialise
// until commit and commit order equals seq order: a reader that saw head
// H can never later find a commit with seq <= H appear.
type NoteStore struct {
	pool *pgxpool.Pool
}

func NewNoteStore(pool *pgxpool.Pool) *NoteStore {
	return &NoteStore{pool: pool}
}

const noteCols = `id, vault_id, path, title, created_at, updated_at, change_seq`

// bumpHeadSQL hands out the next seq for a vault. INSERT … ON CONFLICT
// covers vaults created after migration 0006 (no head row yet); either
// branch row-locks the head until the transaction ends.
const bumpHeadSQL = `
INSERT INTO vault_heads (vault_id, seq) VALUES ($1, 1)
ON CONFLICT (vault_id) DO UPDATE
   SET seq = vault_heads.seq + 1, updated_at = NOW()
RETURNING seq`

func bumpHead(ctx context.Context, tx pgx.Tx, vaultID uuid.UUID) (int64, error) {
	var seq int64
	if err := tx.QueryRow(ctx, bumpHeadSQL, vaultID).Scan(&seq); err != nil {
		return 0, fmt.Errorf("bump head: %w", errMap(err))
	}
	return seq, nil
}

// Upsert writes note metadata (create, move, rename, copy, federation
// create) and returns the vault seq stamped on the row.
func (s *NoteStore) Upsert(ctx context.Context, n domain.Note) (int64, error) {
	const q = `
INSERT INTO notes (id, vault_id, path, title, created_at, updated_at, change_seq)
VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT (vault_id, id) DO UPDATE
   SET path       = EXCLUDED.path,
       title      = EXCLUDED.title,
       updated_at = EXCLUDED.updated_at,
       change_seq = EXCLUDED.change_seq`
	var seq int64
	err := runTx(ctx, s.pool, func(tx pgx.Tx) error {
		var err error
		if seq, err = bumpHead(ctx, tx, n.VaultID); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, q, n.ID, n.VaultID, n.Path, n.Title, n.CreatedAt, n.UpdatedAt, seq)
		return err
	})
	if err != nil {
		return 0, fmt.Errorf("note store: upsert: %w", errMap(err))
	}
	return seq, nil
}

// TouchContent records a (coalesced) content edit: bumps the vault seq and
// stamps change_seq + updated_at. ErrNotFound if the note is gone (the
// bump is rolled back, so no seq is burnt).
func (s *NoteStore) TouchContent(ctx context.Context, vaultID uuid.UUID, id string, at time.Time) (int64, error) {
	const q = `UPDATE notes SET change_seq = $3, updated_at = $4 WHERE vault_id = $1 AND id = $2`
	var seq int64
	err := runTx(ctx, s.pool, func(tx pgx.Tx) error {
		var err error
		if seq, err = bumpHead(ctx, tx, vaultID); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, q, vaultID, id, seq, at)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return domain.ErrNotFound
		}
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("note store: touch content: %w", errMap(err))
	}
	return seq, nil
}

func (s *NoteStore) Get(ctx context.Context, vaultID uuid.UUID, id string) (domain.Note, error) {
	q := `SELECT ` + noteCols + ` FROM notes WHERE vault_id = $1 AND id = $2`
	return s.scanOne(ctx, q, vaultID, id)
}

func (s *NoteStore) GetByPath(ctx context.Context, vaultID uuid.UUID, path string) (domain.Note, error) {
	q := `SELECT ` + noteCols + ` FROM notes WHERE vault_id = $1 AND path = $2`
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

	q := `SELECT ` + noteCols + `
  FROM notes
 WHERE vault_id = $1
 ORDER BY updated_at DESC
 LIMIT $2 OFFSET $3`
	rows, err := s.pool.Query(ctx, q, vaultID, limitArg, offset)
	if err != nil {
		return nil, fmt.Errorf("note store: list: %w", errMap(err))
	}
	return collectNotes(rows)
}

// Delete removes the note row and records a tombstone at the new seq.
func (s *NoteStore) Delete(ctx context.Context, vaultID uuid.UUID, id string) (int64, error) {
	var seq int64
	err := runTx(ctx, s.pool, func(tx pgx.Tx) error {
		var err error
		if seq, err = bumpHead(ctx, tx, vaultID); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `DELETE FROM notes WHERE vault_id = $1 AND id = $2`, vaultID, id)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return domain.ErrNotFound
		}
		_, err = tx.Exec(ctx,
			`INSERT INTO note_tombstones (vault_id, note_id, seq) VALUES ($1, $2, $3)`,
			vaultID, id, seq)
		return err
	})
	if err != nil {
		return 0, fmt.Errorf("note store: delete: %w", errMap(err))
	}
	return seq, nil
}

// Heads returns the current seq for each vault (0 when a vault has no
// head row yet).
func (s *NoteStore) Heads(ctx context.Context, vaultIDs []uuid.UUID) (map[uuid.UUID]int64, error) {
	out := make(map[uuid.UUID]int64, len(vaultIDs))
	if len(vaultIDs) == 0 {
		return out, nil
	}
	rows, err := s.pool.Query(ctx, `SELECT vault_id, seq FROM vault_heads WHERE vault_id = ANY($1)`, vaultIDs)
	if err != nil {
		return nil, fmt.Errorf("note store: heads: %w", errMap(err))
	}
	defer rows.Close()
	for rows.Next() {
		var id uuid.UUID
		var seq int64
		if err := rows.Scan(&id, &seq); err != nil {
			return nil, fmt.Errorf("note store: heads scan: %w", err)
		}
		out[id] = seq
	}
	return out, rows.Err()
}

// Changes returns notes and tombstones with seq in (after, head], merged
// in seq order, at most limit entries. All reads run in one REPEATABLE
// READ snapshot so head, floor, rows and tombstones agree. A cursor
// below the tombstone floor yields *domain.ResyncRequiredError (after = 0
// never does: a client with nothing needs no deletions).
func (s *NoteStore) Changes(ctx context.Context, vaultID uuid.UUID, after int64, limit int) (domain.NoteChanges, error) {
	if limit <= 0 {
		limit = 1
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return domain.NoteChanges{}, fmt.Errorf("note store: changes begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var head, floor int64
	err = tx.QueryRow(ctx, `SELECT seq, tombstone_floor FROM vault_heads WHERE vault_id = $1`, vaultID).Scan(&head, &floor)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return domain.NoteChanges{}, fmt.Errorf("note store: changes head: %w", errMap(err))
	}
	if after > 0 && after < floor {
		return domain.NoteChanges{}, &domain.ResyncRequiredError{Head: head}
	}
	out := domain.NoteChanges{Head: head}
	if after >= head {
		return out, nil
	}

	// Fetch limit+1 of each kind: the merged page needs at most limit
	// entries and one more to know whether the page was cut.
	rows, err := tx.Query(ctx, `SELECT `+noteCols+`
  FROM notes
 WHERE vault_id = $1 AND change_seq > $2 AND change_seq <= $3
 ORDER BY change_seq
 LIMIT $4`, vaultID, after, head, limit+1)
	if err != nil {
		return domain.NoteChanges{}, fmt.Errorf("note store: changes notes: %w", errMap(err))
	}
	notes, err := collectNotes(rows)
	if err != nil {
		return domain.NoteChanges{}, err
	}

	trows, err := tx.Query(ctx, `SELECT note_id, seq
  FROM note_tombstones
 WHERE vault_id = $1 AND seq > $2 AND seq <= $3
 ORDER BY seq
 LIMIT $4`, vaultID, after, head, limit+1)
	if err != nil {
		return domain.NoteChanges{}, fmt.Errorf("note store: changes tombstones: %w", errMap(err))
	}
	defer trows.Close()
	var tombs []domain.NoteTombstone
	for trows.Next() {
		var t domain.NoteTombstone
		if err := trows.Scan(&t.ID, &t.Seq); err != nil {
			return domain.NoteChanges{}, fmt.Errorf("note store: changes tombstone scan: %w", err)
		}
		tombs = append(tombs, t)
	}
	if err := trows.Err(); err != nil {
		return domain.NoteChanges{}, fmt.Errorf("note store: changes tombstone rows: %w", err)
	}

	out.Notes, out.Deleted, out.More = MergeChangePage(notes, tombs, limit)
	return out, nil
}

// MergeChangePage merges two seq-ascending lists into the first limit
// entries by seq and reports whether anything was left over. Seqs are
// unique within a vault (one bump per row/tombstone), so the cut never
// splits equal seqs.
func MergeChangePage(notes []domain.Note, tombs []domain.NoteTombstone, limit int) ([]domain.Note, []domain.NoteTombstone, bool) {
	outN := make([]domain.Note, 0, min(len(notes), limit))
	outT := make([]domain.NoteTombstone, 0, min(len(tombs), limit))
	i, j := 0, 0
	for len(outN)+len(outT) < limit && (i < len(notes) || j < len(tombs)) {
		if j >= len(tombs) || (i < len(notes) && notes[i].ChangeSeq < tombs[j].Seq) {
			outN = append(outN, notes[i])
			i++
		} else {
			outT = append(outT, tombs[j])
			j++
		}
	}
	return outN, outT, i < len(notes) || j < len(tombs)
}

// PruneTombstones deletes tombstones older than before and raises each
// affected vault's tombstone_floor to the highest pruned seq, in one
// statement. Returns the number of tombstones removed.
func (s *NoteStore) PruneTombstones(ctx context.Context, before time.Time) (int64, error) {
	const q = `
WITH pruned AS (
  DELETE FROM note_tombstones WHERE deleted_at < $1
  RETURNING vault_id, seq
), floors AS (
  SELECT vault_id, max(seq) AS floor, count(*) AS n FROM pruned GROUP BY vault_id
), raised AS (
  UPDATE vault_heads h
     SET tombstone_floor = GREATEST(h.tombstone_floor, f.floor)
    FROM floors f
   WHERE h.vault_id = f.vault_id
)
SELECT COALESCE(sum(n), 0)::BIGINT FROM floors`
	var n int64
	if err := s.pool.QueryRow(ctx, q, before).Scan(&n); err != nil {
		return 0, fmt.Errorf("note store: prune tombstones: %w", errMap(err))
	}
	return n, nil
}

func collectNotes(rows pgx.Rows) ([]domain.Note, error) {
	defer rows.Close()
	var out []domain.Note
	for rows.Next() {
		var n domain.Note
		if err := rows.Scan(
			&n.ID, &n.VaultID, &n.Path, &n.Title, &n.CreatedAt, &n.UpdatedAt, &n.ChangeSeq,
		); err != nil {
			return nil, fmt.Errorf("note store: scan: %w", err)
		}
		out = append(out, n)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("note store: rows: %w", err)
	}
	return out, nil
}

func (s *NoteStore) scanOne(ctx context.Context, q string, args ...any) (domain.Note, error) {
	var n domain.Note
	err := s.pool.QueryRow(ctx, q, args...).Scan(
		&n.ID, &n.VaultID, &n.Path, &n.Title, &n.CreatedAt, &n.UpdatedAt, &n.ChangeSeq,
	)
	if err != nil {
		if errors.Is(errMap(err), domain.ErrNotFound) {
			return domain.Note{}, fmt.Errorf("note store: %w", domain.ErrNotFound)
		}
		return domain.Note{}, fmt.Errorf("note store: get: %w", errMap(err))
	}
	return n, nil
}
