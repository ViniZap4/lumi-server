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

// NoteYjsSnapshot is a row in note_yjs_snapshots — exactly one per
// (vault_id, note_id). Replaced on compaction.
type NoteYjsSnapshot struct {
	VaultID       uuid.UUID
	NoteID        string
	State         []byte
	SnapshottedAt time.Time
}

// NoteYjsUpdate is an append-only row in note_yjs_updates. Ordering is by
// `id` (BIGSERIAL); origin_user_id may be NULL for system-driven updates
// (fs-watcher, compaction); origin_kind is a free-form string scoped to
// the SPEC vocabulary: 'web', 'tui-diff', 'fs-watcher', 'snapshot-init'.
type NoteYjsUpdate struct {
	ID           int64
	VaultID      uuid.UUID
	NoteID       string
	Update       []byte
	OriginUserID *uuid.UUID
	OriginKind   string
	CreatedAt    time.Time
}

// NoteYjsStore persists CRDT snapshots and the update log.
type NoteYjsStore struct {
	pool *pgxpool.Pool
}

func NewNoteYjsStore(pool *pgxpool.Pool) *NoteYjsStore {
	return &NoteYjsStore{pool: pool}
}

// GetSnapshot returns the most recent snapshot for (vault_id, note_id) or
// domain.ErrNotFound when none exists. State bytes are returned as-is.
func (s *NoteYjsStore) GetSnapshot(ctx context.Context, vaultID uuid.UUID, noteID string) (NoteYjsSnapshot, error) {
	const q = `
SELECT vault_id, note_id, state, snapshotted_at
  FROM note_yjs_snapshots
 WHERE vault_id = $1 AND note_id = $2`
	var row NoteYjsSnapshot
	err := s.pool.QueryRow(ctx, q, vaultID, noteID).Scan(
		&row.VaultID, &row.NoteID, &row.State, &row.SnapshottedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return NoteYjsSnapshot{}, fmt.Errorf("note_yjs snapshot: %w", domain.ErrNotFound)
		}
		return NoteYjsSnapshot{}, fmt.Errorf("note_yjs snapshot: get: %w", errMap(err))
	}
	return row, nil
}

// UpsertSnapshot writes (or replaces) the snapshot blob for the note.
// snapshotted_at is set server-side via NOW().
func (s *NoteYjsStore) UpsertSnapshot(ctx context.Context, vaultID uuid.UUID, noteID string, state []byte) error {
	const q = `
INSERT INTO note_yjs_snapshots (vault_id, note_id, state)
VALUES ($1, $2, $3)
ON CONFLICT (vault_id, note_id) DO UPDATE
   SET state          = EXCLUDED.state,
       snapshotted_at = NOW()`
	if _, err := s.pool.Exec(ctx, q, vaultID, noteID, state); err != nil {
		return fmt.Errorf("note_yjs snapshot: upsert: %w", errMap(err))
	}
	return nil
}

// SeedSnapshot starts a NEW CRDT history for the note in one transaction
// (docs/CRDT-CLIENT-PROTOCOL.md §12): it replaces the snapshot with
// state, drops every update-log row (a leftover row belongs to an older
// history and must never be replayed onto the new one) and stamps epoch
// on the notes row. When the epoch actually changes the vault seq is
// bumped and stamped on the row, so GET /changes carries the new epoch;
// that seq is returned (0 when the row already held epoch, e.g. create
// inserted the row with it).
//
// Lock order matches every other note write: the vault head is taken
// (bumpHead) before the notes row is written. The pre-check runs without
// a row lock; callers serialise seeding per note (crdt.Registry seed lock).
func (s *NoteYjsStore) SeedSnapshot(ctx context.Context, vaultID uuid.UUID, noteID string, state []byte, epoch string) (int64, error) {
	if epoch == "" {
		return 0, fmt.Errorf("note_yjs seed: %w: empty epoch", domain.ErrValidation)
	}
	const upsertSnap = `
INSERT INTO note_yjs_snapshots (vault_id, note_id, state)
VALUES ($1, $2, $3)
ON CONFLICT (vault_id, note_id) DO UPDATE
   SET state          = EXCLUDED.state,
       snapshotted_at = NOW()`
	var seq int64
	err := runTx(ctx, s.pool, func(tx pgx.Tx) error {
		var current string
		err := tx.QueryRow(ctx,
			`SELECT crdt_epoch FROM notes WHERE vault_id = $1 AND id = $2`,
			vaultID, noteID).Scan(&current)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return domain.ErrNotFound
			}
			return err
		}
		if current != epoch {
			if seq, err = bumpHead(ctx, tx, vaultID); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx,
				`UPDATE notes SET crdt_epoch = $3, change_seq = $4 WHERE vault_id = $1 AND id = $2`,
				vaultID, noteID, epoch, seq); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx,
			`DELETE FROM note_yjs_updates WHERE vault_id = $1 AND note_id = $2`,
			vaultID, noteID); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, upsertSnap, vaultID, noteID, state)
		return err
	})
	if err != nil {
		return 0, fmt.Errorf("note_yjs seed: %w", errMap(err))
	}
	return seq, nil
}

// AppendUpdate adds a row to the update log and returns the assigned id.
// originUserID may be uuid.Nil to record NULL.
func (s *NoteYjsStore) AppendUpdate(
	ctx context.Context,
	vaultID uuid.UUID, noteID string,
	update []byte, originUserID uuid.UUID, originKind string,
) (int64, error) {
	const q = `
INSERT INTO note_yjs_updates (vault_id, note_id, update_blob, origin_user_id, origin_kind)
VALUES ($1, $2, $3, $4, $5)
RETURNING id`
	var origin any
	if originUserID != uuid.Nil {
		origin = originUserID
	}
	var id int64
	err := s.pool.QueryRow(ctx, q, vaultID, noteID, update, origin, originKind).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("note_yjs update: append: %w", errMap(err))
	}
	return id, nil
}

// ListUpdatesSince returns updates with id > sinceID in ascending order.
// Pass sinceID = 0 to get all updates. limit ≤ 0 means "no limit".
func (s *NoteYjsStore) ListUpdatesSince(
	ctx context.Context,
	vaultID uuid.UUID, noteID string,
	sinceID int64, limit int,
) ([]NoteYjsUpdate, error) {
	var (
		rows pgx.Rows
		err  error
	)
	if limit > 0 {
		const q = `
SELECT id, vault_id, note_id, update_blob, origin_user_id, origin_kind, created_at
  FROM note_yjs_updates
 WHERE vault_id = $1 AND note_id = $2 AND id > $3
 ORDER BY id ASC
 LIMIT $4`
		rows, err = s.pool.Query(ctx, q, vaultID, noteID, sinceID, limit)
	} else {
		const q = `
SELECT id, vault_id, note_id, update_blob, origin_user_id, origin_kind, created_at
  FROM note_yjs_updates
 WHERE vault_id = $1 AND note_id = $2 AND id > $3
 ORDER BY id ASC`
		rows, err = s.pool.Query(ctx, q, vaultID, noteID, sinceID)
	}
	if err != nil {
		return nil, fmt.Errorf("note_yjs update: list: %w", errMap(err))
	}
	defer rows.Close()

	out := []NoteYjsUpdate{}
	for rows.Next() {
		var u NoteYjsUpdate
		var origin *uuid.UUID
		if err := rows.Scan(&u.ID, &u.VaultID, &u.NoteID, &u.Update, &origin, &u.OriginKind, &u.CreatedAt); err != nil {
			return nil, fmt.Errorf("note_yjs update: list scan: %w", err)
		}
		u.OriginUserID = origin
		out = append(out, u)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("note_yjs update: list rows: %w", err)
	}
	return out, nil
}

// CountUpdates returns the number of update rows and the sum of
// update_blob byte lengths. Used to decide when to compact.
func (s *NoteYjsStore) CountUpdates(ctx context.Context, vaultID uuid.UUID, noteID string) (count int, bytes int64, err error) {
	const q = `
SELECT COUNT(*), COALESCE(SUM(OCTET_LENGTH(update_blob)), 0)
  FROM note_yjs_updates
 WHERE vault_id = $1 AND note_id = $2`
	row := s.pool.QueryRow(ctx, q, vaultID, noteID)
	if err := row.Scan(&count, &bytes); err != nil {
		return 0, 0, fmt.Errorf("note_yjs update: count: %w", errMap(err))
	}
	return count, bytes, nil
}

// DeleteUpdatesUpTo removes all updates with id <= maxID for the note.
// Used during compaction once the snapshot has folded them in.
func (s *NoteYjsStore) DeleteUpdatesUpTo(ctx context.Context, vaultID uuid.UUID, noteID string, maxID int64) (int64, error) {
	const q = `
DELETE FROM note_yjs_updates
 WHERE vault_id = $1 AND note_id = $2 AND id <= $3`
	tag, err := s.pool.Exec(ctx, q, vaultID, noteID, maxID)
	if err != nil {
		return 0, fmt.Errorf("note_yjs update: delete: %w", errMap(err))
	}
	return tag.RowsAffected(), nil
}

// HighestUpdateID returns the largest update id for the note, or 0 if
// the log is empty. Used to scope a compaction window so updates that
// arrive while we're compacting are not lost.
func (s *NoteYjsStore) HighestUpdateID(ctx context.Context, vaultID uuid.UUID, noteID string) (int64, error) {
	const q = `
SELECT COALESCE(MAX(id), 0) FROM note_yjs_updates
 WHERE vault_id = $1 AND note_id = $2`
	var id int64
	if err := s.pool.QueryRow(ctx, q, vaultID, noteID).Scan(&id); err != nil {
		return 0, fmt.Errorf("note_yjs update: max: %w", errMap(err))
	}
	return id, nil
}

// ResetNote drops a note's persisted CRDT history (snapshot and update
// log) and keeps the row and its epoch: a mirror rebuilding a diverged
// copy from home's full state (docs/SPEC-ESPELHO-SELADO.md §A9).
func (s *NoteYjsStore) ResetNote(ctx context.Context, vaultID uuid.UUID, noteID string) error {
	err := runTx(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM note_yjs_updates WHERE vault_id = $1 AND note_id = $2`, vaultID, noteID); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `DELETE FROM note_yjs_snapshots WHERE vault_id = $1 AND note_id = $2`, vaultID, noteID)
		return err
	})
	if err != nil {
		return fmt.Errorf("note_yjs reset: %w", errMap(err))
	}
	return nil
}
