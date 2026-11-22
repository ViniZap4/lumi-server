-- 0006_vault_feed.up.sql
-- Per-vault change sequence for the account feed and incremental sync
-- (SPEC-LIVROS §3.4).
--
-- vault_heads.seq is the highest seq handed out for the vault on THIS
-- server. Every note metadata write bumps it in the same transaction
-- (UPDATE ... RETURNING / INSERT ... ON CONFLICT DO UPDATE, which row-locks
-- the head and so serialises writers per vault until commit) and stamps
-- the value on notes.change_seq, or on a note_tombstones row for a delete.
-- Content edits bump through a per-note coalescer (<= 1/s per note).
--
-- tombstone_floor is the highest tombstone seq removed by pruning; a
-- client cursor below it can no longer be served incrementally
-- (GET /changes answers 410 resync_required).

CREATE TABLE vault_heads (
  vault_id        UUID PRIMARY KEY REFERENCES vaults(id) ON DELETE CASCADE,
  seq             BIGINT NOT NULL DEFAULT 0 CHECK (seq >= 0),
  tombstone_floor BIGINT NOT NULL DEFAULT 0 CHECK (tombstone_floor >= 0),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE notes ADD COLUMN change_seq BIGINT NOT NULL DEFAULT 0;
CREATE INDEX notes_vault_change_seq_idx ON notes (vault_id, change_seq);

CREATE TABLE note_tombstones (
  vault_id   UUID NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
  note_id    TEXT NOT NULL,
  seq        BIGINT NOT NULL,
  deleted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (vault_id, note_id, seq)
);
CREATE INDEX note_tombstones_vault_seq_idx ON note_tombstones (vault_id, seq);
CREATE INDEX note_tombstones_deleted_at_idx ON note_tombstones (deleted_at);

-- Backfill. Deviation from the spec sketch (every existing note at
-- change_seq = 1): existing notes get DISTINCT seqs 1..n per vault, so
-- seq stays unique within a vault and GET /changes can paginate with a
-- strict "seq > cursor" without ever splitting a run of equal seqs. The
-- head starts at n (0 for an empty vault). Both statements only touch
-- rows that were not backfilled yet.
UPDATE notes n
   SET change_seq = r.rn
  FROM (SELECT vault_id, id,
               row_number() OVER (PARTITION BY vault_id ORDER BY created_at, id) AS rn
          FROM notes) r
 WHERE n.vault_id = r.vault_id AND n.id = r.id AND n.change_seq = 0;

INSERT INTO vault_heads (vault_id, seq)
SELECT v.id, COALESCE((SELECT max(n.change_seq) FROM notes n WHERE n.vault_id = v.id), 0)
  FROM vaults v
ON CONFLICT (vault_id) DO NOTHING;
