-- 0008_crdt_epoch.up.sql
-- CRDT lineage identifier per note (docs/CRDT-CLIENT-PROTOCOL.md §12).
--
-- notes.crdt_epoch is an opaque token that changes whenever a NEW CRDT
-- history starts for (vault_id, id): note creation (a new row, so also
-- delete+recreate), and every seed of the CRDT from text (create-time
-- InitFromText, lazy init from the file, vault copy). Clients persisting
-- offline replicas compare it for equality to decide whether a replica
-- may still be merged into the server's note. Edits, FS diff merges,
-- compaction and renames/moves keep it.
--
-- The application always writes it (32 hex chars from crypto/rand); the
-- column default only covers rows inserted by other tooling. Existing
-- rows are backfilled with fresh epochs: clients holding replicas made
-- before this migration have no epoch to compare and fall back to their
-- pre-epoch heuristics once, then adopt the server's value.
--
-- The backfill does not bump vault seqs: /changes keeps serving existing
-- rows as they were until their next change; clients get the epoch from
-- GET /notes, ws-ticket, /snapshot or /state-vector.

ALTER TABLE notes ADD COLUMN crdt_epoch TEXT;

UPDATE notes SET crdt_epoch = replace(gen_random_uuid()::text, '-', '');

ALTER TABLE notes
  ALTER COLUMN crdt_epoch SET DEFAULT replace(gen_random_uuid()::text, '-', ''),
  ALTER COLUMN crdt_epoch SET NOT NULL;
