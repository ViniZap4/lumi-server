-- 0010_mirror.up.sql
-- Federation hardening + one-way mirrors (docs/SPEC-ESPELHO-SELADO.md §A18).

-- G2: a tombstone remembers which CRDT history it ended, so the relay can
-- tell "the peer still holds the note home deleted" (same epoch: refuse to
-- resurrect it) from "the peer created a new note under that id" (new
-- epoch). NULL on tombstones written before this migration.
ALTER TABLE note_tombstones ADD COLUMN crdt_epoch TEXT;
