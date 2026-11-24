-- 0010_mirror.down.sql
ALTER TABLE note_tombstones DROP COLUMN IF EXISTS crdt_epoch;
