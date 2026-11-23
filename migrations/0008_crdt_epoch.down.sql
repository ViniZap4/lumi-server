-- 0008_crdt_epoch.down.sql
ALTER TABLE notes DROP COLUMN IF EXISTS crdt_epoch;
