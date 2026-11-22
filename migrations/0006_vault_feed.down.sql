-- 0006_vault_feed.down.sql

DROP TABLE note_tombstones;
DROP INDEX notes_vault_change_seq_idx;
ALTER TABLE notes DROP COLUMN change_seq;
DROP TABLE vault_heads;
