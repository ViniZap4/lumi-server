-- 0010_mirror.down.sql
DROP INDEX IF EXISTS vault_federations_one_follower;
ALTER TABLE vault_federations
  DROP COLUMN IF EXISTS promoted_at,
  DROP COLUMN IF EXISTS resync_requested_at,
  DROP COLUMN IF EXISTS paused_at,
  DROP COLUMN IF EXISTS last_integrity_at,
  DROP COLUMN IF EXISTS last_contact_at,
  DROP COLUMN IF EXISTS backfill_cursor,
  DROP COLUMN IF EXISTS home_seq,
  DROP COLUMN IF EXISTS mirror_acked_seq,
  DROP COLUMN IF EXISTS sever_policy,
  DROP COLUMN IF EXISTS publish,
  DROP COLUMN IF EXISTS mode;
ALTER TABLE federation_invites
  DROP COLUMN IF EXISTS sever_policy,
  DROP COLUMN IF EXISTS publish,
  DROP COLUMN IF EXISTS mode;
ALTER TABLE note_tombstones DROP COLUMN IF EXISTS crdt_epoch;
