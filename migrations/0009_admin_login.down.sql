-- 0009_admin_login.down.sql
-- Admin sessions cannot exist without the columns: drop them first.
DELETE FROM admin_tokens WHERE kind = 'session';
DROP INDEX IF EXISTS admin_tokens_user_id_idx;
ALTER TABLE admin_tokens
  DROP CONSTRAINT IF EXISTS admin_tokens_session_ttl_check,
  DROP CONSTRAINT IF EXISTS admin_tokens_session_user_check,
  DROP CONSTRAINT IF EXISTS admin_tokens_kind_check,
  DROP COLUMN IF EXISTS user_id,
  DROP COLUMN IF EXISTS kind;
ALTER TABLE users
  DROP COLUMN IF EXISTS server_admin;
