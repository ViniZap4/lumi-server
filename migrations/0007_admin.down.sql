-- 0007_admin.down.sql
ALTER TABLE users
  DROP COLUMN IF EXISTS locked_until,
  DROP COLUMN IF EXISTS failed_logins,
  DROP COLUMN IF EXISTS disabled_at;
DROP TABLE IF EXISTS admin_tokens;
