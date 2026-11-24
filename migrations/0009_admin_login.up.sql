-- 0009_admin_login.up.sql
-- Admin login with a user account (SPEC-PARTE2 §10, docs/ADMIN.md).
--
-- users.server_admin: the account may sign in to the admin panel with its
-- password. Granted by the CLI (`lumi-server admin grant <user>`), the
-- admin API (POST /admin/v1/users/{id}/server-admin) or the first-boot
-- bootstrap. Never granted by this migration: existing servers grant it
-- explicitly (or the bootstrap grants it to LUMI_ADMIN_USERNAME when its
-- LUMI_ADMIN_PASSWORD still matches and no server admin exists yet).
ALTER TABLE users
  ADD COLUMN server_admin BOOLEAN NOT NULL DEFAULT false;

-- admin_tokens now holds two kinds of bearer credentials:
--   token   "lpa_…": created by the CLI, no user, TTL up to 1 year;
--   session "lps_…": created by POST /admin/v1/session after a password
--                    login of a server admin, tied to that user, TTL at
--                    most 12 hours, never extended. Erasing the user
--                    deletes its admin sessions (ON DELETE CASCADE).
-- Both are stored as the SHA-256 of the whole token, like before.
ALTER TABLE admin_tokens
  ADD COLUMN kind    TEXT NOT NULL DEFAULT 'token',
  ADD COLUMN user_id UUID REFERENCES users(id) ON DELETE CASCADE,
  ADD CONSTRAINT admin_tokens_kind_check CHECK (kind IN ('token', 'session')),
  ADD CONSTRAINT admin_tokens_session_user_check CHECK ((kind = 'session') = (user_id IS NOT NULL)),
  ADD CONSTRAINT admin_tokens_session_ttl_check CHECK (kind <> 'session' OR expires_at <= created_at + interval '12 hours');

CREATE INDEX admin_tokens_user_id_idx ON admin_tokens (user_id) WHERE user_id IS NOT NULL;
