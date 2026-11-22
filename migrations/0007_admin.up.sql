-- 0007_admin.up.sql
-- Server administration (docs/ADMIN.md).
--
-- admin_tokens: bearer credentials for the admin listener. Created only by
-- the CLI (`lumi-server token create`); the API can list and revoke them but
-- never mint one, so a leaked token cannot perpetuate itself. token_hash is
-- the raw SHA-256 of the whole "lpa_..." string; the token itself is shown
-- once and never stored.
CREATE TABLE admin_tokens (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name         TEXT NOT NULL CHECK (char_length(name) BETWEEN 1 AND 64),
  token_hash   BYTEA NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_used_at TIMESTAMPTZ,
  expires_at   TIMESTAMPTZ NOT NULL,
  revoked_at   TIMESTAMPTZ,
  CHECK (expires_at > created_at)
);

-- Account state managed by the operator.
--   disabled_at:   set by `user disable`; login and every session refused.
--   failed_logins: consecutive wrong passwords for an existing account.
--   locked_until:  set once failed_logins reaches the threshold; grows
--                  exponentially, capped (internal/auth). `user unlock`
--                  clears both.
ALTER TABLE users
  ADD COLUMN disabled_at   TIMESTAMPTZ,
  ADD COLUMN failed_logins INT NOT NULL DEFAULT 0 CHECK (failed_logins >= 0),
  ADD COLUMN locked_until  TIMESTAMPTZ;
