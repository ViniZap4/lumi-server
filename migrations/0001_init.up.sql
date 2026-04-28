-- 0001_init.up.sql
-- v2 initial schema. See SPEC.md for design rationale.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Identity --------------------------------------------------------------------

CREATE TABLE users (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  username      TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  display_name  TEXT NOT NULL DEFAULT '',
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE sessions (
  token        TEXT PRIMARY KEY,
  user_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at   TIMESTAMPTZ NOT NULL,
  last_used_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX sessions_user_id_idx ON sessions (user_id);
CREATE INDEX sessions_expires_at_idx ON sessions (expires_at);

-- Vaults ----------------------------------------------------------------------

CREATE TABLE vaults (
  id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  slug       TEXT NOT NULL UNIQUE,
  name       TEXT NOT NULL,
  created_by UUID NOT NULL REFERENCES users(id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Roles are per-vault. Seed roles (Admin / Editor / Viewer / Commenter) are
-- created at vault creation with is_seed = TRUE; they cannot be renamed or
-- deleted via the API. Custom roles can be added by an admin.
CREATE TABLE vault_roles (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  vault_id     UUID NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
  name         TEXT NOT NULL,
  capabilities JSONB NOT NULL,
  is_seed      BOOL NOT NULL DEFAULT FALSE,
  UNIQUE (vault_id, name)
);
CREATE INDEX vault_roles_vault_id_idx ON vault_roles (vault_id);

CREATE TABLE vault_members (
  vault_id  UUID NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
  user_id   UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role_id   UUID NOT NULL REFERENCES vault_roles(id),
  joined_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (vault_id, user_id)
);
CREATE INDEX vault_members_user_id_idx ON vault_members (user_id);

CREATE TABLE invites (
  token           TEXT PRIMARY KEY,
  vault_id        UUID NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
  inviter_user_id UUID NOT NULL REFERENCES users(id),
  role_id         UUID NOT NULL REFERENCES vault_roles(id),
  email_hint      TEXT,
  max_uses        INT NOT NULL DEFAULT 1 CHECK (max_uses > 0),
  use_count       INT NOT NULL DEFAULT 0 CHECK (use_count >= 0),
  expires_at      TIMESTAMPTZ NOT NULL,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  revoked_at      TIMESTAMPTZ
);
CREATE INDEX invites_vault_id_idx ON invites (vault_id);
CREATE INDEX invites_expires_at_idx ON invites (expires_at);

-- Notes -----------------------------------------------------------------------

-- notes.id is vault-scoped (the file's stem). The composite primary key keeps
-- IDs unique within a vault while allowing the same id text in different
-- vaults. notes.path is the relative path inside the vault.
CREATE TABLE notes (
  id         TEXT NOT NULL,
  vault_id   UUID NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
  path       TEXT NOT NULL,
  title      TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (vault_id, id),
  UNIQUE (vault_id, path)
);
CREATE INDEX notes_vault_id_idx ON notes (vault_id);

-- CRDT state (Phase 2 - Yjs) --------------------------------------------------

-- Compacted Yjs state per note. One row per note; updated periodically by the
-- compactor.
CREATE TABLE note_yjs_snapshots (
  vault_id       UUID NOT NULL,
  note_id        TEXT NOT NULL,
  state          BYTEA NOT NULL,
  snapshotted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (vault_id, note_id),
  FOREIGN KEY (vault_id, note_id) REFERENCES notes(vault_id, id) ON DELETE CASCADE
);

-- Append-only Yjs update log. Compacted into snapshots when log exceeds
-- threshold (200 entries or 1 MiB).
CREATE TABLE note_yjs_updates (
  id             BIGSERIAL PRIMARY KEY,
  vault_id       UUID NOT NULL,
  note_id        TEXT NOT NULL,
  update_blob    BYTEA NOT NULL,
  origin_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
  origin_kind    TEXT NOT NULL,                -- 'web', 'tui-diff', 'fs-watcher'
  created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  FOREIGN KEY (vault_id, note_id) REFERENCES notes(vault_id, id) ON DELETE CASCADE
);
CREATE INDEX note_yjs_updates_note_idx ON note_yjs_updates (vault_id, note_id, id);

-- Audit + LGPD ----------------------------------------------------------------

-- Audit log retains rows after user erasure (LGPD-compliant via PII redaction
-- rather than hard delete). user_id / vault_id become NULL; ip + user_agent
-- nullified; payload free-text scrubbed by the erasure routine.
CREATE TABLE audit_log (
  id         BIGSERIAL PRIMARY KEY,
  user_id    UUID REFERENCES users(id) ON DELETE SET NULL,
  vault_id   UUID REFERENCES vaults(id) ON DELETE SET NULL,
  action     TEXT NOT NULL,
  payload    JSONB,
  ip         INET,
  user_agent TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX audit_log_user_id_idx ON audit_log (user_id, created_at DESC);
CREATE INDEX audit_log_vault_id_idx ON audit_log (vault_id, created_at DESC);
CREATE INDEX audit_log_action_idx ON audit_log (action, created_at DESC);

-- Immutable consent ledger. Cascade on user erasure (consents have no audit
-- value once the user is gone).
CREATE TABLE user_consents (
  id              BIGSERIAL PRIMARY KEY,
  user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  tos_version     TEXT NOT NULL,
  privacy_version TEXT NOT NULL,
  accepted_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  ip              INET,
  user_agent      TEXT
);
CREATE INDEX user_consents_user_idx ON user_consents (user_id, accepted_at DESC);
