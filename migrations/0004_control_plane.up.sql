-- 0004_control_plane.up.sql
-- v3 Phase F3: federation control plane.
--
-- Design note (deviation from SPEC-V3's federation_events sketch): instead
-- of an incremental event log, home maintains ONE signed full control-state
-- document per vault, versioned by seq. Full-state replication is idempotent
-- and immune to event-ordering/replay bugs at vault-membership scale
-- (dozens of rows); change history stays in audit_log where it already
-- lives. The document carries roles, members (keyed username@server), and
-- the vault name.

-- Cross-server members (home side): grants for users who live on follower
-- servers. member_key = "<username>@<server-base-url>". Regular local
-- members stay in vault_members; the control-state builder unions both.
CREATE TABLE federated_vault_members (
  vault_id   UUID NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
  member_key TEXT NOT NULL,
  role_id    UUID NOT NULL REFERENCES vault_roles(id),
  added_by   UUID REFERENCES users(id) ON DELETE SET NULL,
  joined_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (vault_id, member_key)
);

-- Home side: the current signed control state per vault. seq increments on
-- every rebuild; followers apply iff incoming seq > their cursor.
CREATE TABLE federation_control_state (
  vault_id   UUID PRIMARY KEY REFERENCES vaults(id) ON DELETE CASCADE,
  seq        BIGINT NOT NULL,
  state      JSONB NOT NULL,
  signature  BYTEA NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Follower side: the last verified control state received from home.
-- Authorization for follower-role vaults resolves against this document.
CREATE TABLE replicated_control_state (
  vault_id    UUID PRIMARY KEY REFERENCES vaults(id) ON DELETE CASCADE,
  seq         BIGINT NOT NULL,
  state       JSONB NOT NULL,
  received_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Home tracks how far each follower has acked, surfacing replication lag
-- to operators (LGPD: "did the revocation reach them yet").
ALTER TABLE vault_federations ADD COLUMN last_acked_seq BIGINT NOT NULL DEFAULT 0;
