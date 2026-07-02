-- 0003_federation.up.sql
-- v3 Phase F1: server identity + federation handshake.
-- See SPEC-V3.md "Federation".

-- Exactly one Ed25519 keypair per server; identity = (public URL, public key).
-- private_key is stored raw: at-rest encryption is a deployment concern
-- (disk encryption), consistent with the vault-content trust model.
CREATE TABLE server_keys (
  id          SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
  public_key  BYTEA NOT NULL,
  private_key BYTEA NOT NULL,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- One row per (vault, peer) federation link. role is THIS server's role for
-- the vault: 'home' rows point at followers, 'follower' rows point at home.
CREATE TABLE vault_federations (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  vault_id     UUID NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
  role         TEXT NOT NULL CHECK (role IN ('home', 'follower')),
  peer_url     TEXT NOT NULL,
  peer_pubkey  BYTEA NOT NULL,
  jurisdiction TEXT,
  status       TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked', 'severed')),
  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  revoked_at   TIMESTAMPTZ,
  UNIQUE (vault_id, peer_url)
);
CREATE INDEX vault_federations_vault_idx ON vault_federations (vault_id);

-- Single-use federation invites, handed to the other operator out-of-band.
CREATE TABLE federation_invites (
  token           TEXT PRIMARY KEY,
  vault_id        UUID NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
  inviter_user_id UUID NOT NULL REFERENCES users(id),
  server_url_hint TEXT NOT NULL DEFAULT '',
  expires_at      TIMESTAMPTZ NOT NULL,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  used_at         TIMESTAMPTZ,
  revoked_at      TIMESTAMPTZ
);
CREATE INDEX federation_invites_vault_idx ON federation_invites (vault_id);
