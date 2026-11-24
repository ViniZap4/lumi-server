-- 0010_mirror.up.sql
-- Federation hardening + one-way mirrors (docs/SPEC-ESPELHO-SELADO.md §A18).

-- G2: a tombstone remembers which CRDT history it ended, so the relay can
-- tell "the peer still holds the note home deleted" (same epoch: refuse to
-- resurrect it) from "the peer created a new note under that id" (new
-- epoch). NULL on tombstones written before this migration.
ALTER TABLE note_tombstones ADD COLUMN crdt_epoch TEXT;

-- Home's signed control document must be stored byte for byte: the
-- signature covers the exact JSON, and JSONB normalises it (key order,
-- whitespace), so a document read back from the table no longer verified
-- on the follower (every reconnect pushed an invalid state). Existing
-- rows keep their (normalised) bytes; the server re-signs a row whose
-- signature no longer verifies the next time it reads it.
ALTER TABLE federation_control_state
  ALTER COLUMN state TYPE BYTEA USING convert_to(state::text, 'UTF8');

-- One-way mirrors (§A2). The invite fixes the mode; home reads it from its
-- own invite row, never from the joiner. publish is reserved for publish
-- mirrors (M3) and stays NULL until then.
ALTER TABLE federation_invites
  ADD COLUMN mode TEXT NOT NULL DEFAULT 'replica' CHECK (mode IN ('replica', 'mirror')),
  ADD COLUMN publish JSONB,
  ADD COLUMN sever_policy TEXT NOT NULL DEFAULT 'keep' CHECK (sever_policy IN ('keep', 'purge'));

ALTER TABLE vault_federations
  ADD COLUMN mode TEXT NOT NULL DEFAULT 'replica' CHECK (mode IN ('replica', 'mirror')),
  ADD COLUMN publish JSONB,
  ADD COLUMN sever_policy TEXT NOT NULL DEFAULT 'keep' CHECK (sever_policy IN ('keep', 'purge')),
  -- home side: highest home vault seq the mirror acknowledged
  ADD COLUMN mirror_acked_seq BIGINT NOT NULL DEFAULT 0 CHECK (mirror_acked_seq >= 0),
  -- mirror side: highest home vault seq fully applied
  ADD COLUMN home_seq BIGINT NOT NULL DEFAULT 0 CHECK (home_seq >= 0),
  ADD COLUMN backfill_cursor TEXT,
  ADD COLUMN last_contact_at TIMESTAMPTZ,
  ADD COLUMN last_integrity_at TIMESTAMPTZ,
  -- operator pause (no revoke): the follower stops dialling, home refuses
  -- the challenge
  ADD COLUMN paused_at TIMESTAMPTZ,
  -- set when an operator asks for a full resync; the running server
  -- bounces the link when it sees a newer value
  ADD COLUMN resync_requested_at TIMESTAMPTZ,
  -- mirror side: `lumi-server mirror promote` turned the copy into an
  -- independent home (lifts the read-only clamp)
  ADD COLUMN promoted_at TIMESTAMPTZ;

-- At most one live follower-side row per vault: a replica XOR a mirror.
CREATE UNIQUE INDEX vault_federations_one_follower
  ON vault_federations (vault_id) WHERE role = 'follower' AND status = 'active';
