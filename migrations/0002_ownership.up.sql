-- 0002_ownership.up.sql
-- v3 Phase O: first-class vault ownership + share-a-copy provenance.
-- See SPEC-V3.md "Vault model" and "Sharing".

-- Every vault has exactly one owner. Backfilled from created_by: until this
-- migration the creator was the de-facto owner (sole-admin semantics).
ALTER TABLE vaults ADD COLUMN owner_user_id UUID REFERENCES users(id);
UPDATE vaults SET owner_user_id = created_by;
ALTER TABLE vaults ALTER COLUMN owner_user_id SET NOT NULL;
CREATE INDEX vaults_owner_user_id_idx ON vaults (owner_user_id);

-- Copy provenance for share-a-copy forks: {vault_id, slug, copied_by, copied_at}.
ALTER TABLE vaults ADD COLUMN copied_from JSONB;

-- created_by becomes nullable provenance so LGPD user erasure can proceed
-- when the creator transferred ownership away: the surviving vault keeps a
-- NULL creator instead of blocking the deletion (owner_user_id stays NOT
-- NULL — erasure transfers or deletes owned vaults first, in the same tx).
ALTER TABLE vaults ALTER COLUMN created_by DROP NOT NULL;
ALTER TABLE vaults DROP CONSTRAINT vaults_created_by_fkey;
ALTER TABLE vaults
  ADD CONSTRAINT vaults_created_by_fkey
  FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL;
