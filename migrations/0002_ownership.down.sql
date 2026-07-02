-- 0002_ownership.down.sql

ALTER TABLE vaults DROP CONSTRAINT vaults_created_by_fkey;
UPDATE vaults SET created_by = owner_user_id WHERE created_by IS NULL;
ALTER TABLE vaults ALTER COLUMN created_by SET NOT NULL;
ALTER TABLE vaults
  ADD CONSTRAINT vaults_created_by_fkey
  FOREIGN KEY (created_by) REFERENCES users(id);

ALTER TABLE vaults DROP COLUMN copied_from;
DROP INDEX vaults_owner_user_id_idx;
ALTER TABLE vaults DROP COLUMN owner_user_id;
