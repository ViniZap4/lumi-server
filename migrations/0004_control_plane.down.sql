-- 0004_control_plane.down.sql

ALTER TABLE vault_federations DROP COLUMN last_acked_seq;
DROP TABLE replicated_control_state;
DROP TABLE federation_control_state;
DROP TABLE federated_vault_members;
