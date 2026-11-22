-- 0005_session_token_hash.down.sql
--
-- Hashes cannot be reversed: every session is dropped (users log in again).

DELETE FROM sessions;
ALTER TABLE sessions RENAME COLUMN token_hash TO token;
