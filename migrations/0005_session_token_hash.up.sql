-- 0005_session_token_hash.up.sql
--
-- Session bearer tokens are no longer stored in plaintext: the column now
-- holds the lowercase hex SHA-256 of the raw token (see
-- internal/storage/pg/sessions.go hashSessionToken). Existing rows are
-- converted in place so live sessions keep working; a DB read no longer
-- yields usable credentials.

ALTER TABLE sessions RENAME COLUMN token TO token_hash;
UPDATE sessions SET token_hash = encode(sha256(convert_to(token_hash, 'UTF8')), 'hex');
