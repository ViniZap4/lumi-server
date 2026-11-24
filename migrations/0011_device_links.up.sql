-- 0011_device_links.up.sql — device links (SPEC-LIVROS §8.4).
--
-- A signed-in client mints a single-use code bound to a PKCE challenge;
-- another client of the same user redeems it with the verifier for a
-- session of its own. Only hashes are stored. A code dies with the
-- session that issued it.
CREATE TABLE device_link_codes (
  code_hash         TEXT PRIMARY KEY,
  user_id           UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  issuer_token_hash TEXT NOT NULL REFERENCES sessions(token_hash) ON DELETE CASCADE,
  challenge         TEXT NOT NULL CHECK (length(challenge) = 43),
  label             TEXT NOT NULL DEFAULT '' CHECK (length(label) <= 320),
  created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at        TIMESTAMPTZ NOT NULL
);
CREATE INDEX device_link_codes_expires_at_idx ON device_link_codes (expires_at);
CREATE INDEX device_link_codes_issuer_idx ON device_link_codes (issuer_token_hash);

-- Sessions created by a device link share a link_group with the session
-- that issued the code, so "sign out on this Mac" (logout scope=device)
-- can end all of them. Rows go away with their session.
CREATE TABLE session_links (
  token_hash TEXT PRIMARY KEY REFERENCES sessions(token_hash) ON DELETE CASCADE,
  link_group UUID NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX session_links_group_idx ON session_links (link_group);
