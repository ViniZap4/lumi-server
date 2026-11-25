-- 0012_publish.up.sql
-- Publish mirrors, phase M3 (docs/SPEC-ESPELHO-SELADO.md §A15, §A18).
-- The mirror operator's opt-in to serve a publish mirror anonymously
-- (`lumi-server publish enable <vault> --base-path /p/<slug>`). The home
-- owner's consent and scope live in vault_federations.publish (0010).
CREATE TABLE publish_settings (
  vault_id   UUID PRIMARY KEY REFERENCES vaults(id) ON DELETE CASCADE,
  base_path  TEXT NOT NULL UNIQUE CHECK (base_path ~ '^/p/[a-z0-9][a-z0-9-]{0,62}$'),
  -- what the operator allows search engines; indexing also needs the
  -- owner's consent (publish.index on the link)
  robots     TEXT NOT NULL DEFAULT 'noindex' CHECK (robots IN ('noindex', 'index')),
  enabled_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
