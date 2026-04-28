# lumi-server

Backend for **lumi v2**: a multi-tenant collaborative note-taking server.

See [SPEC.md](https://github.com/ViniZap4/lumi/blob/main/SPEC.md) in the lumi
monorepo for the full architecture, data model, API surface, and rollout plan.

## Status

- `main` — v1 (single-password REST + WebSocket sync hub).
- `v2`   — current branch. v2 implementation in progress per SPEC.md.

## Quick start (dev)

```sh
cp .env.example .env
docker compose up -d postgres
make dev
```

## Layout

```
cmd/lumi-server/           binary entrypoint
internal/
  api/                     Fiber routes + middleware
  auth/                    sessions, login, password hashing, middleware
  config/                  env parsing
  domain/                  canonical types, errors, capability vocabulary
  invites/                 invite generation + accept flow
  members/                 vault membership
  notes/                   note metadata + CRDT bridge (Phase 2)
  roles/                   custom per-vault roles
  storage/
    fs/                    SafeJoin, atomic write, vault.yaml
    pg/                    sqlc-generated queries
  users/                   user CRUD
  vaults/                  vault CRUD
migrations/                SQL migrations
```

## Pillars

1. Security first / LGPD compliance
2. Performance
3. DX
4. Scale
5. UX
6. UI
7. QA

See SPEC.md.

## Part of lumi

Component of the [lumi monorepo](https://github.com/ViniZap4/lumi).
