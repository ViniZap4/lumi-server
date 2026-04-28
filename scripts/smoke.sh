#!/usr/bin/env bash
# scripts/smoke.sh — Phase 1 end-to-end smoke test.
#
# Brings up Postgres via docker compose, runs migrations, starts the
# server in the background, exercises register → login → me → vault
# create → invite create → invite accept (existing user). Stops the
# server and Postgres on exit.
#
# Requires: docker, docker compose, curl, jq.
#
# Run from the lumi-server repo root:
#   make smoke       # via the Makefile target
#   bash scripts/smoke.sh

set -euo pipefail

cleanup() {
  local rc=$?
  echo "--- cleanup ---"
  if [[ -n "${SERVER_PID:-}" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  docker compose down -v >/dev/null 2>&1 || true
  exit "$rc"
}
trap cleanup EXIT

# 1. Postgres up.
echo "--- starting postgres ---"
docker compose up -d postgres
echo "waiting for postgres to be ready..."
for _ in $(seq 1 30); do
  if docker compose exec -T postgres pg_isready -U lumi -d lumi >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

# 2. Migrate.
echo "--- migrating ---"
LUMI_DATABASE_URL="postgres://lumi:lumi@localhost:5432/lumi?sslmode=disable" \
LUMI_ROOT="$(pwd)/.smoke-vaults" \
LUMI_REQUIRE_TLS=false \
go run ./cmd/lumi-server migrate up

# 3. Server up (admin bootstrap from env, registration open for the test).
echo "--- starting server ---"
mkdir -p "$(pwd)/.smoke-vaults"
LUMI_DATABASE_URL="postgres://lumi:lumi@localhost:5432/lumi?sslmode=disable" \
LUMI_ROOT="$(pwd)/.smoke-vaults" \
LUMI_REQUIRE_TLS=false \
LUMI_REGISTRATION=open \
LUMI_ADMIN_USERNAME=admin \
LUMI_ADMIN_PASSWORD=adminPass99 \
LUMI_LOG_FORMAT=console \
LUMI_LOG_LEVEL=info \
LUMI_PORT=8080 \
LUMI_BIND_ADDR=127.0.0.1 \
go run ./cmd/lumi-server &
SERVER_PID=$!

echo "waiting for server to be ready..."
for _ in $(seq 1 20); do
  if curl -sf http://127.0.0.1:8080/healthz >/dev/null 2>&1; then
    break
  fi
  sleep 0.5
done

# 4. Health + readiness.
echo "--- health ---"
curl -sf http://127.0.0.1:8080/healthz | jq .
curl -sf http://127.0.0.1:8080/readyz | jq .

# 5. Login as bootstrap admin.
echo "--- login admin ---"
ADMIN_TOKEN=$(
  curl -sf -X POST http://127.0.0.1:8080/api/auth/login \
    -H 'Content-Type: application/json' \
    -d '{"username":"admin","password":"adminPass99"}' \
    | jq -r .token
)
echo "admin token: ${ADMIN_TOKEN:0:8}..."

# 6. /api/users/me as admin.
echo "--- me ---"
curl -sf -H "X-Lumi-Token: $ADMIN_TOKEN" http://127.0.0.1:8080/api/users/me | jq .

# 7. Create a vault.
echo "--- create vault ---"
VAULT_JSON=$(
  curl -sf -X POST http://127.0.0.1:8080/api/vaults \
    -H 'Content-Type: application/json' \
    -H "X-Lumi-Token: $ADMIN_TOKEN" \
    -d '{"name":"Smoke Test","slug":"smoke-test"}'
)
echo "$VAULT_JSON" | jq .
VAULT_ID=$(echo "$VAULT_JSON" | jq -r .id)

# 8. List vaults.
echo "--- list vaults ---"
curl -sf -H "X-Lumi-Token: $ADMIN_TOKEN" http://127.0.0.1:8080/api/vaults | jq .

# 9. List roles for the vault (should include the four seed roles).
echo "--- list roles ---"
ROLES_JSON=$(
  curl -sf -H "X-Lumi-Token: $ADMIN_TOKEN" \
    "http://127.0.0.1:8080/api/vaults/$VAULT_ID/roles"
)
echo "$ROLES_JSON" | jq .
EDITOR_ROLE_ID=$(echo "$ROLES_JSON" | jq -r '.roles[] | select(.name=="Editor") | .id')

# 10. Generate an invite link for Editor role.
echo "--- create invite ---"
EXPIRES=$(date -u -v+1H '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date -u -d '+1 hour' '+%Y-%m-%dT%H:%M:%SZ')
INVITE_JSON=$(
  curl -sf -X POST "http://127.0.0.1:8080/api/vaults/$VAULT_ID/invites" \
    -H 'Content-Type: application/json' \
    -H "X-Lumi-Token: $ADMIN_TOKEN" \
    -d "$(printf '{"role_id":"%s","max_uses":1,"expires_at":"%s"}' "$EDITOR_ROLE_ID" "$EXPIRES")"
)
echo "$INVITE_JSON" | jq .
INVITE_TOKEN=$(echo "$INVITE_JSON" | jq -r .token)

# 11. Invite info (public).
echo "--- invite info ---"
curl -sf "http://127.0.0.1:8080/api/invites/$INVITE_TOKEN" | jq .

# 12. Accept invite as a brand-new user (signup branch).
echo "--- accept invite (signup) ---"
ACCEPT_JSON=$(
  curl -sf -X POST "http://127.0.0.1:8080/api/invites/$INVITE_TOKEN/accept" \
    -H 'Content-Type: application/json' \
    -d '{
      "username": "alice",
      "password": "bobcat-stack-9",
      "display_name": "Alice",
      "consent": {
        "tos_version": "default",
        "privacy_version": "default",
        "accepted_at": "'"$(date -u '+%Y-%m-%dT%H:%M:%SZ')"'"
      }
    }'
)
echo "$ACCEPT_JSON" | jq .
ALICE_TOKEN=$(echo "$ACCEPT_JSON" | jq -r .token)

# 13. Alice can see the vault.
echo "--- alice's vaults ---"
curl -sf -H "X-Lumi-Token: $ALICE_TOKEN" http://127.0.0.1:8080/api/vaults | jq .

# 14. Members list.
echo "--- members ---"
curl -sf -H "X-Lumi-Token: $ALICE_TOKEN" \
  "http://127.0.0.1:8080/api/vaults/$VAULT_ID/members" | jq .

echo "--- smoke test PASSED ---"
