#!/usr/bin/env bash
# scripts/smoke.sh — end-to-end smoke test through v2 Phase 2.
#
# Brings up Postgres via docker compose, runs migrations, starts the
# server in the background, exercises:
#
#   Phase 1: register → login → me → vault create → roles → invite
#            create → invite info → invite accept (signup) → members
#   Phase 2: notes CRUD (create, list, get, content, patch body,
#            patch rename, snapshot, diff, delete)
#
# WS live-sync (Phase 2.3) is exercised by the in-process Go tests in
# internal/wsync/; this shell script does not speak the binary Yjs
# protocol. WS handshake reachability is sanity-checked.
#
# Requires: docker, docker compose, curl, jq, and the libyrs static
# library built locally (`make libyrs`) — the server is run as a
# native binary against the Docker-only Postgres, NOT inside Docker.
#
# Run from the lumi-server repo root:
#   make libyrs            # one-time, builds the cgo dep
#   make smoke             # via the Makefile target
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

# ---- v2 Phase 2: notes ------------------------------------------------------

# 15. Alice creates a note.
echo "--- create note ---"
NOTE_JSON=$(
  curl -sf -X POST "http://127.0.0.1:8080/api/vaults/$VAULT_ID/notes" \
    -H 'Content-Type: application/json' \
    -H "X-Lumi-Token: $ALICE_TOKEN" \
    -d '{"title":"Hello from Alice","body":"# Hello\n\nFirst line.\n","tags":["smoke","phase-2"]}'
)
echo "$NOTE_JSON" | jq .
NOTE_ID=$(echo "$NOTE_JSON" | jq -r .id)
[[ "$NOTE_ID" == "hello-from-alice" ]] || { echo "unexpected note id: $NOTE_ID"; exit 1; }

# 16. List notes.
echo "--- list notes ---"
LIST_JSON=$(
  curl -sf -H "X-Lumi-Token: $ALICE_TOKEN" \
    "http://127.0.0.1:8080/api/vaults/$VAULT_ID/notes"
)
echo "$LIST_JSON" | jq .
COUNT=$(echo "$LIST_JSON" | jq '.notes | length')
[[ "$COUNT" == "1" ]] || { echo "expected 1 note, got $COUNT"; exit 1; }

# 17. Get note metadata.
echo "--- get note metadata ---"
curl -sf -H "X-Lumi-Token: $ALICE_TOKEN" \
  "http://127.0.0.1:8080/api/vaults/$VAULT_ID/notes/$NOTE_ID" | jq .

# 18. Get note content (frontmatter + body).
echo "--- get note content ---"
CONTENT_JSON=$(
  curl -sf -H "X-Lumi-Token: $ALICE_TOKEN" \
    "http://127.0.0.1:8080/api/vaults/$VAULT_ID/notes/$NOTE_ID/content"
)
echo "$CONTENT_JSON" | jq .
BODY=$(echo "$CONTENT_JSON" | jq -r .body)
[[ "$BODY" == *"First line."* ]] || { echo "body mismatch: $BODY"; exit 1; }

# 19. PATCH note body.
echo "--- patch note body ---"
curl -sf -X PATCH "http://127.0.0.1:8080/api/vaults/$VAULT_ID/notes/$NOTE_ID" \
  -H 'Content-Type: application/json' \
  -H "X-Lumi-Token: $ALICE_TOKEN" \
  -d '{"body":"# Hello\n\nSecond line.\n"}' | jq .

# 20. Snapshot endpoint — text + vector_clock (base64).
echo "--- snapshot ---"
SNAP_JSON=$(
  curl -sf -H "X-Lumi-Token: $ALICE_TOKEN" \
    "http://127.0.0.1:8080/api/vaults/$VAULT_ID/notes/$NOTE_ID/snapshot"
)
echo "$SNAP_JSON" | jq .
SNAP_TEXT=$(echo "$SNAP_JSON" | jq -r .text)
[[ "$SNAP_TEXT" == *"Second line."* ]] || { echo "snapshot text mismatch"; exit 1; }
VECTOR=$(echo "$SNAP_JSON" | jq -r .vector_clock)
[[ -n "$VECTOR" ]] || { echo "no vector_clock"; exit 1; }

# 21. Diff endpoint — TUI-style snapshot+diff workflow.
echo "--- apply diff ---"
DIFF_JSON=$(
  curl -sf -X POST "http://127.0.0.1:8080/api/vaults/$VAULT_ID/notes/$NOTE_ID/diff" \
    -H 'Content-Type: application/json' \
    -H "X-Lumi-Token: $ALICE_TOKEN" \
    -d "$(jq -n --arg sv "$VECTOR" --arg t '# Hello\n\nThird line.\n' '{base_clock:$sv, text:$t, origin:"tui-diff"}')"
)
echo "$DIFF_JSON" | jq .
DIFF_TEXT=$(echo "$DIFF_JSON" | jq -r .text)
[[ "$DIFF_TEXT" == *"Third line."* ]] || { echo "diff result mismatch"; exit 1; }

# 21b. Diff endpoint — Phase H slice 3 dispatch guards. The raw-update
# happy path needs real lib0-v1 bytes; that's exercised by the
# apple-client LumiAPIClient + LumiCRDT integration tests (and by the
# in-process wsync hub tests for the WS fan-out). Here we lock the
# request-shape validation so a bug in the dispatch can't silently
# steer a write to the wrong path.
echo "--- diff dispatch: both text and update set rejects ---"
BOTH_HTTP=$(
  curl -s -o /dev/null -w '%{http_code}' \
    -X POST "http://127.0.0.1:8080/api/vaults/$VAULT_ID/notes/$NOTE_ID/diff" \
    -H 'Content-Type: application/json' \
    -H "X-Lumi-Token: $ALICE_TOKEN" \
    -d '{"text":"hello","update":"AAAA"}'
)
[[ "$BOTH_HTTP" == "400" ]] || { echo "both-fields = $BOTH_HTTP, expected 400"; exit 1; }

echo "--- diff dispatch: invalid base64 update rejects ---"
BADB64_HTTP=$(
  curl -s -o /dev/null -w '%{http_code}' \
    -X POST "http://127.0.0.1:8080/api/vaults/$VAULT_ID/notes/$NOTE_ID/diff" \
    -H 'Content-Type: application/json' \
    -H "X-Lumi-Token: $ALICE_TOKEN" \
    -d '{"update":"@@@not-base64@@@"}'
)
[[ "$BADB64_HTTP" == "400" ]] || { echo "bad-base64 = $BADB64_HTTP, expected 400"; exit 1; }

# 22. PATCH rename (path change).
echo "--- patch rename ---"
RENAMED_JSON=$(
  curl -sf -X PATCH "http://127.0.0.1:8080/api/vaults/$VAULT_ID/notes/$NOTE_ID" \
    -H 'Content-Type: application/json' \
    -H "X-Lumi-Token: $ALICE_TOKEN" \
    -d '{"path":"renamed.md"}'
)
echo "$RENAMED_JSON" | jq .
NEW_PATH=$(echo "$RENAMED_JSON" | jq -r .path)
[[ "$NEW_PATH" == "renamed.md" ]] || { echo "rename path = $NEW_PATH"; exit 1; }

# 23. WS handshake reachability — the actual Yjs protocol roundtrip
# is exercised by internal/wsync/ unit tests. Here we just confirm
# the upgrade route returns the expected 426 / 101 path.
echo "--- ws endpoint reachable ---"
WS_PROBE_HTTP=$(
  curl -s -o /dev/null -w '%{http_code}' \
    -H "X-Lumi-Token: $ALICE_TOKEN" \
    "http://127.0.0.1:8080/api/vaults/$VAULT_ID/notes/$NOTE_ID/sync"
)
# 426 Upgrade Required is what the route returns to a non-upgrade GET.
[[ "$WS_PROBE_HTTP" == "426" ]] || { echo "WS upgrade route returned $WS_PROBE_HTTP, expected 426"; exit 1; }
echo "ws upgrade route returns 426 to plain GET (correct)"

# 24. DELETE note.
echo "--- delete note ---"
DELETE_HTTP=$(
  curl -s -o /dev/null -w '%{http_code}' \
    -X DELETE "http://127.0.0.1:8080/api/vaults/$VAULT_ID/notes/$NOTE_ID" \
    -H "X-Lumi-Token: $ALICE_TOKEN"
)
[[ "$DELETE_HTTP" == "204" ]] || { echo "DELETE returned $DELETE_HTTP, expected 204"; exit 1; }

# 25. List notes is empty again.
echo "--- list empty ---"
LIST_FINAL=$(
  curl -sf -H "X-Lumi-Token: $ALICE_TOKEN" \
    "http://127.0.0.1:8080/api/vaults/$VAULT_ID/notes"
)
COUNT_FINAL=$(echo "$LIST_FINAL" | jq '.notes | length')
[[ "$COUNT_FINAL" == "0" ]] || { echo "expected 0 notes after delete, got $COUNT_FINAL"; exit 1; }

echo "--- smoke test PASSED ---"
