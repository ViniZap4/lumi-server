#!/bin/sh
# Migration numbering policy check (run in CI; see docs/SPEC-ESPELHO-SELADO.md §B16
# in the umbrella repo).
#
# golang-migrate stores a single current version and applies only versions
# above it. A migration that lands with a number at or below one a database
# already applied is silently skipped there forever. So migrations are
# numbered by MERGE ORDER, with no gaps, no duplicates and no reserved ranges.
#
# Usage: scripts/check-migrations.sh [BASE_REF]
#   Without BASE_REF: structural checks on migrations/ only.
#   With BASE_REF (e.g. origin/main, or the commit a push started from): also
#   checks the working tree against the base tree.
#
# Structural rules (always):
#   - every file is NNNN_snake_name.up.sql or NNNN_snake_name.down.sql;
#   - each version has exactly one name and both an up and a down file;
#   - versions run 0001..N with no gap and no duplicate.
# Base rules (with BASE_REF):
#   - every migration in the base still exists, byte for byte (shipped
#     migrations are immutable: production already applied them);
#   - every new version is greater than the highest version in the base.
set -eu

dir=${MIGRATIONS_DIR:-migrations}
base=${1:-}
fail=0
err() { echo "::error::check-migrations: $*"; fail=1; }

[ -d "$dir" ] || { echo "::error::check-migrations: no $dir directory"; exit 1; }

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM

# --- structural ---------------------------------------------------------------
ls -1 "$dir" > "$tmp/files"
while IFS= read -r f; do
  if ! printf '%s\n' "$f" | grep -Eq '^[0-9]{4}_[a-z0-9]+(_[a-z0-9]+)*\.(up|down)\.sql$'; then
    err "$dir/$f: name must be NNNN_snake_name.up.sql or .down.sql"
  fi
done < "$tmp/files"

grep -E '^[0-9]{4}_[a-z0-9_]+\.(up|down)\.sql$' "$tmp/files" |
  sed -E 's/\.(up|down)\.sql$//' | sort -u > "$tmp/stems"
cut -c1-4 "$tmp/stems" | sort | uniq -d > "$tmp/dups"
while IFS= read -r v; do
  err "version $v has more than one name: $(grep "^$v" "$tmp/stems" | paste -sd ' ' -) (renumber yours to the next free number)"
done < "$tmp/dups"

while IFS= read -r stem; do
  [ -f "$dir/$stem.up.sql" ] || err "$dir/$stem.down.sql has no $stem.up.sql"
  [ -f "$dir/$stem.down.sql" ] || err "$dir/$stem.up.sql has no $stem.down.sql"
done < "$tmp/stems"

cut -c1-4 "$tmp/stems" | sort -u > "$tmp/versions"
expected=1
while IFS= read -r v; do
  n=$(expr "$v" + 0)
  if [ "$n" -ne "$expected" ]; then
    err "version $v follows $(printf '%04d' $((expected - 1))): versions must run 0001..N with no gap (expected $(printf '%04d' "$expected"))"
  fi
  expected=$((n + 1))
done < "$tmp/versions"
max=$(tail -n 1 "$tmp/versions" 2>/dev/null || true)

# --- against the base -----------------------------------------------------------
if [ -n "$base" ]; then
  git rev-parse --verify --quiet "$base^{commit}" >/dev/null ||
    { echo "::error::check-migrations: base ref '$base' not found (fetch it first)"; exit 1; }
  git ls-tree --name-only "$base" -- "$dir/" | sed "s|^$dir/||" |
    grep -E '^[0-9]{4}_.*\.sql$' > "$tmp/base_files" || true
  base_max=$(cut -c1-4 "$tmp/base_files" | sort -u | tail -n 1)
  while IFS= read -r f; do
    if [ ! -f "$dir/$f" ]; then
      err "$dir/$f exists on the base but was removed or renamed; shipped migrations are immutable (add a new migration instead)"
    elif [ "$(git rev-parse "$base:$dir/$f")" != "$(git hash-object "$dir/$f")" ]; then
      err "$dir/$f differs from the base; shipped migrations are immutable (production already applied it; add a new migration instead)"
    fi
  done < "$tmp/base_files"
  while IFS= read -r stem; do
    v=$(printf '%s' "$stem" | cut -c1-4)
    if ! grep -q "^$stem\." "$tmp/base_files" && [ -n "$base_max" ] && [ "$(expr "$v" + 0)" -le "$(expr "$base_max" + 0)" ]; then
      err "new migration $stem has version $v, but the base already reaches $base_max: migrations are numbered by merge order, rename it to $(printf '%04d' $(($(expr "$base_max" + 0) + 1)))_..."
    fi
  done < "$tmp/stems"
  echo "check-migrations: base $base reaches ${base_max:-none}; this tree reaches ${max:-none}"
fi

if [ "$fail" -ne 0 ]; then
  echo "check-migrations: FAILED (policy: numbered by merge order, no gaps, no duplicates, shipped migrations immutable)"
  exit 1
fi
echo "check-migrations: ok ($(wc -l < "$tmp/versions" | tr -d ' ') versions, up to ${max:-none})"
