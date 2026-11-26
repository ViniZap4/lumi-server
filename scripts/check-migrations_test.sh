#!/bin/sh
# Tests for scripts/check-migrations.sh on throwaway git repos.
# Run: sh scripts/check-migrations_test.sh
set -eu

script="$(cd "$(dirname "$0")" && pwd)/check-migrations.sh"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM
pass=0
fail=0

# new_repo: a repo whose main has migrations 0001..0003, checked out on a branch.
new_repo() {
  r="$tmp/$1"
  git init -q "$r"
  mkdir "$r/migrations"
  for m in 0001_init 0002_ownership 0003_feed; do
    echo "-- $m up" > "$r/migrations/$m.up.sql"
    echo "-- $m down" > "$r/migrations/$m.down.sql"
  done
  git -C "$r" add -A
  git -C "$r" -c user.name=t -c user.email=t@t commit -q -m base
  git -C "$r" branch -q -M main
  git -C "$r" checkout -q -b pr
}
add() { echo "-- $2" > "$tmp/$1/migrations/$2.up.sql"; echo "-- $2" > "$tmp/$1/migrations/$2.down.sql"; }

# expect <name> <repo> <want-exit> <pattern> [base]
expect() {
  out=$(cd "$tmp/$2" && sh "$script" ${5:-} 2>&1) && got=0 || got=$?
  if [ "$got" = "$3" ] && printf '%s' "$out" | grep -q -- "$4"; then
    pass=$((pass + 1)); echo "ok   $1"
  else
    fail=$((fail + 1)); echo "FAIL $1 (exit $got, want $3; pattern: $4)"; printf '%s\n' "$out" | sed 's/^/     /'
  fi
}

new_repo clean
expect "clean tree passes" clean 0 "ok (3 versions, up to 0003)"
expect "clean tree vs main passes" clean 0 "base main reaches 0003" main

new_repo next
add next 0004_changesets
expect "next number passes" next 0 "up to 0004" main

new_repo low
git -C "$tmp/low" checkout -q main
add low 0004_search
git -C "$tmp/low" add -A
git -C "$tmp/low" -c user.name=t -c user.email=t@t commit -q -m "main gets 0004"
git -C "$tmp/low" checkout -q pr
add low 0004_user_keys
expect "PR number equal to max on main fails (stale branch)" low 1 "new migration 0004_user_keys has version 0004, but the base already reaches 0004" main
git -C "$tmp/low" merge -q --no-edit main 2>/dev/null
expect "duplicate after merge fails" low 1 "version 0004 has more than one name" main
rm "$tmp/low/migrations/0004_user_keys."*
add low 0005_user_keys
expect "renumbered to max+1 passes" low 0 "up to 0005" main

new_repo below
rm "$tmp/below/migrations/0003_feed."*
git -C "$tmp/below" add -A
git -C "$tmp/below" -c user.name=t -c user.email=t@t commit -q -m drop
add below 0003_other
expect "replacing a shipped migration fails" below 1 "0003_feed.up.sql exists on the base but was removed" main
expect "new version below max fails" below 1 "new migration 0003_other has version 0003" main

new_repo gap
add gap 0005_skip
expect "gap fails" gap 1 "no gap (expected 0004)"
expect "gap vs main fails" gap 1 "no gap" main

new_repo edit
echo "-- sneaky" >> "$tmp/edit/migrations/0002_ownership.up.sql"
expect "editing a shipped migration fails" edit 1 "0002_ownership.up.sql differs from the base" main
expect "editing is fine structurally without base" edit 0 "ok (3 versions"

new_repo nodown
echo "-- x" > "$tmp/nodown/migrations/0004_x.up.sql"
expect "up without down fails" nodown 1 "0004_x.up.sql has no 0004_x.down.sql"

new_repo badname
echo "-- x" > "$tmp/badname/migrations/4_Bad.up.sql"
expect "bad name fails" badname 1 "4_Bad.up.sql: name must be"

new_repo nobase
expect "unknown base fails" nobase 1 "base ref 'origin/nope' not found" origin/nope

echo "check-migrations tests: $pass passed, $fail failed"
[ "$fail" = 0 ]
