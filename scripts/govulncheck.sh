#!/bin/sh
# Blocking govulncheck for CI: fails on any vulnerability that our code
# reaches (symbol-level, govulncheck's default), unless the ID is listed in
# .govulncheck-allow with an expiry date that has not passed yet.
#
# Usage: scripts/govulncheck.sh [packages]   (default ./...; govulncheck on PATH)
#
# .govulncheck-allow, one entry per line ('#' starts a comment):
#   GO-YYYY-NNNN  YYYY-MM-DD  reason (what fixes it and who decides)
# An expired entry no longer counts, so an exception cannot linger silently.
set -eu

allow=${GOVULNCHECK_ALLOW:-.govulncheck-allow}
today=$(date -u +%Y-%m-%d)
out=$(mktemp)
trap 'rm -f "$out"' EXIT INT TERM

rc=0
govulncheck "${@:-./...}" > "$out" 2>&1 || rc=$?
cat "$out"
# 0 = nothing reachable; 3 = vulnerabilities found; anything else = tool error.
case "$rc" in
  0) echo "govulncheck: no reachable vulnerabilities"; exit 0 ;;
  3) ;;
  *) echo "::error::govulncheck failed to run (exit $rc)"; exit 1 ;;
esac

found=$(grep -oE '^Vulnerability #[0-9]+: GO-[0-9]{4}-[0-9]+' "$out" | sed 's/.*: //' | sort -u)
[ -n "$found" ] || { echo "::error::govulncheck exited 3 but no vulnerability IDs were parsed"; exit 1; }

blocked=""
for id in $found; do
  entry=$([ -f "$allow" ] && grep -E "^$id[[:space:]]" "$allow" | head -n 1 || true)
  until=$(printf '%s' "$entry" | awk '{ print $2 }')
  if [ -n "$entry" ] && [ "$until" \> "$today" -o "$until" = "$today" ]; then
    echo "govulncheck: $id allowed until $until: $(printf '%s' "$entry" | awk '{ $1 = ""; $2 = ""; sub(/^ +/, ""); print }')"
  elif [ -n "$entry" ]; then
    echo "::error::govulncheck: $id was allowed until $until, which has passed; fix it or renew the entry in $allow with a reason"
    blocked="$blocked $id"
  else
    echo "::error::govulncheck: reachable vulnerability $id (https://pkg.go.dev/vuln/$id); upgrade the module or Go toolchain that the report names"
    blocked="$blocked $id"
  fi
done

if [ -n "$blocked" ]; then
  echo "govulncheck: FAILED, blocking:$blocked"
  exit 1
fi
echo "govulncheck: only allow-listed vulnerabilities remain"
