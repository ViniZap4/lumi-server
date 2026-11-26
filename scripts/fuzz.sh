#!/usr/bin/env bash
# Runs every native Go fuzz target for FUZZTIME each (default 60s; the
# nightly CI job uses longer sessions). Needs libyrs (make libyrs) for the
# cgo targets in internal/crdt. A crasher is saved under
# <pkg>/testdata/fuzz/<Target>/, replays on every plain `go test`, and
# fails this run.
#
#   FUZZTIME=2m scripts/fuzz.sh
#   FUZZTIME=2m scripts/fuzz.sh ./internal/crdt
set -euo pipefail
cd "$(dirname "$0")/.."
FUZZTIME=${FUZZTIME:-60s}
pkgs=("$@")
[ ${#pkgs[@]} -gt 0 ] || pkgs=(./internal/crdt)
status=0
for pkg in "${pkgs[@]}"; do
  for target in $(go test "$pkg" -list '^Fuzz' | grep '^Fuzz' || true); do
    echo "== $pkg $target ($FUZZTIME)"
    if ! go test "$pkg" -run '^$' -fuzz "^${target}\$" -fuzztime "$FUZZTIME"; then
      status=1
    fi
  done
done
exit $status
