#!/usr/bin/env bash
# Benchmark gate (docs/PERF-BUDGETS.md in the umbrella repo).
#
# Builds the benchmark binaries of this tree (HEAD) and of a base ref
# (default origin/main) in a temporary worktree, runs them interleaved
# (base, head, base, head, ...) so machine drift hits both sides
# equally, compares with benchstat and fails when a benchmark got more
# than 10 % worse with p < 0.05 in any gated unit:
#   sec/op, allocs/op, repo-calls/op (storage round trips per update).
# B/op is reported but not gated (GC-dependent).
#
#   scripts/bench-gate.sh [base-ref]
#   BENCH_ROUNDS=10 BENCH_TIME=200ms BENCHSTAT=benchstat scripts/bench-gate.sh
#
# Needs libyrs in internal/crdt/{lib,include} (copied into the base
# worktree) and benchstat on PATH (or $BENCHSTAT). Packages whose base
# has no benchmarks yet are skipped with a notice.
set -euo pipefail

BASE_REF="${1:-origin/main}"
ROUNDS="${BENCH_ROUNDS:-10}"
BENCHTIME="${BENCH_TIME:-200ms}"
THRESHOLD="${BENCH_THRESHOLD:-10}"
BENCHSTAT="${BENCHSTAT:-benchstat}"
PKGS=(internal/crdt internal/wsync internal/notes)
GATED_UNITS="sec/op allocs/op repo-calls/op"

root="$(git rev-parse --show-toplevel)"
work="$(mktemp -d "${TMPDIR:-/tmp}/lumi-bench.XXXXXX")"
base="$work/base"
cleanup() {
  git -C "$root" worktree remove --force "$base" >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT

git -C "$root" worktree add --detach --quiet "$base" "$BASE_REF"
cp -R "$root/internal/crdt/lib" "$root/internal/crdt/include" "$base/internal/crdt/"
echo "bench-gate: head $(git -C "$root" rev-parse --short HEAD) vs base $BASE_REF ($(git -C "$base" rev-parse --short HEAD)), $ROUNDS rounds x $BENCHTIME"

pkgs=()
for p in "${PKGS[@]}"; do
  if ! grep -qs '^func Benchmark' "$base/$p"/*_test.go; then
    echo "::notice::bench-gate: $p has no benchmarks on $BASE_REF yet; skipped"
    continue
  fi
  name="${p//\//_}"
  (cd "$root" && go test -c -o "$work/head-$name.test" "./$p")
  (cd "$base" && go test -c -o "$work/base-$name.test" "./$p")
  pkgs+=("$p")
done
if [ "${#pkgs[@]}" -eq 0 ]; then
  echo "bench-gate: nothing to compare"
  exit 0
fi

run() { # side pkg
  local name="${2//\//_}" tree="$root"
  [ "$1" = base ] && tree="$base"
  (cd "$tree/$2" && "$work/$1-$name.test" -test.run '^$' -test.bench . -test.benchmem \
    -test.count 1 -test.benchtime "$BENCHTIME") >>"$work/$1.txt"
}
for r in $(seq 1 "$ROUNDS"); do
  for p in "${pkgs[@]}"; do
    run base "$p"
    run head "$p"
  done
  printf '.'
done
echo

"$BENCHSTAT" base="$work/base.txt" head="$work/head.txt" | grep -v '^\(goos\|goarch\|cpu\):' || true
"$BENCHSTAT" -format csv base="$work/base.txt" head="$work/head.txt" 2>/dev/null >"$work/stat.csv"

# CSV sections: a header row ",<unit>,CI,<unit>,CI,vs base,P", then one
# row per benchmark; "vs base" is "~" unless the change is significant.
bad="$(awk -F, -v units=" $GATED_UNITS " -v thr="$THRESHOLD" '
  $1 == "" && $6 == "vs base" { unit = $2; next }
  $1 == "" || $1 == "geomean" || $1 ~ /^(pkg|goos|goarch|cpu):/ { next }
  unit != "" && index(units, " " unit " ") && $6 ~ /^\+[0-9.]+%$/ {
    d = substr($6, 2, length($6) - 2) + 0
    if (d > thr) printf "%s %s +%.1f%% (%s)\n", $1, unit, d, $7
  }' "$work/stat.csv")"

if [ -n "$bad" ]; then
  while IFS= read -r l; do echo "::error::bench-gate: $l"; done <<<"$bad"
  echo "bench-gate: regression over ${THRESHOLD}% (p < 0.05). A slower benchmark needs the owner's approval in the PR (PERF-BUDGETS.md)."
  exit 1
fi
echo "bench-gate: ok"
