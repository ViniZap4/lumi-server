#!/bin/sh
# Strips the embedded LLVM bitcode out of a Rust static library, in place.
#
# Usage: scripts/strip-lto.sh internal/crdt/lib/libyrs.a
#
# Why: the Rust standard library (and compiler_builtins) ship as rlibs whose
# objects carry embedded LLVM bitcode (.llvmbc/.llvmcmd on ELF,
# __LLVM,__bitcode/__cmdline on Mach-O), and a staticlib copies those objects
# as-is. Since Go 1.26.x, cmd/go inspects every archive named in #cgo LDFLAGS
# and refuses LTO sections ("disallowed LTO section __LLVM,__bitcode"). The
# bitcode is only an input for cross-language LTO, which we never use, so
# removing it changes no machine code.
#
# Tool: llvm-objcopy from the rustup llvm-tools component (handles ELF and
# Mach-O archives; installed on demand), else llvm-objcopy on PATH, else GNU
# objcopy (ELF only).
set -eu

lib=${1:?usage: strip-lto.sh <lib.a>}
[ -f "$lib" ] || { echo "strip-lto: $lib not found" >&2; exit 1; }

objcopy=""
if command -v rustc >/dev/null 2>&1; then
  host=$(rustc -vV | sed -n 's/^host: //p')
  cand="$(rustc --print sysroot)/lib/rustlib/$host/bin/llvm-objcopy"
  if [ ! -x "$cand" ] && command -v rustup >/dev/null 2>&1; then
    rustup component add llvm-tools >/dev/null 2>&1 || true
  fi
  [ -x "$cand" ] && objcopy=$cand
fi
if [ -z "$objcopy" ] && command -v llvm-objcopy >/dev/null 2>&1; then
  objcopy=llvm-objcopy
fi
if [ -z "$objcopy" ] && command -v objcopy >/dev/null 2>&1 && [ "$(uname -s)" != Darwin ]; then
  objcopy=objcopy
fi
[ -n "$objcopy" ] || {
  echo "strip-lto: no llvm-objcopy (run: rustup component add llvm-tools) or GNU objcopy found" >&2
  exit 1
}

case "$objcopy" in
  objcopy) "$objcopy" --remove-section=.llvmbc --remove-section=.llvmcmd "$lib" ;;
  *) "$objcopy" \
       --remove-section=.llvmbc --remove-section=.llvmcmd \
       --remove-section=__LLVM,__bitcode --remove-section=__LLVM,__cmdline \
       --remove-section=__LLVM,__asm \
       "$lib" ;;
esac
echo "strip-lto: removed embedded LLVM bitcode from $lib ($objcopy)"
