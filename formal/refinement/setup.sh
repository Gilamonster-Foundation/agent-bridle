#!/usr/bin/env bash
# Link the machine-local Aeneas Lean backend into this project so `lake build`
# can find it, without committing an absolute path. Honours AENEAS_LEAN_LIB;
# defaults to the docs/TOOLCHAIN.md §2 location.
set -euo pipefail
cd "$(dirname "$0")"
DEFAULT="$HOME/opt/aeneas/backends/lean"
TARGET="${AENEAS_LEAN_LIB:-$DEFAULT}"
if [ ! -d "$TARGET" ]; then
  echo "Aeneas Lean backend not found at: $TARGET" >&2
  echo "Build it (docs/TOOLCHAIN.md §2), or set AENEAS_LEAN_LIB to its path." >&2
  exit 1
fi
ln -sfn "$TARGET" aeneas-lean
echo "linked aeneas-lean -> $TARGET"
