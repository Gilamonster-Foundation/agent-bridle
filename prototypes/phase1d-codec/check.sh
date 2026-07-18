#!/usr/bin/env bash
# Reproduce all four prototype vectors and diff them for byte-identity.
set -uo pipefail
cd "$(dirname "$0")"
mkdir -p vectors
export PATH="$HOME/flutter/bin:$PATH"
( cd rust && env -u CARGO_TARGET_DIR cargo run --quiet ) > vectors/rust.json
( source ~/venv/bin/activate 2>/dev/null; python3 python/canon.py ) > vectors/python.json
( cd ts && node canon.mjs ) > vectors/ts.json
( cd dart && dart run bin/canon.dart ) > vectors/dart.json
echo "== full byte-identity (rust ≡ python ≡ ts) =="
for l in python ts; do
  diff <(grep -v '"lang"' vectors/rust.json) <(grep -v '"lang"' vectors/$l.json) >/dev/null \
    && echo "  rust ≡ $l ✅" || echo "  rust ≠ $l ❌"
done
echo "== dart (full vector) =="
diff <(grep -v '"lang"' vectors/rust.json) <(grep -v '"lang"' vectors/dart.json) >/dev/null && echo "  rust ≡ dart ✅ (full)" || echo "  rust ≠ dart ❌"
