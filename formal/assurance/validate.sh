#!/usr/bin/env bash
# Assurance-manifest validator (Phase 7). Checks that every artifact reference in
# manifest.toml RESOLVES against the tree — a dangling proof/test/invariant name
# means the manifest is lying, so this fails.
#
# Deliberately small (grep, no TOML parser dep): the manifest is line-oriented and
# the references are unique tokens. HOOK/PIPELINE PARITY: run by `just check-tla`
# (bundled with the assurance gate) and the `tla` job in formal.yml.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
MAN="$REPO/formal/assurance/manifest.toml"
LEAN_SRC="$REPO/formal/Ceremony/Assurance/AuthorityLattice.lean"
TLA_DIR="$REPO/formal/tla"
fail=0
note() { printf '  %-6s %s\n' "$1" "$2"; }

# 1. Lean theorems: strip the `Ceremony.Assurance.` prefix, require `theorem <name>`.
for t in $(grep -oE 'Ceremony\.Assurance\.[A-Za-z0-9_]+' "$MAN" | sort -u); do
  name="${t##*.}"
  if grep -qE "theorem[[:space:]]+$name\b" "$LEAN_SRC"; then note PASS "lean $name"
  else note FAIL "lean theorem missing: $name"; fail=1; fi
done

# 2. TLA invariants: entries look like `Invariant@Config.cfg`. Require the cfg to
#    exist and the invariant symbol to appear in the spec it configures.
for ref in $(grep -oE '[A-Za-z0-9_]+@[A-Za-z0-9_]+\.cfg' "$MAN" | sort -u); do
  inv="${ref%@*}"; cfg="${ref##*@}"
  if [ ! -f "$TLA_DIR/$cfg" ]; then note FAIL "tla cfg missing: $cfg"; fail=1; continue; fi
  spec="$(grep -oE '[A-Za-z0-9_]+\.tla' "$TLA_DIR/$cfg" | head -1 || true)"
  # cfgs reference the spec only in their header comment; fall back by name.
  case "$cfg" in
    AuthorityLifecycle_*) spec="AuthorityLifecycle.tla" ;;
    EnforcementFence_*)   spec="EnforcementFence_NonEquivocation.tla" ;;
  esac
  if grep -qE "\b$inv\b" "$TLA_DIR/$spec"; then note PASS "tla $inv ($cfg)"
  else note FAIL "tla invariant $inv absent from $spec"; fail=1; fi
done

# 3. Rust tests: require `fn <name>` in the correspondence suite.
RUST_SRC="$REPO/agent-bridle-core/tests/authority_lattice_correspondence.rs"
for t in $(grep -oE 'rust_test[[:space:]]*=[[:space:]]*\[[^]]*\]' "$MAN" \
            | grep -oE '"[a-z0-9_]+"' | tr -d '"' | sort -u); do
  if grep -qE "fn[[:space:]]+$t\b" "$RUST_SRC"; then note PASS "rust $t"
  else note FAIL "rust test missing: $t"; fail=1; fi
done

# 4. Native test files: must exist on disk — EXCEPT those marked `pending:`
#    (they live on an unmerged branch, e.g. #338, and are honestly not on main).
PENDING="$(grep -oE 'pending:agent-bridle[A-Za-z0-9/._-]+\.rs' "$MAN" \
            | sed 's/^pending://' | sort -u)"
for f in $(grep -oE 'agent-bridle[A-Za-z0-9/._-]+\.rs' "$MAN" | sort -u); do
  if printf '%s\n' "$PENDING" | grep -qxF "$f"; then note SKIP "native (pending): $f"; continue; fi
  if [ -f "$REPO/$f" ]; then note PASS "native $f"
  else note FAIL "native test file missing: $f"; fail=1; fi
done

if [ "$fail" -eq 0 ]; then echo "assurance manifest: all references resolve"; else
  echo "assurance manifest: unresolved references above"; fi
exit "$fail"
