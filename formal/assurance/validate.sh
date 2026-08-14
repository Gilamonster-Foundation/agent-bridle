#!/usr/bin/env bash
# Assurance-manifest validator (Phase 7). Checks that every artifact reference in
# manifest.toml RESOLVES against the tree — a dangling proof/test/invariant name
# means the manifest is lying, so this fails.
#
# Deliberately small (grep, no TOML parser dep): the manifest is line-oriented and
# the references are unique tokens. HOOK/PIPELINE PARITY: run by `just check-tla`
# (bundled with the assurance gate) and the `tla` job in formal.yml.
#
# Section 7 additionally validates formal.yml's OWN trigger paths (#356): adding
# an evidence reference to the manifest without adding its path to that workflow
# fails here, so the register cannot come to depend on a file that cannot make
# this validator run.
#
# NOTE: no `set -e`. This script legitimately runs greps that return 1 (a token
# not found is a normal branch, not a script error), so it tracks `fail`
# explicitly and ends with `exit "$fail"`. `set -e` here would abort on the first
# non-matching grep.
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# The manifest path is overridable (BRIDLE_ASSURANCE_MANIFEST) so the self-test
# can point the certification gate at a deliberately-poisoned copy.
MAN="${BRIDLE_ASSURANCE_MANIFEST:-$REPO/formal/assurance/manifest.toml}"
LEAN_SRC="$REPO/formal/Ceremony/Assurance/AuthorityLattice.lean"
POSIX_LEAN_SRC="$REPO/formal/Ceremony/Posix/Machine.lean"
TLA_DIR="$REPO/formal/tla"
fail=0
note() { printf '  %-6s %s\n' "$1" "$2"; }

# 1. Lean theorems: strip the `Ceremony.Assurance.` prefix, require `theorem <name>`.
for t in $(grep -oE 'Ceremony\.Assurance\.[A-Za-z0-9_]+' "$MAN" | sort -u); do
  name="${t##*.}"
  if grep -qE "theorem[[:space:]]+$name\b" "$LEAN_SRC"; then note PASS "lean $name"
  else note FAIL "lean theorem missing: $name"; fail=1; fi
done

# 1b. POSIX Lean theorems (ADR 0026): resolved against Ceremony/Posix/Machine.lean.
for t in $(grep -oE 'Ceremony\.Posix\.[A-Za-z0-9_]+' "$MAN" | sort -u); do
  name="${t##*.}"
  if grep -qE "theorem[[:space:]]+$name\b" "$POSIX_LEAN_SRC"; then note PASS "lean $name (posix)"
  else note FAIL "lean theorem missing: $name (posix)"; fail=1; fi
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
    PosixAuthority_*)      spec="PosixAuthority.tla" ;;
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

# 5. Exact native test functions. A file-only reference is insufficient for a
#    security claim: require every `path.rs::function` token to resolve to both a
#    source file and a function definition in that file.
for ref in $(grep -oE 'agent-bridle[A-Za-z0-9/._-]+\.rs::[A-Za-z0-9_]+' "$MAN" | sort -u); do
  file="${ref%%::*}"
  name="${ref##*::}"
  if [ ! -f "$REPO/$file" ]; then
    note FAIL "native test function file missing: $file"; fail=1
  elif grep -qE "fn[[:space:]]+$name([[:space:]]|\()" "$REPO/$file"; then
    note PASS "native fn $name ($file)"
  else
    note FAIL "native test function missing: $ref"; fail=1
  fi
done

# 6. Release-certification gate. A claim marked status="proved" (release-certified)
#    must NOT depend on pending/undischarged/missing/placeholder evidence. Optional
#    `--rc <SHA>`: additionally require every certified claim that cites native
#    evidence to pin impl_sha == the RC SHA (the artifact actually tested).
#    One self-contained awk (mawk-safe: no POSIX classes, no \x1f), so a normal
#    non-match cannot abort the script.
RC_SHA=""; [ "${1:-}" = "--rc" ] && RC_SHA="${2:-}"
cert_out="$(awk -v rc="$RC_SHA" '
  function v(){ s=$0; sub(/^[^=]*=[ \t]*/,"",s); sub(/[ \t]*#.*/,"",s); gsub(/^"|"[ \t]*$/,"",s); return s }
  function flush(){
    if(id=="" || status!="proved") return
    bad=""
    if(premise ~ /pending|Pending|UNDISCHARGED|unsupported/) bad=bad" premise-undischarged"
    if(native ~ /pending:/)                                  bad=bad" native-pending"
    if(cid ~ /held:|TBD/)                                    bad=bad" placeholder-cid"
    if(rc!="" && native ~ /\.rs/ && impl!=rc)                bad=bad" impl-sha!=RC"
    if(bad=="") print "PASS certified " id
    else        print "FAIL certified " id " depends on:" bad
  }
  /^\[\[claim\]\]/ { flush(); id="";status="";premise="";native="";cid="";impl=""; next }
  /^id[ \t]*=/           { id=v() }
  /^status[ \t]*=/       { status=v() }
  /^premise[ \t]*=/      { premise=v() }
  /^native_test(_fn)?[ \t]*=/ { native=native " " $0 }
  /^evidence_cid[ \t]*=/ { cid=v() }
  /^impl_sha[ \t]*=/     { impl=v() }
  END { flush() }
' "$MAN")"
printf '%s\n' "$cert_out" | sed 's/^/  /'
printf '%s\n' "$cert_out" | grep -q '^FAIL' && fail=1

# 7. Trigger coverage (#356). Sections 1-6 only prove the manifest is honest WHEN
#    THEY RUN, and formal.yml is path-filtered: an evidence file outside those
#    filters can be renamed or deleted without this validator ever running, so a
#    claim keeps its status while its evidence evaporates — a gate reporting green
#    by never running. Require every implementation/evidence path the manifest
#    depends on to be covered by a trigger pattern, so the register enforces its
#    own trigger coverage instead of trusting a human to remember. `formal/**`
#    always triggers, so any future manifest edit runs this check.
WF="$REPO/.github/workflows/formal.yml"
if [ ! -f "$WF" ]; then
  note FAIL "formal workflow missing: .github/workflows/formal.yml"; fail=1
else
  # `<event>\t<pattern>` for every quoted item under an `on: <event>: paths:` list.
  wf_paths="$(awk '
    /^on:/ { inon=1; next }
    /^[^ \t]/ { inon=0 }
    inon && /^  [a-z_]*:/ { sect=$1; sub(/:$/,"",sect); inpaths=0; next }
    inon && /^    paths:/ { inpaths=1; next }
    inon && inpaths && /^      - "/ { s=$0; sub(/^      - "/,"",s); sub(/".*/,"",s); print sect "\t" s; next }
    inon && inpaths && /^    [a-z_]*:/ { inpaths=0 }
  ' "$WF")"
  push_p="$(printf '%s\n' "$wf_paths" | awk -F'\t' '$1=="push"{print $2}' | sort -u)"
  pr_p="$(printf '%s\n' "$wf_paths" | awk -F'\t' '$1=="pull_request"{print $2}' | sort -u)"
  if [ -z "$pr_p" ]; then
    note FAIL "formal.yml: no pull_request paths parsed (filter format changed?)"; fail=1
  elif [ "$push_p" != "$pr_p" ]; then
    note FAIL "formal.yml: push and pull_request path filters differ (one event would skip the gate)"; fail=1
  else
    note PASS "formal.yml push/pull_request path filters agree"
  fi
  # Everything the validator itself reads from the tree, plus every cited
  # native-evidence file. RUST_SRC counts: it carries the model≈production
  # correspondence tests named by `rust_test` entries.
  covered_ok=1
  rust_src_rel="${RUST_SRC#$REPO/}"
  # Pathname expansion OFF for the coverage walk. `$pr_p` holds GitHub trigger
  # PATTERNS, and an unquoted `agent-bridle-fdguard/**` is expanded by the
  # shell against the working tree — so `$p` arrived as `agent-bridle-fdguard/
  # Cargo.toml`, `.../src`, … and the literal `**` the matcher below keys on
  # was never seen. Every `**`-covered evidence file then reported as
  # uncovered: a FALSE FAIL from the gate whose whole job is deciding what
  # counts as covered. Fails closed, so it never hid anything — but a gate
  # that cries wolf is one people learn to route around.
  set -f
  for f in $( { grep -oE 'agent-bridle[A-Za-z0-9/._-]+\.rs' "$MAN" | sed 's/^pending://'
                printf '%s\n' "$rust_src_rel"; } | sort -u ); do
    hit=0
    for p in $pr_p; do
      case "$p" in
        */'**') case "$f" in "${p%/\*\*}"/*) hit=1 ;; esac ;;
        '**') hit=1 ;;
        *)    [ "$f" = "$p" ] && hit=1 ;;
      esac
      [ "$hit" -eq 1 ] && break
    done
    if [ "$hit" -eq 0 ]; then
      note FAIL "evidence not covered by a formal.yml trigger path: $f"
      fail=1; covered_ok=0
    fi
  done
  set +f
  [ "$covered_ok" -eq 1 ] && note PASS "every cited evidence path triggers the formal gate"
fi

if [ "$fail" -eq 0 ]; then echo "assurance manifest: all references resolve; every cited evidence path triggers the gate; no certified claim depends on pending/placeholder evidence"; else
  echo "assurance manifest: violations above"; fi
exit "$fail"
