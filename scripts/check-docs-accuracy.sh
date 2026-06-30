#!/usr/bin/env bash
#
# Docs-accuracy guard: the *shipped* shell is the argv + safe-subset executor
# (ADR 0005), not a brush-backed runtime. brush is a DEFERRED, optional engine
# (agent-bridle#20/#28) and may only be described as such. This guard fails if a
# consumer-facing doc claims a live brush/coreutils runtime for the shipped tool.
#
# ADRs under docs/adr/ are immutable history (ADR 0003 deliberately records the
# old brush-stub state) and are intentionally NOT scanned.
#
# PIPELINE PARITY: run by .github/workflows/security-audit.yml and mirrored by
# .pre-commit-config.yaml. When editing, keep both in sync.
set -uo pipefail

# Consumer-facing docs that describe the shipped tool.
FILES=(
  README.md
  agent-bridle-tool-shell/README.md
  agent-bridle-py/README.md
  agent-bridle-py/Cargo.toml
  agent-bridle-py/pyproject.toml
  agent-bridle-py/tests/test_invoke.py
)

# Phrases that assert brush is the LIVE/shipped runtime (a deferred-engine
# mention like "deferred ... brush engine (#20)" does not match these).
DENY='brush-backed|brush-carried|brush.?s carried builtin|carried coreutils|brush .?.?CommandInterceptor|CaveatInterceptor|brush-core/builtins'

status=0
for f in "${FILES[@]}"; do
  [ -f "$f" ] || continue
  hits=$(grep -InE "$DENY" "$f" 2>/dev/null || true)
  if [ -n "$hits" ]; then
    echo "::error::stale brush-runtime claim in $f:"
    echo "$hits"
    status=1
  fi
done

if [ "$status" -ne 0 ]; then
  echo ""
  echo "FAIL: the shipped shell is the argv + safe-subset engine (ADR 0005)."
  echo "      brush is a DEFERRED, optional engine — mention it only as such (#20/#28)."
  exit 1
fi

echo "OK: no stale brush-runtime claims in shipped-tool docs."
