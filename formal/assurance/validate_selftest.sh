#!/usr/bin/env bash
# Self-test for the release-certification gate in validate.sh: prove it REJECTS a
# manifest that falsely marks an undischarged claim `proved`. A gate that cannot
# fail is not a gate. Run by `just check-tla` and the `tla` CI job.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
POISON="$TMP/manifest.toml"

# Take the real manifest and flip the UNDISCHARGED Windows claim to `proved`.
perl -0pe 's/(id            = "WIN-E2-WRITE-READ".*?status        = ")partial(")/${1}proved${2}/s' \
  "$HERE/manifest.toml" > "$POISON"

if BRIDLE_ASSURANCE_MANIFEST="$POISON" "$HERE/validate.sh" >/dev/null 2>&1; then
  echo "SELF-TEST FAIL: validator ACCEPTED a falsely-certified undischarged claim"
  exit 1
fi
echo "self-test: validator correctly rejects false certification of an undischarged claim"
