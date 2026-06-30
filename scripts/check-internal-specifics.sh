#!/usr/bin/env bash
#
# Internal-specifics linter for the public agent-bridle repository.
#
# Fails if any tracked file contains a value that looks like a real deployment
# specific (private IP host, internal domain, overlay-network host, directory
# realm, or personal email). Uses GENERIC patterns only — no real specific value
# is embedded in this file. Documentation placeholders (RFC 5737 TEST-NET ranges,
# example.* domains, EXAMPLE.LAN) are intentionally NOT matched.
#
# agent-bridle note: `agent-bridle-tool-web` IS the SSRF/net enforcer, so it
# legitimately *names* the private ranges it blocks (RFC1918/CGNAT). The
# net_guard source is excluded, and the generic network-base forms (10.0.0.0,
# 192.168.0.0, …) plus the SSRF probe target (10.0.0.1) are allowlisted, so the
# README and the web tests that document/exercise the deny-list still pass while
# a real operational host (e.g. 192.168.1.100) is still caught.
#
# PIPELINE PARITY: this script is run by .github/workflows/security-audit.yml AND
# mirrored locally by .pre-commit-config.yaml. When editing it, keep both in sync.
#
# Run locally:  bash scripts/check-internal-specifics.sh
set -uo pipefail

# Files that legitimately *define* these patterns are excluded from the scan.
EXCLUDE_REGEX='^(scripts/check-internal-specifics\.sh|\.gitleaks\.toml|\.github/workflows/security-audit\.yml|agent-bridle-tool-web/src/net_guard\.rs)$'

# Generic, never-operational values that are allowed to appear anywhere: the
# RFC1918/CGNAT *network bases* (range identifiers, used to document the SSRF
# deny-list) and the single SSRF probe target the web tests use. A real
# operational host has a non-zero host part and will NOT match these.
# Uses `[.]` (literal-dot class) rather than `\.` so awk's dynamic-regex lexer
# does not warn about escape sequences.
ALLOW_MATCH_REGEX='^(10[.]0[.]0[.]0|172[.]16[.]0[.]0|192[.]168[.]0[.]0|100[.]64[.]0[.]0|169[.]254[.]0[.]0|10[.]0[.]0[.]1)$'

# Generic deny patterns (label|regex). RFC 5737 ranges and example.* are not here,
# so they pass.
PATTERNS=(
  'rfc1918-10:\b10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\b'
  'rfc1918-192:\b192\.168\.[0-9]{1,3}\.[0-9]{1,3}\b'
  'rfc1918-172:\b172\.(1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}\.[0-9]{1,3}\b'
  'cgnat-100:\b100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.[0-9]{1,3}\.[0-9]{1,3}\b'
  'internal-tld:[A-Za-z0-9-]+\.home\.(lab|lan)\b'
  'overlay-host:[A-Za-z0-9-]+\.ts\.net\b'
  'ad-realm:\bHOME\.LAB\b'
  'personal-gmail:[A-Za-z0-9._%+-]+@gmail\.com\b'
)

mapfile -t FILES < <(git ls-files | grep -Ev "$EXCLUDE_REGEX")
if [ "${#FILES[@]}" -eq 0 ]; then
  echo "OK: no files to scan."
  exit 0
fi

status=0
for entry in "${PATTERNS[@]}"; do
  label="${entry%%:*}"
  pat="${entry#*:}"
  # `-o` yields `file:line:match`; drop matches that are allowlisted generic
  # forms (token-precise, so a real leak on the same line is NOT hidden).
  hits=$(grep -InoE "$pat" "${FILES[@]}" 2>/dev/null \
    | awk -F: -v allow="$ALLOW_MATCH_REGEX" '{ if ($NF !~ allow) print }' \
    || true)
  if [ -n "$hits" ]; then
    echo "::error::internal-specific [$label] matched:"
    echo "$hits"
    status=1
  fi
done

if [ "$status" -ne 0 ]; then
  echo ""
  echo "FAIL: internal specifics found. Replace with placeholders:"
  echo "  hosts/domains -> example.lan / example.com"
  echo "  addresses     -> 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 (RFC 5737)"
  echo "  realm/base DN -> EXAMPLE.LAN / dc=example,dc=lan"
  echo "  emails        -> user@example.com"
  echo "See docs/PRIVACY.md."
  exit 1
fi

echo "OK: no internal specifics found in $((${#FILES[@]})) tracked files."
