#!/usr/bin/env bash
# Deterministic TLC driver for the POSIX authority-projection spec (P1..P4).
# HOOK/PIPELINE PARITY: invoked by `just check-tla` and the `tla` job in
# .github/workflows/formal.yml, alongside run-authority-lifecycle.sh. The
# faithful cfg MUST hold []Inv; every bug cfg MUST report a counterexample. A
# bug cfg that stops violating is a REGRESSION (the model no longer exercises
# the defect) and fails this script.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
JAR="${TLA2TOOLS_JAR:-$HOME/opt/tla2tools/tla2tools.jar}"
SPEC="$HERE/PosixAuthority.tla"

if [ ! -f "$JAR" ]; then
  echo "run-posix-authority: tla2tools.jar not found at $JAR — skipping (set TLA2TOOLS_JAR)"; exit 0
fi

# TLC exits non-zero when it finds a counterexample — the EXPECTED outcome for a
# bug cfg — so capture output and match on text, never on exit status.
run() { java -cp "$JAR" tlc2.TLC -config "$HERE/$1" "$SPEC" 2>&1 || true; }

fail=0

# Faithful: must complete with no error.
if run PosixAuthority_faithful.cfg | grep -q "No error has been found"; then
  echo "PASS  faithful            []Inv holds"
else
  echo "FAIL  faithful            expected []Inv to hold"; fail=1
fi

# Bug modes: each must be a counterexample against the named invariant.
for pair in Amplify:NoAuthorityAmplification \
            NamespaceForge:NamespaceNonAmplification \
            DescriptorForge:DescriptorNonAmplification \
            DescendantEscalate:DescendantAttenuation; do
  mode="${pair%%:*}"; inv="${pair##*:}"
  if run "PosixAuthority_${mode}.cfg" | grep -q "Invariant Inv is violated"; then
    printf 'PASS  %-20s counterexample to %s\n' "$mode" "$inv"
  else
    printf 'FAIL  %-20s expected a %s counterexample\n' "$mode" "$inv"; fail=1
  fi
done

exit "$fail"
