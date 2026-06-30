#!/usr/bin/env bash
# Privileged test runner for agent-bridle-jaild (ADR 0013 D4 / #109).
#
# PIPELINE PARITY: intentionally NOT mirrored by CI. CI runs only the crate's
# non-privileged tests (`cargo test` skips the `#[ignore]`d jail proofs, which
# need CAP_SYS_ADMIN). This script is the LOCAL privileged proof.
#
# Usage — build as your normal user first (keeps target/ user-owned), then run
# this as root, optionally passing the test binary explicitly (recommended, since
# sudo strips CARGO_TARGET_DIR):
#     cargo test -p agent-bridle-jaild --no-run
#     sudo ./scripts/jail-dev.sh [path/to/agent_bridle_jaild-<hash>]
#
# Running the prebuilt binary directly (no cargo as root) avoids root-owned
# build artifacts.
set -euo pipefail

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "error: run as root: sudo ./scripts/jail-dev.sh [test-exe]" >&2
  echo "       (build first as your user: cargo test -p agent-bridle-jaild --no-run)" >&2
  exit 1
fi

cd "$(dirname "$0")/.."

EXE="${1:-}"
if [[ -z "${EXE}" ]]; then
  for d in "${CARGO_TARGET_DIR:-}" target; do
    [[ -n "${d}" ]] || continue
    EXE=$(find "${d}/debug/deps" -maxdepth 1 -type f -executable \
            -name 'agent_bridle_jaild-*' 2>/dev/null | head -1)
    [[ -n "${EXE}" ]] && break
  done
fi

if [[ -z "${EXE}" || ! -x "${EXE}" ]]; then
  echo "error: jail test binary not found." >&2
  echo "       build it: cargo test -p agent-bridle-jaild --no-run" >&2
  echo "       then pass its path: sudo ./scripts/jail-dev.sh <path-to-exe>" >&2
  exit 1
fi

echo "== privileged jail proofs (#109): ${EXE} =="
exec "${EXE}" --ignored --nocapture
