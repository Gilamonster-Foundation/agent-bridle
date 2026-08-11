#!/usr/bin/env bash
# Publish agent-bridle v0.8.0 to crates.io, in dependency order, with verification.
#
# PRECONDITIONS (this script asserts them, then STOPS if unmet):
#   * On `main`, clean tree, and main already contains the merged v0.8 train
#     (#309, #314, #315, #317) AND this version bump (Cargo.toml → 0.8.0).
#   * `just check` green on this exact main (fmt + clippy + tests, all feature cells).
#   * Cross-platform CI green on main: Linux, macOS Seatbelt, Windows AppContainer,
#     Python, MCP, formal/Lean. (macOS #318 must NOT be silently ignored if macOS
#     support for the timeout-kill behavior is being claimed — see docs/releases/0.8.0.md.)
#   * `CARGO_REGISTRY_TOKEN` set (or ~/.cargo/credentials.toml has a crates-io token
#     with publish rights for these crates).
#
# It is deliberately step-by-step and pauses before the irreversible publish.
set -euo pipefail

VERSION="0.8.0"
# Topological order: dependencies first. Only publish=true crates.
CRATES=(agent-bridle-core agent-bridle-tool-shell agent-bridle-tool-web agent-bridle agent-bridle-mcp)

say() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }

say "0. Preconditions"
[ "$(git rev-parse --abbrev-ref HEAD)" = "main" ] || { echo "not on main"; exit 1; }
[ -z "$(git status --porcelain)" ] || { echo "tree not clean"; exit 1; }
grep -q 'version = "0.8.0"' Cargo.toml || { echo "workspace version is not 0.8.0"; exit 1; }
git fetch origin main
[ "$(git rev-parse HEAD)" = "$(git rev-parse origin/main)" ] || { echo "local main != origin/main"; exit 1; }

say "1. Full local gate (must be green)"
just check

say "2. Package dry-run for the LEAF crate only (agent-bridle-core)"
# NOTE: a downstream crate's `--dry-run` cannot resolve `agent-bridle-core@${VERSION}`
# until core is actually on crates.io (dry-run verifies against the registry, not the
# workspace path). So only the leaf can be fully dry-run pre-publish; each downstream
# crate is dry-run *inside* the publish loop, after its deps are on the index.
cargo publish -p agent-bridle-core --dry-run --locked --all-features

say "3. PUBLISH (irreversible). Ctrl-C now to abort."
read -r -p "Publish agent-bridle v${VERSION} to crates.io in order? [type 'publish'] " ans
[ "$ans" = "publish" ] || { echo "aborted"; exit 1; }
for c in "${CRATES[@]}"; do
  # Dry-run first (now resolvable: deps published in prior iterations), then publish.
  echo "--- dry-run + publish: $c ---"
  cargo publish -p "$c" --dry-run --locked --all-features
  cargo publish -p "$c" --locked --all-features
  # Let the index settle so the next crate can resolve the just-published dep.
  echo "waiting for crates.io index to expose $c@${VERSION} ..."
  for i in $(seq 1 30); do
    if cargo search "$c" 2>/dev/null | grep -q "^$c = \"${VERSION}\""; then break; fi
    sleep 10
  done
done

say "4. Tag + GitHub release"
git tag -a "v${VERSION}" -m "agent-bridle v${VERSION}"
git push origin "v${VERSION}"
gh release create "v${VERSION}" --title "agent-bridle v${VERSION}" --notes-file docs/releases/0.8.0.md

say "5. Verify PUBLISHED artifacts (not path deps) from a scratch project"
tmp="$(mktemp -d)"; ( cd "$tmp"
  cargo new --bin verify >/dev/null
  cd verify
  for c in "${CRATES[@]}"; do cargo add "${c}@=${VERSION}" >/dev/null 2>&1 || true; done
  cargo build --locked
  echo "published-artifact build OK for v${VERSION}"
)
rm -rf "$tmp"

say "DONE. Report the exact versions/commit to the Newt coordinator for #1632/#1633."
