# agent-bridle build recipes.
#
# PIPELINE PARITY: these recipes mirror .githooks/pre-push and
# .github/workflows/ci.yml. When editing the lint/format/test steps here,
# update the push hook AND the CI workflow to match (HOOK PARITY rule).

# Default: list recipes.
default:
    @just --list

# Full local gate — fmt + clippy (zero warnings) + tests, across the feature
# matrix. This is what the pre-push hook and CI both run.
check:
    cargo fmt --all -- --check
    cargo clippy --workspace --all-targets --all-features -- -D warnings
    cargo clippy --workspace --all-targets --no-default-features -- -D warnings
    cargo test --workspace --all-features
    cargo test --workspace --no-default-features

# Coverage gate. Uses cargo-llvm-cov if installed; skips gracefully otherwise
# so the recipe never blocks a machine that lacks the tool. Also skips when
# there are no tests yet (e.g. a fresh scaffold) — llvm-cov reports "no
# coverage data found" in that case, which is not a failure to gate on.
cov-ci:
    #!/usr/bin/env bash
    set -uo pipefail
    if ! command -v cargo-llvm-cov >/dev/null 2>&1; then
        echo "cargo-llvm-cov not installed — skipping coverage gate (install: cargo install cargo-llvm-cov)"
        exit 0
    fi
    out="$(cargo llvm-cov --workspace --all-features --fail-under-lines 75 2>&1)"
    status=$?
    echo "$out"
    if [ "$status" -ne 0 ] && echo "$out" | grep -q "no coverage data found"; then
        echo "no coverage data (no tests instrumented yet) — skipping coverage gate"
        exit 0
    fi
    exit "$status"

# Install the project's git hooks (points core.hooksPath at .githooks).
install-hooks:
    git config core.hooksPath .githooks
    @echo "Installed git hooks (core.hooksPath -> .githooks)."

# Format in place.
fmt:
    cargo fmt --all

# Publish the brush-free crates to crates.io, IN ORDER (core before its
# dependents). cargo >= 1.66 blocks each publish until the new version is
# downloadable, so the order is causal — no sleeps needed.
#
# AUTH: this recipe names no token and no secret location on purpose. Provide
# crates.io auth the standard way — run `cargo login` once, OR set
# CARGO_REGISTRY_TOKEN from wherever you keep the token, e.g.:
#     CARGO_REGISTRY_TOKEN="$(cat /path/to/your/token)" just publish-crates
# Keep the token on your machine; do not put it in CI secrets.
#
# NOT PUBLISHED: agent-bridle-tool-shell (and transitively the `agent-bridle`
# facade + agent-bridle-mcp) git-dep our brush fork, and crates.io forbids any
# git source in a published manifest. They publish once the CommandInterceptor
# hook lands upstream in reubeno/brush, or via a renamed fork. Until then the
# confined shell is consumable via the MCP server / subprocess / maturin wheel.
# See docs/adr/0001 and docs/DESIGN.md.
#
# DRY_RUN=1 packages + verifies without uploading (note: tool-web's dry-run
# needs core already on crates.io to resolve its dependency).
publish-crates:
    #!/usr/bin/env bash
    set -euo pipefail
    dry=""
    [ "${DRY_RUN:-0}" != "0" ] && dry="--dry-run"
    for crate in agent-bridle-core agent-bridle-tool-web; do
        echo ">>> cargo publish -p ${crate} ${dry}"
        cargo publish -p "${crate}" ${dry}
    done
    echo "Published the brush-free crates. (tool-shell stays gated on the upstream brush hook.)"
