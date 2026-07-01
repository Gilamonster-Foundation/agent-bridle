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
#
# Landlock kernel-enforcement proofs (agent-bridle#74): a local run may
# legitimately SKIP them when the kernel lacks Landlock. CI sets
# `BRIDLE_REQUIRE_LANDLOCK=1` (see .github/workflows/ci.yml) so the proofs
# hard-FAIL rather than silently no-op there — never a green build with the
# boundary unverified. Set it locally too if you want the same strictness.
#
# The macOS Seatbelt backend (agent-bridle#50) is the mirror image: on a Mac,
# `--all-features` builds it and `BRIDLE_REQUIRE_SEATBELT=1` makes its proofs
# hard-FAIL if `sandbox-exec` is missing (the `check-macos` CI job sets it). The
# `seatbelt_impl` module only compiles on macOS, so run `just check` on a Mac to
# exercise it.
check:
    cargo fmt --all -- --check
    cargo clippy --workspace --all-targets --all-features -- -D warnings
    cargo clippy --workspace --all-targets --no-default-features -- -D warnings
    cargo test --workspace --all-features
    cargo test --workspace --no-default-features

# Windows AppContainer L3 backend checks — the local mirror of the `check-windows`
# job in .github/workflows/ci.yml (and nightly-windows.yml). The `appcontainer_impl`
# module and the `agent-bridle-aclaunch` launcher only compile on Windows, so this
# skips gracefully on a non-Windows host (like py-test/cov-ci). BRIDLE_REQUIRE_APPCONTAINER
# makes the fs/exec/net kernel proofs hard-FAIL if a container cannot be created,
# matching the CI job (#74 parity).
#
# HOOK PARITY: run by .githooks/pre-push and mirrored by the `check-windows` CI job.
check-windows:
    #!/usr/bin/env bash
    set -uo pipefail
    case "$(uname -s)" in
        MINGW*|MSYS*|CYGWIN*|Windows_NT) ;;
        *) echo "not a Windows host — skipping check-windows (AppContainer backend is Windows-only)"; exit 0 ;;
    esac
    set -e
    cargo clippy --workspace --exclude agent-bridle-py --all-targets --all-features -- -D warnings
    cargo test -p agent-bridle-core --features windows-appcontainer
    cargo test -p agent-bridle-aclaunch --bins
    BRIDLE_REQUIRE_APPCONTAINER=1 cargo test -p agent-bridle-aclaunch --test kernel_proofs -- --test-threads=1
    BRIDLE_REQUIRE_APPCONTAINER=1 cargo test -p agent-bridle-aclaunch --test net_proofs -- --test-threads=1

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

# Publishability gate for the externally-consumed crate (ADR 0008). Fails if a
# change makes `agent-bridle-core` unpublishable — a git dependency, or a
# path-only required dep with no version — which would silently strand
# out-of-tree consumers (e.g. newt-agent). `--dry-run` never uploads;
# `--allow-dirty` so it runs regardless of working-tree state.
#
# HOOK PARITY: this recipe is run by .githooks/pre-push AND mirrored by the
# "Publishability gate" step in .github/workflows/ci.yml. When editing it,
# update both.
publish-check:
    cargo publish --dry-run --allow-dirty -p agent-bridle-core

# Build the PyO3 extension into an isolated throwaway venv and run the Python
# (Pillar A) tests (#71) — the leash invariant from the language it's published
# for. Skips gracefully when python3/maturin are absent (like cov-ci), so a push
# from a machine without the Python toolchain is not blocked. NEVER uses ~/venv.
#
# HOOK PARITY: mirrored by the `py-test` job in .github/workflows/ci.yml and run
# by .githooks/pre-push. When editing, keep all three in sync.
py-test:
    #!/usr/bin/env bash
    set -uo pipefail
    if ! command -v python3 >/dev/null 2>&1; then
        echo "python3 absent — skipping py-test"
        exit 0
    fi
    if ! command -v maturin >/dev/null 2>&1; then
        echo "maturin absent — skipping py-test (pip install 'maturin>=1.7,<2.0' pytest to enable)"
        exit 0
    fi
    venv="$(mktemp -d)/abp-pytest"
    python3 -m venv "$venv"
    # shellcheck disable=SC1091
    . "$venv/bin/activate"
    pip install -q pytest
    ( cd agent-bridle-py && maturin develop -q )
    python -m pytest agent-bridle-py/tests/ -q

# Install the project's git hooks (points core.hooksPath at .githooks).
install-hooks:
    git config core.hooksPath .githooks
    @echo "Installed git hooks (core.hooksPath -> .githooks)."

# Format in place.
fmt:
    cargo fmt --all

# Publish all crates to crates.io, IN TOPOLOGICAL ORDER (each crate before
# its dependents). cargo >= 1.66 blocks each publish until the new version is
# downloadable, so the order is causal — no sleeps needed.
#
# AUTH: run `cargo login` once, OR set CARGO_REGISTRY_TOKEN:
#     CARGO_REGISTRY_TOKEN="$(cat /path/to/your/token)" just publish-crates
#
# NOT PUBLISHED: agent-bridle-py — PyO3 arm64 linker issues make it
# unpublishable from this machine. Publish via a maturin wheel job if needed.
#
# DRY_RUN=1 packages + verifies without uploading.
#
# HOOK PARITY: the crate list and order here must match the publish-crates
# job matrix in .github/workflows/release.yml.
publish-crates:
    #!/usr/bin/env bash
    set -euo pipefail
    dry=""
    [ "${DRY_RUN:-0}" != "0" ] && dry="--dry-run"
    for crate in agent-bridle-core agent-bridle-tool-shell agent-bridle-tool-web agent-bridle agent-bridle-mcp; do
        echo ">>> cargo publish -p ${crate} ${dry}"
        cargo publish -p "${crate}" ${dry}
    done
    echo "All agent-bridle crates published."
