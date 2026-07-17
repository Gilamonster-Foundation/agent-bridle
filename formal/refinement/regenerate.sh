#!/usr/bin/env bash
# Regenerate the extracted Lean (Types/Funs/FunsExternal/AgentBridleCeremony)
# from the Rust crate `agent-bridle-ceremony`, via Charon -> LLBC -> Aeneas.
# Requires the Charon + Aeneas toolchain (docs/TOOLCHAIN.md §2). The pinned
# Aeneas commit these files were generated against is in aeneas-commit.txt.
#
# Refinement.lean is HAND-WRITTEN and is never overwritten here. Review the diff
# on the generated files before committing (extraction is deterministic; a diff
# means the Rust kernel or the toolchain changed).
set -euxo pipefail
cd "$(dirname "$0")"
CRATE="$(git rev-parse --show-toplevel)/agent-bridle-ceremony"
CHARON="${CHARON:-$HOME/opt/aeneas/charon/bin/charon}"
AENEAS="${AENEAS:-$HOME/opt/aeneas/bin/aeneas}"
OUT="$(mktemp -d)"

# NOTE: this harness overrides CARGO_TARGET_DIR; unset it so Charon's own build
# lands where its Makefile expects (see reference: cargo_target_dir gotcha).
( cd "$CRATE" && env -u CARGO_TARGET_DIR "$CHARON" cargo --preset=aeneas --dest-file "$OUT/agent_bridle_ceremony.llbc" )
"$AENEAS" -backend lean "$OUT/agent_bridle_ceremony.llbc" -dest "$OUT/lean" -split-files

cp "$OUT/lean/Types.lean" "$OUT/lean/Funs.lean" AgentBridleCeremony/
# FunsExternal is the (opaque) external axioms; regenerated as a *_Template.
cp "$OUT/lean/FunsExternal_Template.lean" AgentBridleCeremony/FunsExternal.lean
cp "$OUT/lean/AgentBridleCeremony.lean" .
echo "Regenerated. Review 'git diff' before committing."
