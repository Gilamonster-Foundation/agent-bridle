# formal/refinement/ — the Tier-3 refinement bridge

Proves that the **extracted Rust** of `agent-bridle-ceremony` satisfies the
`Authority.lean` algebraic laws. This is the concrete instance of the
roadmap's central claim: *the Rust waist refines the Lean model.*

## The pipeline

```
agent-bridle-ceremony (Rust)
      │  charon cargo --preset=aeneas        (Rust → LLBC)
      ▼
agent_bridle_ceremony.llbc
      │  aeneas -backend lean                (LLBC → Lean)
      ▼
AgentBridleCeremony/{Types,Funs,FunsExternal}.lean   ← GENERATED (do not hand-edit)
      │  Refinement.lean                     ← HAND-WRITTEN proofs
      ▼
lake build                                    ✅ laws hold on the extracted code
```

`Refinement.lean` re-proves, on the **extracted monadic functions**, the same
laws `formal/Ceremony/P0/Authority.lean` proves abstractly: axis + product
`meet` commutativity/idempotence and attenuation (`(a⊓c) ⊓ a = a⊓c`, i.e.
`(a⊓c) ≤ a` under the meet-order `Authority.lean` defines). All by
`cases <;> rfl` over the finite domain — the extraction reduces cleanly.

## Why this is a separate, heavier tier

The generated code `import Aeneas`, which pulls the Aeneas Lean backend **and
mathlib**. That is far heavier than the fast, mathlib-free `formal/` project
(which builds in seconds and IS in the mandatory pre-push gate). So this tier is
**not** in the mandatory gate; run it on a machine with the toolchain via
`just check-refinement` (which skips gracefully if the toolchain is absent).

## Verifying locally

```sh
# 1. Build the Charon/Aeneas toolchain once (docs/TOOLCHAIN.md §2).
# 2. Link the Aeneas Lean backend (honours AENEAS_LEAN_LIB):
./setup.sh
# 3. Check the proofs:
lake build            # or: just check-refinement (from repo root)
```

`aeneas-lean` (the symlink `setup.sh` creates) and `.lake/` are gitignored — no
absolute path is committed.

## Regenerating after a kernel change

```sh
./regenerate.sh       # re-extracts the generated files; review the diff
lake build            # re-check the proofs against the new extraction
```

Generated against the Aeneas commit in `aeneas-commit.txt`.

## Known gap: `resolve`

`resolve` uses a slice iterator (`iter().fold(...)`), which Aeneas models with
the **opaque axioms** `core.slice.iter.Iter…fold` / `split_first` (see
`AgentBridleCeremony/FunsExternal.lean`). Opaque ⇒ it does not reduce ⇒ its laws
are not yet provable here. The fix is to rewrite `resolve` in the Rust kernel as
**explicit recursion** (no iterator), which extracts to a real recursive
function. Tracked as a follow-up; the algebra (`meet`/`attenuate`) is complete.
