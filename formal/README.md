# formal/ — mechanized models of the Ceremony Suite

Tier-3 (algebra + state machine) verification for `docs/spec/`. The spec's laws
are not just prose — they type-check. One Lake project builds the whole thing.

```sh
just check-formal        # lake build (all proofs) + lake exe formalGate (no proof escapes)
#  or, in formal/:  lake build && lake exe formalGate
```

Gated in CI by `.github/workflows/formal.yml` and locally by `.githooks/pre-push`
(HOOK PARITY). Toolchain pinned in `lean-toolchain` (Lean 4.31); no Mathlib, so
it builds in seconds.

## Layout

| Path | Covers | Origin |
|---|---|---|
| `Ceremony/P0/Authority.lean` | **P0 authority algebra** — the product meet-lattice `Effect × Assurance × Scope`, attenuation (L4), no-fail-open (OB-9/OB-12), order-independence (L1). 25 theorems, 0 `sorry`. | P0 (this suite) |
| `Ceremony/P0/Boundary.lean` | **the OCAP two-stream sequencing, mechanized** — the L3-gated brush default proven to be an `Effect` attenuation in the frozen algebra (no new law/axis); safe-subset fallback *forced* by I9; enforcement = meet-homomorphic image of authority (streams converge). Confirms the [DECIDED board note](../../../knowledge/board/2026-07-16_ocap-two-streams-sequencing-DECIDED.md). | P0 (this suite) |
| `Ceremony/P1/SignedObject.lean` | **P1 signed-object contracts** — profile/algorithm allowlist (`TrustedProfile`), canonical encoding injectivity, the universal `SignaturePreimage` binding profile/codec/domain/store/thread/body/cid/signer (OB-13), genesis. | PR #233 (GPT-5/Codex) |
| `Gate.lean` + `formalGate` exe | the proof-escape gate: rejects `sorry` / omitted modules. | PR #233 |
| `Tests/P1Counterexamples.lean`, `Tests/SignedObjectContracts.lean` | negative + contract tests (Lean-level conformance). | PR #233 |
| `tla/CeremonyStore.tla` | **P2 store** — CAS append + anti-rollback state machine; invariants map to PO-2/2a/2c + OB-15/16. Check with TLC. | P2 (this suite) |
| `tla/EnforcementGate.tla` | **the L3-gate under a fence that DROPS over time** — temporal half of `Boundary.lean`. `NoAdvisoryDynamicExec` holds iff the fence is re-checked at exec (I4). TLC PASSES with `CheckAtExec=TRUE`, exhibits the TOCTOU trace with `FALSE` (two `.cfg`s next to it). | P0 (this suite) |

## Why this shape

Two tools for two kinds of claim (ADR 0023): the **algebra** (pure functions
over a lattice) is Lean+Aeneas territory — it refines to Rust; the **store
state machine** (concurrency, an attacker transition, temporal invariants) is
TLA+ territory. Enrollment **ceremonies** (P3) get **Tier-2** symbolic proofs
(Tamarin/ProVerif) in Phase 2 — a third tool for a third kind of claim.
Conflating them is the failure the reviews punished.

## Where this goes (Phase 1)

The Lean models are the **refinement targets**: the pure Rust kernel (`resolve`,
gate acceptance, the signed-object verifier) will be extracted with Charon and
proven by Aeneas to *refine* these files, so the implementation inherits the
theorems. See `docs/spec/ROADMAP.md` (Phase 1c). Needs the OCaml/opam leg of
`docs/TOOLCHAIN.md`.
