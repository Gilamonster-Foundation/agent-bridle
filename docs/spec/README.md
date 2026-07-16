# The Ceremony Suite — a dependency-ordered set of provable profiles

**Status:** DRAFT (2026-07-16). This directory replaces the single
`ceremony-contract.md` monolith with a suite of **loosely-coupled,
functionally-cohesive** profiles: each names one job, owns its own algebra
and proof obligations, and exposes a narrow seam the others depend on. The
five laws are the **narrow waist**; everything else is a profile that either
supplies a mechanism the laws assume or consumes the laws to build a
ceremony.

This is the project's architecture doctrine applied to its own
specification: *group what works together to do one job into a unit named
for it; expose only the narrow seam.*

## Why a suite, not a constitution

The monolith grew to ~1000 lines spanning identity, enrollment, revocation,
audit, storage, hash agility, rendering, and MITM analysis. That made three
things impossible:

1. **Independent proof.** A rollback theorem should not have to re-import
   the render-swap threat model to compile.
2. **Independent evolution.** Rotating the hash profile should not reopen
   the enrollment protocol.
3. **Independent reuse.** hermes-agent or an outside harness may want the
   Signed-Object and Chain-Store profiles without the ceremony UI.

Each profile below is a **decision** (an ADR): it is `Proposed`, then
`Accepted`, then `Proven`. A downstream decision **cannot be Accepted until
its dependencies are Proven** — that is the "chain of decisions" made real.

## The dependency DAG

```
        ┌─────────────────────────┐
        │  P1 Signed-Object        │   foundation: content-addressing,
        │  (CID · canon · Sealed)  │   canonicalization, signatures, allowlist
        └────────────┬────────────┘
                     │
        ┌────────────▼────────────┐
        │  P2 Chain-Store          │   causal transcript (Merkle DAG),
        │  (DAG · anchor · rollbk) │   anti-rollback anchor
        └────────────┬────────────┘
                     │
        ┌────────────▼────────────┐
        │  P0 Ceremony Contract    │   ◄── THE NARROW WAIST
        │  five laws · lattice ·   │   authority algebra + decision seam
        │  decision surface · gate │   + gate acceptance
        └───┬─────────┬────────┬───┘
            │         │        │
   ┌────────▼───┐ ┌───▼──────┐ ┌▼─────────────────┐
   │ P3 Enroll- │ │ P4 Ident-│ │ P5 Rendering     │
   │ ment       │ │ ity Life-│ │ Security         │
   │ (SAS·PoP)  │ │ cycle    │ │ (WYSIWYS·transc.)│
   └────────────┘ └──────────┘ └──────────────────┘

   External fabric: agent-mesh#67 Conversation Graph — the wider causal
   transcript of which P2's chain-store is the *authority projection*.
```

## The profiles

| # | Profile | Owns | Depends on | Primary teeth |
|---|---|---|---|---|
| **P0** | [Ceremony Contract](ceremony-contract.md) | the five laws; the authority **product lattice**; the `DecisionSurface` seam; gate acceptance | P1, P2 | Lean (lattice + resolution) → Aeneas (kernel refines model) |
| **P1** | [Signed-Object Profile](signed-object-profile.md) | ContentId (multihash), canonical DAG-CBOR, `Sealed<T>`, deterministic signatures, algorithm allowlist, Profile v1 pins | — | proptest round-trip + Lean canonicalization-injectivity contract |
| **P2** | [Chain-Store Profile](chain-store-profile.md) | the causal-transcript DAG, content-CID/line-CID, `Extends` partial order, external anti-rollback anchor | P1 | Lean trusted-state-machine (`untrusted_step_safe`, checkpoint monotonicity) → Aeneas |
| **P3** | [Enrollment Protocol](enrollment-protocol.md) | SAS pairing, PoP introductions, recipient-issued challenge, external anchors | P0, P1, P2 | **symbolic protocol analysis (Tamarin/ProVerif)** — freshness, MITM, unknown-key-share |
| **P4** | [Identity Lifecycle](identity-lifecycle.md) | roles & delegation, quorum revocation, break-glass & succession | P0, P2 | Lean (quorum k-of-n; non-regression of the load-bearing set) + a liveness/recovery obligation |
| **P5** | [Rendering Security](rendering-security-profile.md) | gate-signed requests, effect binding, display-from-effect, render transcript | P0 | Lean (effect-CID soundness) + a stated human-factors residual (not cryptographic) |

## The teeth — three tiers, do not confuse them

Correctness enforcement is layered; each tier assumes the one below and is
verified by a *different* kind of tool. Naming the boundary is the point —
a proof that silently assumes the wrong tier is exactly the "prose becomes
authority-bearing protocol" failure the two security reviews caught.

```
Tier 3  Kernel refinement        Lean model  ⟵Aeneas⟶  pure Rust kernel
        (functional correctness)  proves the algebra + state machine; Charon
                                  extracts the Rust; a bridge theorem proves
                                  the extraction refines the model. CI gate:
                                  no Rust kernel merges unless the refinement
                                  proof passes. (P0, P2, P4.)

Tier 2  Protocol safety          Tamarin / ProVerif symbolic models prove the
        (ceremony soundness)      CEREMONIES have no MITM / replay / unknown-
                                  key-share under Dolev-Yao. Algebra proofs do
                                  NOT cover this — a lattice can be flawless
                                  while its handshake leaks. (P3, parts of P5.)

Tier 1  Cryptographic primitives  Ed25519 unforgeability, BLAKE3 collision
        (assumed, not proven)     resistance, deterministic-nonce property.
                                  Cited to the literature; the trust base.
                                  Rotatable via P1's profile + allowlist.

Cross-cutting: conformance VECTORS (shared JSON, kyln round-trip pattern)
              bind the four client languages (Rust/Python/Dart/TS) to ONE
              observable behaviour — the teeth that keep implementations
              honest where proofs stop.
```

**The refinement boundary (Tier 3), stated once:** the pure kernel is
`resolve`, precedence, the gate acceptance checklist, and the trusted-state
transition — no serde, no IO, no crypto impl, no UI. Crypto and hashing
enter as *abstract injective/one-way contracts* at the kernel edge (P1's
job to satisfy, the kernel's job to assume). This is what lets Aeneas run.

## Build order (what to prove first)

The DAG dictates it: **P1 → P2 → P0 → {P3, P4, P5}.** The provable MVP is
**P1 + P2 + P0** — the Signed-Object foundation, the anti-rollback store,
and the authority kernel with its five laws. That triple is GPT-5's #232
"formal ceremony kernel" almost exactly; adopt it as the P0/P1/P2 slice and
graft the ceremonies (P3–P5) on once the waist is Proven. Nothing in P3–P5
may be Accepted against an unproven waist.

## Proof-obligation ledger (moves with the profiles)

| PO | Profile | Statement | Tier |
|---|---|---|---|
| PO-1 | P0 | ⨅-resolution is order-independent (assoc ∘ comm ∘ idem) | 3 |
| PO-4 | P0 | authority composes by meet, never amplifies | 3 |
| PO-3 | P0 | resolve is total; headless degradation is ⊑-monotone | 3 |
| PO-1c | P1 | canonicalization is injective; verify-over-received-bytes | 3 |
| PO-8 | P1 | algorithm dispatch is allowlist-gated (no downgrade) | 3 |
| PO-2 | P2 | sub-quorum mutation is ⊑-monotone under H1 | 3 |
| PO-2a | P2 | interior deletion/replay rejected vs. a trusted head | 3 |
| PO-2c | P2 | tail truncation + fork rejected vs. the external anchor | 3 |
| PO-5 | P0/P4 | no association without pin; re-key forces re-ceremony | 3 |
| PO-2b | P4 | sub-quorum cannot shrink the load-bearing set | 3 |
| PO-R | P4 | recovery is live: a legitimate owner is never permanently locked out | 3 (liveness) |
| PO-E | P3 | enrollment has no MITM / unknown-key-share under Dolev-Yao | 2 |
| PO-F | P3 | challenge freshness: no self-issued nonce is accepted | 2 |
| PO-W | P5 | effect-CID soundness: an accepted decision's effect = the executed call | 3 |
| WF-1 | P0 | matrix decidable sans escalations (schema predicate) | vector |
| WF-2 | P1 | Memo discipline (CID/sig/parents/Sealed) | vector |

The waist stays **five laws**; the ledger just relocates each obligation to
the profile that owns it.

## The rule underneath the whole suite

> No authorization or claim floats free of the exact history and artifacts
> that gave it meaning.

P1 gives things names; P2 gives history that cannot silently move; P0 makes
authority an algebra that cannot amplify; P3/P4 bind identity to ceremony;
P5 binds what-was-approved to what-executes. Each is a telescope, not the
sky — the thing being observed is a human's authority, faithfully carried.
