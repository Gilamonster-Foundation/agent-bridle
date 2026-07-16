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

Corrected 2026-07-16 per an adversarial review (OB-1): the prose had
back-edges the first diagram hid — P0's attestation and L5 lean on P4, and
P3/P5 consume P4 records. The fix is **dependency inversion**: P0 depends
only on *abstract contracts* (`AttestEvidence`, `ValidAssociationProof`)
that **P4 implements** — so the linear order below is real, not aspirational.

```
  P1 Signed-Object      (foundation: CID · canon · Sealed · allowlist)
        │
        ▼
  P2 Chain-Store        (causal transcript DAG · external anti-rollback anchor)
        │
        ▼
  P0 Ceremony Contract  ◄── THE NARROW WAIST
        │                   five laws · lattice · seam · gate;
        │                   depends on P4 only via abstract contracts
        ▼
  P4 Identity Lifecycle (roles · records · quorum revocation · recovery;
        │                implements P0's AttestEvidence / association proof)
        ▼
  P3 Enrollment         (SAS · PoP; produces P4 PinRecords)

  P5 Rendering  depends on {P0, P1, P4}  (effect binding · gate-signed requests)

  External fabric: agent-mesh#67 Conversation Graph — the wider causal
  transcript of which P2's chain-store is the *authority projection*.
```

Build/prove order: **P1 → P2 → P0 → P4 → P3**, with P5 after P0/P1/P4.

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

The DAG dictates it: **P1 → P2 → P0 → P4 → P3**, P5 after P0/P1/P4 (OB-1).
The provable MVP is
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

## Open specification obligations

Tracked from adversarial review round 6 (a fresh GPT pass on the partitioned
suite, 2026-07-16). The review confirmed the split closed the prior attacks
and rated architecture / threat-honesty / separation / formal-plan all
*Strong*; these are the crisp state-machine gaps that remain. **B = blocker
before implementation-complete; H = high; M = medium.** "choice" = a design
decision the author owns, not a mechanical fix.

| # | Sev | Profile | Gap | Resolution direction |
|---|---|---|---|---|
| OB-1 | B | P0/P4 | declared DAG had back-edges (P0↔P4 cycle) | **dependency inversion** — P0 defines abstract `AttestEvidence` + `ValidAssociationProof`; P4 implements. DAG corrected above. |
| OB-2 | B (choice) | P2 | branching DAG checkpointed with a scalar `(gen,length,head)`; "two heads @ equal length = equivocation" is false for a DAG | **linear authority spine per causal thread** `(store_id, thread_id, sequence)`, one accepted successor per sequence (conversation branches; authority is a railway). Alt: frontier checkpoint `Set<LineCid>`. |
| OB-3 | B | P0/P4 | attestation lacks a canonical challenge preimage + an atomic post-append commit; authenticator ≠ DAG verifier | define one challenge preimage (all bound fields); order: verify-checkpoint → presence → construct → append → **CAS-advance anchor** → then mint. Split roles: witness-verifier (DAG) / WebAuthn authenticator (presence) / surface (signs) / gate (appends+advances+activates). |
| OB-4 | B | P1 | "sign DAG-CBOR + verify received bytes + exchange JSON" is contradictory | **signed-bytes-in-envelope**: `{profile, codec, body: b64(canonical), cid, by, sig}`; JSON/TOML are views, never authority-bearing serializations. |
| OB-9 | B | P0 | `resolve(∅,q) = ⨅(∅) = ⊤ = approve` — **fail-OPEN**, contradicting L3 | seed the meet with a base: `resolve(R,q) = ⨅({ask} ∪ {matching verdicts})`; empty match → ask → (headless) deny. Define `resolve(∅)` for PO-3 totality. + normalize vocabulary (allow vs approve; is `ask` verdict/state/escalation?). |
| OB-5 | H | P3 | challenge consumed *before* signature check → burn-DoS | validate-then-consume (reserve→validate→commit); bind the challenge object CID + recipient + role + context. |
| OB-6 | H | P1/all | domain separation only on the WebAuthn challenge | **universal**: every signature covers (record-type string, `store_id`, thread/principal id, canonical payload). P2 needs a normative, cryptographically-bound `store_id`. |
| OB-7 | H | P4 | RevocationRecord's `policy` CID not pinned to an epoch → replay an older weaker policy | `policy_cid == ActiveRevocationPolicy(target, observed_checkpoint, generation)`. The strength tuple is not totally ordered → enrollment records the **exact required revocation predicate**, not an informal tuple. |
| OB-8 | H | P4 | PO-R "never permanently locked out" is unprovable unconditionally | state it **conditionally** (≥1 uncompromised recovery threshold, eventual quorum comms, fair generation advance, no total material destruction). Timelock recovery must handle attacker-owns-a-device-suppresses-veto. |
| OB-10 | M | P5 | effect-CID binds a call *value*, not the mutable world (symlinks, DNS, container **tags**, repo state, creds) | per-class resource identity in the sealed request (file: path+content-CID/inode; container: image **digest** not tag; repo: commit/tree CID; net: destination+DNS policy). Gate MUST run the exact `Sealed<CallRequest>` whose CID was approved; ambient = named residual, not PO-W. |
| OB-11 | M | suite | no statement of which profile versions form one compatible suite | a **compatibility manifest**: `suite_version` + per-profile version requires + `conformance_vectors` CID. |

Two of these are the review's sharpest: **OB-9** (a latent fail-open in a
fail-closed system) and **OB-1** (the clean DAG was prose-cyclic). OB-2 and
the `attest` factorization remain author's calls.

## The rule underneath the whole suite

> No authorization or claim floats free of the exact history and artifacts
> that gave it meaning.

P1 gives things names; P2 gives history that cannot silently move; P0 makes
authority an algebra that cannot amplify; P3/P4 bind identity to ceremony;
P5 binds what-was-approved to what-executes. Each is a telescope, not the
sky — the thing being observed is a human's authority, faithfully carried.
