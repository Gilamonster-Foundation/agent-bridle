# The Ceremony Suite — a dependency-ordered set of provable profiles

> **New to this job? Start with [`PRIMER.md`](PRIMER.md)** — the agent
> onboarding doc (doctrine, architecture, conventions, current hold, how to
> contribute). Then this index, then your assigned profile.

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

## Specification obligations — status

From adversarial review round 6 (a fresh GPT pass, 2026-07-16), which
confirmed the split closed the prior attacks and rated architecture /
threat-honesty / separation / formal-plan all *Strong*. **All eleven are
addressed in the v0.3.0 repair cut** below (spec text changed; the *proofs*
that discharge them are the implementation phase, still held). **B/H/M** =
original severity.

| # | Sev | Status | Where fixed |
|---|---|---|---|
| OB-1 | B | ✅ resolved | dependency inversion — P0 §3/L5 define abstract `AttestEvidence` + `ValidAssociationProof`; P4 implements. DAG corrected above (P1→P2→P0→P4→P3). |
| OB-2 | B (choice) | ✅ adopted¹ | **linear authority spine per causal thread** `(store_id, thread_id, sequence)` — P2 §1. Conversation branches; authority is a railway. (Frontier alt rejected as harder to prove.) |
| OB-3 | B | ✅ resolved | P0 §3 — one canonical challenge preimage; CAS-committed transaction (verify→presence→construct→append→advance-anchor→mint); four separate roles (authenticator ≠ DAG verifier). |
| OB-4 | B | ✅ resolved | P1 §2 — signed-bytes-in-envelope `{profile, codec, body, cid, by, sig}`; JSON/TOML are views. |
| OB-9 | B | ✅ resolved | P0 L1 — `resolve(∅,q) = ask` (piecewise, not a seed — a seed would downgrade legitimate `approve`); vocabulary glossary P0 §2.4. |
| OB-5 | H | ✅ resolved | P3 §1 — reserve→validate→**consume-last**; bind challenge object CID + recipient + role + context. |
| OB-6 | H | ✅ resolved | P1 §4·5 — universal domain-separation tuple on every signed `body`; normative `store_id` (P2 §1). |
| OB-7 | H | ✅ resolved | P4 §2 — `policy_cid == ActiveRevocationPolicy(target, observed_checkpoint, generation)`; enrollment records the exact required revocation predicate (tuple isn't totally ordered). |
| OB-8 | H | ✅ resolved | P4 §3 — PO-R stated **conditionally**; timelock-recovery veto-suppression threat answered (multi-channel ack, fail-closed on silence). |
| OB-10 | M | ✅ resolved | P5 §1 — per-class sealed resource identities (container **digest** not tag, repo commit/tree CID, …); ambient = named residual. |
| OB-11 | M | ✅ resolved | `suite.toml` compatibility manifest (below). |

¹ OB-2 and the `attest` factorization were the two author's-calls; the
linear spine is *adopted pending your veto* (it's the reviewer's
recommendation and the provable option). The factorization stays open — the
lattice works either way (GPT-5 #232 already leans product-lattice).

The review's own verdict was "approve the split, request-changes on the four
blockers, list the rest." All four blockers (OB-1/2/3/4) plus the OB-9
soundness bug are now closed in text.

## Suite compatibility manifest (OB-11)

`suite.toml` names which profile versions form one compatible suite — one
atomic target for implementers, independent profile evolution preserved:

```toml
suite = "ceremony-suite"
suite_version = "0.3.0"
[requires]
p0 = "0.2"   # ceremony-contract (waist)
p1 = "1"     # signed-object
p2 = "0.2"   # chain-store
p3 = "0.2"   # enrollment
p4 = "0.2"   # identity-lifecycle
p5 = "0.2"   # rendering-security
conformance_vectors = "cid:…"   # populated with the kernel
```

## The rule underneath the whole suite

> No authorization or claim floats free of the exact history and artifacts
> that gave it meaning.

P1 gives things names; P2 gives history that cannot silently move; P0 makes
authority an algebra that cannot amplify; P3/P4 bind identity to ceremony;
P5 binds what-was-approved to what-executes. Each is a telescope, not the
sky — the thing being observed is a human's authority, faithfully carried.
