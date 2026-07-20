# Ceremony Suite — Development Roadmap & Project Plan

**Status:** active, 2026-07-16. The spec is **ratified** (v0.3.1 protocol
freeze, PR #229 merged to `main`). This plan sequences the work from here to
a shipped, formally-verified, multi-language enforcement gate.

**The governing rule:** *prove the narrow waist before building outward, and
never fossilize a wire format ahead of its conformance vectors.* Everything
below respects the dependency DAG `P1 → P2 → P0 → P4 → P3` (P5 on
{P0,P1,P4}) and the three proof tiers (Tier-3 Lean+Aeneas, Tier-2
Tamarin/ProVerif, Tier-1 assumed crypto).

## What is decided vs. held (the gate)

- **Decided & frozen (v0.3.1):** the authority type (`Effect × Assurance ×
  Scope`), `ask`→`NeedsDecision`, the explicit ceiling, the signed-object
  protected-tuple grammar, genesis `STORE_ID_SELF`, CAS append, the five
  laws (L2 upward = equality). ADRs 0020–0023.
- **Safe to build now (nonbinding spikes):** the pure algebra/kernel and its
  proofs; `Sealed<T>` with adversarial property tests; a CAS-based P2 state
  machine; DAG-CBOR/signature experiments; Lean/TLA+ models.
- **HELD until its conformance vectors exist:** frozen Rust structs,
  serialized records, DB schemas, cross-language APIs, stored signatures.
- **Roadmap-only (post-waist):** Byzantine-Vertical-Paxos store evolution.

---

## Phase 0 — Ratify & scaffold  *(this cut)*

| # | Deliverable | State |
|---|---|---|
| 0.1 | Merge the spec suite to `main` | ✅ PR #229 |
| 0.2 | ADRs 0020 (authority type) · 0021 (append CAS→BVP) · 0022 (signed grammar) · 0023 (proof discipline) | this cut |
| 0.3 | **Lean P0 authority model** — `formal/Ceremony/P0/Authority.lean`, 25 theorems, 0 `sorry` | ✅ |
| 0.4 | **TLA+ store model** — `formal/tla/CeremonyStore.tla` (CAS + anti-rollback invariants) | ✅ |
| 0.5 | **Lean P1 signed-object contracts** + Lake project + `formalGate` proof-escape gate + CI (`formal.yml`) + `just check-formal` | ✅ (harvested from PR #233 / GPT-5, integrated with P0) |
| 0.6 | Aeneas/Charon toolchain green on gnuc (opam/OCaml leg) | ✅ built on gnuc; `agent-bridle-ceremony` extracts Rust→LLBC→Lean and the first refinement proofs pass (`formal/refinement/`) |

**Exit:** ADRs merged; the unified Lean project (P0 + P1) builds under CI + the
pre-push gate; TLA+ store model in place; only the opam leg remains before
Rust→Lean extraction.

## Phase 1 — Prove the waist  *(P1 → P2 → P0)*  — the MVP

The provable core. Each profile lands as: pure kernel → property tests →
formal proof → conformance vectors.

- **1a P1 Signed-Object.** `ContentId`/canonical DAG-CBOR/`Sealed<T>`; the
  protected-tuple constructor + verify order (ADR 0022); algorithm allowlist;
  genesis sentinel. Property tests (round-trip, tamper, unknown-field
  fail-closed). *Gate:* PO-1c, PO-8 as Lean contracts + vectors.
  - *Audit obligations (2026-07-18, epic #263):* the harvested P1 kernel is an
    **abstract semantic** skeleton until these are discharged; keep claims
    narrow (audit §12) — do **not** say "formally verified" yet.
    - **F-233-01 / F-233-04:** `digest_binding` asserts impossible *global*
      injectivity over arbitrary `ByteArray` (BLAKE3-256 cannot inhabit it),
      and `signature_binding` / `signature_deterministic` are algebraic-equality
      stand-ins, not EUF-CMA. Restate both as bounded-domain / **computational**
      assumptions under the **Tier-1 "assumed crypto"** boundary (or drop them
      if unused) and align the Rust doc gloss. Hard blocker only at Tier-3
      crypto refinement.
    - **F-233-02 — DISCHARGED at the Lean tier (2026-07-18).**
      `formal/Ceremony/P1/PreimageCodec.lean` now exhibits a domain-separated,
      versioned, tagged, length-delimited `encodeSignaturePreimage` with a proved
      `encodeSignaturePreimage_injective` (reader/round-trip technique; depends only
      on `propext`+`Quot.sound`), plus the payoff bridge `structural_binding_from_bytes`:
      the *structural* `signature_binding` is **derived** from a byte-level EUF-CMA
      assumption (`ByteSigner.bytes_binding`, Tier-1) composed with that injectivity —
      no structural binding postulate needed. Per ADR 0024 §D0 the Lean encoding
      witnesses the *injectivity property*, not the frozen bytes; the exact wire
      encoding is still **frozen with the 1d vectors** (below). *Remaining #263
      riders:* rewire `CryptoBoundary` in `SignedObject.lean` onto `ByteSigner`
      (F-233-01/04), and the `#print axioms` gate upgrade (F-233-06).
    - **AB-005 (runtime wiring):** `Registry::dispatch` feeds
      `CallRequest::unspecified(name)` into the step-up challenge, so approval
      binds the tool name, not the resolved `(tool, args, resource)` tuple. The
      enforcement seam must feed the resolved tuple (`CallRequest::new`) — needs
      a resolver-seam decision. Tracked in epic #258.
- **1b P2 Chain-Store (CAS).** The append CAS + the anti-rollback trusted-state
  machine. **TLA+/TLC model checked first** (`CeremonyStore.tla`), then the
  pure Rust state machine refined to it. *Gate:* PO-2/2a/2c; TLC invariants
  green.
- **1c P0 Authority kernel.** Pure `resolve` (piecewise, no fail-open) +
  precedence + the gate-acceptance checklist. **Charon extracts the Rust
  kernel; Aeneas proves it refines `Authority.lean`.** *Gate:* PO-1/3/4/5
  + the refinement bridge theorem; CI blocks any kernel that fails it.
  - *Started:* `agent-bridle-ceremony` (`authority.rs` + `boundary.rs`) is the
    pure kernel; `formal/refinement/` proves the `meet`/`attenuate` laws on the
    Charon/Aeneas-extracted code. **Remaining:** rewrite `resolve` from an
    iterator-`fold` (Aeneas axiomatizes slice iterators, so it won't reduce) to
    explicit recursion, then extend the refinement proof to cover it.
  - *Audit obligation (AB-012, epic #259):* the `agent-bridle-jaild` broker
    accepts client-supplied caveats without establishing who minted them or the
    caller's entitlement — it enforces *confinement relative to a request*, not
    *authorization to make it*. The P0 authority relation owes a signer/trust
    lookup so the broker can verify an **attested** grant (or the design must
    explicitly narrow the broker to confinement-only). Cross-link #231.
- **1d Conformance vectors.** `tests/vectors/*.json` — positive **and
  negative** — the cross-language behavioral contract. *This unblocks the
  "held" wire freeze.*
  - *Audit obligation (F-233-02, epic #263):* the injective, prefix-free
    `encodeSignaturePreimage` codec + its injectivity proof — **now discharged at
    the Lean tier** (`formal/Ceremony/P1/PreimageCodec.lean`; see Phase 1a). What
    remains **here** is freezing the *exact wire bytes* (ADR 0024 encoding) with the
    DAG-CBOR vectors. **F-233-05** (concrete DAG-CBOR/JSON/
    TOML adapters) is *already this phase* — on track, **not a defect**:
    implementing a wire codec before its vectors would violate the governing
    rule ("never fossilize a wire format ahead of its conformance vectors").

**Exit (the big one):** the Rust waist compiles, refines the Lean model,
passes the TLA+-checked store invariants, and the conformance vectors are
published. Only now do wire structs stop being nonbinding.

## Phase 2 — Ceremonies  *(P4 → P3 → P5)*

- **2a P4 Identity Lifecycle.** Roles/delegation, records, quorum revocation
  (exact policy predicate), break-glass/succession (conditional PO-R). Implements
  P0's `AttestEvidence`/`ValidAssociationProof`.
  - *Audit note (F-233-03):* "signer is committed data, not established origin"
    is **not a P1 defect** — the trusted-key registry / `TrustedKey(profile,
    signer_id, pubkey, epoch, purpose)` lookup is deliberately scheduled here
    (with P0 authority). Do not re-triage it onto Phase 1.
- **2b P3 Enrollment.** SAS pairing, PoP introductions (recipient-issued
  challenge, consume-last). **Tier-2: Tamarin/ProVerif** proofs of
  freshness / no-MITM / no-unknown-key-share.
- **2c P5 Rendering.** Effect binding, gate-signed requests, surface
  attestation (byte-compare canonical render; token = attention aid; **no raw
  secrets**). Stated human-factors residual.

**Exit:** the full ceremony flow works end-to-end against a reference harness;
protocol proofs green.

## Phase 3 — Client libraries

One Rust enforcement core; consumer-side libs elsewhere. **Never fork the gate.**

- Rust (reference, `agent-bridle`) · Python (`agent-bridle-py` PyO3 — exists) ·
  Dart (flutter_rust_bridge → newt-mobile) · TypeScript (Claude Code / Codex —
  pure-spec impl likely). All bound by the Phase-1d conformance vectors.
- First consumer: **newt-agent #1209** (the pinning ceremony).

## Phase 4 — Store evolution: Byzantine Vertical Paxos  *(post-waist)*

Only after the waist is proven. Evolve P2 from CAS (threshold-1 steady state)
to **vertically-reconfigurable replication**: lean steady state + a stronger
**wedge**-based reconfiguration (fence config → safe closing state → certify
next config); 2-full-node deployments get failover via a state-light
reconfiguration participant (`f+1` steady / `2f+1` reconfig); the
partition-authority ceiling becomes operation-sensitive on the frozen lattice;
key custody is a separate Shamir threshold.

- **4a** ADR + TLA+/Lean model of the wedge/closing-state correctness
  (the exit gate before it is normative).
- **4b** Implementation as a P2 evolution / P6 profile.
- **Reference:** (Byzantine) Vertical Paxos — Abraham & Malkhi (IBM Zurich
  DCCL); VP orig. Lamport-Malkhi-Zhou, PODC 2009.

## Cross-cutting tracks

- **Proof CI (Tier-3 gate).** No Rust kernel merges unless its Aeneas
  refinement proof passes; mirrored in the pre-push hook (HOOK/PIPELINE
  PARITY). TLA+/TLC and Tamarin runs wired into CI as they land.
  - *Audit obligation (F-233-06, epic #263):* `formal/Gate.lean` is a **source
    substring scan** for `sorry`/`admit`/`axiom` — hygiene only; it misses
    imported axioms, unsafe decls, and dependency trust. Add machine-readable
    auditing — `#print axioms` / `Lean.collectAxioms` over the exported security
    theorems with a whitelist of acceptable classical/quotient axioms — plus a
    pinned toolchain + immutable action SHAs and retained axiom-set artifacts.
- **Spec ↔ impl parity.** Every wire change updates the spec, the vectors,
  and the ADR in one PR.
- **The `#231` rename** (`passkey`→`attest`→now `Assurance`) rides Phase 1.
- **L1+L4 unification** (five laws → four) — attempt during 1c if the Lean
  formulation collapses them.

## Runtime enforcement hardening — off the ceremony track

The 2026-07-18 adversarial audit (`docs/agent-bridle-adversarial-audit.md`,
verified against `origin/main`) found defects in the **runtime enforcement
layer** (registry/gate, shell, web, jaild, MCP, Python, config) that are **not**
Ceremony phases and must not be forced onto them. They live in standalone
hardening epics; only two bridge into the formal track (AB-005 → Phase 1a,
AB-012 → Phase 1c, both recorded above):

| Epic | Theme | Flagship findings |
|---|---|---|
| #258 | Registry/gate: grant identity, cross-dispatch budget, action-bound step-up | AB-001, AB-005, AB-013, AB-014 |
| #259 | jaild hardening (fail-closed root drop, verified mounts, unpredictable roots, attested grants) | AB-002, AB-003, AB-008, AB-012 |
| #260 | Shell hostile-child & env hygiene (env is authority; timeouts must reap) | AB-004/016, AB-006, AB-015 (→#10) |
| #261 | MCP transport & dispatch conformance | AB-019 (PR #273), AB-020, AB-021 |
| #262 | Fail-closed defaults (no error/absence silently permissive) | AB-009, AB-010, AB-007, AB-024 (→#138), AB-023 (→#138) |
| #263 | **P1 signed-object refinement obligations** (this doc's Phase-1 riders) | F-233-01/02/04/06 |

The claim language in audit §12 governs until epics #258–#262 clear their P0
items: prefer "centralizes tool admission" / "applies platform confinement where
available" over "call limits enforced across a session," "timed-out commands are
stopped," "the jail always drops root," or "human approval is bound to the exact
action."

## Milestone summary

| Milestone | Gate |
|---|---|
| **M0** scaffold | ADRs + both formal models in `formal/` |
| **M1** waist proven | Rust waist refines Lean + passes TLA+ invariants + vectors published |
| **M2** ceremonies | end-to-end flow + Tier-2 protocol proofs |
| **M3** libraries | 4 languages agree on the conformance vectors |
| **M4** BVP store | wedge model proven, reconfiguration shipped |

The prose is done arguing with itself. From M1 on, the adversary is a proof
checker and a conformance vector — exactly as intended.
