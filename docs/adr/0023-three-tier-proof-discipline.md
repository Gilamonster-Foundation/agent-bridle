# ADR 0023 — The three-tier proof discipline

- Status: **Accepted** (2026-07-16). Formalizes the verification architecture
  the adversarial reviews demanded.
- Related: `docs/spec/README.md` ("The teeth"), `formal/`, ADRs 0020–0022.

## Context

Across review rounds 4–7, the recurring failure the reviewers punished was
*"prose becomes authority-bearing protocol"* — a claim proven at the wrong
level, e.g. an algebraic lattice argument used to justify a protocol's
freshness, or a hash-chain used to justify rollback resistance it does not
provide. A single "we'll prove it in Lean" is not credible, because different
claims need different tools.

## Decision

Correctness is enforced in **three tiers, each verified by a different kind of
tool, and the tiers are never conflated.**

- **Tier 3 — kernel refinement (Lean + Aeneas).** The *authority algebra* and
  the *trusted state machine*. A pure Rust kernel is extracted by Charon and
  proven in Lean via Aeneas to **refine** a hand-written model. The algebra
  lives in `formal/lean/Authority.lean` (meet laws, attenuation, no-fail-open,
  order-independence — 25 theorems, 0 `sorry`); the store state machine lives
  in `formal/tla/CeremonyStore.tla` (CAS append, checkpoint monotonicity,
  no-rollback). CI gate: **no Rust kernel merges unless its refinement proof
  passes.**
- **Tier 2 — protocol safety (Tamarin / ProVerif).** The *ceremonies*
  (enrollment, introduction, discharge). A flawless lattice can sit behind a
  leaky handshake, so MITM / replay / unknown-key-share get *symbolic* proof
  under Dolev-Yao — **not** an algebraic argument.
- **Tier 1 — cryptographic primitives (assumed, cited).** Ed25519
  unforgeability, BLAKE3 collision resistance, deterministic nonces. The trust
  base; rotatable via P1's algorithm allowlist.
- **Cross-cutting — conformance vectors.** Shared positive+negative JSON
  vectors bind the four client languages to one observable behavior where
  proofs stop.

## Consequences

- Each spec claim is tagged with the tier that discharges it (the PO ledger in
  `docs/spec/README.md`). A claim with no tier is not a claim — it is prose.
- The pure kernel must stay pure (no serde/IO/crypto/UI) so Aeneas can run;
  crypto enters as abstract injective/one-way contracts at the kernel edge
  (ADR 0022).
- Tooling cost: three verifiers plus a vector harness. Accepted — it is the
  price of not asking reviewers to intuit the protocol.

## Alternatives considered

- **One tool for everything (Lean only).** Rejected: Lean/Aeneas proves
  functional correctness of pure code, not Dolev-Yao protocol safety; forcing
  a handshake into a refinement proof would be exactly the tier-confusion the
  reviews caught.
- **No formal track, tests only.** Rejected: the review series repeatedly
  found soundness bugs (empty-meet fail-open, latent authority injection) that
  survived passing tests; the whole point is that the adversary becomes a
  proof checker.
