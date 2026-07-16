# Formal Ceremony Kernel Design

**Status:** approved for a stacked implementation PR (2026-07-15)
**Parent:** agent-bridle PR #229, `docs/spec/ceremony-contract.md`
**Stacked branch:** `feat/formal-ceremony-kernel`
**Scope:** a hand-written Lean specification, a pure Rust mirror extracted by
Charon/Aeneas, and bridge proofs that the Rust implementation refines the
specification.

## 1. Purpose

The Ceremony Contract currently states algebraic and protocol properties in
prose. The formal kernel must prevent those properties from drifting back into
claims that the implementation does not enforce.

This design addresses two different questions:

1. What behavior is correct?
2. Does the Rust kernel implement that behavior?

The hand-written Lean model answers the first question. Charon and Aeneas
translate a pure Rust kernel into Lean, and bridge theorems answer the second.
A proof suite is incomplete if either side is missing.

The model is deliberately conditional at cryptographic boundaries. Lean can
prove that the protocol uses a collision-resistant hash or an unforgeable
signature in the right place; it does not prove that BLAKE3 or Ed25519 has
those computational properties. Those properties remain explicit assumptions
behind a small verified interface.

## 2. Goals

- Replace the flat verdict order with a product lattice whose independent axes
  cannot be confused.
- Prove meet resolution is associative, commutative, idempotent,
  order-independent, and non-amplifying.
- Make an accepted decision carry evidence that it belongs to the request it
  answers and cannot exceed that request's ceiling.
- Bind authorization to a canonical structured action, not display text.
- Make attest and introduction challenges recipient-bound, generation-bound,
  and single-use.
- Model rollback protection around a trusted checkpoint outside the
  attacker-controlled log.
- Give every quorum signer one canonical unsigned revocation body.
- Reject unsupported algorithms and unsupported authority-bearing wire data
  before it enters the kernel.
- Extract the Rust kernel with Charon/Aeneas and prove that the extracted
  functions refine the hand-written Lean model.
- Run the hand-written and bridge proofs on Linux and native Windows.

## 3. Non-goals

- Proving BLAKE3 collision resistance, Ed25519 unforgeability, WebAuthn
  authenticator correctness, or OS secure-storage guarantees.
- Formalizing JSON, TOML, DAG-CBOR, multicodec, or CID parsers in the first
  increment. Their canonical behavior is covered by shared vectors and an
  abstract injectivity contract at the kernel boundary.
- Proving asynchronous transport, UI rendering, filesystem durability, or
  network liveness.
- Moving serde, IO, crypto implementations, or UI code into the pure kernel.
- Treating a parent-linked log by itself as rollback-proof.

## 4. PR And Commit Structure

The implementation is a separate stacked PR:

- Base branch: `docs/spec-ceremony-contract` (PR #229)
- Head branch: `feat/formal-ceremony-kernel`
- Proposed title: `formal: prove ceremony algebra and protocol safety kernel`

Planned commits:

1. `docs(formal): design the ceremony proof kernel`
2. `formal(lean): prove the requirement algebra and protocol invariants`
3. `formal(rust): add the pure extraction-oriented ceremony kernel`
4. `formal(aeneas): prove the Rust kernel refines the Lean model`
5. `ci(formal): enforce Lean proofs and generated-code freshness`

The parent PR must be refreshed from `main` before the full verification gate.
Its current head predates #219, so native Windows `cargo test --workspace`
runs Unix-only `real_spawn` fixtures and fails before any stacked changes.

## 5. Authority Algebra

### 5.1 Why the flat verdict order is insufficient

The order `deny < attest < ask < approve` combines several independent facts:

- whether authority may be granted;
- the maximum caveats of the grant;
- what evidence is required before granting;
- how long the grant may remain valid.

Combining these axes into one enum makes semantically different states appear
comparable and encourages callers to treat a rendering choice as authority.
The formal model separates them.

### 5.2 Product lattice

The hand-written model defines:

```lean
inductive Permit
  | deny
  | allow

inductive Evidence
  | presence
  | prompt
  | none

inductive Lifetime
  | once
  | generation
  | durable

structure Requirement (Caveats : Type) where
  permit : Permit
  ceiling : Caveats
  evidence : Evidence
  lifetime : Lifetime
```

The order means "no more authority than":

- `deny <= allow`;
- `presence <= prompt <= none` because stronger evidence is more restrictive;
- `once <= generation <= durable`;
- caveats use the existing attenuation order.

`Requirement` receives the componentwise order and meet:

```text
meet(a, b).permit   = min(a.permit, b.permit)
meet(a, b).ceiling  = meet(a.ceiling, b.ceiling)
meet(a, b).evidence = min(a.evidence, b.evidence)
meet(a, b).lifetime = min(a.lifetime, b.lifetime)
```

The first Lean proof set establishes:

- `meet_assoc`;
- `meet_comm`;
- `meet_idem`;
- `meet_le_left` and `meet_le_right`;
- permutation invariance of list-fold resolution;
- every resolved requirement is no more authoritative than every matching
  input constraint;
- headless degradation replaces an unmet evidence obligation with `deny` and
  is therefore non-amplifying.

The existing four verdict names remain wire and policy vocabulary. A total
function maps each verdict into the product lattice. The rest of the kernel
operates on `Requirement`, not on verdict precedence numbers.

## 6. Requests, Decisions, And Effect Binding

### 6.1 Structured actions

Display strings are not authority. The model uses a structured action and an
abstract canonical digest:

```lean
structure Action where
  tool : ToolName
  arguments : CanonicalArguments
  resource : CanonicalResource

structure Request where
  requestId : RequestId
  action : Action
  actionId : Digest
  ceiling : Requirement Caveats
  options : Finset Choice
```

Request validation requires `actionId = digest(action)`. Display text is
derived metadata and never participates in authorization except by being
covered by the request's canonical wire record for auditability.

### 6.2 Validated decisions

Wire input first parses into `RawDecision`. It reaches the kernel only through:

```lean
validateDecision :
  (request : Request) -> RawDecision -> Option (DecisionFor request)
```

`DecisionFor request` contains a choice plus proofs that:

- the decision names `request.requestId`;
- the decision names `request.actionId`;
- the choice is a member of `request.options`;
- the resulting requirement is below `request.ceiling`;
- exactly one of grant and escalation was supplied.

Authorization also receives the action that is about to execute and checks
its digest against `request.actionId`. The soundness theorem states that any
minted context is for the approved action and is no more authoritative than
the request ceiling.

Escalation is represented separately from `DecisionFor`; it cannot construct
an effective grant.

## 7. Challenges And Single Use

Attestation and introduction use the same challenge algebra with different
domain tags:

```lean
inductive Purpose
  | attest
  | introduce

structure Challenge where
  purpose : Purpose
  issuer : Fingerprint
  recipient : Fingerprint
  requestId : Option RequestId
  actionId : Option Digest
  generation : Nat
  nonce : Nonce
```

The signature input is domain-separated by protocol, object kind, and version.
For introductions, the recipient issues the challenge; a nonce chosen only by
the introduced party is not fresh evidence.

The trusted state contains issued and consumed challenge identifiers. An
accepting transition requires the challenge to be issued, unconsumed, valid
for the current generation, and bound to the expected identities and action.
It then consumes the challenge atomically.

Theorems establish:

- an accepted challenge was issued by the expected verifier;
- an accepted attest challenge names the authorized action;
- an accepted introduction names both enrolled identities;
- no sequential execution can accept the same challenge twice;
- a generation mismatch fails closed.

Concurrency atomicity is a boundary obligation for the Rust adapter and is
tested with the existing gate's concurrent single-use regression pattern.

## 8. Trusted State And Protocol Transitions

The protocol model is an inductive transition relation over a small world:

```lean
structure World where
  policy : Policy
  trustedHead : Checkpoint
  generation : Nat
  issued : Finset ChallengeId
  consumed : Finset ChallengeId
  loadBearing : Finset Fingerprint
  profile : CryptoProfile

inductive Step : Actor -> World -> Event -> World -> Prop
```

Events include restrictive policy additions, signed loosening entries, pinning,
revocation, generation bumps, challenge consumption, and checkpoint advances.

The main safety split is explicit:

```lean
theorem untrusted_step_safe
  (h : Step .untrusted before event after) :
  effective after <= effective before /\
  after.loadBearing = before.loadBearing /\
  after.trustedHead = before.trustedHead
```

An untrusted actor may add a restrictive nuisance entry, but cannot widen
authority, add or remove trusted identities, or rewrite the trusted checkpoint.
Any transition outside that class must carry the corresponding authorization
witness: principal signature, accepted ceremony, or valid quorum.

This is stronger and clearer than allowing the load-bearing set to grow under
an untrusted transition. Adding a trusted identity is authority and requires a
ceremony.

## 9. Log Extension And Rollback

A parent-linked log proves ancestry only relative to a known head. It does not
make suffix truncation or presentation of an older fork detectable by itself.

The formal model therefore separates:

- `UntrustedLog`, which may be truncated, reordered, withheld, or replaced;
- `World.trustedHead`, stored or witnessed outside that attacker's authority;
- `Extends(candidate, trustedHead)`, a verified ancestry relation.

A synchronization or reload transition may advance the checkpoint only when
the candidate extends the existing trusted checkpoint. It may never replace
the checkpoint with an ancestor or unrelated fork.

Theorems establish:

- accepted checkpoints are monotonic under `Extends`;
- a strict ancestor of the trusted checkpoint is rejected;
- an unrelated fork is rejected;
- mutations confined to the untrusted log cannot alter trusted state;
- rollback detection is conditional on the checkpoint remaining outside the
  attacker's write authority.

The concrete checkpoint adapter may use OS protected storage, a quorum-signed
peer witness, hardware storage, or another mechanism. Each adapter must state
which principal protects it. No theorem calls a chain rollback-proof without
that premise.

## 10. Canonical Revocation And Quorum

Revocation has one unsigned body:

```lean
structure RevocationBody where
  target : Fingerprint
  reason : RevocationReason
  succession : Option Fingerprint
  tombstone : Bool
  policyEpoch : Nat

structure Endorsement where
  signer : Fingerprint
  signature : Signature

structure Revocation where
  body : RevocationBody
  endorsements : Finset Endorsement
```

Every endorsement verifies over the same domain-separated digest of
`RevocationBody`. Signatures are not part of the body they sign. The enclosing
chain record has a separate append signature.

Validation requires:

- signer membership in the quorum policy selected by `policyEpoch`;
- distinct signer identities;
- every signature verifies over the same body digest;
- the signer count reaches the threshold;
- last-root removal carries either a valid successor or an explicit tombstone;
- ceremony strength is at least the enrollment strength being revoked.

The principal theorem is that fewer than the required distinct valid signers
cannot produce a revocation transition.

## 11. Wire And Crypto Boundary

Signed inputs include a domain separator containing protocol, object kind, and
version. Authority-bearing v1 records reject unknown fields. Future versions
must be explicitly selected and validated; they are not silently interpreted
as v1.

Opaque extension data is permitted only in fields declared non-authoritative.
It remains covered by the canonical content digest and must survive a round
trip unchanged.

`CryptoProfile` is trusted configuration, not attacker-selected input. Before
dispatching on a multihash or multicodec code, validation proves that the code
belongs to the active profile. Profile rotation is an authorized state
transition.

The Lean boundary exposes assumptions such as:

```lean
class CryptoAssumptions (Value Key Message Signature : Type) where
  canonicalInjective : forall {x y : Value},
    canonical x = canonical y -> x = y
  digestBinding : forall {x y : Value},
    digest x = digest y -> canonical x = canonical y
  signatureOrigin : forall {key : Key} {msg : Message} {sig : Signature},
    verifies key msg sig -> signedBy key msg sig
```

These are assumptions used by protocol theorems, not claims that Lean proved
the underlying cryptographic algorithms. `signatureOrigin` proves only which
key produced a signature. Whether that key is authorized is a separate kernel
predicate over the active principal, quorum policy, role, and policy epoch.

The concrete checkpoint adapter has a similarly explicit environmental
obligation: attacker-controlled log writes cannot alter the trusted checkpoint.
The protocol proof is conditional on that adapter property; it is not hidden as
a consequence of hashing.

## 12. Rust Kernel And Aeneas Refinement

The Rust mirror lives in a pure module under `agent-bridle-core`. It contains
only algebraic data, explicit loops, validation predicates, and transition
functions. It contains no serde, IO, async, clocks, random generation, crypto
implementation, trait objects, or UI code.

Boundary adapters convert verified wire and cryptographic results into kernel
values. Invalid or unsupported inputs never construct kernel types.

Charon extracts the module to LLBC and Aeneas emits Lean under
`formal/Generated/`. Generated files are checked in and never edited manually.
`formal/Ceremony/Refinement.lean` proves, for each extracted operation:

- Rust meet equals specification meet;
- Rust resolution equals specification resolution;
- Rust decision validation implies `DecisionFor`;
- Rust transition acceptance implies the specification `Step` relation;
- Rust authorization output satisfies action binding and attenuation.

The bridge theorem is the release gate. Hand-written model proofs and extracted
Rust proofs passing independently are insufficient.

## 13. Lean Project Layout

```text
formal/
  lakefile.toml
  lean-toolchain
  Ceremony/
    Algebra.lean
    Decision.lean
    Challenge.lean
    Log.lean
    Revocation.lean
    Protocol.lean
    CryptoAssumptions.lean
    Refinement.lean
  Generated/
    CeremonyKernel.lean
  Tests/
    Counterexamples.lean
```

The Lean version is pinned to the Aeneas backend's compatible toolchain.
Dependencies are pinned in `lake-manifest.json`.

`Counterexamples.lean` records negative examples for the traps found during
review: suffix rollback without a trusted head, out-of-matrix grants, action
display substitution, replayed challenges, circular quorum payloads, unknown
authority fields, and attacker-selected hash algorithms. These examples make
the missing premise or rejected construction visible to reviewers.

## 14. Verification And CI

The stacked PR adds:

- `lake build` on Ubuntu and native Windows;
- Rust unit and property tests for the pure mirror;
- Linux-only Charon/Aeneas regeneration using pinned toolchains and caches;
- a generated-code freshness check that fails on a diff;
- `cargo fmt`, build, test, and clippy gates already required by the repo;
- pre-push parity for every required CI command.

Live services, network inference, hardware authenticators, and external peers
are not used by automated tests. Crypto and storage adapters use deterministic
mocks at this layer.

Because PR #229 currently predates the Windows test gating in #219, its branch
must first absorb current `main`; otherwise the unrelated Unix-command fixtures
fail on native Windows before formal verification runs.

## 15. Acceptance Criteria

- The product lattice laws compile without `sorry`, `admit`, or new axioms
  outside the named crypto/storage assumptions.
- Resolution is proved permutation-invariant and non-amplifying.
- A validated decision is proved request-bound, action-bound,
  matrix-contained, and ceiling-bounded.
- Attest and introduction challenges are proved single-use in the sequential
  kernel and generation-bound.
- Rollback rejection explicitly depends on an independently trusted
  checkpoint.
- Quorum validation uses distinct signers over one unsigned body.
- Unsupported profiles and unsupported authority-bearing wire versions fail
  closed.
- Aeneas-generated Rust operations are connected to the hand model by bridge
  theorems.
- Lean builds on Windows and Linux; Aeneas regeneration is reproducible on
  Linux/WSL.
- The PR body lists any remaining unproved environmental assumptions.

## 16. Review Guidance

Reviewers should reject any change that:

- moves rendering, serde, IO, or cryptographic implementation into the kernel;
- treats a CID or parent link as freshness without trusted external state;
- lets raw wire values bypass validated constructors;
- lets display text identify an executable effect;
- accepts a decision without checking request, action, matrix, and ceiling;
- treats a nonce as fresh without issuer and consumption state;
- lets quorum signers sign different payloads;
- dispatches an attacker-selected algorithm outside the active profile;
- adds a theorem using `sorry`, `admit`, or an unnamed axiom;
- omits the refinement proof between extracted Rust and the specification.
