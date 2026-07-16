# Formal Ceremony Kernel Design

**Status:** approved for an ordered stack of implementation PRs; reconciled
with the Ceremony Suite on 2026-07-16
**Parent:** agent-bridle PR #229, `docs/spec/README.md` and profiles P0-P5
**Stacked branch:** `feat/formal-ceremony-kernel`
**Scope:** profile-ordered hand-written Lean specifications, a pure Rust mirror
extracted by Charon/Aeneas, and bridge proofs that the Rust implementation
refines the specifications.

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
- Bind every signed object to an explicit signed-bytes envelope whose canonical
  body is transported unchanged through JSON/TOML views.
- Domain-separate every signature by record type, store, causal thread or
  principal, profile, and version.
- Make attest challenges verifier-bound, action-bound, generation-bound, and
  single-use in the Tier-3 kernel. Enrollment and Introduction freshness are
  proved separately as a Tier-2 symbolic protocol.
- Model rollback protection around P2's external anti-rollback anchor, outside
  the attacker-controlled log and represented as trusted state carried into
  every verification.
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
- Proving SAS, proof-of-possession Introduction, MITM resistance, or
  unknown-key-share resistance in Lean. Those are P3 protocol properties and
  require Tamarin or ProVerif under a Dolev-Yao model.

## 4. PR And Commit Structure

Implementation follows the suite dependency DAG. Each proof boundary is a
separate stacked PR so a reviewer can reject one profile without entangling
its dependents:

1. `formal: prove P1 signed-object contracts` -- Lean project, exact
   signed-envelope decoding contract, universal signature domains, private
   sealed-value boundary, version rejection, and trusted allowlist dispatch.
2. `formal: prove P2 chain-store monotonicity` -- external-anchor trusted
   state, DAG extension, rollback/fork rejection, and untrusted-step safety.
3. `formal: prove P0 authority resolution` -- product lattice, total
   resolution, matrix/ceiling validation, and non-amplification.
4. `formal: add the extraction-oriented ceremony kernel` -- pure Rust mirror
   for the proven P0/P1/P2 slice, with property tests.
5. `formal: prove Aeneas refinement of the ceremony kernel` -- checked-in
   extraction and bridge theorems, followed by generated-code freshness gates.

The design PR remains based directly on `docs/spec-ceremony-contract` (PR
#229). Every implementation branch is based on the preceding formal branch.
P3 enrollment gets a separate Tier-2 protocol-verification stack after the
P0/P1/P2 waist is proven; P4 and P5 follow their profile dependencies.

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

## 7. Attestation Challenges And Single Use

The Tier-3 kernel models attestation challenges. P3 Introduction may reuse the
wire shape, but its recipient-issued handshake and adversarial-channel claims
belong to the Tier-2 symbolic model and are not discharged by these theorems:

```lean
inductive Purpose
  | attest

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
The trusted state contains issued and consumed challenge identifiers. An
accepting transition requires the challenge to be issued, unconsumed, valid
for the current generation, and bound to the expected identities and action.
It then consumes the challenge atomically.

Theorems establish:

- an accepted challenge was issued by the expected verifier;
- an accepted attest challenge names the authorized action;
- no sequential execution can accept the same challenge twice;
- a generation mismatch fails closed.

Concurrency atomicity is a boundary obligation for the Rust adapter and is
tested with the existing gate's concurrent single-use regression pattern.

## 8. Trusted State And Protocol Transitions

The P0/P2 kernel model is an inductive transition relation over a small world:

```lean
structure World where
  policy : Policy
  anchor : ExternalAnchor
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
  after.anchor = before.anchor
```

An untrusted actor may add a restrictive nuisance entry, but cannot widen
authority, add or remove trusted identities, or rewrite P2's external anchor.
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
- `World.anchor`, the P2 `ExternalAnchor` stored or witnessed outside that
  attacker's authority;
- `Extends(candidate, anchor.checkpoint)`, a verified ancestry relation.

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

P1 resolves OB-4 with one authority-bearing transport shape. JSON and TOML are
views over an embedded canonical byte string; they are never signed directly:

```lean
structure SignatureDomain where
  recordType : RecordType
  storeId : StoreId
  threadOrPrincipal : ScopeId

structure UnsignedEnvelope where
  profile : ProfileId
  codec : Codec
  domain : SignatureDomain
  body : ByteArray
  cid : ContentId
  signer : Fingerprint

structure SignedEnvelope where
  unsigned : UnsignedEnvelope
  signatureAlgorithm : SignatureAlgorithm
  signature : ByteArray
```

The signature input is the canonical encoding of the entire
`UnsignedEnvelope`. Thus record type, store, causal thread or principal,
profile, codec, body CID, and signer are universally domain-bound (OB-6).
Authority-bearing v1 records reject unknown fields. Future versions must be
explicitly selected and validated; they are not silently interpreted as v1.

The parser remains outside the kernel, but its Tier-1 contract is exact: if
`decode received = some envelope`, then `encode envelope = received`. The
decoder cannot report invented security metadata for unrelated bytes. Shared
vectors exercise the concrete DAG-CBOR and JSON/TOML envelope adapters.

Opaque extension data is permitted only in fields declared non-authoritative.
It remains covered by the canonical content digest and must survive a round
trip unchanged.

`CryptoProfile` is trusted configuration, not attacker-selected input. Before
dispatching on a multihash or multicodec code, validation proves that the code
belongs to the active profile. Profile rotation is an authorized state
transition.

The Lean boundary exposes named assumptions such as:

```lean
class CryptoAssumptions (Value Key Message Signature Digest : Type) where
  canonicalInjective : forall {x y : Value},
    canonical x = canonical y -> x = y
  digestSound : forall {value : Value} {claimed : Digest},
    digestMatches claimed (canonical value) -> claimed = digest (canonical value)
  digestBinding : forall {left right : ByteArray},
    digest left = digest right -> left = right
  signatureOrigin : forall {key : Key} {msg : Message} {sig : Signature},
    verifies key msg sig -> signedBy key msg sig
```

These are assumptions used by protocol theorems, not claims that Lean proved
the underlying cryptographic algorithms. The executable digest/signature
predicates must carry proofs into these semantic relations; an arbitrary
always-true callback is not an admissible boundary implementation.
`signatureOrigin` proves only which key produced a signature. Whether that key
is authorized is a separate kernel predicate over the active principal,
quorum policy, role, and policy epoch.

Verified and sealed types have private constructors. Production code obtains
them only through the checked decoder/verifier path; the formal API exposes
read-only evidence projections. Hash and signature dispatch additionally
requires the active `TrustedProfile` witness, so a caller-created profile cannot
manufacture a legacy algorithm path.

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
    P1/
      SignedObject.lean
    P2/
      ChainStore.lean
    P0/
      Algebra.lean
      Decision.lean
      Challenge.lean
      Protocol.lean
    P4/
      Revocation.lean
    CryptoAssumptions.lean
    Refinement.lean
  Generated/
    CeremonyKernel.lean
  Tests/
    Counterexamples.lean
```

The Lean version is pinned to the Aeneas backend's compatible toolchain.
Dependencies are pinned in `lake-manifest.json`.

Counterexample modules live beside the profile that owns the rejected
construction. They record suffix rollback without an external anchor,
out-of-matrix grants, action display substitution, replayed attest challenges,
circular quorum payloads, unknown authority fields, and attacker-selected hash
algorithms. These examples make the missing premise or rejected construction
visible to reviewers without mixing profile dependencies.

## 14. Verification And CI

The formal stack adds these gates incrementally as their owning profile lands:

- `lake build` on Ubuntu and native Windows;
- Rust unit and property tests for the pure mirror;
- Linux-only Charon/Aeneas regeneration using pinned toolchains and caches;
- a generated-code freshness check that fails on a diff;
- `cargo fmt`, build, test, and clippy gates already required by the repo;
- pre-push parity for every required CI command.

Live services, network inference, hardware authenticators, and external peers
are not used by automated tests. Crypto and storage adapters use deterministic
mocks at this layer.

PR #229 was rebased over #219 before this design was reconciled, and its current
CI is green on Linux, macOS, and Windows. Each child branch must preserve that
baseline while adding its profile-specific proof gate.

## 15. Acceptance Criteria

- The product lattice laws compile without `sorry`, `admit`, or new axioms
  outside the named crypto/storage assumptions.
- Resolution is proved permutation-invariant and non-amplifying.
- A validated decision is proved request-bound, action-bound,
  matrix-contained, and ceiling-bounded.
- A decoded signed envelope recomposes to the exact received bytes; its CID is
  sound for the embedded canonical body and its signature is sound for the
  universally domain-separated unsigned envelope.
- Only a trusted active profile can dispatch cryptographic algorithms, and
  verified/sealed constructors are private.
- Attest challenges are proved single-use in the sequential kernel,
  generation-bound, and action-bound. P3 Introduction claims are absent from
  the Tier-3 acceptance gate and tracked in the Tier-2 protocol stack.
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
- accepts transport metadata that is not proved to recompose to the exact
  received signed envelope;
- signs a payload without record/store/thread-or-principal domain separation;
- lets display text identify an executable effect;
- accepts a decision without checking request, action, matrix, and ceiling;
- treats a nonce as fresh without issuer and consumption state;
- lets quorum signers sign different payloads;
- dispatches an attacker-selected algorithm outside the active profile;
- adds a theorem using `sorry`, `admit`, or an unnamed axiom;
- omits the refinement proof between extracted Rust and the specification.
