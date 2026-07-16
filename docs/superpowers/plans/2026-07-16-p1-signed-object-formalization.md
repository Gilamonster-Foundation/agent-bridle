# P1 Signed-Object Formalization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build and continuously verify the P1 Lean model that makes canonical
encoding, sealed loading, strict version handling, and algorithm
allowlist-before-dispatch explicit proof obligations.

**Architecture:** A dependency-free Lean project models only P1. A signed-byte
envelope embeds the canonical body and universal signature domain. An abstract
codec proves every decoded envelope recomposes to the exact received bytes;
named cryptographic soundness contracts connect executable checks to digest
binding and signature origin. Verified constructors are private, and algorithm
dispatch requires the active `TrustedProfile` witness.

**Tech Stack:** Lean 4 `v4.31.0` via elan/lake, Rust workspace checks, GitHub
Actions on Ubuntu and Windows, PowerShell-compatible local commands.

## Global Constraints

- P1 has no dependency on P0, P2, serde, IO, clocks, network services, or
  concrete cryptographic implementations.
- Cryptographic strength is a Tier-1 assumption; no theorem claims to prove
  BLAKE3 collision resistance or Ed25519 unforgeability.
- Proofs contain no `sorry`, `admit`, or unnamed axioms.
- Verification must run on Linux and native Windows.
- Automated tests are deterministic and use no live services.
- Every commit is authored as Shawn Hartsock and includes
  `Co-Authored-By: OpenAI GPT-5 <codex@openai.com>`.

## Parent-Reconciliation Amendment

PR #229 added OB-4 and OB-6 after the initial TDD outline below was written.
These requirements supersede the earlier `RawEnvelope` and public `Sealed`
snippets:

- Transport is an explicit signed-bytes envelope. JSON/TOML carry an encoded
  canonical body; authority never depends on their reserialization.
- The codec contract requires `decode received = some envelope` to imply
  `encode envelope = received`.
- Every signature covers record type, store ID, causal thread or principal,
  profile/version, codec, CID, signer, and canonical body.
- Executable digest and signature checks carry soundness proofs into named
  Tier-1 `DigestBinding` and `SignedBy` relations.
- Verified and parsed-value constructors are private. The only production path
  is decode, profile/field validation, CID/signature verification, then parse.
- Cryptographic dispatch requires both an allowlist witness and the active
  `TrustedProfile`; caller-created profiles cannot reach legacy dispatch.
- The proof gate scans every Lean source in `formal/`, rejects proof escapes,
  and rejects modules omitted from the root import graph.

---

### Task 1: Pin the standalone Lean project and write the failing contract test

**Files:**
- Create: `formal/lean-toolchain`
- Create: `formal/lakefile.toml`
- Create: `formal/Tests.lean`
- Create: `formal/Tests/SignedObjectContracts.lean`

**Interfaces:**
- Consumes: Lean standard library only.
- Produces: Lake library `CeremonyFormal` rooted at `formal/Ceremony` and test
  import `Ceremony.P1.SignedObject`.

- [x] **Step 1: Add the toolchain and Lake configuration**

```text
leanprover/lean4:v4.31.0
```

```toml
name = "ceremony-formal"
version = "0.1.0"
defaultTargets = ["CeremonyFormal", "CeremonyTests"]

[[lean_lib]]
name = "CeremonyFormal"
srcDir = "."
roots = ["Ceremony"]

[[lean_lib]]
name = "CeremonyTests"
srcDir = "."
roots = ["Tests"]
```

- [x] **Step 2: Write a test importing the not-yet-created P1 module**

```lean
import Ceremony.P1.SignedObject

open Ceremony.P1

example : Profile.v1.allowsHash .blake3_256 := by decide
example : Not (Profile.v1.allowsHash .sha1) := by decide
```

```lean
import Tests.SignedObjectContracts
```

- [x] **Step 3: Run the test and verify RED**

Run: `Push-Location formal; lake build; Pop-Location`

Expected: FAIL because `Ceremony.P1.SignedObject` does not exist.

- [x] **Step 4: Commit only after Task 2 reaches green**

The scaffold, model, and tests land together in Task 2 so no commit leaves the
default Lake target broken.

### Task 2: Model canonical bytes, profile witnesses, and sealed values

**Files:**
- Create: `formal/Ceremony.lean`
- Create: `formal/Ceremony/P1/SignedObject.lean`
- Modify: `formal/Tests/SignedObjectContracts.lean`

**Interfaces:**
- Consumes: `ByteArray`, `Finset`, and decidable equality from Lean core.
- Produces: `HashAlgorithm`, `SignatureAlgorithm`, `Codec`, `Profile`,
  `AllowedHash`, `AllowedSignature`, `AllowedCodec`, `CanonicalEncoding`,
  `VerifiedEnvelope`, `Sealed`, `sealValue`, and
  `sealed_eq_of_same_canonical`.

- [x] **Step 1: Extend the test with the wished-for sealing API**

```lean
def bytesEncoding : CanonicalEncoding ByteArray where
  encode := id
  injective := by
    intro left right h
    exact h

example (a b : ByteArray) (h : bytesEncoding.encode a = bytesEncoding.encode b) :
    a = b := bytesEncoding.injective h

example (value : ByteArray) : (sealValue bytesEncoding value).value = value := rfl
```

- [x] **Step 2: Run the test and verify RED**

Run: `Push-Location formal; lake build; Pop-Location`

Expected: FAIL with unknown identifiers such as `CanonicalEncoding` and
`sealValue`.

- [x] **Step 3: Implement the minimal P1 model**

Define finite algorithm enums, a v1 profile containing exactly BLAKE3-256,
Ed25519, and DAG-CBOR, proof-carrying allowed-algorithm wrappers, an injective
canonical encoder interface, and a `Sealed` value whose canonical bytes must be
proved equal to the encoding of its value. Use this module shape:

```lean
namespace Ceremony.P1

inductive HashAlgorithm | blake3_256 | sha1
  deriving DecidableEq, Repr
inductive SignatureAlgorithm | ed25519 | ecdsa
  deriving DecidableEq, Repr
inductive Codec | dagCbor | json
  deriving DecidableEq, Repr

structure Profile where
  version : Nat
  hashes : List HashAlgorithm
  signatures : List SignatureAlgorithm
  codecs : List Codec

def Profile.v1 : Profile :=
  { version := 1, hashes := [.blake3_256],
    signatures := [.ed25519], codecs := [.dagCbor] }

def Profile.allowsHash (profile : Profile) (algorithm : HashAlgorithm) : Prop :=
  algorithm ∈ profile.hashes

def Profile.allowsSignature
    (profile : Profile) (algorithm : SignatureAlgorithm) : Prop :=
  algorithm ∈ profile.signatures

def Profile.allowsCodec (profile : Profile) (codec : Codec) : Prop :=
  codec ∈ profile.codecs

structure AllowedHash (profile : Profile) where
  algorithm : HashAlgorithm
  allowed : profile.allowsHash algorithm

structure AllowedSignature (profile : Profile) where
  algorithm : SignatureAlgorithm
  allowed : profile.allowsSignature algorithm

structure AllowedCodec (profile : Profile) where
  codec : Codec
  allowed : profile.allowsCodec codec

structure CanonicalEncoding (Value : Type) where
  encode : Value -> ByteArray
  injective : Function.Injective encode

structure Sealed {Value : Type} (encoding : CanonicalEncoding Value) where
  value : Value
  canonical : ByteArray
  canonical_eq : canonical = encoding.encode value

def sealValue (encoding : CanonicalEncoding Value) (value : Value) : Sealed encoding :=
  { value, canonical := encoding.encode value, canonical_eq := rfl }
```

Parsing and concrete signature verification remain boundary parameters rather
than hidden axioms.

- [x] **Step 4: Prove canonical identity and profile rejection**

Add theorems with these exact signatures:

```lean
theorem sealed_eq_of_same_canonical
    {encoding : CanonicalEncoding Value} {a b : Sealed encoding}
    (h : a.canonical = b.canonical) : a = b

theorem sha1_not_allowed : Not (Profile.v1.allowsHash .sha1)
theorem blake3_allowed : Profile.v1.allowsHash .blake3_256
theorem ecdsa_not_allowed : Not (Profile.v1.allowsSignature .ecdsa)
theorem ed25519_allowed : Profile.v1.allowsSignature .ed25519
theorem json_not_allowed : Not (Profile.v1.allowsCodec .json)
theorem dag_cbor_allowed : Profile.v1.allowsCodec .dagCbor
```

- [x] **Step 5: Run the focused proof build and verify GREEN**

Run: `Push-Location formal; lake build; Pop-Location`

Expected: PASS with both `CeremonyFormal` and `SignedObjectContracts` built.

- [x] **Step 6: Commit the P1 model**

```text
formal(lean): prove P1 signed-object contracts

Co-Authored-By: OpenAI GPT-5 <codex@openai.com>
```

### Task 3: Encode verify-before-parse and allowlist-before-dispatch

**Files:**
- Modify: `formal/Ceremony/P1/SignedObject.lean`
- Modify: `formal/Tests/SignedObjectContracts.lean`
- Create: `formal/Tests/P1Counterexamples.lean`
- Modify: `formal/lakefile.toml`

**Interfaces:**
- Consumes: P1 algorithm and canonicalization types from Task 2.
- Produces: `RawEnvelope`, `SupportedVersion`, `VerifiedEnvelope`,
  `verifyEnvelope`, `dispatchHash`, and rejection theorems for unsupported
  versions, critical fields, and algorithms.

- [x] **Step 1: Write failing tests for hostile inputs**

```lean
def v1Envelope : RawEnvelope :=
  { version := 1, hash := .blake3_256, signature := .ed25519,
    codec := .dagCbor, receivedCanonical := ByteArray.mk #[],
    unknownCritical := [] }

def unsupportedVersionEnvelope : RawEnvelope := { v1Envelope with version := 2 }
def sha1Envelope : RawEnvelope := { v1Envelope with hash := .sha1 }
def unknownCriticalEnvelope : RawEnvelope :=
  { v1Envelope with unknownCritical := ["future-authority"] }

example : (verifyEnvelope Profile.v1 v1Envelope).isSome := by decide
example : verifyEnvelope Profile.v1 unsupportedVersionEnvelope = none := by decide
example : verifyEnvelope Profile.v1 sha1Envelope = none := by decide
example : verifyEnvelope Profile.v1 unknownCriticalEnvelope = none := by decide
```

The counterexample module also defines an `unsafeDispatch` that accepts a raw
`HashAlgorithm`; the safe `dispatchHash` requires an `AllowedHash` witness, so
v1 cannot dispatch SHA-1:

```lean
inductive HashImplementation | blake3 | legacySha1 deriving DecidableEq

def unsafeDispatch : HashAlgorithm -> HashImplementation
  | .blake3_256 => .blake3
  | .sha1 => .legacySha1

def dispatchHash (allowed : AllowedHash profile) : HashImplementation :=
  unsafeDispatch allowed.algorithm

example : unsafeDispatch .sha1 = .legacySha1 := rfl

theorem no_v1_sha1_witness
    (allowed : AllowedHash Profile.v1) :
    Not (allowed.algorithm = .sha1) := by
  intro h
  subst h
  exact sha1_not_allowed allowed.allowed
```

- [x] **Step 2: Run the test and verify RED**

Run: `Push-Location formal; lake build; Pop-Location`

Expected: FAIL because envelope verification and safe dispatch are undefined.

- [x] **Step 3: Implement staged verification**

`verifyEnvelope` checks version, rejects non-empty critical unknown fields,
checks profile membership, and only then constructs the proof witness passed to
the abstract dispatch function. It retains received canonical bytes in
`VerifiedEnvelope`; no theorem reserializes a typed value to recover signed
bytes. Implement the boundary with this shape:

```lean
structure RawEnvelope where
  version : Nat
  hash : HashAlgorithm
  signature : SignatureAlgorithm
  codec : Codec
  receivedCanonical : ByteArray
  unknownCritical : List String
  deriving DecidableEq

structure VerifiedEnvelope (profile : Profile) (raw : RawEnvelope) where
  version_eq : raw.version = profile.version
  critical_empty : raw.unknownCritical = []
  allowedHash : AllowedHash profile
  hash_eq : allowedHash.algorithm = raw.hash
  allowedSignature : AllowedSignature profile
  signature_eq : allowedSignature.algorithm = raw.signature
  allowedCodec : AllowedCodec profile
  codec_eq : allowedCodec.codec = raw.codec

def verifyEnvelope (profile : Profile) (raw : RawEnvelope) :
    Option (VerifiedEnvelope profile raw) :=
  if hv : raw.version = profile.version then
    if hc : raw.unknownCritical = [] then
      if hh : profile.allowsHash raw.hash then
        if hs : profile.allowsSignature raw.signature then
          if hcodec : profile.allowsCodec raw.codec then
            some { version_eq := hv, critical_empty := hc,
              allowedHash := { algorithm := raw.hash, allowed := hh },
              hash_eq := rfl,
              allowedSignature := { algorithm := raw.signature,
                allowed := hs }, signature_eq := rfl,
              allowedCodec := { codec := raw.codec, allowed := hcodec },
              codec_eq := rfl }
          else none
        else none
      else none
    else none
  else none
```

- [x] **Step 4: Prove fail-closed behavior**

Add theorems with these exact statements:

```lean
theorem verified_hash_allowed
    (h : verifyEnvelope profile raw = some verified) :
    profile.allowsHash verified.allowedHash.algorithm

theorem verified_signature_allowed
    (h : verifyEnvelope profile raw = some verified) :
    profile.allowsSignature verified.allowedSignature.algorithm

theorem verified_codec_allowed
    (h : verifyEnvelope profile raw = some verified) :
    profile.allowsCodec verified.allowedCodec.codec

theorem unsupported_version_rejected
    (h : Not (raw.version = profile.version)) :
    verifyEnvelope profile raw = none

theorem unknown_critical_rejected
    (h : Not (raw.unknownCritical = [])) :
    verifyEnvelope profile raw = none
```

- [x] **Step 5: Run all Lean targets and verify GREEN**

Run: `Push-Location formal; lake build; Pop-Location`

Expected: PASS, including `P1Counterexamples`.

- [ ] **Step 6: Commit the verification boundary**

```text
formal(lean): enforce allowlist-before-dispatch

Co-Authored-By: OpenAI GPT-5 <codex@openai.com>
```

### Task 4: Add cross-platform proof gates and hook parity

**Files:**
- Modify: `.github/workflows/ci.yml`
- Modify: `justfile`
- Modify: `.githooks/pre-push`
- Modify: `docs/TOOLCHAIN.md`

**Interfaces:**
- Consumes: the `formal` Lake project from Tasks 1-3.
- Produces: `just check-formal`, Linux and Windows `lake build` jobs, and a
  pre-push invocation matching the required CI proof gate.

- [ ] **Step 1: Add a failing local gate check**

Add `check-formal` to `justfile` with `lake build` executed from `formal`, then
invoke it before installing elan to confirm the command fails clearly when the
toolchain is absent.

- [ ] **Step 2: Install/resolve the pinned Lean toolchain and verify the gate**

Run: `elan toolchain install leanprover/lean4:v4.31.0`

Run: `just check-formal`

Expected: PASS.

- [ ] **Step 3: Mirror the gate in CI and pre-push**

Add a `formal` job with an Ubuntu/Windows matrix using `leanprover/lean-action`
and `lake build`. Add `just check-formal` to `.githooks/pre-push`. Keep parity
comments adjacent in all three files.

- [ ] **Step 4: Update toolchain status accurately**

Record native Windows `lake build` as verified only after the local run passes;
leave native Aeneas/opam explicitly unverified and WSL2-recommended.

- [ ] **Step 5: Run syntax and proof gates**

Run: `just check-formal`

Run: `cargo fmt --all -- --check`

Run: `git diff --check`

Expected: all PASS.

- [ ] **Step 6: Commit CI enforcement**

```text
ci(formal): gate P1 proofs on Linux and Windows

Co-Authored-By: OpenAI GPT-5 <codex@openai.com>
```

### Task 5: Run the repository gate and open the stacked PR

**Files:**
- Verify only; no planned source changes.

**Interfaces:**
- Consumes: all P1 commits.
- Produces: a reviewable PR based on `feat/formal-ceremony-kernel`.

- [ ] **Step 1: Scan for proof escapes**

Run: `rg -n '\b(sorry|admit|axiom)\b' formal`

Expected: no matches. Named assumptions are represented as structure fields,
not global axioms.

- [ ] **Step 2: Run the full native-Windows gate**

Run: `just check-formal`

Run: `just check`

Run: `just check-windows`

Run: `just publish-check`

Expected: all PASS. Any environment-dependent kernel proof skip or failure is
reported verbatim in the PR body rather than generalized away.

- [ ] **Step 3: Verify branch shape and attribution**

Run: `git log --format=full origin/feat/formal-ceremony-kernel..HEAD`

Expected: every commit is authored by Shawn Hartsock and contains the OpenAI
GPT-5 co-author trailer.

- [ ] **Step 4: Push normally and open the PR**

Push without bypassing hooks. Open a draft PR titled
`formal: prove P1 signed-object contracts` with `What this PR does`, `Test
plan`, and `Out of scope` sections. Base it on
`feat/formal-ceremony-kernel`; identify the model and Codex desktop harness in
the body.
