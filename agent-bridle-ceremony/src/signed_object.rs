//! The P1 signed-object **kernel** — a Rust mirror of
//! `formal/Ceremony/P1/SignedObject.lean` and the normative
//! `docs/spec/signed-object-profile.md`.
//!
//! P1 is the alphabet the other five profiles write in: it makes objects
//! *nameable, canonical, and verifiable*. It carries **no authority semantics**
//! (that is P0's `Authority` lattice) — only the profile allowlist, the OB-13
//! protected-tuple / signature-preimage logic, and the verify order.
//!
//! What is **built** here (the LOGIC):
//! - the closed algorithm/codec allowlist (`Profile`, `Profile::v1`, the
//!   `allows_*` predicates, `TrustedProfile`) and the "admit only what is on the
//!   list" witnesses (`AllowedHash`/`AllowedSignature`/`AllowedCodec`);
//! - the 10-field [`SignaturePreimage`] (OB-13 protected tuple) and its
//!   [`SignedEnvelopeCodec::signature_preimage`] constructor, which *binds* every
//!   interpretation-bearing field into the signed bytes;
//! - the 6-step [`verify_envelope`] → [`parse_verified`] → [`Sealed`] order, and
//!   the [`STORE_ID_SELF`] genesis resolution (OB-14).
//!
//! What is **HELD** (roadmap Phase 1d — `docs/spec/ROADMAP.md` "decided vs.
//! held"): the actual crypto (BLAKE3-256, Ed25519) and the DAG-CBOR wire bytes.
//! Those are modelled as **abstract trait boundaries** — [`CanonicalEncoding`],
//! [`CanonicalPayloadDecoder`], [`SignedEnvelopeCodec`], [`CryptoBoundary`] — so
//! this module freezes *no* byte layout, serialized record, or stored signature.
//! The kernel (P0) consumes `H` and `Sign` as abstract injective / one-way
//! contracts (spec §7); this module's job is to satisfy them.
//!
//! The 5 verification laws (spec §4), each mapped to code below:
//! 1. **Verify over received canonical bytes, never a re-serialization** — the
//!    codec's [`SignedEnvelopeCodec::decode`] `decode_exact` contract; the
//!    signature is checked over a preimage *derived from the received-decoded
//!    envelope*, never a re-encode (`verify_envelope` STEP 1/2).
//! 2. **Unknown authority-bearing fields fail closed** — `verify_envelope`
//!    STEP 5 rejects a non-empty `unknown_critical`.
//! 3. **Version dispatch, not lenient parsing** — STEP 1 dispatches on the
//!    declared `profile_version` against the trusted profile.
//! 4. **Algorithm allowlist before dispatch (PO-8)** — STEP 1 admits
//!    hash/signature/codec against the *locally-trusted* profile **before** any
//!    hashing or signature check; nothing off the list is honoured.
//! 5. **Universal domain separation + context binding (OB-6)** — the preimage
//!    binds [`SignatureDomain`] (`record_type`, `store_id`, `thread_or_principal`)
//!    under the [`SIGNED_OBJECT_DOMAIN`] label, so a signature is valid only for
//!    its exact context and cannot be replayed across stores, principals, causal
//!    threads, record types, or profile versions.
//!
//! As with `authority.rs`/`boundary.rs`, every function here is total and
//! panic-free, and the `#[cfg(test)]` block discharges the laws by **exhaustive
//! enumeration** over the finite allowlist domain (the Rust analogue of the Lean
//! proofs' `by cases <;> decide`), plus adversarial property tests for the
//! open-ended byte/preimage domain that Lean states as `DecidableEq`.

// The hash-algorithm variant names mirror the Lean `blake3_256` / `sha1`
// (formal/Ceremony/P1/SignedObject.lean). The digit-underscore-digit form trips
// `non_camel_case_types`, but fidelity to the frozen contract's spelling wins.
#![allow(non_camel_case_types)]

// ---------------------------------------------------------------------------
// Algorithm / codec enums (Lean: `HashAlgorithm`, `SignatureAlgorithm`, `Codec`)
// ---------------------------------------------------------------------------

/// Content-hash algorithm (Lean `HashAlgorithm`). Self-describing on the wire
/// via multihash (spec §1); comparison is over the opaque bytes *including* the
/// algorithm code, so two algorithms never collide silently.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HashAlgorithm {
    /// BLAKE3-256 (multihash `0x1e`) — the v1 pin (spec §6). BLAKE3 is an
    /// implementation detail, not a law; the *property* is collision resistance +
    /// preimage hardness (L5 self-certification).
    Blake3_256,
    /// SHA-1 — present in the type so the allowlist can *reject* it (the
    /// `alg:none` / algorithm-confusion surface, PO-8); never trusted by v1.
    Sha1,
}

impl HashAlgorithm {
    /// Every value — the finite domain the allowlist laws `decide` over.
    pub const ALL: [HashAlgorithm; 2] = [HashAlgorithm::Blake3_256, HashAlgorithm::Sha1];
}

/// Signature algorithm (Lean `SignatureAlgorithm`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SignatureAlgorithm {
    /// Ed25519 (RFC 8032) — the v1 pin. **Deterministic**: `Sign(sk, m)` yields
    /// one canonical signature for a fixed key and message (spec §5), so a
    /// re-sign does not fork a chain built over it (P2).
    Ed25519,
    /// ECDSA — present so the allowlist can reject it; a randomised nonce makes
    /// it non-deterministic (see [`SignatureAlgorithm::is_deterministic`]).
    Ecdsa,
}

impl SignatureAlgorithm {
    pub const ALL: [SignatureAlgorithm; 2] =
        [SignatureAlgorithm::Ed25519, SignatureAlgorithm::Ecdsa];

    /// Lean `SignatureAlgorithm.isDeterministic` — `ed25519 => True`,
    /// `ecdsa => False`. Determinism governs **reproducibility** (spec §5); it is
    /// independent of the collision resistance that governs tamper-evidence.
    pub const fn is_deterministic(self) -> bool {
        match self {
            SignatureAlgorithm::Ed25519 => true,
            SignatureAlgorithm::Ecdsa => false,
        }
    }
}

/// Canonical serialization codec (Lean `Codec`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Codec {
    /// DAG-CBOR (codec `0x71`) — the v1 pin; the *property* is an injective
    /// canonical serialization (one value ⇒ one byte string), spec §6.
    DagCbor,
    /// JSON — a human/interchange *view*, never an independent authority-bearing
    /// serialization (spec §2); rejected by the v1 allowlist.
    Json,
}

impl Codec {
    pub const ALL: [Codec; 2] = [Codec::DagCbor, Codec::Json];
}

// ---------------------------------------------------------------------------
// Profile + the closed allowlist (Lean: `Profile`, `Profile.v1`, `allows*`)
// ---------------------------------------------------------------------------

/// A verifier's declared algorithm agility surface (Lean `Profile`). Agility
/// lives *here*, in the profile, never on the wire (spec §4·4): the object may
/// *declare* an algorithm, but only the profile decides whether it is honoured.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Profile {
    pub version: u64,
    pub hashes: Vec<HashAlgorithm>,
    pub signatures: Vec<SignatureAlgorithm>,
    pub codecs: Vec<Codec>,
}

impl Profile {
    /// Lean `Profile.v1` — `{ version := 1, hashes := [blake3_256],
    /// signatures := [ed25519], codecs := [dagCbor] }`. The single trusted
    /// profile (see [`TrustedProfile`]).
    pub fn v1() -> Self {
        Profile {
            version: 1,
            hashes: vec![HashAlgorithm::Blake3_256],
            signatures: vec![SignatureAlgorithm::Ed25519],
            codecs: vec![Codec::DagCbor],
        }
    }

    /// Lean `Profile.allowsHash` — membership in the closed hash allowlist.
    pub fn allows_hash(&self, algorithm: HashAlgorithm) -> bool {
        self.hashes.contains(&algorithm)
    }

    /// Lean `Profile.allowsSignature`.
    pub fn allows_signature(&self, algorithm: SignatureAlgorithm) -> bool {
        self.signatures.contains(&algorithm)
    }

    /// Lean `Profile.allowsCodec`.
    pub fn allows_codec(&self, codec: Codec) -> bool {
        self.codecs.contains(&codec)
    }
}

/// The trusted-profile allowlist (Lean `TrustedProfile`, an inductive with the
/// single constructor `v1`). Only [`Profile::v1`] is trusted — this is the
/// "profile is a **closed allowlist**" law. The invariant is enforced by
/// construction: the only way to obtain a `TrustedProfile` is [`TrustedProfile::v1`]
/// or an [`TrustedProfile::admit`] that succeeds *only* for v1, so
/// `trusted.profile() == Profile::v1()` always holds (Lean `trusted_profile_is_v1`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustedProfile {
    profile: Profile,
}

impl TrustedProfile {
    /// The one trusted profile (Lean `TrustedProfile.v1`).
    pub fn v1() -> Self {
        TrustedProfile {
            profile: Profile::v1(),
        }
    }

    /// Admit an on-the-wire / configured profile only if it is trusted. Fails
    /// closed (returns `None`) for every non-v1 profile — the closed-allowlist
    /// law. Mirrors that `TrustedProfile` has no constructor but `v1`.
    pub fn admit(profile: Profile) -> Option<Self> {
        if profile == Profile::v1() {
            Some(TrustedProfile { profile })
        } else {
            None
        }
    }

    /// The trusted profile (always equal to [`Profile::v1`], Lean
    /// `trusted_profile_is_v1`).
    pub fn profile(&self) -> &Profile {
        &self.profile
    }
}

// ---------------------------------------------------------------------------
// Allowlist witnesses (Lean: `AllowedHash`/`AllowedSignature`/`AllowedCodec`)
// ---------------------------------------------------------------------------
//
// In Lean these carry a *proof* `allowed : profile.allowsX algorithm`. The Rust
// analogue makes illegal states unrepresentable: the field is private and the
// only constructor is `admit`, which checks the allowlist and fails closed. A
// value of this type therefore *witnesses* that its algorithm is on the list —
// the crypto boundary can only ever be handed an admitted algorithm (PO-8).

/// Lean `AllowedHash profile` — a hash algorithm proven on `profile`'s allowlist.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AllowedHash {
    algorithm: HashAlgorithm,
}

impl AllowedHash {
    /// Admit `algorithm` iff `profile` allows it; else fail closed.
    pub fn admit(profile: &Profile, algorithm: HashAlgorithm) -> Option<Self> {
        if profile.allows_hash(algorithm) {
            Some(AllowedHash { algorithm })
        } else {
            None
        }
    }

    pub fn algorithm(&self) -> HashAlgorithm {
        self.algorithm
    }
}

/// Lean `AllowedSignature profile`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AllowedSignature {
    algorithm: SignatureAlgorithm,
}

impl AllowedSignature {
    pub fn admit(profile: &Profile, algorithm: SignatureAlgorithm) -> Option<Self> {
        if profile.allows_signature(algorithm) {
            Some(AllowedSignature { algorithm })
        } else {
            None
        }
    }

    pub fn algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }
}

/// Lean `AllowedCodec profile`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AllowedCodec {
    codec: Codec,
}

impl AllowedCodec {
    pub fn admit(profile: &Profile, codec: Codec) -> Option<Self> {
        if profile.allows_codec(codec) {
            Some(AllowedCodec { codec })
        } else {
            None
        }
    }

    pub fn codec(&self) -> Codec {
        self.codec
    }
}

// ---------------------------------------------------------------------------
// Domain separation + the OB-13 signature preimage (Lean: `SignatureDomain`,
// `SignaturePreimage`)
// ---------------------------------------------------------------------------

/// The universal domain-separation label (spec §2, OB-6): the constant string
/// prefixing every signed-object preimage, keeping this signature context
/// disjoint from every *other* signing context (e.g. a WebAuthn challenge). The
/// abstract preimage encoding a [`CryptoBoundary`] signs begins with this label.
pub const SIGNED_OBJECT_DOMAIN: &str = "agent-bridle/signed-object/v1";

/// The reserved genesis sentinel (spec §2, OB-14): the byte `0x00`. A genesis
/// body binds `store_id = STORE_ID_SELF`; the resulting `cid` *becomes* the
/// store's `store_id`. A verifier resolves this sentinel to "this record's own
/// cid" (see [`resolve_store_id`] / [`VerifiedEnvelope::effective_store_id`]).
pub const STORE_ID_SELF: &[u8] = &[0x00];

/// Resolve a declared `store_id` against a record's own `cid` (OB-14). The
/// genesis sentinel [`STORE_ID_SELF`] resolves to `own_cid` (breaking the
/// `store_id = H(genesis)` circularity); any other value passes through
/// unchanged. This is the *only* place the sentinel is special.
pub fn resolve_store_id(declared_store_id: &[u8], own_cid: &[u8]) -> Vec<u8> {
    if declared_store_id == STORE_ID_SELF {
        own_cid.to_vec()
    } else {
        declared_store_id.to_vec()
    }
}

/// The OB-6 context-binding tuple that opens every signed `body` (Lean
/// `SignatureDomain`). A signature is valid **only** for its exact
/// `(record_type, store_id, thread_or_principal)` context; without this, a
/// validly-signed payload could be replayed across stores, principals, and
/// causal threads. `store_id` is a cryptographically-bound identifier (P2), not
/// prose — "same store" is a value the signature covers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignatureDomain {
    pub record_type: String,
    pub store_id: Vec<u8>,
    pub thread_or_principal: Vec<u8>,
}

/// The body's *self-declared* identity tuple, cross-checked in verify STEP 4
/// against the envelope-level `(profile_version, codec, signer)`. The spec's
/// "no split identity across the boundary" (§2): a body whose embedded tuple
/// disagrees with the envelope it rides in is rejected, even if the signature is
/// otherwise valid.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DomainBinding {
    pub profile_version: u64,
    pub codec: Codec,
    pub signer: Vec<u8>,
}

/// The **protected tuple** the signature covers (Lean `SignaturePreimage`,
/// `deriving DecidableEq`) — the heart of OB-13. A naive envelope that signs
/// only `cid = H(body)` leaves the interpretation-bearing fields (`profile`,
/// `codec`, `signer`) *outside* the signature, so an attacker could re-tag them
/// without breaking the sig. This preimage binds **all ten** fields into the
/// signed bytes; changing any one changes the preimage (proven by the derived
/// `Eq` — the Rust analogue of `DecidableEq`), so any re-tag is detectable.
///
/// The spec's illustrative 5-tuple `protected = canon(<label>, profile, codec,
/// cid, signer)` is a *subset* of these fields; the Lean contract froze the
/// fuller binding (adding `canonical_unsigned`, `hash_algorithm`,
/// `signature_algorithm`, `domain`, `body`, `unknown_critical`) so nothing
/// interpretation-bearing sits outside the signature. Byte layout stays HELD —
/// this is the field set, not an encoding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignaturePreimage {
    /// (1) the whole unsigned envelope, canonically encoded (Lean
    /// `canonicalUnsigned = encodeUnsigned unsigned`).
    pub canonical_unsigned: Vec<u8>,
    /// (2) the declared profile version (Lean `profileVersion`).
    pub profile_version: u64,
    /// (3) the declared content-hash algorithm.
    pub hash_algorithm: HashAlgorithm,
    /// (4) the declared signature algorithm.
    pub signature_algorithm: SignatureAlgorithm,
    /// (5) the declared codec.
    pub codec: Codec,
    /// (6) the OB-6 domain-separation tuple.
    pub domain: SignatureDomain,
    /// (7) the canonical body bytes (`cid = H(body)`).
    pub body: Vec<u8>,
    /// (8) the claimed content id.
    pub claimed_cid: Vec<u8>,
    /// (9) the signer key id (the one canonical location; spec §2).
    pub signer: Vec<u8>,
    /// (10) the declared unknown-critical field names (bound so a downgrade is
    /// tamper-evident, not merely rejected).
    pub unknown_critical: Vec<String>,
}

// ---------------------------------------------------------------------------
// Abstract encoding / crypto boundaries (Lean: `CanonicalEncoding`,
// `CanonicalPayloadDecoder`, `SignedEnvelopeCodec`, `CryptoBoundary`)
//
// These are the HELD surfaces. This module implements NONE of DAG-CBOR / BLAKE3
// / Ed25519; it names the injective/one-way *contracts* the LOGIC relies on and
// leaves the bytes for the Phase-1d conformance vectors.
// ---------------------------------------------------------------------------

/// Lean `CanonicalEncoding Value` — an injective canonical encoder for a payload
/// type. **Contract (HELD, Tier-1/-3):** `encode` is injective (one value ⇒ one
/// byte string); this module assumes it, the DAG-CBOR profile satisfies it
/// (spec §6, PO-1c).
pub trait CanonicalEncoding {
    type Value;

    /// Canonically encode a value (Lean `encode : Value -> ByteArray`).
    fn encode(&self, value: &Self::Value) -> Vec<u8>;
}

/// Lean `CanonicalPayloadDecoder Value encoding` — a strict parser paired with
/// its encoding. **Contract (`parse_exact`):** `parse(bytes) == Some(v)` implies
/// `bytes == encode(v)`. [`parse_verified`] re-checks this at runtime (re-encode
/// and byte-compare) rather than *trusting* the contract, so a lenient parser
/// cannot smuggle a non-canonical body past the seal.
pub trait CanonicalPayloadDecoder: CanonicalEncoding {
    /// Parse canonical bytes into a value, or `None` (Lean
    /// `parse : ByteArray -> Option Value`).
    fn parse(&self, bytes: &[u8]) -> Option<Self::Value>;
}

/// Lean `SignedEnvelopeCodec` — the wire boundary for a signed envelope and its
/// unsigned view. Every accessor reads a field of the *unsigned* view; the
/// [`SignedEnvelopeCodec::signature_preimage`] default method assembles the
/// OB-13 protected tuple from them (Lean `SignedEnvelopeCodec.signaturePreimage`).
///
/// **Contracts (HELD):** `encode` and `encode_unsigned` are injective, and
/// `decode` satisfies `decode_exact`: `decode(received) == Some(env)` implies
/// `encode(env) == received`. That contract is exactly the "verify over received
/// bytes, never a re-serialization" law (spec §4·1) — the preimage is derived
/// from `encode_unsigned(unsigned(env))` of the *received-decoded* envelope, so
/// the signature is checked over the received bytes, not a reconstruction.
pub trait SignedEnvelopeCodec {
    /// The signed envelope (Lean `Envelope`).
    type Envelope;
    /// The unsigned view carrying the interpretation-bearing fields (Lean
    /// `Unsigned`).
    type Unsigned;

    /// Decode received bytes into an envelope, or `None` (Lean `decode`). Must
    /// satisfy `decode_exact` (see the trait docs).
    fn decode(&self, received: &[u8]) -> Option<Self::Envelope>;
    /// Injectively encode an envelope (Lean `encode`).
    fn encode(&self, envelope: &Self::Envelope) -> Vec<u8>;
    /// Project the unsigned view (Lean `unsigned`).
    fn unsigned(&self, envelope: &Self::Envelope) -> Self::Unsigned;
    /// Injectively encode the unsigned view — field (1) of the preimage (Lean
    /// `encodeUnsigned`).
    fn encode_unsigned(&self, unsigned: &Self::Unsigned) -> Vec<u8>;

    /// Declared profile version (Lean `version`).
    fn profile_version(&self, unsigned: &Self::Unsigned) -> u64;
    /// Declared content-hash algorithm (Lean `hash`).
    fn hash_algorithm(&self, unsigned: &Self::Unsigned) -> HashAlgorithm;
    /// Declared signature algorithm (Lean `signatureAlgorithm`).
    fn signature_algorithm(&self, unsigned: &Self::Unsigned) -> SignatureAlgorithm;
    /// Declared codec (Lean `codec`).
    fn codec(&self, unsigned: &Self::Unsigned) -> Codec;
    /// OB-6 domain tuple (Lean `domain`).
    fn domain(&self, unsigned: &Self::Unsigned) -> SignatureDomain;
    /// Canonical body bytes (Lean `body`).
    fn body(&self, unsigned: &Self::Unsigned) -> Vec<u8>;
    /// Claimed content id (Lean `claimedCid`).
    fn claimed_cid(&self, unsigned: &Self::Unsigned) -> Vec<u8>;
    /// Signer key id (Lean `signer`).
    fn signer(&self, unsigned: &Self::Unsigned) -> Vec<u8>;
    /// Unknown-critical field names (Lean `unknownCritical`).
    fn unknown_critical(&self, unsigned: &Self::Unsigned) -> Vec<String>;

    /// The body's self-declared identity tuple, cross-checked in verify STEP 4.
    /// (Not a distinct Lean field — the Lean binds identity via the preimage;
    /// this surfaces the spec's explicit "body tuple == envelope tuple" check so
    /// an internally-inconsistent-but-validly-signed object is still rejected.)
    fn body_binding(&self, unsigned: &Self::Unsigned) -> DomainBinding;

    /// The signature bytes carried by the envelope (Lean `signatureBytes`).
    fn signature_bytes(&self, envelope: &Self::Envelope) -> Vec<u8>;

    /// Assemble the OB-13 [`SignaturePreimage`] from an unsigned view (Lean
    /// `SignedEnvelopeCodec.signaturePreimage`). This is the one normative
    /// constructor: it binds **all ten** interpretation-bearing fields into the
    /// bytes the signature will cover. Provided (not overridable in spirit) so
    /// every codec assembles the protected tuple identically.
    fn signature_preimage(&self, unsigned: &Self::Unsigned) -> SignaturePreimage {
        SignaturePreimage {
            canonical_unsigned: self.encode_unsigned(unsigned),
            profile_version: self.profile_version(unsigned),
            hash_algorithm: self.hash_algorithm(unsigned),
            signature_algorithm: self.signature_algorithm(unsigned),
            codec: self.codec(unsigned),
            domain: self.domain(unsigned),
            body: self.body(unsigned),
            claimed_cid: self.claimed_cid(unsigned),
            signer: self.signer(unsigned),
            unknown_critical: self.unknown_critical(unsigned),
        }
    }
}

/// Lean `CryptoBoundary profile` — the abstract hash + signature oracle. Note it
/// is only ever handed **admitted** algorithms ([`AllowedHash`]/
/// [`AllowedSignature`]), so the Lean profile-parameterization is captured by the
/// witness types (PO-8 is discharged *before* any method here is called).
///
/// This is the **operational** interface only: `digest`, a signature relation, a
/// `Bool` verifier, and its soundness (`signature_sound`). It is deliberately
/// inhabitable by *real* crypto.
///
/// **Security contracts (HELD, Tier-1 assumed crypto) — not baked into this
/// interface (epic #263, F-233-01/04):**
/// - **Digest collision-resistance** is a *computational* assumption (spec §1), not
///   a total-function property. The Lean model no longer postulates the impossible
///   global digest-injectivity that only a fake identity hash could satisfy; a real
///   BLAKE3-256 boundary now inhabits it.
/// - **Signature binding + determinism** (existential unforgeability; Ed25519's
///   one-`(key, message)`-one-signature, spec §5) are stated on the *bytes* a
///   scheme signs — `encodeSignaturePreimage` — as the Tier-1 `ByteSigner`
///   assumptions, from which the Lean model *derives* the structural guarantees
///   (`PreimageCodec.structural_binding_from_bytes` /
///   `structural_determinism_from_bytes`, composed with the proved encoding
///   injectivity). This module *assumes* these; it does not implement BLAKE3 or
///   Ed25519 (HELD).
pub trait CryptoBoundary {
    /// Content hash of `bytes` under an admitted algorithm (Lean `digest`).
    fn digest(&self, algorithm: &AllowedHash, bytes: &[u8]) -> Vec<u8>;

    /// Whether `signature` verifies over `preimage` under an admitted algorithm
    /// (Lean `signatureMatches`). By `signature_sound`, `true` witnesses `SignedBy`.
    fn signature_matches(
        &self,
        algorithm: &AllowedSignature,
        preimage: &SignaturePreimage,
        signature: &[u8],
    ) -> bool;
}

// ---------------------------------------------------------------------------
// Verify order + sealed witnesses (Lean: `VerifiedEnvelope`, `verifyEnvelope`,
// `Sealed`, `parseVerified`, `loadEnvelope`)
// ---------------------------------------------------------------------------

/// Why a verify failed. **Every** variant is a *closed* failure (the analogue of
/// Lean `verifyEnvelope` returning `none`); the variant only names *which* of
/// the ordered steps rejected, so tests can pin the fail-closed point. The order
/// of the fields below mirrors the 6-step verify order (spec §2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifyRejection {
    /// STEP 1 (law §4·1): received bytes did not decode to an envelope.
    Undecodable,
    /// STEP 1 (law §4·3): declared version ≠ the trusted profile's version.
    VersionMismatch,
    /// STEP 1 (law §4·4 / PO-8): hash algorithm off the trusted allowlist.
    HashNotAllowed,
    /// STEP 1 (law §4·4 / PO-8): signature algorithm off the trusted allowlist.
    SignatureAlgNotAllowed,
    /// STEP 1 (law §4·4 / PO-8): codec off the trusted allowlist.
    CodecNotAllowed,
    /// STEP 2 (OB-13): signature does not verify over the protected preimage.
    SignatureInvalid,
    /// STEP 3: `claimed_cid ≠ H(body)`.
    CidMismatch,
    /// STEP 4 (spec §2 "no split identity"): body tuple ≠ envelope
    /// `(profile_version, codec, signer)`.
    BodyDomainMismatch,
    /// STEP 5 (law §4·2): a non-empty unknown-critical set — fail closed.
    UnknownCriticalField,
    /// STEP 6 (canonical form): the body did not parse, or `encode(parse(body))
    /// ≠ body` (a non-canonical / lenient-parsed payload).
    NonCanonicalBody,
    /// STEP 1 (law §4·1, defense-in-depth): `encode(decode(received)) ≠ received`
    /// — the received bytes are not the canonical encoding of the envelope. Lean
    /// carries `decode_exact` as a supplied proof (`SignedObject.lean`); a Rust
    /// trait cannot, so we re-check it at the boundary, closing the RFC-8785
    /// pitfall where a lenient `decode` (drops trailing bytes, normalizes a
    /// field) would let non-canonical bytes verify.
    NonCanonicalEnvelope,
}

/// A verified envelope (Lean `VerifiedEnvelope`) — the witness that all of the
/// verify steps passed. **Sealed at load** (spec §3): the constructor is private,
/// so the only way to obtain one is a successful [`verify_envelope`]. Nothing
/// enters a kernel unverified.
#[derive(Clone, Debug)]
pub struct VerifiedEnvelope<E> {
    envelope: E,
    profile: Profile,
    allowed_hash: AllowedHash,
    allowed_signature: AllowedSignature,
    allowed_codec: AllowedCodec,
    /// The protected tuple that verified — retained for body access and OB-14
    /// store-id resolution.
    preimage: SignaturePreimage,
}

impl<E> VerifiedEnvelope<E> {
    /// The received-decoded envelope (Lean `envelope`).
    pub fn envelope(&self) -> &E {
        &self.envelope
    }

    /// The trusted profile it verified under (always [`Profile::v1`]).
    pub fn profile(&self) -> &Profile {
        &self.profile
    }

    /// The admitted hash algorithm witness.
    pub fn allowed_hash(&self) -> &AllowedHash {
        &self.allowed_hash
    }

    /// The admitted signature algorithm witness.
    pub fn allowed_signature(&self) -> &AllowedSignature {
        &self.allowed_signature
    }

    /// The admitted codec witness.
    pub fn allowed_codec(&self) -> &AllowedCodec {
        &self.allowed_codec
    }

    /// The verified protected tuple.
    pub fn preimage(&self) -> &SignaturePreimage {
        &self.preimage
    }

    /// The verified content id (`= H(body)`, checked in STEP 3).
    pub fn cid(&self) -> &[u8] {
        &self.preimage.claimed_cid
    }

    /// The effective store id (OB-14): resolves the genesis sentinel
    /// [`STORE_ID_SELF`] to this record's own `cid`, else passes the declared
    /// `store_id` through. Since `cid` verified as `H(body)`, a genesis record's
    /// resolved store id *is* its own content id.
    pub fn effective_store_id(&self) -> Vec<u8> {
        resolve_store_id(&self.preimage.domain.store_id, &self.preimage.claimed_cid)
    }
}

/// A verified *and* parsed payload (Lean `Sealed`) — the STEP-6 product. Private
/// constructor: the only way here is [`parse_verified`]/[`load_envelope`], so a
/// `Sealed<V, E>` witnesses that its `value` re-encodes to the signed body
/// (`canonical_eq`). `Sealed<T>` is the Rust heir of the content-addressable
/// `Memo` read-time tamper check (spec §3).
#[derive(Clone, Debug)]
pub struct Sealed<V, E> {
    verified: VerifiedEnvelope<E>,
    value: V,
}

impl<V, E> Sealed<V, E> {
    /// The verified envelope carrying this value.
    pub fn verified(&self) -> &VerifiedEnvelope<E> {
        &self.verified
    }

    /// The sealed payload value.
    pub fn value(&self) -> &V {
        &self.value
    }

    /// Consume the seal, yielding the payload value.
    pub fn into_value(self) -> V {
        self.value
    }
}

/// Verify received bytes into a [`VerifiedEnvelope`] in the normative 6-step
/// order (spec §2), failing closed at the first failing step. This is the Rust
/// mirror of Lean `verifyEnvelope` (which threads the same checks as dependent
/// `if`s; here they are early returns carrying a [`VerifyRejection`] naming the
/// step). PO-8 is honoured: the allowlist gates in STEP 1 run **before** any
/// hashing (STEP 3) or signature check (STEP 2).
///
/// Two orderings here differ from Lean `verifyEnvelope`, both sound because the
/// accept set is the *conjunction* of all steps — order changes only which
/// [`VerifyRejection`] surfaces first, never accept/reject. (1) Lean checks
/// `unknown_critical` before the allowlist; the spec's §2 places it at STEP 5,
/// which we follow. (2) Lean checks `cid` (its digest step) before the
/// signature; we check the signature (STEP 2) before `cid` (STEP 3), matching
/// spec §2's numbering. PO-8 (allowlist before *any* crypto) holds regardless.
pub fn verify_envelope<C, K>(
    trusted: &TrustedProfile,
    envelope_codec: &C,
    crypto: &K,
    received: &[u8],
) -> Result<VerifiedEnvelope<C::Envelope>, VerifyRejection>
where
    C: SignedEnvelopeCodec,
    K: CryptoBoundary,
{
    let profile = trusted.profile();

    // STEP 1 — verify over received bytes (law §4·1): decode ONCE; every field
    // below is read from this received-decoded view, never a re-serialization.
    let envelope = envelope_codec
        .decode(received)
        .ok_or(VerifyRejection::Undecodable)?;
    // STEP 1 (law §4·1, defense-in-depth): the received bytes MUST be the
    // canonical encoding of what we decoded — the Rust-boundary analogue of
    // Lean's carried `decode_exact` proof (a trait cannot carry it). Without
    // this, a lenient concrete `decode` would let non-canonical bytes verify.
    if envelope_codec.encode(&envelope) != received {
        return Err(VerifyRejection::NonCanonicalEnvelope);
    }
    let unsigned = envelope_codec.unsigned(&envelope);

    // STEP 1 — version dispatch (law §4·3) then the algorithm/codec allowlist
    // (law §4·4 / PO-8) — all BEFORE touching the body or the crypto oracle.
    if envelope_codec.profile_version(&unsigned) != profile.version {
        return Err(VerifyRejection::VersionMismatch);
    }
    let allowed_hash = AllowedHash::admit(profile, envelope_codec.hash_algorithm(&unsigned))
        .ok_or(VerifyRejection::HashNotAllowed)?;
    let allowed_signature =
        AllowedSignature::admit(profile, envelope_codec.signature_algorithm(&unsigned))
            .ok_or(VerifyRejection::SignatureAlgNotAllowed)?;
    let allowed_codec = AllowedCodec::admit(profile, envelope_codec.codec(&unsigned))
        .ok_or(VerifyRejection::CodecNotAllowed)?;

    // STEP 2 — recompute the protected tuple; verify the signature under signer.
    let preimage = envelope_codec.signature_preimage(&unsigned);
    let signature = envelope_codec.signature_bytes(&envelope);
    if !crypto.signature_matches(&allowed_signature, &preimage, &signature) {
        return Err(VerifyRejection::SignatureInvalid);
    }

    // STEP 3 — cid == H(body).
    let recomputed_cid = crypto.digest(&allowed_hash, &envelope_codec.body(&unsigned));
    if envelope_codec.claimed_cid(&unsigned) != recomputed_cid {
        return Err(VerifyRejection::CidMismatch);
    }

    // STEP 4 — body domain tuple == envelope (profile_version, codec, signer).
    let expected_binding = DomainBinding {
        profile_version: envelope_codec.profile_version(&unsigned),
        codec: envelope_codec.codec(&unsigned),
        signer: envelope_codec.signer(&unsigned),
    };
    if envelope_codec.body_binding(&unsigned) != expected_binding {
        return Err(VerifyRejection::BodyDomainMismatch);
    }

    // STEP 5 — schema + reject unknown authority-bearing / critical fields.
    if !envelope_codec.unknown_critical(&unsigned).is_empty() {
        return Err(VerifyRejection::UnknownCriticalField);
    }

    // STEP 6 (construction) — mint the sealed-at-load witness.
    Ok(VerifiedEnvelope {
        envelope,
        profile: profile.clone(),
        allowed_hash,
        allowed_signature,
        allowed_codec,
        preimage,
    })
}

/// STEP 6 — parse the verified body into a [`Sealed`] payload (Lean
/// `parseVerified`). Beyond `decoder.parse`, this **re-checks** the canonical
/// form (`encode(value) == body`) rather than trusting the `parse_exact`
/// contract — a lenient parser that dropped or normalised bytes fails closed
/// with [`VerifyRejection::NonCanonicalBody`].
pub fn parse_verified<D, E>(
    decoder: &D,
    verified: VerifiedEnvelope<E>,
) -> Result<Sealed<D::Value, E>, VerifyRejection>
where
    D: CanonicalPayloadDecoder,
{
    let body = verified.preimage.body.clone();
    let value = decoder
        .parse(&body)
        .ok_or(VerifyRejection::NonCanonicalBody)?;
    if decoder.encode(&value) != body {
        return Err(VerifyRejection::NonCanonicalBody);
    }
    Ok(Sealed { verified, value })
}

/// Verify then parse — the full load path (Lean `loadEnvelope`). Returns a
/// [`Sealed`] payload on success, or fails closed with the first rejection.
pub fn load_envelope<C, K, D>(
    trusted: &TrustedProfile,
    envelope_codec: &C,
    crypto: &K,
    decoder: &D,
    received: &[u8],
) -> Result<Sealed<D::Value, C::Envelope>, VerifyRejection>
where
    C: SignedEnvelopeCodec,
    K: CryptoBoundary,
    D: CanonicalPayloadDecoder,
{
    let verified = verify_envelope(trusted, envelope_codec, crypto, received)?;
    parse_verified(decoder, verified)
}

// ===========================================================================
// Tests — the laws by exhaustive enumeration over the finite allowlist domain,
// plus adversarial property tests over the open byte/preimage domain. TEST-ONLY
// stand-ins carry ONLY the binding properties the LOGIC needs; the real BLAKE3 /
// Ed25519 / DAG-CBOR are HELD, exactly as authority.rs exercises the abstract
// lattice laws without a concrete carrier.
// ===========================================================================
#[cfg(test)]
mod tests {
    use super::*;

    // ---- byte-level (de)serialization helpers for the TEST codec (panic-free) --

    fn put_bytes(out: &mut Vec<u8>, b: &[u8]) {
        out.extend_from_slice(&(b.len() as u64).to_le_bytes());
        out.extend_from_slice(b);
    }
    fn take_bytes(input: &[u8], pos: &mut usize) -> Option<Vec<u8>> {
        let len_end = pos.checked_add(8)?;
        let len_slice = input.get(*pos..len_end)?;
        let arr: [u8; 8] = len_slice.try_into().ok()?;
        let len = usize::try_from(u64::from_le_bytes(arr)).ok()?;
        let data_end = len_end.checked_add(len)?;
        let data = input.get(len_end..data_end)?;
        *pos = data_end;
        Some(data.to_vec())
    }
    fn put_u64(out: &mut Vec<u8>, v: u64) {
        out.extend_from_slice(&v.to_le_bytes());
    }
    fn take_u64(input: &[u8], pos: &mut usize) -> Option<u64> {
        let end = pos.checked_add(8)?;
        let arr: [u8; 8] = input.get(*pos..end)?.try_into().ok()?;
        *pos = end;
        Some(u64::from_le_bytes(arr))
    }
    fn take_u8(input: &[u8], pos: &mut usize) -> Option<u8> {
        let b = *input.get(*pos)?;
        *pos = pos.checked_add(1)?;
        Some(b)
    }
    fn put_str(out: &mut Vec<u8>, s: &str) {
        put_bytes(out, s.as_bytes());
    }
    fn take_str(input: &[u8], pos: &mut usize) -> Option<String> {
        String::from_utf8(take_bytes(input, pos)?).ok()
    }

    // TEST-ONLY multicodec-ish tags (distinct bytes; not the real registry).
    fn hash_tag(h: HashAlgorithm) -> u8 {
        match h {
            HashAlgorithm::Blake3_256 => 0x1e,
            HashAlgorithm::Sha1 => 0x11,
        }
    }
    fn hash_from_tag(t: u8) -> Option<HashAlgorithm> {
        match t {
            0x1e => Some(HashAlgorithm::Blake3_256),
            0x11 => Some(HashAlgorithm::Sha1),
            _ => None,
        }
    }
    fn sig_tag(s: SignatureAlgorithm) -> u8 {
        match s {
            SignatureAlgorithm::Ed25519 => 0xed,
            SignatureAlgorithm::Ecdsa => 0xec,
        }
    }
    fn sig_from_tag(t: u8) -> Option<SignatureAlgorithm> {
        match t {
            0xed => Some(SignatureAlgorithm::Ed25519),
            0xec => Some(SignatureAlgorithm::Ecdsa),
            _ => None,
        }
    }
    fn codec_tag(c: Codec) -> u8 {
        match c {
            Codec::DagCbor => 0x71,
            Codec::Json => 0x0f,
        }
    }
    fn codec_from_tag(t: u8) -> Option<Codec> {
        match t {
            0x71 => Some(Codec::DagCbor),
            0x0f => Some(Codec::Json),
            _ => None,
        }
    }

    // ---- the concrete TEST envelope / codec (a real, injective round-trip) ----

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct TestUnsigned {
        version: u64,
        hash: HashAlgorithm,
        sig_alg: SignatureAlgorithm,
        codec: Codec,
        domain: SignatureDomain,
        body: Vec<u8>,
        claimed_cid: Vec<u8>,
        signer: Vec<u8>,
        unknown_critical: Vec<String>,
        body_binding: DomainBinding,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct TestEnvelope {
        unsigned: TestUnsigned,
        signature: Vec<u8>,
    }

    fn enc_unsigned(u: &TestUnsigned) -> Vec<u8> {
        let mut o = Vec::new();
        put_u64(&mut o, u.version);
        o.push(hash_tag(u.hash));
        o.push(sig_tag(u.sig_alg));
        o.push(codec_tag(u.codec));
        put_str(&mut o, &u.domain.record_type);
        put_bytes(&mut o, &u.domain.store_id);
        put_bytes(&mut o, &u.domain.thread_or_principal);
        put_bytes(&mut o, &u.body);
        put_bytes(&mut o, &u.claimed_cid);
        put_bytes(&mut o, &u.signer);
        put_u64(&mut o, u.unknown_critical.len() as u64);
        for s in &u.unknown_critical {
            put_str(&mut o, s);
        }
        put_u64(&mut o, u.body_binding.profile_version);
        o.push(codec_tag(u.body_binding.codec));
        put_bytes(&mut o, &u.body_binding.signer);
        o
    }

    fn dec_unsigned(input: &[u8], pos: &mut usize) -> Option<TestUnsigned> {
        let version = take_u64(input, pos)?;
        let hash = hash_from_tag(take_u8(input, pos)?)?;
        let sig_alg = sig_from_tag(take_u8(input, pos)?)?;
        let codec = codec_from_tag(take_u8(input, pos)?)?;
        let record_type = take_str(input, pos)?;
        let store_id = take_bytes(input, pos)?;
        let thread_or_principal = take_bytes(input, pos)?;
        let body = take_bytes(input, pos)?;
        let claimed_cid = take_bytes(input, pos)?;
        let signer = take_bytes(input, pos)?;
        let count = usize::try_from(take_u64(input, pos)?).ok()?;
        let mut unknown_critical = Vec::with_capacity(count);
        for _ in 0..count {
            unknown_critical.push(take_str(input, pos)?);
        }
        let bb_version = take_u64(input, pos)?;
        let bb_codec = codec_from_tag(take_u8(input, pos)?)?;
        let bb_signer = take_bytes(input, pos)?;
        Some(TestUnsigned {
            version,
            hash,
            sig_alg,
            codec,
            domain: SignatureDomain {
                record_type,
                store_id,
                thread_or_principal,
            },
            body,
            claimed_cid,
            signer,
            unknown_critical,
            body_binding: DomainBinding {
                profile_version: bb_version,
                codec: bb_codec,
                signer: bb_signer,
            },
        })
    }

    struct TestCodec;

    impl SignedEnvelopeCodec for TestCodec {
        type Envelope = TestEnvelope;
        type Unsigned = TestUnsigned;

        fn decode(&self, received: &[u8]) -> Option<TestEnvelope> {
            let mut pos = 0usize;
            let unsigned = dec_unsigned(received, &mut pos)?;
            let signature = take_bytes(received, &mut pos)?;
            // decode_exact: reject trailing bytes so encode(decode(x)) == x.
            if pos != received.len() {
                return None;
            }
            Some(TestEnvelope {
                unsigned,
                signature,
            })
        }
        fn encode(&self, envelope: &TestEnvelope) -> Vec<u8> {
            let mut o = enc_unsigned(&envelope.unsigned);
            put_bytes(&mut o, &envelope.signature);
            o
        }
        fn unsigned(&self, envelope: &TestEnvelope) -> TestUnsigned {
            envelope.unsigned.clone()
        }
        fn encode_unsigned(&self, unsigned: &TestUnsigned) -> Vec<u8> {
            enc_unsigned(unsigned)
        }
        fn profile_version(&self, u: &TestUnsigned) -> u64 {
            u.version
        }
        fn hash_algorithm(&self, u: &TestUnsigned) -> HashAlgorithm {
            u.hash
        }
        fn signature_algorithm(&self, u: &TestUnsigned) -> SignatureAlgorithm {
            u.sig_alg
        }
        fn codec(&self, u: &TestUnsigned) -> Codec {
            u.codec
        }
        fn domain(&self, u: &TestUnsigned) -> SignatureDomain {
            u.domain.clone()
        }
        fn body(&self, u: &TestUnsigned) -> Vec<u8> {
            u.body.clone()
        }
        fn claimed_cid(&self, u: &TestUnsigned) -> Vec<u8> {
            u.claimed_cid.clone()
        }
        fn signer(&self, u: &TestUnsigned) -> Vec<u8> {
            u.signer.clone()
        }
        fn unknown_critical(&self, u: &TestUnsigned) -> Vec<String> {
            u.unknown_critical.clone()
        }
        fn body_binding(&self, u: &TestUnsigned) -> DomainBinding {
            u.body_binding.clone()
        }
        fn signature_bytes(&self, envelope: &TestEnvelope) -> Vec<u8> {
            envelope.signature.clone()
        }
    }

    // A TEST "hash": tag ++ bytes. NOT cryptographic — it carries only the
    // property the LOGIC needs (deterministic; distinct algorithm ⇒ distinct
    // digest; distinct input ⇒ distinct digest). Real BLAKE3 is HELD.
    struct TestCrypto;

    fn test_digest(algorithm: HashAlgorithm, bytes: &[u8]) -> Vec<u8> {
        let mut o = vec![hash_tag(algorithm)];
        o.extend_from_slice(bytes);
        o
    }

    // A TEST "signature": the domain label ++ an injective encoding of ALL ten
    // preimage fields. Stands in for Ed25519 over the DAG-CBOR protected tuple
    // (both HELD); it carries the binding property — any field change ⇒ different
    // bytes ⇒ the old signature no longer matches.
    fn test_sign(algorithm: SignatureAlgorithm, p: &SignaturePreimage) -> Vec<u8> {
        let mut o = Vec::new();
        put_str(&mut o, SIGNED_OBJECT_DOMAIN); // OB-6 universal domain separation
        o.push(sig_tag(algorithm));
        put_bytes(&mut o, &p.canonical_unsigned);
        put_u64(&mut o, p.profile_version);
        o.push(hash_tag(p.hash_algorithm));
        o.push(sig_tag(p.signature_algorithm));
        o.push(codec_tag(p.codec));
        put_str(&mut o, &p.domain.record_type);
        put_bytes(&mut o, &p.domain.store_id);
        put_bytes(&mut o, &p.domain.thread_or_principal);
        put_bytes(&mut o, &p.body);
        put_bytes(&mut o, &p.claimed_cid);
        put_bytes(&mut o, &p.signer);
        put_u64(&mut o, p.unknown_critical.len() as u64);
        for s in &p.unknown_critical {
            put_str(&mut o, s);
        }
        o
    }

    impl CryptoBoundary for TestCrypto {
        fn digest(&self, algorithm: &AllowedHash, bytes: &[u8]) -> Vec<u8> {
            test_digest(algorithm.algorithm(), bytes)
        }
        fn signature_matches(
            &self,
            algorithm: &AllowedSignature,
            preimage: &SignaturePreimage,
            signature: &[u8],
        ) -> bool {
            signature == test_sign(algorithm.algorithm(), preimage).as_slice()
        }
    }

    // Payload decoders. `IdentityPayload` is canonical (value == body). `TrimZero`
    // is a lenient parser used to prove the re-encode guard bites.
    struct IdentityPayload;
    impl CanonicalEncoding for IdentityPayload {
        type Value = Vec<u8>;
        fn encode(&self, value: &Vec<u8>) -> Vec<u8> {
            value.clone()
        }
    }
    impl CanonicalPayloadDecoder for IdentityPayload {
        fn parse(&self, bytes: &[u8]) -> Option<Vec<u8>> {
            Some(bytes.to_vec())
        }
    }

    struct TrimZeroPayload;
    impl CanonicalEncoding for TrimZeroPayload {
        type Value = Vec<u8>;
        fn encode(&self, value: &Vec<u8>) -> Vec<u8> {
            value.clone()
        }
    }
    impl CanonicalPayloadDecoder for TrimZeroPayload {
        fn parse(&self, bytes: &[u8]) -> Option<Vec<u8>> {
            let mut v = bytes.to_vec();
            while v.last() == Some(&0) {
                v.pop();
            }
            Some(v)
        }
    }

    // ---- fixtures ----

    /// Assert a verify/load result failed **closed** at exactly `expected`. Kept
    /// as a helper because the `Ok` witnesses ([`Sealed`] / [`VerifiedEnvelope`])
    /// are deliberately not `PartialEq` — a sealed-at-load capability has no
    /// meaningful value-equality, only "was it minted or refused".
    fn assert_rejected<T>(result: Result<T, VerifyRejection>, expected: VerifyRejection) {
        match result {
            Err(actual) => assert_eq!(actual, expected, "wrong fail-closed reason"),
            Ok(_) => panic!("expected fail-closed {expected:?}, but verification succeeded"),
        }
    }

    /// A well-formed v1 unsigned view over `body`, in store `store_id`, signed by
    /// `signer`. The `cid` and `body_binding` are made internally consistent so a
    /// freshly [`signed`] envelope verifies end-to-end.
    fn v1_unsigned(body: &[u8], store_id: &[u8], signer: &[u8]) -> TestUnsigned {
        TestUnsigned {
            version: 1,
            hash: HashAlgorithm::Blake3_256,
            sig_alg: SignatureAlgorithm::Ed25519,
            codec: Codec::DagCbor,
            domain: SignatureDomain {
                record_type: "agent-bridle/permission-request/v1".to_string(),
                store_id: store_id.to_vec(),
                thread_or_principal: b"thread-1".to_vec(),
            },
            body: body.to_vec(),
            claimed_cid: test_digest(HashAlgorithm::Blake3_256, body),
            signer: signer.to_vec(),
            unknown_critical: Vec::new(),
            body_binding: DomainBinding {
                profile_version: 1,
                codec: Codec::DagCbor,
                signer: signer.to_vec(),
            },
        }
    }

    /// Attach the correct signature for an unsigned view (over its own preimage),
    /// then encode to received bytes — the adversary/tester then mutates fields.
    fn signed(u: TestUnsigned) -> Vec<u8> {
        let codec = TestCodec;
        let preimage = codec.signature_preimage(&u);
        let signature = test_sign(u.sig_alg, &preimage);
        codec.encode(&TestEnvelope {
            unsigned: u,
            signature,
        })
    }

    fn verify(received: &[u8]) -> Result<VerifiedEnvelope<TestEnvelope>, VerifyRejection> {
        verify_envelope(&TrustedProfile::v1(), &TestCodec, &TestCrypto, received)
    }

    // =======================================================================
    // LAW: the profile is a CLOSED allowlist (spec §4·4 / PO-8).
    // Exhaustive over every algorithm/codec value + a bounded version domain —
    // the Rust analogue of the Lean `blake3_allowed`/`sha1_not_allowed`/… lemmas
    // discharged `by decide`.
    // Attack blocked: `alg:none` / algorithm-confusion (an object declaring a
    // broken hash) and version-confusion.
    // =======================================================================

    #[test]
    fn allowlist_admits_exactly_v1_algorithms_and_codec() {
        let v1 = Profile::v1();
        for &h in &HashAlgorithm::ALL {
            let admitted = AllowedHash::admit(&v1, h).is_some();
            assert_eq!(
                admitted,
                h == HashAlgorithm::Blake3_256,
                "hash {h:?} admitted iff it is the v1 pin"
            );
            assert_eq!(v1.allows_hash(h), admitted, "allows_hash agrees with admit");
        }
        for &s in &SignatureAlgorithm::ALL {
            let admitted = AllowedSignature::admit(&v1, s).is_some();
            assert_eq!(admitted, s == SignatureAlgorithm::Ed25519, "sig {s:?}");
            assert_eq!(v1.allows_signature(s), admitted);
        }
        for &c in &Codec::ALL {
            let admitted = AllowedCodec::admit(&v1, c).is_some();
            assert_eq!(admitted, c == Codec::DagCbor, "codec {c:?}");
            assert_eq!(v1.allows_codec(c), admitted);
        }
    }

    #[test]
    fn trusted_profile_is_a_closed_allowlist_of_only_v1() {
        // v1 admits and reports itself (Lean trusted_profile_is_v1).
        let trusted = TrustedProfile::admit(Profile::v1()).expect("v1 is trusted");
        assert_eq!(trusted.profile(), &Profile::v1());
        assert_eq!(TrustedProfile::v1().profile(), &Profile::v1());

        // Every perturbation of v1 is rejected: wrong version, or any single
        // allowlist entry swapped to the non-v1 alternative, or an added entry.
        let rejects = [
            Profile {
                version: 0,
                ..Profile::v1()
            },
            Profile {
                version: 2,
                ..Profile::v1()
            },
            Profile {
                hashes: vec![HashAlgorithm::Sha1],
                ..Profile::v1()
            },
            Profile {
                hashes: vec![HashAlgorithm::Blake3_256, HashAlgorithm::Sha1],
                ..Profile::v1()
            },
            Profile {
                signatures: vec![SignatureAlgorithm::Ecdsa],
                ..Profile::v1()
            },
            Profile {
                codecs: vec![Codec::Json],
                ..Profile::v1()
            },
            Profile {
                hashes: vec![],
                ..Profile::v1()
            },
        ];
        for p in rejects {
            assert!(
                TrustedProfile::admit(p.clone()).is_none(),
                "non-v1 profile must fail closed: {p:?}"
            );
        }
    }

    // =======================================================================
    // LAW: deterministic signatures (spec §5 — why Ed25519 is pinned).
    // Attack blocked: a randomised (ECDSA) signature re-signs differently each
    // time, forking any chain built over it (P2).
    // =======================================================================

    #[test]
    fn every_v1_admissible_signature_is_deterministic() {
        assert!(SignatureAlgorithm::Ed25519.is_deterministic());
        assert!(!SignatureAlgorithm::Ecdsa.is_deterministic());
        let v1 = Profile::v1();
        for &s in &SignatureAlgorithm::ALL {
            if AllowedSignature::admit(&v1, s).is_some() {
                assert!(s.is_deterministic(), "v1 admits only deterministic sigs");
            }
        }
    }

    // =======================================================================
    // LAW (OB-13): the protected preimage BINDS every one of the ten fields.
    // A change to ANY field changes the preimage (derived Eq == Lean DecidableEq),
    // so nothing interpretation-bearing sits outside the signature.
    // Attack blocked: re-tagging codec / profile / signer without re-signing.
    // =======================================================================

    fn base_preimage() -> SignaturePreimage {
        SignaturePreimage {
            canonical_unsigned: b"cu".to_vec(),
            profile_version: 1,
            hash_algorithm: HashAlgorithm::Blake3_256,
            signature_algorithm: SignatureAlgorithm::Ed25519,
            codec: Codec::DagCbor,
            domain: SignatureDomain {
                record_type: "r".to_string(),
                store_id: b"s".to_vec(),
                thread_or_principal: b"t".to_vec(),
            },
            body: b"b".to_vec(),
            claimed_cid: b"c".to_vec(),
            signer: b"k".to_vec(),
            unknown_critical: vec![],
        }
    }

    #[test]
    fn preimage_binds_all_ten_fields() {
        let base = base_preimage();
        // Ten independent single-field mutations; each must differ from `base`.
        let mutations: Vec<SignaturePreimage> = vec![
            // 1 — canonical_unsigned
            SignaturePreimage {
                canonical_unsigned: b"CU".to_vec(),
                ..base.clone()
            },
            // 2 — profile_version
            SignaturePreimage {
                profile_version: 2,
                ..base.clone()
            },
            // 3 — hash_algorithm
            SignaturePreimage {
                hash_algorithm: HashAlgorithm::Sha1,
                ..base.clone()
            },
            // 4 — signature_algorithm
            SignaturePreimage {
                signature_algorithm: SignatureAlgorithm::Ecdsa,
                ..base.clone()
            },
            // 5 — codec
            SignaturePreimage {
                codec: Codec::Json,
                ..base.clone()
            },
            // 6 — domain
            SignaturePreimage {
                domain: SignatureDomain {
                    record_type: "OTHER".to_string(),
                    ..base.domain.clone()
                },
                ..base.clone()
            },
            // 7 — body
            SignaturePreimage {
                body: b"B".to_vec(),
                ..base.clone()
            },
            // 8 — claimed_cid
            SignaturePreimage {
                claimed_cid: b"C".to_vec(),
                ..base.clone()
            },
            // 9 — signer
            SignaturePreimage {
                signer: b"K".to_vec(),
                ..base.clone()
            },
            // 10 — unknown_critical
            SignaturePreimage {
                unknown_critical: vec!["x".to_string()],
                ..base.clone()
            },
        ];
        assert_eq!(mutations.len(), 10, "one mutation per bound field");
        for (i, m) in mutations.iter().enumerate() {
            assert_ne!(*m, base, "field {} must be bound into the preimage", i + 1);
            // And the signature over it differs from the base signature — so a
            // stale signature cannot be transplanted onto a re-tagged preimage.
            assert_ne!(
                test_sign(SignatureAlgorithm::Ed25519, m),
                test_sign(SignatureAlgorithm::Ed25519, &base),
            );
        }
    }

    #[test]
    fn preimage_constructor_wires_every_accessor() {
        // The OB-13 constructor pulls each of the 10 fields from its accessor.
        let codec = TestCodec;
        let u = v1_unsigned(b"payload", STORE_ID_SELF, b"signer-A");
        let p = codec.signature_preimage(&u);
        assert_eq!(p.canonical_unsigned, codec.encode_unsigned(&u));
        assert_eq!(p.profile_version, u.version);
        assert_eq!(p.hash_algorithm, u.hash);
        assert_eq!(p.signature_algorithm, u.sig_alg);
        assert_eq!(p.codec, u.codec);
        assert_eq!(p.domain, u.domain);
        assert_eq!(p.body, u.body);
        assert_eq!(p.claimed_cid, u.claimed_cid);
        assert_eq!(p.signer, u.signer);
        assert_eq!(p.unknown_critical, u.unknown_critical);
    }

    #[test]
    fn re_tagging_signer_without_resigning_is_caught_by_the_signature() {
        // OB-13 concrete attack: take a valid envelope, re-tag the (envelope-
        // level) signer, keep the old signature. STEP 2 rejects it because the
        // signer is INSIDE the protected preimage.
        let mut u = v1_unsigned(b"payload", b"store-9", b"signer-A");
        let good = signed(u.clone());
        assert!(verify(&good).is_ok(), "baseline verifies");

        u.signer = b"signer-EVIL".to_vec();
        // Re-attach the OLD signature (computed over signer-A's preimage).
        let old_sig = {
            let codec = TestCodec;
            test_sign(
                SignatureAlgorithm::Ed25519,
                &codec.signature_preimage(&v1_unsigned(b"payload", b"store-9", b"signer-A")),
            )
        };
        let received = TestCodec.encode(&TestEnvelope {
            unsigned: u,
            signature: old_sig,
        });
        assert_rejected(verify(&received), VerifyRejection::SignatureInvalid);
    }

    // =======================================================================
    // LAW (spec §4·2): unknown authority-bearing / critical fields FAIL CLOSED.
    // Attack blocked: silent downgrade / version-confusion via a tolerated field.
    // =======================================================================

    #[test]
    fn unknown_critical_field_fails_closed() {
        // Empty ⇒ Ok; any unknown-critical entry ⇒ closed rejection.
        for names in [
            Vec::<String>::new(),
            vec!["x.unknown".to_string()],
            vec!["a".to_string(), "b".to_string()],
        ] {
            let mut u = v1_unsigned(b"payload", b"store-1", b"signer-A");
            u.unknown_critical = names.clone();
            let received = signed(u);
            let result = verify(&received);
            if names.is_empty() {
                assert!(result.is_ok(), "no unknown-critical ⇒ verifies");
            } else {
                assert_rejected(result, VerifyRejection::UnknownCriticalField);
            }
        }
    }

    // =======================================================================
    // OB-14: genesis STORE_ID_SELF resolves to the record's OWN cid; a normal
    // record's declared store id passes through unchanged.
    // Attack blocked: circular genesis (store_id = H(genesis)) and cross-store
    // replay (store_id is bound + resolved, not prose).
    // =======================================================================

    #[test]
    fn resolve_store_id_sentinel_and_passthrough() {
        let cid = b"cid-bytes".to_vec();
        assert_eq!(
            resolve_store_id(STORE_ID_SELF, &cid),
            cid,
            "sentinel ⇒ own cid"
        );
        assert_eq!(
            resolve_store_id(b"store-42", &cid),
            b"store-42".to_vec(),
            "declared store id passes through"
        );
    }

    #[test]
    fn genesis_store_id_self_resolves_to_own_cid() {
        // Genesis: body binds STORE_ID_SELF; effective store id == its own cid.
        let body = b"genesis-record";
        let received = signed(v1_unsigned(body, STORE_ID_SELF, b"founder"));
        let verified = verify(&received).expect("genesis verifies");
        let own_cid = test_digest(HashAlgorithm::Blake3_256, body);
        assert_eq!(verified.cid(), own_cid.as_slice());
        assert_eq!(
            verified.effective_store_id(),
            own_cid,
            "OB-14: genesis store id BECOMES the record's own cid"
        );

        // A subsequent record binds a concrete store id (that same cid), which
        // resolves to itself unchanged.
        let received2 = signed(v1_unsigned(b"second-record", &own_cid, b"founder"));
        let verified2 = verify(&received2).expect("second record verifies");
        assert_eq!(verified2.effective_store_id(), own_cid);
    }

    // =======================================================================
    // The 6-step verify ORDER — positive path + one negative per step, each
    // pinned to its VerifyRejection so the fail-closed point is exact.
    // =======================================================================

    #[test]
    fn happy_path_verifies_and_seals_the_body() {
        let body = b"hello-world";
        let received = signed(v1_unsigned(body, STORE_ID_SELF, b"signer-A"));

        // decode_exact / law §4·1: encode(decode(received)) == received.
        let decoded = TestCodec.decode(&received).expect("decodes");
        assert_eq!(
            TestCodec.encode(&decoded),
            received,
            "verify over received bytes"
        );

        let sealed = load_envelope(
            &TrustedProfile::v1(),
            &TestCodec,
            &TestCrypto,
            &IdentityPayload,
            &received,
        )
        .expect("loads and seals");
        assert_eq!(sealed.value(), &body.to_vec(), "sealed value is the body");
        assert_eq!(sealed.verified().profile(), &Profile::v1());
    }

    #[test]
    fn step1_undecodable_fails_closed() {
        assert_rejected(verify(b"\x00\x01garbage"), VerifyRejection::Undecodable);
        assert_rejected(verify(&[]), VerifyRejection::Undecodable);
    }

    #[test]
    fn step1_version_mismatch_fails_closed() {
        let mut u = v1_unsigned(b"p", b"s", b"k");
        u.version = 2;
        assert_rejected(verify(&signed(u)), VerifyRejection::VersionMismatch);
    }

    #[test]
    fn step1_allowlist_rejects_off_profile_algorithms_before_crypto() {
        let mut h = v1_unsigned(b"p", b"s", b"k");
        h.hash = HashAlgorithm::Sha1;
        assert_rejected(verify(&signed(h)), VerifyRejection::HashNotAllowed);

        let mut s = v1_unsigned(b"p", b"s", b"k");
        s.sig_alg = SignatureAlgorithm::Ecdsa;
        assert_rejected(verify(&signed(s)), VerifyRejection::SignatureAlgNotAllowed);

        let mut c = v1_unsigned(b"p", b"s", b"k");
        c.codec = Codec::Json;
        assert_rejected(verify(&signed(c)), VerifyRejection::CodecNotAllowed);
    }

    #[test]
    fn step2_bad_signature_fails_closed() {
        let received = {
            let u = v1_unsigned(b"p", b"s", b"k");
            let codec = TestCodec;
            codec.encode(&TestEnvelope {
                unsigned: u,
                signature: b"not-a-valid-signature".to_vec(),
            })
        };
        assert_rejected(verify(&received), VerifyRejection::SignatureInvalid);
    }

    #[test]
    fn step3_cid_mismatch_fails_closed() {
        // Tamper the claimed cid; re-sign so STEP 2 passes and STEP 3 is reached.
        let mut u = v1_unsigned(b"p", b"s", b"k");
        u.claimed_cid = b"wrong-cid".to_vec();
        assert_rejected(verify(&signed(u)), VerifyRejection::CidMismatch);
    }

    #[test]
    fn step4_body_domain_mismatch_fails_closed() {
        // Validly-signed but internally inconsistent: body claims a different
        // signer than the envelope. STEP 2/3 pass (we re-sign); STEP 4 rejects.
        let mut u = v1_unsigned(b"p", b"store-1", b"signer-A");
        u.body_binding.signer = b"signer-B".to_vec();
        assert_rejected(verify(&signed(u)), VerifyRejection::BodyDomainMismatch);
    }

    #[test]
    fn step6_non_canonical_body_fails_closed() {
        // A body with a trailing zero: the lenient TrimZero parser drops it, so
        // encode(parse(body)) != body ⇒ closed rejection. The IdentityPayload
        // (canonical) accepts the same body.
        let body = b"payload\x00";
        let received = signed(v1_unsigned(body, b"s", b"k"));

        assert!(load_envelope(
            &TrustedProfile::v1(),
            &TestCodec,
            &TestCrypto,
            &IdentityPayload,
            &received,
        )
        .is_ok());

        assert_rejected(
            load_envelope(
                &TrustedProfile::v1(),
                &TestCodec,
                &TestCrypto,
                &TrimZeroPayload,
                &received,
            ),
            VerifyRejection::NonCanonicalBody,
        );
    }

    #[test]
    fn cross_context_replay_is_blocked_by_domain_binding() {
        // OB-6: a signature is valid ONLY for its (record_type, store, thread)
        // context. Move the same body+signer to a different record_type WITHOUT
        // re-signing and STEP 2 rejects it (domain is inside the preimage).
        let original = v1_unsigned(b"p", b"store-1", b"signer-A");
        let good = signed(original.clone());
        assert!(verify(&good).is_ok());

        let stale_sig = TestCodec.signature_bytes(&TestCodec.decode(&good).expect("decodes"));
        let mut replayed = original;
        replayed.domain.record_type = "agent-bridle/OTHER-record/v1".to_string();
        let received = TestCodec.encode(&TestEnvelope {
            unsigned: replayed,
            signature: stale_sig,
        });
        assert_rejected(verify(&received), VerifyRejection::SignatureInvalid);
    }
}
