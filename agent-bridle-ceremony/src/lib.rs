//! Ceremony Suite — the authority kernel (P0 of the narrow waist).
//!
//! This crate is the **pure algebra** at the center of the Ceremony Suite
//! (`docs/spec/ceremony-contract.md`): the `Authority = Effect × Assurance ×
//! Scope` product meet-lattice, `resolve`, and attenuation. It is a faithful
//! Rust mirror of `formal/Ceremony/P0/Authority.lean` and is meant to be
//! **extracted by Charon and proven by Aeneas to refine that Lean model**
//! (roadmap Phase 1c). Everything here is total, panic-free, dependency-free,
//! and finite — chosen for extractability, not convenience.
//!
//! What this crate is NOT: it holds **no wire format**. Serialized records,
//! signatures, stored bytes, and cross-language APIs are the signed-object (P1)
//! and chain-store (P2) profiles' concern and stay HELD until the Phase-1d
//! conformance vectors freeze them. Keeping the kernel a pure spike is
//! deliberate (`docs/spec/ROADMAP.md`).
//!
//! ```
//! use agent_bridle_ceremony::{Authority, Effect, Assurance, Scope, Resolution, resolve};
//!
//! let a = Authority::new(Effect::Allow, Assurance::Hardware, Scope::Durable);
//! let ceiling = Authority::new(Effect::Allow, Assurance::Presence, Scope::Session);
//! // attenuation never amplifies: the grant is bounded by the ceiling on every axis.
//! let granted = a.attenuate(ceiling);
//! assert!(granted.le(a) && granted.le(ceiling));
//!
//! // no fail-open: an unmatched request is a decision to make, never ⊤.
//! assert_eq!(resolve(&[]), Resolution::NeedsDecision);
//! ```

#![forbid(unsafe_code)]

mod authority;
mod boundary;
mod chain_store;
mod signed_object;

pub use authority::{resolve, Assurance, Authority, Effect, Resolution, Scope};
pub use boundary::{
    boundary_ceiling, boundary_verdict, brush_honest, enforceable_ceiling, minted_grant,
    safe_subset, Fence, Request,
};
pub use chain_store::{
    AcceptOutcome, AppendOutcome, AuthorityCheckpoint, ChainStore, LineCid, Rejection, StoreId,
    ThreadId,
};
pub use signed_object::{
    load_envelope, parse_verified, resolve_store_id, verify_envelope, AllowedCodec, AllowedHash,
    AllowedSignature, CanonicalEncoding, CanonicalPayloadDecoder, Codec, CryptoBoundary,
    DomainBinding, HashAlgorithm, Profile, Sealed, SignatureAlgorithm, SignatureDomain,
    SignaturePreimage, SignedEnvelopeCodec, TrustedProfile, VerifiedEnvelope, VerifyRejection,
    SIGNED_OBJECT_DOMAIN, STORE_ID_SELF,
};
