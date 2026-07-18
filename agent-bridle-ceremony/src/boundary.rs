//! The enforcement boundary — a Rust mirror of `formal/Ceremony/P0/Boundary.lean`.
//!
//! This module carries the "OCAP two-stream sequencing" result into Rust: the
//! **L3-gated brush default** (brush is the confined default where a kernel
//! fence enforces; fall back to safe-subset's structural refusal otherwise) is
//! *not* a new mechanism — it is [`Effect::meet`] driven by an enforceable
//! ceiling the active fence supplies. Everything here is expressed with the
//! [`super::authority`] algebra and adds no new operation, exactly as the Lean
//! file proves.
//!
//! As with the authority kernel, the laws are discharged here by exhaustive
//! enumeration over the finite domain (the Rust analogue of the Lean proofs).
//! The temporal half — a fence that *drops* between grant and exec must be
//! re-checked at exec (spec I4) — is not a pure-function property and lives in
//! `formal/tla/EnforcementGate.tla`, not here.

use crate::authority::{Assurance, Authority, Effect, Scope};

/// Enforcement strength *right now* (ADR 0002 I9/I10 `sandbox_kind`).
/// `Kernel` = an L3 fence (Landlock/seatbelt/AppContainer) is actively
/// confining a spawned process; `Advisory` = none, so L1/L2 cannot see inside a
/// spawned binary. This is deliberately **not** a fourth `Authority` axis — it
/// bounds only what the boundary can faithfully enforce, which lands on
/// `Effect` through the meet below.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Fence {
    Advisory,
    Kernel,
}

impl Fence {
    pub const ALL: [Fence; 2] = [Fence::Advisory, Fence::Kernel];
}

/// A shell request, abstracted to the one bit the decision turns on: does it use
/// dynamic constructs (`$(…)`, pipes, `eval`) whose containment only a kernel
/// fence can provide? `dynamic == false` is structurally safe.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Request {
    pub dynamic: bool,
}

impl Request {
    pub const fn new(dynamic: bool) -> Self {
        Request { dynamic }
    }

    pub const ALL: [Request; 2] = [Request::new(false), Request::new(true)];
}

/// safe-subset engine: **structural** refusal of dynamic constructs — least
/// authority by construction, fence-independent (it never runs `$(…)`).
pub const fn safe_subset(q: Request) -> Effect {
    if q.dynamic {
        Effect::Deny
    } else {
        Effect::Allow
    }
}

/// brush engine as its **honest** verdict (ADR 0002 I9: never report an advisory
/// run as confined). Under `Kernel` the op is confined ⇒ honest `Allow`. Under
/// `Advisory` a dynamic op cannot be confined, so running it and calling it
/// confined would overclaim ⇒ the honest verdict is `Deny` (fail-closed, I5/L3);
/// a static op is structurally safe regardless.
pub const fn brush_honest(f: Fence, q: Request) -> Effect {
    match (f, q.dynamic) {
        (Fence::Kernel, _) => Effect::Allow,
        (Fence::Advisory, true) => Effect::Deny,
        (Fence::Advisory, false) => Effect::Allow,
    }
}

/// The DECIDED rule: brush is the default where a kernel fence enforces; else
/// fall back to safe-subset's structural refusal.
pub const fn boundary_verdict(f: Fence, q: Request) -> Effect {
    match f {
        Fence::Kernel => brush_honest(Fence::Kernel, q),
        Fence::Advisory => safe_subset(q),
    }
}

/// the enforceable-effect ceiling the fence supplies for this request.
pub const fn enforceable_ceiling(f: Fence, q: Request) -> Effect {
    boundary_verdict(f, q)
}

/// the fence ceiling as an `Authority`: enforceable on `Effect`, `⊤` on the
/// other two axes (the fence says nothing about human presence or duration).
pub const fn boundary_ceiling(f: Fence, q: Request) -> Authority {
    Authority::new(boundary_verdict(f, q), Assurance::Hardware, Scope::Durable)
}

/// what the gate actually mints: the request attenuated by the fence ceiling —
/// the frozen product meet, no bespoke operation.
pub const fn minted_grant(req: Authority, f: Fence, q: Request) -> Authority {
    req.attenuate(boundary_ceiling(f, q))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority::{Assurance, Authority, Effect, Scope};

    fn all_authorities() -> Vec<Authority> {
        let mut v = Vec::new();
        for &e in &Effect::ALL {
            for &a in &Assurance::ALL {
                for &s in &Scope::ALL {
                    v.push(Authority::new(e, a, s));
                }
            }
        }
        v
    }

    /// `fallback_is_forced`: under `Advisory`, the honest brush verdict IS
    /// safe-subset's — so the fallback is derived from I9, not a separate knob.
    #[test]
    fn fallback_is_forced() {
        for &q in &Request::ALL {
            assert_eq!(brush_honest(Fence::Advisory, q), safe_subset(q));
        }
    }

    /// `boundary_verdict_eq_honest`: the "default + fallback" phrasing is one
    /// function, not two.
    #[test]
    fn boundary_verdict_equals_honest_brush() {
        for &f in &Fence::ALL {
            for &q in &Request::ALL {
                assert_eq!(boundary_verdict(f, q), brush_honest(f, q));
            }
        }
    }

    /// `allow_is_effect_top` + `boundary_verdict_is_attenuation`: the decision is
    /// `Effect::meet(Allow, ceiling)` — the frozen meet, nothing new.
    #[test]
    fn boundary_verdict_is_attenuation_of_allow() {
        for &e in &Effect::ALL {
            assert_eq!(Effect::Allow.meet(e), e, "allow is Effect's top");
        }
        for &f in &Fence::ALL {
            for &q in &Request::ALL {
                assert_eq!(
                    boundary_verdict(f, q),
                    Effect::Allow.meet(enforceable_ceiling(f, q))
                );
            }
        }
    }

    /// `minted_le_request`: a minted grant never exceeds the request.
    #[test]
    fn minted_grant_never_exceeds_request() {
        for &req in &all_authorities() {
            for &f in &Fence::ALL {
                for &q in &Request::ALL {
                    assert!(minted_grant(req, f, q).le(req));
                }
            }
        }
    }

    /// `minted_le_enforceable`: a minted grant never exceeds what the fence can
    /// enforce (I9 "never overclaim", in the product).
    #[test]
    fn minted_grant_never_exceeds_enforceable_ceiling() {
        for &req in &all_authorities() {
            for &f in &Fence::ALL {
                for &q in &Request::ALL {
                    assert!(minted_grant(req, f, q).le(boundary_ceiling(f, q)));
                }
            }
        }
    }

    /// `advisory_dynamic_grant_is_deny`: a containment-needing request under no
    /// kernel fence mints `Deny` on the effect axis — fail closed (L3/I5), for
    /// ANY request ceiling.
    #[test]
    fn advisory_dynamic_fails_closed_on_effect() {
        let dynamic = Request::new(true);
        for &req in &all_authorities() {
            assert_eq!(
                minted_grant(req, Fence::Advisory, dynamic).effect,
                Effect::Deny
            );
        }
    }

    /// The convergence check (`proj_effect_meet`): projection to the carrier
    /// brush enforces commutes with the meet — Stream B's attenuation, projected
    /// onto what Stream A enforces, IS Stream A's attenuation.
    #[test]
    fn projection_to_effect_is_a_meet_homomorphism() {
        for &a in &all_authorities() {
            for &b in &all_authorities() {
                assert_eq!(a.meet(b).effect, a.effect.meet(b.effect));
                assert_eq!(a.meet(b).assurance, a.assurance.meet(b.assurance));
                assert_eq!(a.meet(b).scope, a.scope.meet(b.scope));
            }
        }
    }
}
