//! The P0 authority algebra — a Rust mirror of `formal/Ceremony/P0/Authority.lean`.
//!
//! `Authority = Effect × Assurance × Scope` is a **product meet-lattice** (ADR
//! 0020). A verdict is a *point*, not a rung: each axis is an independent finite
//! chain, and `meet` (`⊓`, greatest lower bound) is componentwise. Authority
//! composes by meet and **never amplifies** — the only movement the algebra
//! permits is attenuation (ADR 0002's "narrow-only, no `join`/`widen`").
//!
//! Every function here is total and pure over finite enums, with no external
//! dependencies, so it is the intended **Charon/Aeneas refinement target**: the
//! Lean file states the laws as theorems; this module is what a future Aeneas
//! proof shows *refines* them. Until that toolchain lands (roadmap Phase 1c /
//! `docs/TOOLCHAIN.md`), the `#[cfg(test)]` block below discharges the same laws
//! by **exhaustive enumeration** over the (tiny) finite domain — the Rust
//! analogue of the Lean proofs' `by cases <;> decide`.

/// *What* is permitted. `Deny` is ⊥ (ADR 0020 D2 — the single canonical bottom).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Effect {
    Deny,
    Allow,
}

/// *How strongly present* the human is (ADR 0020 D3 — the former `attest` lives
/// here). A grant with `Assurance > None` is inert until a presence proof
/// discharges it (P0 §3, the forward-only ratchet).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Assurance {
    None,
    Presence,
    Hardware,
}

/// *How long* the grant covers (ADR 0020 D5 — a profile-declared, closed order;
/// this crate pins the v1 order `Once ⊏ Session ⊏ Durable`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Scope {
    Once,
    Session,
    Durable,
}

impl Effect {
    /// position in the chain; `meet` = the lower rank.
    pub const fn rank(self) -> u8 {
        match self {
            Effect::Deny => 0,
            Effect::Allow => 1,
        }
    }

    /// greatest lower bound on the `Deny ⊏ Allow` chain.
    pub const fn meet(self, other: Effect) -> Effect {
        if self.rank() <= other.rank() {
            self
        } else {
            other
        }
    }

    /// every value, for exhaustive proofs/tests (mirrors the Lean finite enum).
    pub const ALL: [Effect; 2] = [Effect::Deny, Effect::Allow];
}

impl Assurance {
    pub const fn rank(self) -> u8 {
        match self {
            Assurance::None => 0,
            Assurance::Presence => 1,
            Assurance::Hardware => 2,
        }
    }

    pub const fn meet(self, other: Assurance) -> Assurance {
        if self.rank() <= other.rank() {
            self
        } else {
            other
        }
    }

    pub const ALL: [Assurance; 3] = [Assurance::None, Assurance::Presence, Assurance::Hardware];
}

impl Scope {
    pub const fn rank(self) -> u8 {
        match self {
            Scope::Once => 0,
            Scope::Session => 1,
            Scope::Durable => 2,
        }
    }

    pub const fn meet(self, other: Scope) -> Scope {
        if self.rank() <= other.rank() {
            self
        } else {
            other
        }
    }

    pub const ALL: [Scope; 3] = [Scope::Once, Scope::Session, Scope::Durable];
}

/// A verdict: a point in the product lattice `Effect × Assurance × Scope`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Authority {
    pub effect: Effect,
    pub assurance: Assurance,
    pub scope: Scope,
}

impl Authority {
    pub const fn new(effect: Effect, assurance: Assurance, scope: Scope) -> Self {
        Authority {
            effect,
            assurance,
            scope,
        }
    }

    /// `⊥ = (Deny, None, Once)` — the single denied authority (ADR 0020 D2), the
    /// fail-closed floor every axis meets down to.
    pub const BOTTOM: Authority = Authority::new(Effect::Deny, Assurance::None, Scope::Once);

    /// `⊤ = (Allow, Hardware, Durable)` — the identity of `meet`. Note: `⊤` is
    /// *not* a default verdict; an unmatched request is `NeedsDecision`, never
    /// `⊤` (see [`resolve`]).
    pub const TOP: Authority = Authority::new(Effect::Allow, Assurance::Hardware, Scope::Durable);

    /// componentwise meet (`⊓`) — the product greatest lower bound.
    pub const fn meet(self, other: Authority) -> Authority {
        Authority::new(
            self.effect.meet(other.effect),
            self.assurance.meet(other.assurance),
            self.scope.meet(other.scope),
        )
    }

    /// the meet-induced order: `self ≤ other ⇔ self ⊓ other = self`.
    pub fn le(self, other: Authority) -> bool {
        self.meet(other) == self
    }

    /// pass `self` through a `ceiling`; the result never exceeds either input on
    /// any axis (L4 / PO-4 — attenuation only, `authority(escalate) = ⊥`).
    pub const fn attenuate(self, ceiling: Authority) -> Authority {
        self.meet(ceiling)
    }
}

/// The result of resolving a request against matching rules (ADR 0020 D4).
///
/// `NeedsDecision` (the former `ask`) has **no place in the lattice** — it is
/// control flow, routed to a decision surface; headless it degrades to `Deny`.
/// Critically it is *not* `⊤`: an unmatched request must never fail open.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Resolution {
    NeedsDecision,
    Decided(Authority),
}

/// Resolve the authority of a request as the meet (`⨅`) of the authorities of
/// the rules that match it (L1). An **empty** match set is `NeedsDecision`, not
/// the empty meet `⊤` — the no-fail-open clause (OB-9 / OB-12): the piecewise
/// definition never seeds the fold with `⊤`, which would both fail open on no
/// match *and* silently downgrade a legitimate `Allow`.
///
/// Uses explicit index recursion ([`meet_from`]) rather than `iter().fold`: the
/// iterator/closure form extracts to Aeneas's *opaque* slice-iterator axioms and
/// cannot be reduced in a refinement proof, whereas this extracts to a real
/// recursive function (see `formal/refinement/`).
pub fn resolve(candidates: &[Authority]) -> Resolution {
    if candidates.is_empty() {
        Resolution::NeedsDecision
    } else {
        Resolution::Decided(meet_from(candidates, 1, candidates[0]))
    }
}

/// Fold the meet over `candidates[start..]`, accumulating into `acc`. Explicit
/// tail recursion — no iterator, no closure — so it extracts to a genuine
/// recursive function for the Aeneas refinement. The recursion decreases
/// `candidates.len() - start`, so it terminates.
fn meet_from(candidates: &[Authority], start: usize, acc: Authority) -> Authority {
    if start >= candidates.len() {
        acc
    } else {
        meet_from(candidates, start + 1, acc.meet(candidates[start]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// every `Authority` value — 2 × 3 × 3 = 18 points; the finite domain the
    /// Lean proofs `decide` over. Exhausting it here proves the same laws.
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

    // ---- axis meet laws (mirror Effect/Assurance/Scope .meet_comm/assoc/idem) ----

    #[test]
    fn effect_meet_is_commutative_associative_idempotent() {
        for &a in &Effect::ALL {
            assert_eq!(a.meet(a), a, "idempotent");
            for &b in &Effect::ALL {
                assert_eq!(a.meet(b), b.meet(a), "commutative");
                for &c in &Effect::ALL {
                    assert_eq!(a.meet(b).meet(c), a.meet(b.meet(c)), "associative");
                }
            }
        }
    }

    #[test]
    fn assurance_meet_is_commutative_associative_idempotent() {
        for &a in &Assurance::ALL {
            assert_eq!(a.meet(a), a, "idempotent");
            for &b in &Assurance::ALL {
                assert_eq!(a.meet(b), b.meet(a), "commutative");
                for &c in &Assurance::ALL {
                    assert_eq!(a.meet(b).meet(c), a.meet(b.meet(c)), "associative");
                }
            }
        }
    }

    #[test]
    fn scope_meet_is_commutative_associative_idempotent() {
        for &a in &Scope::ALL {
            assert_eq!(a.meet(a), a, "idempotent");
            for &b in &Scope::ALL {
                assert_eq!(a.meet(b), b.meet(a), "commutative");
                for &c in &Scope::ALL {
                    assert_eq!(a.meet(b).meet(c), a.meet(b.meet(c)), "associative");
                }
            }
        }
    }

    // ---- product meet laws (mirror meet_comm / meet_assoc / meet_idem) ----

    #[test]
    fn authority_meet_is_commutative_associative_idempotent() {
        for &a in &all_authorities() {
            assert_eq!(a.meet(a), a, "idempotent (meet_idem)");
            for &b in &all_authorities() {
                assert_eq!(a.meet(b), b.meet(a), "commutative (meet_comm)");
                for &c in &all_authorities() {
                    assert_eq!(
                        a.meet(b).meet(c),
                        a.meet(b.meet(c)),
                        "associative (meet_assoc)"
                    );
                }
            }
        }
    }

    // ---- attenuation / no-amplify (mirror meet_le_left / meet_le_right / PO-4) ----

    #[test]
    fn meet_never_amplifies_on_any_axis() {
        for &a in &all_authorities() {
            for &c in &all_authorities() {
                let m = a.meet(c);
                assert!(m.le(a), "meet_le_left: (a ⊓ c) ≤ a");
                assert!(m.le(c), "meet_le_right: (a ⊓ c) ≤ c");
                // and it never exceeds either on any single axis
                assert!(m.effect.rank() <= a.effect.rank() && m.effect.rank() <= c.effect.rank());
                assert!(
                    m.assurance.rank() <= a.assurance.rank()
                        && m.assurance.rank() <= c.assurance.rank()
                );
                assert!(m.scope.rank() <= a.scope.rank() && m.scope.rank() <= c.scope.rank());
            }
        }
    }

    #[test]
    fn attenuate_is_bounded_by_input_and_ceiling() {
        for &a in &all_authorities() {
            for &ceiling in &all_authorities() {
                let g = a.attenuate(ceiling);
                assert!(g.le(a), "attenuate ≤ input (attenuate_le_input)");
                assert!(g.le(ceiling), "attenuate ≤ ceiling (attenuate_le_ceiling)");
            }
        }
    }

    #[test]
    fn sequential_ceilings_collapse_to_one_meet() {
        // attenuate_compose: attenuate (attenuate a c) d = attenuate a (c ⊓ d)
        for &a in &all_authorities() {
            for &c in &all_authorities() {
                for &d in &all_authorities() {
                    assert_eq!(a.attenuate(c).attenuate(d), a.attenuate(c.meet(d)));
                }
            }
        }
    }

    // ---- bottom / top ----

    #[test]
    fn bottom_is_the_meet_annihilator_top_is_the_identity() {
        for &a in &all_authorities() {
            assert_eq!(a.meet(Authority::BOTTOM), Authority::BOTTOM, "⊥ absorbs");
            assert_eq!(a.meet(Authority::TOP), a, "⊤ is identity");
            assert!(Authority::BOTTOM.le(a), "⊥ ≤ everything");
            assert!(a.le(Authority::TOP), "everything ≤ ⊤");
        }
    }

    // ---- resolution (mirror resolve_empty / resolve_swap) ----

    #[test]
    fn resolve_empty_needs_decision_never_fails_open() {
        // OB-9/OB-12: the empty match is NeedsDecision, NOT Decided(⊤).
        assert_eq!(resolve(&[]), Resolution::NeedsDecision);
        assert_ne!(resolve(&[]), Resolution::Decided(Authority::TOP));
    }

    #[test]
    fn resolve_singleton_is_that_authority() {
        for &a in &all_authorities() {
            assert_eq!(resolve(&[a]), Resolution::Decided(a));
        }
    }

    #[test]
    fn resolve_is_order_independent() {
        // resolve_swap generalized: any permutation resolves identically, since
        // the fold is over the commutative/associative meet. Check adjacent
        // swaps (which generate every permutation) across all triples.
        for &x in &all_authorities() {
            for &y in &all_authorities() {
                for &z in &all_authorities() {
                    let base = resolve(&[x, y, z]);
                    assert_eq!(base, resolve(&[y, x, z]), "swap first two");
                    assert_eq!(base, resolve(&[x, z, y]), "swap last two");
                    assert_eq!(base, resolve(&[z, y, x]), "swap ends");
                }
            }
        }
    }

    #[test]
    fn resolve_is_the_meet_of_all_matches() {
        for &x in &all_authorities() {
            for &y in &all_authorities() {
                assert_eq!(resolve(&[x, y]), Resolution::Decided(x.meet(y)));
            }
        }
    }
}
