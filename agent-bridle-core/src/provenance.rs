//! provenance — the resolved-authority lattice + scope-relation admission.
//!
//! bridle's **native** projection of a per-backend enforcement fence into a
//! portable resolved-authority lattice, plus the pure admission decision over it.
//! It mirrors `agent-mesh-protocol`'s `ResolvedScope` / `ScopeRelation` / `admit`
//! (mesh PR #72) *exactly*, so that when a mesh release carrying those types is
//! published this module collapses to a re-export + a version-pin bump. Until then
//! the leash pin is `agent-mesh-protocol = "0.6"` and 0.6.3 predates #72, so the
//! algebra lives here.
//!
//! The algebra is the one the machine-checked Lean spec
//! `CaveatLattice/ResolvedLattice.lean` proves for *all* inputs (newt-agent #1635):
//! `union` is a genuine least-upper-bound, admission is
//! `resolved ⊑ delegated ⊔ closure`, and a widening is *refused* — never filed
//! under a weaker enforcement strength.
//!
//! # Why this exists — the #317 audit finding
//!
//! The bounded-authority audit proved enforcement admitted a *wider* kernel scope
//! than the Caveat delegated, on **strength alone**: the admission witness carried
//! only per-axis enforcement *strength*, never the resolved *scope*, so INV-BOUND
//! (`effective ⊆ authorized`) could not even be expressed. Widening was folded into
//! a strength *downgrade*, which made a widening's refusal depend on where the
//! per-axis floor happened to sit rather than on the widening itself — the sh→bash
//! launcher widening was admitted while an identical loopback widening was refused.
//!
//! Here scope fidelity is a **first-class relation, orthogonal to strength**: a
//! `Widened` or `Unknown` axis is refused regardless of how strongly the mechanism
//! enforces it. Strength (INV-FLOOR) and scope (INV-BOUND) are separate obligations.
//!
//! This module changes no behavior on its own; it is the typed operand the live
//! admission/apply path is refactored onto next.

use std::collections::BTreeSet;

/// The resolved authority a native enforcement fence actually permits on one axis.
///
/// - `Bounded { concrete, classes }` — a finite set of concrete grants (exact
///   paths / hosts / program names) plus a set of *capability classes* (symbolic
///   ranges a mechanism permits atomically, e.g. a whole loopback interface, or
///   Windows' "any internetClient"). The two dimensions unite pointwise.
/// - `Unbounded` — the mechanism permits everything on this axis (top).
/// - `Unknown` — the projection could not decide what the mechanism permits;
///   admission treats this as fail-closed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResolvedScope {
    /// A concrete-plus-classes bounded scope.
    Bounded {
        /// Exact grants (paths, hosts, program names) the fence permits.
        concrete: BTreeSet<String>,
        /// Capability classes the fence permits (symbolic ranges).
        classes: BTreeSet<String>,
    },
    /// The mechanism permits everything on this axis.
    Unbounded,
    /// The resolved authority could not be decided (fail-closed).
    Unknown,
}

/// How a resolved scope relates to an authorized bound.
///
/// Admission accepts `Exact` and `Subset`; it refuses `Widened` (the resolved
/// scope exceeds the bound) and `Unknown` (undecidable ⇒ fail-closed).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScopeRelation {
    /// The resolved scope permits exactly the bound.
    Exact,
    /// The resolved scope permits strictly less than the bound.
    Subset,
    /// The resolved scope permits something outside the bound (a widening).
    Widened,
    /// The relation could not be decided (either side is `Unknown`).
    Unknown,
}

impl ResolvedScope {
    /// The bottom of the authority order: a bounded scope permitting nothing. It is
    /// the identity for [`ResolvedScope::union`] — `bottom ⊔ X ≈ X`.
    pub fn bottom() -> Self {
        ResolvedScope::Bounded {
            concrete: BTreeSet::new(),
            classes: BTreeSet::new(),
        }
    }

    /// The join (least upper bound). `Unknown` absorbs; else `Unbounded` absorbs;
    /// else the two `Bounded` dimensions unite pointwise. Mirrors the Lean
    /// `ResolvedLattice.union` and mesh #72's `ResolvedScope::union` exactly.
    pub fn union(&self, other: &ResolvedScope) -> ResolvedScope {
        use ResolvedScope::*;
        match (self, other) {
            (Unknown, _) | (_, Unknown) => Unknown,
            (Unbounded, _) | (_, Unbounded) => Unbounded,
            (
                Bounded {
                    concrete: c1,
                    classes: l1,
                },
                Bounded {
                    concrete: c2,
                    classes: l2,
                },
            ) => Bounded {
                concrete: c1.union(c2).cloned().collect(),
                classes: l1.union(l2).cloned().collect(),
            },
        }
    }

    /// Whether `self` is within `bound` on both dimensions — the conservative,
    /// fail-closed subset test. A concrete grant is **not** assumed covered by a
    /// class (that would need domain knowledge the lattice does not have), so a
    /// single address resolving to a whole-interface *class* reads as *not* within
    /// a concrete-only bound — exactly the widening we must refuse.
    fn within(&self, bound: &ResolvedScope) -> bool {
        use ResolvedScope::*;
        match (self, bound) {
            // Unknown never decides "within": fail-closed.
            (Unknown, _) | (_, Unknown) => false,
            // Everything is within Unbounded.
            (_, Unbounded) => true,
            // Unbounded is within nothing bounded.
            (Unbounded, Bounded { .. }) => false,
            (
                Bounded {
                    concrete: c1,
                    classes: l1,
                },
                Bounded {
                    concrete: c2,
                    classes: l2,
                },
            ) => c1.is_subset(c2) && l1.is_subset(l2),
        }
    }

    /// Classify how `self` (a resolved scope) relates to `bound` (an authorized
    /// bound). This is the pure projection admission reasons over.
    pub fn relate(&self, bound: &ResolvedScope) -> ScopeRelation {
        use ResolvedScope::*;
        if matches!(self, Unknown) || matches!(bound, Unknown) {
            return ScopeRelation::Unknown;
        }
        if self == bound {
            return ScopeRelation::Exact;
        }
        if self.within(bound) {
            ScopeRelation::Subset
        } else {
            ScopeRelation::Widened
        }
    }
}

/// The per-axis admission decision (INV-BOUND). A resolved fence axis is admitted
/// iff its resolved scope stays within the bound `delegated ⊔ closure` — i.e. the
/// relation is `Exact` or `Subset`. `Widened` and `Unknown` are refused.
///
/// `closure` is the *explicit, pre-authorized* runtime closure (loader paths, an
/// interpreter the grant implies, etc.). Extra authority may be admitted ONLY
/// because the closure authorizes it — never by silent widening. This is the
/// honest-parity mechanism the Lean `admits_via_closure` proves: `resolved ⊑
/// closure ⇒ admitted`, and `¬ (resolved ⊑ delegated ⊔ closure) ⇒ refused`.
pub fn admit_scope(
    resolved: &ResolvedScope,
    delegated: &ResolvedScope,
    closure: &ResolvedScope,
) -> ScopeRelation {
    let bound = delegated.union(closure);
    resolved.relate(&bound)
}

/// Whether a per-axis [`ScopeRelation`] may be admitted. `Exact`/`Subset` ⇒ yes;
/// `Widened`/`Unknown` ⇒ fail-closed refusal.
pub fn relation_admits(relation: ScopeRelation) -> bool {
    matches!(relation, ScopeRelation::Exact | ScopeRelation::Subset)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bounded(concrete: &[&str], classes: &[&str]) -> ResolvedScope {
        ResolvedScope::Bounded {
            concrete: concrete.iter().map(|s| s.to_string()).collect(),
            classes: classes.iter().map(|s| s.to_string()).collect(),
        }
    }

    // ----- join-semilattice laws (the same ones mesh #72 proptests and the Lean
    // ResolvedLattice proves; here as concrete regressions over the native type) -----

    #[test]
    fn bottom_is_the_union_identity() {
        let x = bounded(&["a", "b"], &["cls"]);
        assert_eq!(ResolvedScope::bottom().union(&x), x);
        assert_eq!(x.union(&ResolvedScope::bottom()), x);
    }

    #[test]
    fn union_is_commutative() {
        let a = bounded(&["a"], &[]);
        let b = bounded(&["b"], &["c"]);
        assert_eq!(a.union(&b), b.union(&a));
    }

    #[test]
    fn union_is_idempotent() {
        let a = bounded(&["a", "b"], &["c"]);
        assert_eq!(a.union(&a), a);
    }

    #[test]
    fn union_is_associative() {
        let a = bounded(&["a"], &[]);
        let b = bounded(&["b"], &[]);
        let c = bounded(&["c"], &["k"]);
        assert_eq!(a.union(&b).union(&c), a.union(&b.union(&c)));
    }

    #[test]
    fn unknown_propagates_through_union() {
        let a = bounded(&["a"], &[]);
        assert_eq!(ResolvedScope::Unknown.union(&a), ResolvedScope::Unknown);
        assert_eq!(a.union(&ResolvedScope::Unknown), ResolvedScope::Unknown);
    }

    #[test]
    fn unbounded_absorbs_bounded() {
        let a = bounded(&["a"], &[]);
        assert_eq!(ResolvedScope::Unbounded.union(&a), ResolvedScope::Unbounded);
        assert_eq!(a.union(&ResolvedScope::Unbounded), ResolvedScope::Unbounded);
    }

    #[test]
    fn union_is_an_upper_bound_no_widening() {
        // Each operand relates as Exact-or-Subset to the union (never Widened).
        let a = bounded(&["a"], &[]);
        let b = bounded(&["b"], &["k"]);
        let u = a.union(&b);
        assert!(relation_admits(a.relate(&u)));
        assert!(relation_admits(b.relate(&u)));
    }

    // ----- ScopeRelation classification -----

    #[test]
    fn exact_when_equal() {
        let a = bounded(&["sh"], &[]);
        assert_eq!(a.relate(&a), ScopeRelation::Exact);
    }

    #[test]
    fn subset_when_within() {
        let narrow = bounded(&["sh"], &[]);
        let wide = bounded(&["sh", "bash"], &[]);
        assert_eq!(narrow.relate(&wide), ScopeRelation::Subset);
    }

    #[test]
    fn widened_when_it_escapes_the_bound() {
        let resolved = bounded(&["sh", "bash"], &[]);
        let bound = bounded(&["sh"], &[]);
        assert_eq!(resolved.relate(&bound), ScopeRelation::Widened);
    }

    #[test]
    fn unbounded_resolved_widens_a_bounded_bound() {
        let bound = bounded(&["sh"], &[]);
        assert_eq!(
            ResolvedScope::Unbounded.relate(&bound),
            ScopeRelation::Widened
        );
    }

    #[test]
    fn anything_is_subset_of_unbounded_bound() {
        let resolved = bounded(&["sh"], &[]);
        assert_eq!(
            resolved.relate(&ResolvedScope::Unbounded),
            ScopeRelation::Subset
        );
    }

    #[test]
    fn unknown_on_either_side_is_unknown() {
        let a = bounded(&["a"], &[]);
        assert_eq!(a.relate(&ResolvedScope::Unknown), ScopeRelation::Unknown);
        assert_eq!(ResolvedScope::Unknown.relate(&a), ScopeRelation::Unknown);
    }

    #[test]
    fn a_concrete_grant_is_not_covered_by_a_class() {
        // The single-address → whole-interface widening: resolved carries a class
        // the concrete-only bound does not authorize ⇒ Widened (fail-closed).
        let resolved = bounded(&["127.0.0.1"], &["loopback-interface"]);
        let bound = bounded(&["127.0.0.1"], &[]);
        assert_eq!(resolved.relate(&bound), ScopeRelation::Widened);
    }

    // ----- admit_scope: the INV-BOUND decision the #317 audit needed -----

    #[test]
    fn sh_to_bash_launcher_widening_is_refused() {
        // exec grant Only{sh}; the Seatbelt profile resolves to permit {sh, bash}.
        // With no closure authorizing bash, this is a widening ⇒ refused. This is
        // the case #317 wrongly ADMITTED on strength alone.
        let delegated = bounded(&["sh"], &[]);
        let resolved = bounded(&["sh", "bash"], &[]);
        let no_closure = ResolvedScope::bottom();
        let rel = admit_scope(&resolved, &delegated, &no_closure);
        assert_eq!(rel, ScopeRelation::Widened);
        assert!(!relation_admits(rel));
    }

    #[test]
    fn loopback_full_interface_widening_is_refused() {
        // net grant Only{127.0.0.1}; the mechanism resolves to the whole loopback
        // interface (a class). Same widening pattern as sh→bash, same verdict —
        // refused — regardless of enforcement strength.
        let delegated = bounded(&["127.0.0.1"], &[]);
        let resolved = bounded(&["127.0.0.1"], &["loopback-interface"]);
        let no_closure = ResolvedScope::bottom();
        assert!(!relation_admits(admit_scope(
            &resolved,
            &delegated,
            &no_closure
        )));
    }

    #[test]
    fn extra_authority_is_admitted_only_via_an_explicit_closure() {
        // bash is admitted here — but ONLY because an explicit runtime closure
        // authorizes it (e.g. sh's launcher is a declared, minimal dependency),
        // never by silent widening. This is the honest-parity mechanism.
        let delegated = bounded(&["sh"], &[]);
        let resolved = bounded(&["sh", "bash"], &[]);
        let closure = bounded(&["bash"], &[]);
        assert!(relation_admits(admit_scope(
            &resolved, &delegated, &closure
        )));
    }

    #[test]
    fn a_fence_within_the_grant_alone_is_admitted() {
        let delegated = bounded(&["sh"], &[]);
        let resolved = bounded(&["sh"], &[]);
        assert_eq!(
            admit_scope(&resolved, &delegated, &ResolvedScope::bottom()),
            ScopeRelation::Exact
        );
    }

    #[test]
    fn an_unknown_resolution_fails_closed() {
        let delegated = bounded(&["sh"], &[]);
        assert!(!relation_admits(admit_scope(
            &ResolvedScope::Unknown,
            &delegated,
            &ResolvedScope::bottom()
        )));
    }

    #[test]
    fn an_unbounded_fence_over_a_bounded_grant_is_refused() {
        // audit row 16 — a ConfinedCommand whose fence resolves unbounded on an
        // axis the Caveat bounded ⇒ refused.
        let delegated = bounded(&["/workspace"], &[]);
        assert!(!relation_admits(admit_scope(
            &ResolvedScope::Unbounded,
            &delegated,
            &ResolvedScope::bottom()
        )));
    }
}
