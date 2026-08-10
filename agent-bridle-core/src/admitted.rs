//! admitted — the ONE admitted fence (L2 non-equivocation + L3 bound, live).
//!
//! The #317 bounded-authority audit's structural finding: admission analyzed
//! `effective`, but the spawn then applied a **re-derived, wider**
//! `mechanism_effective` (the trusted-worker exec addition) — so the object
//! admitted was not the object applied (L2), and the widening never met a
//! scope check (L3). Nineteen concrete violations shared that one shape.
//!
//! This module closes the shape generically, not site-by-site:
//!
//! * [`RuntimeClosure`] — the **explicit, minimal, harness-disjoint** ledger of
//!   authority the harness legitimately adds beyond the delegated grant
//!   (today: the trusted-worker executable). Anything the mechanism will be
//!   asked to permit that is not in the delegated caveats MUST be declared
//!   here; there is no other door.
//! * [`AdmittedFence`] — the one admission object. [`AdmittedFence::admit`]
//!   derives the mechanism caveats (delegated ∪ declared closure) **once**,
//!   checks the per-axis strength floor ([`unenforceable_axis`], L4) and the
//!   per-axis scope bound (`admit` over the resolved-authority lattice —
//!   `resolved ⊆ delegated ∪ closure`, L3) — and only then hands out the
//!   caveats the sandbox may apply. The spawn path holds no other derivation:
//!   what was analyzed is what is applied (L2).
//!
//! Fail-closed (L7): an undeclared widening admits as `Superset` and refuses;
//! a closure entry into the harness's own private stores refuses at
//! declaration time; an unresolvable comparison refuses.

use std::collections::BTreeSet;
use std::path::Path;

use crate::provenance::{
    admit, AdmissionDecision, ResolvedAuthority, ResolvedScope, ScopeRelation,
};
use crate::{
    unenforceable_axis, Caveats, ConfinementMechanism, EnforcementFloor, Scope, ToolError,
    ToolResult,
};

/// Path fragments that name the harness's own secret/private stores. A closure
/// entry that would make any of these child-visible is refused at declaration
/// time — the closure is *harness-disjoint* by definition (the OCAP store, key
/// material, and agent state are the harness's authority, never the child's).
const HARNESS_PRIVATE_MARKERS: &[&str] = &[".newt", ".ssh", ".gnupg", ".aws", ".config/gh"];

fn require_harness_disjoint(entry: &str) -> ToolResult<()> {
    for marker in HARNESS_PRIVATE_MARKERS {
        if entry
            .split('/')
            .any(|segment| segment == *marker || entry.ends_with(marker))
        {
            return Err(ToolError::denied(format!(
                "refusing closure entry {entry:?}: it reaches the harness-private \
                 store {marker:?} (the runtime closure must be harness-disjoint)"
            )));
        }
    }
    Ok(())
}

/// The explicit, minimal, harness-disjoint authority the harness adds beyond
/// the delegated grant — L3's `authorized_closure` operand, as a ledger.
///
/// Empty by default: the common spawn adds nothing. Each entry is refused at
/// declaration time if it reaches a harness-private store.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuntimeClosure {
    exec: BTreeSet<String>,
}

impl RuntimeClosure {
    /// The empty closure — the harness adds nothing beyond the grant.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Declare one executable the harness adds to the mechanism's exec
    /// allow-list (e.g. the fixed trusted-worker binary). Canonicalized by the
    /// caller; refused here if it reaches a harness-private store.
    ///
    /// # Errors
    /// [`ToolError::Denied`] when the entry violates harness-disjointness.
    pub fn with_exec(mut self, program: impl Into<String>) -> ToolResult<Self> {
        let program = program.into();
        require_harness_disjoint(&program)?;
        self.exec.insert(program);
        Ok(self)
    }

    /// Whether this closure declares nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.exec.is_empty()
    }

    /// The closure as a resolved-authority operand for the L3 scope check.
    fn to_resolved(&self) -> ResolvedAuthority {
        ResolvedAuthority {
            fs_read: ResolvedScope::empty(),
            fs_write: ResolvedScope::empty(),
            exec: ResolvedScope::concrete(self.exec.iter().cloned()),
            net: ResolvedScope::empty(),
        }
    }
}

/// The pure L3 scope admission for a spawn: is every axis of what the
/// mechanism will actually be asked to permit (`mechanism_caveats`) within
/// `delegated ∪ closure`? Factored out of [`AdmittedFence::admit`] so the
/// refusal is directly testable against a hand-widened mechanism — the exact
/// bug class the audit found (a widening living only in the mechanism copy).
pub(crate) fn scope_admission(
    mechanism_caveats: &Caveats,
    delegated: &Caveats,
    closure: &RuntimeClosure,
) -> AdmissionDecision {
    let resolved = ResolvedAuthority::from_delegated(mechanism_caveats);
    admit(&resolved, delegated, &closure.to_resolved())
}

/// The one admitted fence: delegated authority + declared closure + governing
/// mechanism, with the mechanism caveats derived exactly once at admission.
///
/// Constructible only via [`AdmittedFence::admit`], which is where the L3 scope
/// bound and the L4 strength floor are both checked — so holding an
/// `AdmittedFence` *is* the proof that what the sandbox will apply was
/// admitted. The spawn path consumes [`Self::mechanism_caveats`] for both the
/// wrapper prefix and `apply`; it performs no further derivation (L2).
#[derive(Debug, Clone)]
pub struct AdmittedFence {
    mechanism: ConfinementMechanism,
    mechanism_caveats: Caveats,
}

impl AdmittedFence {
    /// Admit a spawn fence, fail-closed.
    ///
    /// Derives the mechanism caveats as `delegated ∪ closure` on the exec axis
    /// (a closure entry is inserted only into a restricted `Only(_)` scope — an
    /// `All` axis already permits it), then refuses unless BOTH hold:
    ///
    /// 1. **L3 scope:** every axis of the derived mechanism caveats is
    ///    `⊆ delegated ∪ closure` over the resolved lattice ([`admit`]). With
    ///    the derivation above this holds by construction — the check is kept
    ///    live so any future derivation change that widens beyond the declared
    ///    closure refuses instead of shipping (computed, never asserted).
    /// 2. **L4 strength:** every restricted axis of the *delegated* caveats
    ///    meets the principal's per-axis floor under the governing mechanism
    ///    ([`unenforceable_axis`]).
    ///
    /// # Errors
    /// [`ToolError::Denied`] with the axis and relation (scope) or the typed
    /// unmet-floor reason (strength).
    pub fn admit(
        delegated: &Caveats,
        closure: RuntimeClosure,
        mechanism: ConfinementMechanism,
        floor: EnforcementFloor,
    ) -> ToolResult<Self> {
        // THE one derivation (L2): delegated ∪ declared closure, exec axis.
        let mut mechanism_caveats = delegated.clone();
        if let Scope::Only(programs) = &mut mechanism_caveats.exec {
            programs.extend(closure.exec.iter().cloned());
        }

        // L3: computed scope bound. By construction this admits today; it is
        // the live guard that keeps every future mechanism-derivation change
        // inside `delegated ∪ closure`.
        match scope_admission(&mechanism_caveats, delegated, &closure) {
            AdmissionDecision::Admit => {}
            AdmissionDecision::Reject(reject) => {
                return Err(ToolError::denied(format!(
                    "refusing to spawn: mechanism authority on the {:?} axis is {} the \
                     delegated grant ∪ declared closure (L3 BOUND)",
                    reject.axis,
                    match reject.relation {
                        ScopeRelation::Superset => "a WIDENING of",
                        ScopeRelation::Incomparable => "incomparable with",
                        ScopeRelation::Unknown => "not decidable against",
                        // Equal/Subset admit; unreachable in a reject.
                        _ => "outside",
                    },
                )));
            }
        }

        // L4: per-axis strength floor over the delegated (restricted) axes.
        if let Some(unmet) = unenforceable_axis(delegated, mechanism, floor) {
            return Err(ToolError::denied(format!(
                "refusing to spawn: {unmet} (governing sandbox: {:?})",
                mechanism.kind()
            )));
        }

        Ok(Self {
            mechanism,
            mechanism_caveats,
        })
    }

    /// The caveats the sandbox applies — the SAME object that was admitted.
    #[must_use]
    pub fn mechanism_caveats(&self) -> &Caveats {
        &self.mechanism_caveats
    }

    /// The governing mechanism this fence was admitted under.
    #[must_use]
    pub fn mechanism(&self) -> ConfinementMechanism {
        self.mechanism
    }
}

/// Canonicalize a trusted-worker program path for a closure declaration.
///
/// # Errors
/// [`ToolError::Denied`] when the path cannot be resolved (a worker we cannot
/// name exactly is a worker we refuse to authorize).
pub(crate) fn canonical_closure_program(program: &str) -> ToolResult<String> {
    Ok(Path::new(program)
        .canonicalize()
        .map_err(|error| ToolError::denied(format!("cannot resolve trusted worker: {error}")))?
        .to_string_lossy()
        .into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provenance::ConfinedAxis;
    use crate::{AxisEnforcement, ChildNetworkPolicy, SandboxKind};

    fn exec_only(programs: &[&str]) -> Caveats {
        Caveats {
            exec: Scope::only(programs.iter().map(|s| s.to_string())),
            ..Caveats::top()
        }
    }

    fn advisory_floor() -> EnforcementFloor {
        EnforcementFloor::from_scalar(AxisEnforcement::Advisory)
    }

    fn mechanism_none() -> ConfinementMechanism {
        ConfinementMechanism::new(SandboxKind::None, ChildNetworkPolicy::LandlockOnly)
    }

    // ── L3: the scope admission catches the audit's bug class ────────────────

    #[test]
    fn a_mechanism_widening_not_declared_in_the_closure_is_refused() {
        // The OLD bug, reconstructed: the mechanism copy silently carries an
        // executable (the worker) that neither the grant nor any declared
        // closure names. The scope admission must call it a Superset.
        let delegated = exec_only(&["/usr/bin/git"]);
        let mut widened = delegated.clone();
        if let Scope::Only(p) = &mut widened.exec {
            p.insert("/opt/worker".into());
        }
        match scope_admission(&widened, &delegated, &RuntimeClosure::empty()) {
            AdmissionDecision::Reject(reject) => {
                assert_eq!(reject.axis, ConfinedAxis::Exec);
                assert_eq!(reject.relation, ScopeRelation::Superset);
            }
            AdmissionDecision::Admit => panic!("an undeclared widening must refuse"),
        }
    }

    #[test]
    fn the_same_widening_is_admitted_when_the_closure_declares_it() {
        let delegated = exec_only(&["/usr/bin/git"]);
        let mut widened = delegated.clone();
        if let Scope::Only(p) = &mut widened.exec {
            p.insert("/opt/worker".into());
        }
        let closure = RuntimeClosure::empty().with_exec("/opt/worker").unwrap();
        assert!(matches!(
            scope_admission(&widened, &delegated, &closure),
            AdmissionDecision::Admit
        ));
    }

    // ── L2: one derivation — admit() output IS the applied caveats ───────────

    #[test]
    fn admitted_mechanism_caveats_are_the_grant_plus_exactly_the_declared_closure() {
        let delegated = exec_only(&["/usr/bin/git"]);
        let closure = RuntimeClosure::empty().with_exec("/opt/worker").unwrap();
        let admitted =
            AdmittedFence::admit(&delegated, closure, mechanism_none(), advisory_floor()).unwrap();
        assert_eq!(
            admitted.mechanism_caveats().exec,
            Scope::only(["/usr/bin/git".to_string(), "/opt/worker".to_string()])
        );
        // No other axis moved.
        assert_eq!(admitted.mechanism_caveats().fs_read, delegated.fs_read);
        assert_eq!(admitted.mechanism_caveats().net, delegated.net);
    }

    #[test]
    fn an_unrestricted_exec_axis_takes_no_closure_entries() {
        // `All` already permits the worker; inserting into it is meaningless
        // and the derivation must not manufacture a restriction.
        let delegated = Caveats::top();
        let closure = RuntimeClosure::empty().with_exec("/opt/worker").unwrap();
        let admitted =
            AdmittedFence::admit(&delegated, closure, mechanism_none(), advisory_floor()).unwrap();
        assert_eq!(admitted.mechanism_caveats().exec, Scope::top());
    }

    // ── Harness-disjointness: the closure can never open the harness's stores ─

    #[test]
    fn a_closure_entry_reaching_a_harness_private_store_is_refused() {
        for entry in [
            "/Users/u/.newt/ocap-store/worker",
            "/home/u/.ssh/helper",
            "/home/u/.gnupg/agent",
        ] {
            assert!(
                RuntimeClosure::empty().with_exec(entry).is_err(),
                "{entry} must be refused"
            );
        }
        // A benign sibling is fine.
        assert!(RuntimeClosure::empty()
            .with_exec("/opt/newt-tools/worker")
            .is_ok());
    }

    // ── L4 still enforced through the same admission door ────────────────────

    #[test]
    fn the_strength_floor_still_refuses_through_admit() {
        // A kernel floor under a `None` mechanism must refuse (no backend).
        let delegated = Caveats {
            fs_read: Scope::only(["/repo".to_string()]),
            ..Caveats::top()
        };
        let err = AdmittedFence::admit(
            &delegated,
            RuntimeClosure::empty(),
            mechanism_none(),
            EnforcementFloor::from_scalar(AxisEnforcement::Kernel),
        );
        assert!(err.is_err(), "kernel floor with no backend must refuse");
    }
}
