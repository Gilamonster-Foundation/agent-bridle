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

/// Whether a single path entry reaches one of the harness-private stores — the
/// one canonical predicate every harness-disjoint check shares (the per-entry
/// declaration guard, the whole-closure lattice guard, and the backend's
/// object-identity check on a closure root's *canonical* form), so there is
/// exactly one definition of "harness-private" in the crate.
pub(crate) fn entry_reaches_harness_private(entry: &str) -> bool {
    // Treat each marker as a path-COMPONENT SEQUENCE, so a MULTI-segment marker
    // like `.config/gh` matches a path INSIDE it (`…/.config/gh/hosts.yml`) — a
    // per-segment match misses that (found by the PR-0b final adversarial pass).
    // Padding with separators keeps the match on component boundaries, so a
    // sibling like `/opt/newt-tools` does NOT match `.newt` and `/home/u/.sshfoo`
    // does NOT match `.ssh`.
    let padded = format!("/{}/", entry.trim_matches('/'));
    HARNESS_PRIVATE_MARKERS
        .iter()
        .any(|marker| padded.contains(&format!("/{}/", marker.trim_matches('/'))))
}

fn require_harness_disjoint(entry: &str) -> ToolResult<()> {
    if entry_reaches_harness_private(entry) {
        return Err(ToolError::denied(format!(
            "refusing closure entry {entry:?}: it reaches a harness-private store \
             (the runtime closure must be harness-disjoint)"
        )));
    }
    Ok(())
}

/// Whether a resolved-authority runtime closure is disjoint from harness-private
/// authority on the authority-bearing axes (fs_read / fs_write / exec) — the
/// whole-closure form of [`require_harness_disjoint`], used by [`AdmittedFence::admit`]
/// on the backend-declared closure. A `Bounded` axis passes iff no concrete entry
/// reaches a harness-private store; an `Unbounded`/`Unknown` axis is non-disjoint
/// by definition (it would authorize everything / cannot be decided) and so fails
/// closed — a closure may never launder unbounded or undecidable authority.
pub(crate) fn closure_is_harness_disjoint(closure: &ResolvedAuthority) -> bool {
    let axis_ok = |scope: &ResolvedScope| match scope {
        ResolvedScope::Bounded { concrete, .. } => concrete
            .iter()
            .all(|entry| !entry_reaches_harness_private(entry)),
        ResolvedScope::Unbounded | ResolvedScope::Unknown => false,
    };
    axis_ok(&closure.fs_read) && axis_ok(&closure.fs_write) && axis_ok(&closure.exec)
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
}

/// A backend's **conservative projection** of the caveats it is about to apply:
/// what the installed native fence actually permits a hostile child
/// (`resolved`), and the harness-added system substrate that permission
/// legitimately rests on (`runtime_closure`) — both as resolved-authority
/// lattice values, computed by the backend from the *same* routines its `apply`
/// uses (Q2 anti-drift). The L3 bound is `resolved ⊆ delegated ∪ runtime_closure`
/// computed over these — the **ruleset grain**, not the caveats grain.
///
/// This is the operand the #317 audit found missing: admission used to project
/// the *caveats* (`ResolvedAuthority::from_delegated(mechanism_caveats)`), which
/// is blind to authority the ruleset installs beyond the grant (e.g. Landlock's
/// `base_read` loader/library trees). A backend that cannot honestly bound an
/// axis returns `Unknown` on it here, and admission fails closed (L7).
#[derive(Debug, Clone)]
pub struct BackendProjection {
    /// What the fence actually permits — the conservative upper bound.
    pub resolved: ResolvedAuthority,
    /// The harness-added substrate the resolution rests on (loader/base-read/
    /// device sinks / the resolved program image). Must be harness-disjoint.
    pub runtime_closure: ResolvedAuthority,
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
    /// `All` axis already permits it), asks the backend to `project` what it will
    /// actually install for those caveats, then refuses unless ALL hold:
    ///
    /// 1. **L3 harness-disjoint:** the backend-declared runtime closure touches
    ///    no harness-private store and no undecidable axis
    ///    ([`closure_is_harness_disjoint`]).
    /// 2. **L3 scope (ruleset grain):** the backend's *resolved* authority — the
    ///    conservative upper bound on what the installed fence permits a hostile
    ///    child — is `⊆ delegated ∪ runtime_closure` over the resolved lattice
    ///    ([`admit`]). This is the #317 fix: the operand is the backend's real
    ///    projection ([`BackendProjection`]), not `from_delegated(mechanism_caveats)`,
    ///    so authority the ruleset installs beyond the grant (Landlock's
    ///    `base_read` loader/library trees; a symlinked grant root that resolves
    ///    `Unknown`) is *seen* and either declared-and-admitted or refused —
    ///    never silently permitted. Computed, never asserted.
    /// 3. **L4 strength:** every restricted axis of the *delegated* caveats meets
    ///    the principal's per-axis floor under the governing mechanism
    ///    ([`unenforceable_axis`]).
    ///
    /// `project` is called with the derived mechanism caveats and returns the
    /// backend's [`BackendProjection`]; it is the only place a `Sandbox`
    /// participates, so this module stays free of any backend dependency.
    ///
    /// # Errors
    /// [`ToolError::Denied`] with the axis and relation (scope), a harness-
    /// disjointness violation, or the typed unmet-floor reason (strength).
    pub fn admit(
        delegated: &Caveats,
        closure: RuntimeClosure,
        mechanism: ConfinementMechanism,
        floor: EnforcementFloor,
        project: impl FnOnce(&Caveats) -> BackendProjection,
    ) -> ToolResult<Self> {
        // THE one derivation (L2): delegated ∪ declared closure, exec axis.
        let mut mechanism_caveats = delegated.clone();
        if let Scope::Only(programs) = &mut mechanism_caveats.exec {
            programs.extend(closure.exec.iter().cloned());
        }

        // The backend's conservative projection of what it will ACTUALLY install
        // for these mechanism caveats (ruleset grain), plus the harness-added
        // substrate that projection rests on. Computed from the same routines the
        // backend's `apply` uses, so the ROOT-SET DERIVATION cannot independently
        // drift from the fence. (This is NOT native semantic fidelity: OS access
        // masks, path/symlink interpretation, aliases and deputies still need the
        // CompiledFence + AppliedFenceEvidence / native-hostile-test layer.)
        let projection = project(&mechanism_caveats);

        // L3 (a): the declared runtime closure must be harness-disjoint — it may
        // rest on system loader/base-read substrate but never the harness's own
        // stores, and never launder unbounded or undecidable authority.
        if !closure_is_harness_disjoint(&projection.runtime_closure) {
            return Err(ToolError::denied(
                "refusing to spawn: the backend runtime closure reaches harness-private \
                 authority or an undecidable axis (L3 BOUND: closure must be harness-disjoint)",
            ));
        }

        // L3 (b): computed ruleset-grain scope bound — the conservative resolved
        // authority ⊆ delegated ∪ runtime_closure. Superset/Incomparable/Unknown
        // refuse fail-closed (L7), independent of enforcement strength.
        match admit(&projection.resolved, delegated, &projection.runtime_closure) {
            AdmissionDecision::Admit => {}
            AdmissionDecision::Reject(reject) => {
                return Err(ToolError::denied(format!(
                    "refusing to spawn: backend authority on the {:?} axis is {} the \
                     delegated grant ∪ declared runtime closure (L3 BOUND)",
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
    use crate::provenance::empty_closure;
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

    fn exec_scope(programs: &[&str]) -> ResolvedScope {
        ResolvedScope::concrete(programs.iter().map(|s| s.to_string()))
    }

    /// A faithful projector: the fence installs exactly the (derived) caveats and
    /// declares no substrate — L3 admits by construction, isolating L2/L4.
    fn identity_projection(caveats: &Caveats) -> BackendProjection {
        BackendProjection {
            resolved: ResolvedAuthority::from_delegated(caveats),
            runtime_closure: empty_closure(),
        }
    }

    /// A faithful projector that DECLARES a folded trusted-worker exec entry in
    /// its runtime closure — mirroring a real allowlist backend (the resolved
    /// program image is both installed and declared).
    fn worker_projection(worker: &'static str) -> impl Fn(&Caveats) -> BackendProjection {
        move |caveats: &Caveats| BackendProjection {
            resolved: ResolvedAuthority::from_delegated(caveats),
            runtime_closure: ResolvedAuthority {
                exec: exec_scope(&[worker]),
                ..empty_closure()
            },
        }
    }

    // ── L3 (ruleset grain): the PROJECTION catches a widening the caveats hide ─

    #[test]
    fn a_backend_widening_beyond_the_declared_closure_is_refused() {
        // The #317 bug class at ruleset grain: the fence resolves to permit a
        // program (`/opt/extra`) the grant never named and no closure declares.
        // The conservative projection surfaces it; admission calls it a Superset —
        // the OLD `from_delegated(mechanism_caveats)` operand was blind to it.
        let delegated = exec_only(&["/usr/bin/git"]);
        let project = |caveats: &Caveats| BackendProjection {
            resolved: ResolvedAuthority {
                exec: exec_scope(&["/usr/bin/git", "/opt/extra"]),
                ..ResolvedAuthority::from_delegated(caveats)
            },
            runtime_closure: empty_closure(),
        };
        let err = AdmittedFence::admit(
            &delegated,
            RuntimeClosure::empty(),
            mechanism_none(),
            advisory_floor(),
            project,
        )
        .unwrap_err();
        let ToolError::Denied { reason } = err else {
            panic!("expected a denial")
        };
        assert!(
            reason.contains("Exec") && reason.contains("WIDENING"),
            "an undeclared ruleset widening must refuse as a Superset: {reason}"
        );
    }

    #[test]
    fn the_same_widening_is_admitted_when_the_runtime_closure_declares_it() {
        let delegated = exec_only(&["/usr/bin/git"]);
        let project = |caveats: &Caveats| BackendProjection {
            resolved: ResolvedAuthority {
                exec: exec_scope(&["/usr/bin/git", "/opt/extra"]),
                ..ResolvedAuthority::from_delegated(caveats)
            },
            runtime_closure: ResolvedAuthority {
                exec: exec_scope(&["/opt/extra"]),
                ..empty_closure()
            },
        };
        assert!(AdmittedFence::admit(
            &delegated,
            RuntimeClosure::empty(),
            mechanism_none(),
            advisory_floor(),
            project,
        )
        .is_ok());
    }

    #[test]
    fn an_unknown_resolved_axis_fails_closed_even_under_top_delegation() {
        // A backend that cannot honestly bound an axis returns Unknown; admission
        // refuses even under a top delegation (L7) — the live E1/E3 posture.
        let delegated = Caveats::top();
        let project = |caveats: &Caveats| BackendProjection {
            resolved: ResolvedAuthority {
                net: ResolvedScope::Unknown,
                ..ResolvedAuthority::from_delegated(caveats)
            },
            runtime_closure: empty_closure(),
        };
        assert!(AdmittedFence::admit(
            &delegated,
            RuntimeClosure::empty(),
            mechanism_none(),
            advisory_floor(),
            project,
        )
        .is_err());
    }

    // ── L2: one derivation — admit() output IS the applied caveats ───────────

    #[test]
    fn admitted_mechanism_caveats_are_the_grant_plus_exactly_the_declared_closure() {
        let delegated = exec_only(&["/usr/bin/git"]);
        let closure = RuntimeClosure::empty().with_exec("/opt/worker").unwrap();
        let admitted = AdmittedFence::admit(
            &delegated,
            closure,
            mechanism_none(),
            advisory_floor(),
            worker_projection("/opt/worker"),
        )
        .unwrap();
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
        let admitted = AdmittedFence::admit(
            &delegated,
            closure,
            mechanism_none(),
            advisory_floor(),
            identity_projection,
        )
        .unwrap();
        assert_eq!(admitted.mechanism_caveats().exec, Scope::top());
    }

    // ── Harness-disjointness: neither door can open the harness's stores ──────

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

    #[test]
    fn a_backend_runtime_closure_reaching_a_harness_store_refuses_at_admission() {
        // The whole-closure guard: even a backend-declared closure (not the exec
        // ledger) that reaches `.newt` is refused before the scope check.
        let delegated = exec_only(&["/usr/bin/git"]);
        let project = |_caveats: &Caveats| BackendProjection {
            resolved: ResolvedAuthority::from_delegated(&exec_only(&["/usr/bin/git"])),
            runtime_closure: ResolvedAuthority {
                fs_read: exec_scope(&["/home/u/.newt/ocap-store"]),
                ..empty_closure()
            },
        };
        let err = AdmittedFence::admit(
            &delegated,
            RuntimeClosure::empty(),
            mechanism_none(),
            advisory_floor(),
            project,
        )
        .unwrap_err();
        let ToolError::Denied { reason } = err else {
            panic!("expected a denial")
        };
        assert!(
            reason.contains("harness-private"),
            "a closure reaching the harness store must refuse: {reason}"
        );
    }

    #[test]
    fn closure_is_harness_disjoint_flags_unbounded_and_private() {
        assert!(closure_is_harness_disjoint(&empty_closure()));
        let mut private = empty_closure();
        private.fs_read = exec_scope(&["/home/u/.ssh/id_ed25519"]);
        assert!(!closure_is_harness_disjoint(&private));
        let mut unbounded = empty_closure();
        unbounded.exec = ResolvedScope::Unbounded;
        assert!(!closure_is_harness_disjoint(&unbounded));
    }

    #[test]
    fn harness_private_matcher_handles_multi_segment_markers_on_boundaries() {
        // A MULTI-segment marker (`.config/gh`) must match a path INSIDE it — a
        // per-segment check missed this (found by the PR-0b final adversarial pass).
        assert!(entry_reaches_harness_private(
            "/home/u/.config/gh/hosts.yml"
        ));
        assert!(entry_reaches_harness_private("/home/u/.config/gh"));
        // Single-segment markers still match on component boundaries.
        assert!(entry_reaches_harness_private("/home/u/.ssh/id_ed25519"));
        assert!(entry_reaches_harness_private("/home/u/.newt/ocap"));
        // …and do NOT false-positive on a mere prefix/sibling.
        assert!(!entry_reaches_harness_private("/opt/newt-tools/worker"));
        assert!(!entry_reaches_harness_private("/home/u/.sshfoo/x"));
        assert!(!entry_reaches_harness_private("/home/u/.config/ghi/x"));
    }

    // ── L4 still enforced through the same admission door ────────────────────

    #[test]
    fn the_strength_floor_still_refuses_through_admit() {
        // A kernel floor under a `None` mechanism must refuse (no backend). The
        // projection admits at L3 (identity), isolating the L4 strength refusal.
        let delegated = Caveats {
            fs_read: Scope::only(["/repo".to_string()]),
            ..Caveats::top()
        };
        let err = AdmittedFence::admit(
            &delegated,
            RuntimeClosure::empty(),
            mechanism_none(),
            EnforcementFloor::from_scalar(AxisEnforcement::Kernel),
            identity_projection,
        );
        assert!(err.is_err(), "kernel floor with no backend must refuse");
    }
}
