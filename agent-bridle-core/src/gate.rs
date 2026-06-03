//! The [`Gate`] — the single mint site for [`ToolContext`].
//!
//! `authorize` is the choke point of the whole design (DESIGN §2). It:
//!
//! 1. confines the grant to the tool's declared need:
//!    `effective = granted.meet(tool.required())` — least authority, provably
//!    non-amplifying (the `meet` law is property-tested in agent-mesh-protocol);
//! 2. enforces the `max_calls` budget (charges one call, denies when exhausted);
//! 3. enforces `valid_for_generation` (denies if the gate's **generation
//!    counter** — a causal, NOT wall-clock, coordinate — is not in the grant's
//!    permitted set);
//! 4. mints a [`ToolContext`] from the effective caveats and the sandbox kind.
//!
//! Because `ToolContext` has no other constructor, step 4 is the only way a
//! tool can ever obtain the proof it needs to run.

use std::sync::atomic::{AtomicU64, Ordering};

use crate::{
    Caveats, CountBound, Sandbox, SandboxKind, Scope, Tool, ToolContext, ToolError, ToolResult,
};

/// The leash enforcer. One gate backs a session (or a sub-delegation); it
/// tracks the remaining call budget and the generation it is valid for.
///
/// The gate is interior-mutable on its budget (an [`AtomicU64`]) so `authorize`
/// takes `&self` — a registry can hold one shared gate behind an `Arc`.
pub struct Gate {
    /// Remaining calls that may still be charged. `None` ⇒ unlimited.
    remaining: Option<AtomicU64>,
    /// The causal generation this gate currently embodies (a counter, never a
    /// clock). A grant authorizes the gate only if this is in its
    /// `valid_for_generation` set.
    generation: u64,
    /// The OS-level sandbox stamped into every context this gate mints.
    sandbox_kind: SandboxKind,
}

impl Gate {
    /// A gate at `generation`, with no independent budget cap of its own (the
    /// grant's `max_calls` still applies on the first `authorize`) and the
    /// honest P0 sandbox kind ([`SandboxKind::None`]).
    #[must_use]
    pub fn new(generation: u64) -> Self {
        Self {
            remaining: None,
            generation,
            sandbox_kind: SandboxKind::None,
        }
    }

    /// A gate whose call budget is seeded from a [`CountBound`] — typically the
    /// `max_calls` of the session grant — so the budget persists across
    /// multiple `authorize` calls on this gate. `Unlimited` ⇒ no cap.
    #[must_use]
    pub fn with_budget(generation: u64, max_calls: CountBound) -> Self {
        let remaining = match max_calls {
            CountBound::Unlimited => None,
            CountBound::AtMost(n) => Some(AtomicU64::new(n)),
        };
        Self {
            remaining,
            generation,
            sandbox_kind: SandboxKind::None,
        }
    }

    /// Record the OS-level sandbox this gate's contexts run under. A tool reads
    /// it back via [`ToolContext::sandbox_kind`]. (P3 wires a real
    /// [`Sandbox`].)
    #[must_use]
    pub fn with_sandbox(mut self, sandbox: &dyn Sandbox) -> Self {
        self.sandbox_kind = sandbox.kind();
        self
    }

    /// The generation this gate embodies.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// The **only** path to a [`ToolContext`].
    ///
    /// See the module docs for the four enforcement steps. Order matters: we
    /// deny on authority/generation *before* charging the budget, so a denied
    /// request does not consume a call.
    pub fn authorize(&self, tool: &dyn Tool, granted: &Caveats) -> ToolResult<ToolContext> {
        // (1) Least-authority confinement. `required()` is a *ceiling the tool
        // promises to stay under*, defaulting to `top` ("confine me entirely by
        // the grant"). The meet is the greatest lower bound, so the tool can
        // never receive more than the grant *or* more than it declared:
        // `effective ⊑ granted` and `effective ⊑ required`, always. There is no
        // separate `required.leq(granted)` precondition — a tool declaring
        // `top` would spuriously fail it; confinement is the meet, and
        // per-operation denial happens later in the tool via the context's
        // `check_*` leash methods.
        let effective = granted.meet(&tool.required());

        // (2) Generation check (causal, not wall-clock). Checked before
        // charging so a denied request does not consume a call.
        self.check_generation(granted)?;

        // (3) Budget: charge exactly one call; deny (without charging) when
        // exhausted. The grant's own max_calls is honored even when this gate
        // carries no independent budget.
        self.charge_one(granted)?;

        // (4) The single mint site.
        Ok(ToolContext::mint(effective, self.sandbox_kind))
    }

    /// Deny unless this gate's generation is in the grant's
    /// `valid_for_generation` set (`All` ⇒ valid for every generation).
    fn check_generation(&self, granted: &Caveats) -> ToolResult<()> {
        let ok = match &granted.valid_for_generation {
            Scope::All => true,
            Scope::Only(set) => set.contains(&self.generation),
        };
        if ok {
            Ok(())
        } else {
            Err(ToolError::Generation)
        }
    }

    /// Charge one call against whichever budget is tighter: the gate's persisted
    /// remaining count (if any) or the grant's `max_calls` for this single
    /// dispatch. Returns [`ToolError::Budget`] when exhausted, **without**
    /// charging.
    fn charge_one(&self, granted: &Caveats) -> ToolResult<()> {
        // Per-dispatch floor from the grant: a grant of AtMost(0) is always
        // denied regardless of the gate's persisted budget.
        if let CountBound::AtMost(0) = granted.max_calls {
            return Err(ToolError::Budget);
        }

        match &self.remaining {
            None => Ok(()),
            Some(counter) => {
                // Compare-and-decrement so concurrent authorize calls cannot
                // over-spend the budget.
                loop {
                    let cur = counter.load(Ordering::Acquire);
                    if cur == 0 {
                        return Err(ToolError::Budget);
                    }
                    if counter
                        .compare_exchange_weak(cur, cur - 1, Ordering::AcqRel, Ordering::Acquire)
                        .is_ok()
                    {
                        return Ok(());
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ToolContext;

    struct NoopTool {
        required: Caveats,
    }
    #[async_trait::async_trait]
    impl Tool for NoopTool {
        fn name(&self) -> &str {
            "noop"
        }
        fn schema(&self) -> serde_json::Value {
            serde_json::json!({})
        }
        fn required(&self) -> Caveats {
            self.required.clone()
        }
        async fn invoke(
            &self,
            _args: serde_json::Value,
            _cx: &ToolContext,
        ) -> ToolResult<serde_json::Value> {
            Ok(serde_json::Value::Null)
        }
    }

    fn top_tool() -> NoopTool {
        NoopTool {
            required: Caveats::top(),
        }
    }

    #[test]
    fn effective_is_meet_and_leq_granted() {
        let granted = Caveats {
            exec: Scope::only(["echo".to_string(), "ls".to_string()]),
            max_calls: CountBound::AtMost(5),
            ..Caveats::top()
        };
        // Tool needs only `echo`.
        let tool = NoopTool {
            required: Caveats {
                exec: Scope::only(["echo".to_string()]),
                ..Caveats::top()
            },
        };
        let gate = Gate::new(0);
        let cx = gate.authorize(&tool, &granted).unwrap();
        // effective == granted.meet(required)
        assert_eq!(*cx.caveats(), granted.meet(&tool.required()));
        // effective ⊑ granted
        assert!(cx.caveats().leq(&granted));
        // and exec narrowed to the meet (just echo)
        assert_eq!(cx.caveats().exec, Scope::only(["echo".to_string()]));
    }

    #[test]
    fn effective_is_intersection_when_tool_declares_more_than_granted() {
        // Tool declares it may exec `rm`; session only granted `echo`. The meet
        // is the empty intersection, so the tool is authorized but effectively
        // can exec *nothing* — denial surfaces at the per-operation check, not
        // at authorize. This is the least-authority guarantee in action.
        let tool = NoopTool {
            required: Caveats {
                exec: Scope::only(["rm".to_string()]),
                ..Caveats::top()
            },
        };
        let granted = Caveats {
            exec: Scope::only(["echo".to_string()]),
            ..Caveats::top()
        };
        let gate = Gate::new(0);
        let cx = gate.authorize(&tool, &granted).expect("authorize succeeds");
        assert_eq!(cx.caveats().exec, Scope::none());
        assert!(cx.check_exec("rm").is_err());
        assert!(cx.check_exec("echo").is_err()); // not in the meet either
        assert!(cx.caveats().leq(&granted));
    }

    #[test]
    fn default_required_top_is_confined_by_grant() {
        // A tool that declares `required = top` (the default) must NOT be
        // denied under a restricted grant — it is confined *to* the grant.
        let granted = Caveats {
            exec: Scope::only(["echo".to_string()]),
            ..Caveats::top()
        };
        let gate = Gate::new(0);
        let cx = gate.authorize(&top_tool(), &granted).expect("authorize");
        assert_eq!(*cx.caveats(), granted); // meet(top, granted) == granted
    }

    #[test]
    fn budget_at_most_two_allows_two_then_denies() {
        let granted = Caveats::top();
        let gate = Gate::with_budget(0, CountBound::AtMost(2));
        assert!(gate.authorize(&top_tool(), &granted).is_ok());
        assert!(gate.authorize(&top_tool(), &granted).is_ok());
        let err = gate.authorize(&top_tool(), &granted).unwrap_err();
        assert!(matches!(err, ToolError::Budget));
    }

    #[test]
    fn grant_max_calls_zero_always_denied() {
        let granted = Caveats {
            max_calls: CountBound::AtMost(0),
            ..Caveats::top()
        };
        let gate = Gate::new(0);
        assert!(matches!(
            gate.authorize(&top_tool(), &granted).unwrap_err(),
            ToolError::Budget
        ));
    }

    #[test]
    fn generation_mismatch_denies() {
        // Gate is generation 7; grant only valid for generation 3.
        let gate = Gate::new(7);
        let granted = Caveats {
            valid_for_generation: Scope::only([3u64]),
            ..Caveats::top()
        };
        assert!(matches!(
            gate.authorize(&top_tool(), &granted).unwrap_err(),
            ToolError::Generation
        ));

        // Matching generation is allowed.
        let granted_ok = Caveats {
            valid_for_generation: Scope::only([7u64]),
            ..Caveats::top()
        };
        assert!(gate.authorize(&top_tool(), &granted_ok).is_ok());
    }

    #[test]
    fn denied_request_does_not_charge_budget() {
        // Generation mismatch should be checked before charging, so the budget
        // survives a denied authorize.
        let gate = Gate::with_budget(7, CountBound::AtMost(1));
        let bad = Caveats {
            valid_for_generation: Scope::only([3u64]),
            ..Caveats::top()
        };
        assert!(gate.authorize(&top_tool(), &bad).is_err());
        // Budget untouched: a valid grant still works.
        let good = Caveats::top();
        assert!(gate.authorize(&top_tool(), &good).is_ok());
    }
}
