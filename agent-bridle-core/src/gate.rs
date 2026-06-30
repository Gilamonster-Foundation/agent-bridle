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

use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use crate::step_up::{
    Attestation, CallRequest, Challenge, Decision, DischargeAttempt, DischargeProvider,
    DischargeVerifier, StepUpPolicy,
};
use crate::{
    Caveats, CountBound, Sandbox, SandboxKind, Scope, Tool, ToolContext, ToolError, ToolResult,
};

/// Defensive cap on the freshness-window scan (ADR 0007 D4). The gate recomputes
/// the bound challenge once per generation in the window, so an unbounded
/// `freshness_generations` would be an unbounded loop. A discharge may be reused
/// for at most this many generations regardless of a larger requested window —
/// the cap **tightens** the window (fail-closed), never loosens it.
const MAX_FRESHNESS_WINDOW: u64 = 4096;

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
    /// Bound challenges already consumed by an accepted [`crate::Discharge`].
    /// Makes every verified human gesture **single-use** (replay-proof): a
    /// discharge re-presented after it first succeeded is denied. Interior-mutable
    /// like the budget so `authorize_with_discharge` keeps `&self`. ADR 0007 D4.
    consumed: Mutex<HashSet<[u8; 32]>>,
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
            consumed: Mutex::new(HashSet::new()),
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
            consumed: Mutex::new(HashSet::new()),
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

/// Step-up admission (human-presence capabilities) — see [`crate::step_up`].
///
/// [`Gate::evaluate`] is the pure entry point; when a step-up is owed it returns
/// [`Decision::NeedsDischarge`] without minting or charging. The caller obtains a
/// proof and re-presents it to [`Gate::authorize_with_discharge`]. The gate only
/// ever *verifies* a proof — it never performs the gesture (that is a host
/// capability, a sibling of [`Sandbox`](crate::Sandbox)).
impl Gate {
    /// Evaluate a call under a [`StepUpPolicy`] without performing any gesture.
    ///
    /// [`Decision::Allow`] (minted and charged) when no step-up is owed,
    /// [`Decision::NeedsDischarge`] (nothing minted or charged) when one is, and
    /// [`Decision::Deny`] on a generation or budget failure.
    pub fn evaluate(
        &self,
        tool: &dyn Tool,
        granted: &Caveats,
        request: &CallRequest,
        policy: &StepUpPolicy,
    ) -> Decision {
        let effective = granted.meet(&tool.required());
        if self.check_generation(granted).is_err() {
            return Decision::Deny(ToolError::Generation);
        }
        let required = policy.required_for(request);
        if required.demands_gesture() {
            return Decision::NeedsDischarge(required);
        }
        match self.charge_one(granted) {
            Ok(()) => Decision::Allow(ToolContext::mint(effective, self.sandbox_kind)),
            Err(e) => Decision::Deny(e),
        }
    }

    /// Admit a call that owes a step-up by verifying a [`Discharge`].
    ///
    /// Recomputes the bound [`Challenge`] from `request`, the gate's generation,
    /// and `nonce`, then asks `verifier` to check the proof. On success mints the
    /// context (least authority, exactly as [`Gate::authorize`]) and — when the
    /// policy demanded a record — returns a content-addressed [`Attestation`].
    /// Ordering matches `authorize`: deny on generation or verification *before*
    /// charging, so a rejected discharge consumes no call. With no step-up owed
    /// this degenerates to an ordinary authorize.
    pub fn authorize_with_discharge(
        &self,
        tool: &dyn Tool,
        granted: &Caveats,
        request: &CallRequest,
        policy: &StepUpPolicy,
        attempt: &DischargeAttempt,
    ) -> ToolResult<(ToolContext, Option<Attestation>)> {
        let effective = granted.meet(&tool.required());
        self.check_generation(granted)?;

        let required = policy.required_for(request);
        if !required.demands_gesture() {
            self.charge_one(granted)?;
            return Ok((ToolContext::mint(effective, self.sandbox_kind), None));
        }

        // Freshness window (ADR 0007 D4): accept a discharge bound to any
        // generation in `[generation - freshness_generations, generation]`.
        // Recompute the bound challenge across the window (newest first) and use
        // the one the discharge actually answers. If none match, fall back to the
        // current-generation challenge so the verifier yields the canonical "does
        // not answer this action's challenge" denial — which covers both a wrong
        // action/nonce and a too-stale gesture. `freshness_generations: 0` ⇒ only
        // the current generation is accepted (fresh-per-act). The window is
        // capped (MAX_FRESHNESS_WINDOW) to bound the scan, fail-closed.
        let content_id = request.content_id();
        let window = required.freshness_generations.min(MAX_FRESHNESS_WINDOW);
        let oldest = self.generation.saturating_sub(window);
        let expected = (oldest..=self.generation)
            .rev()
            .map(|g| Challenge::bind(&content_id, g, &attempt.nonce))
            .find(|c| c.as_bytes() == &attempt.discharge.challenge)
            .unwrap_or_else(|| Challenge::bind(&content_id, self.generation, &attempt.nonce));

        if let Err(reason) = attempt
            .verifier
            .verify(attempt.discharge, &required, &expected)
        {
            return Err(ToolError::denied(reason));
        }

        // Single-use (ADR 0007 D4): consume the bound challenge atomically,
        // *before* charging or minting, so a replay (same content_id+generation+
        // nonce) is denied and charges nothing — one gesture authorizes exactly
        // one act. The lock makes two concurrent identical discharges resolve to
        // exactly one success.
        {
            let mut consumed = self
                .consumed
                .lock()
                .expect("step-up consumed-challenge ledger mutex poisoned");
            if !consumed.insert(*expected.as_bytes()) {
                return Err(ToolError::denied("discharge already consumed (replay)"));
            }
        }

        let attestation = required.record.then(|| {
            Attestation::from_verified(
                &request.tool,
                &request.resource,
                attempt.discharge,
                self.generation,
            )
        });

        self.charge_one(granted)?;
        Ok((ToolContext::mint(effective, self.sandbox_kind), attestation))
    }

    /// Orchestrate the whole step-up sequence — evaluate, run the host ceremony,
    /// and authorize — so a host needs **one** call for the gated path.
    ///
    /// Computes the requirement for `request`; if no gesture is owed this
    /// degenerates to an ordinary [`Gate::authorize`] (with `None` for the
    /// attestation). Otherwise it runs the host's `provider` ceremony, supplying
    /// the gate's generation and the caller's single-use `nonce`, then forwards
    /// the produced proof to [`Gate::authorize_with_discharge`] — reusing that
    /// single verified mint path (this adds **no** second mint site).
    ///
    /// Fail-closed: a provider error (the human declined, no authenticator, a
    /// transport failure) returns [`ToolError::denied`] and mints/charges
    /// nothing. The gate still verifies the proof itself via `verifier` (the
    /// presence floor and the challenge binding); the provider is never trusted
    /// to self-attest (ADR 0007 D5), so a `verifier` that rejects a too-weak or
    /// mismatched proof still denies even when the provider returned `Ok`.
    #[allow(clippy::too_many_arguments)]
    pub fn authorize_step_up(
        &self,
        tool: &dyn Tool,
        granted: &Caveats,
        request: &CallRequest,
        policy: &StepUpPolicy,
        provider: &dyn DischargeProvider,
        verifier: &dyn DischargeVerifier,
        nonce: [u8; 32],
    ) -> ToolResult<(ToolContext, Option<Attestation>)> {
        let required = policy.required_for(request);
        if !required.demands_gesture() {
            // No step-up owed: the base authorize is the whole story.
            return self.authorize(tool, granted).map(|cx| (cx, None));
        }
        // Run the host ceremony. A failure is fail-closed — nothing minted or
        // charged, because we have not reached the mint path yet.
        let discharge = provider
            .obtain(request, &required, self.generation, &nonce)
            .map_err(ToolError::denied)?;
        let attempt = DischargeAttempt {
            nonce,
            discharge: &discharge,
            verifier,
        };
        // Reuse the single verified mint path. The gate re-checks presence and
        // the challenge binding regardless of what the provider claimed.
        self.authorize_with_discharge(tool, granted, request, policy, &attempt)
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
