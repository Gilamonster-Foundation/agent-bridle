//! The [`Registry`] — explicit-builder tool catalog + leashed dispatch.
//!
//! Explicit registration is the **default** (DESIGN §5): newt's release profile
//! is `strip=true` + `lto="thin"`, the verified real-world trigger for linker
//! DCE silently dropping an `inventory`-self-registered tool from `tools/list`.
//! A `Registry::builder().tool(...).build()` is immune because every tool is
//! referenced by an explicit anchor symbol. We deliberately do **not** use
//! `inventory` in P0.

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use crate::gate::DEFAULT_STRENGTH_FLOOR;
use crate::{
    AxisEnforcement, CallRequest, Caveats, CountBound, DischargeProvider, DischargeVerifier, Gate,
    StepUpPolicy, Tool, ToolContext, ToolError, ToolResult,
};

/// An unforgeable, opaque grant identity minted by a [`Registry`]. It keys the
/// persistent per-grant call-budget ledger (AB-001, #264), so a grant's
/// `max_calls` is enforced **across** dispatches — not reset every call. Its
/// constructor is private, so a caller cannot forge one; and every mint yields a
/// fresh id, so two grants with *equal caveats* get **independent** budgets (the
/// ledger is keyed by identity, never by serialized caveats).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct GrantId(u64);

/// A minted grant: authority ([`Caveats`]) bound to an unforgeable [`GrantId`].
/// Pass it to [`Registry::dispatch`] and **reuse it across calls** so the call
/// budget persists — mint it once per session (`Registry::mint_grant`), not per
/// call. Minting a fresh grant per call gives per-call budget semantics.
#[derive(Clone, Debug)]
pub struct Grant {
    id: GrantId,
    caveats: Caveats,
}

impl Grant {
    /// The authority this grant carries.
    #[must_use]
    pub fn caveats(&self) -> &Caveats {
        &self.caveats
    }

    /// The grant's opaque, unforgeable identity.
    #[must_use]
    pub fn id(&self) -> GrantId {
        self.id
    }
}

/// Optional step-up enforcement wired into [`Registry::dispatch`] (ADR 0018 R2 /
/// ADR 0007). When present, dispatch runs the gate's step-up ceremony
/// (`evaluate → obtain → authorize_with_discharge`) instead of a plain
/// `authorize`, so a host-designated HIGH-consequence call demands a human
/// gesture on the **default** path — and even while *unbridled* (the human gate
/// is orthogonal to the capability axis, ADR 0018 D8). A refused/failed gesture
/// is a fail-closed denial; nothing is minted or charged. Absent ⇒ today's
/// behavior (no gestures).
struct StepUp {
    policy: StepUpPolicy,
    provider: Arc<dyn DischargeProvider + Send + Sync>,
    verifier: Arc<dyn DischargeVerifier + Send + Sync>,
}

/// A catalog of tools that dispatches through the leash.
///
/// Each [`Registry::dispatch`] looks up the named tool, has a fresh [`Gate`]
/// authorize it against the supplied grant (the single mint site), then runs
/// it. A registry has no ambient authority of its own — all authority flows in
/// per-dispatch as the `granted` caveats.
pub struct Registry {
    tools: BTreeMap<String, Arc<dyn Tool>>,
    /// The causal generation dispatched gates embody. Defaults to 0; set via
    /// [`RegistryBuilder::generation`]. A *counter*, never a clock.
    generation: u64,
    /// Optional step-up enforcement on the dispatch path (`None` ⇒ today's plain
    /// authorize). Set via [`RegistryBuilder::step_up`].
    step_up: Option<StepUp>,
    /// Monotonic single-use nonce counter for the step-up ceremony. Core is
    /// rng-less; a per-registry counter is single-use *across* dispatches, which
    /// is what anti-replay needs here — the gate binds `challenge(action,
    /// generation, nonce)`, so a fresh nonce makes a captured discharge invalid on
    /// any later call. (A host wanting unpredictable nonces runs its own ceremony.)
    step_up_nonce: AtomicU64,
    /// Monotonic grant-id counter. Core is rng-less (like `step_up_nonce`); the
    /// private [`GrantId`] constructor is the unforgeability guarantee, and a
    /// counter gives every mint a distinct id (⇒ independent budgets).
    grant_counter: AtomicU64,
    /// AB-001 (#264): the **persistent** per-grant call-budget ledger, keyed by
    /// the grant's unforgeable id. `None` ⇒ unlimited; `Some(n)` ⇒ n calls
    /// remaining. Seeded create-on-first-use from the grant's `max_calls`, and
    /// charged under the lock so concurrent dispatches cannot overspend.
    ledger: Mutex<HashMap<GrantId, Option<u64>>>,
}

impl Registry {
    /// Start building a registry with explicit tool registration.
    #[must_use]
    pub fn builder() -> RegistryBuilder {
        RegistryBuilder::default()
    }

    /// The MCP `tools/list` payload: one object per tool with `name`,
    /// `description`-free `inputSchema`. (Descriptions are a frontend concern.)
    #[must_use]
    pub fn tool_definitions(&self) -> Vec<serde_json::Value> {
        self.tools
            .values()
            .map(|t| {
                serde_json::json!({
                    "name": t.name(),
                    "inputSchema": t.schema(),
                })
            })
            .collect()
    }

    /// The set of registered tool names (sorted). Used by the CI presence test.
    #[must_use]
    pub fn tool_names(&self) -> Vec<&str> {
        self.tools.keys().map(String::as_str).collect()
    }

    /// Whether a tool is registered under `name`.
    #[must_use]
    pub fn contains(&self, name: &str) -> bool {
        self.tools.contains_key(name)
    }

    /// Mint a [`Grant`] from `caveats`. **Reuse the returned grant across calls**
    /// so the `max_calls` budget persists — mint once per session, not per call
    /// (AB-001, #264). Two grants minted from equal caveats have distinct ids and
    /// therefore **independent** budgets.
    #[must_use]
    pub fn mint_grant(&self, caveats: Caveats) -> Grant {
        Grant {
            id: GrantId(self.grant_counter.fetch_add(1, Ordering::Relaxed)),
            caveats,
        }
    }

    /// Dispatch `name` with `args`, enforced by the leash, charging `grant`'s
    /// persistent call budget.
    ///
    /// The `grant` is authorized (minting the [`crate::ToolContext`] the tool
    /// needs); if authorization is denied, the tool never runs and nothing is
    /// charged. Reuse the same grant across calls for a cross-dispatch budget.
    pub async fn dispatch(
        &self,
        name: &str,
        args: serde_json::Value,
        grant: &Grant,
    ) -> ToolResult<serde_json::Value> {
        self.dispatch_with_strength_floor(name, args, grant, DEFAULT_STRENGTH_FLOOR)
            .await
    }

    /// Dispatch `name` with an explicit minimum confinement strength.
    ///
    /// This is the strong-principal form of [`Self::dispatch`]. The selected
    /// floor is stamped into the unforgeable [`crate::ToolContext`] at the
    /// gate's mint site and follows delegated trusted-worker requests. A
    /// subprocess boundary then refuses to launch if any restricted axis would
    /// fall below that floor. This closes the gap between a host's prospective
    /// enforcement check and the backend actually governing execution.
    pub async fn dispatch_with_strength_floor(
        &self,
        name: &str,
        args: serde_json::Value,
        grant: &Grant,
        strength_floor: AxisEnforcement,
    ) -> ToolResult<serde_json::Value> {
        let tool = self
            .tools
            .get(name)
            .ok_or_else(|| ToolError::not_found(name))?
            .clone();

        // AB-001 (#264): charge the PERSISTENT per-grant budget first. Under the
        // ledger lock, so concurrent dispatches on one grant cannot overspend.
        self.charge_grant(grant)?;

        // Authorize (generation / step-up / strength-floor). A pre-invoke error
        // means the tool never ran, so refund the charge unconditionally.
        let cx = match self.authorize_grant(tool.as_ref(), grant.caveats(), name, strength_floor) {
            Ok(cx) => cx,
            Err(e) => {
                self.refund_grant(grant);
                return Err(e);
            }
        };

        // Budget is spent only on an *admitted* call. A policy denial — whether
        // at the gate above or inside the tool when it refuses a specific
        // argument on authority grounds (`ToolError::Denied`) — performed no
        // effect, so it costs nothing. A tool that ran and *failed*
        // (`ToolError::Failed`) or timed out stays charged.
        let result = tool.invoke(args, &cx).await;
        if matches!(result, Err(ToolError::Denied { .. })) {
            self.refund_grant(grant);
        }
        result
    }

    /// Authorize `granted` for `tool` through a fresh gate — plain or via the
    /// step-up ceremony. The gate carries NO call budget: the persistent budget
    /// lives in the registry ledger ([`Self::charge_grant`]), so it is enforced
    /// across dispatches rather than reset on each per-dispatch gate.
    fn authorize_grant(
        &self,
        tool: &dyn Tool,
        granted: &Caveats,
        name: &str,
        strength_floor: AxisEnforcement,
    ) -> ToolResult<ToolContext> {
        let gate = Gate::with_budget(self.generation, CountBound::Unlimited)
            .with_strength_floor(strength_floor);
        match &self.step_up {
            // Step-up wired in (ADR 0018 R2): a policy-demanded gesture is
            // obtained + verified before minting; a refusal is a fail-closed
            // denial. The gate stays the single mint site.
            Some(su) => {
                let request = CallRequest::unspecified(name);
                // Fresh single-use nonce per ceremony (monotonic counter → the
                // gate's bound challenge differs each call, defeating replay).
                let mut nonce = [0u8; 32];
                let n = self.step_up_nonce.fetch_add(1, Ordering::Relaxed);
                nonce[..8].copy_from_slice(&n.to_le_bytes());
                let (cx, _attestation) = gate.authorize_step_up(
                    tool,
                    granted,
                    &request,
                    &su.policy,
                    su.provider.as_ref(),
                    su.verifier.as_ref(),
                    nonce,
                )?;
                Ok(cx)
            }
            None => gate.authorize(tool, granted),
        }
    }

    /// Charge one call against `grant`'s persistent budget, seeding it
    /// create-on-first-use from the grant's `max_calls`. `Unlimited` never
    /// exhausts; `AtMost(0)` (or a spent budget) is a fail-closed
    /// [`ToolError::Budget`]. Held under the ledger lock so concurrent charges
    /// cannot overspend.
    fn charge_grant(&self, grant: &Grant) -> ToolResult<()> {
        let mut ledger = self.ledger.lock().expect("grant ledger mutex poisoned");
        let remaining = ledger
            .entry(grant.id)
            .or_insert_with(|| match grant.caveats.max_calls {
                CountBound::AtMost(n) => Some(n),
                CountBound::Unlimited => None,
            });
        match remaining {
            None => Ok(()),
            Some(0) => Err(ToolError::Budget),
            Some(n) => {
                *n -= 1;
                Ok(())
            }
        }
    }

    /// Return a charge that did not result in an admitted call (a denied
    /// authorize) to `grant`'s budget.
    fn refund_grant(&self, grant: &Grant) {
        let mut ledger = self.ledger.lock().expect("grant ledger mutex poisoned");
        if let Some(Some(n)) = ledger.get_mut(&grant.id) {
            *n += 1;
        }
    }
}

/// Explicit builder for a [`Registry`]. The supported, DCE-proof registration
/// path.
#[derive(Default)]
pub struct RegistryBuilder {
    tools: BTreeMap<String, Arc<dyn Tool>>,
    generation: u64,
    step_up: Option<StepUp>,
}

impl RegistryBuilder {
    /// Register a tool. A later registration with the same name replaces an
    /// earlier one.
    #[must_use]
    pub fn tool(mut self, tool: Arc<dyn Tool>) -> Self {
        self.tools.insert(tool.name().to_string(), tool);
        self
    }

    /// Set the causal generation dispatched gates will embody (default 0).
    #[must_use]
    pub fn generation(mut self, generation: u64) -> Self {
        self.generation = generation;
        self
    }

    /// Enforce **step-up** on the dispatch path (ADR 0018 R2 / ADR 0007): a
    /// policy-demanded human gesture is obtained via `provider`, verified by
    /// `verifier`, and required before the tool runs — on the default path and
    /// even while unbridled. Omit to keep today's gesture-free dispatch.
    #[must_use]
    pub fn step_up(
        mut self,
        policy: StepUpPolicy,
        provider: Arc<dyn DischargeProvider + Send + Sync>,
        verifier: Arc<dyn DischargeVerifier + Send + Sync>,
    ) -> Self {
        self.step_up = Some(StepUp {
            policy,
            provider,
            verifier,
        });
        self
    }

    /// Finish building.
    #[must_use]
    pub fn build(self) -> Registry {
        Registry {
            tools: self.tools,
            generation: self.generation,
            step_up: self.step_up,
            step_up_nonce: AtomicU64::new(0),
            grant_counter: AtomicU64::new(0),
            ledger: Mutex::new(HashMap::new()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CountBound, Scope, ToolContext};

    /// A tool that records that it ran and echoes its `program` arg back, but
    /// only after the leash lets it exec that program.
    struct ProbeTool;
    #[async_trait::async_trait]
    impl Tool for ProbeTool {
        fn name(&self) -> &str {
            "probe"
        }
        fn schema(&self) -> serde_json::Value {
            serde_json::json!({ "type": "object" })
        }
        async fn invoke(
            &self,
            args: serde_json::Value,
            cx: &ToolContext,
        ) -> ToolResult<serde_json::Value> {
            let program = args["program"].as_str().unwrap_or("");
            cx.check_exec(program)?;
            Ok(serde_json::json!({ "ran": program }))
        }
    }

    /// A tool whose only action is to cross a subprocess boundary. The fake
    /// path must never reach the OS when the requested strength exceeds the
    /// governing backend.
    struct SpawnProbeTool;
    #[async_trait::async_trait]
    impl Tool for SpawnProbeTool {
        fn name(&self) -> &str {
            "spawn_probe"
        }

        fn schema(&self) -> serde_json::Value {
            serde_json::json!({ "type": "object" })
        }

        async fn invoke(
            &self,
            _args: serde_json::Value,
            cx: &ToolContext,
        ) -> ToolResult<serde_json::Value> {
            crate::ConfinedCommand::new("agent-bridle-strength-floor-must-refuse").spawn(cx)?;
            panic!("a backend downgrade must be refused before process creation")
        }
    }

    fn reg() -> Registry {
        Registry::builder().tool(Arc::new(ProbeTool)).build()
    }

    /// Minimal no-dependency `block_on`. `agent-bridle-core` deliberately does
    /// NOT depend on tokio (the dep budget is the leanness win, DESIGN §3), so
    /// these async-dispatch tests drive the future with a tiny std-only
    /// executor. The futures here complete synchronously (no real I/O), so a
    /// noop-waker poll loop is sufficient.
    fn block_on<F: std::future::Future>(fut: F) -> F::Output {
        use std::task::{Context, Poll, Waker};
        // The crate forbids `unsafe`, so we use the safe `Waker::noop()`
        // (stable since 1.85) rather than hand-rolling a RawWaker vtable.
        let mut cx = Context::from_waker(Waker::noop());
        let mut fut = std::pin::pin!(fut);
        loop {
            match fut.as_mut().poll(&mut cx) {
                Poll::Ready(out) => return out,
                Poll::Pending => std::thread::yield_now(),
            }
        }
    }

    #[test]
    fn dispatch_unknown_tool_is_not_found() {
        let r = reg();
        let grant = r.mint_grant(Caveats::top());
        let err = block_on(r.dispatch("nope", serde_json::json!({}), &grant)).unwrap_err();
        assert!(matches!(err, ToolError::NotFound { .. }));
    }

    #[test]
    fn dispatch_runs_in_scope_and_denies_out_of_scope() {
        let r = reg();
        let granted = Caveats {
            exec: Scope::only(["echo".to_string()]),
            ..Caveats::top()
        };
        let grant = r.mint_grant(granted);
        let ok = block_on(r.dispatch("probe", serde_json::json!({ "program": "echo" }), &grant))
            .unwrap();
        assert_eq!(ok["ran"], "echo");

        let denied = block_on(r.dispatch("probe", serde_json::json!({ "program": "rm" }), &grant))
            .unwrap_err();
        assert!(matches!(denied, ToolError::Denied { .. }));
    }

    #[test]
    fn explicit_dispatch_strength_floor_refuses_backend_downgrade() {
        let registry = Registry::builder().tool(Arc::new(SpawnProbeTool)).build();
        // A non-empty hostname allow-list is advisory for a directly spawned
        // process on every current host backend. Requiring Kernel must therefore
        // refuse before the deliberately nonexistent program reaches the OS.
        let granted = Caveats {
            net: Scope::only(["example.invalid".to_string()]),
            ..Caveats::top()
        };
        let grant = registry.mint_grant(granted);
        let error = block_on(registry.dispatch_with_strength_floor(
            "spawn_probe",
            serde_json::json!({}),
            &grant,
            AxisEnforcement::Kernel,
        ))
        .unwrap_err();
        let ToolError::Denied { reason } = error else {
            panic!("backend downgrade returned the wrong error: {error:?}");
        };
        assert!(
            reason.contains("required strength floor (Kernel)"),
            "denial must identify the unachievable strength floor: {reason}"
        );
    }

    /// AB-001 regression: a `max_calls` bound is enforced *across* dispatches on
    /// one grant. Before the GrantId ledger, each `dispatch` seeded a fresh gate
    /// from the grant, so `AtMost(2)` was silently unbounded — the third call
    /// went through. The registry-owned ledger, keyed by the unforgeable
    /// `GrantId`, now decrements a single balance per grant.
    #[test]
    fn dispatch_budget_persists_across_dispatches() {
        let r = reg();
        let grant = r.mint_grant(Caveats {
            max_calls: CountBound::AtMost(2),
            ..Caveats::top()
        });
        let call =
            || block_on(r.dispatch("probe", serde_json::json!({ "program": "echo" }), &grant));
        assert!(call().is_ok(), "first call within budget");
        assert!(call().is_ok(), "second call exhausts budget");
        assert!(
            matches!(call().unwrap_err(), ToolError::Budget),
            "third call must be denied: the AtMost(2) bound is spent"
        );
    }

    /// Two grants minted from *equal* caveats hold *independent* budgets: the
    /// ledger is keyed by grant identity, not by caveat value. Exhausting one
    /// grant must not touch the other.
    #[test]
    fn two_grants_equal_caveats_have_independent_budgets() {
        let r = reg();
        let caveats = Caveats {
            max_calls: CountBound::AtMost(1),
            ..Caveats::top()
        };
        let a = r.mint_grant(caveats.clone());
        let b = r.mint_grant(caveats);
        let echo =
            |g: &Grant| block_on(r.dispatch("probe", serde_json::json!({ "program": "echo" }), g));
        assert!(echo(&a).is_ok(), "grant A's single call");
        assert!(
            matches!(echo(&a).unwrap_err(), ToolError::Budget),
            "grant A now spent"
        );
        // Grant B is untouched by A's exhaustion.
        assert!(echo(&b).is_ok(), "grant B keeps its own independent budget");
    }

    /// A dispatch denied at authorization (out-of-scope program) must not spend
    /// budget: the charge is refunded before the error returns. A later valid
    /// call still succeeds within the original bound.
    #[test]
    fn denied_dispatch_does_not_charge_budget() {
        let r = reg();
        let grant = r.mint_grant(Caveats {
            exec: Scope::only(["echo".to_string()]),
            max_calls: CountBound::AtMost(1),
            ..Caveats::top()
        });
        let denied = block_on(r.dispatch("probe", serde_json::json!({ "program": "rm" }), &grant))
            .unwrap_err();
        assert!(
            matches!(denied, ToolError::Denied { .. }),
            "out-of-scope program denied"
        );
        // The single-call budget was refunded, so the in-scope call still runs.
        assert!(
            block_on(r.dispatch("probe", serde_json::json!({ "program": "echo" }), &grant)).is_ok(),
            "denied admission must not have consumed the AtMost(1) budget"
        );
    }

    /// AB-001 concurrency invariant: many threads racing `dispatch` on ONE grant
    /// never overspend its `max_calls`. The ledger charge is a check-and-decrement
    /// held under a single mutex, so *exactly* the budget is admitted — no more
    /// (overspend), no fewer (a lost decrement) — and the losers fail closed with
    /// `Budget`. This is the property the per-dispatch gate could not provide.
    #[test]
    fn concurrent_dispatches_on_one_grant_never_overspend() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        const THREADS: usize = 64;
        const BUDGET: u64 = 20;
        let r = reg();
        let grant = r.mint_grant(Caveats {
            max_calls: CountBound::AtMost(BUDGET),
            ..Caveats::top()
        });
        let admitted = AtomicUsize::new(0);
        let denied = AtomicUsize::new(0);
        std::thread::scope(|s| {
            for _ in 0..THREADS {
                s.spawn(|| {
                    match block_on(r.dispatch(
                        "probe",
                        serde_json::json!({ "program": "echo" }),
                        &grant,
                    )) {
                        Ok(_) => {
                            admitted.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(ToolError::Budget) => {
                            denied.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(e) => panic!("unexpected error under concurrency: {e:?}"),
                    }
                });
            }
        });
        assert_eq!(
            admitted.load(Ordering::Relaxed),
            BUDGET as usize,
            "exactly the budget is admitted — no overspend, no lost decrement"
        );
        assert_eq!(
            denied.load(Ordering::Relaxed),
            THREADS - BUDGET as usize,
            "every over-budget racer fails closed with Budget"
        );
    }

    /// A provider whose ceremony always fails (no authenticator / human declined)
    /// — enough to prove the gesture is *demanded* and a refusal is fail-closed,
    /// without any crypto. The verifier is never reached (obtain fails first).
    struct FailingProvider;
    impl crate::DischargeProvider for FailingProvider {
        fn obtain(
            &self,
            _request: &crate::CallRequest,
            _required: &crate::AttestRequirement,
            _generation: u64,
            _nonce: &[u8; 32],
        ) -> Result<crate::Discharge, String> {
            Err("test: no authenticator present".into())
        }
    }
    struct StubVerifier;
    impl crate::DischargeVerifier for StubVerifier {
        fn verify(
            &self,
            _discharge: &crate::Discharge,
            _required: &crate::AttestRequirement,
            _expected: &crate::Challenge,
        ) -> Result<(), String> {
            Ok(()) // never called in this test — the provider refuses first
        }
    }

    /// R2 (ADR 0018): a step-up policy demanding a gesture is enforced on the
    /// **default dispatch path** — a refused gesture is a fail-closed denial and
    /// the tool never runs (nothing minted/charged). Without the seam, dispatch is
    /// unchanged (covered by `dispatch_runs_in_scope_and_denies_out_of_scope`).
    #[test]
    fn step_up_policy_demands_a_gesture_on_the_default_path() {
        let policy = crate::StepUpPolicy::new(
            vec![crate::Rule {
                selector: "probe".to_string(),
                requirement: crate::AttestRequirement::passkey_recorded(),
            }],
            crate::AttestRequirement::NONE,
        );
        let r = Registry::builder()
            .tool(Arc::new(ProbeTool))
            .step_up(policy, Arc::new(FailingProvider), Arc::new(StubVerifier))
            .build();
        let granted = Caveats {
            exec: Scope::only(["echo".to_string()]),
            ..Caveats::top()
        };
        // The policy demands a passkey for `probe`; the provider refuses → denied.
        let grant = r.mint_grant(granted);
        let err = block_on(r.dispatch("probe", serde_json::json!({ "program": "echo" }), &grant))
            .unwrap_err();
        assert!(
            matches!(err, ToolError::Denied { .. }),
            "a demanded-but-refused gesture must fail closed: {err:?}"
        );
    }

    /// R3 (ADR 0018 D8): the step-up (human) axis is **independent of authority**.
    /// Even a `top()` grant — the maximally-permissive extreme an unbridled
    /// principal carries — does not lower the step-up floor: a demanded gesture is
    /// still required. Caveats decide *whether the authority exists*; step-up
    /// decides *what gesture admits its use*. Nothing launders one into the other.
    #[test]
    fn step_up_holds_at_maximal_authority() {
        let policy = crate::StepUpPolicy::new(
            vec![crate::Rule {
                selector: "probe".to_string(),
                requirement: crate::AttestRequirement::passkey_recorded(),
            }],
            crate::AttestRequirement::NONE,
        );
        let r = Registry::builder()
            .tool(Arc::new(ProbeTool))
            .step_up(policy, Arc::new(FailingProvider), Arc::new(StubVerifier))
            .build();
        // top() authority does NOT bypass the demanded gesture.
        let grant = r.mint_grant(Caveats::top());
        let err = block_on(r.dispatch("probe", serde_json::json!({ "program": "echo" }), &grant))
            .unwrap_err();
        assert!(
            matches!(err, ToolError::Denied { .. }),
            "maximal (top) authority must still owe the step-up gesture: {err:?}"
        );
    }

    #[test]
    fn tool_definitions_have_name_and_schema() {
        let r = reg();
        let defs = r.tool_definitions();
        assert_eq!(defs.len(), 1);
        assert_eq!(defs[0]["name"], "probe");
        assert!(defs[0]["inputSchema"].is_object());
        assert!(r.contains("probe"));
        assert_eq!(r.tool_names(), vec!["probe"]);
    }
}
