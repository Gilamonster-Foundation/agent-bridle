//! The [`Registry`] — explicit-builder tool catalog + leashed dispatch.
//!
//! Explicit registration is the **default** (DESIGN §5): newt's release profile
//! is `strip=true` + `lto="thin"`, the verified real-world trigger for linker
//! DCE silently dropping an `inventory`-self-registered tool from `tools/list`.
//! A `Registry::builder().tool(...).build()` is immune because every tool is
//! referenced by an explicit anchor symbol. We deliberately do **not** use
//! `inventory` in P0.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use crate::{
    CallRequest, Caveats, DischargeProvider, DischargeVerifier, Gate, StepUpPolicy, Tool,
    ToolError, ToolResult,
};

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

    /// Dispatch `name` with `args`, enforced by the leash.
    ///
    /// A fresh gate (seeded with the grant's `max_calls` and the registry's
    /// generation) authorizes the tool, minting the [`crate::ToolContext`] the
    /// tool needs. If authorization is denied, the tool never runs.
    pub async fn dispatch(
        &self,
        name: &str,
        args: serde_json::Value,
        granted: &Caveats,
    ) -> ToolResult<serde_json::Value> {
        let tool = self
            .tools
            .get(name)
            .ok_or_else(|| ToolError::not_found(name))?;

        let gate = self.gate_for(granted);
        let cx = match &self.step_up {
            // Step-up wired in (ADR 0018 R2): run the host-orchestrated ceremony
            // through the gate — a policy-demanded gesture is obtained + verified
            // before minting; a refusal is a fail-closed denial (nothing minted or
            // charged). The gate stays the single mint site. This holds on the
            // default path and while unbridled (the human gate is orthogonal).
            Some(su) => {
                let request = CallRequest::unspecified(name);
                // Fresh single-use nonce per ceremony (monotonic counter → the
                // gate's bound challenge differs each call, defeating replay).
                let mut nonce = [0u8; 32];
                let n = self.step_up_nonce.fetch_add(1, Ordering::Relaxed);
                nonce[..8].copy_from_slice(&n.to_le_bytes());
                let (cx, _attestation) = gate.authorize_step_up(
                    tool.as_ref(),
                    granted,
                    &request,
                    &su.policy,
                    su.provider.as_ref(),
                    su.verifier.as_ref(),
                    nonce,
                )?;
                cx
            }
            None => gate.authorize(tool.as_ref(), granted)?,
        };
        tool.invoke(args, &cx).await
    }

    /// Construct the per-dispatch gate. Factored out so the budget seeding and
    /// generation stay in one place. The gate's budget is seeded from the
    /// grant's `max_calls` so a single dispatch's per-call charge interacts
    /// correctly with `AtMost(n)`.
    fn gate_for(&self, granted: &Caveats) -> Gate {
        Gate::with_budget(self.generation, granted.max_calls)
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
        let err = block_on(r.dispatch("nope", serde_json::json!({}), &Caveats::top())).unwrap_err();
        assert!(matches!(err, ToolError::NotFound { .. }));
    }

    #[test]
    fn dispatch_runs_in_scope_and_denies_out_of_scope() {
        let r = reg();
        let granted = Caveats {
            exec: Scope::only(["echo".to_string()]),
            ..Caveats::top()
        };
        let ok = block_on(r.dispatch("probe", serde_json::json!({ "program": "echo" }), &granted))
            .unwrap();
        assert_eq!(ok["ran"], "echo");

        let denied =
            block_on(r.dispatch("probe", serde_json::json!({ "program": "rm" }), &granted))
                .unwrap_err();
        assert!(matches!(denied, ToolError::Denied { .. }));
    }

    #[test]
    fn dispatch_budget_two_then_denied() {
        let granted = Caveats {
            max_calls: CountBound::AtMost(2),
            ..Caveats::top()
        };
        // Each `dispatch` builds a fresh gate seeded from the grant's bound, so
        // a single dispatch's per-call charge interacts with AtMost(n). To prove
        // budget exhaustion *across* calls the persistent budget must live on
        // one shared gate — so we drive the gate directly here:
        let gate = Gate::with_budget(0, CountBound::AtMost(2));
        let tool = ProbeTool;
        assert!(gate.authorize(&tool, &granted).is_ok());
        assert!(gate.authorize(&tool, &granted).is_ok());
        assert!(matches!(
            gate.authorize(&tool, &granted).unwrap_err(),
            ToolError::Budget
        ));
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
        let err = block_on(r.dispatch("probe", serde_json::json!({ "program": "echo" }), &granted))
            .unwrap_err();
        assert!(
            matches!(err, ToolError::Denied { .. }),
            "a demanded-but-refused gesture must fail closed: {err:?}"
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
