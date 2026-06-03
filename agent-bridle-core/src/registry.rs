//! The [`Registry`] — explicit-builder tool catalog + leashed dispatch.
//!
//! Explicit registration is the **default** (DESIGN §5): newt's release profile
//! is `strip=true` + `lto="thin"`, the verified real-world trigger for linker
//! DCE silently dropping an `inventory`-self-registered tool from `tools/list`.
//! A `Registry::builder().tool(...).build()` is immune because every tool is
//! referenced by an explicit anchor symbol. We deliberately do **not** use
//! `inventory` in P0.

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::{Caveats, Gate, Tool, ToolError, ToolResult};

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
        let cx = gate.authorize(tool.as_ref(), granted)?;
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

    /// Finish building.
    #[must_use]
    pub fn build(self) -> Registry {
        Registry {
            tools: self.tools,
            generation: self.generation,
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
