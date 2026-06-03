//! The [`Tool`] trait: a leashable capability.

use async_trait::async_trait;

use crate::{Caveats, ToolContext, ToolResult};

/// A capability the agent can invoke, governed by the leash.
///
/// A tool declares the authority it needs via [`Tool::required`]; the
/// [`crate::Gate`] confines the grant to `granted.meet(required)` and hands the
/// tool a [`ToolContext`] minted from that meet. The tool can only act through
/// the context's `check_*` methods, so it can never exceed what it declared or
/// what the session was granted.
#[async_trait]
pub trait Tool: Send + Sync {
    /// The dispatch name (the key in `tools/list` and in
    /// [`crate::Registry::dispatch`]).
    fn name(&self) -> &str;

    /// The MCP `inputSchema` (JSON Schema) for this tool's arguments.
    fn schema(&self) -> serde_json::Value;

    /// The authority ceiling this tool promises to stay under.
    ///
    /// Defaults to [`Caveats::top`] — i.e. "I declare nothing special; confine
    /// me entirely by the session grant." Because the gate hands the tool the
    /// *meet* of granted-and-required, a `top` default means the tool runs under
    /// exactly the granted caveats, while a narrower declaration tightens the
    /// effective authority (and any future Landlock ruleset) even further. It is
    /// a *ceiling*, not a demand: declaring authority the grant lacks is not an
    /// error — the meet simply intersects it away, and per-operation
    /// [`ToolContext`](crate::ToolContext) `check_*` calls deny at use.
    fn required(&self) -> Caveats {
        Caveats::top()
    }

    /// Run the tool. The `cx` proves the leash was passed; the tool enforces
    /// per-operation policy by calling `cx.check_exec`, `cx.check_path_*`, etc.
    async fn invoke(
        &self,
        args: serde_json::Value,
        cx: &ToolContext,
    ) -> ToolResult<serde_json::Value>;
}
