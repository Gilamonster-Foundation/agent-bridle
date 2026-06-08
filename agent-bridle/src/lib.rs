//! `agent-bridle` — the facade.
//!
//! Re-exports the [`agent_bridle_core`] leash and assembles the default tool
//! [`Registry`] a host consumes. Tools are registered through the **explicit
//! builder** (DESIGN §5) — the DCE-proof path under `strip+lto` release
//! profiles — and each tool's symbol is anchored here by a `pub use`, so the
//! linker can never silently drop one from `tools/list`.
//!
//! The default [`registry`] ships a **fail-closed stub** `shell` tool: the
//! brush-backed confined shell is pending an upstream brush merge, so the
//! published default denies every shell invocation rather than running anything
//! unconfined. A host that needs to actually run commands opts in explicitly via
//! [`registry_with_shell`] with [`ShellTool::insecure_bash`] (per-command
//! approval) or [`ShellTool::dangerous_unconfined`] — both run an UNCONFINED
//! bash. See `agent-bridle-mcp`'s `--insecure` / `--dangerously-allow-all`.
//!
//! ```
//! use agent_bridle::registry;
//! use agent_bridle::{Caveats, CountBound, Scope};
//!
//! # async fn demo() -> anyhow::Result<()> {
//! let reg = registry();
//! let granted = Caveats {
//!     exec: Scope::only(["echo".to_string()]),
//!     max_calls: CountBound::AtMost(2),
//!     ..Caveats::top()
//! };
//! // The default `shell` tool is the fail-closed stub: it denies and spawns
//! // nothing, regardless of the grant. Escalate via `registry_with_shell`.
//! let denied = reg
//!     .dispatch("shell", serde_json::json!({ "program": "echo", "args": ["hi"] }), &granted)
//!     .await;
//! assert!(denied.is_err());
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

// Re-export the whole leash so hosts depend on one crate.
pub use agent_bridle_core::*;

// Anchor each tool's symbol in the facade (DESIGN §5): an explicit `pub use`
// keeps the linker from DCE-ing a tool module under strip+lto.
#[cfg(feature = "shell")]
pub use agent_bridle_tool_shell::{ApprovalHook, ShellPolicy, ShellTool};
#[cfg(feature = "web")]
pub use agent_bridle_tool_web::WebFetchTool;

/// Build the default tool registry for this host's compiled feature set.
///
/// Uses the explicit [`Registry::builder`] — never `inventory` — so the tool
/// set is deterministic and DCE-proof. Which tools are present depends on the
/// compiled features:
///
/// - `shell` (default): adds the `shell` tool as the **fail-closed stub**
///   ([`ShellTool::stub`]) — it denies every invocation and spawns nothing. The
///   brush-backed confined shell is pending an upstream brush merge; to run
///   commands now, use [`registry_with_shell`] with an opt-in unconfined policy.
/// - `web`: adds the confined `web_fetch` tool — the `net` enforcer (host
///   allowlist + SSRF block + per-redirect re-check + IP pinning).
///
/// Under `--no-default-features` the registry is empty but valid; a host adds
/// tools by enabling features (or building its own registry).
#[cfg(feature = "shell")]
#[must_use]
pub fn registry() -> Registry {
    registry_with_shell(ShellTool::stub())
}

/// Build the default tool registry when the `shell` feature is OFF: only the
/// (optional) `web_fetch` tool can be present; otherwise the registry is empty
/// but valid.
#[cfg(not(feature = "shell"))]
#[must_use]
pub fn registry() -> Registry {
    with_web(Registry::builder()).build()
}

/// Build the tool registry using a caller-supplied [`ShellTool`] (plus the
/// `web_fetch` tool under the `web` feature).
///
/// This is the escalation seam: a host passes [`ShellTool::insecure_bash`]
/// (per-command approval) or [`ShellTool::dangerous_unconfined`] to enable an
/// UNCONFINED bash, while [`registry`] uses the safe [`ShellTool::stub`]. Under
/// `--no-default-features` (no `shell` feature) there is no `ShellTool` type, so
/// this function is unavailable; use [`registry`].
#[cfg(feature = "shell")]
#[must_use]
pub fn registry_with_shell(shell: ShellTool) -> Registry {
    let builder = Registry::builder().tool(std::sync::Arc::new(shell));
    with_web(builder).build()
}

/// Add the `web_fetch` tool to a builder when the `web` feature is on; a no-op
/// otherwise. Factored out so the two registry constructors share it.
#[allow(unused_mut)]
fn with_web(mut builder: RegistryBuilder) -> RegistryBuilder {
    #[cfg(feature = "web")]
    {
        builder = builder.tool(std::sync::Arc::new(WebFetchTool::new()));
    }
    builder
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Presence test (DESIGN §5): under `--features shell` the `shell` tool must
    /// be registered. This is the CI guard that linker DCE has not dropped it.
    #[cfg(feature = "shell")]
    #[test]
    fn shell_tool_is_present_with_feature() {
        let reg = registry();
        assert!(
            reg.contains("shell"),
            "expected `shell` tool to be registered"
        );
        let names = reg.tool_names();
        assert!(
            names.contains(&"shell"),
            "tool_names missing shell: {names:?}"
        );
    }

    /// Without the `shell` feature the shell tool must be absent (proves the
    /// feature actually gates it).
    #[cfg(not(feature = "shell"))]
    #[test]
    fn shell_tool_absent_without_feature() {
        let reg = registry();
        assert!(!reg.contains("shell"));
    }

    /// Presence test (DESIGN §5): under `--features web` the `web_fetch` tool —
    /// the `net` enforcer — must be registered (and thus exposed by
    /// `agent-bridle-mcp`). This is the CI guard that linker DCE has not dropped
    /// it under strip+lto.
    #[cfg(feature = "web")]
    #[test]
    fn web_fetch_tool_is_present_with_feature() {
        let reg = registry();
        assert!(
            reg.contains("web_fetch"),
            "expected `web_fetch` tool to be registered"
        );
        assert!(
            reg.tool_names().contains(&"web_fetch"),
            "tool_names missing web_fetch: {:?}",
            reg.tool_names()
        );
    }

    /// Without the `web` feature the web tool must be absent.
    #[cfg(not(feature = "web"))]
    #[test]
    fn web_fetch_tool_absent_without_feature() {
        let reg = registry();
        assert!(!reg.contains("web_fetch"));
    }

    /// Under `--no-default-features` (no `shell`, no `web`) the registry is empty
    /// but valid.
    #[cfg(all(not(feature = "shell"), not(feature = "web")))]
    #[test]
    fn registry_is_empty_with_no_tool_features() {
        let reg = registry();
        assert!(reg.tool_names().is_empty());
    }

    /// The facade re-exports the core leash types.
    #[test]
    fn leash_types_are_reexported() {
        let _c = Caveats::top();
        let _s: Scope<String> = Scope::top();
        let _b = CountBound::Unlimited;
        let _k = SandboxKind::None;
    }
}
