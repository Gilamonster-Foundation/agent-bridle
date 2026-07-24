//! `agent-bridle` — the facade.
//!
//! Re-exports the [`agent_bridle_core`] leash and assembles the default tool
//! [`Registry`] a host consumes. Tools are registered through the **explicit
//! builder** (DESIGN §5) — the DCE-proof path under `strip+lto` release
//! profiles — and each tool's symbol is anchored here by a `pub use`, so the
//! linker can never silently drop one from `tools/list`.
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
//! let out = reg
//!     .dispatch("shell", serde_json::json!({ "program": "echo", "args": ["hi"] }), &granted)
//!     .await?;
//! assert_eq!(out["exit_code"], 0);
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
pub use agent_bridle_tool_shell::ShellTool;
#[cfg(any(feature = "shell", feature = "host-shell", feature = "brush"))]
pub use agent_bridle_tool_shell::{ShellInvocationId, ShellOutputObserver, ShellOutputStream};
// The sandboxed-host engine (ADR 0019 / #194). Anchored here so a host can
// construct its own registry with it (`Registry::builder().tool(Arc::new(
// HostShellTool::new()))`); it is deliberately NOT added to `registry()` — it
// is a complementary construction-time engine choice, and it shares the
// `"shell"` name with `ShellTool` (ADR 0019 D3).
#[cfg(feature = "host-shell")]
pub use agent_bridle_tool_shell::HostShellTool;
// The carried brush engine (agent-bridle#20): a bash-in-Rust shell confined
// in-process by the CommandInterceptor — the only engine that also confines a
// restricted exec/net grant. Behind the `brush` feature (the crates.io
// `brush-ocap-*` fork); NOT auto-added to `registry()` — it shares the
// `"shell"` name with ShellTool (ADR 0005 D2), so the embedder selects it.
#[cfg(feature = "brush")]
pub use agent_bridle_tool_shell::BrushShellTool;
// Carried-coreutils dispatch (issue #206): an embedder's binary calls
// `maybe_dispatch()` at the very top of `main` to become dispatch-capable, so the
// brush engine's carried `ls`/`cat`/… shims (which re-exec `<self>
// --invoke-bundled <name>`) resolve in-process against the host binary — carried
// coreutils with no host tools. `register_shims`/`install_default_providers` are
// used by the engine internally but re-exported for completeness.
#[cfg(feature = "carried-coreutils")]
pub use agent_bridle_tool_shell::{install_default_providers, maybe_dispatch, register_shims};
#[cfg(feature = "web")]
pub use agent_bridle_tool_web::WebFetchTool;

/// Build the default tool registry for this host's compiled feature set.
///
/// Uses the explicit [`Registry::builder`] — never `inventory` — so the tool
/// set is deterministic and DCE-proof. Which tools are present depends on the
/// compiled features:
///
/// - `carried-coreutils` (default): adds the carried Brush-backed `shell` tool.
/// - `shell`: selects the lean argv + safe-subset `shell` instead when
///   `carried-coreutils` is disabled.
/// - `web`: adds the confined `web_fetch` tool — the `net` enforcer (host
///   allowlist + SSRF block + per-redirect re-check + IP pinning).
///
/// Under `--no-default-features` the registry is empty but valid; a host adds
/// tools by enabling features (or building its own registry).
#[must_use]
pub fn registry() -> Registry {
    #[allow(unused_mut)]
    let mut builder = Registry::builder();

    #[cfg(feature = "carried-coreutils")]
    {
        builder = builder.tool(std::sync::Arc::new(BrushShellTool::new()));
    }

    #[cfg(all(feature = "shell", not(feature = "carried-coreutils")))]
    {
        builder = builder.tool(std::sync::Arc::new(ShellTool::new()));
    }

    #[cfg(feature = "web")]
    {
        builder = builder.tool(std::sync::Arc::new(WebFetchTool::new()));
    }

    builder.build()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Presence test (DESIGN §5): either registry-selected shell feature must
    /// register exactly the public `shell` identity.
    #[cfg(any(feature = "shell", feature = "carried-coreutils"))]
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

    /// The default carried engine publishes its full-shell `cmd` schema, not
    /// the safe-subset engine's argv form.
    #[cfg(feature = "carried-coreutils")]
    #[test]
    fn default_shell_is_the_carried_brush_engine() {
        let reg = registry();
        let shell = reg
            .tool_definitions()
            .into_iter()
            .find(|definition| definition["name"] == "shell")
            .expect("carried shell present");
        let properties = shell["inputSchema"]["properties"]
            .as_object()
            .expect("shell schema properties");
        assert!(properties.contains_key("cmd"), "Brush schema needs `cmd`");
        assert!(
            !properties.contains_key("program"),
            "default registry must not select the argv safe-subset engine"
        );
    }

    /// Without either registry-selected shell feature the tool must be absent.
    #[cfg(not(any(feature = "shell", feature = "carried-coreutils")))]
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
    #[cfg(all(
        not(feature = "shell"),
        not(feature = "carried-coreutils"),
        not(feature = "web")
    ))]
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
