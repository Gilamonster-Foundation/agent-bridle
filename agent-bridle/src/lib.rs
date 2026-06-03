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

// Anchor the shell tool's symbol in the facade (DESIGN §5): an explicit
// `pub use` keeps the linker from DCE-ing a tool module under strip+lto.
#[cfg(feature = "shell")]
pub use agent_bridle_tool_shell::ShellTool;

/// Build the default tool registry for this host's compiled feature set.
///
/// Uses the explicit [`Registry::builder`] — never `inventory` — so the tool
/// set is deterministic and DCE-proof. Which tools are present depends on the
/// compiled features:
///
/// - `shell` (default): adds the confined brush-backed `shell` tool.
///
/// Under `--no-default-features` the registry is empty but valid; a host adds
/// tools by enabling features (or building its own registry).
#[must_use]
pub fn registry() -> Registry {
    #[allow(unused_mut)]
    let mut builder = Registry::builder();

    #[cfg(feature = "shell")]
    {
        builder = builder.tool(std::sync::Arc::new(ShellTool::new()));
    }

    builder.build()
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

    /// Under `--no-default-features` the shell tool must be absent (proves the
    /// feature actually gates it) but the registry still builds.
    #[cfg(not(feature = "shell"))]
    #[test]
    fn shell_tool_absent_without_feature() {
        let reg = registry();
        assert!(!reg.contains("shell"));
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
