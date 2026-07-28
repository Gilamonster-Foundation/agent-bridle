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
//! // Mint one grant from the leash. The grant carries a persistent budget: its
//! // `max_calls` bound is enforced *across* every dispatch it drives, not reset
//! // per call (agent-bridle#264).
//! let grant = reg.mint_grant(Caveats {
//!     exec: Scope::only(["echo".to_string()]),
//!     max_calls: CountBound::AtMost(2),
//!     ..Caveats::top()
//! });
//! let out = reg
//!     .dispatch("shell", serde_json::json!({ "program": "echo", "args": ["hi"] }), &grant)
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
#[cfg(any(feature = "shell", feature = "carried-coreutils"))]
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
// The carried brush engine (agent-bridle#20): a bash-in-Rust shell run in a
// dedicated worker. Its CommandInterceptor provides the worker-local L2 leash;
// when effective caveats engage a native L3 backend, the worker and descendants
// inherit it. Behind the `brush` feature (the crates.io `brush-ocap-*` fork);
// NOT auto-added to `registry()` — it shares the `"shell"` name with ShellTool
// (ADR 0005 D2), so the embedder selects it.
#[cfg(feature = "brush")]
pub use agent_bridle_tool_shell::{brush_private_control_supported, BrushShellTool};
/// Parse and inspect Brush shell source without expansion or execution.
///
/// The returned source-bound schema lets an embedder present command
/// substitutions, state-free arithmetic expansions, redirections, and
/// statically discoverable commands for approval before invoking
/// [`BrushShellTool`]. Arithmetic that depends on shell variables, arrays,
/// assignments, or nested expansion fails closed, as do parameter forms that
/// can reinterpret runtime values as expansion syntax.
#[cfg(feature = "brush")]
pub use agent_bridle_tool_shell::{
    inspect_shell, DescendantExec, InspectedCommand, InspectedConstruct, InspectedRedirect,
    RedirectOperation, ShellConstructKind, ShellInspection, ShellInspectionError,
};
// An embedder calls `maybe_dispatch()` at the very top of `main` so the private
// sandboxed Brush worker re-exec resolves before normal application startup.
#[cfg(feature = "brush")]
pub use agent_bridle_tool_shell::maybe_dispatch;
// With carried-coreutils, non-conflicting `ls`/`cat`/… shims additionally
// re-exec `<self> --invoke-bundled <name>` and resolve against the host binary.
// Registration helpers are re-exported for completeness.
#[cfg(feature = "carried-coreutils")]
pub use agent_bridle_tool_shell::{install_default_providers, register_shims};
#[cfg(feature = "web")]
pub use agent_bridle_tool_web::WebFetchTool;

/// Build the default tool registry for this host's compiled feature set.
///
/// Uses the explicit [`Registry::builder`] — never `inventory` — so the tool
/// set is deterministic and DCE-proof. Which tools are present depends on the
/// compiled features:
///
/// - `carried-coreutils` (default): adds the carried Brush-backed `shell` tool
///   where authenticated private control is supported; otherwise it selects
///   the safe-subset shell rather than advertising an unusable worker.
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
        if brush_private_control_supported() {
            builder = builder.tool(std::sync::Arc::new(BrushShellTool::new()));
        } else {
            builder = builder.tool(std::sync::Arc::new(ShellTool::new()));
        }
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
    #[cfg(all(
        feature = "carried-coreutils",
        any(target_os = "linux", target_os = "macos")
    ))]
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

    /// A default build on a target without authenticated private control keeps
    /// a functional shell, but advertises the safe-subset argv schema rather
    /// than pretending the unavailable Brush worker can run.
    #[cfg(all(
        feature = "carried-coreutils",
        not(any(target_os = "linux", target_os = "macos"))
    ))]
    #[test]
    fn default_shell_falls_back_to_safe_subset_when_private_control_is_unsupported() {
        assert!(!brush_private_control_supported());
        let reg = registry();
        let shell = reg
            .tool_definitions()
            .into_iter()
            .find(|definition| definition["name"] == "shell")
            .expect("safe-subset shell present");
        let properties = shell["inputSchema"]["properties"]
            .as_object()
            .expect("shell schema properties");
        assert!(
            properties.contains_key("program"),
            "fallback schema must disclose the argv safe-subset engine"
        );
    }

    #[cfg(feature = "brush")]
    #[test]
    fn private_control_probe_matches_the_compiled_transport() {
        assert_eq!(
            brush_private_control_supported(),
            cfg!(any(target_os = "linux", target_os = "macos"))
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

    /// The facade forwards the EdDSA WebAuthn verifier feature to core.
    #[cfg(feature = "verifier-webauthn")]
    #[test]
    fn webauthn_verifier_is_reexported() {
        let _ = WebAuthnVerifier;
    }

    /// The facade forwards the ES256 WebAuthn verifier feature to core.
    #[cfg(feature = "verifier-webauthn-es256")]
    #[test]
    fn webauthn_es256_verifier_is_reexported() {
        let _ = WebAuthnEs256Verifier;
    }

    /// The facade exposes parse-only Brush inspection so a host can preflight
    /// dynamic constructs before any shell tool is invoked.
    #[cfg(feature = "brush")]
    #[test]
    fn brush_inspection_is_reexported_for_preflight() {
        let inspected: ShellInspection =
            inspect_shell(r#"echo "$(printf '%s' "$((1 + 2))")""#).expect("inspection");

        let substitution: &InspectedConstruct = &inspected.constructs[0];
        assert_eq!(substitution.kind, ShellConstructKind::CommandSubstitution);
        assert!(substitution.quoted);

        let nested = substitution
            .inspection
            .as_deref()
            .expect("recursive substitution inspection");
        assert_eq!(
            nested.constructs[0].kind,
            ShellConstructKind::ArithmeticExpansion
        );
        assert_eq!(nested.constructs[0].body, "1 + 2");

        let error = inspect_shell("echo $((runtime_value))")
            .expect_err("runtime-state arithmetic must fail closed through the facade");
        assert!(error.message().contains("runtime shell state"));
    }
}
