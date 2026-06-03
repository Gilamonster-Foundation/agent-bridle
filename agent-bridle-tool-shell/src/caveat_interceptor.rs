//! [`CaveatInterceptor`] — the in-process capability hook for free-form shell.
//!
//! brush 0.5 cannot be confined in-process by a cleared `PATH` + a builtin
//! allow-list: any command whose name contains a path separator (e.g.
//! `/bin/rm`, `./payload`) bypasses both `PATH` and the builtin table and runs
//! directly (DESIGN §6). Our brush fork closes this by exposing
//! [`brush_core::extensions::CommandInterceptor`], whose `before_exec` /
//! `before_open` hooks fire at the **single external-spawn funnel** and at
//! `Shell::open_file` — so a policy applied here cannot be circumvented by
//! spelling a command (or a redirection target) differently. This makes the
//! confined shell a true superset of an `sh -c` cmd-string shell, cross-OS.
//!
//! [`CaveatInterceptor`] carries one invocation's **effective** caveats (the
//! `ToolContext` minted by the gate) and delegates every decision to the
//! *shared* leash logic on [`ToolContext`] — [`ToolContext::check_exec`],
//! [`ToolContext::check_path_read`], [`ToolContext::check_path_write`]. It does
//! **not** duplicate the canonicalizing path check; the one in
//! `agent-bridle-core` (realpath, reject symlink/`..` escapes) is the single
//! source of truth.

use std::path::Path;

use agent_bridle_core::ToolContext;
use brush_core::extensions::{CommandInterceptor, ExecDecision, OpenDecision};

/// A brush [`CommandInterceptor`] that enforces an invocation's effective
/// caveats in-process.
///
/// Holds an `Option<ToolContext>`:
///
/// - `Some(cx)` — enforce `cx`'s effective caveats (the normal, constructed
///   case). Built per-invocation via [`CaveatInterceptor::new`].
/// - `None` — the [`Default`] value. **Conservatively denies everything.** The
///   trait requires `Default`, but a `ToolContext` is un-forgeable (no public
///   constructor by design), so the default cannot carry caveats; denying is the
///   only safe behavior. A default-constructed interceptor must never reach a
///   live shell — but if one ever did, it is fail-closed, not allow-all.
#[derive(Debug, Clone, Default)]
pub struct CaveatInterceptor {
    /// The minted context whose effective caveats gate this shell, or `None`
    /// for the fail-closed default.
    cx: Option<ToolContext>,
}

impl CaveatInterceptor {
    /// Build an interceptor that enforces `cx`'s effective caveats.
    #[must_use]
    pub fn new(cx: ToolContext) -> Self {
        Self { cx: Some(cx) }
    }
}

impl CommandInterceptor for CaveatInterceptor {
    /// Deny unless the effective `exec` caveat allows `program`.
    ///
    /// `program` is what brush is about to spawn: for `PATH`-resolved commands
    /// the resolved absolute path, and for path-separator commands the path as
    /// written (`/bin/rm`, `./x`). Either way we test that exact string against
    /// the `exec` scope, so `/bin/rm` is denied whenever `rm` (or `/bin/rm`) is
    /// not granted — this is the path-separator bypass, now closed at the funnel.
    fn before_exec(&self, program: &str, _args: &[String]) -> ExecDecision {
        match &self.cx {
            Some(cx) => match cx.check_exec(program) {
                Ok(()) => ExecDecision::Allow,
                Err(e) => ExecDecision::Deny(e.to_string()),
            },
            // Fail-closed default: no caveats means no authority.
            None => ExecDecision::Deny(
                "no effective caveats (default interceptor); exec denied".to_string(),
            ),
        }
    }

    /// Deny unless the effective `fs_read`/`fs_write` caveat allows `path`.
    ///
    /// `write` selects the axis. Both checks canonicalize first (realpath) and
    /// reject paths that escape the granted scope via `..` or a symlink — that
    /// logic is the shared one in `agent-bridle-core`, reused here, not copied.
    fn before_open(&self, path: &Path, write: bool) -> OpenDecision {
        let Some(cx) = &self.cx else {
            return OpenDecision::Deny(
                "no effective caveats (default interceptor); open denied".to_string(),
            );
        };
        let result = if write {
            cx.check_path_write(path)
        } else {
            cx.check_path_read(path)
        };
        match result {
            Ok(()) => OpenDecision::Allow,
            Err(e) => OpenDecision::Deny(e.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_bridle_core::{Caveats, Gate, Scope, Tool, ToolResult};

    /// Mint a `ToolContext` the only legitimate way — through the gate — using a
    /// trivial tool with default (`top`) requirements so `effective == granted`.
    fn ctx(granted: Caveats) -> ToolContext {
        struct AnyTool;
        #[async_trait::async_trait]
        impl Tool for AnyTool {
            fn name(&self) -> &str {
                "any"
            }
            fn schema(&self) -> serde_json::Value {
                serde_json::json!({})
            }
            async fn invoke(
                &self,
                _args: serde_json::Value,
                _cx: &ToolContext,
            ) -> ToolResult<serde_json::Value> {
                Ok(serde_json::Value::Null)
            }
        }
        Gate::new(0)
            .authorize(&AnyTool, &granted)
            .expect("authorize")
    }

    #[test]
    fn default_is_fail_closed() {
        let interceptor = CaveatInterceptor::default();
        assert!(matches!(
            interceptor.before_exec("echo", &[]),
            ExecDecision::Deny(_)
        ));
        assert!(matches!(
            interceptor.before_open(Path::new("/tmp"), false),
            OpenDecision::Deny(_)
        ));
    }

    #[test]
    fn before_exec_allows_in_scope_denies_out_of_scope() {
        let interceptor = CaveatInterceptor::new(ctx(Caveats {
            exec: Scope::only(["echo".to_string()]),
            ..Caveats::top()
        }));
        assert!(matches!(
            interceptor.before_exec("echo", &[]),
            ExecDecision::Allow
        ));
        assert!(matches!(
            interceptor.before_exec("rm", &["-rf".to_string()]),
            ExecDecision::Deny(_)
        ));
    }

    #[test]
    fn before_exec_denies_path_separator_spelled_command() {
        // The load-bearing case the hook exists for: `/bin/rm` is denied because
        // `/bin/rm` is not within `exec: Only{echo}` — the path-separator bypass
        // is closed, since the hook fires even for path-separator commands.
        let interceptor = CaveatInterceptor::new(ctx(Caveats {
            exec: Scope::only(["echo".to_string()]),
            ..Caveats::top()
        }));
        assert!(matches!(
            interceptor.before_exec("/bin/rm", &["-rf".to_string()]),
            ExecDecision::Deny(_)
        ));
    }

    #[test]
    fn before_open_write_uses_fs_write_axis() {
        let dir = std::env::temp_dir();
        let interceptor = CaveatInterceptor::new(ctx(Caveats {
            fs_write: Scope::only([dir.to_string_lossy().into_owned()]),
            ..Caveats::top()
        }));
        // A new file under the allowed dir: write allowed.
        assert!(matches!(
            interceptor.before_open(&dir.join("ab-interceptor-ok.txt"), true),
            OpenDecision::Allow
        ));
        // Clearly outside the allowed dir: write denied.
        assert!(matches!(
            interceptor.before_open(Path::new("/etc/shadow"), true),
            OpenDecision::Deny(_)
        ));
    }
}
