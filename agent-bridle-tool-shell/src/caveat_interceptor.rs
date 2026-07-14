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
use std::sync::{Arc, Mutex};

use agent_bridle_core::{Denial, DenialKind, ToolContext};
use brush_core::extensions::{CommandInterceptor, ExecDecision, OpenDecision};

/// The shared, per-invocation denial sink.
///
/// brush clones the [`CaveatInterceptor`] internally (the trait requires
/// `Clone`), so to see *every* denial the shell hit we cannot store the log in
/// the struct by value — each clone would get its own copy. The `Arc<Mutex<_>>`
/// makes all clones write to one vec. The `ShellTool` creates a *fresh* sink per
/// `invoke`, so two concurrent invocations never share one — that is what keeps
/// denials from cross-contaminating across invocations.
pub(crate) type DenialSink = Arc<Mutex<Vec<Denial>>>;

/// A brush [`CommandInterceptor`] that enforces an invocation's effective
/// caveats in-process **and records each denial it makes** into a shared sink.
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
///
/// Every `Deny` is appended to the [`DenialSink`] so the shell tool can read a
/// **structured** signal after the run instead of string-matching stderr. An
/// `Allow` records nothing — so a permitted command that exits non-zero on its
/// own (e.g. exit 126) is never mistaken for a leash denial.
#[derive(Debug, Clone, Default)]
pub struct CaveatInterceptor {
    /// The minted context whose effective caveats gate this shell, or `None`
    /// for the fail-closed default.
    cx: Option<ToolContext>,
    /// Shared sink every denial is recorded into. `None` only for the
    /// [`Default`] interceptor (which still denies, just records nothing —
    /// it never reaches a live shell).
    sink: Option<DenialSink>,
}

impl CaveatInterceptor {
    /// Build an interceptor that enforces `cx`'s effective caveats and records
    /// every denial it makes into `sink`.
    #[must_use]
    pub(crate) fn new(cx: ToolContext, sink: DenialSink) -> Self {
        Self {
            cx: Some(cx),
            sink: Some(sink),
        }
    }

    /// Record a denial into the shared sink (a no-op if there is no sink).
    fn record(&self, kind: DenialKind, target: impl Into<String>, reason: impl Into<String>) {
        if let Some(sink) = &self.sink {
            // A poisoned mutex would only happen if a brush callback panicked
            // mid-record; recover the inner vec rather than poison-propagate so
            // a single bad record cannot lose the rest of the denial log.
            let mut guard = sink
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            guard.push(Denial {
                kind,
                target: target.into(),
                reason: reason.into(),
            });
        }
    }
}

impl CommandInterceptor for CaveatInterceptor {
    /// Deny unless the effective `exec` caveat allows `program`.
    ///
    /// `program` is what brush is about to spawn: for `PATH`-resolved commands
    /// the resolved absolute path, and for path-separator commands the path as
    /// written (`/bin/rm`, `./x`). We hand that string to
    /// [`ToolContext::check_exec`], which allows it if the `exec` scope contains
    /// it verbatim OR contains its basename — so a bare-name grant (`["git"]`)
    /// matches the resolved `/usr/bin/git`, while `/bin/rm` is denied whenever
    /// neither `rm` nor `/bin/rm` is granted (the path-separator bypass stays
    /// closed at the funnel).
    fn before_exec(&self, program: &str, _args: &[String]) -> ExecDecision {
        match &self.cx {
            Some(cx) => match cx.check_exec(program) {
                Ok(()) => ExecDecision::Allow,
                Err(e) => {
                    let reason = e.to_string();
                    // Record the denial as a structured signal BEFORE returning.
                    self.record(DenialKind::Exec, program, &reason);
                    ExecDecision::Deny(reason)
                }
            },
            // Fail-closed default: no caveats means no authority.
            None => {
                let reason = "no effective caveats (default interceptor); exec denied".to_string();
                self.record(DenialKind::Exec, program, &reason);
                ExecDecision::Deny(reason)
            }
        }
    }

    /// Deny unless the effective `fs_read`/`fs_write` caveat allows `path`.
    ///
    /// `write` selects the axis. Both checks canonicalize first (realpath) and
    /// reject paths that escape the granted scope via `..` or a symlink — that
    /// logic is the shared one in `agent-bridle-core`, reused here, not copied.
    fn before_open(&self, path: &Path, write: bool) -> OpenDecision {
        // newt#969: the standard sinks are ALWAYS-permitted write targets.
        // `2>/dev/null` is the most common idiom in shell training data, and
        // writing to /dev/null|stdout|stderr is not a filesystem mutation in
        // any capability sense — no data persists, nothing is created. A
        // closed 3-item whitelist, not a general redirect grant.
        if write
            && matches!(
                path.to_str(),
                Some("/dev/null" | "/dev/stdout" | "/dev/stderr")
            )
        {
            return OpenDecision::Allow;
        }
        let Some(cx) = &self.cx else {
            let reason = "no effective caveats (default interceptor); open denied".to_string();
            self.record(DenialKind::Open, path.to_string_lossy(), &reason);
            return OpenDecision::Deny(reason);
        };
        let result = if write {
            cx.check_path_write(path)
        } else {
            cx.check_path_read(path)
        };
        match result {
            Ok(()) => OpenDecision::Allow,
            Err(e) => {
                let reason = e.to_string();
                self.record(DenialKind::Open, path.to_string_lossy(), &reason);
                OpenDecision::Deny(reason)
            }
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

    /// Build an interceptor with a fresh sink, returning both so a test can
    /// assert on what was recorded.
    fn interceptor_with_sink(granted: Caveats) -> (CaveatInterceptor, DenialSink) {
        let sink: DenialSink = Arc::new(Mutex::new(Vec::new()));
        let interceptor = CaveatInterceptor::new(ctx(granted), Arc::clone(&sink));
        (interceptor, sink)
    }

    /// Snapshot the sink's recorded denials.
    fn drain(sink: &DenialSink) -> Vec<Denial> {
        sink.lock().unwrap().clone()
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
        let (interceptor, sink) = interceptor_with_sink(Caveats {
            exec: Scope::only(["echo".to_string()]),
            ..Caveats::top()
        });
        assert!(matches!(
            interceptor.before_exec("echo", &[]),
            ExecDecision::Allow
        ));
        assert!(matches!(
            interceptor.before_exec("rm", &["-rf".to_string()]),
            ExecDecision::Deny(_)
        ));
        // An Allow records nothing; only the Deny is in the sink.
        let recorded = drain(&sink);
        assert_eq!(
            recorded.len(),
            1,
            "exactly one denial expected: {recorded:?}"
        );
        assert_eq!(recorded[0].kind, DenialKind::Exec);
        assert_eq!(recorded[0].target, "rm");
        assert!(recorded[0].reason.contains("not within the granted"));
    }

    #[test]
    fn before_exec_denies_path_separator_spelled_command() {
        // The load-bearing case the hook exists for: `/bin/rm` is denied because
        // `/bin/rm` is not within `exec: Only{echo}` — the path-separator bypass
        // is closed, since the hook fires even for path-separator commands.
        let (interceptor, sink) = interceptor_with_sink(Caveats {
            exec: Scope::only(["echo".to_string()]),
            ..Caveats::top()
        });
        assert!(matches!(
            interceptor.before_exec("/bin/rm", &["-rf".to_string()]),
            ExecDecision::Deny(_)
        ));
        // The denial records the path-separator program verbatim.
        let recorded = drain(&sink);
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].kind, DenialKind::Exec);
        assert_eq!(recorded[0].target, "/bin/rm");
    }

    #[test]
    fn allow_records_nothing_in_sink() {
        // A permitted exec must NOT leave a denial — this is what keeps a
        // permitted command that exits 126 on its own from being flagged.
        let (interceptor, sink) = interceptor_with_sink(Caveats {
            exec: Scope::only(["echo".to_string()]),
            ..Caveats::top()
        });
        assert!(matches!(
            interceptor.before_exec("echo", &[]),
            ExecDecision::Allow
        ));
        assert!(drain(&sink).is_empty(), "an Allow must record nothing");
    }

    #[test]
    fn dev_null_sinks_are_always_writable() {
        // newt#969: `cmd 2>/dev/null` must never be a capability denial — the
        // sinks are not mutations. Even with NO caveats (fail-closed default
        // interceptor), the three standard sinks stay writable; everything
        // else keeps failing closed.
        let i = CaveatInterceptor::default();
        assert!(matches!(
            i.before_open(Path::new("/dev/null"), true),
            OpenDecision::Allow
        ));
        assert!(matches!(
            i.before_open(Path::new("/dev/stdout"), true),
            OpenDecision::Allow
        ));
        assert!(matches!(
            i.before_open(Path::new("/dev/stderr"), true),
            OpenDecision::Allow
        ));
        // Not a general /dev grant, and reads are unaffected by the whitelist.
        assert!(matches!(
            i.before_open(Path::new("/dev/sda"), true),
            OpenDecision::Deny(_)
        ));
        assert!(matches!(
            i.before_open(Path::new("/etc/passwd"), true),
            OpenDecision::Deny(_)
        ));
    }

    #[test]
    fn before_open_write_uses_fs_write_axis() {
        let dir = std::env::temp_dir();
        let (interceptor, _sink) = interceptor_with_sink(Caveats {
            fs_write: Scope::only([dir.to_string_lossy().into_owned()]),
            ..Caveats::top()
        });
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

    #[test]
    fn before_open_denial_is_recorded_as_open_kind() {
        let dir = std::env::temp_dir();
        let (interceptor, sink) = interceptor_with_sink(Caveats {
            fs_write: Scope::only([dir.to_string_lossy().into_owned()]),
            ..Caveats::top()
        });
        let _ = interceptor.before_open(Path::new("/etc/shadow"), true);
        let recorded = drain(&sink);
        assert_eq!(recorded.len(), 1, "one open denial expected: {recorded:?}");
        assert_eq!(recorded[0].kind, DenialKind::Open);
        assert_eq!(recorded[0].target, "/etc/shadow");
    }

    #[test]
    fn clones_share_one_sink() {
        // brush clones the interceptor; every clone must write to the same sink
        // (that is why the sink is Arc-shared). Two denials via two clones
        // appear in the one shared log.
        let (interceptor, sink) = interceptor_with_sink(Caveats {
            exec: Scope::only(["echo".to_string()]),
            ..Caveats::top()
        });
        let clone = interceptor.clone();
        let _ = interceptor.before_exec("rm", &[]);
        let _ = clone.before_exec("curl", &[]);
        let recorded = drain(&sink);
        assert_eq!(
            recorded.len(),
            2,
            "both clones' denials must land: {recorded:?}"
        );
        let targets: Vec<&str> = recorded.iter().map(|d| d.target.as_str()).collect();
        assert!(targets.contains(&"rm"));
        assert!(targets.contains(&"curl"));
    }
}
