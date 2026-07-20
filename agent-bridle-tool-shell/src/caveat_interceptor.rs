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
//! A third hook, `before_command`, fires once per command — builtins included —
//! and is where **cancellation** is observed; see the impl below.
//!
//! [`CaveatInterceptor`] carries one invocation's **effective** caveats (the
//! `ToolContext` minted by the gate) and delegates every decision to the
//! *shared* leash logic on [`ToolContext`] — [`ToolContext::check_exec`],
//! [`ToolContext::check_path_read`], [`ToolContext::check_path_write`]. It does
//! **not** duplicate the canonicalizing path check; the one in
//! `agent-bridle-core` (realpath, reject symlink/`..` escapes) is the single
//! source of truth.

use std::collections::HashSet;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use agent_bridle_core::{Denial, DenialKind, ToolContext};
use brush_core::extensions::{CommandDecision, CommandInterceptor, ExecDecision, OpenDecision};

/// The shared, per-invocation denial sink.
///
/// brush clones the [`CaveatInterceptor`] internally (the trait requires
/// `Clone`), so to see *every* denial the shell hit we cannot store the log in
/// the struct by value — each clone would get its own copy. The `Arc<Mutex<_>>`
/// makes all clones write to one vec. The `ShellTool` creates a *fresh* sink per
/// `invoke`, so two concurrent invocations never share one — that is what keeps
/// denials from cross-contaminating across invocations.
pub(crate) type DenialSink = Arc<Mutex<Vec<Denial>>>;

/// The shared, per-invocation **allow memo** (B1.3).
///
/// A confined loop re-spawns the same program thousands of times
/// (`while read f; do wc -l "$f"; done` → N identical `/usr/bin/wc` admissions),
/// and [`ToolContext::check_exec`] recomputes the identical answer every time.
/// This set records programs already admitted **under this invocation's `cx`** so
/// the second and later admissions short-circuit to `Allow`.
///
/// # Security invariant (the one thing to enforce in review)
///
/// This is a **pure memo, not an authority**. It is sound only because:
///
/// 1. **The key is the whole admission input.** `check_exec` is a function of
///    exactly `(cx.effective.exec, program)`. `cx` is fixed for the invocation
///    (`ToolContext::effective` is private with no setter — a running tool cannot
///    widen its own caveats), so for a fixed `cx` the answer is a function of
///    `program` alone. Memoizing therefore returns the *same* decision the
///    recomputation would, never a different one.
/// 2. **One cache belongs to exactly one `cx`.** The cache is created *inside*
///    [`CaveatInterceptor::new`], which is the only place a `cx` is installed, and
///    there is no constructor, setter, or accessor that lets a caller inject or
///    share a cache. So a cache cannot outlive, or be reused across, the
///    invocation whose caveats minted it — an `Allow` can never bleed across
///    leashes. The [`Default`] (fail-closed) interceptor gets `None` and caches
///    nothing.
/// 3. **Only `Allow` is memoized.** Denials are recomputed and re-recorded every
///    time, exactly as before, so the denial log and its telemetry are unchanged.
/// 4. **Cancellation is observed strictly earlier.** `before_command` fires (and
///    terminates a cancelled run) before control can ever reach `before_exec`,
///    so no memoized `Allow` can outlive a cancellation. See `before_command`.
///
/// `Arc<Mutex<_>>` for the same reason as [`DenialSink`]: brush clones the
/// interceptor internally, and every clone must consult the one shared memo.
pub(crate) type AllowCache = Arc<Mutex<HashSet<String>>>;

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
    /// Per-run cancellation flag (FIX 2). When an outer caller (the wall-clock
    /// timeout, or a future interrupt) trips this, the next `before_command` —
    /// or `before_open`, for a redirect opened outside any command — terminates
    /// the run. `None` (the default) means "no cancellation wired".
    cancel: Option<Arc<AtomicBool>>,
    /// Per-invocation memo of programs already admitted under `cx` (B1.3).
    /// `None` for the [`Default`] interceptor, which denies everything and so
    /// has nothing to memoize. See [`AllowCache`] for the security invariant.
    allow_cache: Option<AllowCache>,
}

impl CaveatInterceptor {
    /// Build an interceptor that enforces `cx`'s effective caveats and records
    /// every denial it makes into `sink`.
    ///
    /// The allow memo (B1.3) is minted **here**, together with `cx` — that is what
    /// structurally ties one cache to exactly one caveat set. There is
    /// deliberately no way to pass one in: see [`AllowCache`].
    #[must_use]
    pub(crate) fn new(cx: ToolContext, sink: DenialSink) -> Self {
        Self {
            cx: Some(cx),
            sink: Some(sink),
            cancel: None,
            allow_cache: Some(Arc::new(Mutex::new(HashSet::new()))),
        }
    }

    /// Whether `program` was already admitted under this invocation's `cx`.
    fn is_memoized_allow(&self, program: &str) -> bool {
        self.allow_cache.as_ref().is_some_and(|c| {
            c.lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .contains(program)
        })
    }

    /// Memoize an `Allow` for `program`. Only ever called after a real
    /// [`ToolContext::check_exec`] returned `Ok`.
    fn memoize_allow(&self, program: &str) {
        if let Some(cache) = &self.allow_cache {
            cache
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(program.to_string());
        }
    }

    /// Wire a per-run cancellation flag (FIX 2). When tripped, the next
    /// `before_command` terminates the run.
    #[must_use]
    pub(crate) fn with_cancel(mut self, cancel: Arc<AtomicBool>) -> Self {
        self.cancel = Some(cancel);
        self
    }

    /// Whether the run has been cancelled. `false` when no flag is wired.
    fn is_cancelled(&self) -> bool {
        self.cancel
            .as_ref()
            .is_some_and(|c| c.load(Ordering::SeqCst))
    }

    /// Record a cancelled run's refusal as a structured denial and return the
    /// reason to hand back as a `Deny`. This is the fail-closed direction — it
    /// refuses, never permits — so the OCAP guarantee is preserved.
    fn cancelled(&self, kind: DenialKind, target: impl Into<String>) -> String {
        const REASON: &str = "run cancelled (timeout or interrupt)";
        self.record(kind, target, REASON);
        REASON.to_string()
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
    /// **The cancellation seam.** Fires once per command — builtin, function,
    /// and external alike — so a run can be stopped wherever it is, and returns
    /// a `Deny` that *terminates* the run rather than becoming an exit status an
    /// enclosing loop would shrug off (`brush_core::error::Error::is_terminating`).
    ///
    /// This is what bounds a PURE-BUILTIN runaway (`while true; do :; done`),
    /// which reaches neither the external-spawn funnel (`before_exec`) nor the
    /// file-open one (`before_open`) and so had no observation point at all.
    ///
    /// It makes **no capability decision**: admission stays in `before_exec` /
    /// `before_open`, which have the resolved program path and the canonicalized
    /// file path this hook does not. Uncancelled runs always `Allow` — the hot
    /// path is one relaxed atomic load, no allocation.
    fn before_command(&self, name: &str) -> CommandDecision {
        if self.is_cancelled() {
            return CommandDecision::Deny(self.cancelled(DenialKind::Exec, name));
        }
        CommandDecision::Allow
    }

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
    ///
    /// Carries no cancellation check: `before_command` fires first on *every*
    /// path that reaches here (`ExecutionContext::execute` consults it before
    /// dispatching to `execute_via_external`, the sole caller of the
    /// `before_exec` site), so a cancelled run is already terminated. That is
    /// also what keeps the allow memo below sound —
    /// `memoized_allow_does_not_outlive_cancellation` pins it.
    fn before_exec(&self, program: &str, _args: &[String]) -> ExecDecision {
        if self.is_memoized_allow(program) {
            return ExecDecision::Allow;
        }
        match &self.cx {
            Some(cx) => match cx.check_exec(program) {
                Ok(()) => {
                    // Memoize only the affirmative decision; denials are
                    // recomputed and re-recorded every time (below), so the
                    // denial log is bit-for-bit what it was before B1.3.
                    self.memoize_allow(program);
                    ExecDecision::Allow
                }
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
    ///
    /// Keeps its cancellation check, unlike `before_exec`: a redirect on a
    /// COMPOUND command (`while …; done > f`) is opened by the interpreter's
    /// redirect setup, outside any command dispatch, so `before_command` is not
    /// provably ahead of this hook. Checked before the /dev/null allowance below
    /// so cancellation wins outright. Fail-closed and cheap.
    fn before_open(&self, path: &Path, write: bool) -> OpenDecision {
        if self.is_cancelled() {
            return OpenDecision::Deny(self.cancelled(DenialKind::Open, path.to_string_lossy()));
        }
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

    // ---- B1.3: the per-invocation allow memo -------------------------------

    /// The memo must not change any decision: repeated admissions return the
    /// same answer the uncached path computes, for both axes.
    #[test]
    fn memo_never_changes_a_decision() {
        let (interceptor, _sink) = interceptor_with_sink(Caveats {
            exec: Scope::only(["echo".to_string()]),
            ..Caveats::top()
        });
        for _ in 0..5 {
            assert!(matches!(
                interceptor.before_exec("echo", &[]),
                ExecDecision::Allow
            ));
            assert!(matches!(
                interceptor.before_exec("rm", &[]),
                ExecDecision::Deny(_)
            ));
        }
    }

    /// Denials are NEVER memoized: each one is recomputed and re-recorded, so
    /// the denial log is exactly what it was before B1.3 (five attempts on the
    /// same out-of-scope program still yield five records).
    #[test]
    fn denials_are_recorded_every_time_not_memoized() {
        let (interceptor, sink) = interceptor_with_sink(Caveats {
            exec: Scope::only(["echo".to_string()]),
            ..Caveats::top()
        });
        for _ in 0..5 {
            let _ = interceptor.before_exec("rm", &[]);
        }
        let recorded = drain(&sink);
        assert_eq!(
            recorded.len(),
            5,
            "every denial must still be recorded: {recorded:?}"
        );
        assert!(recorded.iter().all(|d| d.kind == DenialKind::Exec));
    }

    /// An `Allow` memoized under one invocation's caveats MUST NOT be visible to
    /// another invocation with different caveats. This is the security invariant:
    /// the cache is minted inside `new` alongside the `cx`, so two interceptors
    /// never share one — `echo` allowed over here stays denied over there.
    #[test]
    fn memo_does_not_bleed_across_invocations_with_different_caveats() {
        let (permissive, _s1) = interceptor_with_sink(Caveats {
            exec: Scope::only(["echo".to_string()]),
            ..Caveats::top()
        });
        // Warm the permissive interceptor's memo.
        assert!(matches!(
            permissive.before_exec("echo", &[]),
            ExecDecision::Allow
        ));

        // A DIFFERENT invocation, whose caveats do not grant `echo`.
        let (restrictive, sink) = interceptor_with_sink(Caveats {
            exec: Scope::only(["ls".to_string()]),
            ..Caveats::top()
        });
        assert!(
            matches!(restrictive.before_exec("echo", &[]), ExecDecision::Deny(_)),
            "a memoized Allow must never cross into an invocation with different caveats"
        );
        assert_eq!(drain(&sink).len(), 1, "and the denial is recorded");
    }

    /// brush clones the interceptor per pipeline stage; the clones must share the
    /// one memo (that is the whole point — otherwise each stage re-pays the
    /// admission). Sharing within ONE invocation is correct: same `cx`.
    #[test]
    fn clones_share_one_memo_within_an_invocation() {
        let (interceptor, _sink) = interceptor_with_sink(Caveats {
            exec: Scope::only(["echo".to_string()]),
            ..Caveats::top()
        });
        assert!(matches!(
            interceptor.before_exec("echo", &[]),
            ExecDecision::Allow
        ));
        let clone = interceptor.clone();
        assert!(
            clone.is_memoized_allow("echo"),
            "a clone must see the memo its sibling warmed"
        );
        assert!(matches!(
            clone.before_exec("echo", &[]),
            ExecDecision::Allow
        ));
    }

    /// The fail-closed default keeps no memo and still denies everything.
    #[test]
    fn default_interceptor_memoizes_nothing() {
        let interceptor = CaveatInterceptor::default();
        for _ in 0..3 {
            assert!(matches!(
                interceptor.before_exec("echo", &[]),
                ExecDecision::Deny(_)
            ));
        }
        assert!(!interceptor.is_memoized_allow("echo"));
    }

    /// **The cancellation-ordering guard.** A program already memoized as
    /// allowed must not outlive a cancellation. The memo lives in `before_exec`,
    /// which brush only reaches AFTER `before_command` has allowed the same
    /// command — so a cancelled run is terminated one hook earlier and the memo
    /// is never consulted. Without that ordering, the very loop the memo speeds
    /// up would become uncancellable from its second iteration onward.
    #[test]
    fn memoized_allow_does_not_outlive_cancellation() {
        let cancel = Arc::new(AtomicBool::new(false));
        let sink: DenialSink = Arc::new(Mutex::new(Vec::new()));
        let interceptor = CaveatInterceptor::new(ctx(Caveats::top()), Arc::clone(&sink))
            .with_cancel(Arc::clone(&cancel));

        // Warm the memo: `/bin/echo` is now a memoized Allow.
        assert!(matches!(
            interceptor.before_exec("/bin/echo", &[]),
            ExecDecision::Allow
        ));
        assert!(interceptor.is_memoized_allow("/bin/echo"));

        // Trip cancellation; the gate the memoized program must pass first is
        // `before_command`, and it terminatingly refuses.
        cancel.store(true, Ordering::SeqCst);
        assert!(
            matches!(
                interceptor.before_command("/bin/echo"),
                CommandDecision::Deny(_)
            ),
            "a cancelled run must be denied even for a memoized-Allow program"
        );

        // The cancellation is recorded as a structured exec denial — the memo
        // did not swallow the telemetry either.
        let recorded = drain(&sink);
        assert_eq!(recorded.len(), 1, "one cancellation denial: {recorded:?}");
        assert_eq!(recorded[0].kind, DenialKind::Exec);
    }

    /// An uncancelled run's `before_command` makes no capability decision: it
    /// allows everything, leaving admission to `before_exec`/`before_open`.
    #[test]
    fn before_command_allows_when_not_cancelled() {
        let (interceptor, sink) = interceptor_with_sink(Caveats::default());
        assert!(matches!(
            interceptor.before_command("rm"),
            CommandDecision::Allow
        ));
        assert!(drain(&sink).is_empty(), "an Allow records no denial");
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
