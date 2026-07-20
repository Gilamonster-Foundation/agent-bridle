//! The carried **brush engine** (agent-bridle#20 / Track 2): a bash-in-Rust
//! shell run **in-process**, confined by the `CommandInterceptor` L2 leash.
//!
//! Unlike [`HostShellTool`](crate::HostShellTool) — which *refuses* a restricted
//! `exec`/`net` grant because it cannot bound a real `/bin/sh`'s forked children
//! — this engine's interceptor fires on every resolved program name and every
//! opened path *inside* brush (`before_exec` at the single external-spawn funnel,
//! `before_open` at `Shell::open_file`). So it **serves** restricted `exec`/`fs`
//! grants, in-process, on any platform, and records each denial into a shared
//! sink surfaced as structured `denials` on the envelope.
//!
//! It uses the temporary `brush-ocap-*` fork carrying the upstream hook PR
//! (reubeno/brush#1184). Enforcement is L2 (advisory `sandbox_kind = None`); an
//! L3 backstop is a follow-up. The curated builtin set removes `exec` (the one
//! builtin that spawns outside the `before_exec` funnel — a proven bypass).

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;

use agent_bridle_core::{
    default_exec_path, Denial, Disclosure, SandboxKind, Scope, Tool, ToolContext, ToolEnvelope,
    ToolError, ToolResult,
};
use async_trait::async_trait;
use brush_builtins::{default_builtins, BuiltinSet};
use brush_core::builtins::Registration;
use brush_core::extensions::{DefaultErrorFormatter, ShellExtensionsImpl};
use brush_core::openfiles::{OpenFile, OpenFiles};
use brush_core::variables::ShellVariable;
use brush_core::{Shell, ShellFd};

use crate::caveat_interceptor::{CaveatInterceptor, DenialSink};
use crate::output_observer::{drain_capped, output_session, OutputEmitter};

/// The engine identity stamped on the disclosure (ADR 0005 D2 / ADR 0019 D4).
const ENGINE_NAME: &str = "brush";
/// Default cap on captured output bytes (mirrors the other engines' default).
const DEFAULT_MAX_OUTPUT: usize = 64 * 1024;
/// Minimal, standard `PATH` used when `exec` is RESTRICTED: external commands
/// must still *resolve* so they reach the interceptor's `before_exec` gate
/// (which then denies the out-of-scope ones). Under full-access the full ambient
/// path is used instead (see [`BrushShellTool::invoke`]).
const RESTRICTED_PATH: &str = "/usr/local/bin:/usr/bin:/bin";
/// Builtins removed from the confined shell because they reach `spawn`/`exec`
/// *without* going through the interceptor funnels. The brush-fork audit found
/// exactly one: `exec` (its non-subshell branch calls `cmd.exec()` directly). A
/// confined shell needs nothing to replace into, so removing it closes a live
/// authority leak at zero cost. Every other spawn/open path funnels through a
/// hook and is intentionally kept.
const REMOVED_BUILTINS: &[&str] = &["exec"];

/// Default wall-clock ceiling for a confined run (FIX 3). Sourced from the shared
/// shell-limits contract — [`LimitsPolicy::default_timeout_secs`](agent_bridle_core::LimitsPolicy)
/// (60s) — so the brush path bounds itself exactly like the safe-subset and host
/// engines instead of running unbounded.
fn default_timeout() -> Duration {
    Duration::from_secs(agent_bridle_core::LimitsPolicy::default().default_timeout_secs)
}

/// The brush [`ShellExtensions`](brush_core::extensions::ShellExtensions) carried
/// by this engine: the default error formatter plus the capability interceptor.
type LeashedExtensions = ShellExtensionsImpl<DefaultErrorFormatter, CaveatInterceptor>;

/// The engine's input schema (shared `cmd`/`env`/`cwd` contract with the other
/// engines), parsed once from the embedded data file — knowledge in data, not an
/// inline literal (three-Cs).
static DEFAULT_SCHEMA: LazyLock<Arc<serde_json::Value>> = LazyLock::new(|| {
    Arc::new(
        serde_json::from_str(include_str!("host_shell.schema.json"))
            .expect("embedded host_shell.schema.json must be valid JSON"),
    )
});

/// The carried brush engine — a [`Tool`] that runs a free-form command string
/// through an in-process bash-in-Rust shell confined by the `CommandInterceptor`
/// leash. Registered under `"shell"` (the ADR 0005 D2 seam), a peer of
/// [`ShellTool`](crate::ShellTool) / [`HostShellTool`](crate::HostShellTool).
#[derive(Clone)]
pub struct BrushShellTool {
    max_output: usize,
    schema: Arc<serde_json::Value>,
    output_observer: Option<Arc<dyn crate::ShellOutputObserver>>,
    /// Wall-clock ceiling for one run (FIX 3). A run that exceeds it is stopped
    /// and reported `timed_out:true` with exit 124.
    timeout: Duration,
}

impl std::fmt::Debug for BrushShellTool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BrushShellTool").finish_non_exhaustive()
    }
}

impl Default for BrushShellTool {
    fn default() -> Self {
        Self::new()
    }
}

impl BrushShellTool {
    /// The engine with default output cap and the embedded schema.
    #[must_use]
    pub fn new() -> Self {
        Self {
            max_output: DEFAULT_MAX_OUTPUT,
            schema: DEFAULT_SCHEMA.clone(),
            output_observer: None,
            timeout: default_timeout(),
        }
    }

    /// Override the wall-clock ceiling (three-Cs: Configuration). A run that
    /// exceeds `timeout` is stopped — the FIX-2 cancel flag is tripped, and the
    /// worker's next command is denied terminatingly — and reported
    /// `timed_out:true` with exit 124.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Attach a presentation-only observer for bounded stdout/stderr chunks.
    ///
    /// The observer receives only output captured by an admitted invocation and
    /// cannot change the interceptor, authority, or final result envelope.
    /// Delivery may finish asynchronously after the invocation returns;
    /// `on_finish` marks the queue-drained boundary.
    #[must_use]
    pub fn with_output_observer(mut self, observer: Arc<dyn crate::ShellOutputObserver>) -> Self {
        self.output_observer = Some(observer);
        self
    }

    /// Override the tool's input schema (three-Cs: Configuration).
    #[must_use]
    pub fn with_schema(mut self, schema: serde_json::Value) -> Self {
        self.schema = Arc::new(schema);
        self
    }

    fn disclosure(&self) -> Disclosure {
        Disclosure {
            engine: Some(ENGINE_NAME.to_string()),
            ..Disclosure::default()
        }
    }
}

#[async_trait]
impl Tool for BrushShellTool {
    fn name(&self) -> &str {
        "shell"
    }

    fn schema(&self) -> serde_json::Value {
        (*self.schema).clone()
    }

    async fn invoke(
        &self,
        args: serde_json::Value,
        cx: &ToolContext,
    ) -> ToolResult<serde_json::Value> {
        let cmd = args
            .get("cmd")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| ToolError::denied("brush: missing required `cmd` string"))?
            .to_string();
        let cwd = args
            .get("cwd")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string);

        // The schema's `env` seam: the DELIBERATE import surface across the
        // confinement boundary (this engine runs `do_not_inherit_env(true)`, so
        // nothing ambient leaks in). String values only, mirroring the host and
        // safe-subset engines. Before this, brush silently DROPPED `env` even
        // though the schema advertised it — losing HOME/USER/VIRTUAL_ENV and
        // re-opening the #783-class `~`-expansion bug under this engine.
        let env: BTreeMap<String, String> = args
            .get("env")
            .and_then(serde_json::Value::as_object)
            .map(|m| {
                m.iter()
                    .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                    .collect()
            })
            .unwrap_or_default();

        // PATH parity: the FULL ambient path when `exec` is unrestricted (so the
        // agent's own tools — `~/.cargo/bin`, `/opt/homebrew/bin`, … — resolve
        // like a host shell); a minimal standard path when `exec` is RESTRICTED,
        // so externals still resolve to reach the `before_exec` gate that denies
        // the out-of-scope ones. The host env is never inherited otherwise.
        let path_value = if matches!(cx.caveats().exec, Scope::All) {
            default_exec_path()
        } else {
            RESTRICTED_PATH.to_string()
        };

        let sink: DenialSink = Arc::new(Mutex::new(Vec::new()));
        // FIX 2: a per-run cancellation flag wired into the interceptor. An outer
        // caller trips it (the FIX-3 wall-clock timeout below, or a future newt
        // interrupt) and the interceptor aborts the run at the next command /
        // redirect boundary — so a runaway confined command is recoverable.
        let cancel = Arc::new(AtomicBool::new(false));
        let interceptor =
            CaveatInterceptor::new(cx.clone(), Arc::clone(&sink)).with_cancel(Arc::clone(&cancel));
        let max_output = self.max_output;
        let (output_guard, output) = output_session(self.output_observer.clone(), max_output);

        // brush's shell API is async and blocks on a per-invocation current-thread
        // runtime; run it off the async runtime on a blocking worker, bounded by
        // the wall-clock ceiling (FIX 3). Mirrors the safe-subset / host engines.
        let run = tokio::task::spawn_blocking(move || {
            run_in_brush(cmd, cwd, path_value, env, interceptor, max_output, output)
        });
        let timeout = self.timeout;
        match tokio::time::timeout(timeout, run).await {
            Ok(joined) => {
                let captured = joined
                    .map_err(|e| ToolError::Exec(std::io::Error::other(format!("join: {e}"))))??;
                // Any denial the interceptor recorded lifts the envelope to `denied:true`.
                let denials: Vec<Denial> = sink.lock().map(|g| g.clone()).unwrap_or_default();
                let envelope = ToolEnvelope::new(SandboxKind::None)
                    .with_disclosure(self.disclosure())
                    .with_exit_code(captured.exit_code)
                    .with_stdout(captured.stdout)
                    .with_stderr(captured.stderr)
                    .with_timed_out(false)
                    .with_denials(denials)
                    .into_json();
                output_guard.finish();
                Ok(envelope)
            }
            Err(_elapsed) => {
                // FIX 3: on elapse, TRIP the FIX-2 cancel flag. The worker
                // observes it at its next COMMAND boundary — `before_command`
                // fires for every command, builtins included, and its `Deny` is
                // terminating — so the operator recovers at the ceiling
                // (`timed_out:true` + exit 124, mirroring the safe-subset/host
                // paths) AND the interpreter actually stops, including a
                // pure-builtin loop (`while true; do :; done`).
                //
                // Residual gap: a run already blocked INSIDE a command reaches no
                // further command boundary, so it is not stopped here — a `wait`
                // on a background job, a blocking fifo read, or an
                // already-spawned long child (`sleep 30`, which is also not
                // killed). Those need kill-on-drop at the fork level (Effort B).
                //
                // ENGINE DEFECT this ceiling is currently masking (measured
                // 2026-07-19, brush-ocap-core 0.5.0): a COMPOUND command
                // (`while`/`for`/`if`/`{…}`/subshell) used as a NON-FINAL pipeline
                // stage deadlocks once it writes more than one pipe buffer
                // (64 KiB on macOS). `interp.rs` `ExecuteInPipeline for
                // ast::Command`, arm `Self::Compound(..)`, runs the compound
                // INLINE to completion (`.await` → `ExecutionSpawnResult::
                // Completed`) instead of spawning it like the `Self::Simple` arm
                // does, and `spawn_pipeline_processes` awaits each stage in
                // order — so the DOWNSTREAM stage is not created until the
                // compound finishes. The compound therefore writes into a pipe
                // with no reader, fills the buffer, and blocks forever.
                //
                // Measured: `while …; done | cat` emitting 2000×32B (62 KiB)
                // completes in 0.23s; the same loop at 2100×32B (65 KiB) never
                // completes (still running at a 240s ceiling). It needs NO
                // external command to reproduce — a pure-builtin `echo` body is
                // enough — so this is NOT a spawn-cost problem, and it is the
                // real reason the canonical `find … | while read f; do wc -l
                // "$f"; done | sort -rn | head` "hangs" on a large tree while
                // bash runs it in ~3s. Below the threshold the same pipeline is
                // byte-identical to bash and already at spawn-cost parity.
                //
                // The fix is fork-side (Effort B): the `Compound` arm must spawn
                // to a task and return `StartedTask` when it is a non-final
                // stage, mirroring `execute_via_builtin_in_owned_shell`.
                cancel.store(true, Ordering::SeqCst);
                // FIX 5: surface denials the run recorded BEFORE it timed out, so
                // leash telemetry survives a timed-out run (the Ok branch does the
                // same). The still-running worker may append more, but a lock
                // serializes the read; we take the snapshot as of now.
                let denials: Vec<Denial> = sink.lock().map(|g| g.clone()).unwrap_or_default();
                // Stop accepting presentation events at the timeout boundary; the
                // detached worker may still be winding down.
                drop(output_guard);
                Ok(ToolEnvelope::new(SandboxKind::None)
                    .with_disclosure(self.disclosure())
                    .with_exit_code(124)
                    .with_stderr(format!("command timed out after {}s", timeout.as_secs()))
                    .with_timed_out(true)
                    .with_denials(denials)
                    .into_json())
            }
        }
    }
}

/// What a finished brush run produced.
#[derive(Debug)]
struct Captured {
    exit_code: i32,
    stdout: String,
    stderr: String,
}

/// Drive a brush shell to completion for one command, capturing stdout/stderr
/// via real OS pipes (an `Arc<Mutex<Vec<u8>>>` will not satisfy brush's fd
/// `Stream`; pipes are mandatory). The shell is built with the supplied
/// [`CaveatInterceptor`] so exec/open are confined in-process. IO must be enabled
/// on the runtime (not just time): `$(...)` sets up real pipes via tokio's IO
/// driver, and with IO enabled the inner program hits the `before_exec` funnel
/// (a legible recorded denial) rather than panicking.
fn run_in_brush(
    cmd: String,
    cwd: Option<String>,
    path_value: String,
    env: BTreeMap<String, String>,
    interceptor: CaveatInterceptor,
    max_output: usize,
    output: OutputEmitter,
) -> ToolResult<Captured> {
    let (out_reader, out_writer) =
        std::io::pipe().map_err(|e| ToolError::Exec(brush_io("create stdout pipe", &e)))?;
    let (err_reader, err_writer) =
        std::io::pipe().map_err(|e| ToolError::Exec(brush_io("create stderr pipe", &e)))?;

    // Drain the read ends on background threads so a chatty command cannot
    // deadlock by filling the pipe buffer before the shell exits. Each thread
    // reports its captured output over a channel (FIX 4) rather than via
    // `JoinHandle::join`: a `join` blocks the caller for the ENTIRE lifetime of
    // any background child that inherited a dup of the write pipe (brush hands
    // each child a real `dup(2)`; there is no kill-on-drop), which would pin a
    // scarce `spawn_blocking` worker — so `collect_drained` bounded-waits then
    // DETACHES instead.
    let (out_tx, out_rx) = std::sync::mpsc::channel();
    let stdout_output = output.clone();
    std::thread::spawn(move || {
        let _ = out_tx.send(drain(
            out_reader,
            max_output,
            &stdout_output,
            crate::ShellOutputStream::Stdout,
        ));
    });
    let (err_tx, err_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = err_tx.send(drain(
            err_reader,
            max_output,
            &output,
            crate::ShellOutputStream::Stderr,
        ));
    });

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| ToolError::Exec(brush_io("build shell runtime", &e)))?;

    let working_dir = cwd.map(std::path::PathBuf::from);

    let exit_code = rt.block_on(async move {
        let mut fds: HashMap<ShellFd, OpenFile> = HashMap::new();
        // FIX 1 (critical #4): seed STDIN_FD with `/dev/null` (an at-EOF reader).
        // Otherwise brush defaults STDIN_FD to the real `std::io::stdin()`
        // (`openfiles.rs` `default_files`), so a confined `cat`/`wc`/`grep`/`sort`
        // with no pipe would read the OPERATOR'S TERMINAL — hanging the turn,
        // stealing keystrokes, and corrupting MCP stdio. `openfiles::null()` is the
        // cross-platform sink (`/dev/null` on unix, `NUL` on Windows), mirroring
        // how the safe-subset engine gives spawned children `Stdio::null()`.
        fds.insert(
            OpenFiles::STDIN_FD,
            brush_core::openfiles::null()
                .map_err(|e| ToolError::Exec(brush_io("open /dev/null stdin", &e)))?,
        );
        fds.insert(OpenFiles::STDOUT_FD, OpenFile::from(out_writer));
        fds.insert(OpenFiles::STDERR_FD, OpenFile::from(err_writer));

        let mut shell: Shell<LeashedExtensions> =
            Shell::builder_with_extensions::<LeashedExtensions>()
                .command_interceptor(interceptor)
                .builtins(confined_builtins())
                .do_not_inherit_env(true)
                .no_editing(true)
                .interactive(false)
                .fds(fds)
                .maybe_working_dir(working_dir)
                .build()
                .await
                .map_err(|e| ToolError::Exec(brush_io("build shell", &e)))?;

        // Register the carried coreutils shims (issue #206). They re-exec
        // `<self> --invoke-bundled <name>`, so they resolve in-process ONLY when
        // the host binary is dispatch-capable (calls `maybe_dispatch()` in main).
        // The re-exec still funnels through the `before_exec` interceptor.
        #[cfg(feature = "carried-coreutils")]
        {
            crate::coreutils_dispatch::install_default_providers();
            crate::coreutils_dispatch::register_shims(&mut shell);
        }

        shell
            .env_mut()
            .set_global("PATH", ShellVariable::new(path_value))
            .map_err(|e| ToolError::Exec(brush_io("seed PATH", &e)))?;

        // Windows: a child spawned under `do_not_inherit_env(true)` needs the
        // OS-minimal vars (`SystemRoot`, …) or `CreateProcess`/CRT init fails to
        // start it at all. These are not secrets — every Windows process needs
        // them — so seeding them keeps external commands and the carried-coreutils
        // re-exec runnable under confinement. Unix needs none of this.
        #[cfg(windows)]
        for key in [
            "SystemRoot",
            "SystemDrive",
            "windir",
            "TEMP",
            "TMP",
            "USERPROFILE",
            "NUMBER_OF_PROCESSORS",
        ] {
            if let Ok(val) = std::env::var(key) {
                let _ = shell.env_mut().set_global(key, ShellVariable::new(val));
            }
        }

        // Import the caller-provided env (the schema's `env` seam) LAST, so a
        // caller `PATH` (e.g. a venv-prepended one) wins over the exec-scope
        // seed above — matching the host and safe-subset engines. This does NOT
        // widen authority: `before_exec` gates the RESOLVED PROGRAM against the
        // caveats regardless of `PATH` (host_shell.schema.json). Nothing ambient
        // is inherited; only these explicitly-passed vars cross the boundary.
        for (key, val) in &env {
            shell
                .env_mut()
                .set_global(key, ShellVariable::new(val.clone()))
                .map_err(|e| ToolError::Exec(brush_io("seed env var", &e)))?;
        }

        let result = shell.run_dash_c_command(cmd).await.map_err(|e| {
            // FIX 2: the interceptor's `before_command` answers a cancelled
            // run with a TERMINATING `CommandDenied`, which the interpreter
            // propagates out of the run instead of folding into an exit
            // status an enclosing loop would shrug off. That is the only
            // terminating error we can provoke, so it is exactly this run's
            // clean cancellation.
            if e.is_terminating() {
                ToolError::denied("brush run cancelled (timeout or interrupt)")
            } else {
                ToolError::Exec(brush_io("run command", &e))
            }
        })?;

        // Drop the shell so it releases its clones of the pipe writers; only then
        // do the reader threads see EOF.
        drop(shell);

        Ok::<i32, ToolError>(i32::from(u8::from(result.exit_code)))
    })?;

    let stdout = collect_drained(&out_rx, "stdout")?;
    let stderr = collect_drained(&err_rx, "stderr")?;

    Ok(Captured {
        exit_code,
        stdout,
        stderr,
    })
}

/// Wall-clock ceiling for waiting on a drain thread before DETACHING it (FIX 4).
/// The drain finishes as soon as every writer — the shell's own clones plus any
/// dup a background child inherited — is closed; in the common case (no surviving
/// child) that is immediate after `drop(shell)`, so this bound is only ever hit
/// when a background child keeps a pipe-writer dup open. It caps how long a single
/// confined run can hold its `spawn_blocking` worker on drain, well under the
/// engine's wall-clock timeout.
const DRAIN_DETACH_DEADLINE: Duration = Duration::from_millis(500);

/// Collect a drain thread's captured output without ever pinning the (scarce)
/// `spawn_blocking` worker on it (FIX 4 / finding #7). Returns as soon as the
/// drain finishes; if a background child holds a pipe-writer dup past
/// [`DRAIN_DETACH_DEADLINE`], DETACHES the drain thread (a cheap leaked OS thread
/// that self-terminates when the child eventually exits) and returns empty — the
/// observer already received the live bytes; the worker is freed rather than hung
/// for the child's whole lifetime.
fn collect_drained(
    rx: &std::sync::mpsc::Receiver<ToolResult<String>>,
    stream: &str,
) -> ToolResult<String> {
    use std::sync::mpsc::RecvTimeoutError;
    match rx.recv_timeout(DRAIN_DETACH_DEADLINE) {
        // The drain finished and reported its captured output (or a drain error).
        Ok(result) => result,
        // A background child still holds the write pipe: detach, free the worker.
        Err(RecvTimeoutError::Timeout) => Ok(String::new()),
        // The drain thread dropped its sender without reporting — it panicked.
        Err(RecvTimeoutError::Disconnected) => Err(ToolError::denied(format!(
            "{stream} reader thread panicked"
        ))),
    }
}

/// The curated builtin set: the bash-mode default set with [`REMOVED_BUILTINS`]
/// stripped out (robust-by-construction — a removed builtin is simply gone, so a
/// confined shell running `exec` gets "command not found", never a spawn).
fn confined_builtins() -> HashMap<String, Registration<LeashedExtensions>> {
    let mut builtins = default_builtins::<LeashedExtensions>(BuiltinSet::BashMode);
    for name in REMOVED_BUILTINS {
        builtins.remove(*name);
    }
    builtins
}

/// Read a pipe to EOF (capped at `max` bytes), returning lossy UTF-8.
fn drain(
    reader: std::io::PipeReader,
    max: usize,
    output: &OutputEmitter,
    stream: crate::ShellOutputStream,
) -> ToolResult<String> {
    let (buf, _truncated) = drain_capped(reader, max, output, stream)
        .map_err(|e| ToolError::Exec(brush_io("drain pipe", &e)))?;
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// Wrap a brush/IO error with context as an [`std::io::Error`].
fn brush_io(ctx: &str, e: &impl std::fmt::Display) -> std::io::Error {
    std::io::Error::other(format!("{ctx}: {e}"))
}

/// FIX 2 cancellation-seam tests. These exercise the private `run_in_brush`
/// funnel directly (the cancel flag is per-run and, until the timeout wiring in
/// FIX 3, not reachable through `invoke`), and are real-spawn by nature — brush
/// runs its shell in-process, there is no mock. Unix-only for the fixed
/// `/bin/*` external paths that force the `before_exec` funnel.
#[cfg(all(test, unix))]
mod cancel_tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::{Duration, Instant};

    use agent_bridle_core::{Caveats, DenialKind, Gate, Scope, Tool, ToolResult};

    use crate::caveat_interceptor::DenialSink;

    /// Mint a `ToolContext` the only legitimate way — through the gate.
    fn ctx(granted: Caveats) -> agent_bridle_core::ToolContext {
        struct AnyTool;
        #[async_trait]
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
                _cx: &agent_bridle_core::ToolContext,
            ) -> ToolResult<serde_json::Value> {
                Ok(serde_json::Value::Null)
            }
        }
        Gate::new(0)
            .authorize(&AnyTool, &granted)
            .expect("authorize")
    }

    /// A pre-tripped flag makes the run abort at the very first external-spawn
    /// boundary (`before_exec`) instead of completing — and the abort is recorded
    /// as a structured `exec` denial, i.e. it REFUSED the spawn (OCAP-preserving),
    /// never allowed one.
    #[test]
    fn cancel_flag_aborts_at_the_next_external_command() {
        let cancel = Arc::new(AtomicBool::new(true));
        let sink: DenialSink = Arc::new(Mutex::new(Vec::new()));
        let interceptor = CaveatInterceptor::new(ctx(Caveats::top()), Arc::clone(&sink))
            .with_cancel(Arc::clone(&cancel));

        let res = run_in_brush(
            "/bin/echo hi".to_string(),
            None,
            RESTRICTED_PATH.to_string(),
            BTreeMap::new(),
            interceptor,
            DEFAULT_MAX_OUTPUT,
            OutputEmitter::default(),
        );

        assert!(
            res.is_err(),
            "a cancelled run must abort, not complete: {res:?}"
        );
        let recorded = sink.lock().expect("sink").clone();
        assert_eq!(recorded.len(), 1, "one cancellation denial: {recorded:?}");
        assert_eq!(recorded[0].kind, DenialKind::Exec);
    }

    /// The load-bearing recovery property, shared by every loop shape below: a
    /// loop that would spin forever is stopped PROMPTLY by tripping the flag
    /// mid-run, and the blocking worker FINISHES — no leaked, grinding thread
    /// (report open-Q #4) — returning a cancellation error rather than panicking.
    ///
    /// Hermetic by construction: the caveats grant no exec authority, so a loop
    /// body that *is* an external is refused at `before_exec` (a cheap recorded
    /// denial, no real subprocess) while still cycling the interpreter.
    ///
    /// Returns the recorded denials so a caller can assert on them.
    fn assert_loop_is_cancellable(cmd: &str, path: &str, what: &str) -> Vec<Denial> {
        let cancel = Arc::new(AtomicBool::new(false));
        let sink: DenialSink = Arc::new(Mutex::new(Vec::new()));
        let cx = ctx(Caveats {
            exec: Scope::only(["__never_in_scope__".to_string()]),
            ..Caveats::top()
        });
        let interceptor =
            CaveatInterceptor::new(cx, Arc::clone(&sink)).with_cancel(Arc::clone(&cancel));

        let (cmd, path) = (cmd.to_string(), path.to_string());
        let worker = std::thread::spawn(move || {
            run_in_brush(
                cmd,
                None,
                path,
                BTreeMap::new(),
                interceptor,
                DEFAULT_MAX_OUTPUT,
                OutputEmitter::default(),
            )
        });

        // Let the loop get going; it is infinite, so it must still be running.
        std::thread::sleep(Duration::from_millis(150));
        assert!(
            !worker.is_finished(),
            "the {what} loop should still be spinning before cancel"
        );

        // Trip the flag: the next `before_command` observes it and terminates.
        cancel.store(true, Ordering::SeqCst);

        let deadline = Instant::now() + Duration::from_secs(5);
        while !worker.is_finished() {
            assert!(
                Instant::now() < deadline,
                "cancel did not stop the {what} loop — the blocking worker leaked"
            );
            std::thread::sleep(Duration::from_millis(10));
        }

        let res = worker
            .join()
            .expect("the worker must return cleanly, not panic");
        assert!(
            res.is_err(),
            "a cancelled {what} run returns a cancellation error: {res:?}"
        );
        let recorded = sink.lock().expect("sink").clone();
        recorded
    }

    /// **The headline bound.** A loop of PURE BUILTINS reaches no external-spawn
    /// and no file-open boundary, so before `before_command` existed it had no
    /// observation point at all: the timeout fired, the caller got exit 124, and
    /// the detached worker span a CPU until process exit. `before_command` fires
    /// once per command — builtins included — and its `Deny` terminates the run
    /// instead of being folded into an exit status the enclosing loop shrugs off.
    #[test]
    fn tripping_cancel_stops_a_pure_builtin_loop() {
        assert_loop_is_cancellable("while true; do :; done", "", "pure-builtin");
    }

    /// The external-command shape: unchanged behavior, now observed one hook
    /// earlier (`before_command` precedes `before_exec` on every path).
    #[test]
    fn tripping_cancel_stops_a_loop_of_an_external_command() {
        assert_loop_is_cancellable(
            "while true; do /bin/true; done",
            RESTRICTED_PATH,
            "external",
        );
    }

    /// **The carried-coreutils cancellation guard.** A loop whose body is a
    /// CARRIED util (`cat`, registered as a shim builtin) must remain
    /// cancellable — the same property the shapes above pin.
    ///
    /// This now holds for the strongest reason: `before_command` fires for the
    /// shim itself, so cancellation no longer depends on the shim's re-exec
    /// crossing `before_exec`. It stays a REGRESSION GUARD for the in-process
    /// carried-coreutils work (B1.1) — the denial assertion below still pins
    /// that a carried util crosses the leash — so do not delete it when making
    /// carried utils in-process; make it pass.
    #[cfg(feature = "carried-coreutils")]
    #[test]
    fn tripping_cancel_stops_a_loop_of_a_carried_coreutil() {
        // `cat` resolves to the carried shim, NOT to /bin/cat: PATH is empty, so
        // nothing external could satisfy it.
        let recorded = assert_loop_is_cancellable(
            "while true; do cat /etc/hostname; done",
            "",
            "carried-util",
        );
        // The loop really did reach the admission seam every iteration (rather
        // than running the util in-process, invisible to the leash).
        assert!(
            recorded.iter().any(|d| d.kind == DenialKind::Exec),
            "the carried-util loop must register exec-axis denials: {recorded:?}"
        );
    }
}

/// FIX 4 detach-mechanism tests. The load-bearing behavior — free the scarce
/// `spawn_blocking` worker instead of pinning it for the whole lifetime of a
/// background child that holds a pipe-writer dup — lives in `collect_drained`, so
/// it is exercised DIRECTLY here. (An end-to-end `sleep 5 & echo hi` invoke would
/// route through brush's real `&` job control, which is inherently racy on the
/// per-run current-thread runtime — finding #7 / Effort B — and makes a timing
/// assertion flaky; the detach itself is deterministic.)
#[cfg(test)]
mod drain_tests {
    use super::*;
    use std::io::Write;
    use std::time::Instant;

    /// A writer kept open (as a surviving background child would keep its dup)
    /// must NOT pin the caller: `collect_drained` bounded-waits to the deadline,
    /// then DETACHES and returns — freeing the worker while a cheap OS drain
    /// thread lingers until the writer finally closes.
    #[test]
    fn collect_drained_detaches_when_a_writer_stays_open() {
        let (reader, writer) = std::io::pipe().expect("pipe");
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(drain(
                reader,
                DEFAULT_MAX_OUTPUT,
                &OutputEmitter::default(),
                crate::ShellOutputStream::Stdout,
            ));
        });

        let start = Instant::now();
        let out = collect_drained(&rx, "stdout").expect("no drain error");
        let elapsed = start.elapsed();

        assert!(
            elapsed >= DRAIN_DETACH_DEADLINE
                && elapsed < DRAIN_DETACH_DEADLINE + Duration::from_secs(2),
            "must detach ~at the deadline, not block on the held-open writer: {elapsed:?}"
        );
        assert_eq!(out, "", "detached before EOF → empty captured output");

        // Releasing the writer lets the detached drain thread reach EOF and end.
        drop(writer);
    }

    /// The common case: once every writer is closed the drain reaches EOF and
    /// `collect_drained` returns the FULL captured output PROMPTLY — well under
    /// the detach deadline — so normal runs lose nothing to the backstop.
    #[test]
    fn collect_drained_returns_full_output_promptly_when_writers_close() {
        let (reader, mut writer) = std::io::pipe().expect("pipe");
        writer.write_all(b"captured-output").expect("write");
        drop(writer); // EOF: no surviving writer dup.

        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(drain(
                reader,
                DEFAULT_MAX_OUTPUT,
                &OutputEmitter::default(),
                crate::ShellOutputStream::Stdout,
            ));
        });

        let start = Instant::now();
        let out = collect_drained(&rx, "stdout").expect("no drain error");
        assert_eq!(out, "captured-output", "full foreground output is captured");
        assert!(
            start.elapsed() < DRAIN_DETACH_DEADLINE,
            "must return as soon as the drain EOFs, not wait out the detach deadline"
        );
    }
}
