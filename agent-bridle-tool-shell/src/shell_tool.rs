//! The confined [`ShellTool`].

use std::collections::HashMap;
use std::io::Read;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use agent_bridle_core::{
    Caveats, Denial, SandboxKind, Tool, ToolContext, ToolEnvelope, ToolError, ToolResult,
};
use async_trait::async_trait;
use brush_builtins::{default_builtins, BuiltinSet};
use brush_core::extensions::{DefaultErrorFormatter, ShellExtensionsImpl};
use brush_core::openfiles::OpenFile;
use brush_core::{Shell, ShellFd};

use crate::caveat_interceptor::{CaveatInterceptor, DenialSink};

/// Maximum permitted timeout, in seconds. Requests above this are clamped.
const MAX_TIMEOUT_SECS: u64 = 300;
/// Default timeout when the caller does not specify one.
const DEFAULT_TIMEOUT_SECS: u64 = 30;

/// brush fds.
const STDOUT_FD: ShellFd = 1;
const STDERR_FD: ShellFd = 2;

/// A standard `PATH` for free-form (`cmd`) mode so external commands *resolve*
/// — and therefore reach the [`CaveatInterceptor`]'s `before_exec` hook, which
/// is the real gate. Without a resolvable `PATH`, a denied command like `rm`
/// would fail as "command not found" before the hook ever fires; with it, the
/// hook denies it explicitly (and `/bin/rm` is denied regardless of `PATH`,
/// since the path-separator branch goes straight to the spawn funnel). The host
/// environment is still *not* inherited — only this `PATH` is seeded.
const FREEFORM_PATH: &str = "/usr/local/bin:/usr/bin:/bin";

/// The brush [`ShellExtensions`](brush_core::extensions::ShellExtensions) we
/// build: the default error formatter plus our capability [`CaveatInterceptor`].
type LeashedExtensions = ShellExtensionsImpl<DefaultErrorFormatter, CaveatInterceptor>;

/// A shell tool that runs a command through a brush shell confined by the leash.
///
/// It accepts **two input shapes**:
///
/// - **argv form** (`program` + `args`) — one named command. `invoke` first
///   asks the leash whether `program` may execute ([`ToolContext::check_exec`]),
///   denying out-of-scope programs before any shell is built.
/// - **free-form `cmd`** — an `sh -c`-style command string (pipelines,
///   redirections, `&&`, globbing). This is the drop-in shape for an unconfined
///   `shell_run`.
///
/// In **both** shapes the brush shell is built with a [`CaveatInterceptor`]
/// carrying this invocation's effective caveats. The interceptor rides the brush
/// fork's `CommandInterceptor` hook: `before_exec` denies any program not in the
/// `exec` scope (including path-separator-spelled commands like `/bin/rm`, which
/// otherwise bypass `PATH` and the builtin table — DESIGN §6), and `before_open`
/// denies redirections/`source` opens outside `fs_read`/`fs_write`. So
/// confinement is real in-process, cross-OS — a true superset of `sh -c`.
#[derive(Debug, Default, Clone, Copy)]
pub struct ShellTool;

impl ShellTool {
    /// Construct the tool.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

/// Which input shape an invocation used — it changes how the shell's `PATH` is
/// seeded (see [`FREEFORM_PATH`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// `program` + `args`: a single named command, gated by an `exec` pre-check;
    /// `PATH` is cleared so carried builtins prove they run with no host binary.
    Argv,
    /// `cmd`: a free-form `sh -c`-style string; `PATH` is seeded so externals
    /// resolve to the [`CaveatInterceptor`]'s `before_exec` hook.
    FreeForm,
}

/// Parsed, validated arguments for one shell invocation.
struct ShellArgs {
    /// The fully-formed command line handed to `run_dash_c_command`.
    command: String,
    /// The argv0 program name (argv mode only), used for the `exec` pre-check.
    program: Option<String>,
    mode: Mode,
    cwd: Option<String>,
    timeout: Duration,
}

impl ShellArgs {
    fn parse(args: &serde_json::Value) -> ToolResult<Self> {
        let has_program = args.get("program").is_some();
        let has_cmd = args.get("cmd").is_some();

        let cwd = args
            .get("cwd")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string);

        let timeout_secs = args
            .get("timeout_secs")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(DEFAULT_TIMEOUT_SECS)
            .min(MAX_TIMEOUT_SECS);
        let timeout = Duration::from_secs(timeout_secs);

        match (has_program, has_cmd) {
            (true, true) => Err(ToolError::denied(
                "provide either `program` (argv form) or `cmd` (free-form), not both",
            )),
            (false, false) => Err(ToolError::denied(
                "missing required field: one of `program` (argv form) or `cmd` (free-form)",
            )),
            (true, false) => Self::parse_argv(args, cwd, timeout),
            (false, true) => Self::parse_freeform(args, cwd, timeout),
        }
    }

    /// Argv form: `program` (string) + optional `args` (array of strings).
    fn parse_argv(
        args: &serde_json::Value,
        cwd: Option<String>,
        timeout: Duration,
    ) -> ToolResult<Self> {
        let program = args
            .get("program")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| ToolError::denied("`program` must be a string"))?
            .to_string();

        let arg_list = match args.get("args") {
            None | Some(serde_json::Value::Null) => Vec::new(),
            Some(serde_json::Value::Array(a)) => a
                .iter()
                .map(|v| {
                    v.as_str()
                        .map(str::to_string)
                        .ok_or_else(|| ToolError::denied("`args` must be an array of strings"))
                })
                .collect::<ToolResult<Vec<_>>>()?,
            Some(_) => return Err(ToolError::denied("`args` must be an array of strings")),
        };

        // Build a quoted command line so brush parses one simple command; each
        // token is single-quoted (embedded quotes escaped) so args pass
        // literally — no word-splitting, no expansion.
        let mut command = sh_quote(&program);
        for a in &arg_list {
            command.push(' ');
            command.push_str(&sh_quote(a));
        }

        Ok(Self {
            command,
            program: Some(program),
            mode: Mode::Argv,
            cwd,
            timeout,
        })
    }

    /// Free-form: `cmd` (string), run `sh -c`-style. No pre-quoting — the string
    /// is the script. Confinement comes entirely from the interceptor hook.
    fn parse_freeform(
        args: &serde_json::Value,
        cwd: Option<String>,
        timeout: Duration,
    ) -> ToolResult<Self> {
        let command = args
            .get("cmd")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| ToolError::denied("`cmd` must be a string"))?
            .to_string();

        Ok(Self {
            command,
            program: None,
            mode: Mode::FreeForm,
            cwd,
            timeout,
        })
    }
}

#[async_trait]
impl Tool for ShellTool {
    fn name(&self) -> &str {
        "shell"
    }

    fn schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "program": {
                    "type": "string",
                    "description": "Argv form: the command to run (argv[0]). \
                        Gated by the `exec` caveat. Mutually exclusive with `cmd`."
                },
                "args": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "Argv form: arguments passed to `program` (argv[1..])."
                },
                "cmd": {
                    "type": "string",
                    "description": "Free-form: an sh -c-style command string \
                        (pipelines, redirections, &&, globbing). Confined in-process \
                        by the capability interceptor hook (exec + fs). Mutually \
                        exclusive with `program`."
                },
                "cwd": {
                    "type": "string",
                    "description": "Working directory for the command."
                },
                "timeout_secs": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": MAX_TIMEOUT_SECS,
                    "description": "Wall-clock timeout bound (not a coordination primitive)."
                }
            },
            "additionalProperties": false
        })
    }

    async fn invoke(
        &self,
        args: serde_json::Value,
        cx: &ToolContext,
    ) -> ToolResult<serde_json::Value> {
        let parsed = ShellArgs::parse(&args)?;
        // The kind we will actually run under (honest reporting). L3 is enforced
        // on the confined thread below; this just predicts it for the envelope.
        let sandbox_kind = intended_sandbox_kind(cx.caveats());

        // (1) The leash, argv-mode fast path. If a *named* program is not in the
        // `exec` scope, deny before building anything. Free-form (`cmd`) has no
        // single named program; its exec gating is the interceptor's
        // `before_exec` hook, which fires at the spawn funnel (below).
        if let Some(program) = &parsed.program {
            cx.check_exec(program)?;
        }

        // (2) The OS-level sandbox (L3) is NOT applied here: Landlock's
        // restrict_self is per-thread and irreversible, and this is the caller's
        // (reused) async thread. It is applied inside `run_confined`, on the
        // dedicated throwaway thread that actually runs brush — see there.

        // (3) Run via brush with carried builtins, captured output, the
        // capability interceptor (the cross-OS in-process leash), and a timeout.
        // Blocking shell work runs on a blocking thread; the interceptor carries
        // THIS invocation's effective caveats.
        //
        // The denial sink is minted FRESH here, once per invocation, and shared
        // (Arc) into the interceptor — and through it into every brush-made
        // clone. We keep our own clone of the Arc so we can read the recorded
        // denials after the brush task finishes. Because each invocation gets a
        // brand-new sink, two concurrent invocations can never observe each
        // other's denials.
        let timeout = parsed.timeout;
        let sink: DenialSink = Arc::new(Mutex::new(Vec::new()));
        let interceptor = CaveatInterceptor::new(cx.clone(), Arc::clone(&sink));
        let effective = cx.caveats().clone();
        let run = tokio::task::spawn_blocking(move || run_confined(parsed, interceptor, effective));
        let joined = tokio::time::timeout(timeout, run).await;

        match joined {
            // Completed in time.
            Ok(join_result) => {
                let captured = join_result
                    .map_err(|e| ToolError::Other(anyhow::anyhow!("shell task panicked: {e}")))??;
                // Read the structured denial signal the interceptor recorded.
                // `denied: true` is set iff at least one Deny actually fired —
                // NOT merely because the command exited non-zero on its own.
                let denials = take_denials(&sink);
                Ok(ToolEnvelope::new(sandbox_kind)
                    .with_exit_code(captured.exit_code)
                    .with_stdout(captured.stdout)
                    .with_stderr(captured.stderr)
                    .with_timed_out(false)
                    .with_denials(denials)
                    .into_json())
            }
            // Timed out: the blocking task is detached; report a timeout
            // envelope so the caller sees the bound was hit. Surface any denials
            // recorded before the bound was hit, too.
            Err(_elapsed) => {
                let denials = take_denials(&sink);
                Ok(ToolEnvelope::new(sandbox_kind)
                    .with_stderr(format!("command timed out after {}s", timeout.as_secs()))
                    .with_timed_out(true)
                    .with_denials(denials)
                    .into_json())
            }
        }
    }
}

/// Drain the per-invocation denial sink into an owned `Vec<Denial>`.
///
/// A poisoned lock (a brush callback panicking mid-record) is recovered rather
/// than propagated: a security signal is too important to drop because one
/// record raced a panic.
fn take_denials(sink: &DenialSink) -> Vec<Denial> {
    let mut guard = sink
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    std::mem::take(&mut *guard)
}

/// The sandbox kind this invocation will actually run under, for honest
/// reporting in the result envelope.
///
/// Landlock only when the `linux-landlock` feature + kernel support it **and**
/// the caveats actually restrict `fs_write` (the only axis L3 governs in this
/// increment). Otherwise [`SandboxKind::None`] — the leash is then the in-process
/// L2 interceptor only, advertised honestly. `fs_write = All` means nothing to
/// confine at L3, so it is reported (and applied) as None.
fn intended_sandbox_kind(effective: &Caveats) -> SandboxKind {
    #[cfg(all(target_os = "linux", feature = "linux-landlock"))]
    {
        if matches!(effective.fs_write, agent_bridle_core::Scope::Only(_))
            && agent_bridle_core::landlock_is_supported()
        {
            return SandboxKind::Landlock;
        }
    }
    let _ = effective;
    SandboxKind::None
}

/// Enforce the OS-level sandbox (L3) on the **current** thread.
///
/// MUST be called on the dedicated, throwaway shell thread (see [`run_confined`])
/// — never on a reused thread — because Landlock's `restrict_self` is per-thread
/// and irreversible. A no-op unless [`intended_sandbox_kind`] is Landlock.
/// Fail-closed: a requested-but-unenforceable ruleset returns `Err`.
fn apply_sandbox(effective: &Caveats) -> ToolResult<()> {
    #[cfg(all(target_os = "linux", feature = "linux-landlock"))]
    {
        use agent_bridle_core::Sandbox;
        if intended_sandbox_kind(effective) == SandboxKind::Landlock {
            agent_bridle_core::LandlockSandbox::new().apply(effective)?;
        }
    }
    let _ = effective;
    Ok(())
}

/// Run the confined shell on a **dedicated, throwaway OS thread**.
///
/// L3's Landlock `restrict_self` is per-thread and irreversible, and tokio
/// reuses its blocking-pool threads — so restricting a pool thread would poison
/// every later `spawn_blocking` task that lands on it. A fresh thread that dies
/// when the invocation ends cannot leak its restriction. brush runs on a
/// current-thread runtime *on this same thread* (see [`run_in_brush`]), so the
/// `fork`/`exec` of any child it spawns happens here too and the child inherits
/// the Landlock domain.
fn run_confined(
    parsed: ShellArgs,
    interceptor: CaveatInterceptor,
    effective: Caveats,
) -> ToolResult<Captured> {
    std::thread::Builder::new()
        .name("agent-bridle-confined-shell".into())
        .spawn(move || run_in_brush(parsed, interceptor, &effective))
        .map_err(|e| ToolError::Exec(io_ctx("spawn confined shell thread", e)))?
        .join()
        .map_err(|_| ToolError::Other(anyhow::anyhow!("confined shell thread panicked")))?
}

/// What a finished brush run produced.
struct Captured {
    exit_code: i32,
    stdout: String,
    stderr: String,
}

/// Drive a brush shell to completion for one command, capturing stdout/stderr
/// via real OS pipes (DESIGN §6: `Arc<Mutex<Vec<u8>>>` will not compile against
/// brush's `Stream`; pipes are mandatory). The shell is built with the supplied
/// [`CaveatInterceptor`] so exec/open are confined in-process.
///
/// This is synchronous: it runs on the dedicated confined thread (see
/// [`run_confined`]) and spins a tiny current-thread tokio runtime for brush's
/// async shell API.
fn run_in_brush(
    parsed: ShellArgs,
    interceptor: CaveatInterceptor,
    effective: &Caveats,
) -> ToolResult<Captured> {
    // Real OS pipes for fd 1 and 2. Created BEFORE the sandbox so their fds are
    // already open: Landlock governs the path-based `open(2)`, not writes to an
    // already-open fd, so capture keeps working under any `fs_write` scope.
    let (out_reader, out_writer) =
        std::io::pipe().map_err(|e| ToolError::Exec(io_ctx("create stdout pipe", e)))?;
    let (err_reader, err_writer) =
        std::io::pipe().map_err(|e| ToolError::Exec(io_ctx("create stderr pipe", e)))?;

    // Drain the read ends on background threads so a chatty command cannot
    // deadlock by filling the pipe buffer before the shell exits.
    let out_handle = std::thread::spawn(move || drain(out_reader));
    let err_handle = std::thread::spawn(move || drain(err_reader));

    // L3: enforce the OS-level sandbox on THIS (fresh, throwaway) thread, before
    // any command runs. brush's current-thread runtime and every child it forks
    // run on this thread and inherit the Landlock domain. Reads/exec are
    // ungoverned in this increment; `fs_write` is confined to the granted scope.
    // Fail-closed: a requested-but-unenforceable ruleset aborts the invocation.
    apply_sandbox(effective)?;

    // brush's shell API is async; run it on a single-thread runtime confined to
    // this blocking worker thread.
    //
    // IO **must** be enabled (not just time): command substitution `$(...)`
    // sets up real OS pipes via tokio's IO driver. With IO disabled, `$(/bin/rm
    // ...)` panics deep in tokio ("IO is disabled"); that panic surfaces from
    // `invoke` as an opaque `Err` instead of the clean, structured `denied:
    // true` envelope the leash is supposed to produce. With IO enabled, the
    // substitution runs through the normal command path, the inner program hits
    // the `before_exec` funnel, and an out-of-scope command yields a recorded
    // denial — fail-closed *and* legible. `enable_all` turns on both the IO and
    // time drivers.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| ToolError::Exec(io_ctx("build shell runtime", e)))?;

    let mode = parsed.mode;
    let command = parsed.command;
    let working_dir = parsed.cwd.map(std::path::PathBuf::from);

    let exit_code = rt.block_on(async move {
        let mut fds: HashMap<ShellFd, OpenFile> = HashMap::new();
        fds.insert(STDOUT_FD, OpenFile::from(out_writer));
        fds.insert(STDERR_FD, OpenFile::from(err_writer));

        let mut shell: Shell<LeashedExtensions> =
            Shell::builder_with_extensions::<LeashedExtensions>()
                // The capability hook — THE in-process leash for free-form scripts.
                .command_interceptor(interceptor)
                // Carried builtins for our custom extensions type — but CURATED:
                // every builtin that can spawn/exec/open OUTSIDE the two
                // interceptor funnels (`before_exec` / `before_open`) is removed,
                // so the confined shell has no uncovered path to authority. See
                // [`confined_builtins`].
                .builtins(confined_builtins())
                // Do not inherit the host environment — confinement, and so a
                // carried builtin must come from brush, not the host PATH.
                .do_not_inherit_env(true)
                .no_editing(true)
                .interactive(false)
                .fds(fds)
                // `maybe_working_dir` accepts the Option without changing the
                // builder typestate path conditionally.
                .maybe_working_dir(working_dir)
                .build()
                .await
                .map_err(|e| ToolError::Exec(io_ctx("build shell", into_io(&e))))?;

        // PATH policy depends on the mode:
        //
        // - Argv: empty PATH proves carried builtins run with no host binary on
        //   disk (the named program was already exec-gated before we got here).
        // - FreeForm: a standard PATH so external commands *resolve* and reach
        //   the interceptor's `before_exec` hook (the real gate). The host env
        //   is still not inherited (`do_not_inherit_env(true)`); only PATH is
        //   seeded. `/bin/rm`-style path-separator commands are denied either
        //   way, since they go straight to the spawn funnel.
        let path_value = match mode {
            Mode::Argv => "",
            Mode::FreeForm => FREEFORM_PATH,
        };
        shell
            .env_mut()
            .set_global(
                "PATH",
                brush_core::variables::ShellVariable::new(path_value),
            )
            .map_err(|e| ToolError::Exec(io_ctx("seed PATH", into_io(&e))))?;

        let result = shell
            .run_dash_c_command(command)
            .await
            .map_err(|e| ToolError::Exec(io_ctx("run command", into_io(&e))))?;

        // Drop the shell so it releases its clones of the pipe writers; only
        // then will the reader threads see EOF.
        drop(shell);

        Ok::<i32, ToolError>(i32::from(u8::from(result.exit_code)))
    })?;

    let stdout = out_handle
        .join()
        .map_err(|_| ToolError::Other(anyhow::anyhow!("stdout reader thread panicked")))??;
    let stderr = err_handle
        .join()
        .map_err(|_| ToolError::Other(anyhow::anyhow!("stderr reader thread panicked")))??;

    Ok(Captured {
        exit_code,
        stdout,
        stderr,
    })
}

/// Builtins removed from the confined shell because they reach `spawn`/`exec`/
/// `open` *without* going through the interceptor funnels (`before_exec` at the
/// single external-spawn site, `before_open` at `Shell::open_file`).
///
/// The audit of the brush fork (rev 4e65a06) found exactly one such builtin:
///
/// - **`exec`** — In its non-subshell branch, `exec`
///   ([`brush-builtins/src/exec.rs`]) calls `compose_std_command(...)` and then
///   `cmd.exec()` (replace-process) *directly*, never consulting
///   `before_exec`. PROVEN bypass: under `exec: only{echo}`,
///   `exec /usr/bin/touch MARKER` ran `touch` (the marker file appeared) and
///   actually replaced the host process image — the leash never fired. A
///   confined shell does not need `exec` (there is nothing to replace into),
///   so removing it costs nothing and closes a live authority leak.
///
/// Every *other* path that can run a program or open a file was verified to
/// funnel through a hook and is therefore intentionally KEPT:
///
/// - `command`, `eval`, `.`/`source`, `fc`, `coproc`, background `&`,
///   process substitution `<(...)`/`>(...)`, and ordinary external commands all
///   route through `SimpleCommand::execute` → `execute_external_command`, whose
///   first act is `before_exec` (the funnel).
/// - `mapfile`/`readarray` and `read` only consume *already-open* fds
///   (`try_fd`); the redirection that opened the fd went through `before_open`.
/// - Redirections and `source` open files exclusively via `Shell::open_file`,
///   which calls `before_open`.
///
/// `exec` cannot be smuggled back in: `enable -f` (load a builtin from a shared
/// object) is `unimp` in the fork, and `enable`/`builtin exec` only act on
/// registrations already present in the map — once removed, there is nothing to
/// re-enable.
const REMOVED_BUILTINS: &[&str] = &["exec"];

/// The curated builtin set for the confined shell: the bash-mode default set
/// with every [`REMOVED_BUILTINS`] entry stripped out.
///
/// `default_builtins` hands back a plain owned `HashMap`, so omission is a
/// `remove` on that map — robust-by-construction: the shell builder seeds an
/// empty map and only takes what we give it, and nothing in brush
/// auto-registers a builtin, so a removed builtin is simply *gone* (a confined
/// shell that runs `exec` gets "command not found", never a spawn).
fn confined_builtins() -> HashMap<String, brush_core::builtins::Registration<LeashedExtensions>> {
    let mut builtins = default_builtins::<LeashedExtensions>(BuiltinSet::BashMode);
    for name in REMOVED_BUILTINS {
        builtins.remove(*name);
    }
    builtins
}

/// Read a pipe to EOF, returning its bytes as a lossy UTF-8 string.
fn drain(mut reader: std::io::PipeReader) -> ToolResult<String> {
    let mut buf = Vec::new();
    reader
        .read_to_end(&mut buf)
        .map_err(|e| ToolError::Exec(io_ctx("drain pipe", e)))?;
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// Single-quote a shell token, escaping embedded single quotes the POSIX way
/// (`'` → `'\''`). Guarantees the token is passed literally.
fn sh_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for ch in s.chars() {
        if ch == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

/// Wrap a context string around an io::Error.
fn io_ctx(ctx: &str, e: std::io::Error) -> std::io::Error {
    std::io::Error::new(e.kind(), format!("{ctx}: {e}"))
}

/// Render a brush error as an io::Error (brush's Error is not io::Error).
fn into_io(e: &brush_core::Error) -> std::io::Error {
    std::io::Error::other(e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_bridle_core::{CountBound, Gate, Scope};

    /// Mint a context for the shell tool through the gate, the only legitimate
    /// way.
    fn authorize(granted: &Caveats) -> ToolResult<ToolContext> {
        let tool = ShellTool::new();
        Gate::new(0).authorize(&tool, granted)
    }

    fn echo_grant() -> Caveats {
        Caveats {
            exec: Scope::only(["echo".to_string()]),
            max_calls: CountBound::AtMost(8),
            ..Caveats::top()
        }
    }

    #[tokio::test]
    async fn echo_in_scope_runs_and_captures_stdout() {
        let cx = authorize(&echo_grant()).unwrap();
        let out = ShellTool::new()
            .invoke(
                serde_json::json!({ "program": "echo", "args": ["hi"] }),
                &cx,
            )
            .await
            .expect("invoke");
        assert_eq!(out["exit_code"], 0);
        assert!(
            out["stdout"].as_str().unwrap().contains("hi"),
            "stdout was {:?}",
            out["stdout"]
        );
        // The recorded sandbox kind travels with the result.
        assert_eq!(out["sandbox_kind"], "none");
        assert_eq!(out["timed_out"], false);
    }

    #[tokio::test]
    async fn carried_builtin_runs_with_empty_path() {
        // No host PATH is inherited and PATH is cleared inside the shell; echo
        // still works because it is a *carried* brush builtin.
        let cx = authorize(&echo_grant()).unwrap();
        let out = ShellTool::new()
            .invoke(
                serde_json::json!({ "program": "echo", "args": ["carried"] }),
                &cx,
            )
            .await
            .expect("invoke");
        assert!(out["stdout"].as_str().unwrap().contains("carried"));
    }

    #[tokio::test]
    async fn out_of_scope_program_is_denied() {
        // `rm` is not in the granted exec scope → denied before running.
        let cx = authorize(&echo_grant()).unwrap();
        let err = ShellTool::new()
            .invoke(
                serde_json::json!({ "program": "rm", "args": ["-rf", "/"] }),
                &cx,
            )
            .await
            .unwrap_err();
        assert!(matches!(err, ToolError::Denied { .. }), "got {err:?}");
    }

    #[tokio::test]
    async fn third_call_denied_by_budget() {
        // One shared gate, AtMost(2): first two authorize, the third is Budget.
        let tool = ShellTool::new();
        let granted = echo_grant();
        let gate = Gate::with_budget(0, CountBound::AtMost(2));

        let cx1 = gate.authorize(&tool, &granted).unwrap();
        let _ = tool
            .invoke(
                serde_json::json!({ "program": "echo", "args": ["1"] }),
                &cx1,
            )
            .await
            .unwrap();

        let cx2 = gate.authorize(&tool, &granted).unwrap();
        let _ = tool
            .invoke(
                serde_json::json!({ "program": "echo", "args": ["2"] }),
                &cx2,
            )
            .await
            .unwrap();

        let denied = gate.authorize(&tool, &granted).unwrap_err();
        assert!(matches!(denied, ToolError::Budget), "got {denied:?}");
    }

    #[test]
    fn schema_has_both_argv_and_freeform() {
        let s = ShellTool::new().schema();
        // Argv form.
        assert_eq!(s["properties"]["program"]["type"], "string");
        // Free-form `cmd` superset (now landed behind the interceptor hook).
        assert_eq!(s["properties"]["cmd"]["type"], "string");
        // Neither is `required` — exactly one must be supplied (validated at
        // parse time), and they are mutually exclusive.
        assert!(s.get("required").is_none());
    }

    // ── Free-form (`cmd`) confinement via the interceptor hook ──────────────

    #[tokio::test]
    async fn freeform_echo_in_scope_runs() {
        // cmd `echo hi` → allowed (echo is a carried builtin), stdout has `hi`.
        let cx = authorize(&echo_grant()).unwrap();
        let out = ShellTool::new()
            .invoke(serde_json::json!({ "cmd": "echo hi" }), &cx)
            .await
            .expect("invoke");
        assert_eq!(out["exit_code"], 0);
        assert!(
            out["stdout"].as_str().unwrap().contains("hi"),
            "stdout was {:?}",
            out["stdout"]
        );
    }

    #[tokio::test]
    async fn freeform_rm_denied_via_before_exec() {
        // (a) cmd `rm -rf /tmp/x` → DENIED via before_exec (rm ∉ exec). A
        // standard PATH is seeded so `rm` resolves and the hook (not "command
        // not found") is what stops it. We assert the STRUCTURED signal: the
        // result envelope carries `denied: true` and a denials entry naming
        // kind=exec / target=rm — no stderr string-matching needed.
        let cx = authorize(&echo_grant()).unwrap();
        let out = ShellTool::new()
            .invoke(serde_json::json!({ "cmd": "rm -rf /tmp/x" }), &cx)
            .await
            .expect("invoke");
        assert_ne!(out["exit_code"], 0, "rm must not succeed: {out:?}");
        // The headline assertion: structured denial, not stderr-grepping.
        assert_eq!(
            out["denied"], true,
            "result must be flagged denied: {out:?}"
        );
        let denials = out["denials"].as_array().expect("denials array");
        // The target is exactly what brush handed the hook: for a PATH-resolved
        // command that is the resolved absolute path (e.g. /usr/bin/rm), so we
        // assert kind=exec and that the program is `rm` (the basename).
        assert!(
            denials.iter().any(|d| d["kind"] == "exec"
                && d["target"]
                    .as_str()
                    .is_some_and(|t| t == "rm" || t.ends_with("/rm"))),
            "expected an exec denial naming rm, got {denials:?}"
        );
        // The reason is carried for surfacing to the agent.
        assert!(denials[0]["reason"]
            .as_str()
            .unwrap()
            .contains("not within the granted"));
    }

    #[tokio::test]
    async fn freeform_bin_rm_denied_closes_path_separator_bypass() {
        // (b) cmd `/bin/rm -rf /tmp/x` → DENIED. THE load-bearing case: a
        // path-separator command bypasses PATH and the builtin table, so a
        // cleared PATH alone would NOT stop it — only the before_exec hook (at
        // the single spawn funnel) does. Proves the bypass is closed AND that
        // the path-separator denial is flagged structurally.
        let cx = authorize(&echo_grant()).unwrap();
        let out = ShellTool::new()
            .invoke(serde_json::json!({ "cmd": "/bin/rm -rf /tmp/x" }), &cx)
            .await
            .expect("invoke");
        assert_ne!(out["exit_code"], 0, "/bin/rm must not succeed: {out:?}");
        assert_eq!(
            out["denied"], true,
            "/bin/rm must be flagged denied: {out:?}"
        );
        let denials = out["denials"].as_array().expect("denials array");
        assert!(
            denials
                .iter()
                .any(|d| d["kind"] == "exec" && d["target"] == "/bin/rm"),
            "expected an exec//bin/rm denial, got {denials:?}"
        );
    }

    #[tokio::test]
    async fn freeform_write_outside_fs_write_denied_via_before_open() {
        // cmd `echo x > <disallowed path>` → DENIED via before_open. fs_write is
        // restricted to a temp scratch dir; a redirect to /etc is refused.
        let scratch = std::env::temp_dir().join(format!(
            "ab-shell-fswrite-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&scratch).expect("mkdir scratch");

        let cx = authorize(&Caveats {
            exec: Scope::only(["echo".to_string()]),
            fs_write: Scope::only([scratch.to_string_lossy().into_owned()]),
            max_calls: CountBound::AtMost(8),
            ..Caveats::top()
        })
        .unwrap();

        let out = ShellTool::new()
            .invoke(
                serde_json::json!({ "cmd": "echo x > /etc/ab-should-not-exist" }),
                &cx,
            )
            .await
            .expect("invoke");
        assert_ne!(
            out["exit_code"], 0,
            "redirect outside scope must fail: {out:?}"
        );
        // (c) the open-denial is flagged structurally with kind=open and the
        // refused path as target.
        assert_eq!(
            out["denied"], true,
            "redirect must be flagged denied: {out:?}"
        );
        let denials = out["denials"].as_array().expect("denials array");
        assert!(
            denials.iter().any(|d| d["kind"] == "open"
                && d["target"]
                    .as_str()
                    .is_some_and(|t| t.contains("ab-should-not-exist"))),
            "expected an open denial for the redirect target, got {denials:?}"
        );
        assert!(
            !std::path::Path::new("/etc/ab-should-not-exist").exists(),
            "the denied file must not have been created"
        );

        let _ = std::fs::remove_dir_all(&scratch);
    }

    #[tokio::test]
    async fn freeform_allowed_redirection_within_scope_succeeds() {
        // An allowed redirection within fs_write scope → succeeds, and the file
        // is created with the expected content.
        let scratch = std::env::temp_dir().join(format!(
            "ab-shell-okwrite-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&scratch).expect("mkdir scratch");
        let target = scratch.join("out.txt");

        let cx = authorize(&Caveats {
            exec: Scope::only(["echo".to_string()]),
            fs_write: Scope::only([scratch.to_string_lossy().into_owned()]),
            max_calls: CountBound::AtMost(8),
            ..Caveats::top()
        })
        .unwrap();

        let cmd = format!("echo inscope > {}", target.display());
        let out = ShellTool::new()
            .invoke(serde_json::json!({ "cmd": cmd }), &cx)
            .await
            .expect("invoke");
        assert_eq!(
            out["exit_code"], 0,
            "in-scope redirect must succeed: {out:?}"
        );
        // An in-scope run records no denial: the structured field is omitted.
        assert!(out.get("denied").is_none(), "must not be flagged: {out:?}");
        assert!(out.get("denials").is_none(), "no denials expected: {out:?}");
        let written = std::fs::read_to_string(&target).expect("read back");
        assert!(written.contains("inscope"), "file content was {written:?}");

        let _ = std::fs::remove_dir_all(&scratch);
    }

    #[tokio::test]
    async fn freeform_permitted_command_exiting_126_is_not_flagged_denied() {
        // (d) NO FALSE POSITIVES. A permitted command that itself exits 126 must
        // NOT be flagged as a leash denial — `denied` is set ONLY when the
        // interceptor actually recorded a Deny, never merely from a 126 exit.
        // `exit 126` is a carried shell builtin: it sets the code with no
        // exec/open going through the interceptor, so nothing is recorded.
        let cx = authorize(&echo_grant()).unwrap();
        let out = ShellTool::new()
            .invoke(serde_json::json!({ "cmd": "exit 126" }), &cx)
            .await
            .expect("invoke");
        assert_eq!(out["exit_code"], 126, "expected a raw 126 exit: {out:?}");
        // The whole point: 126 alone does NOT mean denied.
        assert!(
            out.get("denied").is_none(),
            "a permitted 126 exit must NOT be flagged denied: {out:?}"
        );
        assert!(
            out.get("denials").is_none(),
            "no denials must be recorded for a permitted 126 exit: {out:?}"
        );
    }

    #[tokio::test]
    async fn concurrent_invocations_do_not_cross_contaminate_denials() {
        // (e) The sink is PER-INVOCATION. Two invocations run concurrently with
        // different grants; each must see only its OWN denials, never the
        // other's. Both use path-separator-spelled programs so the before_exec
        // hook fires at the spawn funnel regardless of whether the binary is
        // installed (no reliance on a host having `rm`/`curl` on PATH).
        // Invocation A (echo-only) runs `/bin/rm` → its own exec//bin/rm denial.
        // Invocation B (rm-allowed) runs `/usr/bin/curl` → its own
        // exec//usr/bin/curl denial. If the sink leaked across invocations, A
        // would see `curl` or B would see `rm`.
        let grant_a = Caveats {
            exec: Scope::only(["echo".to_string()]),
            max_calls: CountBound::AtMost(8),
            ..Caveats::top()
        };
        let grant_b = Caveats {
            exec: Scope::only(["rm".to_string()]),
            max_calls: CountBound::AtMost(8),
            ..Caveats::top()
        };
        let cx_a = authorize(&grant_a).unwrap();
        let cx_b = authorize(&grant_b).unwrap();

        // Drive both at once on the same runtime so their brush runs overlap.
        let tool = ShellTool::new();
        let fut_a = tool.invoke(serde_json::json!({ "cmd": "/bin/rm /tmp/x" }), &cx_a);
        let fut_b = tool.invoke(
            serde_json::json!({ "cmd": "/usr/bin/curl http://x" }),
            &cx_b,
        );
        let (out_a, out_b) = tokio::join!(fut_a, fut_b);
        let out_a = out_a.expect("invoke A");
        let out_b = out_b.expect("invoke B");

        // Targets are whatever brush handed the hook (PATH-resolved absolute
        // paths); test by basename so the assertion is host-independent.
        let names = |out: &serde_json::Value| -> Vec<String> {
            out["denials"]
                .as_array()
                .unwrap()
                .iter()
                .map(|d| {
                    let t = d["target"].as_str().unwrap();
                    t.rsplit('/').next().unwrap_or(t).to_string()
                })
                .collect()
        };

        // A denied `rm`, and ONLY `rm` — never B's `curl`.
        assert_eq!(out_a["denied"], true, "A must be denied: {out_a:?}");
        let a_names = names(&out_a);
        assert!(
            a_names.iter().any(|n| n == "rm"),
            "A should see its own rm: {a_names:?}"
        );
        assert!(
            !a_names.iter().any(|n| n == "curl"),
            "A must NOT see B's curl denial (cross-contamination): {a_names:?}"
        );

        // B denied `curl`, and ONLY `curl` — never A's `rm`.
        assert_eq!(out_b["denied"], true, "B must be denied: {out_b:?}");
        let b_names = names(&out_b);
        assert!(
            b_names.iter().any(|n| n == "curl"),
            "B should see its own curl: {b_names:?}"
        );
        assert!(
            !b_names.iter().any(|n| n == "rm"),
            "B must NOT see A's rm denial (cross-contamination): {b_names:?}"
        );
    }

    /// A program that is a REAL external on the CI runner (NOT one of brush's
    /// carried builtins, which bypass `before_exec` and so would not exercise
    /// the leash). `env` is on every Linux runner and is not in the brush
    /// builtin set, so it genuinely funnels through the interceptor.
    const EXTERNAL_PROG: &str = "env";

    #[tokio::test]
    async fn freeform_external_granted_by_bare_name_actually_runs() {
        // THE missing end-to-end test. This whole bug existed because nothing
        // ever ran an ALLOWED EXTERNAL by bare name through the interceptor.
        //
        // Grant `exec = only{"env"}` (a BARE NAME) and run the EXTERNAL `env`
        // via the confined free-form shell. The interceptor hands `before_exec`
        // the PATH-resolved absolute path (`/usr/bin/env`); before the fix the
        // bare-name grant never matched that path and the command was DENIED.
        // With basename matching it is ALLOWED: it runs, exits 0, and records
        // NO denial. `env` is a real external (NOT a carried brush builtin), so
        // this proves a bare-name-granted external executes through the hook.
        if which_external(EXTERNAL_PROG).is_none() {
            return; // external not present on this host; nothing to prove.
        }
        let cx = authorize(&Caveats {
            exec: Scope::only([EXTERNAL_PROG.to_string()]),
            max_calls: CountBound::AtMost(8),
            ..Caveats::top()
        })
        .unwrap();
        let out = ShellTool::new()
            .invoke(serde_json::json!({ "cmd": EXTERNAL_PROG }), &cx)
            .await
            .expect("invoke");
        assert_eq!(
            out["exit_code"], 0,
            "a bare-name-granted external must run and exit 0: {out:?}"
        );
        assert!(
            out.get("denied").is_none(),
            "a granted external must NOT be flagged denied: {out:?}"
        );
        assert!(
            out.get("denials").is_none(),
            "no denials expected for a granted external: {out:?}"
        );
    }

    #[tokio::test]
    async fn freeform_external_not_granted_by_bare_name_is_denied() {
        // The negative half: grant `exec = only{"echo"}` (a carried builtin
        // only) and run the EXTERNAL `env`. Its resolved basename `env` is not
        // in the grant, so the interceptor denies it via before_exec — proving
        // basename matching did not over-broaden into allowing ungranted
        // externals.
        if which_external(EXTERNAL_PROG).is_none() {
            return;
        }
        let cx = authorize(&echo_grant()).unwrap();
        let out = ShellTool::new()
            .invoke(serde_json::json!({ "cmd": EXTERNAL_PROG }), &cx)
            .await
            .expect("invoke");
        assert_ne!(
            out["exit_code"], 0,
            "an ungranted external must not succeed: {out:?}"
        );
        assert_eq!(
            out["denied"], true,
            "an ungranted external must be flagged denied: {out:?}"
        );
        let denials = out["denials"].as_array().expect("denials array");
        assert!(
            denials.iter().any(|d| d["kind"] == "exec"
                && d["target"].as_str().is_some_and(
                    |t| t == EXTERNAL_PROG || t.ends_with(&format!("/{EXTERNAL_PROG}"))
                )),
            "expected an exec denial naming {EXTERNAL_PROG}, got {denials:?}"
        );
    }

    /// Locate an external on the same `PATH` the free-form shell seeds
    /// ([`FREEFORM_PATH`]), so the test's presence check matches what brush
    /// will resolve. Returns `None` if not found (test self-skips).
    fn which_external(name: &str) -> Option<std::path::PathBuf> {
        FREEFORM_PATH.split(':').find_map(|dir| {
            let p = std::path::Path::new(dir).join(name);
            p.is_file().then_some(p)
        })
    }

    #[tokio::test]
    async fn freeform_and_argv_are_mutually_exclusive() {
        let cx = authorize(&echo_grant()).unwrap();
        let err = ShellTool::new()
            .invoke(
                serde_json::json!({ "program": "echo", "cmd": "echo hi" }),
                &cx,
            )
            .await
            .unwrap_err();
        assert!(matches!(err, ToolError::Denied { .. }), "got {err:?}");
    }

    #[tokio::test]
    async fn neither_program_nor_cmd_is_rejected() {
        let cx = authorize(&echo_grant()).unwrap();
        let err = ShellTool::new()
            .invoke(serde_json::json!({ "args": ["x"] }), &cx)
            .await
            .unwrap_err();
        assert!(matches!(err, ToolError::Denied { .. }), "got {err:?}");
    }

    // ── Security regression: bypass-capable builtins are removed ────────────
    //
    // These prove the audit's two holes are closed, fail-closed.

    /// Build a unique scratch marker path under the temp dir (counter, not a
    /// clock), pre-removed so a stale file can't mask a failure.
    fn fresh_marker(tag: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!(
            "ab-sec-{tag}-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let _ = std::fs::remove_file(&p);
        p
    }

    #[test]
    fn exec_builtin_is_removed_from_the_confined_set() {
        // The audit finding, asserted directly on the curated map: the only
        // bypass-capable builtin (`exec`) is NOT registered in the confined
        // shell, while a known-safe one (`echo`) still is.
        let builtins = confined_builtins();
        assert!(
            !builtins.contains_key("exec"),
            "`exec` must be absent from the confined builtin set"
        );
        for name in REMOVED_BUILTINS {
            assert!(
                !builtins.contains_key(*name),
                "removed builtin `{name}` must be absent from the confined set"
            );
        }
        // The carried-safe builtins survive the curation.
        assert!(builtins.contains_key("echo"), "echo must still be carried");
        assert!(
            builtins.contains_key("command"),
            "command (funnel-routed) is intentionally kept"
        );
    }

    #[tokio::test]
    async fn freeform_exec_builtin_cannot_run_a_denied_program() {
        // THE load-bearing security regression. Before the fix, the `exec`
        // builtin called `cmd.exec()` directly — bypassing `before_exec` — so
        // `exec /usr/bin/touch MARKER` ran `touch` (and replaced the process
        // image). With `exec` removed from the confined set it is "command not
        // found": the marker must NOT be created, and the program must not run.
        let marker = fresh_marker("exec-builtin");
        let cx = authorize(&echo_grant()).unwrap();
        let cmd = format!("exec /usr/bin/touch {}", marker.display());
        let out = ShellTool::new()
            .invoke(serde_json::json!({ "cmd": cmd }), &cx)
            .await
            .expect("invoke must return cleanly, never panic/replace-process");
        // exec is gone → non-zero (command not found), and the program is dead.
        assert_ne!(out["exit_code"], 0, "exec must not succeed: {out:?}");
        assert!(
            !marker.exists(),
            "the exec'd program must NOT have run (marker created): {out:?}"
        );
        let _ = std::fs::remove_file(&marker);
    }

    #[tokio::test]
    async fn argv_exec_program_is_denied() {
        // The argv form names `exec` as the program. It is not in the granted
        // `exec` scope (`only{echo}`), so the leash's argv-mode pre-check denies
        // it before any shell is built — defense in depth alongside removal.
        let cx = authorize(&echo_grant()).unwrap();
        let err = ShellTool::new()
            .invoke(
                serde_json::json!({ "program": "exec", "args": ["/usr/bin/touch", "/tmp/x"] }),
                &cx,
            )
            .await
            .unwrap_err();
        assert!(matches!(err, ToolError::Denied { .. }), "got {err:?}");
    }

    #[tokio::test]
    async fn argv_exec_program_even_if_granted_does_not_bypass() {
        // Even when `exec` IS in the granted scope, the builtin is absent from
        // the confined shell, so the argv pre-check passes but the shell reports
        // "command not found" rather than process-replacing into the target.
        // The carried program never runs.
        let marker = fresh_marker("argv-exec");
        let cx = authorize(&Caveats {
            exec: Scope::only(["exec".to_string(), "echo".to_string()]),
            max_calls: CountBound::AtMost(8),
            ..Caveats::top()
        })
        .unwrap();
        let out = ShellTool::new()
            .invoke(
                serde_json::json!({
                    "program": "exec",
                    "args": ["/usr/bin/touch", marker.to_string_lossy()]
                }),
                &cx,
            )
            .await
            .expect("invoke must return cleanly");
        assert_ne!(
            out["exit_code"], 0,
            "exec builtin is gone → not found: {out:?}"
        );
        assert!(
            !marker.exists(),
            "no program may run via a removed exec builtin: {out:?}"
        );
        let _ = std::fs::remove_file(&marker);
    }

    #[tokio::test]
    async fn freeform_command_substitution_denies_cleanly_without_io_panic() {
        // Before the fix, the runtime had only `enable_time()`, so `$(...)`
        // command substitution panicked in tokio ("IO is disabled") and `invoke`
        // returned an opaque Err. With IO enabled, the substitution runs through
        // the funnel: the inner `/bin/rm` is denied via `before_exec`, the call
        // returns a CLEAN envelope with `denied: true`, and nothing is deleted.
        let victim = fresh_marker("cmdsubst-victim");
        std::fs::write(&victim, b"keep me").expect("seed victim file");

        let cx = authorize(&echo_grant()).unwrap();
        let cmd = format!("echo $(/bin/rm -rf {})", victim.display());
        let out = ShellTool::new()
            .invoke(serde_json::json!({ "cmd": cmd }), &cx)
            .await
            .expect("invoke must NOT be an Err/panic — a clean denial envelope");
        assert_eq!(
            out["denied"], true,
            "command substitution of a denied program must be flagged denied: {out:?}"
        );
        let denials = out["denials"].as_array().expect("denials array");
        assert!(
            denials.iter().any(|d| d["kind"] == "exec"
                && d["target"]
                    .as_str()
                    .is_some_and(|t| t == "/bin/rm" || t.ends_with("/rm"))),
            "expected an exec denial for /bin/rm, got {denials:?}"
        );
        assert!(
            victim.exists(),
            "the denied rm must NOT have deleted the victim file: {out:?}"
        );
        let _ = std::fs::remove_file(&victim);
    }

    // ── L3 (Landlock) kernel enforcement of an EXTERNAL program's writes ────

    #[cfg(all(target_os = "linux", feature = "linux-landlock"))]
    #[tokio::test]
    async fn l3_landlock_confines_external_program_write_outside_fs_write() {
        // THE reason L3 exists. L2 (`before_open`) cannot see an *external*
        // program's own writes once it has spawned — only the kernel can. Grant
        // exec={touch} + fs_write=Only{scratch}, then run the genuine external
        // `/usr/bin/touch` (path-separator form forces the spawn funnel, never a
        // carried builtin) to create a marker OUTSIDE scratch. Before this wiring
        // the marker WAS created (L2 is blind to the child); with the Landlock
        // ruleset enforced on the confined thread the kernel denies the write, so
        // the marker must NOT exist — even though the in-process leash never
        // fired for the child's syscalls.
        use agent_bridle_core::landlock_is_supported;
        let touch = std::path::Path::new("/usr/bin/touch");
        if !landlock_is_supported() || !touch.is_file() {
            return; // environment can't exercise this; self-skip.
        }

        let scratch = std::env::temp_dir().join(format!(
            "ab-l3-ok-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&scratch).expect("mkdir scratch");
        // A sibling under the temp dir — NOT beneath the granted scratch root.
        let outside = std::env::temp_dir().join(format!(
            "ab-l3-escape-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let _ = std::fs::remove_file(&outside);

        let cx = authorize(&Caveats {
            exec: Scope::only(["touch".to_string()]),
            fs_write: Scope::only([scratch.to_string_lossy().into_owned()]),
            max_calls: CountBound::AtMost(8),
            ..Caveats::top()
        })
        .unwrap();

        let cmd = format!("/usr/bin/touch {}", outside.display());
        let out = ShellTool::new()
            .invoke(serde_json::json!({ "cmd": cmd }), &cx)
            .await
            .expect("invoke");

        // The envelope honestly reports kernel confinement is in force.
        assert_eq!(
            out["sandbox_kind"], "landlock",
            "L3 must be active for a restricted fs_write scope: {out:?}"
        );
        // The kernel blocked the external's write: the marker is absent.
        assert!(
            !outside.exists(),
            "Landlock must prevent an external program writing outside fs_write: {out:?}"
        );
        // A write WITHIN scope still succeeds through the same confined run.
        let inside = scratch.join("inside.txt");
        let cmd2 = format!("/usr/bin/touch {}", inside.display());
        let cx2 = authorize(&Caveats {
            exec: Scope::only(["touch".to_string()]),
            fs_write: Scope::only([scratch.to_string_lossy().into_owned()]),
            max_calls: CountBound::AtMost(8),
            ..Caveats::top()
        })
        .unwrap();
        let out2 = ShellTool::new()
            .invoke(serde_json::json!({ "cmd": cmd2 }), &cx2)
            .await
            .expect("invoke");
        assert_eq!(
            out2["exit_code"], 0,
            "in-scope external write must succeed: {out2:?}"
        );
        assert!(
            inside.exists(),
            "in-scope marker should have been created: {out2:?}"
        );

        let _ = std::fs::remove_dir_all(&scratch);
        let _ = std::fs::remove_file(&outside);
    }

    /// Test-only unique-name disambiguator (a counter, never a clock).
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
}
