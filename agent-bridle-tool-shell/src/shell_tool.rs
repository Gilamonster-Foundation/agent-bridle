//! The confined [`ShellTool`].

use std::collections::HashMap;
use std::io::Read;
use std::time::Duration;

use agent_bridle_core::{
    Caveats, SandboxKind, Tool, ToolContext, ToolEnvelope, ToolError, ToolResult,
};
use async_trait::async_trait;
use brush_builtins::{default_builtins, BuiltinSet};
use brush_core::extensions::{DefaultErrorFormatter, ShellExtensionsImpl};
use brush_core::openfiles::OpenFile;
use brush_core::{Shell, ShellFd};

use crate::caveat_interceptor::CaveatInterceptor;

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
        let sandbox_kind = cx.sandbox_kind();

        // (1) The leash, argv-mode fast path. If a *named* program is not in the
        // `exec` scope, deny before building anything. Free-form (`cmd`) has no
        // single named program; its exec gating is the interceptor's
        // `before_exec` hook, which fires at the spawn funnel (below).
        if let Some(program) = &parsed.program {
            cx.check_exec(program)?;
        }

        // (2) Apply the OS-level sandbox before running. For P0 this is a noop
        // (SandboxKind::None); P3 wires a real Landlock ruleset built from the
        // effective caveats here.
        apply_sandbox(cx.caveats(), sandbox_kind)?;

        // (3) Run via brush with carried builtins, captured output, the
        // capability interceptor (the cross-OS in-process leash), and a timeout.
        // Blocking shell work runs on a blocking thread; the interceptor carries
        // THIS invocation's effective caveats.
        let timeout = parsed.timeout;
        let interceptor = CaveatInterceptor::new(cx.clone());
        let run = tokio::task::spawn_blocking(move || run_in_brush(parsed, interceptor));
        let joined = tokio::time::timeout(timeout, run).await;

        match joined {
            // Completed in time.
            Ok(join_result) => {
                let captured = join_result
                    .map_err(|e| ToolError::Other(anyhow::anyhow!("shell task panicked: {e}")))??;
                Ok(ToolEnvelope::new(sandbox_kind)
                    .with_exit_code(captured.exit_code)
                    .with_stdout(captured.stdout)
                    .with_stderr(captured.stderr)
                    .with_timed_out(false)
                    .into_json())
            }
            // Timed out: the blocking task is detached; report a timeout
            // envelope so the caller sees the bound was hit.
            Err(_elapsed) => Ok(ToolEnvelope::new(sandbox_kind)
                .with_stderr(format!("command timed out after {}s", timeout.as_secs()))
                .with_timed_out(true)
                .into_json()),
        }
    }
}

/// Apply the OS sandbox (P0: noop). Kept as a seam so P3 can drop in Landlock.
fn apply_sandbox(_effective: &Caveats, _kind: SandboxKind) -> ToolResult<()> {
    // P3 TODO(linux-landlock): when the feature is active and the kernel
    // supports it, build + enforce a Landlock ruleset from `_effective` here,
    // and have the gate stamp SandboxKind::Landlock.
    Ok(())
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
/// This is synchronous: it runs on a blocking thread and spins a tiny current-
/// thread tokio runtime for brush's async shell API.
fn run_in_brush(parsed: ShellArgs, interceptor: CaveatInterceptor) -> ToolResult<Captured> {
    // Real OS pipes for fd 1 and 2.
    let (out_reader, out_writer) =
        std::io::pipe().map_err(|e| ToolError::Exec(io_ctx("create stdout pipe", e)))?;
    let (err_reader, err_writer) =
        std::io::pipe().map_err(|e| ToolError::Exec(io_ctx("create stderr pipe", e)))?;

    // Drain the read ends on background threads so a chatty command cannot
    // deadlock by filling the pipe buffer before the shell exits.
    let out_handle = std::thread::spawn(move || drain(out_reader));
    let err_handle = std::thread::spawn(move || drain(err_reader));

    // brush's shell API is async; run it on a single-thread runtime confined to
    // this blocking worker thread.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_time()
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
                // Carried builtins for our custom extensions type.
                .builtins(default_builtins::<LeashedExtensions>(BuiltinSet::BashMode))
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
        // cmd `rm -rf /tmp/x` → DENIED via before_exec (rm ∉ exec). A standard
        // PATH is seeded so `rm` resolves and the hook (not "command not found")
        // is what stops it; the non-zero exit + denial text prove the hook.
        let cx = authorize(&echo_grant()).unwrap();
        let out = ShellTool::new()
            .invoke(serde_json::json!({ "cmd": "rm -rf /tmp/x" }), &cx)
            .await
            .expect("invoke");
        assert_ne!(out["exit_code"], 0, "rm must not succeed: {out:?}");
        let stderr = out["stderr"].as_str().unwrap();
        assert!(
            stderr.contains("not within the granted authority") || stderr.contains("denied"),
            "expected an exec-denial in stderr, got {stderr:?}"
        );
    }

    #[tokio::test]
    async fn freeform_bin_rm_denied_closes_path_separator_bypass() {
        // cmd `/bin/rm -rf /tmp/x` → DENIED. THE load-bearing case: a
        // path-separator command bypasses PATH and the builtin table, so a
        // cleared PATH alone would NOT stop it — only the before_exec hook (at
        // the single spawn funnel) does. Proves the bypass is closed.
        let cx = authorize(&echo_grant()).unwrap();
        let out = ShellTool::new()
            .invoke(serde_json::json!({ "cmd": "/bin/rm -rf /tmp/x" }), &cx)
            .await
            .expect("invoke");
        assert_ne!(out["exit_code"], 0, "/bin/rm must not succeed: {out:?}");
        let stderr = out["stderr"].as_str().unwrap();
        assert!(
            stderr.contains("not within the granted authority") || stderr.contains("denied"),
            "expected an exec-denial for /bin/rm in stderr, got {stderr:?}"
        );
        // And the target must still exist if it did (we never created it); the
        // denial is observable purely via the refusal above.
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
        let stderr = out["stderr"].as_str().unwrap();
        assert!(
            stderr.contains("denied")
                || stderr.contains("not within the granted")
                || stderr.contains("open denied"),
            "expected an open-denial in stderr, got {stderr:?}"
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
        let written = std::fs::read_to_string(&target).expect("read back");
        assert!(written.contains("inscope"), "file content was {written:?}");

        let _ = std::fs::remove_dir_all(&scratch);
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

    /// Test-only unique-name disambiguator (a counter, never a clock).
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
}
