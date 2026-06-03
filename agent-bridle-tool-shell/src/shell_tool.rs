//! The confined [`ShellTool`].

use std::collections::HashMap;
use std::io::Read;
use std::time::Duration;

use agent_bridle_core::{
    Caveats, SandboxKind, Tool, ToolContext, ToolEnvelope, ToolError, ToolResult,
};
use async_trait::async_trait;
use brush_builtins::{default_builtins, BuiltinSet};
use brush_core::openfiles::OpenFile;
use brush_core::{Shell, ShellFd};

/// Maximum permitted timeout, in seconds. Requests above this are clamped.
const MAX_TIMEOUT_SECS: u64 = 300;
/// Default timeout when the caller does not specify one.
const DEFAULT_TIMEOUT_SECS: u64 = 30;

/// brush fds.
const STDOUT_FD: ShellFd = 1;
const STDERR_FD: ShellFd = 2;

/// A shell tool that runs a single, **named** command (argv form) through a
/// brush shell, confined by the leash.
///
/// `invoke` first asks the leash whether the named `program` may be executed
/// ([`ToolContext::check_exec`]); an out-of-scope program returns a *denied*
/// envelope (the leash refusing), demonstrating enforcement. An allowed command
/// runs in a non-interactive brush shell with `do_not_inherit_env(true)` and an
/// empty `PATH`, so brush's *carried* builtins (echo, printf, …) work even when
/// the host has no such binary on disk.
#[derive(Debug, Default, Clone, Copy)]
pub struct ShellTool;

impl ShellTool {
    /// Construct the tool.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

/// Parsed, validated arguments for one shell invocation.
struct ShellArgs {
    program: String,
    args: Vec<String>,
    cwd: Option<String>,
    timeout: Duration,
}

impl ShellArgs {
    fn parse(args: &serde_json::Value) -> ToolResult<Self> {
        let program = args
            .get("program")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| ToolError::denied("missing required string field `program`"))?
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

        let cwd = args
            .get("cwd")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string);

        let timeout_secs = args
            .get("timeout_secs")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(DEFAULT_TIMEOUT_SECS)
            .min(MAX_TIMEOUT_SECS);

        Ok(Self {
            program,
            args: arg_list,
            cwd,
            timeout: Duration::from_secs(timeout_secs),
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
                    "description": "The command to run (argv[0]). Gated by the `exec` caveat."
                },
                "args": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "Arguments passed to the command (argv[1..])."
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
            "required": ["program"],
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

        // (1) The leash. If the named program is not in the `exec` scope, this
        // denies — the command never runs, demonstrating enforcement before any
        // process is spawned.
        cx.check_exec(&parsed.program)?;

        // (2) Apply the OS-level sandbox before running. For P0 this is a noop
        // (SandboxKind::None); P3 wires a real Landlock ruleset built from the
        // effective caveats here.
        apply_sandbox(cx.caveats(), sandbox_kind)?;

        // (3) Run via brush with carried builtins, captured output, and a
        // timeout. Blocking shell work runs on a blocking thread.
        let timeout = parsed.timeout;
        let run = tokio::task::spawn_blocking(move || run_in_brush(parsed));
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

/// Drive a brush shell to completion for one argv-form command, capturing
/// stdout/stderr via real OS pipes (DESIGN §6: `Arc<Mutex<Vec<u8>>>` will not
/// compile against brush's `Stream`; pipes are mandatory).
///
/// This is synchronous: it runs on a blocking thread and spins a tiny current-
/// thread tokio runtime for brush's async shell API.
fn run_in_brush(parsed: ShellArgs) -> ToolResult<Captured> {
    // Build a quoted command line from the argv so brush parses it as a single
    // simple command. Each token is single-quoted (with embedded single-quotes
    // escaped) so args are passed literally — no word-splitting, no expansion.
    let mut command = sh_quote(&parsed.program);
    for a in &parsed.args {
        command.push(' ');
        command.push_str(&sh_quote(a));
    }

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

    let exit_code = rt.block_on(async move {
        let mut fds: HashMap<ShellFd, OpenFile> = HashMap::new();
        fds.insert(STDOUT_FD, OpenFile::from(out_writer));
        fds.insert(STDERR_FD, OpenFile::from(err_writer));

        let working_dir = parsed.cwd.map(std::path::PathBuf::from);

        let mut shell = Shell::builder()
            .builtins(default_builtins::<
                brush_core::extensions::DefaultShellExtensions,
            >(BuiltinSet::BashMode))
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

        // Empty PATH: prove carried builtins run without any host binary on
        // disk. `do_not_inherit_env(true)` already drops the host PATH; this
        // also overrides the default PATH that init-well-known-vars would seed.
        shell
            .env_mut()
            .set_global("PATH", brush_core::variables::ShellVariable::new(""))
            .map_err(|e| ToolError::Exec(io_ctx("clear PATH", into_io(&e))))?;

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
            max_calls: CountBound::AtMost(2),
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
    fn schema_is_argv_form() {
        let s = ShellTool::new().schema();
        assert_eq!(s["properties"]["program"]["type"], "string");
        assert_eq!(s["required"][0], "program");
        // It is argv form, NOT a free-form `cmd` string (the brush exec-bypass
        // mitigation): there is no `cmd` property.
        assert!(s["properties"].get("cmd").is_none());
    }
}
