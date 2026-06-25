//! [`ShellTool`] — the confined shell, **argv + safe-subset engine** (ADR 0005).
//!
//! Per ADR 0005, the object-capability *boundary* is L3 (kernel) and this engine
//! is the L2 *convenience*: `agent-bridle` is the exec funnel — it parses the
//! request itself (see [`crate::parse`]), checks the `exec`/`fs` leash, spawns
//! the program directly, and **refuses the dynamic constructs by design**. Until
//! an L3 backstop is active (deferred — agent-bridle#35), a run is honestly
//! *advisory*: the result's `sandbox_kind` reports what actually enforced it
//! (I9), which today is [`SandboxKind::None`].
//!
//! This is **increment 1** of agent-bridle#34: a single command with quoted
//! arguments. Pipelines, redirections, `&&`/`||`/`;` and globbing land in later
//! increments; today they are refused as `Unsupported` (distinct from the
//! `Dynamic` constructs refused by design). `brush-bridle-core` remains the
//! deferred, reversible full-bash alternative engine (ADR 0005 D4, #20).

use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use agent_bridle_core::{
    Denial, DenialKind, SandboxKind, Tool, ToolContext, ToolEnvelope, ToolError, ToolResult,
};
use async_trait::async_trait;

use crate::parse::{classify, Refusal};

/// Maximum permitted (and default-clamped) wall-clock timeout.
const MAX_TIMEOUT_SECS: u64 = 300;
/// Default timeout when the caller does not specify one.
const DEFAULT_TIMEOUT_SECS: u64 = 60;
/// Cap on captured stdout/stderr returned in the envelope (bytes), so a chatty
/// command cannot return unbounded output. Streaming/byte-exact caps are a
/// follow-up; the timeout bounds runaway producers in the meantime.
const MAX_OUTPUT_BYTES: usize = 1 << 20; // 1 MiB

/// The confined shell tool.
///
/// Registers under `"shell"`. Accepts either argv form (`program` + `args`) or a
/// free-form `cmd` string parsed by the safe-subset engine. Leash refusals
/// (out-of-scope `exec`, a refused construct) are returned as a **structured
/// denied envelope** (`denied: true`), not a hard error — so an agent gets an
/// actionable signal it can correct.
#[derive(Debug, Default, Clone, Copy)]
pub struct ShellTool;

impl ShellTool {
    /// Construct the tool.
    #[must_use]
    pub fn new() -> Self {
        Self
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
                    "description": "Free-form command line run by the confined safe-subset engine: \
                        a single command with quoted arguments. Dynamic constructs \
                        ($(...), backticks, subshells) are refused by design; pipelines, \
                        redirections, &&/||/; and globbing are added incrementally and are \
                        refused (with a clear `denied` reason) until then. Mutually exclusive \
                        with `program`."
                },
                "cwd": {
                    "type": "string",
                    "description": "Working directory for the command (must be within fs_read scope)."
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
        // Honest reporting (ADR 0005 D1 / I9): this engine is L2 convenience, so
        // the kind is whatever is actually in force — None until L3 (#35).
        let sandbox_kind = cx.sandbox_kind();

        // Resolve to a single command's argv, or surface a structured refusal.
        let argv = match parsed.argv() {
            Ok(argv) => argv,
            Err(refusal) => return Ok(refused_envelope(sandbox_kind, &refusal)),
        };

        // Leash: the exec axis. Out-of-scope program → structured denial.
        if let Err(e) = cx.check_exec(&argv[0]) {
            return Ok(deny(sandbox_kind, DenialKind::Exec, &argv[0], &e));
        }

        // Leash: a provided cwd must be within fs_read scope.
        if let Some(cwd) = &parsed.cwd {
            if let Err(e) = cx.check_path_read(Path::new(cwd)) {
                return Ok(deny(sandbox_kind, DenialKind::Open, cwd, &e));
            }
        }

        // Run on a blocking thread, bounded by the timeout. On timeout the
        // blocking task is detached and a timeout envelope is returned.
        let cwd = parsed.cwd.clone();
        let timeout = parsed.timeout;
        let run = tokio::task::spawn_blocking(move || run_command(&argv, cwd.as_deref()));
        match tokio::time::timeout(timeout, run).await {
            Ok(joined) => {
                let captured = joined
                    .map_err(|e| ToolError::Other(anyhow::anyhow!("shell task panicked: {e}")))??;
                Ok(ToolEnvelope::new(sandbox_kind)
                    .with_exit_code(captured.exit_code)
                    .with_stdout(captured.stdout)
                    .with_stderr(captured.stderr)
                    .with_timed_out(false)
                    .into_json())
            }
            Err(_elapsed) => Ok(ToolEnvelope::new(sandbox_kind)
                .with_stderr(format!("command timed out after {}s", timeout.as_secs()))
                .with_timed_out(true)
                .into_json()),
        }
    }
}

/// Build a structured `denied` envelope for a leash refusal.
fn deny(
    sandbox_kind: SandboxKind,
    kind: DenialKind,
    target: &str,
    err: &ToolError,
) -> serde_json::Value {
    ToolEnvelope::new(sandbox_kind)
        .with_denials(vec![Denial {
            kind,
            target: target.to_string(),
            reason: err.to_string(),
        }])
        .into_json()
}

/// Build a structured `denied` envelope for a parser [`Refusal`].
fn refused_envelope(sandbox_kind: SandboxKind, refusal: &Refusal) -> serde_json::Value {
    ToolEnvelope::new(sandbox_kind)
        .with_denials(vec![Denial {
            kind: DenialKind::Exec,
            target: refusal.construct(),
            reason: refusal.to_string(),
        }])
        .into_json()
}

/// Parsed, validated `shell` arguments.
struct ShellArgs {
    program: Option<String>,
    args: Vec<String>,
    cmd: Option<String>,
    cwd: Option<String>,
    timeout: Duration,
}

impl ShellArgs {
    fn parse(v: &serde_json::Value) -> ToolResult<Self> {
        let obj = v
            .as_object()
            .ok_or_else(|| ToolError::denied("shell args must be a JSON object"))?;

        let program = obj
            .get("program")
            .and_then(|x| x.as_str())
            .map(String::from);
        let cmd = obj.get("cmd").and_then(|x| x.as_str()).map(String::from);
        let args = obj
            .get("args")
            .and_then(|x| x.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(String::from))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let cwd = obj.get("cwd").and_then(|x| x.as_str()).map(String::from);
        let timeout_secs = obj
            .get("timeout_secs")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(DEFAULT_TIMEOUT_SECS)
            .clamp(1, MAX_TIMEOUT_SECS);

        match (&program, &cmd) {
            (Some(_), Some(_)) => {
                return Err(ToolError::denied(
                    "provide exactly one of `program` or `cmd`, not both",
                ))
            }
            (None, None) => return Err(ToolError::denied("provide one of `program` or `cmd`")),
            _ => {}
        }
        if program.is_none() && !args.is_empty() {
            return Err(ToolError::denied(
                "`args` may only be used together with `program`",
            ));
        }

        Ok(Self {
            program,
            args,
            cmd,
            cwd,
            timeout: Duration::from_secs(timeout_secs),
        })
    }

    /// Resolve to a single command's argv (argv form is already structured;
    /// free-form is parsed by the safe-subset engine).
    fn argv(&self) -> Result<Vec<String>, Refusal> {
        if let Some(program) = &self.program {
            let mut argv = Vec::with_capacity(1 + self.args.len());
            argv.push(program.clone());
            argv.extend(self.args.iter().cloned());
            Ok(argv)
        } else {
            classify(self.cmd.as_deref().unwrap_or(""))
        }
    }
}

/// What a finished command produced.
struct Captured {
    exit_code: i32,
    stdout: String,
    stderr: String,
}

/// Spawn `argv` directly (no shell), capture stdout/stderr, and return the exit
/// code. `argv[0]` is the program; `argv[1..]` the arguments. stdin is closed.
fn run_command(argv: &[String], cwd: Option<&str>) -> ToolResult<Captured> {
    let mut cmd = std::process::Command::new(&argv[0]);
    cmd.args(&argv[1..])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(dir) = cwd {
        cmd.current_dir(dir);
    }
    let out = cmd.output().map_err(ToolError::Exec)?;
    Ok(Captured {
        exit_code: out.status.code().unwrap_or(-1),
        stdout: capped_utf8(&out.stdout),
        stderr: capped_utf8(&out.stderr),
    })
}

/// Lossy-decode at most [`MAX_OUTPUT_BYTES`] of captured output. Truncation at a
/// byte boundary is safe: [`String::from_utf8_lossy`] replaces any partial
/// trailing sequence rather than panicking.
fn capped_utf8(bytes: &[u8]) -> String {
    let slice = &bytes[..bytes.len().min(MAX_OUTPUT_BYTES)];
    String::from_utf8_lossy(slice).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_bridle_core::{Caveats, Gate, Scope};

    /// Mint a `ToolContext` the only legitimate way — through the gate.
    fn ctx(granted: Caveats) -> ToolContext {
        Gate::new(0)
            .authorize(&ShellTool, &granted)
            .expect("authorize")
    }

    /// A grant that allows exactly the given exec basenames.
    fn exec_only(names: &[&str]) -> Caveats {
        Caveats {
            exec: Scope::only(names.iter().map(|s| (*s).to_string())),
            ..Caveats::top()
        }
    }

    #[test]
    fn name_is_shell() {
        assert_eq!(ShellTool::new().name(), "shell");
    }

    #[test]
    fn schema_advertises_the_interface() {
        let s = ShellTool::new().schema();
        let props = s.get("properties").unwrap();
        for k in ["program", "args", "cmd", "cwd", "timeout_secs"] {
            assert!(props.get(k).is_some(), "missing schema property {k}");
        }
    }

    #[tokio::test]
    async fn argv_mode_runs_a_permitted_command() {
        let cx = ctx(exec_only(&["echo"]));
        let out = ShellTool::new()
            .invoke(serde_json::json!({"program": "echo", "args": ["hi"]}), &cx)
            .await
            .expect("invoke");
        assert_eq!(out["exit_code"], 0);
        assert_eq!(out["stdout"], "hi\n");
        assert_eq!(out["sandbox_kind"], "none"); // honest: advisory until L3
        assert!(out.get("denied").is_none());
    }

    #[tokio::test]
    async fn cmd_mode_runs_a_simple_command() {
        let cx = ctx(exec_only(&["echo"]));
        let out = ShellTool::new()
            .invoke(serde_json::json!({"cmd": "echo hi"}), &cx)
            .await
            .expect("invoke");
        assert_eq!(out["stdout"], "hi\n");
    }

    #[tokio::test]
    async fn cmd_mode_honors_quoting() {
        let cx = ctx(exec_only(&["echo"]));
        let out = ShellTool::new()
            .invoke(serde_json::json!({"cmd": "echo \"a b\""}), &cx)
            .await
            .expect("invoke");
        assert_eq!(out["stdout"], "a b\n");
    }

    /// The load-bearing security test for the engine: a quoted metacharacter is a
    /// literal argument — `echo "a|b"` prints `a|b`, it does not pipe.
    #[tokio::test]
    async fn quoted_pipe_is_a_literal_argument() {
        let cx = ctx(exec_only(&["echo"]));
        let out = ShellTool::new()
            .invoke(serde_json::json!({"cmd": "echo \"a|b\""}), &cx)
            .await
            .expect("invoke");
        assert_eq!(out["stdout"], "a|b\n");
        assert!(out.get("denied").is_none());
    }

    #[tokio::test]
    async fn out_of_scope_exec_is_denied_structurally() {
        let cx = ctx(exec_only(&["echo"])); // rm not granted
        let out = ShellTool::new()
            .invoke(
                serde_json::json!({"program": "rm", "args": ["-rf", "x"]}),
                &cx,
            )
            .await
            .expect("invoke");
        assert_eq!(out["denied"], true);
        assert_eq!(out["denials"][0]["kind"], "exec");
        assert_eq!(out["denials"][0]["target"], "rm");
    }

    /// A dynamic construct is refused by design and is NEVER executed.
    #[tokio::test]
    async fn command_substitution_is_refused_and_not_run() {
        let cx = ctx(Caveats::top()); // even with full exec, the form is refused
        let out = ShellTool::new()
            .invoke(serde_json::json!({"cmd": "echo $(whoami)"}), &cx)
            .await
            .expect("invoke");
        assert_eq!(out["denied"], true);
        assert!(
            out.get("exit_code").is_none(),
            "nothing must have run: {out}"
        );
        assert!(out["denials"][0]["reason"]
            .as_str()
            .unwrap()
            .contains("refused by design"));
    }

    /// A pipeline is refused as unsupported — the downstream command never runs.
    #[tokio::test]
    async fn pipeline_is_refused_so_downstream_never_runs() {
        let cx = ctx(Caveats::top());
        let out = ShellTool::new()
            .invoke(serde_json::json!({"cmd": "echo a | rm -rf x"}), &cx)
            .await
            .expect("invoke");
        assert_eq!(out["denied"], true);
        assert!(out.get("exit_code").is_none());
    }

    #[tokio::test]
    async fn both_program_and_cmd_is_a_hard_error() {
        let cx = ctx(Caveats::top());
        let res = ShellTool::new()
            .invoke(
                serde_json::json!({"program": "echo", "cmd": "echo hi"}),
                &cx,
            )
            .await;
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("exactly one"));
    }

    #[tokio::test]
    async fn timeout_is_reported() {
        let cx = ctx(exec_only(&["sleep"]));
        let out = ShellTool::new()
            .invoke(
                serde_json::json!({"program": "sleep", "args": ["5"], "timeout_secs": 1}),
                &cx,
            )
            .await
            .expect("invoke");
        assert_eq!(out["timed_out"], true);
    }
}
