//! [`ShellTool`] — the confined shell, **argv + safe-subset engine** (ADR 0005).
//!
//! Per ADR 0005, the object-capability *boundary* is L3 (kernel) and this engine
//! is the L2 *convenience*: `agent-bridle` is the exec funnel — it parses the
//! request itself (see [`crate::parse`]), checks the `exec`/`fs` leash, spawns
//! the program(s) directly, and **refuses the dynamic constructs by design**.
//! Until an L3 backstop is active (deferred — agent-bridle#35), a run is honestly
//! *advisory*: the result's `sandbox_kind` reports what actually enforced it (I9),
//! today [`SandboxKind::None`].
//!
//! **Increments 1–2** of agent-bridle#34: a **pipeline** of simple commands
//! (`a | b | c`) with quoted arguments. Redirections, `&&`/`||`/`;` and globbing
//! land in later increments; today they are refused as `Unsupported`. The actual
//! process spawning is behind a [`Spawner`] seam so the parse + leash logic is
//! unit-tested against a mock (no real subprocesses); the real `std::process`
//! path is covered by the `tests/real_spawn.rs` integration test.

use std::io::Read;
use std::path::Path;
use std::process::{Child, ChildStdout, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use agent_bridle_core::{
    Denial, DenialKind, SandboxKind, Tool, ToolContext, ToolEnvelope, ToolError, ToolResult,
};
use async_trait::async_trait;

use crate::parse::{classify, Pipeline, Refusal};

/// Maximum permitted (and default-clamped) wall-clock timeout.
const MAX_TIMEOUT_SECS: u64 = 300;
/// Default timeout when the caller does not specify one.
const DEFAULT_TIMEOUT_SECS: u64 = 60;
/// Cap on captured stdout/stderr returned in the envelope (bytes), so a chatty
/// command cannot return unbounded output. Streaming caps are a follow-up; the
/// timeout bounds runaway producers in the meantime.
const MAX_OUTPUT_BYTES: usize = 1 << 20; // 1 MiB

/// What a finished pipeline produced (the last stage's exit code; concatenated
/// output). The unit of the [`Spawner`] seam.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Captured {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

/// The pipeline-execution seam.
///
/// The real implementation ([`OsSpawner`]) spawns processes; tests inject a mock
/// so the parse + leash logic is verified without real subprocesses (the
/// workspace norm: no real process/fs in unit tests). A `Spawner` only ever
/// receives a pipeline that already passed the `exec` leash — admission happens
/// in [`ShellTool::invoke`] *before* the spawner is called.
pub(crate) trait Spawner: Send + Sync {
    /// Run a leash-approved pipeline to completion, capturing its output.
    fn run(&self, stages: &[Vec<String>], cwd: Option<&str>) -> ToolResult<Captured>;
}

/// The real spawner: a `std::process` pipeline wired with OS pipes.
struct OsSpawner;

impl Spawner for OsSpawner {
    fn run(&self, stages: &[Vec<String>], cwd: Option<&str>) -> ToolResult<Captured> {
        run_pipeline(stages, cwd)
    }
}

/// The confined shell tool.
///
/// Registers under `"shell"`. Accepts either argv form (`program` + `args`) or a
/// free-form `cmd` string parsed by the safe-subset engine. Leash refusals
/// (out-of-scope `exec`, a refused construct) are returned as a **structured
/// denied envelope** (`denied: true`), not a hard error.
#[derive(Clone)]
pub struct ShellTool {
    spawner: Arc<dyn Spawner>,
}

impl std::fmt::Debug for ShellTool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ShellTool")
    }
}

impl ShellTool {
    /// Construct the tool with the real OS spawner.
    #[must_use]
    pub fn new() -> Self {
        Self {
            spawner: Arc::new(OsSpawner),
        }
    }

    /// Construct with an injected spawner (tests only).
    #[cfg(test)]
    fn with_spawner(spawner: Arc<dyn Spawner>) -> Self {
        Self { spawner }
    }
}

impl Default for ShellTool {
    fn default() -> Self {
        Self::new()
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
                        a pipeline of simple commands (a | b | c) with quoted arguments. Dynamic \
                        constructs ($(...), backticks, subshells) are refused by design; \
                        redirections, &&/||/; and globbing are added incrementally and refused \
                        (with a clear `denied` reason) until then. Mutually exclusive with `program`."
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
        // Honest reporting (ADR 0005 D1 / I9): L2 convenience, so the kind is
        // whatever is actually in force — None until L3 (#35).
        let sandbox_kind = cx.sandbox_kind();

        // Resolve to a pipeline, or surface a structured refusal.
        let pipeline = match parsed.pipeline() {
            Ok(p) => p,
            Err(refusal) => return Ok(refused_envelope(sandbox_kind, &refusal)),
        };

        // Atomic admission (ADR 0001): EVERY stage's program must be in `exec`
        // scope *before any stage spawns*, so a single out-of-scope stage denies
        // the whole pipeline with no partial side effects.
        for stage in &pipeline {
            if let Err(e) = cx.check_exec(&stage[0]) {
                return Ok(deny(sandbox_kind, DenialKind::Exec, &stage[0], &e));
            }
        }
        // Leash: a provided cwd must be within fs_read scope.
        if let Some(cwd) = &parsed.cwd {
            if let Err(e) = cx.check_path_read(Path::new(cwd)) {
                return Ok(deny(sandbox_kind, DenialKind::Open, cwd, &e));
            }
        }

        // Run on a blocking thread, bounded by the timeout. On timeout the
        // blocking task is detached and a timeout envelope is returned.
        let spawner = Arc::clone(&self.spawner);
        let cwd = parsed.cwd.clone();
        let timeout = parsed.timeout;
        let run = tokio::task::spawn_blocking(move || spawner.run(&pipeline, cwd.as_deref()));
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

    /// Resolve to a pipeline (argv form is a one-stage pipeline; free-form is
    /// parsed by the safe-subset engine).
    fn pipeline(&self) -> Result<Pipeline, Refusal> {
        if let Some(program) = &self.program {
            let mut argv = Vec::with_capacity(1 + self.args.len());
            argv.push(program.clone());
            argv.extend(self.args.iter().cloned());
            Ok(vec![argv])
        } else {
            classify(self.cmd.as_deref().unwrap_or(""))
        }
    }
}

/// Spawn a pipeline of commands wired with OS pipes, capturing the last stage's
/// stdout and every stage's stderr. The pipeline's exit code is the last stage's
/// (bash semantics without `pipefail`).
///
/// Deadlock-free: every stage's stderr and the last stage's stdout are drained
/// by their own threads, so no pipe can fill while we `wait()` the children.
fn run_pipeline(stages: &[Vec<String>], cwd: Option<&str>) -> ToolResult<Captured> {
    debug_assert!(!stages.is_empty(), "the parser guarantees ≥1 stage");

    let mut children: Vec<Child> = Vec::with_capacity(stages.len());
    let mut prev_stdout: Option<ChildStdout> = None;

    for (i, argv) in stages.iter().enumerate() {
        let mut cmd = Command::new(&argv[0]);
        cmd.args(&argv[1..]);
        if let Some(dir) = cwd {
            cmd.current_dir(dir);
        }
        cmd.stdin(match prev_stdout.take() {
            Some(out) => Stdio::from(out),
            None => Stdio::null(),
        });
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                // A bad stage must not orphan the stages already started.
                for mut started in children {
                    let _ = started.kill();
                    let _ = started.wait();
                }
                return Err(ToolError::Exec(e));
            }
        };

        // Wire this stage's stdout into the next stage's stdin — except the last
        // stage, whose stdout we capture below.
        if i + 1 < stages.len() {
            prev_stdout = child.stdout.take();
        }
        children.push(child);
    }

    // Drain every stderr and the last stdout concurrently so no pipe deadlocks.
    let mut stderr_readers = Vec::with_capacity(children.len());
    for child in &mut children {
        let mut err = child.stderr.take().expect("stderr is piped");
        stderr_readers.push(std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = err.read_to_end(&mut buf);
            buf
        }));
    }
    let mut last_stdout = children
        .last_mut()
        .expect("≥1 stage")
        .stdout
        .take()
        .expect("last stage stdout is piped");
    let stdout_reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = last_stdout.read_to_end(&mut buf);
        buf
    });

    // Wait all stages; the pipeline's exit code is the last stage's.
    let last = children.len() - 1;
    let mut exit_code = -1;
    for (i, child) in children.iter_mut().enumerate() {
        let status = child.wait().map_err(ToolError::Exec)?;
        if i == last {
            exit_code = status.code().unwrap_or(-1);
        }
    }

    let stdout = stdout_reader.join().unwrap_or_default();
    let mut stderr = Vec::new();
    for reader in stderr_readers {
        stderr.extend(reader.join().unwrap_or_default());
    }

    Ok(Captured {
        exit_code,
        stdout: capped_utf8(&stdout),
        stderr: capped_utf8(&stderr),
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
    use std::sync::Mutex;

    /// A spawner that records every pipeline it is asked to run and returns a
    /// canned result — no real processes. `block_ms` lets a test exercise the
    /// timeout path deterministically without a real `sleep`.
    #[derive(Default)]
    struct MockSpawner {
        calls: Mutex<Vec<Pipeline>>,
        stdout: String,
        exit_code: i32,
        block_ms: u64,
    }

    impl Spawner for MockSpawner {
        fn run(&self, stages: &[Vec<String>], _cwd: Option<&str>) -> ToolResult<Captured> {
            self.calls.lock().unwrap().push(stages.to_vec());
            if self.block_ms > 0 {
                std::thread::sleep(Duration::from_millis(self.block_ms));
            }
            Ok(Captured {
                exit_code: self.exit_code,
                stdout: self.stdout.clone(),
                stderr: String::new(),
            })
        }
    }

    fn ctx(granted: Caveats) -> ToolContext {
        Gate::new(0)
            .authorize(&ShellTool::new(), &granted)
            .expect("authorize")
    }

    fn exec_only(names: &[&str]) -> Caveats {
        Caveats {
            exec: Scope::only(names.iter().map(|s| (*s).to_string())),
            ..Caveats::top()
        }
    }

    /// Pipelines the mock recorded (what *would* have been spawned).
    fn recorded(mock: &Arc<MockSpawner>) -> Vec<Pipeline> {
        mock.calls.lock().unwrap().clone()
    }

    fn argv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| (*s).to_string()).collect()
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
    async fn argv_mode_resolves_to_one_stage_and_runs() {
        let mock = Arc::new(MockSpawner {
            stdout: "hi\n".into(),
            ..Default::default()
        });
        let out = ShellTool::with_spawner(mock.clone())
            .invoke(
                serde_json::json!({"program": "echo", "args": ["hi"]}),
                &ctx(exec_only(&["echo"])),
            )
            .await
            .expect("invoke");
        assert_eq!(out["exit_code"], 0);
        assert_eq!(out["stdout"], "hi\n");
        assert_eq!(out["sandbox_kind"], "none"); // honest: advisory until L3
        assert_eq!(recorded(&mock), vec![vec![argv(&["echo", "hi"])]]);
    }

    #[tokio::test]
    async fn pipeline_passes_every_stage_to_the_spawner() {
        let mock = Arc::new(MockSpawner::default());
        ShellTool::with_spawner(mock.clone())
            .invoke(
                serde_json::json!({"cmd": "grep foo | wc -l"}),
                &ctx(exec_only(&["grep", "wc"])),
            )
            .await
            .expect("invoke");
        assert_eq!(
            recorded(&mock),
            vec![vec![argv(&["grep", "foo"]), argv(&["wc", "-l"])]]
        );
    }

    #[tokio::test]
    async fn quoted_pipe_stays_a_single_stage() {
        let mock = Arc::new(MockSpawner::default());
        ShellTool::with_spawner(mock.clone())
            .invoke(
                serde_json::json!({"cmd": "echo \"a|b\""}),
                &ctx(exec_only(&["echo"])),
            )
            .await
            .expect("invoke");
        assert_eq!(recorded(&mock), vec![vec![argv(&["echo", "a|b"])]]);
    }

    /// THE security assertion: an out-of-scope program is denied and the spawner
    /// is NEVER called — nothing would have run.
    #[tokio::test]
    async fn out_of_scope_exec_denied_before_spawn() {
        let mock = Arc::new(MockSpawner::default());
        let out = ShellTool::with_spawner(mock.clone())
            .invoke(
                serde_json::json!({"program": "rm", "args": ["-rf", "/tmp/x"]}),
                &ctx(exec_only(&["echo"])),
            )
            .await
            .expect("invoke");
        assert_eq!(out["denied"], true);
        assert_eq!(out["denials"][0]["kind"], "exec");
        assert_eq!(out["denials"][0]["target"], "rm");
        assert!(recorded(&mock).is_empty(), "spawner must not be called");
    }

    /// Atomic admission: if ANY pipeline stage is out of scope, the whole
    /// pipeline is denied and nothing spawns — no partial side effects.
    #[tokio::test]
    async fn pipeline_atomic_admission_denies_whole_if_any_stage_out_of_scope() {
        let mock = Arc::new(MockSpawner::default());
        let out = ShellTool::with_spawner(mock.clone())
            .invoke(
                serde_json::json!({"cmd": "grep foo | rm -rf x"}),
                &ctx(exec_only(&["grep"])), // rm not granted
            )
            .await
            .expect("invoke");
        assert_eq!(out["denied"], true);
        assert_eq!(out["denials"][0]["target"], "rm");
        assert!(
            recorded(&mock).is_empty(),
            "an out-of-scope stage must abort the whole pipeline before any spawn"
        );
    }

    /// A dynamic construct is refused by design and never reaches the spawner.
    #[tokio::test]
    async fn dynamic_construct_refused_before_spawn() {
        let mock = Arc::new(MockSpawner::default());
        let out = ShellTool::with_spawner(mock.clone())
            .invoke(
                serde_json::json!({"cmd": "echo $(whoami)"}),
                &ctx(Caveats::top()),
            )
            .await
            .expect("invoke");
        assert_eq!(out["denied"], true);
        assert!(out.get("exit_code").is_none());
        assert!(out["denials"][0]["reason"]
            .as_str()
            .unwrap()
            .contains("refused by design"));
        assert!(recorded(&mock).is_empty());
    }

    #[tokio::test]
    async fn both_program_and_cmd_is_a_hard_error() {
        let res = ShellTool::new()
            .invoke(
                serde_json::json!({"program": "echo", "cmd": "echo hi"}),
                &ctx(Caveats::top()),
            )
            .await;
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("exactly one"));
    }

    #[tokio::test]
    async fn timeout_is_reported() {
        // The mock blocks longer than the 1s timeout — no real process involved.
        let mock = Arc::new(MockSpawner {
            block_ms: 1500,
            ..Default::default()
        });
        let out = ShellTool::with_spawner(mock)
            .invoke(
                serde_json::json!({"program": "anything", "timeout_secs": 1}),
                &ctx(exec_only(&["anything"])),
            )
            .await
            .expect("invoke");
        assert_eq!(out["timed_out"], true);
    }
}
