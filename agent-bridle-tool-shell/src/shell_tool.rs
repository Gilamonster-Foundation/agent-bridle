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
//! **Increments 1–4** of agent-bridle#34: a sequence of pipelines joined by
//! `&&`/`||`/`;`, each pipeline simple commands with quoted arguments and file
//! redirections (`> out`, `>> out`, `< in`). Globbing and variable expansion land
//! in a later increment. Because `agent-bridle` performs each redirect's file
//! open itself, those opens are leash-checked (`fs_write`/`fs_read`) *before any
//! stage spawns* — a real enforcement point, unlike a spawned program's own
//! opens (L3's job). Process spawning is behind a [`Spawner`] seam (mocked in
//! unit tests; real path in `tests/real_spawn.rs`).

use std::io::Read;
use std::path::Path;
use std::process::{Child, ChildStdout, Stdio};
use std::sync::Arc;
use std::time::Duration;

use agent_bridle_core::{
    Denial, DenialKind, SandboxKind, Tool, ToolContext, ToolEnvelope, ToolError, ToolResult,
};
use async_trait::async_trait;

use crate::parse::{classify, Command, Redirect, Refusal, Script, ScriptItem, Sep};

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
/// so the parse + leash + sequencing logic is verified without real subprocesses
/// (the workspace norm: no real process/fs in unit tests). A `Spawner` only ever
/// receives a pipeline that already passed the `exec` **and** redirect-`fs` leash
/// — admission happens in [`ShellTool::invoke`] *before* the spawner runs.
pub(crate) trait Spawner: Send + Sync {
    /// Run one leash-approved pipeline to completion, capturing its output.
    fn run(&self, stages: &[Command], cwd: Option<&str>) -> ToolResult<Captured>;
}

/// The real spawner: a `std::process` pipeline wired with OS pipes + redirects.
struct OsSpawner;

impl Spawner for OsSpawner {
    fn run(&self, stages: &[Command], cwd: Option<&str>) -> ToolResult<Captured> {
        run_pipeline(stages, cwd)
    }
}

/// The confined shell tool.
///
/// Registers under `"shell"`. Accepts either argv form (`program` + `args`) or a
/// free-form `cmd` string parsed by the safe-subset engine. Leash refusals
/// (out-of-scope `exec`/`fs`, a refused construct) are returned as a **structured
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
                        pipelines (a | b) joined by &&/||/;, with quoted arguments and file \
                        redirections (> out, >> out, < in; targets gated by fs_write/fs_read). \
                        Dynamic constructs ($(...), backticks, subshells) are refused by design; \
                        globbing and fd-number redirections (2>, 2>&1) are added incrementally and \
                        refused (with a clear `denied` reason) until then. Mutually exclusive with `program`."
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

        // Resolve to a script (sequence of pipelines), or surface a refusal.
        let script = match parsed.script() {
            Ok(s) => s,
            Err(refusal) => return Ok(refused_envelope(sandbox_kind, &refusal)),
        };

        // Atomic admission (ADR 0001): every program (`exec`) and every redirect
        // target (`fs_write`/`fs_read`, which bridle itself opens) across the
        // WHOLE script must pass *before any stage spawns* — one out-of-scope
        // element denies the whole script with no partial side effects (even for
        // commands a `&&`/`||` would have short-circuited away).
        for item in &script {
            for stage in &item.pipeline {
                if let Err(e) = cx.check_exec(&stage.argv[0]) {
                    return Ok(deny(sandbox_kind, DenialKind::Exec, &stage.argv[0], &e));
                }
                for redirect in &stage.redirects {
                    let (path, checked) = match redirect {
                        Redirect::Stdout { path, .. } => {
                            (path, cx.check_path_write(Path::new(path)))
                        }
                        Redirect::Stdin { path } => (path, cx.check_path_read(Path::new(path))),
                    };
                    if let Err(e) = checked {
                        return Ok(deny(sandbox_kind, DenialKind::Open, path, &e));
                    }
                }
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
        let run =
            tokio::task::spawn_blocking(move || run_script(&*spawner, &script, cwd.as_deref()));
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

/// Execute a [`Script`] with `&&`/`||`/`;` short-circuit semantics, concatenating
/// the output of the pipelines that actually run. The script's exit code is that
/// of the last pipeline that ran (bash AND-OR-list semantics).
fn run_script(
    spawner: &dyn Spawner,
    script: &[ScriptItem],
    cwd: Option<&str>,
) -> ToolResult<Captured> {
    let mut stdout = String::new();
    let mut stderr = String::new();
    let mut status: i32 = 0;

    for item in script {
        let run_it = match item.sep {
            Sep::Seq => true,
            Sep::And => status == 0,
            Sep::Or => status != 0,
        };
        if run_it {
            let captured = spawner.run(&item.pipeline, cwd)?;
            stdout.push_str(&captured.stdout);
            stderr.push_str(&captured.stderr);
            status = captured.exit_code;
        }
    }

    Ok(Captured {
        exit_code: status,
        stdout: cap_string(stdout),
        stderr: cap_string(stderr),
    })
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

    /// Resolve to a script (argv form is a one-pipeline, one-stage script with no
    /// redirects; free-form is parsed by the safe-subset engine).
    fn script(&self) -> Result<Script, Refusal> {
        if let Some(program) = &self.program {
            let mut argv = Vec::with_capacity(1 + self.args.len());
            argv.push(program.clone());
            argv.extend(self.args.iter().cloned());
            Ok(vec![ScriptItem {
                sep: Sep::Seq,
                pipeline: vec![Command {
                    argv,
                    redirects: Vec::new(),
                }],
            }])
        } else {
            classify(self.cmd.as_deref().unwrap_or(""))
        }
    }
}

/// Open a file for an `fs_write` redirect target (`>` truncates, `>>` appends).
fn open_for_write(path: &str, append: bool) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(!append)
        .append(append)
        .open(path)
}

/// Kill (and reap) any stages already spawned, so a mid-pipeline error does not
/// orphan processes.
fn kill_all(children: &mut [Child]) {
    for child in children.iter_mut() {
        let _ = child.kill();
        let _ = child.wait();
    }
}

/// Spawn a pipeline of commands wired with OS pipes and file redirections,
/// capturing the last stage's stdout (unless it is redirected to a file) and
/// every stage's stderr. The pipeline's exit code is the last stage's (bash
/// semantics without `pipefail`).
///
/// Deadlock-free: every stage's stderr and the last stage's stdout are drained by
/// their own threads, so no pipe can fill while we `wait()` the children.
fn run_pipeline(stages: &[Command], cwd: Option<&str>) -> ToolResult<Captured> {
    debug_assert!(!stages.is_empty(), "the parser guarantees ≥1 stage");
    let n = stages.len();

    let mut children: Vec<Child> = Vec::with_capacity(n);
    let mut prev_stdout: Option<ChildStdout> = None;

    for (i, stage) in stages.iter().enumerate() {
        let mut cmd = std::process::Command::new(&stage.argv[0]);
        cmd.args(&stage.argv[1..]);
        if let Some(dir) = cwd {
            cmd.current_dir(dir);
        }

        // stdin: a `< file` redirect wins over the incoming pipe.
        if let Some(path) = stage.stdin_path() {
            let file = match std::fs::File::open(path) {
                Ok(f) => f,
                Err(e) => {
                    kill_all(&mut children);
                    return Err(ToolError::Exec(e));
                }
            };
            cmd.stdin(Stdio::from(file));
            prev_stdout = None; // discard the incoming pipe, if any
        } else {
            cmd.stdin(match prev_stdout.take() {
                Some(out) => Stdio::from(out),
                None => Stdio::null(),
            });
        }

        // stdout: a `> file` / `>> file` redirect wins over the pipe/capture.
        let stdout_to_file = stage.stdout_redirect().is_some();
        if let Some((path, append)) = stage.stdout_redirect() {
            let file = match open_for_write(path, append) {
                Ok(f) => f,
                Err(e) => {
                    kill_all(&mut children);
                    return Err(ToolError::Exec(e));
                }
            };
            cmd.stdout(Stdio::from(file));
        } else {
            cmd.stdout(Stdio::piped());
        }
        cmd.stderr(Stdio::piped());

        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                kill_all(&mut children);
                return Err(ToolError::Exec(e));
            }
        };

        // Wire this stage's stdout into the next stage's stdin only if it is
        // piped (no redirect) and there is a next stage.
        if !stdout_to_file && i + 1 < n {
            prev_stdout = child.stdout.take();
        }
        children.push(child);
    }

    // Drain every stage's stderr concurrently.
    let mut stderr_readers = Vec::with_capacity(n);
    for child in &mut children {
        let mut err = child.stderr.take().expect("stderr is piped");
        stderr_readers.push(std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = err.read_to_end(&mut buf);
            buf
        }));
    }
    // Drain the last stage's stdout, unless it went to a file.
    let last = n - 1;
    let stdout_reader = if stages[last].stdout_redirect().is_none() {
        let mut out = children[last]
            .stdout
            .take()
            .expect("last stage stdout is piped");
        Some(std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = out.read_to_end(&mut buf);
            buf
        }))
    } else {
        None
    };

    // Wait all stages; the pipeline's exit code is the last stage's.
    let mut exit_code = -1;
    for (i, child) in children.iter_mut().enumerate() {
        let status = child.wait().map_err(ToolError::Exec)?;
        if i == last {
            exit_code = status.code().unwrap_or(-1);
        }
    }

    let stdout = stdout_reader.map_or_else(Vec::new, |h| h.join().unwrap_or_default());
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

/// Cap an already-decoded string to [`MAX_OUTPUT_BYTES`] at a char boundary
/// (used for the concatenated output of a multi-pipeline script).
fn cap_string(mut s: String) -> String {
    if s.len() > MAX_OUTPUT_BYTES {
        let mut end = MAX_OUTPUT_BYTES;
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        s.truncate(end);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_bridle_core::{Caveats, Gate, Scope};
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// A spawner that records every pipeline it runs and returns a canned exit
    /// code per program (argv0), default 0 — no real processes. `block_ms` lets
    /// a test exercise the timeout path without a real `sleep`.
    #[derive(Default)]
    struct MockSpawner {
        calls: Mutex<Vec<Vec<Command>>>,
        exit_by_program: HashMap<String, i32>,
        stdout_by_program: HashMap<String, String>,
        block_ms: u64,
    }

    impl MockSpawner {
        fn with_exit(program: &str, code: i32) -> Self {
            let mut m = Self::default();
            m.exit_by_program.insert(program.to_string(), code);
            m
        }
    }

    impl Spawner for MockSpawner {
        fn run(&self, stages: &[Command], _cwd: Option<&str>) -> ToolResult<Captured> {
            self.calls.lock().unwrap().push(stages.to_vec());
            if self.block_ms > 0 {
                std::thread::sleep(Duration::from_millis(self.block_ms));
            }
            let prog = &stages[0].argv[0];
            Ok(Captured {
                exit_code: self.exit_by_program.get(prog).copied().unwrap_or(0),
                stdout: self
                    .stdout_by_program
                    .get(prog)
                    .cloned()
                    .unwrap_or_default(),
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

    /// The programs (argv0 of each pipeline's first stage) the mock actually ran,
    /// in order — the cheapest way to assert short-circuit behavior.
    fn ran_programs(mock: &Arc<MockSpawner>) -> Vec<String> {
        mock.calls
            .lock()
            .unwrap()
            .iter()
            .map(|pipeline| pipeline[0].argv[0].clone())
            .collect()
    }

    #[test]
    fn name_is_shell() {
        assert_eq!(ShellTool::new().name(), "shell");
    }

    #[tokio::test]
    async fn and_runs_second_only_on_success() {
        // `true && echo` → both run.
        let mock = Arc::new(MockSpawner::default());
        ShellTool::with_spawner(mock.clone())
            .invoke(
                serde_json::json!({"cmd": "true && echo hi"}),
                &ctx(exec_only(&["true", "echo"])),
            )
            .await
            .expect("invoke");
        assert_eq!(ran_programs(&mock), vec!["true", "echo"]);
    }

    #[tokio::test]
    async fn and_short_circuits_on_failure() {
        // `false && echo` → `echo` is skipped because `false` exits non-zero.
        let mock = Arc::new(MockSpawner::with_exit("false", 1));
        let out = ShellTool::with_spawner(mock.clone())
            .invoke(
                serde_json::json!({"cmd": "false && echo hi"}),
                &ctx(exec_only(&["false", "echo"])),
            )
            .await
            .expect("invoke");
        assert_eq!(ran_programs(&mock), vec!["false"], "echo must be skipped");
        assert_eq!(out["exit_code"], 1, "script exit is the last that ran");
    }

    #[tokio::test]
    async fn or_runs_second_only_on_failure() {
        // `false || echo` → `echo` runs (fallback).
        let mock = Arc::new(MockSpawner::with_exit("false", 1));
        ShellTool::with_spawner(mock.clone())
            .invoke(
                serde_json::json!({"cmd": "false || echo hi"}),
                &ctx(exec_only(&["false", "echo"])),
            )
            .await
            .expect("invoke");
        assert_eq!(ran_programs(&mock), vec!["false", "echo"]);
    }

    #[tokio::test]
    async fn or_short_circuits_on_success() {
        // `true || echo` → `echo` is skipped because `true` succeeded.
        let mock = Arc::new(MockSpawner::default());
        ShellTool::with_spawner(mock.clone())
            .invoke(
                serde_json::json!({"cmd": "true || echo hi"}),
                &ctx(exec_only(&["true", "echo"])),
            )
            .await
            .expect("invoke");
        assert_eq!(ran_programs(&mock), vec!["true"]);
    }

    #[tokio::test]
    async fn semicolon_runs_unconditionally() {
        // `false ; echo` → both run; exit is the last (`echo` → 0).
        let mock = Arc::new(MockSpawner::with_exit("false", 1));
        let out = ShellTool::with_spawner(mock.clone())
            .invoke(
                serde_json::json!({"cmd": "false ; echo hi"}),
                &ctx(exec_only(&["false", "echo"])),
            )
            .await
            .expect("invoke");
        assert_eq!(ran_programs(&mock), vec!["false", "echo"]);
        assert_eq!(out["exit_code"], 0);
    }

    /// Atomic admission across the WHOLE script: an out-of-scope command anywhere
    /// (even one a `;` would reach, or a `&&` would skip) denies everything and
    /// nothing spawns.
    #[tokio::test]
    async fn out_of_scope_anywhere_denies_the_whole_script() {
        let mock = Arc::new(MockSpawner::default());
        let out = ShellTool::with_spawner(mock.clone())
            .invoke(
                serde_json::json!({"cmd": "echo ok ; rm -rf x"}),
                &ctx(exec_only(&["echo"])), // rm not granted
            )
            .await
            .expect("invoke");
        assert_eq!(out["denied"], true);
        assert_eq!(out["denials"][0]["target"], "rm");
        assert!(ran_programs(&mock).is_empty(), "nothing must run");
    }

    #[tokio::test]
    async fn combined_output_concatenates_in_order() {
        let mut mock = MockSpawner::default();
        mock.stdout_by_program.insert("echo".into(), "x".into());
        mock.stdout_by_program.insert("printf".into(), "y".into());
        let mock = Arc::new(mock);
        let out = ShellTool::with_spawner(mock.clone())
            .invoke(
                serde_json::json!({"cmd": "echo a ; printf b"}),
                &ctx(exec_only(&["echo", "printf"])),
            )
            .await
            .expect("invoke");
        assert_eq!(out["stdout"], "xy");
    }

    /// A dynamic construct anywhere in the sequence is refused before any spawn.
    #[tokio::test]
    async fn dynamic_in_sequence_refused_before_spawn() {
        let mock = Arc::new(MockSpawner::default());
        let out = ShellTool::with_spawner(mock.clone())
            .invoke(
                serde_json::json!({"cmd": "echo ok && $(evil)"}),
                &ctx(Caveats::top()),
            )
            .await
            .expect("invoke");
        assert_eq!(out["denied"], true);
        assert!(ran_programs(&mock).is_empty());
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
