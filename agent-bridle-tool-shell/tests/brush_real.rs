//! Real-spawn reality-check for the carried **brush engine** (agent-bridle#20).
//!
//! Proves the engine's whole thesis: it runs a **dynamic construct the
//! safe-subset engine refuses** (`$(...)`) in-process, AND — unlike the
//! sandbox-host engine, which refuses a restricted `exec` grant — it **confines**
//! a restricted `exec` grant in-process via the `CommandInterceptor`, denying an
//! out-of-scope command (structured `denied:true`) while it never runs.
//!
//! Kept out of the unit tests (which mock the spawner) per the workspace norm.
#![cfg(feature = "brush")]

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use agent_bridle_core::{Caveats, Gate, Scope, Tool, ToolContext};
use agent_bridle_tool_shell::{
    BrushShellTool, ShellInvocationId, ShellOutputObserver, ShellOutputStream,
};

#[cfg(unix)]
const OUTPUT_CAP: usize = 64 * 1024;

#[derive(Default)]
struct OutputRecorder {
    chunks: Mutex<Vec<(ShellOutputStream, Vec<u8>)>>,
    finished: Mutex<bool>,
    finished_cv: Condvar,
}

impl ShellOutputObserver for OutputRecorder {
    fn on_output(&self, _invocation: ShellInvocationId, stream: ShellOutputStream, chunk: &[u8]) {
        self.chunks
            .lock()
            .expect("output recorder lock")
            .push((stream, chunk.to_vec()));
    }

    fn on_finish(&self, _invocation: ShellInvocationId) {
        *self.finished.lock().expect("finished lock") = true;
        self.finished_cv.notify_all();
    }
}

impl OutputRecorder {
    fn bytes(&self, stream: ShellOutputStream) -> Vec<u8> {
        self.chunks
            .lock()
            .expect("output recorder lock")
            .iter()
            .filter(|(seen, _)| *seen == stream)
            .flat_map(|(_, chunk)| chunk.iter().copied())
            .collect()
    }

    fn wait_finished(&self) {
        let finished = self.finished.lock().expect("finished lock");
        let (finished, _) = self
            .finished_cv
            .wait_timeout_while(finished, Duration::from_secs(2), |finished| !*finished)
            .expect("finished condition variable");
        assert!(*finished, "timed out waiting for observer finish");
    }
}

/// Mint a [`ToolContext`] carrying `granted` — the public-API path an embedder
/// uses (mirrors `host_shell_real.rs`).
fn ctx(granted: Caveats) -> ToolContext {
    Gate::new(0)
        .authorize(&BrushShellTool::new(), &granted)
        .expect("authorize")
}

fn unique_temp(tag: &str) -> std::path::PathBuf {
    static N: AtomicU64 = AtomicU64::new(0);
    std::env::temp_dir().join(format!(
        "ab-brush-{}-{}-{}",
        tag,
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ))
}

#[tokio::test]
async fn output_observer_matches_the_brush_envelope() {
    let observer = Arc::new(OutputRecorder::default());
    let out = BrushShellTool::new()
        .with_output_observer(observer.clone())
        .invoke(
            serde_json::json!({ "cmd": "printf brush-out; printf brush-err >&2" }),
            &ctx(Caveats::top()),
        )
        .await
        .expect("invoke");

    observer.wait_finished();
    assert_eq!(observer.bytes(ShellOutputStream::Stdout), b"brush-out");
    assert_eq!(observer.bytes(ShellOutputStream::Stderr), b"brush-err");
    assert_eq!(out["stdout"], "brush-out");
    assert_eq!(out["stderr"], "brush-err");
}

#[cfg(unix)]
#[tokio::test]
async fn stderr_observer_and_brush_envelope_apply_the_output_cap() {
    let observer = Arc::new(OutputRecorder::default());
    let out = BrushShellTool::new()
        .with_output_observer(observer.clone())
        .invoke(
            serde_json::json!({
                "cmd": format!("yes b | head -c {} >&2", OUTPUT_CAP + 4),
            }),
            &ctx(Caveats::top()),
        )
        .await
        .expect("invoke chatty brush shell");

    observer.wait_finished();
    let observed = observer.bytes(ShellOutputStream::Stderr);
    assert_eq!(observed.len(), OUTPUT_CAP);
    assert_eq!(
        out["stderr"].as_str().expect("stderr string").as_bytes(),
        observed
    );
}

/// Full-access: a `$(...)` command substitution — refused by the safe-subset
/// engine — RUNS in-process, and the engine identity is disclosed.
#[tokio::test]
async fn full_access_runs_dynamic_construct_and_captures() {
    let out = BrushShellTool::new()
        .invoke(
            serde_json::json!({ "cmd": "echo \"$(echo composed)\"" }),
            &ctx(Caveats::top()),
        )
        .await
        .expect("invoke");

    assert_ne!(out["denied"], true, "ambient grant must run: {out}");
    assert_eq!(out["exit_code"], 0, "the command must succeed: {out}");
    assert_eq!(
        out["stdout"].as_str().unwrap_or("").trim(),
        "composed",
        "the $(...) substitution must have executed in-process: {out}"
    );
    assert_eq!(
        out["disclosure"]["engine"], "brush",
        "engine identity must be disclosed: {out}"
    );
}

/// Restricted `exec` (only `echo`): an out-of-scope external is DENIED by the
/// interceptor — structured `denied:true`, `kind:"exec"` — and never runs. This
/// is the engine's differentiator: it confines a restricted exec grant that the
/// sandbox-host engine refuses to serve.
#[tokio::test]
async fn restricted_exec_denies_out_of_scope_command_in_process() {
    let caveats = Caveats {
        exec: Scope::only(["echo".to_string()]),
        ..Caveats::top()
    };
    let sentinel = unique_temp("exec-sentinel");
    let _ = std::fs::remove_file(&sentinel);
    // Path-separator form goes straight to the external-spawn funnel → before_exec.
    let cmd = format!("/bin/touch {}", sentinel.to_string_lossy());

    let out = BrushShellTool::new()
        .invoke(serde_json::json!({ "cmd": cmd }), &ctx(caveats))
        .await
        .expect("invoke");

    assert_eq!(
        out["denied"], true,
        "an out-of-scope exec must be denied by the interceptor: {out}"
    );
    assert_eq!(
        out["denials"][0]["kind"], "exec",
        "denial names exec: {out}"
    );
    assert!(
        !sentinel.exists(),
        "the denied command must not have run: {out}"
    );
}

/// Restricted `exec` (only `echo`): an in-scope command still runs.
#[tokio::test]
async fn restricted_exec_allows_in_scope_command() {
    let caveats = Caveats {
        exec: Scope::only(["echo".to_string()]),
        ..Caveats::top()
    };

    let out = BrushShellTool::new()
        .invoke(serde_json::json!({ "cmd": "echo ok" }), &ctx(caveats))
        .await
        .expect("invoke");

    assert_ne!(out["denied"], true, "in-scope command must run: {out}");
    assert_eq!(out["stdout"].as_str().unwrap_or("").trim(), "ok", "{out}");
}

/// The schema's `env` seam now reaches the shell (EPIC #1243 Leg 2). Before
/// this, brush silently DROPPED `args["env"]` — a caller var expanded to empty.
/// This is the regression guard: a passed var expands inside the confined shell.
#[tokio::test]
async fn env_seam_delivers_caller_vars_to_the_shell() {
    let out = BrushShellTool::new()
        .invoke(
            serde_json::json!({
                "cmd": "echo \"$NEWT_SEAM_PROBE\"",
                "env": { "NEWT_SEAM_PROBE": "delivered" },
            }),
            &ctx(Caveats::top()),
        )
        .await
        .expect("invoke");

    assert_ne!(out["denied"], true, "{out}");
    assert_eq!(
        out["stdout"].as_str().unwrap_or("").trim(),
        "delivered",
        "the caller-provided env var must expand in the shell (was dropped before Leg 2): {out}"
    );
}

/// FIX 1 (critical #4): a confined stdin-reader must get **immediate EOF**, not
/// the operator's terminal. Before the fix `run_in_brush` seeded `STDIN_FD` from
/// the real `std::io::stdin()`, so a bare `cat`/`wc`/`grep` with no pipe read the
/// operator's fd 0 — hanging the turn and stealing keystrokes. With `STDIN_FD`
/// backed by `/dev/null`, a bare `cat` returns promptly with empty output + EOF.
/// The `tokio::time::timeout` here is the regression teeth: on the old behavior a
/// terminal fd 0 would block `cat` forever and this test would time out.
#[cfg(unix)]
#[tokio::test]
async fn confined_stdin_reader_gets_eof_not_the_operator_terminal() {
    let cx = ctx(Caveats::top());
    let tool = BrushShellTool::new();
    // Path-separator form runs the real external `/bin/cat` (the carried-coreutils
    // `cat` shim would otherwise re-exec this non-dispatch test binary); an
    // external child inherits the shell's STDIN_FD, so this proves the null fd
    // reaches spawned children.
    let invoke = tool.invoke(serde_json::json!({ "cmd": "/bin/cat" }), &cx);
    let out = tokio::time::timeout(Duration::from_secs(10), invoke)
        .await
        .expect("a confined stdin-reader must not block on the operator terminal")
        .expect("invoke");

    assert_eq!(out["exit_code"], 0, "cat on /dev/null exits 0: {out}");
    assert_eq!(
        out["stdout"], "",
        "stdin is /dev/null → cat reads immediate EOF, empty output: {out}"
    );
}

/// HOME crosses the seam — the concrete #783-class motivation: without it,
/// `~` expansion and HOME-relative tooling misbehave under the brush engine.
/// Nothing ambient leaks in (do_not_inherit_env); only the passed value shows.
#[tokio::test]
async fn env_seam_delivers_home_for_tilde_class_tooling() {
    let out = BrushShellTool::new()
        .invoke(
            serde_json::json!({
                "cmd": "echo \"$HOME\"",
                "env": { "HOME": "/seam/home" },
            }),
            &ctx(Caveats::top()),
        )
        .await
        .expect("invoke");

    assert_eq!(
        out["stdout"].as_str().unwrap_or("").trim(),
        "/seam/home",
        "HOME must cross the import surface: {out}"
    );
}
