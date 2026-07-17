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
