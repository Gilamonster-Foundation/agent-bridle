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

use agent_bridle_core::{Caveats, Gate, Scope, Tool, ToolContext};
use agent_bridle_tool_shell::BrushShellTool;

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
