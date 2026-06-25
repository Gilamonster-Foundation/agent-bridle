//! Real-spawn integration tests for the engine's `std::process` path.
//!
//! These exercise the *real* `OsSpawner` with actual processes, and are kept out
//! of the unit tests (which mock the spawner) per the workspace norm: no real
//! subprocesses/fs in unit tests. They use only universally-present tools
//! (`echo`, `cat`, `true`, `false`).
#![cfg(feature = "shell")]

use agent_bridle_core::{Caveats, Gate, Scope, Tool, ToolContext};
use agent_bridle_tool_shell::ShellTool;

/// Mint a context the only legitimate way — through the gate.
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

#[tokio::test]
async fn real_echo_runs_and_captures_stdout() {
    let out = ShellTool::new()
        .invoke(
            serde_json::json!({"program": "echo", "args": ["hello"]}),
            &ctx(exec_only(&["echo"])),
        )
        .await
        .expect("invoke");
    assert_eq!(out["exit_code"], 0);
    assert_eq!(out["stdout"], "hello\n");
    assert!(out.get("denied").is_none());
}

#[tokio::test]
async fn real_pipeline_passes_data_between_stages() {
    // echo's stdout becomes cat's stdin; cat echoes it back.
    let out = ShellTool::new()
        .invoke(
            serde_json::json!({"cmd": "echo hello | cat"}),
            &ctx(exec_only(&["echo", "cat"])),
        )
        .await
        .expect("invoke");
    assert_eq!(out["exit_code"], 0);
    assert_eq!(out["stdout"], "hello\n");
}

#[tokio::test]
async fn real_pipeline_exit_code_is_the_last_stage() {
    // `true | false` → last stage (false) exits 1.
    let out = ShellTool::new()
        .invoke(
            serde_json::json!({"cmd": "true | false"}),
            &ctx(exec_only(&["true", "false"])),
        )
        .await
        .expect("invoke");
    assert_eq!(
        out["exit_code"], 1,
        "pipeline exit is the last stage's: {out}"
    );

    // `false | true` → last stage (true) exits 0, even though stage 1 failed.
    let out = ShellTool::new()
        .invoke(
            serde_json::json!({"cmd": "false | true"}),
            &ctx(exec_only(&["true", "false"])),
        )
        .await
        .expect("invoke");
    assert_eq!(out["exit_code"], 0, "no pipefail: {out}");
}

#[tokio::test]
async fn real_stderr_and_nonzero_exit_are_captured() {
    // `cat` of a nonexistent path writes to stderr and exits non-zero.
    let out = ShellTool::new()
        .invoke(
            serde_json::json!({"program": "cat", "args": ["/nonexistent/agent-bridle/path"]}),
            &ctx(exec_only(&["cat"])),
        )
        .await
        .expect("invoke");
    assert_ne!(
        out["exit_code"], 0,
        "cat of a missing file must fail: {out}"
    );
    assert!(
        !out["stderr"].as_str().unwrap_or("").is_empty(),
        "stderr must be captured: {out}"
    );
}

#[tokio::test]
async fn real_out_of_scope_program_is_denied_and_never_spawns() {
    // `rm` is not granted: the leash denies it before any real process starts.
    let out = ShellTool::new()
        .invoke(
            serde_json::json!({"program": "rm", "args": ["-rf", "/tmp/agent-bridle-should-not-exist"]}),
            &ctx(exec_only(&["echo"])),
        )
        .await
        .expect("invoke");
    assert_eq!(out["denied"], true);
    assert_eq!(out["denials"][0]["target"], "rm");
    assert!(out.get("exit_code").is_none(), "nothing ran: {out}");
}
