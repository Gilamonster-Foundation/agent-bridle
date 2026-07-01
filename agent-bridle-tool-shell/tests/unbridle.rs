//! End-to-end proof of the ADR 0018 unbridle escape hatch (I12 / #151).
//!
//! In a **dedicated test binary** so flipping the process-global unbridle marker
//! (`agent_bridle_core::set_unbridled`) cannot leak into the confinement proofs in
//! `real_spawn.rs` or the mocked unit tests (a `OnceLock` can't be un-set).
#![cfg(feature = "shell")]

use agent_bridle_core::{set_unbridled, Caveats, Gate, Scope, Tool, ToolContext};
use agent_bridle_tool_shell::ShellTool;

fn ctx(granted: Caveats) -> ToolContext {
    Gate::new(0)
        .authorize(&ShellTool::new(), &granted)
        .expect("authorize")
}

/// Unbridled: a granted program runs **natively** (no OS sandbox → `sandbox_kind`
/// None), every envelope discloses `unbridled`, and — crucially — the L2 OCAP gate
/// **still denies** an out-of-scope program (authority is kept; only the mechanism
/// is dropped, ADR 0018 D1).
#[tokio::test]
async fn unbridled_runs_native_discloses_and_still_gates_the_grant() {
    set_unbridled(); // this binary is dedicated to the unbridled posture

    // A restricted grant: only `echo` is permitted.
    let granted = Caveats {
        exec: Scope::only(["echo".to_string()]),
        ..Caveats::top()
    };

    // The granted program runs (native), reports None, and discloses unbridled.
    let out = ShellTool::new()
        .invoke(
            serde_json::json!({"program": "echo", "args": ["hi"]}),
            &ctx(granted.clone()),
        )
        .await
        .expect("invoke");
    assert_eq!(out["exit_code"], 0);
    assert_eq!(out["stdout"], "hi\n");
    assert_eq!(
        out["sandbox_kind"], "none",
        "unbridled ⇒ no OS sandbox: {out}"
    );
    assert_eq!(
        out["disclosure"]["unbridled"], true,
        "every envelope must disclose unbridled: {out}"
    );

    // The L2 OCAP gate still holds: an out-of-scope exec is denied even unbridled.
    let denied = ShellTool::new()
        .invoke(
            serde_json::json!({"program": "rm", "args": ["-rf", "/tmp/nope"]}),
            &ctx(granted),
        )
        .await
        .expect("invoke");
    assert_eq!(
        denied["denied"], true,
        "unbridle keeps the L2 grant gate — out-of-scope exec must be denied: {denied}"
    );
    assert_eq!(
        denied["disclosure"]["unbridled"], true,
        "a denied envelope discloses unbridled too: {denied}"
    );
}
