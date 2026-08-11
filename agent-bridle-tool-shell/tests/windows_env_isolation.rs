//! Windows env-isolation integration test (issue #323 — a Bridle-0.8 blocker).
//!
//! The real `OsSpawner` path previously cleared the ambient environment only
//! under `#[cfg(unix)]`, so on Windows a parent-only provider secret
//! (`OPENAI_API_KEY`, …) leaked all the way to the confined child through the
//! real `dispatch_bridled_shell → ShellTool → aclaunch → AppContainer` route
//! (aclaunch forwards its own environment, exactly as Seatbelt's `sandbox-exec`
//! does on macOS). This proves the leak is closed: the child starts from a fixed
//! minimal baseline plus only the delegated caller env.
//!
//! Windows-only (the Unix analog lives in `real_spawn.rs`, which is `cfg(unix)`
//! because its POSIX binaries do not ship on Windows). `cmd /c set` prints the
//! child's environment; the ambient secret must be absent from it. Real
//! subprocess (the expensive tier) — not a unit test.
#![cfg(all(windows, feature = "shell"))]

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

/// #323: a parent-process (ambient) secret NOT passed as a caller env entry must
/// not reach the confined child. Stands in for a leaked `OPENAI_API_KEY`.
#[tokio::test]
async fn windows_ambient_env_is_not_inherited() {
    // Proves the #323 contract in one confined run:
    //   child_env == minimal_platform_baseline ∪ explicitly_delegated_env
    // (NOT ambient_parent_env ∪ delegated_env).
    //
    // A parent-only ambient secret (stands in for a leaked `OPENAI_API_KEY`) that
    // is NOT delegated, and an explicitly delegated var that IS.
    std::env::set_var("AB323_AMBIENT_SECRET", "leak");
    let out = ShellTool::new()
        .invoke(
            serde_json::json!({
                "program": "cmd",
                "args": ["/c", "set"],
                // The ONLY authority the child should receive beyond the baseline.
                "env": { "AB323_GRANTED": "allowed" },
            }),
            &ctx(exec_only(&["cmd"])),
        )
        .await
        .expect("invoke");
    std::env::remove_var("AB323_AMBIENT_SECRET");
    let stdout = out["stdout"].as_str().unwrap_or_default();
    // Non-vacuity: the child actually RAN and printed its environment (the fixed
    // Windows baseline includes `SystemRoot`), so the assertions below reflect a
    // real env_clear, not a child that failed to spawn and produced no output.
    assert!(
        stdout.contains("SystemRoot="),
        "positive control: `cmd /c set` must have run and printed the baseline env:\n{stdout}"
    );
    // Negative: the ambient parent secret must NOT reach the confined child.
    assert!(
        !stdout.contains("AB323_AMBIENT_SECRET"),
        "ambient parent env must not leak into the confined Windows child:\n{stdout}"
    );
    // Positive control (#323 §1B): the explicitly delegated var MUST reach the
    // child — env isolation must not break the legitimate delegation path.
    assert!(
        stdout.contains("AB323_GRANTED=allowed"),
        "an explicitly delegated env var must still pass through to the child:\n{stdout}"
    );
}
