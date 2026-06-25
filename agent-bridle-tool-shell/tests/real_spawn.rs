//! Real-spawn integration tests for the engine's `std::process` path.
//!
//! These exercise the *real* `OsSpawner` with actual processes (and, for
//! redirections, real files), and are kept out of the unit tests (which mock the
//! spawner) per the workspace norm: no real subprocesses/fs in unit tests. They
//! use only universally-present tools (`echo`, `cat`, `sort`, `true`, `false`).
#![cfg(feature = "shell")]

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

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

/// A unique temp path (pid + atomic counter, never a clock) so parallel tests do
/// not collide. The file is created/used by the test and removed at the end.
fn unique_temp(tag: &str) -> PathBuf {
    static N: AtomicU64 = AtomicU64::new(0);
    std::env::temp_dir().join(format!(
        "ab-redir-{}-{}-{}",
        tag,
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ))
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

#[tokio::test]
async fn real_stdout_redirect_truncates_then_appends_a_file() {
    let path = unique_temp("out");
    let p = path.to_string_lossy().into_owned();

    // `> file` writes (truncates).
    ShellTool::new()
        .invoke(
            serde_json::json!({"cmd": format!("echo first > {p}")}),
            &ctx(exec_only(&["echo"])),
        )
        .await
        .expect("invoke");
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "first\n");

    // `>> file` appends.
    ShellTool::new()
        .invoke(
            serde_json::json!({"cmd": format!("echo second >> {p}")}),
            &ctx(exec_only(&["echo"])),
        )
        .await
        .expect("invoke");
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "first\nsecond\n");

    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn real_stdin_redirect_feeds_a_file() {
    let path = unique_temp("in");
    std::fs::write(&path, "b\na\nc\n").unwrap();
    let p = path.to_string_lossy().into_owned();

    let out = ShellTool::new()
        .invoke(
            serde_json::json!({"cmd": format!("sort < {p}")}),
            &ctx(exec_only(&["sort"])),
        )
        .await
        .expect("invoke");
    assert_eq!(out["exit_code"], 0);
    assert_eq!(out["stdout"], "a\nb\nc\n");

    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn real_pipeline_with_stdout_redirect_on_last_stage() {
    // `echo … | cat > file` — the pipe feeds cat, whose stdout goes to the file;
    // captured stdout is empty because the last stage redirected to a file.
    let path = unique_temp("pipe");
    let p = path.to_string_lossy().into_owned();

    let out = ShellTool::new()
        .invoke(
            serde_json::json!({"cmd": format!("echo piped | cat > {p}")}),
            &ctx(exec_only(&["echo", "cat"])),
        )
        .await
        .expect("invoke");
    assert_eq!(out["exit_code"], 0);
    assert_eq!(
        out["stdout"], "",
        "last-stage redirect means empty captured stdout: {out}"
    );
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "piped\n");

    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn real_and_chain_runs_then_short_circuits() {
    // `true && echo ran` → echo runs.
    let out = ShellTool::new()
        .invoke(
            serde_json::json!({"cmd": "true && echo ran"}),
            &ctx(exec_only(&["true", "echo"])),
        )
        .await
        .expect("invoke");
    assert_eq!(out["stdout"], "ran\n");
    assert_eq!(out["exit_code"], 0);

    // `false && echo nope` → echo is skipped; exit is `false`'s.
    let out = ShellTool::new()
        .invoke(
            serde_json::json!({"cmd": "false && echo nope"}),
            &ctx(exec_only(&["false", "echo"])),
        )
        .await
        .expect("invoke");
    assert_eq!(out["stdout"], "", "echo must be skipped: {out}");
    assert_eq!(out["exit_code"], 1);
}

#[tokio::test]
async fn real_or_fallback_and_semicolon_sequence() {
    // `false || echo fallback` → fallback runs.
    let out = ShellTool::new()
        .invoke(
            serde_json::json!({"cmd": "false || echo fallback"}),
            &ctx(exec_only(&["false", "echo"])),
        )
        .await
        .expect("invoke");
    assert_eq!(out["stdout"], "fallback\n");

    // `echo a ; echo b` → both run, output concatenated in order.
    let out = ShellTool::new()
        .invoke(
            serde_json::json!({"cmd": "echo a ; echo b"}),
            &ctx(exec_only(&["echo"])),
        )
        .await
        .expect("invoke");
    assert_eq!(out["stdout"], "a\nb\n");
}

#[tokio::test]
async fn real_glob_expands_against_the_filesystem() {
    // A unique temp dir with a.rs="A", b.rs="B", c.txt="C".
    let dir = unique_temp("glob");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("a.rs"), "A").unwrap();
    std::fs::write(dir.join("b.rs"), "B").unwrap();
    std::fs::write(dir.join("c.txt"), "C").unwrap();
    let d = dir.to_string_lossy().into_owned();

    // `cat *.rs` (cwd = the temp dir) → expands to `cat a.rs b.rs` (sorted) → "AB".
    let out = ShellTool::new()
        .invoke(
            serde_json::json!({"cmd": "cat *.rs", "cwd": d}),
            &ctx(exec_only(&["cat"])),
        )
        .await
        .expect("invoke");
    assert_eq!(out["exit_code"], 0);
    assert_eq!(out["stdout"], "AB", "glob expanded + sorted: {out}");

    // No match → the literal pattern; `cat zzz*` fails (no such file).
    let out = ShellTool::new()
        .invoke(
            serde_json::json!({"cmd": "cat zzz*", "cwd": d}),
            &ctx(exec_only(&["cat"])),
        )
        .await
        .expect("invoke");
    assert_ne!(
        out["exit_code"], 0,
        "unmatched glob → literal, cat fails: {out}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn real_allowlisted_var_expands_from_the_environment() {
    // `echo $HOME` expands HOME from this process's env (the test reads the same
    // env, so the assertion is deterministic regardless of the host value).
    let expected = format!("{}\n", std::env::var("HOME").unwrap_or_default());
    let out = ShellTool::new()
        .invoke(
            serde_json::json!({"cmd": "echo $HOME"}),
            &ctx(exec_only(&["echo"])),
        )
        .await
        .expect("invoke");
    assert_eq!(out["exit_code"], 0);
    assert_eq!(
        out["stdout"], expected,
        "$HOME must expand to the env value: {out}"
    );
}
