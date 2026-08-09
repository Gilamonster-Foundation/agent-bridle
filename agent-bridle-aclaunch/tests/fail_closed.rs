//! Native fail-closed proofs for Windows AppContainer launcher degradation.
//!
//! A restricted axis whose enforcement witness cannot be installed must refuse
//! before the hostile command starts. These tests use stdout as the side-effect
//! marker, so the child does not need any filesystem grant to reveal a spawn.

#![cfg(target_os = "windows")]

use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

const LAUNCHER: &str = env!("CARGO_BIN_EXE_agent-bridle-aclaunch");
const STARTED: &str = "HOSTILE_STARTED";

static N: AtomicU64 = AtomicU64::new(0);

fn tag(kind: &str) -> String {
    format!(
        "{kind}-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    )
}

fn launch(args: &[&str]) -> std::process::Output {
    Command::new(LAUNCHER)
        .args(args)
        .current_dir("C:\\Windows")
        .output()
        .expect("spawn agent-bridle-aclaunch")
}

fn appcontainer_available() -> bool {
    launch(&["--name", &tag("probe"), "cmd.exe", "/c", "exit 0"])
        .status
        .success()
}

fn skip_proof_unless_appcontainer() -> bool {
    let required = std::env::var("BRIDLE_REQUIRE_APPCONTAINER")
        .map(|v| !v.is_empty() && v != "0")
        .unwrap_or(false);
    if appcontainer_available() {
        return false;
    }
    if required {
        panic!("BRIDLE_REQUIRE_APPCONTAINER is set but AppContainer could not be created");
    }
    eprintln!("skipping AppContainer fail-closed proof: cannot create AppContainer here");
    true
}

fn missing_path(kind: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!("ab-missing-{}", tag(kind)));
    path.push("does-not-exist");
    path
}

fn assert_refused_before_spawn(out: &std::process::Output, expected_stderr: &str) {
    assert!(
        !out.status.success(),
        "launcher must fail when the enforcement witness is unavailable"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.contains(STARTED),
        "hostile child must not start when the enforcement witness is unavailable; stdout={stdout:?}"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains(expected_stderr),
        "stderr must identify the failed enforcement witness, expected {expected_stderr:?}; \
         stderr={stderr:?}"
    );
}

#[test]
fn profile_creation_failure_refuses_before_spawn() {
    if skip_proof_unless_appcontainer() {
        return;
    }

    let out = launch(&["--name", "", "cmd.exe", "/c", "echo", STARTED]);
    assert_refused_before_spawn(&out, "CreateAppContainerProfile");
}

#[test]
fn acl_grant_failure_refuses_before_spawn() {
    if skip_proof_unless_appcontainer() {
        return;
    }

    let missing = missing_path("acl");
    let out = launch(&[
        "--name",
        &tag("acl"),
        "--fs-write",
        &missing.to_string_lossy(),
        "cmd.exe",
        "/c",
        "echo",
        STARTED,
    ]);
    assert_refused_before_spawn(&out, "could not grant write access");
}

#[test]
fn process_attribute_failure_refuses_before_spawn() {
    if skip_proof_unless_appcontainer() {
        return;
    }

    let out = launch(&[
        "--name",
        &tag("attr"),
        "--test-force-process-attribute-failure",
        "cmd.exe",
        "/c",
        "echo",
        STARTED,
    ]);
    assert_refused_before_spawn(&out, "process-attribute failure");
}
