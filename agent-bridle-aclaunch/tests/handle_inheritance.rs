//! Real AppContainer proof for agent-bridle#319: an intentionally inheritable
//! HANDLE held by the launcher must not be ambiently delegated to the confined
//! child. Stdio remains delegated; outside-authority canary handles do not.

#![cfg(target_os = "windows")]

use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

const LAUNCHER: &str = env!("CARGO_BIN_EXE_agent-bridle-aclaunch");
const HANDLEPROBE: &str = env!("CARGO_BIN_EXE_ab-handleprobe");

static N: AtomicU64 = AtomicU64::new(0);
const STATUS_INVALID_HANDLE: i32 = -1_073_741_816;

fn tag(kind: &str) -> String {
    format!(
        "{kind}-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    )
}

fn fresh_dir(kind: &str) -> PathBuf {
    let mut d = std::env::temp_dir();
    d.push(format!("ab-handle-{}", tag(kind)));
    std::fs::create_dir_all(&d).expect("create temp dir");
    let _ = Command::new("icacls")
        .arg(&d)
        .args(["/setintegritylevel", "(OI)(CI)Low"])
        .output();
    d
}

fn stage_probe() -> (PathBuf, PathBuf) {
    let dir = fresh_dir("probe");
    let dest = dir.join("ab-handleprobe.exe");
    std::fs::copy(HANDLEPROBE, &dest).expect("stage ab-handleprobe.exe");
    (dir, dest)
}

fn launch(args: &[&str]) -> std::process::Output {
    Command::new(LAUNCHER)
        .args(args)
        .current_dir("C:\\Windows")
        .output()
        .expect("spawn agent-bridle-aclaunch")
}

fn assert_probe_saw_non_delegated_handle(out: &std::process::Output, kind: &str) {
    if out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("HANDLE_WRITE_DENIED") && stderr.contains(&format!("kind={kind}")),
            "proof must observe {kind} HANDLE denial, not a silent no-op; status={:?} \
             stdout={} stderr={}",
            out.status.code(),
            String::from_utf8_lossy(&out.stdout).trim(),
            stderr.trim()
        );
        return;
    }
    assert_eq!(
        out.status.code(),
        Some(STATUS_INVALID_HANDLE),
        "{kind} handle probe must either report HANDLE_WRITE_DENIED or terminate with \
         STATUS_INVALID_HANDLE. status={:?} stdout={} stderr={}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).trim(),
        String::from_utf8_lossy(&out.stderr).trim()
    );
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
    eprintln!("skipping AppContainer handle proof: cannot create an AppContainer here");
    true
}

#[test]
fn inheritable_outside_file_handle_is_not_delegated_to_confined_child() {
    if skip_proof_unless_appcontainer() {
        return;
    }

    let (probe_dir, probe) = stage_probe();
    let outside_dir = fresh_dir("outside-file");
    let outside = outside_dir.join("outside.txt");
    std::fs::write(&outside, "ORIG\n").expect("seed outside file");

    let out = launch(&[
        "--name",
        &tag("hfile"),
        "--test-inheritable-file-handle",
        &outside.to_string_lossy(),
        "--fs-read",
        &probe_dir.to_string_lossy(),
        &probe.to_string_lossy(),
    ]);

    let outside_text = std::fs::read_to_string(&outside).expect("read canary file");
    assert_probe_saw_non_delegated_handle(&out, "file");
    assert!(
        !outside_text.contains("LEAKED_FILE_HANDLE"),
        "confined child wrote through an ambient inherited outside-file HANDLE; \
         status={:?} stdout={} stderr={}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).trim(),
        String::from_utf8_lossy(&out.stderr).trim()
    );

    let _ = std::fs::remove_dir_all(&probe_dir);
    let _ = std::fs::remove_dir_all(&outside_dir);
}

#[test]
fn inheritable_pipe_handle_is_not_delegated_to_confined_child() {
    if skip_proof_unless_appcontainer() {
        return;
    }

    let (probe_dir, probe) = stage_probe();
    let out = launch(&[
        "--name",
        &tag("hpipe"),
        "--test-inheritable-pipe-handle",
        "--fs-read",
        &probe_dir.to_string_lossy(),
        &probe.to_string_lossy(),
    ]);

    assert_probe_saw_non_delegated_handle(&out, "pipe");

    let _ = std::fs::remove_dir_all(&probe_dir);
}
