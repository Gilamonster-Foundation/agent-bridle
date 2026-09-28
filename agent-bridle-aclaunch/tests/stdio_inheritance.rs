//! Real AppContainer proof for standard-handle delivery to a console-only child.
//!
//! Git for Windows 2.55 attempts to open the `NUL` device during startup. This
//! test separates that device-access result from the three standard handles:
//! the launcher must deliver every caller handle it has. The test records the
//! `NUL` result but deliberately does not prescribe it: device access is host
//! policy, not authority this launcher may grant or revoke.

#![cfg(target_os = "windows")]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

const LAUNCHER: &str = env!("CARGO_BIN_EXE_agent-bridle-aclaunch");
const STDIOPROBE: &str = env!("CARGO_BIN_EXE_ab-stdio-probe");

static N: AtomicU64 = AtomicU64::new(0);

fn tag(kind: &str) -> String {
    format!(
        "{kind}-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    )
}

fn fresh_dir(kind: &str) -> PathBuf {
    let mut dir = std::env::temp_dir();
    dir.push(format!("ab-stdio-{}", tag(kind)));
    std::fs::create_dir_all(&dir).expect("create stdio probe directory");
    let low = Command::new("icacls")
        .arg(&dir)
        .args(["/setintegritylevel", "(OI)(CI)Low"])
        .output()
        .expect("lower stdio probe directory integrity");
    assert!(
        low.status.success(),
        "stdio probe directory must use Low integrity; stdout={} stderr={}",
        String::from_utf8_lossy(&low.stdout).trim(),
        String::from_utf8_lossy(&low.stderr).trim()
    );
    dir
}

fn stage_probe() -> (PathBuf, PathBuf) {
    let dir = fresh_dir("probe");
    let probe = dir.join("ab-stdio-probe.exe");
    std::fs::copy(STDIOPROBE, &probe).expect("stage ab-stdio-probe.exe");
    (dir, probe)
}

/// Deliberately use `output()`: this is the same stdin/null and stdout/stderr
/// pipe shape that `git_ownership.rs` gives the launcher for Git.
fn launch(args: &[&str]) -> Output {
    Command::new(LAUNCHER)
        .args(args)
        .current_dir("C:\\Windows")
        .output()
        .expect("spawn agent-bridle-aclaunch")
}

fn run_unconfined(probe: &Path) -> Output {
    Command::new(probe)
        .current_dir("C:\\Windows")
        .output()
        .expect("spawn ab-stdio-probe directly")
}

fn appcontainer_available() -> bool {
    launch(&["--name", &tag("probe"), "cmd.exe", "/c", "exit 0"])
        .status
        .success()
}

/// `true` only on a developer host where AppContainer creation is unavailable.
/// CI sets `BRIDLE_REQUIRE_APPCONTAINER`, so this boundary cannot silently skip.
fn skip_proof_unless_appcontainer() -> bool {
    let required = std::env::var("BRIDLE_REQUIRE_APPCONTAINER")
        .map(|value| !value.is_empty() && value != "0")
        .unwrap_or(false);
    if appcontainer_available() {
        return false;
    }
    assert!(
        !required,
        "BRIDLE_REQUIRE_APPCONTAINER is set but an AppContainer could not be created"
    );
    eprintln!("skipping AppContainer stdio proof: cannot create an AppContainer here");
    true
}

#[derive(Debug)]
struct ProbeReport {
    stdin_valid: bool,
    stdout_valid: bool,
    stderr_valid: bool,
    nul_open: bool,
    nul_error: u32,
}

fn parse_bool_field(record: &str, field: &str) -> bool {
    let value = record
        .split_whitespace()
        .find_map(|part| part.strip_prefix(&format!("{field}=")))
        .unwrap_or_else(|| panic!("probe output is missing {field}: {record:?}"));
    match value {
        "true" => true,
        "false" => false,
        _ => panic!("probe emitted a non-boolean {field}={value:?}: {record:?}"),
    }
}

fn parse_u32_field(record: &str, field: &str) -> u32 {
    record
        .split_whitespace()
        .find_map(|part| part.strip_prefix(&format!("{field}=")))
        .unwrap_or_else(|| panic!("probe output is missing {field}: {record:?}"))
        .parse()
        .unwrap_or_else(|error| panic!("probe emitted an invalid {field}: {error}; {record:?}"))
}

fn report(output: &Output, route: &str) -> ProbeReport {
    assert!(
        output.status.success(),
        "{route} stdio probe must run: status={:?} stdout={} stderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout).trim(),
        String::from_utf8_lossy(&output.stderr).trim()
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    eprintln!("{route} stdio probe: {}", stdout.trim());
    ProbeReport {
        stdin_valid: parse_bool_field(&stdout, "stdin_valid"),
        stdout_valid: parse_bool_field(&stdout, "stdout_valid"),
        stderr_valid: parse_bool_field(&stdout, "stderr_valid"),
        nul_open: parse_bool_field(&stdout, "nul_open"),
        nul_error: parse_u32_field(&stdout, "nul_error"),
    }
}

fn assert_standard_handles(report: &ProbeReport, route: &str) {
    assert!(
        report.stdin_valid,
        "{route} child is missing a valid stdin handle: {report:?}"
    );
    assert!(
        report.stdout_valid,
        "{route} child is missing a valid stdout handle: {report:?}"
    );
    assert!(
        report.stderr_valid,
        "{route} child is missing a valid stderr handle: {report:?}"
    );
}

/// Regression for the suspected Git startup cause: the launcher must retain
/// all three caller standard handles. A future handle-list regression fails
/// here before it is misdiagnosed as a Git ownership or configuration failure.
#[test]
fn appcontainer_child_receives_all_caller_standard_handles() {
    if skip_proof_unless_appcontainer() {
        return;
    }

    let (probe_dir, probe) = stage_probe();
    let direct = report(&run_unconfined(&probe), "unconfined");
    assert_standard_handles(&direct, "unconfined");
    assert!(
        direct.nul_open,
        "unconfined control must be able to open NUL: {direct:?}"
    );

    let confined = report(
        &launch(&[
            "--name",
            &tag("stdio"),
            "--fs-read",
            &probe_dir.to_string_lossy(),
            &probe.to_string_lossy(),
        ]),
        "AppContainer",
    );
    assert_standard_handles(&confined, "AppContainer");
    assert_eq!(
        confined.nul_open,
        confined.nul_error == 0,
        "AppContainer NUL observation must retain the immediate Win32 result: {confined:?}"
    );
    eprintln!(
        "AppContainer NUL observation: open={} win32_error={}",
        confined.nul_open, confined.nul_error
    );

    let _ = std::fs::remove_dir_all(&probe_dir);
}
