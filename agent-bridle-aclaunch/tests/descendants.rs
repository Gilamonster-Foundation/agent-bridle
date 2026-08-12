//! Native descendant-containment proofs for Windows AppContainer.

#![cfg(target_os = "windows")]

use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

const LAUNCHER: &str = env!("CARGO_BIN_EXE_agent-bridle-aclaunch");
const TOKENPROBE: &str = env!("CARGO_BIN_EXE_ab-tokenprobe");

static N: AtomicU64 = AtomicU64::new(0);

fn tag(kind: &str) -> String {
    format!(
        "{kind}-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    )
}

fn fresh_dir(kind: &str) -> PathBuf {
    let mut d = std::env::temp_dir();
    d.push(format!("ab-desc-{}", tag(kind)));
    std::fs::create_dir_all(&d).expect("create temp dir");
    let _ = Command::new("icacls")
        .arg(&d)
        .args(["/setintegritylevel", "(OI)(CI)Low"])
        .output();
    d
}

fn stage_probe() -> (PathBuf, PathBuf) {
    let dir = fresh_dir("probe");
    let dest = dir.join("ab-tokenprobe.exe");
    std::fs::copy(TOKENPROBE, &dest).expect("stage ab-tokenprobe.exe");
    (dir, dest)
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
    eprintln!("skipping AppContainer descendant proof: cannot create AppContainer here");
    true
}

fn sids(stdout: &[u8]) -> Vec<String> {
    String::from_utf8_lossy(stdout)
        .lines()
        .filter_map(|line| line.split("appcontainer_sid=").nth(1))
        .map(str::trim)
        .map(str::to_string)
        .collect()
}

fn assert_appcontainer_identity(out: &std::process::Output, min_lines: usize, route: &str) {
    assert!(
        out.status.success(),
        "{route} must run; status={:?} stdout={} stderr={}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).trim(),
        String::from_utf8_lossy(&out.stderr).trim()
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.matches("is_appcontainer=1").count() >= min_lines,
        "{route} must report AppContainer token identity; stdout={stdout:?}"
    );
    let sids = sids(&out.stdout);
    assert!(
        sids.len() >= min_lines,
        "{route} must report AppContainer SIDs; stdout={stdout:?}"
    );
    let first = &sids[0];
    assert!(
        first.starts_with("S-1-15-2-"),
        "{route} SID must be an AppContainer SID, got {first:?}"
    );
    assert!(
        sids.iter().all(|sid| sid == first),
        "{route} descendants must keep the same AppContainer SID; sids={sids:?}"
    );
}

fn assert_route_marker(out: &std::process::Output, marker: &str, route: &str) {
    assert!(
        out.status.success(),
        "{route} must run; status={:?} stdout={} stderr={}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).trim(),
        String::from_utf8_lossy(&out.stderr).trim()
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains(marker),
        "{route} must reach its built-in marker {marker:?}; stdout={stdout:?}"
    );
}

fn assert_os_access_denied(out: &std::process::Output, route: &str) {
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !out.status.success() && text.contains("Access is denied."),
        "{route} must be OS-policy denied, not command-not-found or a missing test \
         resource; status={:?} stdout={} stderr={}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).trim(),
        String::from_utf8_lossy(&out.stderr).trim()
    );
}

fn assert_appcontainer_descendant_or_os_spawn_denial(out: &std::process::Output, route: &str) {
    assert_appcontainer_identity(out, 1, route);
    let stdout = String::from_utf8_lossy(&out.stdout);
    if stdout.contains("cmd_spawn_denied_os_policy=5") {
        assert_eq!(
            sids(&out.stdout).len(),
            1,
            "{route} must not claim a descendant identity after OS-policy denial; stdout={stdout:?}"
        );
    } else {
        assert_appcontainer_identity(out, 2, route);
    }
}

fn assert_host_descendant_control(out: &std::process::Output, route: &str) {
    assert!(
        out.status.success(),
        "{route} must run; status={:?} stdout={} stderr={}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).trim(),
        String::from_utf8_lossy(&out.stderr).trim()
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout.matches("is_appcontainer=0").count(),
        2,
        "{route} must prove both host-token generations; stdout={stdout:?}"
    );
}

#[test]
fn direct_cmd_powershell_and_helper_descendants_keep_appcontainer_identity() {
    if skip_proof_unless_appcontainer() {
        return;
    }
    let (probe_dir, probe) = stage_probe();
    let probe_s = probe.to_string_lossy();
    let probe_dir_s = probe_dir.to_string_lossy();

    let host_cmd_control = Command::new(&probe)
        .arg("spawn-cmd")
        .current_dir("C:\\Windows")
        .output()
        .expect("run host helper-to-cmd positive control");
    assert_host_descendant_control(&host_cmd_control, "host helper to cmd.exe positive control");

    let direct = launch(&[
        "--name",
        &tag("direct"),
        "--fs-read",
        &probe_dir_s,
        "--fs-read",
        &probe_s,
        &probe_s,
        "print",
    ]);
    assert_appcontainer_identity(&direct, 1, "direct helper child");

    let via_cmd = launch(&[
        "--name",
        &tag("cmd"),
        "cmd.exe",
        "/d",
        "/c",
        "echo cmd-route-ran",
    ]);
    assert_route_marker(&via_cmd, "cmd-route-ran", "cmd.exe child");

    let via_cmd_grandchild = launch(&[
        "--name",
        &tag("cmd-gc"),
        "cmd.exe",
        "/d",
        "/c",
        "cmd.exe /d /c echo cmd-grandchild-route-ran",
    ]);
    assert_route_marker(
        &via_cmd_grandchild,
        "cmd-grandchild-route-ran",
        "cmd.exe to cmd.exe grandchild",
    );

    let powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
    let via_powershell = launch(&[
        "--name",
        &tag("ps"),
        powershell,
        "-NoProfile",
        "-Command",
        "Write-Output powershell-route-ran",
    ]);
    assert_route_marker(&via_powershell, "powershell-route-ran", "PowerShell child");

    let via_powershell_grandchild = launch(&[
        "--name",
        &tag("ps-gc"),
        powershell,
        "-NoProfile",
        "-Command",
        "cmd.exe /d /c echo powershell-grandchild-route-ran",
    ]);
    assert_route_marker(
        &via_powershell_grandchild,
        "powershell-grandchild-route-ran",
        "PowerShell to cmd.exe grandchild",
    );

    let helper_grandchild = launch(&[
        "--name",
        &tag("helper"),
        "--fs-read",
        &probe_dir_s,
        "--fs-read",
        &probe_s,
        &probe_s,
        "spawn-cmd",
    ]);
    assert_appcontainer_descendant_or_os_spawn_denial(
        &helper_grandchild,
        "helper child to cmd.exe grandchild",
    );

    let helper_to_helper = launch(&[
        "--name",
        &tag("helper2"),
        "--fs-read",
        &probe_dir_s,
        "--fs-read",
        &probe_s,
        &probe_s,
        "spawn-self",
    ]);
    assert_appcontainer_identity(
        &helper_to_helper,
        2,
        "helper child to tokenprobe grandchild",
    );

    let cmd_to_helper = launch(&[
        "--name",
        &tag("cmd-helper"),
        "--fs-read",
        &probe_dir_s,
        "--fs-read",
        &probe_s,
        "cmd.exe",
        "/c",
        &probe_s,
        "print",
    ]);
    assert_os_access_denied(&cmd_to_helper, "cmd.exe to staged helper grandchild");

    let ps_command = format!("& '{}' print", probe_s.replace('\'', "''"));
    let powershell_to_helper = launch(&[
        "--name",
        &tag("ps-helper"),
        "--fs-read",
        &probe_dir_s,
        "--fs-read",
        &probe_s,
        powershell,
        "-NoProfile",
        "-Command",
        &ps_command,
    ]);
    assert_appcontainer_identity(
        &powershell_to_helper,
        1,
        "PowerShell to staged helper grandchild",
    );

    let _ = std::fs::remove_dir_all(&probe_dir);
}
