//! Real AppContainer **net-axis** kernel-enforcement proofs (#133, ADR 0016).
//!
//! Spawn the `ab-netprobe` helper as a confined child and assert the Windows
//! network-isolation layer:
//!   * **deny-all** (no `--net-allow`, no `--loopback-exemption`) kernel-blocks even
//!     loopback egress — the AppContainer default; and
//!   * `--loopback-exemption` (`NetworkIsolationSetAppContainerConfig`) permits
//!     loopback while off-box stays denied — the fence the egress proxy rides
//!     (ADR 0016 / #133).
//!
//! The deny-all proof needs no elevation and is deterministic (a loopback listener
//! in-process; the confined probe cannot reach it). The loopback-exemption proof
//! needs an **elevated** token (the NetworkIsolation API), so it skips when not
//! elevated — unless `BRIDLE_REQUIRE_APPCONTAINER` is set, as the (elevated) CI
//! Windows runner does.
#![cfg(target_os = "windows")]

use std::io::Write;
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

const LAUNCHER: &str = env!("CARGO_BIN_EXE_agent-bridle-aclaunch");
const NETPROBE: &str = env!("CARGO_BIN_EXE_ab-netprobe");

static N: AtomicU64 = AtomicU64::new(0);

fn tag(kind: &str) -> String {
    format!(
        "{kind}-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    )
}

/// A fresh temp dir (integrity lowered to Low; see kernel_proofs.rs for why).
fn fresh_dir(kind: &str) -> PathBuf {
    let mut d = std::env::temp_dir();
    d.push(format!("ab-net-{}", tag(kind)));
    std::fs::create_dir_all(&d).expect("create temp dir");
    let _ = Command::new("icacls")
        .arg(&d)
        .args(["/setintegritylevel", "(OI)(CI)Low"])
        .output();
    d
}

/// Copy `ab-netprobe.exe` into a fresh dir the AppContainer can be granted
/// read+execute on (the crate's `target` dir is not container-accessible), and
/// return `(probe_dir, probe_exe)`.
fn stage_probe() -> (PathBuf, PathBuf) {
    let dir = fresh_dir("probe");
    let dest = dir.join("ab-netprobe.exe");
    std::fs::copy(NETPROBE, &dest).expect("stage ab-netprobe.exe");
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
        panic!("BRIDLE_REQUIRE_APPCONTAINER is set but an AppContainer could not be created here");
    }
    eprintln!("skipping AppContainer net proof: cannot create an AppContainer here");
    true
}

/// `net session` succeeds only for an elevated (admin) token — the privilege the
/// loopback-exemption API needs.
fn elevated() -> bool {
    Command::new("net")
        .args(["session"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// A loopback TCP listener that accepts one connection (then returns). Returns the
/// ephemeral port. Runs in the parent (test) process; a confined child can only
/// reach it if the AppContainer permits loopback.
fn loopback_listener() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        if let Ok((mut s, _)) = l.accept() {
            let _ = s.write_all(b"ok");
        }
    });
    port
}

/// deny-all (#133): with no network capability and no loopback exemption, the
/// AppContainer kernel-blocks even a loopback connection.
#[test]
fn net_deny_all_kernel_blocks_loopback_egress() {
    if skip_proof_unless_appcontainer() {
        return;
    }
    let (probe_dir, probe) = stage_probe();
    let port = loopback_listener();

    // Grant read+execute on the staged probe only (so it can RUN); grant NO network.
    let out = launch(&[
        "--name",
        &tag("net-deny"),
        "--fs-read",
        &probe_dir.to_string_lossy(),
        &probe.to_string_lossy(),
        "127.0.0.1",
        &port.to_string(),
    ]);
    assert!(
        !out.status.success(),
        "AppContainer must kernel-block loopback egress with no --net-allow/--loopback-exemption; \
         probe stderr: {}",
        String::from_utf8_lossy(&out.stderr).trim()
    );

    let _ = std::fs::remove_dir_all(&probe_dir);
}

/// loopback exemption (#133, ADR 0016): with `--loopback-exemption` the confined
/// child reaches loopback (the egress-proxy fence). Needs an elevated token for the
/// NetworkIsolation API — skips when not elevated unless the boundary is required.
#[test]
fn net_loopback_exemption_permits_loopback() {
    if skip_proof_unless_appcontainer() {
        return;
    }
    let required = std::env::var("BRIDLE_REQUIRE_APPCONTAINER")
        .map(|v| !v.is_empty() && v != "0")
        .unwrap_or(false);
    if !elevated() {
        if required {
            panic!(
                "BRIDLE_REQUIRE_APPCONTAINER is set but this token is not elevated — the \
                 loopback-exemption proof needs admin (NetworkIsolationSetAppContainerConfig)"
            );
        }
        eprintln!("skipping loopback-exemption proof: not elevated (needs admin)");
        return;
    }
    let (probe_dir, probe) = stage_probe();
    let port = loopback_listener();

    let out = launch(&[
        "--name",
        &tag("net-loop"),
        "--loopback-exemption",
        "--fs-read",
        &probe_dir.to_string_lossy(),
        &probe.to_string_lossy(),
        "127.0.0.1",
        &port.to_string(),
    ]);
    assert!(
        out.status.success(),
        "with --loopback-exemption the confined child must reach loopback; probe stderr: {}",
        String::from_utf8_lossy(&out.stderr).trim()
    );

    let _ = std::fs::remove_dir_all(&probe_dir);
}
