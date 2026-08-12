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

use std::net::{TcpListener, UdpSocket};
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

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

fn tcp_listener(bind: &str) -> Option<(String, u16, mpsc::Receiver<()>)> {
    let l = TcpListener::bind(bind).ok()?;
    let addr = l.local_addr().ok()?;
    let host = addr.ip().to_string();
    let port = addr.port();
    l.set_nonblocking(true)
        .expect("set TCP listener nonblocking");
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            match l.accept() {
                Ok((_s, _)) => {
                    let _ = tx.send(());
                    return;
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(_) => return,
            }
        }
    });
    Some((host, port, rx))
}

fn udp_socket(bind: &str) -> Option<UdpSocket> {
    let sock = UdpSocket::bind(bind).ok()?;
    sock.set_read_timeout(Some(Duration::from_millis(500)))
        .expect("set UDP read timeout");
    Some(sock)
}

fn local_non_loopback_ipv4() -> Option<String> {
    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    // UDP connect only asks the routing table which source address would be used;
    // it sends no packet, so this is not an Internet dependency.
    sock.connect("8.8.8.8:80").ok()?;
    let ip = sock.local_addr().ok()?.ip();
    (ip.is_ipv4() && !ip.is_loopback() && !ip.is_unspecified()).then(|| ip.to_string())
}

fn assert_unconfined_tcp_positive_control(host: &str, port: u16, rx: mpsc::Receiver<()>) {
    let out = Command::new(NETPROBE)
        .args(["tcp", host, &port.to_string()])
        .output()
        .expect("spawn unconfined ab-netprobe tcp");
    assert!(
        out.status.success(),
        "positive control: unconfined TCP probe must connect to live listener; stderr={}",
        String::from_utf8_lossy(&out.stderr).trim()
    );
    rx.recv_timeout(Duration::from_secs(2))
        .expect("positive-control TCP listener must observe the connection");
}

fn assert_unconfined_udp_positive_control(host: &str, sock: &UdpSocket) {
    let port = sock.local_addr().unwrap().port();
    let out = Command::new(NETPROBE)
        .args(["udp", host, &port.to_string()])
        .output()
        .expect("spawn unconfined ab-netprobe udp");
    assert!(
        out.status.success(),
        "positive control: unconfined UDP probe must send to listener; stderr={}",
        String::from_utf8_lossy(&out.stderr).trim()
    );
    let mut buf = [0_u8; 16];
    let (n, _) = sock
        .recv_from(&mut buf)
        .expect("positive-control UDP listener must receive datagram");
    assert_eq!(&buf[..n], b"ping");
}

fn assert_tcp_probe_failed(out: &std::process::Output, route: &str) {
    assert!(
        !out.status.success(),
        "{route}: AppContainer must deny TCP egress; status={:?} stdout={} stderr={}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).trim(),
        String::from_utf8_lossy(&out.stderr).trim()
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("ab-netprobe: tcp"),
        "{route}: failed result must come from the TCP proof helper, not a missing \
         command or unrelated launcher failure; stderr={stderr:?}"
    );
}

fn launch_owned(args: &[String]) -> std::process::Output {
    Command::new(LAUNCHER)
        .args(args)
        .current_dir("C:\\Windows")
        .output()
        .expect("spawn agent-bridle-aclaunch")
}

fn confined_tcp_probe(
    probe_dir: &std::path::Path,
    probe: &std::path::Path,
    tag_kind: String,
    host: &str,
    port: u16,
) -> std::process::Output {
    let mut args = vec!["--name".to_string(), tag_kind];
    args.extend([
        "--fs-read".to_string(),
        probe_dir.to_string_lossy().into_owned(),
        probe.to_string_lossy().into_owned(),
        "tcp".to_string(),
        host.to_string(),
        port.to_string(),
    ]);
    launch_owned(&args)
}

fn confined_udp_probe(
    probe_dir: &std::path::Path,
    probe: &std::path::Path,
    tag_kind: String,
    host: &str,
    port: u16,
) -> std::process::Output {
    let mut args = vec!["--name".to_string(), tag_kind];
    args.extend([
        "--fs-read".to_string(),
        probe_dir.to_string_lossy().into_owned(),
        probe.to_string_lossy().into_owned(),
        "udp".to_string(),
        host.to_string(),
        port.to_string(),
    ]);
    launch_owned(&args)
}

/// deny-all (#133): with no network capability and no loopback exemption, the
/// AppContainer kernel-blocks even a loopback connection.
#[test]
fn net_deny_all_kernel_blocks_loopback_egress() {
    if skip_proof_unless_appcontainer() {
        return;
    }
    let (probe_dir, probe) = stage_probe();
    let (control_host, control_port, control_rx) =
        tcp_listener("127.0.0.1:0").expect("bind loopback TCP control listener");
    assert_unconfined_tcp_positive_control(&control_host, control_port, control_rx);

    let (host, port, rx) = tcp_listener("127.0.0.1:0").expect("bind loopback TCP listener");

    // Grant read+execute on the staged probe only (so it can RUN); grant NO network.
    let out = confined_tcp_probe(&probe_dir, &probe, tag("net-deny"), &host, port);
    assert_tcp_probe_failed(&out, "TCP loopback deny-all");
    assert!(
        rx.recv_timeout(Duration::from_millis(700)).is_err(),
        "sandboxed TCP loopback connection must not reach the live listener"
    );

    let _ = std::fs::remove_dir_all(&probe_dir);
}

/// deny-all (#133): UDP loopback is denied too. A live parent listener and an
/// unconfined positive control distinguish AppContainer policy from an absent
/// server or broken probe.
#[test]
fn net_deny_all_kernel_blocks_udp_loopback_egress() {
    if skip_proof_unless_appcontainer() {
        return;
    }
    let (probe_dir, probe) = stage_probe();
    let sock = udp_socket("127.0.0.1:0").expect("bind IPv4 UDP loopback");
    assert_unconfined_udp_positive_control("127.0.0.1", &sock);
    let port = sock.local_addr().unwrap().port();

    let out = launch(&[
        "--name",
        &tag("udp-deny"),
        "--fs-read",
        &probe_dir.to_string_lossy(),
        &probe.to_string_lossy(),
        "udp",
        "127.0.0.1",
        &port.to_string(),
    ]);
    let mut buf = [0_u8; 16];
    assert!(
        sock.recv_from(&mut buf).is_err(),
        "confined UDP probe must not reach the positive-control listener; status={:?} \
         stdout={} stderr={}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).trim(),
        String::from_utf8_lossy(&out.stderr).trim()
    );

    let _ = std::fs::remove_dir_all(&probe_dir);
}

/// IPv6 loopback is part of the same deny-all network surface when available.
#[test]
fn net_deny_all_kernel_blocks_ipv6_loopback_egress() {
    if skip_proof_unless_appcontainer() {
        return;
    }
    let Some(sock) = udp_socket("[::1]:0") else {
        eprintln!("skipping IPv6 UDP loopback proof: ::1 unavailable on this host");
        return;
    };
    let (probe_dir, probe) = stage_probe();
    assert_unconfined_udp_positive_control("::1", &sock);
    let port = sock.local_addr().unwrap().port();

    let out = launch(&[
        "--name",
        &tag("udp6-deny"),
        "--fs-read",
        &probe_dir.to_string_lossy(),
        &probe.to_string_lossy(),
        "udp",
        "::1",
        &port.to_string(),
    ]);
    let mut buf = [0_u8; 16];
    assert!(
        sock.recv_from(&mut buf).is_err(),
        "confined IPv6 UDP probe must not reach the positive-control listener; status={:?} \
         stdout={} stderr={}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).trim(),
        String::from_utf8_lossy(&out.stderr).trim()
    );

    let _ = std::fs::remove_dir_all(&probe_dir);
}

#[test]
fn net_deny_all_kernel_blocks_tcp_to_non_loopback_local_interface() {
    if skip_proof_unless_appcontainer() {
        return;
    }
    let local_ip = local_non_loopback_ipv4()
        .expect("proof host must have a non-loopback IPv4 address for off-box direct evidence");
    let (probe_dir, probe) = stage_probe();

    let (control_host, control_port, control_rx) =
        tcp_listener(&format!("{local_ip}:0")).expect("bind local-interface TCP control");
    assert_unconfined_tcp_positive_control(&control_host, control_port, control_rx);

    let (host, port, rx) =
        tcp_listener(&format!("{local_ip}:0")).expect("bind local-interface TCP");
    let out = confined_tcp_probe(&probe_dir, &probe, tag("tcp-offbox-deny"), &host, port);
    assert_tcp_probe_failed(&out, "TCP non-loopback local-interface deny-all");
    assert!(
        rx.recv_timeout(Duration::from_millis(700)).is_err(),
        "sandboxed TCP non-loopback connection must not reach the live listener"
    );

    let _ = std::fs::remove_dir_all(&probe_dir);
}

#[test]
fn net_deny_all_blocks_udp_to_non_loopback_local_interface() {
    if skip_proof_unless_appcontainer() {
        return;
    }
    let local_ip = local_non_loopback_ipv4()
        .expect("proof host must have a non-loopback IPv4 address for off-box direct evidence");
    let (probe_dir, probe) = stage_probe();
    let sock = udp_socket(&format!("{local_ip}:0")).expect("bind local-interface UDP");
    assert_unconfined_udp_positive_control(&local_ip, &sock);
    let port = sock.local_addr().unwrap().port();

    let out = confined_udp_probe(&probe_dir, &probe, tag("udp-offbox-deny"), &local_ip, port);
    let mut buf = [0_u8; 16];
    assert!(
        sock.recv_from(&mut buf).is_err(),
        "confined UDP non-loopback probe must not reach the positive-control listener; \
         status={:?} stdout={} stderr={}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).trim(),
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
    // Elevation is a *separate* requirement from "AppContainer must work": a normal
    // dev host (non-elevated) can run every other proof but not this one. So the
    // hard-require is its own flag, BRIDLE_REQUIRE_ELEVATED, which the (elevated) CI
    // runner sets — `just check-windows` on a non-elevated box skips this gracefully.
    let require_elevated = std::env::var("BRIDLE_REQUIRE_ELEVATED")
        .map(|v| !v.is_empty() && v != "0")
        .unwrap_or(false);
    if !elevated() {
        if require_elevated {
            panic!(
                "BRIDLE_REQUIRE_ELEVATED is set but this token is not elevated — the \
                 loopback-exemption proof needs admin (NetworkIsolationSetAppContainerConfig)"
            );
        }
        eprintln!("skipping loopback-exemption proof: not elevated (needs admin)");
        return;
    }
    let (probe_dir, probe) = stage_probe();
    let (host, port, rx) = tcp_listener("127.0.0.1:0").expect("bind loopback TCP listener");

    let out = launch(&[
        "--name",
        &tag("net-loop"),
        "--loopback-exemption",
        "--fs-read",
        &probe_dir.to_string_lossy(),
        &probe.to_string_lossy(),
        &host,
        &port.to_string(),
    ]);
    assert!(
        out.status.success(),
        "with --loopback-exemption the confined child must reach loopback; probe stderr: {}",
        String::from_utf8_lossy(&out.stderr).trim()
    );
    rx.recv_timeout(Duration::from_secs(2))
        .expect("loopback-exemption proof must reach the live listener");

    let _ = std::fs::remove_dir_all(&probe_dir);
}
