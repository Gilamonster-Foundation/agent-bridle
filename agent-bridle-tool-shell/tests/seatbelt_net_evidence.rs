//! macOS Seatbelt **real-resource** network evidence (#317 Blocker 2 grounding).
//!
//! These are NATIVE-ENFORCEMENT proofs, not policy/unit assertions: each spawns a
//! real confined child under real `/usr/bin/sandbox-exec` and adversarially
//! attempts to open sockets, with parent-side listeners and positive controls so
//! a connection *failure* cannot masquerade as a sandbox *denial*. They ground
//! the classifications `enforcement_report` makes for Seatbelt:
//!
//! * `net:none`      → Kernel: TCP, UDP, loopback, and pathname AF_UNIX all
//!   kernel-DENIED (`(deny network*)`), proven against live parent listeners.
//! * loopback-only   → Kernel: the loopback listener is REACHABLE while off-box
//!   egress stays DENIED — the exact ADR 0015 fence.
//! * remote allowlist → Advisory (below Kernel): SBPL cannot name a general host,
//!   so the witness is honestly NOT Kernel and CONFINED would refuse before spawn.
//!
//! Every enforcing case pins `sandbox_kind == "seatbelt"` so a denial is the real
//! envelope, never command-not-found or a silent downgrade.
#![cfg(all(target_os = "macos", feature = "macos-seatbelt", feature = "shell"))]

use std::io::{Read, Write};
use std::net::TcpListener;
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use agent_bridle_core::{seatbelt_is_supported, Caveats, Gate, Scope, Tool, ToolContext};
use agent_bridle_tool_shell::ShellTool;

fn ctx(granted: Caveats) -> ToolContext {
    Gate::new(0)
        .authorize(&ShellTool::new(), &granted)
        .expect("authorize")
}

fn unique_temp(tag: &str) -> PathBuf {
    static N: AtomicU64 = AtomicU64::new(0);
    std::env::temp_dir().join(format!(
        "ab-net-{}-{}-{}",
        tag,
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ))
}

/// A `python3` probe written to a temp file (read ambiently by the confined
/// child; net-only caveats leave fs/exec unrestricted so the interpreter loads —
/// isolating "does the sandbox deny this socket?" from "can python start?"). It
/// prints `OK` on a successful open/connect and `DENIED …` on a sandbox refusal.
const PROBE: &str = r#"
import socket, sys
kind, target = sys.argv[1], sys.argv[2]
try:
    if kind == "tcp":
        host, port = target.rsplit(":", 1)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(4)
        s.connect((host, int(port)))
    elif kind == "udp":
        host, port = target.rsplit(":", 1)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto(b"x", (host, int(port)))
    elif kind == "unix":
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.settimeout(4)
        s.connect(target)
    print("OK")
except (PermissionError, OSError) as e:
    print("DENIED", type(e).__name__, getattr(e, "errno", ""))
"#;

fn write_probe() -> PathBuf {
    let p = unique_temp("probe.py");
    std::fs::write(&p, PROBE).expect("write probe");
    p
}

/// A parent-side loopback TCP listener that accepts one connection and writes a
/// byte. Returns the bound port and a join handle; the OS assigns the port so
/// nothing collides under parallel runs.
fn spawn_loopback_tcp() -> (u16, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let port = listener.local_addr().unwrap().port();
    let handle = std::thread::spawn(move || {
        // Accept exactly one connection (the confined attempt or the parent's
        // unblock), write a byte, and exit.
        if let Ok((mut s, _)) = listener.accept() {
            let _ = s.write_all(b"y");
        }
    });
    (port, handle)
}

fn skip() -> bool {
    if !seatbelt_is_supported() || !std::path::Path::new("/usr/bin/python3").exists() {
        eprintln!("skipping: sandbox-exec or python3 unavailable");
        return true;
    }
    false
}

/// Run the probe under `caveats` and return (sandbox_kind, net_enforcement,
/// stdout). Uses the safe-subset ShellTool, which engages Seatbelt when a
/// governed axis is restricted.
async fn run_probe(
    caveats: Caveats,
    probe: &std::path::Path,
    kind: &str,
    target: &str,
) -> serde_json::Value {
    ShellTool::new()
        .invoke(
            serde_json::json!({
                "cmd": format!("python3 {} {} {}", probe.display(), kind, target)
            }),
            &ctx(caveats),
        )
        .await
        .expect("invoke")
}

fn net_none() -> Caveats {
    Caveats {
        net: Scope::none(),
        ..Caveats::top()
    }
}

// ── net:none — every socket family kernel-denied ─────────────────────────────

#[tokio::test]
async fn seatbelt_net_none_denies_udp() {
    if skip() {
        return;
    }
    let probe = write_probe();
    let out = run_probe(net_none(), &probe, "udp", "1.1.1.1:53").await;
    assert_eq!(out["sandbox_kind"], "seatbelt", "{out}");
    assert_eq!(out["enforcement"]["net"], "kernel", "{out}");
    assert!(
        out["stdout"]
            .as_str()
            .unwrap_or_default()
            .contains("DENIED"),
        "UDP sendto under net:none must be kernel-denied: {out}"
    );
    let _ = std::fs::remove_file(&probe);
}

#[tokio::test]
async fn seatbelt_net_none_denies_loopback_tcp_against_a_live_listener() {
    if skip() {
        return;
    }
    let probe = write_probe();
    // A REAL listener is accepting on this port: a refusal is therefore the
    // sandbox, not a missing server (the positive control is the live socket).
    let (port, handle) = spawn_loopback_tcp();
    let out = run_probe(net_none(), &probe, "tcp", &format!("127.0.0.1:{port}")).await;
    assert_eq!(out["sandbox_kind"], "seatbelt", "{out}");
    assert!(
        out["stdout"]
            .as_str()
            .unwrap_or_default()
            .contains("DENIED"),
        "loopback TCP to a LIVE listener under net:none must be kernel-denied: {out}"
    );
    // Unblock the listener (nothing connected) by connecting from the parent.
    let _ = std::net::TcpStream::connect(("127.0.0.1", port));
    let _ = handle.join();
    let _ = std::fs::remove_file(&probe);
}

#[tokio::test]
async fn seatbelt_net_none_denies_pathname_af_unix_deputy() {
    if skip() {
        return;
    }
    let probe = write_probe();
    // A host deputy on a PATHNAME AF_UNIX socket — the Linux residual, repeated.
    // On macOS `(deny network*)` governs AF_UNIX connect itself (stronger than
    // Linux, where only the fs fence bounds it). The socket path is fs-ambient
    // here (net-only caveats), so a denial is purely the NET axis.
    let sock = unique_temp("deputy.sock");
    let _ = std::fs::remove_file(&sock);
    let listener = UnixListener::bind(&sock).expect("bind unix");
    let sock_for_thread = sock.clone();
    let handle = std::thread::spawn(move || {
        if let Ok((mut s, _)) = listener.accept() {
            let _ = s.write_all(b"relayed");
        }
        let _ = sock_for_thread;
    });
    let out = run_probe(net_none(), &probe, "unix", &sock.to_string_lossy()).await;
    assert_eq!(out["sandbox_kind"], "seatbelt", "{out}");
    assert!(
        out["stdout"]
            .as_str()
            .unwrap_or_default()
            .contains("DENIED"),
        "pathname AF_UNIX connect under net:none must be kernel-denied: {out}"
    );
    // Unblock the deputy thread.
    if let Ok(mut s) = std::os::unix::net::UnixStream::connect(&sock) {
        let mut buf = [0u8; 8];
        let _ = s.read(&mut buf);
    }
    let _ = handle.join();
    let _ = std::fs::remove_file(&sock);
    let _ = std::fs::remove_file(&probe);
}

// ── loopback-only — loopback REACHABLE, off-box DENIED (same sandbox) ─────────

#[tokio::test]
async fn seatbelt_loopback_only_allows_loopback_but_denies_offbox() {
    if skip() {
        return;
    }
    let probe = write_probe();
    let loopback_only = Caveats {
        net: Scope::only(["127.0.0.1".to_string()]),
        ..Caveats::top()
    };

    // (a) loopback to a LIVE listener SUCCEEDS — the ADR 0015 loopback re-allow.
    let (port, handle) = spawn_loopback_tcp();
    let ok = run_probe(
        loopback_only.clone(),
        &probe,
        "tcp",
        &format!("127.0.0.1:{port}"),
    )
    .await;
    assert_eq!(ok["sandbox_kind"], "seatbelt", "{ok}");
    assert_eq!(
        ok["enforcement"]["net"], "kernel",
        "loopback-only is a kernel fence: {ok}"
    );
    assert!(
        ok["stdout"].as_str().unwrap_or_default().contains("OK"),
        "granted loopback must connect to a live listener: {ok}"
    );
    let _ = std::net::TcpStream::connect(("127.0.0.1", port));
    let _ = handle.join();

    // (b) off-box egress under the SAME loopback-only fence is DENIED.
    let denied = run_probe(loopback_only, &probe, "tcp", "1.1.1.1:80").await;
    assert_eq!(denied["sandbox_kind"], "seatbelt", "{denied}");
    assert!(
        denied["stdout"]
            .as_str()
            .unwrap_or_default()
            .contains("DENIED"),
        "off-box TCP under a loopback-only fence must be kernel-denied: {denied}"
    );
    let _ = std::fs::remove_file(&probe);
}

// ── remote allowlist — honestly below Kernel (SBPL cannot name a host) ────────

#[tokio::test]
async fn seatbelt_general_remote_allowlist_is_not_kernel() {
    if skip() {
        return;
    }
    // A general remote host is inexpressible in SBPL, so Bridle must NOT claim a
    // Kernel net witness for it — CONFINED would then refuse before spawn rather
    // than run under an over-claimed fence. Assert the envelope's net axis is not
    // "kernel" (it is advisory: no wrapper engages for a bare remote allowlist).
    let probe = write_probe();
    let remote = Caveats {
        net: Scope::only(["example.com".to_string()]),
        ..Caveats::top()
    };
    let out = run_probe(remote, &probe, "udp", "1.1.1.1:53").await;
    assert_ne!(
        out["enforcement"]["net"], "kernel",
        "a general remote allowlist must NOT be reported as a Kernel net witness: {out}"
    );
    let _ = std::fs::remove_file(&probe);
}
