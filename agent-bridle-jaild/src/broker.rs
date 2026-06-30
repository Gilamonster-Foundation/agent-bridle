//! Broker side of the jail (#108 / ADR 0013 D4): a privileged (root) service that
//! turns an unprivileged client's [`JailRequest`] into a kernel-confined run.
//!
//! The broker is the policy-enforcement point that holds `CAP_SYS_ADMIN`:
//!
//! 1. It **derives the rootfs from the caveats itself** (never a client-supplied
//!    plan), so a client cannot ask for arbitrary host paths in the jail.
//! 2. It enforces **program identity**: the requested program must be inside the
//!    caveats' `exec` scope, resolved to the granted on-host binary.
//! 3. It **drops to the client's uid/gid** (`SO_PEERCRED`) before `exec`, so the
//!    jailed program never runs with the broker's root — the jail confines *what
//!    exists*, the uid drop confines *what authority it runs with*.

use std::io;
use std::os::unix::io::{AsRawFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;

use agent_bridle_core::{build_rootfs_plan, Scope};

use crate::protocol::{read_frame, write_frame, JailRequest, JailResponse};

/// Apply policy to `req` and (if it passes) run it in a jail. `client` is the
/// peer's `(uid, gid)` from `SO_PEERCRED`; when `Some`, the jailed program is
/// dropped to it before `exec` (when `None`, e.g. a direct in-process call, the
/// program runs as the caller — used only by the privileged self-tests).
#[must_use]
pub fn handle_request(req: &JailRequest, client: Option<(u32, u32)>) -> JailResponse {
    let granted = match &req.caveats.exec {
        Scope::All => {
            return JailResponse::Rejected {
                reason: "exec scope is unconfined (All); a minimal-rootfs jail is meaningless"
                    .to_string(),
            }
        }
        Scope::Only(set) => set,
    };

    let name = match Path::new(&req.program).file_name().and_then(|n| n.to_str()) {
        Some(n) => n.to_string(),
        None => {
            return JailResponse::Rejected {
                reason: format!("invalid program path: {:?}", req.program),
            }
        }
    };
    if !granted.contains(&name) {
        return JailResponse::Rejected {
            reason: format!("program `{name}` is not in the exec scope"),
        };
    }

    let plan = match build_rootfs_plan(&req.caveats) {
        Ok(p) => p,
        Err(e) => {
            return JailResponse::Rejected {
                reason: format!("rootfs plan: {e}"),
            }
        }
    };

    let abs = plan
        .entries
        .iter()
        .find(|e| !e.is_dir && e.src.file_name().and_then(|n| n.to_str()) == Some(name.as_str()))
        .map(|e| e.src.clone());
    let abs = match abs {
        Some(a) => a,
        None => {
            return JailResponse::Rejected {
                reason: format!("granted program `{name}` not found on host"),
            }
        }
    };

    let run = match client {
        Some((uid, gid)) => crate::run_jailed_as(&plan, &abs, &req.args, uid, gid),
        None => crate::run_jailed(&plan, &abs, &req.args),
    };
    match run {
        Ok(r) => JailResponse::Ran {
            code: r.status.code(),
            stdout: r.stdout,
            stderr: r.stderr,
        },
        Err(e) => JailResponse::Rejected {
            reason: format!("jail execution failed: {e}"),
        },
    }
}

/// The connected peer's `(uid, gid)` via `SO_PEERCRED`.
pub fn peer_cred(fd: RawFd) -> io::Result<(u32, u32)> {
    // SAFETY: getsockopt fills a correctly-sized `ucred` for SO_PEERCRED on a
    // connected AF_UNIX socket; we pass its size and check the return code.
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut cred as *mut libc::ucred).cast(),
            &mut len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((cred.uid, cred.gid))
}

/// Handle one client connection: read a request, run policy, write the reply.
pub fn handle_connection(stream: &mut UnixStream) {
    let cred = peer_cred(stream.as_raw_fd()).ok();
    let resp = match read_frame(stream) {
        Ok(bytes) => match serde_json::from_slice::<JailRequest>(&bytes) {
            Ok(req) => handle_request(&req, cred),
            Err(e) => JailResponse::Rejected {
                reason: format!("malformed request: {e}"),
            },
        },
        Err(e) => JailResponse::Rejected {
            reason: format!("read error: {e}"),
        },
    };
    if let Ok(bytes) = serde_json::to_vec(&resp) {
        let _ = write_frame(stream, &bytes);
    }
}

/// Serve connections until the listener errors. One request per connection.
pub fn serve(listener: &UnixListener) -> io::Result<()> {
    for conn in listener.incoming() {
        let mut stream = conn?;
        handle_connection(&mut stream);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_bridle_core::{Caveats, Scope};

    fn unique(tag: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let mut d = std::env::temp_dir();
        d.push(format!(
            "agent-bridle-broker-{}-{}-{}",
            tag,
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        d
    }

    /// Non-privileged (CI): an unconfined `exec` scope is refused before any
    /// privileged work — a minimal-rootfs jail is meaningless when any program
    /// may run.
    #[test]
    fn rejects_unconfined_exec() {
        let req = JailRequest {
            caveats: Caveats::top(), // exec: All
            program: "cat".to_string(),
            args: vec![],
        };
        match handle_request(&req, None) {
            JailResponse::Rejected { reason } => assert!(reason.contains("unconfined"), "{reason}"),
            other => panic!("expected Rejected, got {other:?}"),
        }
    }

    /// Non-privileged (CI): a program outside the `exec` scope is refused before
    /// any privileged work (program-identity enforcement at the policy layer).
    #[test]
    fn rejects_ungranted_program() {
        let req = JailRequest {
            caveats: Caveats {
                exec: Scope::only(["cat".to_string()]),
                ..Caveats::top()
            },
            program: "sh".to_string(),
            args: vec!["-c".to_string(), "echo escaped".to_string()],
        };
        match handle_request(&req, None) {
            JailResponse::Rejected { reason } => {
                assert!(reason.contains("not in the exec scope"), "{reason}")
            }
            other => panic!("expected Rejected, got {other:?}"),
        }
    }

    /// ADR 0013 D4 (#108), root-only: the broker runs a granted program in the
    /// jail **dropped to an unprivileged uid** and returns its output.
    #[test]
    #[ignore = "requires CAP_SYS_ADMIN; run via scripts/jail-dev.sh"]
    fn broker_runs_granted_program_dropped_to_unprivileged_uid() {
        assert!(crate::is_root(), "run as root via scripts/jail-dev.sh");
        let work = unique("run");
        std::fs::create_dir_all(&work).unwrap();
        std::fs::write(work.join("hello"), b"hi\n").unwrap();

        let req = JailRequest {
            caveats: Caveats {
                exec: Scope::only(["cat".to_string()]),
                fs_read: Scope::only([work.to_string_lossy().into_owned()]),
                fs_write: Scope::only([work.to_string_lossy().into_owned()]),
                ..Caveats::top()
            },
            program: "cat".to_string(),
            args: vec![work.join("hello").to_string_lossy().into_owned()],
        };

        // Drop to `nobody` (65534): the jailed program must run unprivileged, not
        // as the broker's root.
        match handle_request(&req, Some((65534, 65534))) {
            JailResponse::Ran {
                code,
                stdout,
                stderr,
            } => {
                assert_eq!(
                    code,
                    Some(0),
                    "stderr: {}",
                    String::from_utf8_lossy(&stderr)
                );
                assert_eq!(stdout, b"hi\n");
            }
            JailResponse::Rejected { reason } => panic!("unexpected rejection: {reason}"),
        }
        let _ = std::fs::remove_dir_all(&work);
    }

    /// ADR 0013 D4 (#108), root-only: a full socket round-trip — broker on a Unix
    /// socket, client request, jailed run, reply.
    #[test]
    #[ignore = "requires CAP_SYS_ADMIN; run via scripts/jail-dev.sh"]
    fn socket_round_trip_runs_granted_program() {
        assert!(crate::is_root(), "run as root via scripts/jail-dev.sh");
        let work = unique("sock-work");
        std::fs::create_dir_all(&work).unwrap();
        std::fs::write(work.join("hello"), b"socket\n").unwrap();
        let sock = unique("sock");
        let _ = std::fs::remove_file(&sock);

        let listener = UnixListener::bind(&sock).expect("bind");
        let server = std::thread::spawn(move || {
            if let Some(conn) = listener.incoming().next() {
                let mut stream = conn.expect("accept");
                handle_connection(&mut stream);
            }
        });

        let req = JailRequest {
            caveats: Caveats {
                exec: Scope::only(["cat".to_string()]),
                fs_read: Scope::only([work.to_string_lossy().into_owned()]),
                ..Caveats::top()
            },
            program: "cat".to_string(),
            args: vec![work.join("hello").to_string_lossy().into_owned()],
        };
        let resp = crate::request_jailed(&sock, &req).expect("client round-trip");
        server.join().expect("server thread");

        match resp {
            JailResponse::Ran { code, stdout, .. } => {
                assert_eq!(code, Some(0));
                assert_eq!(stdout, b"socket\n");
            }
            JailResponse::Rejected { reason } => panic!("unexpected rejection: {reason}"),
        }
        let _ = std::fs::remove_dir_all(&work);
        let _ = std::fs::remove_file(&sock);
    }
}
