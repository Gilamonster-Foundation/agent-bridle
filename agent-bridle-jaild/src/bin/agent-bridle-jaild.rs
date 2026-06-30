//! `agent-bridle-jaild` — the privileged jail broker daemon (#108 / ADR 0013 D4).
//!
//! Runs as root (typically a systemd service), listens on a Unix socket, and
//! serves [`agent_bridle_jaild::JailRequest`]s: it derives a minimal rootfs from
//! each request's caveats, enforces program identity, and runs the program in a
//! mount-namespace jail dropped to the client's uid.
//!
//! Usage: `agent-bridle-jaild [SOCKET_PATH]` (default `/run/agent-bridle-jaild.sock`;
//! also read from `$BRIDLE_JAILD_SOCKET`).

use std::process::ExitCode;

fn main() -> ExitCode {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::PermissionsExt;
        use std::os::unix::net::UnixListener;

        let path = std::env::args()
            .nth(1)
            .or_else(|| std::env::var("BRIDLE_JAILD_SOCKET").ok())
            .unwrap_or_else(|| "/run/agent-bridle-jaild.sock".to_string());

        if !agent_bridle_jaild::is_root() {
            eprintln!("agent-bridle-jaild: must run as root (CAP_SYS_ADMIN) to build jails");
            return ExitCode::FAILURE;
        }

        // Replace any stale socket from a previous run.
        let _ = std::fs::remove_file(&path);
        let listener = match UnixListener::bind(&path) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("agent-bridle-jaild: cannot bind {path}: {e}");
                return ExitCode::FAILURE;
            }
        };
        // 0660: the owning user/group may submit jobs; the world may not. Deployment
        // assigns the socket's group to the agent's group (out of scope here).
        if let Err(e) = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o660)) {
            eprintln!("agent-bridle-jaild: cannot set socket perms on {path}: {e}");
            return ExitCode::FAILURE;
        }

        eprintln!("agent-bridle-jaild: listening on {path}");
        if let Err(e) = agent_bridle_jaild::serve(&listener) {
            eprintln!("agent-bridle-jaild: serve error: {e}");
            return ExitCode::FAILURE;
        }
        ExitCode::SUCCESS
    }
    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("agent-bridle-jaild is Linux-only (mount namespaces + pivot_root)");
        ExitCode::FAILURE
    }
}
