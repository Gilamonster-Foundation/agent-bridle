//! Close *ambient* file descriptors on a confined spawn (agent-bridle#319).
//!
//! An already-open descriptor is itself an object capability. A confined child
//! must obtain resources only by inheriting the descriptors it was *delegated*
//! (its stdio), never by inheriting descriptors the parent happened to leave
//! open. `std::process::Command` relies on the platform CLOEXEC convention, but a
//! descriptor the parent opened with `CLOEXEC` cleared **is inherited** across
//! `exec` — a real capability leak (proven by
//! `agent-bridle-tool-shell/tests/real_spawn.rs::real_ambient_fd_is_not_inherited`).
//!
//! This crate is the single `unsafe`-permitting seam that lets
//! `agent-bridle-core` keep `#![forbid(unsafe_code)]` (ADR 0026, slice-1
//! decision): it installs an async-signal-safe `pre_exec` hook that marks every
//! descriptor `>= 3` **close-on-exec** (`close_range` with `CLOSE_RANGE_CLOEXEC`),
//! so the kernel closes them atomically at `exec`, preserving stdio (`0`/`1`/`2`).
//!
//! Marking-then-exec — rather than closing the range *immediately* in the child —
//! is deliberate: `std::process::Command` keeps its own `CLOEXEC` pipe (also a
//! descriptor `>= 3`) open across the `pre_exec → exec` window to report an `exec`
//! failure back to the parent. Closing that pipe early makes a failed spawn (a
//! missing or non-executable program) surface as a bogus `Ok` — the child dies by
//! `SIGABRT` and the parent reads the early EOF as success — instead of the
//! correct `io::Error`. `CLOSE_RANGE_CLOEXEC` leaves the pipe to close itself at
//! `exec`, so exec failures are reported faithfully while ambient descriptors
//! still never reach the confined child. The one `unsafe` block is documented and
//! encapsulated here, so callers invoke a **safe** function.
//!
//! ## Platform scope
//!
//! Enforcement is **Linux-only** for now (`close_range(2)` with
//! `CLOSE_RANGE_CLOEXEC`, kernel ≥ 5.11 — the only child-safe, race-free
//! primitive; enumerating `/proc/self/fd` in the fork child would not be
//! async-signal-safe). On every other platform
//! [`deny_inherited_fds`] is a no-op and the CLOEXEC-convention residual remains
//! (macOS/Windows fd-hygiene is tracked as a follow-up in the POSIX briefs).
//!
//! ## Fail-closed
//!
//! If `close_range` fails at spawn time, the pre-exec hook returns an error, so
//! `Command::spawn` fails and the child never runs: a confined child never
//! executes with unclosed ambient descriptors.

/// Install a pre-exec step that marks every inherited descriptor `>= 3`
/// close-on-exec, so the kernel closes them at `exec` in the child while
/// preserving stdio.
///
/// Safe to call: the installed closure invokes only `close_range`, which is
/// async-signal-safe, so this satisfies [`CommandExt::pre_exec`]'s contract on
/// the caller's behalf. See the crate docs for platform scope and fail-closed
/// behavior.
///
/// [`CommandExt::pre_exec`]: std::os::unix::process::CommandExt::pre_exec
#[cfg(target_os = "linux")]
pub fn deny_inherited_fds(cmd: &mut std::process::Command) {
    use std::os::unix::process::CommandExt;

    // SAFETY: the closure runs in the forked child after `fork` and before
    // `exec`. It calls only `close_range` — an async-signal-safe syscall — and
    // `io::Error::last_os_error` (a `read` of `errno`, itself async-signal-safe);
    // it allocates nothing, takes no locks, and returns promptly, satisfying
    // `pre_exec`'s async-signal-safety contract. Rust's `Command` performs its
    // stdio `dup2` onto fds 0/1/2 *before* running pre-exec hooks, so the range
    // `[3, U32::MAX]` covers only ambient descriptors and never the child's
    // delegated stdio. `CLOSE_RANGE_CLOEXEC` marks that range close-on-exec rather
    // than closing it immediately, so std's own `CLOEXEC` exec-status pipe (also a
    // descriptor `>= 3`) survives to report an `exec` failure; every marked fd
    // still closes atomically at `exec`, so the confined child never inherits one.
    unsafe {
        cmd.pre_exec(|| {
            // close_range(first=3, last=U32::MAX, CLOSE_RANGE_CLOEXEC): mark every
            // fd >= 3 close-on-exec; the kernel closes them atomically at `exec`.
            let rc = libc::close_range(
                3,
                libc::c_uint::MAX,
                libc::CLOSE_RANGE_CLOEXEC as libc::c_int,
            );
            if rc != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

/// No-op on non-Linux platforms: enforcement is Linux-only for now and the
/// CLOEXEC-convention residual remains elsewhere (see the crate docs).
#[cfg(not(target_os = "linux"))]
pub fn deny_inherited_fds(_cmd: &mut std::process::Command) {}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::os::fd::AsRawFd;
    use std::process::{Command, Stdio};

    /// The seam closes an ambient (CLOEXEC-cleared) descriptor in the child while
    /// preserving stdio. Regression for agent-bridle#319 at the crate boundary
    /// (the tool-shell integration test proves it end-to-end through ShellTool).
    #[test]
    fn deny_inherited_fds_closes_ambient_but_keeps_stdio() {
        // An ambient inheritable fd: a file opened then stripped of CLOEXEC.
        let dir = std::env::temp_dir();
        let path = dir.join(format!("fdguard-{}-{}", std::process::id(), line!()));
        std::fs::write(&path, b"cap").unwrap();
        let file = std::fs::File::open(&path).unwrap();
        // Clear CLOEXEC so the fd WOULD be inherited without the guard.
        let raw = file.as_raw_fd();
        // SAFETY: test-only fcntl on our own fd to model an inheritable descriptor.
        unsafe {
            let flags = libc::fcntl(raw, libc::F_GETFD);
            assert_eq!(
                libc::fcntl(raw, libc::F_SETFD, flags & !libc::FD_CLOEXEC),
                0
            );
        }

        let mut cmd = Command::new("ls");
        cmd.arg("-l").arg("/proc/self/fd").stdout(Stdio::piped());
        super::deny_inherited_fds(&mut cmd);
        let out = cmd.output().expect("spawn ls");
        drop(file);
        let _ = std::fs::remove_file(&path);

        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success(),
            "ls should run (stdio preserved): {stdout}"
        );
        assert!(
            !stdout.contains(path.to_string_lossy().as_ref()),
            "ambient fd must be closed in the child:\n{stdout}"
        );
    }

    /// A confined spawn of a MISSING program must still report the failure as
    /// `io::ErrorKind::NotFound`, never a bogus `Ok`. Regression for the
    /// `close_range` flag choice: closing fds `>= 3` *immediately* (`flags = 0`)
    /// also closes std's own `CLOEXEC` exec-status pipe, so a failed `exec` cannot
    /// be reported — `spawn` returns `Ok` with a child killed by `SIGABRT`.
    /// `CLOSE_RANGE_CLOEXEC` leaves that pipe to close at `exec`, so the error
    /// surfaces correctly. This test FAILS on the immediate-close variant and
    /// PASSES with the close-on-exec flag.
    #[test]
    fn deny_inherited_fds_reports_a_missing_program_as_not_found() {
        let mut cmd = Command::new("/nonexistent/agent-bridle-fdguard-missing-xyzzy");
        cmd.stdout(Stdio::null()).stderr(Stdio::null());
        super::deny_inherited_fds(&mut cmd);
        let err = cmd
            .spawn()
            .expect_err("spawning a missing program must fail, not succeed");
        assert_eq!(
            err.kind(),
            std::io::ErrorKind::NotFound,
            "a missing confined program must surface as NotFound, not a bogus spawn success"
        );
    }
}
