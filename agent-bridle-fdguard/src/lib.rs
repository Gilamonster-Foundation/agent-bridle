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
//! descriptor `>= 3` **close-on-exec**, so the kernel closes them atomically at
//! `exec`, preserving stdio (`0`/`1`/`2`).
//!
//! Marking-then-exec — rather than closing the descriptors *immediately* in the
//! child — is deliberate: `std::process::Command` keeps its own `CLOEXEC` pipe
//! (also a descriptor `>= 3`) open across the `pre_exec → exec` window to report
//! an `exec` failure back to the parent. Closing that pipe early makes a failed
//! spawn (a missing or non-executable program) surface as a bogus `Ok` — the
//! child dies by `SIGABRT` and the parent reads the early EOF as success —
//! instead of the correct `io::Error`. Close-on-exec marking leaves the pipe to
//! close itself at `exec`, so exec failures are reported faithfully while
//! ambient descriptors still never reach the confined child. The `unsafe`
//! blocks are documented and encapsulated here, so callers invoke a **safe**
//! function.
//!
//! ## Platform scope
//!
//! - **Linux**: `close_range(2)` with `CLOSE_RANGE_CLOEXEC` (kernel ≥ 5.11) —
//!   one race-free syscall marks the whole range `[3, ∞)`.
//! - **macOS**: no `close_range` exists, so the pre-exec hook sweeps
//!   `fcntl(fd, F_SETFD, FD_CLOEXEC)` over `[3, bound)`. `fcntl` is
//!   async-signal-safe; the sweep allocates nothing. The exclusive `bound` is
//!   computed **in the parent** (where ordinary calls are allowed) as the larger
//!   of `RLIMIT_NOFILE.rlim_cur` — while that limit holds, `open` cannot return
//!   a descriptor at or above it — and one past the highest descriptor open at
//!   install time (`/dev/fd`), which covers descriptors that predate a later
//!   rlimit lowering. Residual: a descriptor opened *after* installation under
//!   a rlimit *raised* after installation would sit above the captured bound;
//!   every in-repo call site installs the guard immediately before `spawn`, so
//!   no such window exists on the confined path.
//! - **Everywhere else** [`deny_inherited_fds`] is a no-op and the
//!   CLOEXEC-convention residual remains. On Windows the *confined* path does
//!   not go through `std::process::Command` at all: `agent-bridle-aclaunch`
//!   spawns with an explicit `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` of only the
//!   delegated handles, which is the Windows equivalent of this guard.
//!
//! ## Fail-closed
//!
//! If the marking step fails at spawn time (`close_range` on Linux, any
//! non-`EBADF` `fcntl` failure on macOS), the pre-exec hook returns an error, so
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

/// Install a pre-exec step that marks every inherited descriptor `>= 3`
/// close-on-exec, so the kernel closes them at `exec` in the child while
/// preserving stdio.
///
/// Safe to call: the installed closure invokes only `fcntl`, which is
/// async-signal-safe, so this satisfies [`CommandExt::pre_exec`]'s contract on
/// the caller's behalf. See the crate docs for the sweep bound, its residual,
/// and fail-closed behavior.
///
/// [`CommandExt::pre_exec`]: std::os::unix::process::CommandExt::pre_exec
#[cfg(target_os = "macos")]
pub fn deny_inherited_fds(cmd: &mut std::process::Command) {
    use std::os::unix::process::CommandExt;

    // Captured in the parent: the child-side sweep must not call anything that
    // is not async-signal-safe (getrlimit/readdir are not on that list).
    let bound = ambient_fd_bound();

    // SAFETY: the closure runs in the forked child after `fork` and before
    // `exec`. It calls only `fcntl` — async-signal-safe per POSIX — and
    // `io::Error::last_os_error`/`from_raw_os_error` (an `errno` read; no
    // allocation for OS-errno errors); it allocates nothing, takes no locks, and
    // is bounded by `bound` (≤ `HARD_CAP`), satisfying `pre_exec`'s
    // async-signal-safety contract. Rust's `Command` performs its stdio `dup2`
    // onto fds 0/1/2 *before* running pre-exec hooks, so sweeping `[3, bound)`
    // covers only ambient descriptors and never the child's delegated stdio.
    // Marking `FD_CLOEXEC` rather than closing immediately keeps std's own
    // `CLOEXEC` exec-status pipe alive to report an `exec` failure (it is
    // already close-on-exec, so re-marking it is a no-op); every marked fd
    // closes atomically at `exec`, so the confined child never inherits one.
    unsafe {
        cmd.pre_exec(move || {
            for fd in 3..bound {
                let flags = libc::fcntl(fd, libc::F_GETFD);
                if flags == -1 {
                    let err = std::io::Error::last_os_error();
                    // A hole in the descriptor table is not an error.
                    if err.raw_os_error() == Some(libc::EBADF) {
                        continue;
                    }
                    return Err(err);
                }
                if flags & libc::FD_CLOEXEC == 0
                    && libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) == -1
                {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
}

/// Exclusive upper bound on descriptor numbers the macOS pre-exec sweep visits.
///
/// Runs in the **parent** at install time, where non-async-signal-safe calls
/// are fine. The bound is the larger of:
///
/// - `RLIMIT_NOFILE.rlim_cur` — while that limit holds, the kernel cannot
///   allocate a descriptor at or above it, so it bounds every descriptor opened
///   between installation and `exec`;
/// - one past the highest descriptor currently open (`/dev/fd`) — covers
///   descriptors that were opened before the soft limit was lowered.
///
/// Both legs are capped at `HARD_CAP` so the child-side sweep always
/// terminates promptly; macOS cannot hand out descriptors that high without
/// `kern.maxfilesperproc` (default 10240) being raised past a million.
#[cfg(target_os = "macos")]
fn ambient_fd_bound() -> libc::c_int {
    const HARD_CAP: u64 = 1 << 20;

    let mut lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit writes into the stack struct above; no other aliasing.
    // On failure we fall back to the hard cap — the wider (fail-closed) bound.
    let rlim_bound = if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) } == 0 {
        lim.rlim_cur.min(HARD_CAP)
    } else {
        HARD_CAP
    };

    let max_open = std::fs::read_dir("/dev/fd")
        .ok()
        .into_iter()
        .flatten()
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| {
            entry
                .file_name()
                .to_str()
                .and_then(|s| s.parse::<u64>().ok())
        })
        .max()
        .unwrap_or(0);

    rlim_bound.max((max_open + 1).min(HARD_CAP)) as libc::c_int
}

/// No-op on platforms without an enforcement leg: the CLOEXEC-convention
/// residual remains there (see the crate docs — on Windows the confined path
/// spawns via `agent-bridle-aclaunch`'s explicit handle allowlist instead).
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn deny_inherited_fds(_cmd: &mut std::process::Command) {}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod tests {
    use std::os::fd::AsRawFd;
    use std::process::{Command, Stdio};

    /// The seam closes an ambient (CLOEXEC-cleared) descriptor in the child while
    /// preserving stdio. Regression for agent-bridle#319 at the crate boundary
    /// (the tool-shell integration test proves it end-to-end through ShellTool).
    #[cfg(target_os = "linux")]
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

    /// Cross-Unix regression for agent-bridle#319 (the macOS leg's red→green
    /// test; also runs on Linux): a child probes the ambient descriptor by
    /// *using* it (`echo >&N`), positively establishing inherited-vs-closed —
    /// the positive control proves the descriptor really was inheritable, the
    /// guarded spawn proves it is closed at `exec`.
    #[test]
    fn deny_inherited_fds_makes_an_ambient_fd_unusable_in_the_child() {
        // A writable ambient fd (write-capable so the control's `echo >&N`
        // succeeds), stripped of CLOEXEC to model an inheritable descriptor.
        let dir = std::env::temp_dir();
        let path = dir.join(format!("fdguard-{}-{}", std::process::id(), line!()));
        std::fs::write(&path, b"cap").unwrap();
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        let raw = file.as_raw_fd();
        // SAFETY: test-only fcntl on our own fd to model an inheritable descriptor.
        unsafe {
            let flags = libc::fcntl(raw, libc::F_GETFD);
            assert_eq!(
                libc::fcntl(raw, libc::F_SETFD, flags & !libc::FD_CLOEXEC),
                0
            );
        }
        let probe = format!("echo probe >&{raw} 2>/dev/null");

        // Positive control: WITHOUT the guard the child can use the descriptor.
        let control = Command::new("/bin/sh")
            .arg("-c")
            .arg(&probe)
            .status()
            .expect("spawn control sh");
        assert!(
            control.success(),
            "positive control: without the guard, fd {raw} must be usable in the child"
        );

        // With the guard the same probe must fail: the fd is closed at `exec`.
        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-c").arg(&probe);
        super::deny_inherited_fds(&mut cmd);
        let status = cmd.status().expect("spawn guarded sh");
        drop(file);
        let _ = std::fs::remove_file(&path);
        assert!(
            !status.success(),
            "ambient fd {raw} must be closed in the confined child (agent-bridle#319)"
        );
    }

    /// A confined spawn of a MISSING program must still report the failure as
    /// `io::ErrorKind::NotFound`, never a bogus `Ok`. Regression for the
    /// mark-don't-close choice on BOTH legs: closing fds `>= 3` *immediately*
    /// also closes std's own `CLOEXEC` exec-status pipe, so a failed `exec`
    /// cannot be reported — `spawn` returns `Ok` with a child killed by
    /// `SIGABRT`. Close-on-exec marking leaves that pipe to close at `exec`, so
    /// the error surfaces correctly. This test FAILS on an immediate-close
    /// variant and PASSES with close-on-exec marking.
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
