//! `agent-bridle-jaild` — the privileged **Tier-1.5 mount-namespace jail** that
//! turns a [`RootfsPlan`](agent_bridle_core::RootfsPlan) (ADR 0013 D2 / #107) into
//! a *runnable* program-identity confinement (ADR 0013 **D3/D4** / #109).
//!
//! # Why a separate crate
//!
//! `agent-bridle-core` forbids `unsafe` and stays dependency-lean, but a jail must
//! call `unshare(2)`, `mount(2)`, and `pivot_root(2)` — privileged syscalls with
//! no safe std equivalent. Per ADR 0013 **D4** the privileged mechanism lives in
//! its own component (`agent-bridle-jaild`), keeping the unsafe, root-only surface
//! out of core. This crate is the in-process jail primitive; the unprivileged
//! client ⇄ privileged broker IPC is the follow-up (#108).
//!
//! # The identity invariant (ADR 0013 D1)
//!
//! Confine program *identity* by controlling **what exists** in the process's
//! filesystem, not by allow-listing reads. [`run_jailed`] builds a fresh mount
//! namespace containing *only* the plan's entries (the granted binaries, their
//! `ldd` closure + loader, the curated data, the granted fs roots) and
//! `pivot_root`s into it. With no un-granted ELF physically present, an
//! `ld.so <readable>` trampoline, a `system("curl")`, and a shebang to an
//! un-granted interpreter all fail with `ENOENT` — the target is simply absent.
//!
//! # Privilege
//!
//! [`run_jailed`] needs `CAP_SYS_ADMIN` (typically root). It uses the host's
//! capability, **not** unprivileged user namespaces, so it composes with hosts
//! that set `kernel.apparmor_restrict_unprivileged_userns=1` (the #101 hardening).
//! As a non-root caller it fails closed with an error — never a panic, never a
//! silent unconfined run.

/// The outcome of a jailed run: the child's exit status and captured output.
#[derive(Debug)]
pub struct JailRun {
    /// The exit status of the jailed program.
    pub status: std::process::ExitStatus,
    /// Captured standard output.
    pub stdout: Vec<u8>,
    /// Captured standard error.
    pub stderr: Vec<u8>,
}

#[cfg(target_os = "linux")]
mod linux;

/// Run `program` (an absolute path) with `args` inside a Tier-1.5 mount-namespace
/// jail materialized from `plan`, capturing its output.
///
/// The jailed process sees **only** the paths in `plan`. A `program` (or any path
/// it later tries to `exec`) that is not in the plan is physically absent and
/// fails with `ENOENT` — the ADR 0013 D1 identity invariant.
///
/// Requires `CAP_SYS_ADMIN`. Returns an error (never a panic, never an unconfined
/// run) when the caller lacks privilege or the jail cannot be built.
///
/// **Linux-only**: the jail is built from a [`RootfsPlan`](agent_bridle_core::RootfsPlan),
/// which `agent-bridle-core` exposes only on Linux, and uses mount namespaces, so
/// this function exists only on Linux targets.
#[cfg(target_os = "linux")]
pub fn run_jailed<I, S>(
    plan: &agent_bridle_core::RootfsPlan,
    program: &std::path::Path,
    args: I,
) -> std::io::Result<JailRun>
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    linux::run_jailed(plan, program, args)
}

/// Whether the current process is effectively root (a quick precondition check for
/// callers and the privileged test harness).
#[must_use]
pub fn is_root() -> bool {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: geteuid() is always safe; it reads the effective uid.
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}
