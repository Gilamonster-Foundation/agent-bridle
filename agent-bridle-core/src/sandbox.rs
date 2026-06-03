//! OS-level sandbox plumbing.
//!
//! On Linux, Landlock is the *authoritative* boundary (DESIGN §6, ADR 0001 L3):
//! it is the only layer that can confine a *permitted external program's own
//! syscalls* once it has spawned — what neither the static decomposition (L1)
//! nor the in-process brush interceptor (L2) can see. With the `linux-landlock`
//! feature on a Landlock-capable kernel, [`LandlockSandbox`] builds and enforces
//! a real ruleset from the effective [`Caveats`] (first increment: the
//! `fs_write` axis). Without the feature, off-Linux, or on a kernel lacking
//! Landlock, the sandbox is the advisory [`NoopSandbox`] reporting
//! [`SandboxKind::None`] — the leash is then in-process only, honestly
//! advertised, with no overclaiming.

use crate::{Caveats, ToolResult};

/// Which OS-level sandbox actually backs an authorization.
///
/// Recorded in every [`crate::ToolContext`] and surfaced in every result
/// envelope so callers can tell whether the leash is kernel-enforced or merely
/// advisory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SandboxKind {
    /// A real Landlock ruleset is active (Linux). Kernel-enforced.
    Landlock,
    /// No OS-level sandbox — the leash is in-process/advisory only. This is the
    /// honest default until the Landlock ruleset (P3) lands.
    #[default]
    None,
}

/// An OS-level confinement that can be applied from a set of [`Caveats`].
///
/// Implementations translate the lattice's `fs_read`/`fs_write`/`exec`/`net`
/// axes into kernel rules (Landlock, namespaces). For P0 only [`NoopSandbox`]
/// exists.
pub trait Sandbox: Send + Sync {
    /// The kind of confinement this sandbox provides.
    fn kind(&self) -> SandboxKind;

    /// Apply the confinement for the given effective caveats. Called by a tool
    /// *before* it does any privileged work, on the thread/process that will do
    /// it. A `Noop` implementation succeeds without restricting anything.
    fn apply(&self, effective: &Caveats) -> ToolResult<()>;
}

/// The P0 sandbox: applies nothing and reports [`SandboxKind::None`].
///
/// This is the honest default until the Landlock ruleset (P3) lands. Tools that
/// consult `sandbox_kind()` can see that their exec/fs guarantees are advisory.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopSandbox;

impl Sandbox for NoopSandbox {
    fn kind(&self) -> SandboxKind {
        SandboxKind::None
    }

    fn apply(&self, _effective: &Caveats) -> ToolResult<()> {
        // Intentionally a no-op: the advisory default. Real kernel enforcement
        // lives in `LandlockSandbox` (Linux + `linux-landlock`).
        Ok(())
    }
}

/// Return the strongest [`Sandbox`] available in this build on this kernel.
///
/// On Linux, with the `linux-landlock` feature **and** a Landlock-capable
/// kernel, this is a [`LandlockSandbox`] (kernel-enforced). Otherwise it is the
/// advisory [`NoopSandbox`] — so a caller that wants confinement gets the real
/// thing where it exists and an honest [`SandboxKind::None`] where it does not,
/// rather than silently overclaiming.
pub fn best_available_sandbox() -> Box<dyn Sandbox> {
    #[cfg(all(target_os = "linux", feature = "linux-landlock"))]
    {
        if landlock_impl::landlock_is_supported() {
            return Box::new(landlock_impl::LandlockSandbox::new());
        }
    }
    Box::new(NoopSandbox)
}

#[cfg(all(target_os = "linux", feature = "linux-landlock"))]
pub use landlock_impl::{landlock_is_supported, LandlockSandbox};

#[cfg(all(target_os = "linux", feature = "linux-landlock"))]
mod landlock_impl {
    use super::{Sandbox, SandboxKind};
    use crate::{Caveats, Scope, ToolError, ToolResult};
    use landlock::{
        path_beneath_rules, Access, AccessFs, CompatLevel, Compatible, Ruleset, RulesetAttr,
        RulesetCreatedAttr, RulesetStatus, ABI,
    };

    /// ABI floor we request. Every filesystem *write*-side right exists by V3
    /// (WriteFile/Make*/Remove* at V1, Refer at V2, Truncate at V3). We request
    /// V3 and run BestEffort, so newer kernels keep working and older ones
    /// degrade gracefully (dropping Refer/Truncate) instead of failing to build
    /// the ruleset.
    const ABI_FLOOR: ABI = ABI::V3;

    /// `true` if this kernel can enforce a Landlock ruleset.
    ///
    /// Non-destructive: it creates (but never `restrict_self`s) a throwaway
    /// ruleset under `HardRequirement`, so an unsupported kernel surfaces as
    /// `Err` rather than being silently swallowed by best-effort.
    pub fn landlock_is_supported() -> bool {
        Ruleset::default()
            .set_compatibility(CompatLevel::HardRequirement)
            .handle_access(AccessFs::from_all(ABI::V1))
            .and_then(|r| r.create())
            .is_ok()
    }

    /// A real, kernel-enforced Landlock sandbox (Linux).
    ///
    /// **First increment — the `fs_write` axis.** The handled access set is the
    /// write/modify-side filesystem rights only; reads and execute are left
    /// ungoverned on purpose, so a dynamically-linked permitted binary can still
    /// load its shared libraries and run. (Read/exec confinement is a documented
    /// follow-up: it needs a base allow-list of loader/system paths — see ADR
    /// 0001 and the crate TODOs — otherwise locking `fs_read` would break every
    /// system binary.) This already closes the ADR-0001 gap on the write axis: a
    /// permitted external program can no longer write outside `fs_write`, even
    /// though L2 cannot see its syscalls once it has spawned.
    ///
    /// `restrict_self` is per-thread and irreversible, and is inherited across
    /// `fork`/`execve`. Callers must therefore call [`Sandbox::apply`] on the
    /// very thread that will spawn the confined work, immediately before the
    /// spawn.
    #[derive(Debug, Default, Clone, Copy)]
    pub struct LandlockSandbox;

    impl LandlockSandbox {
        /// Construct the sandbox. (Stateless; capability comes from the kernel.)
        pub fn new() -> Self {
            Self
        }
    }

    impl Sandbox for LandlockSandbox {
        fn kind(&self) -> SandboxKind {
            SandboxKind::Landlock
        }

        fn apply(&self, effective: &Caveats) -> ToolResult<()> {
            let write = AccessFs::from_write(ABI_FLOOR);

            // Which path roots may be written. `All` => the whole tree (the
            // ruleset is still in force, but writes anywhere are permitted).
            // `Only(set)` => exactly those roots; `Only(empty)` => nowhere, i.e.
            // all writes denied. A scope path that does not exist cannot anchor a
            // rule and is skipped — safe, because its parent is not granted, so
            // writes beneath it stay denied.
            let roots: Vec<String> = match &effective.fs_write {
                Scope::All => vec!["/".to_string()],
                Scope::Only(set) => set
                    .iter()
                    .filter(|p| std::path::Path::new(p).exists())
                    .cloned()
                    .collect(),
            };

            let status = Ruleset::default()
                .set_compatibility(CompatLevel::BestEffort)
                .handle_access(write)
                .map_err(landlock_denied)?
                .create()
                .map_err(landlock_denied)?
                .add_rules(path_beneath_rules(&roots, write))
                .map_err(landlock_denied)?
                .restrict_self()
                .map_err(landlock_denied)?;

            // Fail closed: if the kernel did not actually enforce the ruleset,
            // do not let the caller believe it is confined.
            if status.ruleset == RulesetStatus::NotEnforced {
                return Err(ToolError::denied(
                    "landlock ruleset was not enforced by this kernel",
                ));
            }
            Ok(())
        }
    }

    fn landlock_denied(e: impl std::fmt::Display) -> ToolError {
        ToolError::denied(format!("landlock: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noop_reports_none_and_never_fails() {
        let s = NoopSandbox;
        assert_eq!(s.kind(), SandboxKind::None);
        assert!(s.apply(&Caveats::top()).is_ok());
    }

    #[test]
    fn sandbox_kind_serde_is_snake_case() {
        assert_eq!(
            serde_json::to_string(&SandboxKind::None).unwrap(),
            "\"none\""
        );
        assert_eq!(
            serde_json::to_string(&SandboxKind::Landlock).unwrap(),
            "\"landlock\""
        );
    }

    #[test]
    fn best_available_sandbox_is_a_sandbox() {
        // Always returns *some* sandbox; on a non-landlock build/kernel it is the
        // advisory Noop. Just exercise the trait object.
        let sb = best_available_sandbox();
        assert!(sb.apply(&Caveats::top()).is_ok());
    }
}

// Real kernel enforcement test. Only meaningful with the feature on Linux; it
// asserts the leash is the *kernel's*, not ours — the regression proof that
// `fs_write` confines a process even outside the in-process L2 interceptor.
#[cfg(all(target_os = "linux", feature = "linux-landlock", test))]
mod landlock_kernel_tests {
    use super::*;
    use crate::Scope;
    use std::fs;
    use std::path::PathBuf;

    fn unique_dir(tag: &str) -> PathBuf {
        // No rand dep: derive a unique path from pid + a per-call atomic counter.
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let mut d = std::env::temp_dir();
        d.push(format!(
            "agent-bridle-ll-{}-{}-{}",
            tag,
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn fs_write_is_kernel_enforced_outside_scope_denied_inside_allowed() {
        if !landlock_is_supported() {
            eprintln!("skipping fs_write landlock test: kernel lacks Landlock");
            return;
        }

        let allowed = unique_dir("allowed");
        let forbidden = unique_dir("forbidden");
        let allowed_t = allowed.clone();
        let forbidden_t = forbidden.clone();

        // `restrict_self` is per-thread and irreversible, so confine a throwaway
        // thread rather than poisoning the test runner's threads.
        let (inside_ok, outside) = std::thread::spawn(move || {
            let cav = Caveats {
                fs_write: Scope::only([allowed_t.to_string_lossy().into_owned()]),
                ..Caveats::top()
            };
            LandlockSandbox::new().apply(&cav).expect("apply landlock");

            let inside = fs::write(allowed_t.join("ok.txt"), b"hi");
            let outside = fs::write(forbidden_t.join("escape.txt"), b"nope");
            (inside.is_ok(), outside)
        })
        .join()
        .unwrap();

        assert!(inside_ok, "writing within fs_write scope must succeed");
        let err = outside.expect_err("writing outside fs_write scope must be denied by Landlock");
        assert_eq!(
            err.kind(),
            std::io::ErrorKind::PermissionDenied,
            "the denial must come from the kernel (EACCES)"
        );

        let _ = fs::remove_dir_all(&allowed);
        let _ = fs::remove_dir_all(&forbidden);
    }

    #[test]
    fn empty_fs_write_scope_denies_all_writes() {
        if !landlock_is_supported() {
            eprintln!("skipping empty-scope landlock test: kernel lacks Landlock");
            return;
        }
        let dir = unique_dir("none");
        let dir_t = dir.clone();
        let outside = std::thread::spawn(move || {
            let cav = Caveats {
                fs_write: Scope::none(),
                ..Caveats::top()
            };
            LandlockSandbox::new().apply(&cav).expect("apply landlock");
            fs::write(dir_t.join("x.txt"), b"nope")
        })
        .join()
        .unwrap();
        assert_eq!(
            outside
                .expect_err("empty fs_write must deny all writes")
                .kind(),
            std::io::ErrorKind::PermissionDenied
        );
        let _ = fs::remove_dir_all(&dir);
    }
}
