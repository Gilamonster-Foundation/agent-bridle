//! OS-level sandbox plumbing.
//!
//! On Linux, Landlock is the *authoritative* boundary (DESIGN §6, ADR 0001 L3):
//! it is the only layer that can confine a *permitted external program's own
//! syscalls* once it has spawned — what neither the static decomposition (L1)
//! nor the in-process brush interceptor (L2) can see. With the `linux-landlock`
//! feature on a Landlock-capable kernel, [`LandlockSandbox`] builds and enforces
//! a real ruleset from the effective [`Caveats`] (the `fs_write` axis, and the
//! `fs_read` axis when reads are restricted — `exec`/`net` are follow-ups,
//! agent-bridle#31). Without the feature, off-Linux, or on a kernel lacking
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
    /// A real AppContainer token is active (Windows). Kernel-enforced.
    AppContainer,
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
    #[cfg(all(target_os = "windows", feature = "windows-appcontainer"))]
    {
        Box::new(appcontainer_impl::AppContainerSandbox::new())
    }

    #[cfg(not(all(target_os = "windows", feature = "windows-appcontainer")))]
    {
        #[cfg(all(target_os = "linux", feature = "linux-landlock"))]
        {
            if landlock_impl::landlock_is_supported() {
                return Box::new(landlock_impl::LandlockSandbox::new());
            }
        }
        Box::new(NoopSandbox)
    }
}

#[cfg(all(target_os = "linux", feature = "linux-landlock"))]
pub use landlock_impl::{landlock_is_supported, LandlockSandbox};

#[cfg(all(target_os = "windows", feature = "windows-appcontainer"))]
pub(crate) mod appcontainer_impl {
    use super::{Sandbox, SandboxKind};
    use crate::{Caveats, ToolError, ToolResult};

    /// A Windows AppContainer process sandbox.
    ///
    /// AppContainer is attached when creating a new process with
    /// `PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES`; unlike Landlock, it cannot
    /// be installed on the current thread and inherited by a later spawn via a
    /// Rust `std::process::Command`. The process-spawn path must therefore use a
    /// Windows-specific launcher. Calling [`Sandbox::apply`] directly fails
    /// closed rather than pretending the current thread was confined.
    #[derive(Debug, Default, Clone, Copy)]
    pub struct AppContainerSandbox;

    impl AppContainerSandbox {
        /// Construct the sandbox. (Stateless; capability comes from Windows.)
        pub fn new() -> Self {
            Self
        }
    }

    impl Sandbox for AppContainerSandbox {
        fn kind(&self) -> SandboxKind {
            SandboxKind::AppContainer
        }

        fn apply(&self, _effective: &Caveats) -> ToolResult<()> {
            Err(ToolError::denied(
                "AppContainer must be applied at Windows process creation",
            ))
        }
    }
}

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

    /// Read-only base allow-list: the loader/system paths a dynamically-linked
    /// binary must read to start (the dynamic linker, shared libraries, the
    /// linker cache, locale, name-resolution config, and the `/dev` and
    /// `/proc/self` essentials). Added whenever `fs_read` is confined so a
    /// *permitted* program still loads libc — while user data outside scope stays
    /// unreadable. Note `/etc` is **not** granted wholesale: only the specific
    /// files below, so e.g. `/etc/shadow` remains denied. Tuned for a glibc/FHS
    /// layout (the CI target); a musl/Nix layout may need more entries — paths
    /// that do not exist are skipped, so extra entries are harmless.
    const BASE_READ_PATHS: &[&str] = &[
        "/usr",
        "/bin",
        "/sbin",
        "/lib",
        "/lib64",
        "/lib32",
        "/libx32",
        "/opt",
        "/etc/ld.so.cache",
        "/etc/ld.so.preload",
        "/etc/alternatives",
        "/etc/nsswitch.conf",
        "/etc/localtime",
        "/etc/resolv.conf",
        "/proc/self",
        "/dev/null",
        "/dev/zero",
        "/dev/full",
        "/dev/urandom",
        "/dev/random",
        "/usr/share/locale",
        "/usr/lib/locale",
    ];

    /// A real, kernel-enforced Landlock sandbox (Linux).
    ///
    /// **The `fs_write` and `fs_read` axes.** Writes are always governed (from
    /// `fs_write`); reads are governed only when `fs_read` is *restricted*
    /// (`Only(_)`), in which case the granted read roots plus [`BASE_READ_PATHS`]
    /// are read-allowed and everything else is denied — so a permitted external
    /// program cannot read user data outside `fs_read` (closing `grep -f
    /// /etc/shadow`-style reads) yet can still load its libraries. `Execute` is
    /// deliberately left ungoverned this increment, so dynamically-linked
    /// binaries can mmap-exec their libraries without an execute allow-list; the
    /// `exec` axis (blocking e.g. `find -exec curl`) and `net` are follow-ups
    /// (agent-bridle#31). When `fs_read` is `All`, reads stay ambient (no base
    /// list needed, nothing to confine). These close the ADR-0001 gap on the
    /// read/write axes: confinement holds even though L2 cannot see the spawned
    /// program's syscalls.
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
            // Pure read rights — `from_read` also includes `Execute`, which we
            // intentionally leave ungoverned this increment so libraries can be
            // mmap-exec'd without an execute allow-list.
            let read = AccessFs::ReadFile | AccessFs::ReadDir;

            // Govern writes always; govern reads only when `fs_read` is actually
            // restricted (`Only`) — `All` means no read confinement was asked
            // for, so reads stay ambient and no base allow-list is needed.
            let confine_read = matches!(effective.fs_read, Scope::Only(_));
            let handled = if confine_read { write | read } else { write };

            let write_roots = scope_roots(&effective.fs_write);
            let ruleset = Ruleset::default()
                .set_compatibility(CompatLevel::BestEffort)
                .handle_access(handled)
                .map_err(landlock_denied)?
                .create()
                .map_err(landlock_denied)?
                .add_rules(path_beneath_rules(&write_roots, write))
                .map_err(landlock_denied)?;

            let ruleset = if confine_read {
                // Granted read roots plus the loader/system base list, so the
                // permitted binary loads while out-of-scope reads stay denied.
                let mut read_roots = scope_roots(&effective.fs_read);
                read_roots.extend(BASE_READ_PATHS.iter().map(|p| (*p).to_string()));
                read_roots.retain(|p| std::path::Path::new(p).exists());
                ruleset
                    .add_rules(path_beneath_rules(&read_roots, read))
                    .map_err(landlock_denied)?
            } else {
                ruleset
            };

            let status = ruleset.restrict_self().map_err(landlock_denied)?;

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

    /// The existing path roots a [`Scope`] grants: `All` => the whole tree
    /// (`/`); `Only(set)` => exactly those paths that exist (a non-existent path
    /// cannot anchor a Landlock rule and is skipped — safe, since its parent is
    /// ungranted, so access beneath it stays denied).
    fn scope_roots(scope: &Scope<String>) -> Vec<String> {
        match scope {
            Scope::All => vec!["/".to_string()],
            Scope::Only(set) => set
                .iter()
                .filter(|p| std::path::Path::new(p).exists())
                .cloned()
                .collect(),
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
        assert_eq!(
            serde_json::to_string(&SandboxKind::AppContainer).unwrap(),
            "\"app_container\""
        );
    }

    #[test]
    fn best_available_sandbox_is_a_sandbox() {
        // Always returns *some* sandbox; on a non-landlock build/kernel it is the
        // advisory Noop. Just exercise the trait object.
        let sb = best_available_sandbox();
        if sb.kind() == SandboxKind::AppContainer {
            assert!(
                sb.apply(&Caveats::top()).is_err(),
                "AppContainer cannot be applied to the current thread"
            );
        } else {
            assert!(sb.apply(&Caveats::top()).is_ok());
        }
    }

    #[cfg(all(target_os = "windows", feature = "windows-appcontainer"))]
    #[test]
    fn windows_appcontainer_feature_selects_appcontainer_backend() {
        assert_eq!(best_available_sandbox().kind(), SandboxKind::AppContainer);
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

    /// Whether a kernel-enforcement proof should run, skip, or hard-**FAIL** — a
    /// pure decision over (Landlock supported?, enforcement required?). Required
    /// but unsupported is a FAILURE: a security library must not ship a green
    /// build in which its kernel boundary was never exercised (#74).
    #[derive(Debug, PartialEq, Eq)]
    enum ProofGate {
        Run,
        Skip,
        Fail,
    }

    fn proof_gate(supported: bool, required: bool) -> ProofGate {
        match (supported, required) {
            (true, _) => ProofGate::Run,
            (false, true) => ProofGate::Fail,
            (false, false) => ProofGate::Skip,
        }
    }

    /// `true` if the caller should `return` (skip the proof). **Panics** when
    /// Landlock is *required* (`BRIDLE_REQUIRE_LANDLOCK` set, as CI does) but the
    /// kernel lacks it — so a flagged run cannot pass without actually exercising
    /// the boundary. A local run without the flag legitimately skips (#74).
    fn skip_proof_unless_landlock() -> bool {
        let required = std::env::var("BRIDLE_REQUIRE_LANDLOCK")
            .map(|v| !v.is_empty() && v != "0")
            .unwrap_or(false);
        match proof_gate(landlock_is_supported(), required) {
            ProofGate::Run => false,
            ProofGate::Skip => {
                eprintln!(
                    "skipping Landlock proof: kernel lacks Landlock \
                     (set BRIDLE_REQUIRE_LANDLOCK=1 to require it, as CI does)"
                );
                true
            }
            ProofGate::Fail => panic!(
                "BRIDLE_REQUIRE_LANDLOCK is set but this kernel lacks Landlock — the \
                 fs_write/fs_read kernel-enforcement proofs cannot be verified (#74)"
            ),
        }
    }

    #[test]
    fn proof_gate_required_but_unsupported_is_a_failure() {
        assert_eq!(proof_gate(true, false), ProofGate::Run);
        assert_eq!(proof_gate(true, true), ProofGate::Run);
        assert_eq!(proof_gate(false, false), ProofGate::Skip);
        // The crux (#74): required + unsupported must FAIL, never silently skip,
        // so CI cannot pass without exercising the kernel boundary.
        assert_eq!(proof_gate(false, true), ProofGate::Fail);
    }

    #[test]
    fn fs_write_is_kernel_enforced_outside_scope_denied_inside_allowed() {
        if skip_proof_unless_landlock() {
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
        if skip_proof_unless_landlock() {
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

    #[test]
    fn fs_read_is_kernel_enforced_outside_scope_denied_inside_allowed() {
        if skip_proof_unless_landlock() {
            return;
        }
        let allowed = unique_dir("read-allowed");
        let forbidden = unique_dir("read-forbidden");
        // Create both files BEFORE confining (afterwards the forbidden dir is
        // unreadable, but it must already hold a file to attempt the read).
        fs::write(allowed.join("ok.txt"), b"in-scope").unwrap();
        fs::write(forbidden.join("secret.txt"), b"out-of-scope").unwrap();
        let allowed_t = allowed.clone();
        let forbidden_t = forbidden.clone();

        let (inside, outside) = std::thread::spawn(move || {
            let cav = Caveats {
                fs_read: Scope::only([allowed_t.to_string_lossy().into_owned()]),
                ..Caveats::top()
            };
            LandlockSandbox::new().apply(&cav).expect("apply landlock");
            let inside = fs::read(allowed_t.join("ok.txt"));
            let outside = fs::read(forbidden_t.join("secret.txt"));
            (inside, outside)
        })
        .join()
        .unwrap();

        assert_eq!(inside.expect("in-scope read must succeed"), b"in-scope");
        assert_eq!(
            outside
                .expect_err("reading outside fs_read scope must be denied by Landlock")
                .kind(),
            std::io::ErrorKind::PermissionDenied,
            "the denial must come from the kernel (EACCES)"
        );

        let _ = fs::remove_dir_all(&allowed);
        let _ = fs::remove_dir_all(&forbidden);
    }

    #[test]
    fn read_confined_binary_still_loads_via_base_allowlist() {
        if skip_proof_unless_landlock() {
            return;
        }
        let allowed = unique_dir("rc-allowed");
        let forbidden = unique_dir("rc-forbidden");
        fs::write(allowed.join("ok.txt"), b"hello\n").unwrap();
        fs::write(forbidden.join("secret.txt"), b"nope\n").unwrap();
        let allowed_t = allowed.clone();
        let forbidden_t = forbidden.clone();

        // Confine reads, then run a *real* dynamically-linked binary (`cat`):
        // it must still load (proving the base allow-list covers the loader and
        // libc) and read the in-scope file, but be denied the out-of-scope one.
        let (inside, outside) = std::thread::spawn(move || {
            let cav = Caveats {
                fs_read: Scope::only([allowed_t.to_string_lossy().into_owned()]),
                ..Caveats::top()
            };
            LandlockSandbox::new().apply(&cav).expect("apply landlock");
            let inside = std::process::Command::new("cat")
                .arg(allowed_t.join("ok.txt"))
                .output();
            let outside = std::process::Command::new("cat")
                .arg(forbidden_t.join("secret.txt"))
                .output();
            (inside, outside)
        })
        .join()
        .unwrap();

        let inside = inside.expect("cat must still load+run under read confinement");
        assert!(
            inside.status.success(),
            "in-scope cat must succeed: {inside:?}"
        );
        assert_eq!(inside.stdout, b"hello\n");

        let outside = outside.expect("cat launches (loader is allowed) even for a denied target");
        assert!(
            !outside.status.success(),
            "cat of an out-of-scope file must fail (read denied): {outside:?}"
        );

        let _ = fs::remove_dir_all(&allowed);
        let _ = fs::remove_dir_all(&forbidden);
    }

    #[test]
    fn fs_read_all_leaves_reads_ambient() {
        if skip_proof_unless_landlock() {
            return;
        }
        // With fs_read: All (only fs_write restricted), reads are NOT governed —
        // a path outside the write scope is still readable.
        let outside_dir = unique_dir("ambient-read");
        fs::write(outside_dir.join("readable.txt"), b"still readable").unwrap();
        let write_scope = unique_dir("ambient-write");
        let outside_t = outside_dir.clone();
        let write_t = write_scope.clone();

        let read = std::thread::spawn(move || {
            let cav = Caveats {
                fs_write: Scope::only([write_t.to_string_lossy().into_owned()]),
                ..Caveats::top() // fs_read stays All
            };
            LandlockSandbox::new().apply(&cav).expect("apply landlock");
            fs::read(outside_t.join("readable.txt"))
        })
        .join()
        .unwrap();

        assert_eq!(
            read.expect("fs_read: All must leave reads ambient"),
            b"still readable"
        );
        let _ = fs::remove_dir_all(&outside_dir);
        let _ = fs::remove_dir_all(&write_scope);
    }
}
