//! OS-level sandbox plumbing.
//!
//! On Linux, Landlock is the *authoritative* boundary (DESIGN §6, ADR 0001 L3):
//! it is the only layer that can confine a *permitted external program's own
//! syscalls* once it has spawned — what neither the static decomposition (L1)
//! nor the in-process brush interceptor (L2) can see. With the `linux-landlock`
//! feature on a Landlock-capable kernel, [`LandlockSandbox`] builds and enforces
//! a real ruleset from the effective [`Caveats`] (the `fs_write` axis, plus the
//! `fs_read` and `exec` axes when those are restricted — `net` is a follow-up,
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

    /// Execute base allow-list: the dynamic linker(s) only — specific **files**,
    /// never directories. The kernel `execve`s the program and `open_exec`s its
    /// `PT_INTERP` (the loader), so both need `Execute`; shared libraries are
    /// opened `O_RDONLY` and `mmap`'d (governed by the read axis, not Execute),
    /// so the `.so` directories do **not** need to be execute-allowed.
    ///
    /// This is the security-critical narrowing: a directory grant here would be
    /// recursive (`path_beneath`), and `/lib`→`/usr/lib` is a merged-usr symlink,
    /// so allowing any lib *directory* would make every executable beneath
    /// `/usr/lib` runnable — including real shells/interpreters (`/usr/lib/klibc/
    /// bin/sh`, busybox, `git`, `go`, apt net helpers), fully defeating the exec
    /// axis. Allowing only the loader file (plus the resolved granted programs)
    /// closes that. Paths are symlinks to the real loader; `path_beneath` follows
    /// them. Non-existent entries are skipped, so listing several arches is safe.
    const LOADER_PATHS: &[&str] = &[
        "/lib64/ld-linux-x86-64.so.2",
        "/lib/ld-linux-x86-64.so.2",
        "/lib/ld-linux.so.2",
        "/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
        "/lib64/ld64.so.2",
        "/lib/ld-linux-aarch64.so.1",
        "/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1",
        "/lib/ld-linux-armhf.so.3",
        "/lib/ld-musl-x86-64.so.1",
        "/lib/ld-musl-aarch64.so.1",
    ];

    /// A real, kernel-enforced Landlock sandbox (Linux).
    ///
    /// **The `fs_write`, `fs_read`, and `exec` axes.** Writes are always governed
    /// (from `fs_write`). Reads are governed only when `fs_read` is *restricted*
    /// (`Only(_)`): the granted read roots plus [`BASE_READ_PATHS`] are
    /// read-allowed and all else denied — so a permitted program cannot read user
    /// data outside `fs_read` (closing `grep -f /etc/shadow`) yet still loads its
    /// libraries. Execute is governed only when `exec` is restricted: the
    /// *resolved* granted program paths plus [`BASE_EXEC_PATHS`] (the loader and
    /// library dirs) are execute-allowed and all else denied — so a permitted
    /// program cannot `execve` a different, un-granted tool (closing `find -exec
    /// curl` / `awk 'system("curl …")'`). When an axis is `All` it stays ambient
    /// (no base list needed). `net` remains a follow-up (netns / Landlock-net —
    /// agent-bridle#31). These close the ADR-0001 gap on the read/write/exec
    /// axes: confinement holds even though L2 cannot see the spawned program's
    /// syscalls.
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
            // govern separately (only when `exec` is restricted).
            let read = AccessFs::ReadFile | AccessFs::ReadDir;

            // Govern writes always; govern reads / execute only when their axis
            // is actually restricted (`Only`). `All` on an axis means it was not
            // confined, so it stays ambient and needs no base allow-list.
            let confine_read = matches!(effective.fs_read, Scope::Only(_));
            let confine_exec = matches!(effective.exec, Scope::Only(_));
            let mut handled = write;
            if confine_read {
                handled |= read;
            }
            if confine_exec {
                handled |= AccessFs::Execute;
            }

            let write_roots = scope_roots(&effective.fs_write);
            let mut ruleset = Ruleset::default()
                .set_compatibility(CompatLevel::BestEffort)
                .handle_access(handled)
                .map_err(landlock_denied)?
                .create()
                .map_err(landlock_denied)?
                .add_rules(path_beneath_rules(&write_roots, write))
                .map_err(landlock_denied)?;

            if confine_read {
                // Granted read roots plus the loader/system base list, so the
                // permitted binary loads while out-of-scope reads stay denied.
                let mut read_roots = scope_roots(&effective.fs_read);
                read_roots.extend(BASE_READ_PATHS.iter().map(|p| (*p).to_string()));
                read_roots.retain(|p| std::path::Path::new(p).exists());
                ruleset = ruleset
                    .add_rules(path_beneath_rules(&read_roots, read))
                    .map_err(landlock_denied)?;
            }

            if confine_exec {
                // Execute-allow ONLY the resolved granted program paths plus the
                // dynamic linker(s) — never library directories (those would be
                // recursive and reachable shells/interpreters live under them).
                // A permitted binary still runs (program execve + loader + .so
                // reads), but cannot execve a DIFFERENT, un-granted program.
                let mut exec_roots = resolve_exec_paths(&effective.exec);
                exec_roots.extend(LOADER_PATHS.iter().map(|p| (*p).to_string()));
                exec_roots.retain(|p| std::path::Path::new(p).exists());
                ruleset = ruleset
                    .add_rules(path_beneath_rules(&exec_roots, AccessFs::Execute))
                    .map_err(landlock_denied)?;
            }

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

    /// Resolve each `exec` grant to the absolute, symlink-canonicalized path the
    /// kernel will see at `execve`, so the execute-allow rules match what a
    /// permitted invocation actually runs. A `/`-bearing grant is treated as a
    /// path; a bare name is searched on `PATH` (first match, like `execvp`) — the
    /// same surface [`crate::ToolContext::check_exec`] admits by name/basename.
    /// Unresolvable grants are dropped (they cannot anchor a rule; the program
    /// would not be runnable anyway).
    fn resolve_exec_paths(scope: &Scope<String>) -> Vec<String> {
        let set = match scope {
            Scope::All => return Vec::new(),
            Scope::Only(set) => set,
        };
        let dirs = exec_search_dirs();
        let mut out = Vec::new();
        for entry in set {
            let candidate = if entry.contains('/') {
                let p = std::path::PathBuf::from(entry);
                p.exists().then_some(p)
            } else {
                dirs.iter()
                    .map(|d| std::path::Path::new(d).join(entry))
                    .find(|c| c.is_file())
            };
            if let Some(p) = candidate {
                if let Ok(canon) = p.canonicalize() {
                    out.push(canon.to_string_lossy().into_owned());
                }
            }
        }
        out
    }

    /// The directories to search for a bare-name `exec` grant: `$PATH` when set,
    /// else a conservative default (so a scrubbed-env caller still resolves).
    fn exec_search_dirs() -> Vec<String> {
        if let Ok(path) = std::env::var("PATH") {
            let dirs: Vec<String> = path
                .split(':')
                .filter(|s| !s.is_empty())
                .map(String::from)
                .collect();
            if !dirs.is_empty() {
                return dirs;
            }
        }
        [
            "/usr/local/bin",
            "/usr/bin",
            "/bin",
            "/usr/local/sbin",
            "/usr/sbin",
            "/sbin",
        ]
        .iter()
        .map(|s| (*s).to_string())
        .collect()
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

    #[test]
    fn fs_read_is_kernel_enforced_outside_scope_denied_inside_allowed() {
        if !landlock_is_supported() {
            eprintln!("skipping fs_read landlock test: kernel lacks Landlock");
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
        if !landlock_is_supported() {
            eprintln!("skipping read-confined binary test: kernel lacks Landlock");
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
        if !landlock_is_supported() {
            eprintln!("skipping fs_read-all test: kernel lacks Landlock");
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

    #[test]
    fn exec_is_kernel_enforced_granted_runs_ungranted_denied() {
        if !landlock_is_supported() {
            eprintln!("skipping exec landlock test: kernel lacks Landlock");
            return;
        }
        let dir = unique_dir("exec");
        fs::write(dir.join("data.txt"), b"payload\n").unwrap();
        let dir_t = dir.clone();

        // Grant exec of `cat` only. The granted program (and its libraries) must
        // still run; an un-granted system tool (`head`) must be execve-denied by
        // the kernel — the `find -exec curl` escape, in miniature.
        let (granted, ungranted) = std::thread::spawn(move || {
            let cav = Caveats {
                exec: Scope::only(["cat".to_string()]),
                ..Caveats::top()
            };
            LandlockSandbox::new().apply(&cav).expect("apply landlock");
            let granted = std::process::Command::new("cat")
                .arg(dir_t.join("data.txt"))
                .output();
            let ungranted = std::process::Command::new("head")
                .arg(dir_t.join("data.txt"))
                .output();
            (granted, ungranted)
        })
        .join()
        .unwrap();

        let granted = granted.expect("granted `cat` must still load and run");
        assert!(
            granted.status.success(),
            "granted cat must succeed: {granted:?}"
        );
        assert_eq!(granted.stdout, b"payload\n");

        // execve of the un-granted binary is denied by the kernel: std surfaces
        // the post-fork exec failure as a spawn error.
        let err = ungranted.expect_err("un-granted `head` must be exec-denied by Landlock");
        assert_eq!(
            err.kind(),
            std::io::ErrorKind::PermissionDenied,
            "the denial must come from the kernel (EACCES on execve)"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn exec_all_leaves_exec_ambient() {
        if !landlock_is_supported() {
            eprintln!("skipping exec-all landlock test: kernel lacks Landlock");
            return;
        }
        let dir = unique_dir("exec-ambient");
        fs::write(dir.join("data.txt"), b"x\n").unwrap();
        let dir_t = dir.clone();

        // With exec: All (only fs_write restricted), execve is NOT governed — an
        // un-granted tool still runs.
        let out = std::thread::spawn(move || {
            let cav = Caveats {
                fs_write: Scope::only([dir_t.to_string_lossy().into_owned()]),
                ..Caveats::top() // exec stays All
            };
            LandlockSandbox::new().apply(&cav).expect("apply landlock");
            std::process::Command::new("head")
                .arg(dir_t.join("data.txt"))
                .output()
        })
        .join()
        .unwrap();

        assert!(
            out.expect("exec: All must leave execve ambient")
                .status
                .success(),
            "an un-granted tool must still run when exec is not confined"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// Adversarial sweep: with `exec` confined to `cat` and writes confined to a
    /// scratch dir, every classic "make the permitted program launch something
    /// else" escape must be kernel-denied — direct un-granted exec, a payload the
    /// program could write+run, a shebang script (whose interpreter is
    /// un-granted), and a symlink to an un-granted tool. The granted program
    /// still works (control).
    #[test]
    fn exec_escape_attempts_are_all_denied() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        if !landlock_is_supported() {
            eprintln!("skipping exec escape sweep: kernel lacks Landlock");
            return;
        }
        let scratch = unique_dir("exec-escape"); // in fs_write scope
        fs::write(scratch.join("data.txt"), b"ok\n").unwrap();

        // A real ELF the confined context could try to run from the scratch dir
        // (a "written payload"); copying an existing binary avoids needing a
        // compiler. Made before confinement.
        let payload = scratch.join("payload");
        if let Ok(src) = std::fs::read("/bin/cat").or_else(|_| std::fs::read("/usr/bin/cat")) {
            fs::write(&payload, src).unwrap();
            fs::set_permissions(&payload, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        // A shebang script and a symlink to an un-granted interpreter/tool.
        let script = scratch.join("script.sh");
        fs::write(&script, b"#!/bin/sh\necho pwned\n").unwrap();
        fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        let link = scratch.join("sh-link");
        let _ = symlink("/bin/sh", &link);

        // Real shells/interpreters that live UNDER the library tree (/usr/lib*).
        // These are the adversarial-review finding: a recursive lib-dir execute
        // grant would make them runnable. With loader-only execute they must be
        // denied. Tested only where present (Debian/Ubuntu hosts + CI).
        let lib_execs: Vec<PathBuf> = [
            "/usr/lib/klibc/bin/sh",
            "/usr/lib/initramfs-tools/bin/busybox",
            "/usr/lib/git-core/git",
        ]
        .iter()
        .map(PathBuf::from)
        .filter(|p| p.exists())
        .collect();

        let scratch_t = scratch.clone();
        let results = std::thread::spawn(move || {
            let cav = Caveats {
                exec: Scope::only(["cat".to_string()]),
                fs_write: Scope::only([scratch_t.to_string_lossy().into_owned()]),
                ..Caveats::top()
            };
            LandlockSandbox::new().apply(&cav).expect("apply landlock");

            // (label, result) — every attempt must fail to exec.
            let mut attempts = vec![
                (
                    "ungranted-tool".to_string(),
                    std::process::Command::new("head")
                        .arg("/etc/hostname")
                        .output(),
                ),
                (
                    "written-payload".to_string(),
                    std::process::Command::new(scratch_t.join("payload")).output(),
                ),
                (
                    "shebang-script".to_string(),
                    std::process::Command::new(scratch_t.join("script.sh")).output(),
                ),
                (
                    "symlink-to-sh".to_string(),
                    std::process::Command::new(scratch_t.join("sh-link"))
                        .arg("-c")
                        .arg("echo pwned")
                        .output(),
                ),
            ];
            for p in &lib_execs {
                attempts.push((
                    format!("under-usr-lib:{}", p.display()),
                    std::process::Command::new(p).arg("--version").output(),
                ));
            }
            // Control: the granted program still runs.
            let control = std::process::Command::new("cat")
                .arg(scratch_t.join("data.txt"))
                .output();
            (attempts, control)
        })
        .join()
        .unwrap();

        let (attempts, control) = results;
        for (label, res) in attempts {
            match res {
                Err(e) => assert_eq!(
                    e.kind(),
                    std::io::ErrorKind::PermissionDenied,
                    "escape `{label}` failed for the wrong reason: {e:?}"
                ),
                Ok(out) => panic!(
                    "escape `{label}` was NOT denied — it ran (status {:?}, stdout {:?})",
                    out.status, out.stdout
                ),
            }
        }
        let control = control.expect("granted `cat` must still run");
        assert!(
            control.status.success() && control.stdout == b"ok\n",
            "control: {control:?}"
        );

        let _ = fs::remove_dir_all(&scratch);
    }
}
