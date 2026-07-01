//! OS-level sandbox plumbing.
//!
//! The L3 boundary is the only layer that can confine a *permitted external
//! program's own syscalls* once it has spawned — what neither the static
//! decomposition (L1) nor the in-process interceptor (L2) can see. It is
//! OS-specific, so each operating system gets its own backend behind one
//! [`Sandbox`] trait, selected in code by [`best_available_sandbox`] (one
//! `cfg(target_os, feature)` arm per backend, with a runtime capability probe),
//! never overclaiming: a build either compiles a real backend for its host or
//! falls back to the advisory [`NoopSandbox`] reporting [`SandboxKind::None`]
//! (DESIGN §6, ADR 0001 L3, **ADR 0006** per-OS backends, **ADR 0009** the
//! cross-platform strategy).
//!
//! - **Linux** — [`LandlockSandbox`] (`linux-landlock`): a real Landlock ruleset
//!   confining the `fs_write` axis, and `fs_read` when restricted. `restrict_self`
//!   confines the calling thread (inherited across `fork`/`execve`).
//! - **macOS** — [`SeatbeltSandbox`] (`macos-seatbelt`): an SBPL profile derived
//!   from the effective [`Caveats`], applied by wrapping the spawned program in
//!   `sandbox-exec(1)` (no FFI — core forbids `unsafe`). Confines the `fs_write`
//!   and `fs_read` axes, and kernel-denies **all** network egress when `net` is
//!   empty (a confinement Landlock cannot provide); `exec` and non-empty `net`
//!   host allowlists are follow-ups (agent-bridle#31/#57).
//!
//! A backend confines either by restricting the calling thread in [`Sandbox::apply`]
//! (Landlock) **or** by wrapping the spawned command via
//! [`Sandbox::command_prefix`] (Seatbelt); a spawn site honors both, so the
//! mechanism is uniform at the call site.

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
    /// A real Seatbelt (`sandbox-exec` SBPL) profile is active (macOS).
    /// Kernel-enforced against the spawned program's interior.
    Seatbelt,
    /// A real AppContainer token is active (Windows). Kernel-enforced.
    AppContainer,
    /// A Linux **minimal-rootfs mount-namespace jail** is active (ADR 0013 D3/D4,
    /// agent-bridle#109/#108). The process runs in a `pivot_root` jail that
    /// physically contains only the granted program files, so `exec` is
    /// kernel-confined by **identity** — no un-granted binary *exists* to run or to
    /// `ld.so`-trampoline into (ADR 0011 D7's precondition is now physically true,
    /// not asserted) — and the filesystem axes are kernel-confined by the
    /// read-only/read-write bind-mounts. Network is not namespaced at this tier, so
    /// `net` stays advisory (never overclaimed). Reserved for the minimal-rootfs
    /// mode: a Landlock-only boundary run stays [`SandboxKind::Landlock`] (its exec
    /// axis is held — ADR 0011).
    MinimalRootfs,
    /// A Linux **Tier-2 micro-VM** is active (ADR 0013 D3, ADR 0009 D2,
    /// agent-bridle#111): the same minimal rootfs booted as a qemu guest under a
    /// separate kernel. Identity is closed as in [`SandboxKind::MinimalRootfs`]
    /// (only the granted program exists in the guest) and the filesystem is confined
    /// by the guest boundary; with no guest network device, egress is impossible —
    /// so `exec`, the fs axes, **and** `net` are all kernel-confined, and a
    /// guest-kernel compromise is still contained. The strongest tier.
    MicroVm,
    /// No OS-level sandbox — the leash is in-process/advisory only. This is the
    /// honest default on a host with no compiled-and-capable backend.
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
    ///
    /// This is the confinement mechanism for *thread-confining* backends
    /// (Landlock's `restrict_self`). *Wrapper-based* backends (macOS Seatbelt)
    /// confine via [`Sandbox::command_prefix`] instead and make this a no-op.
    fn apply(&self, effective: &Caveats) -> ToolResult<()>;

    /// The argv prefix that wraps a child so a *wrapper-based* L3 backend
    /// confines it (macOS `sandbox-exec`). The returned vector, prepended to a
    /// `(program, args…)`, is the argv that must actually be spawned.
    ///
    /// Backends that confine the spawning thread in [`Sandbox::apply`]
    /// (Landlock) or that do not confine ([`NoopSandbox`]) return an **empty**
    /// prefix. A spawn site applies *both* `apply()` and this prefix, so either
    /// mechanism is honored without the caller knowing which backend is active.
    ///
    /// **Fail-closed:** a backend that is selected but cannot build its wrapper
    /// (e.g. the wrapper binary is missing) returns `Err` — never an empty
    /// (silently unconfined) prefix. The default is the empty prefix.
    fn command_prefix(&self, effective: &Caveats) -> ToolResult<Vec<String>> {
        let _ = effective;
        Ok(Vec::new())
    }
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

/// `true` if either filesystem axis is actually restricted (`Only(_)`) — the
/// condition under which the fs-confining backends (Landlock, Seatbelt) have
/// something to enforce. When **no** fs axis is restricted, an fs-only backend
/// governs nothing, so honest reporting downgrades the [`SandboxKind`] to
/// [`SandboxKind::None`] rather than overclaiming a boundary that confines
/// nothing (I9 / ADR 0006 D3). Used by every spawn site that reports a kind.
#[must_use]
pub(crate) fn restricts_fs(caveats: &Caveats) -> bool {
    matches!(caveats.fs_write, crate::Scope::Only(_))
        || matches!(caveats.fs_read, crate::Scope::Only(_))
}

/// `true` if the `exec` axis is actually restricted (`Only(_)`) — the condition
/// under which an exec-confining backend has an allow-list to enforce. Today only
/// the macOS Seatbelt backend acts on this: `process-exec*` is a kernel-checked
/// operation that confines the spawned program's **interior** execs (covering the
/// loader trampoline that Landlock cannot — ADR 0014), so an `exec:Only` grant
/// engages Seatbelt even when no fs/net axis is restricted. Landlock's exec axis
/// stays held (agent-bridle#31/#57), so it does **not** engage on this alone.
#[must_use]
pub(crate) fn restricts_exec(caveats: &Caveats) -> bool {
    matches!(caveats.exec, crate::Scope::Only(_))
}

/// `true` if the `net` axis is restricted to the **empty** set — i.e. *all*
/// network egress is denied. This is the one network policy SBPL can soundly
/// express (`(deny network*)`); a non-empty host allowlist filters by socket,
/// not hostname, so it is **not** expressible and stays advisory (never silently
/// dropped). Only the macOS Seatbelt backend acts on this today.
#[must_use]
pub(crate) fn net_fully_denied(caveats: &Caveats) -> bool {
    matches!(&caveats.net, crate::Scope::Only(s) if s.is_empty())
}

/// The host tokens that name the machine's own **loopback interface**. SBPL's
/// `(remote ip "localhost:*")` filter matches exactly these destinations
/// (`127.0.0.1` and `::1`) — empirically the *only* remote a non-empty SBPL net
/// rule can name (an arbitrary IP is rejected: "host must be * or localhost").
const LOOPBACK_HOSTS: &[&str] = &["localhost", "127.0.0.1", "::1"];

/// `true` if the `net` axis is restricted to a **non-empty** allow-list whose
/// every host is a [loopback identifier](LOOPBACK_HOSTS) — the one non-deny-all
/// net policy SBPL *can* kernel-enforce (`(deny network*)` + `(allow network*
/// (remote ip "localhost:*"))`), confining egress to the loopback interface so the
/// process's **own off-box socket egress is kernel-denied** (ADR 0015; the
/// system-resolver DNS residual is shared with the empty-net case). A general remote
/// host cannot be named in SBPL (only `*`/`localhost` + ports), so a mixed or
/// non-loopback allow-list is **not** loopback-only and stays advisory — never
/// silently dropped. Mutually exclusive with [`net_fully_denied`] (empty set).
///
/// The kernel rule confines egress to the loopback *interface* — `localhost` =
/// `127.0.0.1` **and** `::1`, the finest grain SBPL can name. For a **spawned
/// child** (governed only by the kernel rule, not the in-process leash) that
/// interface *is* the boundary, so a grant naming a single loopback address
/// (e.g. `127.0.0.1`) still permits the other (`::1`) — a widening strictly
/// *within* loopback, never off-box. Admission (`ToolContext::check_net`,
/// exact-match) narrows to the granted host for the engine's *own* operations.
/// Unlike the fs `(subpath root)` case — where the kernel subtree and the granted
/// root denote the same set — the loopback interface can exceed a single-address
/// grant; see ADR 0015 D2.
#[must_use]
pub(crate) fn net_loopback_only(caveats: &Caveats) -> bool {
    matches!(&caveats.net, crate::Scope::Only(s)
        if !s.is_empty() && s.iter().all(|h| LOOPBACK_HOSTS.contains(&h.as_str())))
}

/// The [`SandboxKind`] honestly in force for `caveats` given the strongest
/// `available` backend: the backend's own kind when it will actually confine
/// *something*, else [`SandboxKind::None`]. The single honesty rule shared by the
/// subprocess primitive ([`crate::ConfinedCommand`]) and the shell engine, so
/// neither overclaims.
///
/// Capabilities differ per backend, so the engaging condition does too: Landlock
/// governs the filesystem axes; Seatbelt governs those, kernel-denies all egress
/// when `net` is empty ([`net_fully_denied`]) or confines it to the loopback
/// interface for a loopback-only allow-list ([`net_loopback_only`], ADR 0015),
/// **and** confines the `exec` axis via `process-exec*` ([`restricts_exec`]) — a
/// confinement Landlock cannot supply (ADR 0014). Landlock's exec axis stays held
/// (agent-bridle#31/#57), so a Landlock host does not engage on `exec` alone.
/// AppContainer (Windows) engages on any restricted fs axis or a fully-denied
/// `net` — matching the honesty condition for what the launcher actually confines
/// (ADR 0006 / #51).
#[must_use]
pub fn effective_sandbox_kind(available: SandboxKind, caveats: &Caveats) -> SandboxKind {
    match available {
        SandboxKind::Landlock if restricts_fs(caveats) => SandboxKind::Landlock,
        SandboxKind::Seatbelt
            if restricts_fs(caveats)
                || net_fully_denied(caveats)
                || net_loopback_only(caveats)
                || restricts_exec(caveats) =>
        {
            SandboxKind::Seatbelt
        }
        SandboxKind::AppContainer if restricts_fs(caveats) || net_fully_denied(caveats) => {
            SandboxKind::AppContainer
        }
        _ => SandboxKind::None,
    }
}

/// Return the strongest [`Sandbox`] available in this build on this host.
///
/// One `cfg(target_os, feature)` arm per backend, each with a runtime capability
/// probe (ADR 0006 D2): on Linux with `linux-landlock` and a capable kernel a
/// [`LandlockSandbox`]; on macOS with `macos-seatbelt` and `sandbox-exec`
/// present a [`SeatbeltSandbox`]. Otherwise the advisory [`NoopSandbox`] — so a
/// caller that wants confinement gets the real thing where it exists and an
/// honest [`SandboxKind::None`] where it does not, rather than silently
/// overclaiming. Enabling a backend's feature off its target OS compiles nothing
/// and selects nothing (the arm is `cfg`-gated away).
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
        #[cfg(all(target_os = "macos", feature = "macos-seatbelt"))]
        {
            if seatbelt_impl::seatbelt_is_supported() {
                return Box::new(seatbelt_impl::SeatbeltSandbox::new());
            }
        }
        Box::new(NoopSandbox)
    }
}

#[cfg(all(target_os = "linux", feature = "linux-landlock"))]
pub use landlock_impl::{landlock_is_supported, LandlockSandbox};

#[cfg(all(target_os = "macos", feature = "macos-seatbelt"))]
pub use seatbelt_impl::{seatbelt_is_supported, SeatbeltSandbox};

#[cfg(all(target_os = "windows", feature = "windows-appcontainer"))]
pub(crate) mod appcontainer_impl {
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::{net_fully_denied, restricts_fs, Sandbox, SandboxKind};
    use crate::{Caveats, Scope, ToolError, ToolResult};

    /// Monotonic counter for unique container names (PID + counter → no clock).
    static SPAWN_N: AtomicU64 = AtomicU64::new(0);

    /// A Windows AppContainer process sandbox.
    ///
    /// AppContainer is attached when creating a new process via
    /// `PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES`; it cannot be installed on
    /// the current thread and inherited across a later spawn the way Landlock
    /// can. The spawn path must therefore use the `agent-bridle-aclaunch`
    /// wrapper binary returned by [`command_prefix`] rather than the thread
    /// `apply` path (ADR 0006 / agent-bridle#51).
    ///
    /// Calling [`Sandbox::apply`] directly fails closed: it is never correct to
    /// call `apply` expecting AppContainer confinement on the current thread.
    #[derive(Debug, Default, Clone, Copy)]
    pub struct AppContainerSandbox;

    impl AppContainerSandbox {
        /// Construct the sandbox. (Stateless; confinement is per-process.)
        pub fn new() -> Self {
            Self
        }
    }

    /// Return the path of `agent-bridle-aclaunch.exe`, searching first next to
    /// the current executable and then via `PATH`.
    fn find_launcher() -> Option<String> {
        const LAUNCHER: &str = "agent-bridle-aclaunch.exe";

        // Same directory as the current exe — the normal install layout.
        if let Ok(mut p) = std::env::current_exe() {
            p.set_file_name(LAUNCHER);
            if p.exists() {
                return Some(p.to_string_lossy().into_owned());
            }
        }
        // Fall back to PATH.
        std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
            .map(|dir| dir.join(LAUNCHER))
            .find(|p| p.exists())
            .map(|p| p.to_string_lossy().into_owned())
    }

    impl Sandbox for AppContainerSandbox {
        fn kind(&self) -> SandboxKind {
            SandboxKind::AppContainer
        }

        /// Fail closed: AppContainer is applied at process creation via the
        /// `agent-bridle-aclaunch` launcher prefix, not via this thread.
        fn apply(&self, _effective: &Caveats) -> ToolResult<()> {
            Err(ToolError::denied(
                "AppContainer must be applied at Windows process creation via the \
                 agent-bridle-aclaunch launcher; call command_prefix instead",
            ))
        }

        /// Build the `["agent-bridle-aclaunch.exe", ...]` prefix that wraps the
        /// child inside a fresh AppContainer profile.
        ///
        /// Returns an empty prefix when nothing on a governed axis is restricted
        /// (so the spawn runs unwrapped — the backend engages only when it
        /// actually confines something). Fails closed if the launcher binary is
        /// not found.
        fn command_prefix(&self, effective: &Caveats) -> ToolResult<Vec<String>> {
            // Nothing to confine — no wrapper needed.
            if !restricts_fs(effective) && !net_fully_denied(effective) {
                return Ok(Vec::new());
            }

            // Fail-closed: without the launcher we cannot enforce.
            let launcher = find_launcher().ok_or_else(|| {
                ToolError::denied(
                    "windows-appcontainer: agent-bridle-aclaunch.exe not found next to the \
                     current executable or on PATH; cannot confine",
                )
            })?;

            // Unique container name: PID + monotonic counter (no wall clock).
            let n = SPAWN_N.fetch_add(1, Ordering::Relaxed);
            let container_name = format!("ab{}{}", std::process::id(), n);

            let mut prefix = vec![launcher, "--name".to_string(), container_name];

            // Grant network capabilities only when net is fully unrestricted
            // (Scope::All). Any non-All net scope denies egress by default via
            // the AppContainer's deny-by-default network policy.
            if matches!(effective.net, Scope::All) {
                prefix.push("--net-allow".to_string());
            }

            Ok(prefix)
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

    /// Read base allow-list: the loader/library trees + the system DATA and
    /// runtime files a permitted, dynamically-linked program needs to start and
    /// resolve names — but **NOT** the executable directories (`/usr/bin`, `/bin`,
    /// `/sbin`). Keeping the bin dirs out of the read set shrinks the
    /// loader-trampoline corpus (ADR 0011 D3): `/usr/bin/curl` is then unreadable
    /// and so cannot be `mmap`-exec'd via `ld.so`. The granted program's OWN
    /// binary is added back in `apply` ([`BIN_READ_PATHS`] when `exec` is ambient,
    /// or the resolved granted paths when `exec` is confined).
    ///
    /// This *shrinks* the corpus, it does not *close* the trampoline — `/usr/lib`
    /// (the `.so` tree) still hides some interpreters, so `exec` stays
    /// `interceptor`, never `kernel` (ADR 0011 D7). `/etc` is never granted
    /// wholesale (so `/etc/shadow` stays denied) — only the specific resolver /
    /// loader files below. glibc/FHS-tuned; non-existent paths are skipped, so
    /// extra entries are harmless.
    const BASE_READ_PATHS: &[&str] = &[
        // Library / loader trees: the dynamic linker + shared objects.
        "/lib",
        "/lib64",
        "/lib32",
        "/libx32",
        "/usr/lib",
        "/usr/lib64",
        "/usr/libexec",
        // System DATA a program reads at runtime (none of these are bin dirs):
        // locale, timezone, terminfo, gconv, CA-cert bundles, package data, …
        "/usr/share",
        "/etc/ld.so.cache",
        "/etc/ld.so.preload",
        "/etc/alternatives",
        "/etc/nsswitch.conf",
        "/etc/localtime",
        "/etc/resolv.conf",
        "/etc/ssl",
        "/etc/ca-certificates",
        "/proc/self",
        "/dev/null",
        "/dev/zero",
        "/dev/full",
        "/dev/urandom",
        "/dev/random",
    ];

    /// Executable directories a program's OWN binary loads from. Read-allowed only
    /// when `exec` is **ambient** (`All`) — then the program is arbitrary and its
    /// path unknown, so the bin dirs must be readable for it to load. When `exec`
    /// is confined (`Only`), these are deliberately NOT read-allowed (the granted
    /// binaries are added by resolved path instead), shrinking the trampoline
    /// corpus to exactly the granted programs (ADR 0011 D3).
    const BIN_READ_PATHS: &[&str] = &[
        "/usr/bin",
        "/bin",
        "/usr/sbin",
        "/sbin",
        "/usr/local/bin",
        "/usr/local/sbin",
        "/opt",
    ];

    /// Execute base allow-list: the dynamic linker(s) only — specific **files**,
    /// never directories. The kernel `execve`s the program and `open_exec`s its
    /// `PT_INTERP` (the loader), so both need `Execute`; shared libraries are
    /// `open(O_RDONLY)`+`mmap`'d (governed by the read axis, not `Execute`), so the
    /// `.so` directories do **not** need execute.
    ///
    /// Security-critical narrowing: a *directory* grant here would be recursive
    /// (`path_beneath`), and `/lib`→`/usr/lib` is a merged-usr symlink, so allowing
    /// any lib directory would make every executable beneath `/usr/lib` runnable
    /// (`/usr/lib/klibc/bin/sh`, busybox, `git`, `go`), defeating the axis. Allow
    /// only the loader file (plus the resolved granted programs). Non-existent
    /// entries are skipped, so listing several arches is safe.
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
    /// (from `fs_write`); reads are governed only when `fs_read` is *restricted*
    /// (`Only(_)`), in which case the granted read roots plus [`BASE_READ_PATHS`]
    /// are read-allowed and everything else is denied — so a permitted external
    /// program cannot read user data outside `fs_read` (closing `grep -f
    /// /etc/shadow`-style reads) yet can still load its libraries.
    ///
    /// `Execute` is governed only when `exec` is restricted: the *resolved*
    /// granted program files plus [`LOADER_PATHS`] (the dynamic linker only — never
    /// library directories, which `path_beneath` would make recursively executable
    /// and expose `/usr/lib`'s interpreters) are execute-allowed and all else
    /// denied. This kernel-denies a **direct** `execve` of a different, un-granted
    /// tool (`find -exec curl`, a written/symlinked payload, a shebang to an
    /// un-granted interpreter) — the ADR 0011 boundary increment.
    ///
    /// It does **not** close the loader/interpreter *trampoline*: with reads
    /// allow-listed, `ld.so` can `mmap`-exec any readable ELF, and a granted
    /// interpreter runs arbitrary in-process code — neither is an `execve` the
    /// `Execute` rule sees (ADR 0011 D2; Landlock has no `mmap` hook). So this is
    /// the filesystem **boundary** + direct-execve denial, **not** program
    /// identity — the per-axis report therefore keeps `exec → interceptor`, never
    /// `kernel` (ADR 0011 D7); a strong principal still fails closed on a
    /// restricted `exec` (ADR 0012 D4, already wired). The trampoline-tight close
    /// (narrowed read base + W^X + seccomp `execve`/namespace deny, or a
    /// micro-VM rootfs) is the Tier-2 follow-up (#57 / ADR 0009). When an axis is
    /// `All` it stays ambient. `net` remains a follow-up (#35).
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
            // Pure read rights — `from_read` also bundles `Execute`, which we
            // govern separately (only when `exec` is restricted), never via the
            // read axis.
            let read = AccessFs::ReadFile | AccessFs::ReadDir;

            // Govern writes always; govern reads / execute only when their axis is
            // actually restricted (`Only`). `All` means no confinement was asked
            // for, so that axis stays ambient and needs no base allow-list.
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
            let ruleset = Ruleset::default()
                .set_compatibility(CompatLevel::BestEffort)
                .handle_access(handled)
                .map_err(landlock_denied)?
                .create()
                .map_err(landlock_denied)?
                .add_rules(path_beneath_rules(&write_roots, write))
                .map_err(landlock_denied)?;

            let ruleset = if confine_read {
                // Granted read roots + the loader/library/data base list, so a
                // permitted binary loads while out-of-scope reads stay denied.
                let mut read_roots = scope_roots(&effective.fs_read);
                read_roots.extend(BASE_READ_PATHS.iter().map(|p| (*p).to_string()));
                // The program's own binary must be readable to load. When `exec`
                // is confined, read-allow ONLY the resolved granted programs — so
                // the bin dirs stay OUT of the trampoline corpus (`/usr/bin/curl`
                // unreadable ⇒ not `ld.so`-trampolinable; ADR 0011 D3). When `exec`
                // is ambient the program is unknown, so the bin dirs are
                // read-allowed wholesale.
                if confine_exec {
                    read_roots.extend(resolve_exec_paths(&effective.exec));
                } else {
                    read_roots.extend(BIN_READ_PATHS.iter().map(|p| (*p).to_string()));
                }
                read_roots.retain(|p| std::path::Path::new(p).exists());
                ruleset
                    .add_rules(path_beneath_rules(&read_roots, read))
                    .map_err(landlock_denied)?
            } else {
                ruleset
            };

            let ruleset = if confine_exec {
                // Execute-allow ONLY the resolved granted program files plus the
                // dynamic linker(s) — never library directories (recursive +
                // expose `/usr/lib`'s interpreters). A permitted binary still runs
                // (its own execve + the loader + .so reads), but cannot DIRECTLY
                // execve a different, un-granted program.
                let mut exec_roots = resolve_exec_paths(&effective.exec);
                exec_roots.extend(LOADER_PATHS.iter().map(|p| (*p).to_string()));
                exec_roots.retain(|p| std::path::Path::new(p).exists());
                ruleset
                    .add_rules(path_beneath_rules(&exec_roots, AccessFs::Execute))
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

    /// Resolve the granted `exec` scope to absolute, existing program **files**
    /// for the `Execute` allow-list: a path-bearing entry is taken as-is (if it
    /// exists); a bare name is resolved against the exec search dirs. Canonicalized
    /// so the rule anchors the real inode. `All` => empty (exec stays ambient).
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

    /// The directories a bare program name is resolved against: `$PATH` if set,
    /// else a conventional fallback. Used only to anchor the `Execute` allow-list
    /// (the spawn itself still resolves the program normally).
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

#[cfg(all(target_os = "macos", feature = "macos-seatbelt"))]
mod seatbelt_impl {
    use super::{Sandbox, SandboxKind};
    use crate::{Caveats, Scope, ToolError, ToolResult};
    use std::path::Path;

    /// The macOS sandbox wrapper. We invoke it by **absolute path** (never via
    /// `PATH`) so the boundary cannot be shadowed by a `sandbox-exec` planted
    /// earlier in a caller's `PATH`. `sandbox-exec(1)` is deprecated-but-present
    /// on stock macOS; using it keeps the boundary FFI-free, which core requires
    /// (`unsafe_code = "forbid"`).
    const SANDBOX_EXEC: &str = "/usr/bin/sandbox-exec";

    /// Read-side base allow-list (subpaths): the system/loader paths a
    /// dynamically-linked Mach-O binary must read to *start and run* — the
    /// dynamic linker and dyld shared cache (under `/System`, incl. the Cryptex
    /// volume), system dylibs/frameworks, the binaries themselves, the
    /// name-service and locale config (`/private/etc`, the real target of
    /// `/etc`), the dyld closure db, and the `/dev` essentials. Added whenever
    /// `fs_read` is confined, alongside the literal root entry (see
    /// [`seatbelt_profile`]), so a *permitted* program still loads while user
    /// data outside scope stays unreadable. Non-existent entries are dropped
    /// during canonicalization, so extra entries are harmless across macOS
    /// layouts (verified on Apple Silicon: `grep`/`cat`/`cp` load read-confined).
    const BASE_READ_PATHS: &[&str] = &[
        "/usr",
        "/bin",
        "/sbin",
        "/System",
        "/Library",
        "/opt",
        "/private/etc",
        "/private/var/db/dyld",
        "/dev",
    ];

    /// `true` if this host can enforce a Seatbelt profile — i.e. the
    /// `sandbox-exec` wrapper is present. The wrapper itself is the boundary, so
    /// its presence is the capability (the analog of `landlock_is_supported`).
    #[must_use]
    pub fn seatbelt_is_supported() -> bool {
        Path::new(SANDBOX_EXEC).exists()
    }

    /// A real, kernel-enforced Seatbelt sandbox (macOS).
    ///
    /// **The `fs_write` and `fs_read` axes** — the same *axes* the Linux Landlock
    /// backend governs (not necessarily the same path-level strictness; see
    /// below). Confinement is applied by wrapping the spawned program in
    /// `sandbox-exec -p <profile>`, where the SBPL profile is generated from the
    /// effective [`Caveats`] (see [`seatbelt_profile`]): writes are denied
    /// outside the granted `fs_write` roots, and — when `fs_read` is restricted —
    /// reads are denied outside the granted roots plus the loader/system base
    /// list. It also kernel-denies **all** network egress when `net` is empty
    /// (`(deny network*)`) — a confinement Landlock cannot provide, closing the
    /// `find -exec curl` egress path at L3. A non-empty `net` host allowlist is
    /// not expressible in SBPL (it filters by socket, not hostname) and stays
    /// advisory.
    ///
    /// **The `exec` axis** — when restricted, the profile emits
    /// `(deny process-exec*)` and re-allows exactly the granted programs (resolved
    /// to absolute paths). Because `process-exec*` is a kernel-checked operation
    /// applied to the confined process *and everything it spawns*, this confines
    /// the program's **interior** execs — the L3 gap a path allow-list alone
    /// cannot reach. Unlike Landlock, no seccomp backstop is needed: the loader
    /// trampoline (`dyld TARGET`) is itself a governed `process-exec`, and the
    /// `mmap(PROT_EXEC)` read-as-code path is closed by Apple-Silicon hardware
    /// W^X + code signing — so "the readable set equals the runnable set" (the
    /// fact that forces the Linux seccomp filter) does **not** hold here. The axis
    /// is therefore honestly reported `Kernel` (ADR 0014; agent-bridle#31/#57).
    ///
    /// Read confinement here is **content-level**: file *metadata* (stat,
    /// existence, directory traversal) stays ambient so binaries can load through
    /// symlink ancestors, and the system read base ([`BASE_READ_PATHS`], incl.
    /// `/private/etc`) is broadly readable — looser than Landlock's file-level
    /// `/etc` allow-list, but the protected resource (out-of-scope file
    /// *contents*, the exfil threat) is denied identically. macOS keeps user
    /// secrets in the Keychain and `$HOME`, not `/etc`.
    ///
    /// Unlike Landlock's per-thread `restrict_self`, Seatbelt confinement is
    /// carried by the wrapper process and inherited by the child, so
    /// [`Sandbox::apply`] is a no-op and the boundary lives entirely in
    /// [`Sandbox::command_prefix`].
    #[derive(Debug, Default, Clone, Copy)]
    pub struct SeatbeltSandbox;

    impl SeatbeltSandbox {
        /// Construct the sandbox. (Stateless; capability comes from the OS.)
        #[must_use]
        pub fn new() -> Self {
            Self
        }
    }

    impl Sandbox for SeatbeltSandbox {
        fn kind(&self) -> SandboxKind {
            SandboxKind::Seatbelt
        }

        fn apply(&self, _effective: &Caveats) -> ToolResult<()> {
            // Deliberate no-op: Seatbelt confines via the `sandbox-exec` wrapper
            // (see `command_prefix`), not by restricting the calling thread. The
            // boundary is the wrapped spawn.
            Ok(())
        }

        fn command_prefix(&self, effective: &Caveats) -> ToolResult<Vec<String>> {
            // Nothing on a governed axis (fs, all-egress-denied or loopback-only
            // net, or a restricted exec allow-list) => nothing to confine; run
            // unwrapped (coarse honesty falls to `None` upstream, and the per-axis
            // report omits unrestricted axes).
            if !super::restricts_fs(effective)
                && !super::net_fully_denied(effective)
                && !super::net_loopback_only(effective)
                && !super::restricts_exec(effective)
            {
                return Ok(Vec::new());
            }
            // Fail-closed: if the wrapper is gone we cannot enforce, so refuse
            // rather than hand back an empty (silently unconfined) prefix.
            if !seatbelt_is_supported() {
                return Err(ToolError::denied(
                    "macOS seatbelt: /usr/bin/sandbox-exec is unavailable; cannot confine",
                ));
            }
            Ok(vec![
                SANDBOX_EXEC.to_string(),
                "-p".to_string(),
                seatbelt_profile(effective),
            ])
        }
    }

    /// Generate the SBPL profile for `effective`. **Pure** (modulo path
    /// canonicalization against the real filesystem); no spawning.
    ///
    /// Model (the macOS analog of Landlock handling only the write/read access
    /// rights and leaving the rest ambient): start from `(allow default)` so
    /// unhandled operations — `exec`, `network`, mach lookups a normal process
    /// needs — stay ambient, then `(deny file-write*)` / `(deny file-read*)` for
    /// a restricted axis and re-allow exactly the granted roots (canonicalized,
    /// so `/tmp` → `/private/tmp` matches). An empty `fs_write` scope emits the
    /// deny with no re-allow — every write denied. SBPL evaluates last-match-wins,
    /// so the trailing allow-roots override the deny.
    #[must_use]
    pub fn seatbelt_profile(effective: &Caveats) -> String {
        let mut p = String::from("(version 1)\n(allow default)\n");

        // fs_write: deny writes, then re-allow the granted roots.
        if let Scope::Only(_) = &effective.fs_write {
            p.push_str("(deny file-write*)\n");
            let roots = confined_roots(&effective.fs_write);
            if !roots.is_empty() {
                p.push_str("(allow file-write*");
                for r in &roots {
                    p.push_str(&format!(" (subpath {})", sbpl_string(r)));
                }
                p.push_str(")\n");
            }
        }

        // fs_read: deny reads, then re-allow. `(allow file-read-metadata)`
        // permits path *traversal* and `stat` everywhere — without it, reaching
        // an in-scope file through a symlink ancestor (`/tmp`, `/var`, `/etc` →
        // `/private/…`) is denied at the symlink lookup. Metadata reveals only
        // existence/size, never **content**; the data axis stays confined to the
        // loader/system base, the root directory *entry* (dyld reads `/` itself),
        // and the granted roots — so a permitted program loads and reads in-scope
        // files while out-of-scope file *contents* (the exfil threat) stay denied.
        if let Scope::Only(_) = &effective.fs_read {
            p.push_str("(deny file-read*)\n");
            p.push_str("(allow file-read-metadata)\n");
            p.push_str("(allow file-read* (literal \"/\")");
            for base in BASE_READ_PATHS {
                if let Some(c) = canonical_path(base) {
                    p.push_str(&format!(" (subpath {})", sbpl_string(&c)));
                }
            }
            for r in confined_roots(&effective.fs_read) {
                p.push_str(&format!(" (subpath {})", sbpl_string(&r)));
            }
            p.push_str(")\n");
        }

        // net: SBPL can name only `*`/`localhost` + ports as a remote (an
        // arbitrary IP is rejected: "host must be * or localhost"; ADR 0015), so a
        // general host allowlist is inexpressible and left ambient (reported
        // advisory, never silently dropped). The two policies it *can* enforce:
        //   • empty scope  → `(deny network*)`: every socket kernel-denied — a
        //     confinement no Landlock increment can supply.
        //   • loopback-only allowlist → deny all, then re-allow the loopback
        //     interface (`localhost` = 127.0.0.1 + ::1). The process's own off-box
        //     socket egress stays kernel-denied; the exact loopback host is narrowed
        //     by admission. Last-match-wins, so the allow overrides.
        if super::net_fully_denied(effective) {
            p.push_str("(deny network*)\n");
        } else if super::net_loopback_only(effective) {
            p.push_str("(deny network*)\n");
            p.push_str("(allow network* (remote ip \"localhost:*\"))\n");
        }

        // exec: deny *all* further execs, then re-allow exactly the granted
        // programs (resolved to absolute, canonical paths). `process-exec*` is
        // kernel-checked on the confined process AND everything it spawns, so this
        // is the `exec` axis at interior grain — no seccomp backstop needed (the
        // dyld trampoline is itself a governed `process-exec`, and `mmap(PROT_EXEC)`
        // read-as-code is closed by hardware W^X + code signing; ADR 0014). An
        // empty/unresolvable grant emits the deny with no re-allow — every exec
        // (including the wrapped program's own launch) denied: fail-closed, never
        // ambient. SBPL is last-match-wins, so the trailing allow overrides.
        if let Scope::Only(_) = &effective.exec {
            p.push_str("(deny process-exec*)\n");
            let targets = resolve_exec_targets(&effective.exec);
            if !targets.is_empty() {
                p.push_str("(allow process-exec*");
                for t in &targets {
                    p.push_str(&format!(" (literal {})", sbpl_string(t)));
                }
                p.push_str(")\n");
            }
        }

        p
    }

    /// The canonicalized, existing roots a restricted [`Scope`] grants. A path
    /// that cannot be resolved to any existing ancestor is dropped (it cannot
    /// anchor a rule — safe, since its parent is ungranted, so access beneath it
    /// stays denied). `All` yields nothing (callers only pass a restricted axis).
    fn confined_roots(scope: &Scope<String>) -> Vec<String> {
        let Scope::Only(set) = scope else {
            return Vec::new();
        };
        let mut roots: Vec<String> = set.iter().filter_map(|p| canonical_path(p)).collect();
        roots.sort();
        roots.dedup();
        roots
    }

    /// System binary directories searched to resolve a **bare-name** `exec` grant
    /// (e.g. `["git"]`) to absolute path(s) for the `process-exec*` allow-list.
    /// SIP-protected, read-only system locations — a trustworthy pin. Bare names
    /// resolve through this *fixed* list, never the ambient `$PATH` (ADR 0014 /
    /// ADR 0011 D5), so a binary planted earlier on a caller's `$PATH` cannot
    /// widen the kernel allow-list. An absolute-path grant is honored verbatim
    /// (then canonicalized); a basename collision outside these dirs is not.
    const TRUSTED_EXEC_DIRS: &[&str] = &["/usr/bin", "/bin", "/usr/sbin", "/sbin"];

    /// Resolve a restricted `exec` [`Scope`] to the absolute, canonical program
    /// paths that anchor the SBPL `(allow process-exec* (literal …))` rules. The
    /// kernel matches `process-exec` against the *resolved* path of the exec
    /// target, so each grant must become a realpath: an absolute grant is
    /// canonicalized; a bare name is resolved against [`TRUSTED_EXEC_DIRS`] (each
    /// existing hit included, mirroring admission's basename semantics in
    /// [`crate::context`] but pinned to trusted dirs). A relative-path or
    /// unresolvable grant is dropped — it cannot anchor a rule, so the program
    /// stays denied (fail-closed). `All` yields nothing (callers pass a restricted
    /// axis). Results are sorted+deduped so the emitted profile is deterministic.
    fn resolve_exec_targets(scope: &Scope<String>) -> Vec<String> {
        let Scope::Only(set) = scope else {
            return Vec::new();
        };
        let canon_file = |path: &Path, out: &mut Vec<String>| {
            if let Ok(c) = std::fs::canonicalize(path) {
                if c.is_file() {
                    out.push(c.to_string_lossy().into_owned());
                }
            }
        };
        let mut out: Vec<String> = Vec::new();
        for token in set {
            if token.starts_with('/') {
                // Absolute grant: honored verbatim (canonicalized, must exist).
                canon_file(Path::new(token), &mut out);
            } else if !token.contains('/') {
                // Bare name: resolve against the fixed trusted system dirs only.
                for dir in TRUSTED_EXEC_DIRS {
                    canon_file(&Path::new(dir).join(token), &mut out);
                }
            }
            // else: a relative path grant cannot anchor a kernel rule safely — drop.
        }
        out.sort();
        out.dedup();
        out
    }

    /// Resolve `p` to an absolute, symlink-free path suitable for `(subpath …)`
    /// matching, which the kernel performs against the *resolved* path (so a
    /// granted `/tmp/x` must become `/private/tmp/x` or it never matches). If the
    /// leaf does not yet exist, canonicalize the longest existing ancestor and
    /// re-append the remainder. `None` if not even an ancestor resolves.
    fn canonical_path(p: &str) -> Option<String> {
        let path = Path::new(p);
        if let Ok(c) = std::fs::canonicalize(path) {
            return Some(c.to_string_lossy().into_owned());
        }
        let mut tail: Vec<std::ffi::OsString> = Vec::new();
        let mut cur = path;
        while let Some(parent) = cur.parent() {
            if let Some(name) = cur.file_name() {
                tail.push(name.to_owned());
            }
            if let Ok(c) = std::fs::canonicalize(parent) {
                let mut resolved = c;
                for seg in tail.iter().rev() {
                    resolved.push(seg);
                }
                return Some(resolved.to_string_lossy().into_owned());
            }
            cur = parent;
        }
        None
    }

    /// Quote `s` as an SBPL string literal, escaping `\` and `"` so a crafted
    /// path can never break out of the quotes and inject profile syntax.
    fn sbpl_string(s: &str) -> String {
        let mut out = String::with_capacity(s.len() + 2);
        out.push('"');
        for ch in s.chars() {
            if ch == '\\' || ch == '"' {
                out.push('\\');
            }
            out.push(ch);
        }
        out.push('"');
        out
    }

    #[cfg(test)]
    mod unit {
        use super::*;
        use crate::Scope;

        #[test]
        fn unrestricted_caveats_make_no_wrapper() {
            assert!(SeatbeltSandbox::new()
                .command_prefix(&Caveats::top())
                .unwrap()
                .is_empty());
        }

        #[test]
        fn empty_net_denies_all_egress_and_engages_the_wrapper() {
            // net:none with fs unrestricted still confines (network), so the
            // wrapper must engage and the profile must deny all egress.
            let cav = Caveats {
                net: Scope::none(),
                ..Caveats::top()
            };
            let prof = seatbelt_profile(&cav);
            assert!(prof.contains("(deny network*)"), "{prof}");
            assert!(
                !SeatbeltSandbox::new()
                    .command_prefix(&cav)
                    .unwrap()
                    .is_empty(),
                "net:none must engage the sandbox-exec wrapper"
            );
        }

        #[test]
        fn nonempty_net_allowlist_is_not_denied() {
            // A general (non-loopback) host allowlist is not expressible in SBPL —
            // it can name only `*`/`localhost` + ports as a remote — so no network
            // rule is emitted; left ambient (advisory), never silently dropped.
            let cav = Caveats {
                net: Scope::only(["example.com".to_string()]),
                ..Caveats::top()
            };
            let prof = seatbelt_profile(&cav);
            assert!(
                !prof.contains("network"),
                "non-loopback net must stay ambient: {prof}"
            );
        }

        #[test]
        fn loopback_only_net_confines_to_loopback_and_engages() {
            // A loopback-only allowlist IS expressible: deny all egress, then
            // re-allow the loopback interface (ADR 0015). Off-box egress stays
            // kernel-denied; the wrapper engages even with fs/exec unrestricted.
            for host in ["localhost", "127.0.0.1", "::1"] {
                let cav = Caveats {
                    net: Scope::only([host.to_string()]),
                    ..Caveats::top()
                };
                let prof = seatbelt_profile(&cav);
                assert!(prof.contains("(deny network*)"), "{host}: {prof}");
                assert!(
                    prof.contains("(allow network* (remote ip \"localhost:*\"))"),
                    "{host}: loopback re-allow missing: {prof}"
                );
                assert!(
                    !SeatbeltSandbox::new()
                        .command_prefix(&cav)
                        .unwrap()
                        .is_empty(),
                    "{host}: a loopback-only net grant must engage the wrapper"
                );
            }
        }

        #[test]
        fn mixed_loopback_and_remote_host_stays_ambient() {
            // A single non-loopback host taints the set: SBPL cannot express the
            // remote, so the whole allowlist stays ambient (advisory) rather than
            // emit a rule that would silently drop `example.com`.
            let cav = Caveats {
                net: Scope::only(["localhost".to_string(), "example.com".to_string()]),
                ..Caveats::top()
            };
            let prof = seatbelt_profile(&cav);
            assert!(
                !prof.contains("network"),
                "a mixed loopback+remote allowlist must stay ambient: {prof}"
            );
        }

        #[test]
        fn restricted_write_yields_sandbox_exec_wrapper() {
            let cav = Caveats {
                fs_write: Scope::only(["/tmp".to_string()]),
                ..Caveats::top()
            };
            let prefix = SeatbeltSandbox::new().command_prefix(&cav).unwrap();
            assert_eq!(prefix[0], SANDBOX_EXEC);
            assert_eq!(prefix[1], "-p");
            assert!(prefix[2].contains("(deny file-write*)"));
        }

        #[test]
        fn profile_denies_then_reallows_write_roots() {
            let cav = Caveats {
                fs_write: Scope::only(["/tmp".to_string()]),
                ..Caveats::top()
            };
            let prof = seatbelt_profile(&cav);
            assert!(prof.contains("(allow default)"));
            assert!(prof.contains("(deny file-write*)"));
            // `/tmp` must be canonicalized to its real target for subpath match.
            assert!(prof.contains("(subpath \"/private/tmp\")"), "{prof}");
            // No read axis restricted => no read deny.
            assert!(!prof.contains("(deny file-read*)"));
        }

        #[test]
        fn empty_write_scope_denies_all_writes_no_allow() {
            let cav = Caveats {
                fs_write: Scope::none(),
                ..Caveats::top()
            };
            let prof = seatbelt_profile(&cav);
            assert!(prof.contains("(deny file-write*)"));
            assert!(
                !prof.contains("(allow file-write*"),
                "an empty scope must grant no write roots: {prof}"
            );
        }

        #[test]
        fn restricted_read_includes_loader_base_and_root_entry() {
            let cav = Caveats {
                fs_read: Scope::only(["/tmp".to_string()]),
                ..Caveats::top()
            };
            let prof = seatbelt_profile(&cav);
            assert!(prof.contains("(deny file-read*)"));
            assert!(prof.contains("(literal \"/\")"), "{prof}");
            assert!(prof.contains("(subpath \"/usr\")"), "{prof}");
            assert!(prof.contains("(subpath \"/System\")"), "{prof}");
        }

        #[test]
        fn sbpl_string_escapes_quotes_and_backslashes() {
            assert_eq!(sbpl_string("/a/b"), "\"/a/b\"");
            assert_eq!(sbpl_string("/a\"b"), "\"/a\\\"b\"");
            assert_eq!(sbpl_string("/a\\b"), "\"/a\\\\b\"");
        }

        /// Count double-quotes that are *not* backslash-escaped — the structural
        /// quotes SBPL actually sees. Each `(subpath "…")` term I emit
        /// contributes exactly two; any extra would mean a path broke out of its
        /// literal.
        fn unescaped_quotes(s: &str) -> usize {
            let b = s.as_bytes();
            (0..b.len())
                .filter(|&i| b[i] == b'"' && (i == 0 || b[i - 1] != b'\\'))
                .count()
        }

        #[test]
        fn crafted_path_cannot_inject_profile_syntax() {
            // A path crafted to close the string and add its own allow rule must
            // stay inside one escaped literal — its quotes get backslash-escaped,
            // so SBPL sees exactly the two structural quotes of the single term.
            let cav = Caveats {
                fs_write: Scope::only(["/tmp/x\") (allow file-write* (subpath \"/".to_string()]),
                ..Caveats::top()
            };
            let prof = seatbelt_profile(&cav);
            assert_eq!(
                unescaped_quotes(&prof),
                2,
                "exactly one structural (subpath \"…\") term — no breakout: {prof}"
            );
            assert!(
                prof.contains("\\\""),
                "the crafted quotes must be backslash-escaped: {prof}"
            );
        }

        #[test]
        fn restricted_exec_emits_deny_and_allowlist() {
            let cav = Caveats {
                exec: Scope::only(["/bin/echo".to_string()]),
                ..Caveats::top()
            };
            let prof = seatbelt_profile(&cav);
            assert!(prof.contains("(deny process-exec*)"), "{prof}");
            assert!(
                prof.contains("(allow process-exec* (literal \"/bin/echo\")"),
                "{prof}"
            );
        }

        #[test]
        fn bare_name_exec_resolves_through_trusted_dirs() {
            // A bare name is pinned to the fixed trusted system dirs, never $PATH.
            let cav = Caveats {
                exec: Scope::only(["true".to_string()]),
                ..Caveats::top()
            };
            let prof = seatbelt_profile(&cav);
            // `/usr/bin/true` exists on every macOS host and canonicalizes to
            // itself, so the literal must name the absolute resolved path.
            assert!(
                prof.contains("(literal \"/usr/bin/true\")"),
                "bare name must resolve to its trusted-dir absolute path: {prof}"
            );
        }

        #[test]
        fn restricted_exec_engages_the_wrapper() {
            // exec-only (no fs/net restriction) must still engage sandbox-exec.
            let cav = Caveats {
                exec: Scope::only(["/bin/echo".to_string()]),
                ..Caveats::top()
            };
            let prefix = SeatbeltSandbox::new().command_prefix(&cav).unwrap();
            assert_eq!(prefix.first().map(String::as_str), Some(SANDBOX_EXEC));
        }

        #[test]
        fn empty_exec_scope_denies_all_exec_with_no_allow() {
            // exec:none — the program may exec nothing. The deny is emitted with no
            // re-allow, so even the wrapped program's launch is denied: fail-closed,
            // never silently ambient.
            let cav = Caveats {
                exec: Scope::none(),
                ..Caveats::top()
            };
            let prof = seatbelt_profile(&cav);
            assert!(prof.contains("(deny process-exec*)"), "{prof}");
            assert!(
                !prof.contains("(allow process-exec*"),
                "an empty exec scope must grant no exec targets: {prof}"
            );
        }

        #[test]
        fn relative_and_unresolvable_exec_grants_are_dropped() {
            // A relative-path grant cannot anchor a kernel rule; a bare name with no
            // trusted-dir hit resolves to nothing. Either way: deny with no allow.
            let cav = Caveats {
                exec: Scope::only(["./payload".to_string(), "no-such-binary-xyzzy".to_string()]),
                ..Caveats::top()
            };
            let prof = seatbelt_profile(&cav);
            assert!(prof.contains("(deny process-exec*)"), "{prof}");
            assert!(
                !prof.contains("(allow process-exec*"),
                "unresolvable/relative grants must not anchor an allow: {prof}"
            );
        }

        #[test]
        fn unrestricted_exec_emits_no_exec_rules() {
            // exec:All (the default) is ambient on the exec axis — no rules.
            let prof = seatbelt_profile(&Caveats::top());
            assert!(!prof.contains("process-exec"), "{prof}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Scope;

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
            serde_json::to_string(&SandboxKind::Seatbelt).unwrap(),
            "\"seatbelt\""
        );
        assert_eq!(
            serde_json::to_string(&SandboxKind::AppContainer).unwrap(),
            "\"app_container\""
        );
        assert_eq!(
            serde_json::to_string(&SandboxKind::MinimalRootfs).unwrap(),
            "\"minimal_rootfs\""
        );
        assert_eq!(
            serde_json::to_string(&SandboxKind::MicroVm).unwrap(),
            "\"micro_vm\""
        );
    }

    #[test]
    fn effective_kind_downgrades_to_none_when_no_fs_axis_restricted() {
        // The honesty rule (I9): a backend that confines nothing must not be
        // reported. With every axis `All`, even a real backend → None. (For
        // AppContainer the rule keeps it `None` here regardless — its shell/spawn
        // launcher is a follow-up, so it is not engaged via this path yet.)
        for available in [
            SandboxKind::Landlock,
            SandboxKind::Seatbelt,
            SandboxKind::AppContainer,
            SandboxKind::None,
        ] {
            assert_eq!(
                effective_sandbox_kind(available, &Caveats::top()),
                SandboxKind::None,
                "unrestricted fs must report None for {available:?}"
            );
        }
        // With a restricted fs axis, the backend's own kind is reported …
        let restricted = Caveats {
            fs_write: Scope::only(["/w".to_string()]),
            ..Caveats::top()
        };
        assert_eq!(
            effective_sandbox_kind(SandboxKind::Landlock, &restricted),
            SandboxKind::Landlock
        );
        assert_eq!(
            effective_sandbox_kind(SandboxKind::Seatbelt, &restricted),
            SandboxKind::Seatbelt
        );
        // … except a None host is always None (nothing to enforce with).
        assert_eq!(
            effective_sandbox_kind(SandboxKind::None, &restricted),
            SandboxKind::None
        );
        // A restricted *read* axis also engages (Landlock/Seatbelt govern reads).
        let read_only = Caveats {
            fs_read: Scope::only(["/r".to_string()]),
            ..Caveats::top()
        };
        assert_eq!(
            effective_sandbox_kind(SandboxKind::Seatbelt, &read_only),
            SandboxKind::Seatbelt
        );
        // An empty net scope (all egress denied), even with fs unrestricted,
        // engages Seatbelt (it kernel-denies network) but NOT Landlock (which
        // cannot gate net) — capabilities differ, so honesty differs.
        let net_denied = Caveats {
            net: Scope::none(),
            ..Caveats::top()
        };
        assert_eq!(
            effective_sandbox_kind(SandboxKind::Seatbelt, &net_denied),
            SandboxKind::Seatbelt,
            "Seatbelt kernel-denies egress, so net:none engages it"
        );
        assert_eq!(
            effective_sandbox_kind(SandboxKind::Landlock, &net_denied),
            SandboxKind::None,
            "Landlock cannot gate net, so net:none must NOT report Landlock"
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

    /// #57 boundary: with `exec` confined to `cat`, the granted program (and its
    /// libraries) still runs, but a DIRECT `execve` of an un-granted tool (`head`)
    /// — the `find -exec curl` escape in miniature — is kernel-denied by the
    /// `Execute` allow-list. (This is the boundary/direct-execve close, NOT the
    /// trampoline; `exec` stays reported `interceptor`, ADR 0011 D7.)
    #[test]
    fn exec_direct_execve_of_ungranted_tool_is_kernel_denied() {
        if skip_proof_unless_landlock() {
            return;
        }
        let dir = unique_dir("exec");
        fs::write(dir.join("data.txt"), b"payload\n").unwrap();
        let dir_t = dir.clone();

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

        // execve of the un-granted binary is kernel-denied: std surfaces the
        // post-fork exec failure as a PermissionDenied spawn error.
        let err = ungranted.expect_err("un-granted `head` must be exec-denied by Landlock");
        assert_eq!(
            err.kind(),
            std::io::ErrorKind::PermissionDenied,
            "the denial must come from the kernel (EACCES on execve)"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    /// #57 adversarial sweep: with `exec` confined to `cat` and writes confined to
    /// a scratch dir, EVERY classic "make the permitted program launch something
    /// else" DIRECT-execve escape must be kernel-denied — an un-granted tool, a
    /// payload the context could write+run, a shebang script (un-granted
    /// interpreter), a symlink to an un-granted tool, and the real
    /// shells/interpreters that live under `/usr/lib*` (which a recursive lib-dir
    /// Execute grant — the narrowing this avoids — would have exposed). The
    /// granted program still works (control). (Direct-execve boundary only; the
    /// ld.so/interpreter trampoline is out of scope — `exec` stays `interceptor`.)
    #[test]
    fn exec_escape_attempts_are_all_denied() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        if skip_proof_unless_landlock() {
            return;
        }
        let scratch = unique_dir("exec-escape"); // in fs_write scope
        fs::write(scratch.join("data.txt"), b"ok\n").unwrap();

        // A real ELF the confined context could try to run from the scratch dir (a
        // "written payload"); copy an existing binary to avoid needing a compiler.
        let payload = scratch.join("payload");
        if let Ok(src) = std::fs::read("/bin/cat").or_else(|_| std::fs::read("/usr/bin/cat")) {
            fs::write(&payload, src).unwrap();
            fs::set_permissions(&payload, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        // A shebang script + a symlink to an un-granted interpreter.
        let script = scratch.join("script.sh");
        fs::write(&script, b"#!/bin/sh\necho pwned\n").unwrap();
        fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        let link = scratch.join("sh-link");
        let _ = symlink("/bin/sh", &link);

        // Real shells/interpreters that live UNDER the library tree (/usr/lib*):
        // loader-only Execute must deny them. Tested only where present.
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
        let (attempts, control) = std::thread::spawn(move || {
            let cav = Caveats {
                exec: Scope::only(["cat".to_string()]),
                fs_write: Scope::only([scratch_t.to_string_lossy().into_owned()]),
                ..Caveats::top()
            };
            LandlockSandbox::new().apply(&cav).expect("apply landlock");

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

    /// #57 / ADR 0011 D3: when BOTH `exec` and `fs_read` are confined, the read
    /// base excludes the bin dirs — the granted program (and its libs) still
    /// loads, but an un-granted system binary is NOT readable, so it cannot be
    /// `ld.so`-trampolined (the trampoline corpus is shrunk to the granted set).
    #[test]
    fn read_base_excludes_bin_dirs_when_exec_confined() {
        if skip_proof_unless_landlock() {
            return;
        }
        let dir = unique_dir("read-narrow");
        fs::write(dir.join("data.txt"), b"payload\n").unwrap();
        let dir_t = dir.clone();

        let (granted, head_bytes) = std::thread::spawn(move || {
            let cav = Caveats {
                exec: Scope::only(["cat".to_string()]),
                fs_read: Scope::only([dir_t.to_string_lossy().into_owned()]),
                ..Caveats::top()
            };
            LandlockSandbox::new().apply(&cav).expect("apply landlock");
            // Granted `cat` loads (its binary + libs are read-allowed) and reads
            // the in-scope file.
            let granted = std::process::Command::new("cat")
                .arg(dir_t.join("data.txt"))
                .output();
            // Reading an un-granted bin-dir binary's bytes (a would-be trampoline
            // payload) is denied — the bin dirs are not in the read set.
            let head_bytes = std::fs::read("/usr/bin/head").or_else(|_| std::fs::read("/bin/head"));
            (granted, head_bytes)
        })
        .join()
        .unwrap();

        let granted = granted.expect("granted `cat` must load + run under narrowed reads");
        assert!(
            granted.status.success() && granted.stdout == b"payload\n",
            "granted cat under narrowed reads: {granted:?}"
        );
        assert!(
            head_bytes.is_err(),
            "an un-granted bin-dir binary must be unreadable (trampoline corpus shrunk): {head_bytes:?}"
        );

        let _ = fs::remove_dir_all(&dir);
    }
}

// Real kernel-enforcement proof for macOS Seatbelt. Only meaningful on macOS
// with the feature; it asserts the leash is the *kernel's* (sandbox-exec's),
// not ours — the spawned child's own out-of-scope writes/reads are denied even
// though L2 cannot see its syscalls. Mirrors the Landlock proofs above.
#[cfg(all(target_os = "macos", feature = "macos-seatbelt", test))]
mod seatbelt_kernel_tests {
    use super::*;
    use crate::Scope;
    use std::fs;
    use std::path::PathBuf;

    /// Whether a proof should run, skip, or hard-**FAIL** — the same gate as the
    /// Landlock proofs (#74): *required but unsupported is a FAILURE*, so a
    /// macOS CI job that sets `BRIDLE_REQUIRE_SEATBELT` can never go green with
    /// the kernel boundary unexercised.
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

    /// `true` if the caller should skip the proof. **Panics** when Seatbelt is
    /// *required* (`BRIDLE_REQUIRE_SEATBELT` set, as a macOS CI job does) but the
    /// host lacks `sandbox-exec`. A local run without the flag legitimately skips.
    fn skip_proof_unless_seatbelt() -> bool {
        let required = std::env::var("BRIDLE_REQUIRE_SEATBELT")
            .map(|v| !v.is_empty() && v != "0")
            .unwrap_or(false);
        match proof_gate(seatbelt_is_supported(), required) {
            ProofGate::Run => false,
            ProofGate::Skip => {
                eprintln!(
                    "skipping Seatbelt proof: /usr/bin/sandbox-exec unavailable \
                     (set BRIDLE_REQUIRE_SEATBELT=1 to require it, as macOS CI does)"
                );
                true
            }
            ProofGate::Fail => panic!(
                "BRIDLE_REQUIRE_SEATBELT is set but /usr/bin/sandbox-exec is unavailable — \
                 the fs_write/fs_read kernel-enforcement proofs cannot be verified"
            ),
        }
    }

    fn unique_dir(tag: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let mut d = std::env::temp_dir();
        d.push(format!(
            "agent-bridle-sb-{}-{}-{}",
            tag,
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&d).unwrap();
        d
    }

    /// Spawn `program args` through the real `sandbox-exec` wrapper that
    /// [`SeatbeltSandbox::command_prefix`] builds for `cav`, and return its exit
    /// status. This exercises the *production* profile path end to end.
    fn run_wrapped(cav: &Caveats, program: &str, args: &[&str]) -> std::process::ExitStatus {
        let prefix = SeatbeltSandbox::new()
            .command_prefix(cav)
            .expect("a restricted axis must yield a wrapper prefix");
        assert!(!prefix.is_empty(), "expected a sandbox-exec wrapper");
        std::process::Command::new(&prefix[0])
            .args(&prefix[1..])
            .arg(program)
            .args(args)
            .status()
            .expect("spawn sandbox-exec")
    }

    #[test]
    fn proof_gate_required_but_unsupported_is_a_failure() {
        assert_eq!(proof_gate(true, false), ProofGate::Run);
        assert_eq!(proof_gate(true, true), ProofGate::Run);
        assert_eq!(proof_gate(false, false), ProofGate::Skip);
        assert_eq!(proof_gate(false, true), ProofGate::Fail);
    }

    #[test]
    fn fs_write_is_kernel_enforced_outside_scope_denied_inside_allowed() {
        if skip_proof_unless_seatbelt() {
            return;
        }
        let allowed = unique_dir("w-allowed");
        let forbidden = unique_dir("w-forbidden");
        let cav = Caveats {
            fs_write: Scope::only([allowed.to_string_lossy().into_owned()]),
            ..Caveats::top()
        };

        let inside = run_wrapped(
            &cav,
            "/usr/bin/touch",
            &[allowed.join("ok.txt").to_str().unwrap()],
        );
        assert!(
            inside.success(),
            "writing within fs_write scope must succeed"
        );
        assert!(
            allowed.join("ok.txt").exists(),
            "the in-scope file must exist"
        );

        let outside = run_wrapped(
            &cav,
            "/usr/bin/touch",
            &[forbidden.join("escape.txt").to_str().unwrap()],
        );
        assert!(
            !outside.success(),
            "the kernel must deny a write outside fs_write scope"
        );
        assert!(
            !forbidden.join("escape.txt").exists(),
            "the out-of-scope file must NOT have been created"
        );

        let _ = fs::remove_dir_all(&allowed);
        let _ = fs::remove_dir_all(&forbidden);
    }

    #[test]
    fn empty_fs_write_scope_denies_all_writes() {
        if skip_proof_unless_seatbelt() {
            return;
        }
        let dir = unique_dir("w-none");
        let cav = Caveats {
            fs_write: Scope::none(),
            ..Caveats::top()
        };
        let target = dir.join("x.txt");
        let prefix = SeatbeltSandbox::new().command_prefix(&cav).expect("prefix");
        let out = std::process::Command::new(&prefix[0])
            .args(&prefix[1..])
            .arg("/usr/bin/touch")
            .arg(&target)
            .output()
            .expect("spawn sandbox-exec");
        assert!(!out.status.success(), "empty fs_write must deny all writes");
        // Positive control: the failure is the *kernel* denying the write (EPERM),
        // not a spurious touch error — so this assertion cannot pass vacuously.
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("Operation not permitted"),
            "denial must be a sandbox EPERM, got: {stderr:?}"
        );
        assert!(!target.exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn fs_read_is_kernel_enforced_outside_scope_denied_inside_allowed() {
        if skip_proof_unless_seatbelt() {
            return;
        }
        let allowed = unique_dir("r-allowed");
        let forbidden = unique_dir("r-forbidden");
        fs::write(allowed.join("ok.txt"), b"in-scope").unwrap();
        fs::write(forbidden.join("secret.txt"), b"out-of-scope").unwrap();
        let cav = Caveats {
            fs_read: Scope::only([allowed.to_string_lossy().into_owned()]),
            ..Caveats::top()
        };

        // A real dynamically-linked binary (`cat`) must still load (the base
        // allow-list covers dyld) and read the in-scope file …
        let inside = run_wrapped(
            &cav,
            "/bin/cat",
            &[allowed.join("ok.txt").to_str().unwrap()],
        );
        assert!(
            inside.success(),
            "in-scope cat must load and read under read-confinement"
        );
        // … but be denied the out-of-scope one.
        let outside = run_wrapped(
            &cav,
            "/bin/cat",
            &[forbidden.join("secret.txt").to_str().unwrap()],
        );
        assert!(
            !outside.success(),
            "reading outside fs_read scope must be kernel-denied"
        );

        let _ = fs::remove_dir_all(&allowed);
        let _ = fs::remove_dir_all(&forbidden);
    }

    #[test]
    fn net_fully_denied_kernel_blocks_egress() {
        if skip_proof_unless_seatbelt() {
            return;
        }
        let curl = "/usr/bin/curl";
        if !std::path::Path::new(curl).exists() {
            eprintln!("skipping: no curl(1) on this host");
            return;
        }
        let cav = Caveats {
            net: Scope::none(),
            ..Caveats::top()
        };
        // Positive control: a benign NON-network command under the SAME net:none
        // profile must succeed — proving the profile parsed and only egress is
        // denied. Without this, a malformed `(deny network*)` (sandbox-exec exit
        // 65, child never launches) would let the denial assertion pass vacuously.
        let benign = run_wrapped(&cav, "/bin/echo", &["ok"]);
        assert!(
            benign.success(),
            "net:none must still allow non-network commands (profile must parse)"
        );
        // Egress denied: curl to a literal IP (no DNS) exits **7** ("couldn't
        // connect") because the socket is kernel-denied immediately. Asserting
        // exactly 7 — not merely non-zero — rules out the vacuous passes: a
        // no-egress host times out (28), a broken profile never launches the child
        // (65). `--max-time` bounds it regardless.
        let confined = run_wrapped(&cav, curl, &["-sS", "--max-time", "5", "http://1.1.1.1/"]);
        assert_eq!(
            confined.code(),
            Some(7),
            "egress under net:none must be kernel-denied at the socket (curl exit 7)"
        );
    }

    /// A one-shot loopback listener answering a single HTTP request, so an ALLOW
    /// assertion tests a *reachable* socket (curl 0) — not "connection refused"
    /// (also 7). Detached, so an unexpected deny can't hang the test on a
    /// never-accepted connection. Returns the bound `SocketAddr`, or `None` if the
    /// family is unavailable on this host (e.g. no `::1`), so a caller can skip.
    fn spawn_loopback_http(bind: &str) -> Option<std::net::SocketAddr> {
        let listener = std::net::TcpListener::bind(bind).ok()?;
        let addr = listener.local_addr().ok()?;
        std::thread::spawn(move || {
            if let Ok((mut sock, _)) = listener.accept() {
                use std::io::{Read, Write};
                let mut buf = [0u8; 1024];
                let _ = sock.read(&mut buf);
                let _ = sock.write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok");
            }
        });
        Some(addr)
    }

    /// A loopback-only `net` grant kernel-confines egress to the loopback
    /// *interface* (ADR 0015): the process reaches loopback (v4 **and** v6, since
    /// SBPL's `localhost` denotes both) and is kernel-DENIED any off-box host. The
    /// grant here names a **single** v4 address (`127.0.0.1`) yet `::1` is still
    /// reachable — the documented interface-granular widening (D2): a spawned child
    /// is governed only by the kernel rule, not the exact-host admission leash.
    #[test]
    fn net_loopback_only_permits_loopback_interface_denies_offbox() {
        if skip_proof_unless_seatbelt() {
            return;
        }
        let curl = "/usr/bin/curl";
        if !std::path::Path::new(curl).exists() {
            eprintln!("skipping: no curl(1) on this host");
            return;
        }
        let v4 = spawn_loopback_http("127.0.0.1:0").expect("bind v4 loopback");

        // A single v4 loopback address — the case that widens to the interface.
        let cav = Caveats {
            net: Scope::only(["127.0.0.1".to_string()]),
            ..Caveats::top()
        };
        // Positive control: a benign non-network command runs — the loopback
        // profile parsed (a malformed one exits 65 and never launches the child).
        assert!(
            run_wrapped(&cav, "/bin/echo", &["ok"]).success(),
            "loopback-only profile must still run non-network commands (must parse)"
        );
        // ALLOW (v4): egress to the loopback listener succeeds (curl exit 0). A
        // deny-all or malformed rule would fail this — so it cannot pass vacuously.
        let v4_url = format!("http://127.0.0.1:{}/", v4.port());
        assert!(
            run_wrapped(&cav, curl, &["-sS", "--max-time", "5", &v4_url]).success(),
            "net:Only([127.0.0.1]) must kernel-PERMIT v4 loopback egress"
        );
        // ALLOW (v6): `::1` is reachable too — locking the interface-granular
        // widening documented in ADR 0015 D2 (kernel `localhost` = 127.0.0.1 + ::1,
        // broader than the single-address grant). Skipped only if v6 loopback is
        // unavailable on the host (never on stock macOS).
        if let Some(v6) = spawn_loopback_http("[::1]:0") {
            let v6_url = format!("http://[::1]:{}/", v6.port());
            assert!(
                run_wrapped(&cav, curl, &["-sS", "--max-time", "5", &v6_url]).success(),
                "net:Only([127.0.0.1]) kernel-permits the whole loopback interface, incl. ::1 (ADR 0015 D2)"
            );
        }
        // DENY: off-box egress to a literal IP (no DNS) is kernel-denied at the
        // socket. Assert both curl exit 7 AND the EPERM signal ("Operation not
        // permitted") in stderr — so a no-internet runner (ENETUNREACH, also exit
        // 7) cannot make this pass vacuously; it must be a *permission* denial.
        let offbox = run_wrapped_output(
            &cav,
            curl,
            &["-sS", "-v", "--max-time", "5", "http://1.1.1.1/"],
        );
        assert_eq!(
            offbox.status.code(),
            Some(7),
            "net:Only([127.0.0.1]) must kernel-DENY off-box egress (curl exit 7)"
        );
        let stderr = String::from_utf8_lossy(&offbox.stderr);
        assert!(
            stderr.contains("Operation not permitted"),
            "off-box denial must be a kernel EPERM, not a routing failure: {stderr}"
        );
    }

    /// Like [`run_wrapped`] but captures stdout/stderr, so a proof can assert on
    /// the *interior* exec behavior (a granted program's child exec statuses) the
    /// kernel produced — the L3-grain the `exec` axis claims.
    fn run_wrapped_output(cav: &Caveats, program: &str, args: &[&str]) -> std::process::Output {
        let prefix = SeatbeltSandbox::new()
            .command_prefix(cav)
            .expect("a restricted axis must yield a wrapper prefix");
        assert!(!prefix.is_empty(), "expected a sandbox-exec wrapper");
        std::process::Command::new(&prefix[0])
            .args(&prefix[1..])
            .arg(program)
            .args(args)
            .output()
            .expect("spawn sandbox-exec")
    }

    /// The exec allow-list is kernel-enforced at the **interior**: a granted shell
    /// runs, may exec a *listed* binary, but is kernel-denied an *unlisted* one —
    /// the L3 gap a path allow-list alone cannot reach (ADR 0014). The discriminator
    /// is exact: the unlisted `/usr/bin/false` must fail at **exec** (status 127),
    /// not run-and-return-1 — so this cannot pass vacuously.
    #[test]
    fn exec_allowlist_permits_listed_denies_unlisted_child() {
        if skip_proof_unless_seatbelt() {
            return;
        }
        let cav = Caveats {
            exec: Scope::only(["/bin/zsh".to_string(), "/usr/bin/true".to_string()]),
            ..Caveats::top()
        };
        let out = run_wrapped_output(
            &cav,
            "/bin/zsh",
            &["-c", "/usr/bin/true; echo T=$?; /usr/bin/false; echo F=$?"],
        );
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            stdout.contains("T=0"),
            "a listed binary must exec and run (T=0): {stdout:?}"
        );
        assert!(
            stdout.contains("F=127"),
            "an unlisted binary must be kernel-denied at EXEC (status 127), not run: {stdout:?}"
        );
    }

    /// The `exec:none`-style floor: when the granted set is just the entry shell,
    /// the shell launches but may exec **nothing** further — every child exec is
    /// kernel-denied. This is the interior "no further exec" guarantee.
    #[test]
    fn granted_shell_cannot_exec_any_unlisted_child() {
        if skip_proof_unless_seatbelt() {
            return;
        }
        let cav = Caveats {
            exec: Scope::only(["/bin/zsh".to_string()]),
            ..Caveats::top()
        };
        let out = run_wrapped_output(&cav, "/bin/zsh", &["-c", "/usr/bin/true; echo S=$?"]);
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            stdout.contains("S=127"),
            "a shell granted only itself must be denied every child exec (S=127): {stdout:?}"
        );
    }

    /// The ADR 0011 loader trampoline — the bypass that has **no Landlock hook**
    /// and forces the Linux seccomp backstop — is *closed by the platform* on
    /// macOS. A granted interpreter (`perl`) cannot reach an unlisted binary by:
    /// (a) directly `exec`ing it, nor (b) trampolining through `dyld`. Both are
    /// governed `process-exec`s; `dyld` is not allow-listed, so both are denied.
    #[test]
    fn granted_interpreter_cannot_trampoline_to_unlisted_binary() {
        if skip_proof_unless_seatbelt() {
            return;
        }
        let cav = Caveats {
            exec: Scope::only(["/usr/bin/perl".to_string()]),
            ..Caveats::top()
        };
        // Each `exec` returns (and perl continues) only when the exec was DENIED.
        let script = "print \"PERL-RAN\\n\"; \
                      exec(\"/usr/bin/true\"); print \"DIRECT-DENIED\\n\"; \
                      exec(\"/usr/lib/dyld\", \"/usr/bin/true\"); print \"TRAMPOLINE-DENIED\\n\";";
        let out = run_wrapped_output(&cav, "/usr/bin/perl", &["-e", script]);
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            stdout.contains("PERL-RAN"),
            "the granted interpreter must run: {stdout:?}"
        );
        assert!(
            stdout.contains("DIRECT-DENIED"),
            "direct exec of an unlisted binary must be denied: {stdout:?}"
        );
        assert!(
            stdout.contains("TRAMPOLINE-DENIED"),
            "the dyld loader trampoline must be denied (no standing loader entry): {stdout:?}"
        );
    }

    /// Positive control / no deny-of-function: an allow-listed **dynamically
    /// linked** binary still loads its dylibs (via the kernel-trusted dyld path,
    /// which the exec allow-list does not gate) and runs normally under exec
    /// confinement — proving the axis confines *spawning*, not legitimate linking.
    #[test]
    fn exec_confinement_does_not_break_dynamic_linking() {
        if skip_proof_unless_seatbelt() {
            return;
        }
        let curl = "/usr/bin/curl";
        if !std::path::Path::new(curl).exists() {
            eprintln!("skipping: no curl(1) on this host");
            return;
        }
        let cav = Caveats {
            exec: Scope::only([curl.to_string()]),
            ..Caveats::top()
        };
        let status = run_wrapped(&cav, curl, &["--version"]);
        assert!(
            status.success(),
            "an allow-listed dynamic binary must load + run under exec confinement"
        );
    }
}
