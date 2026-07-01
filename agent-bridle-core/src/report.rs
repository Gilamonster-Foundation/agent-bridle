//! Axis-granular confinement honesty (ADR 0004 D1).
//!
//! A single [`SandboxKind`] cannot honestly describe a run where one axis is
//! kernel-confined while others are only advisory. For example, the Landlock
//! backend governs `fs_write` (always) and `fs_read` (when restricted) but
//! leaves `exec` and `net` ungoverned for now (agent-bridle#31/#57). Reporting
//! `sandbox_kind: landlock` for such a run is true coarsely but misleading at
//! the grain a caller reasons about.
//!
//! [`enforcement_report`] classifies each **restricted** Caveat axis (`Only(_)`,
//! not `All`) as one of [`AxisEnforcement`]. It is a pure function of the
//! effective [`Caveats`] and the active [`SandboxKind`] — no IO. The coarse
//! `sandbox_kind` stays the **minimum** claim; this report refines it and is
//! never allowed to describe an `advisory` axis as confined.

use serde::{Deserialize, Serialize};

use crate::{Caveats, SandboxKind, Scope};

/// How a single restricted Caveat axis is actually enforced for a run
/// (ADR 0004 D1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AxisEnforcement {
    /// An OS ruleset enforces this axis against the spawned program's
    /// **interior** (e.g. Landlock on `fs_write`). The strongest claim.
    ///
    /// **`exec → kernel` is about *identity*, not *behavior* (ADR 0013 D6 /
    /// agent-bridle#114).** It means "no **un-granted program** can run as a
    /// process" — via Seatbelt `process-exec*` (ADR 0014), or a Linux minimal
    /// rootfs that physically excludes un-granted binaries (ADR 0013). It does
    /// **NOT** mean a *granted* program — especially a granted **interpreter**
    /// (`sh`, `python`, `perl`) — is constrained in what it *does*: its interior
    /// logic is still bounded only by the `fs_read`/`fs_write`/`net` axes (read
    /// those for the data-side guarantee). Do not read `exec → kernel` as "this
    /// program will only do what I expect."
    Kernel,
    /// The in-process L2 leash gates this axis at the spawn/open chokepoint —
    /// it holds for the engine's own operations, **not** for a permitted
    /// external child's interior (a `find -exec` child's reads escape it).
    Interceptor,
    /// Validated at admission, then **ambient** — nothing backstops the spawned
    /// interior. Honest "we checked the request, we cannot confine the effect."
    Advisory,
}

impl AxisEnforcement {
    /// Ascending confinement strength: `Advisory (0) < Interceptor (1) <
    /// Kernel (2)`.
    ///
    /// The variants are *declared* strongest-first (`Kernel` first) so the type
    /// reads top-down — which means a naive `#[derive(PartialOrd, Ord)]` would
    /// order them DESCENDING (`Kernel < Advisory`) and silently invert every
    /// `min` / [`fence_strength`] into a **fail-open** (ADR 0012 D2). The order is
    /// therefore defined **explicitly** here, never derived; this hand-written
    /// `impl` also turns a future stray `#[derive(Ord)]` into a hard compile error
    /// (conflicting impls) rather than a silent security bug.
    fn rank(self) -> u8 {
        match self {
            AxisEnforcement::Advisory => 0,
            AxisEnforcement::Interceptor => 1,
            AxisEnforcement::Kernel => 2,
        }
    }
}

impl Ord for AxisEnforcement {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.rank().cmp(&other.rank())
    }
}

impl PartialOrd for AxisEnforcement {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// Per-axis confinement report for the four OS-confinement Caveat axes
/// (`fs_read`, `fs_write`, `exec`, `net`).
///
/// Only **restricted** (`Only(_)`) axes appear (`Some(_)`); an axis granted
/// `All` is unrestricted — there is nothing to confine — and is `None`. The
/// `max_calls` / `valid_for_generation` axes are gate-enforced budget/causality,
/// not OS-confinement axes, so they are not part of this report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct EnforcementReport {
    /// Enforcement of the `fs_read` axis, when restricted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fs_read: Option<AxisEnforcement>,
    /// Enforcement of the `fs_write` axis, when restricted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fs_write: Option<AxisEnforcement>,
    /// Enforcement of the `exec` axis, when restricted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exec: Option<AxisEnforcement>,
    /// Enforcement of the `net` axis, when restricted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub net: Option<AxisEnforcement>,
}

impl EnforcementReport {
    /// `true` when no axis is restricted (every axis is `All`) — so the report
    /// carries no information and may be omitted from a result envelope.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.fs_read.is_none()
            && self.fs_write.is_none()
            && self.exec.is_none()
            && self.net.is_none()
    }
}

/// `true` if a scope actually restricts (`Only(_)`); `All` does not confine.
fn is_restricted<T: Ord + Clone>(scope: &Scope<T>) -> bool {
    matches!(scope, Scope::Only(_))
}

/// Classify each restricted axis of `effective` under the `active` sandbox
/// (ADR 0004 D1). Pure; no IO.
///
/// The mapping reflects what each layer *actually* enforces today:
///
/// - **`fs_read` / `fs_write`** — `kernel` when a real OS sandbox is active
///   (Landlock governs writes always and reads when restricted), otherwise
///   `interceptor` (the in-process leash gates the engine's own opens).
/// - **`exec`** — `kernel` under **Seatbelt** (macOS): the profile emits
///   `(deny process-exec*)` + an allow-list of the granted programs, and
///   `process-exec*` is kernel-checked on the confined process *and everything it
///   spawns*, so a permitted child's own `exec` is confined too. Apple-Silicon
///   hardware W^X + code signing close the `mmap(PROT_EXEC)` / loader-trampoline
///   bypass with no seccomp backstop (ADR 0014). Under **Landlock** and a
///   **Noop** host it stays `interceptor`: the spawn funnel (`before_exec` /
///   `check_exec`) gates the engine's own spawns, but no OS execute allow-list
///   confines a child's interior (the Landlock exec axis is held —
///   agent-bridle#31/#57).
/// - **`net`** — `advisory`: no kernel net rules are wired (agent-bridle#31) and
///   the shell engine does not gate a spawned program's egress. Reported
///   conservatively as advisory so the axis is never described as confined when
///   it is not (honesty rule); a tool that does gate net for its own requests
///   over-delivers relative to this floor, which is the safe direction.
#[must_use]
pub fn enforcement_report(effective: &Caveats, active: SandboxKind) -> EnforcementReport {
    // Filesystem axes: kernel when an OS sandbox actually governs them, else the
    // in-process interceptor. Exhaustive over `SandboxKind` so a new backend
    // must decide its mapping rather than silently defaulting.
    let fs = |scope: &Scope<String>| {
        is_restricted(scope).then_some(match active {
            // Real OS sandboxes that govern the filesystem axes in the kernel —
            // Landlock (Linux, FS allow-list via restrict_self), Seatbelt (macOS,
            // SBPL read/write rules), and the Linux minimal-rootfs jail (read-only/
            // read-write bind-mounts inside its mount namespace, ADR 0013 D3/D4).
            SandboxKind::Landlock
            | SandboxKind::Seatbelt
            | SandboxKind::MinimalRootfs
            | SandboxKind::MicroVm => AxisEnforcement::Kernel,
            // AppContainer: FS ACL narrowing is deferred (#136). Until per-path
            // ACEs are wired in the launcher the fs axis is NOT kernel-enforced —
            // only the in-process leash (tool-call boundary) checks it. Reporting
            // Kernel here would be an honesty overclaim (ADR 0006 / #136).
            SandboxKind::AppContainer | SandboxKind::None => AxisEnforcement::Interceptor,
        })
    };
    EnforcementReport {
        fs_read: fs(&effective.fs_read),
        fs_write: fs(&effective.fs_write),
        exec: is_restricted(&effective.exec).then_some(match active {
            // `exec → kernel` is reserved for modes that close the axis by
            // *identity*: Seatbelt (macOS) via `process-exec*` — interior-covering,
            // no trampoline bypass on Apple Silicon (ADR 0014) — and the Linux
            // minimal-rootfs jail, where no un-granted binary physically *exists*
            // to run or to `ld.so`-trampoline into (ADR 0013 D5, ADR 0011 D7's
            // precondition made physically true). Landlock's exec axis is held
            // (agent-bridle#31/#57) and a Noop host has no OS allow-list, so both
            // stay interceptor; AppContainer's exec story is not wired this
            // increment, so it stays interceptor too (never overclaimed).
            SandboxKind::Seatbelt | SandboxKind::MinimalRootfs | SandboxKind::MicroVm => {
                AxisEnforcement::Kernel
            }
            SandboxKind::Landlock | SandboxKind::AppContainer | SandboxKind::None => {
                AxisEnforcement::Interceptor
            }
        }),
        net: is_restricted(&effective.net).then_some(match active {
            // AppContainer: the capability model kernel-denies egress only when ALL
            // network capabilities are withheld, i.e. when `net` is the empty set
            // (deny-all). A non-empty allow-list cannot be kernel-expressed in the
            // current launcher (no proxy, only the raw capability toggle), so it
            // stays advisory — the in-process leash checks it, but a rogue child
            // could bypass (#133). MicroVM: no guest NIC at all → always Kernel.
            SandboxKind::AppContainer if crate::sandbox::net_fully_denied(effective) => {
                AxisEnforcement::Kernel
            }
            SandboxKind::AppContainer => AxisEnforcement::Advisory,
            SandboxKind::MicroVm => AxisEnforcement::Kernel,
            // Seatbelt kernel-denies *all* egress when the net scope is empty
            // (`(deny network*)`), and confines a **loopback-only** allowlist to
            // the loopback interface (`(allow network* (remote ip "localhost:*"))`)
            // so the process's own off-box socket egress is kernel-denied (ADR
            // 0015) — both honest `kernel`. A general remote host is inexpressible
            // in SBPL (only
            // `*`/`localhost` + ports), so it stays advisory. Landlock does not gate
            // net this increment.
            SandboxKind::Seatbelt
                if crate::sandbox::net_fully_denied(effective)
                    || crate::sandbox::net_loopback_only(effective) =>
            {
                AxisEnforcement::Kernel
            }
            // Landlock V4 (kernel ≥ 6.7) can deny-all TCP when the net scope is
            // empty (no NetPort rules → deny-by-default). Non-empty host allowlists
            // are not expressible (port-based, not hostname-based) and stay advisory.
            SandboxKind::Landlock
                if crate::sandbox::net_fully_denied(effective)
                    && crate::sandbox::landlock_net_capable() =>
            {
                AxisEnforcement::Kernel
            }
            // The minimal-rootfs jail does not namespace the network this tier, so
            // egress is unconfined — advisory, never overclaimed (ADR 0013 D5).
            SandboxKind::Landlock
            | SandboxKind::Seatbelt
            | SandboxKind::MinimalRootfs
            | SandboxKind::None => AxisEnforcement::Advisory,
        }),
    }
}

/// The fence's overall strength: the greatest-lower-bound (weakest) enforcement
/// across the **restricted** axes of `report` — a fence is only as strong as its
/// weakest confined axis (ADR 0012 D1). Returns `None` when no axis is restricted
/// (an empty report: a top grant confining nothing — a vacuous top with nothing
/// to enforce). **Pure**: recomputed from the report on every call, never stored,
/// so it cannot diverge from the lattice it summarizes (ADR 0004 D3 / ADR 0012's
/// rejection of a parallel strength enum). Consumers that need to know *which*
/// axis dropped the strength still read the per-axis [`EnforcementReport`].
#[must_use]
pub fn fence_strength(report: &EnforcementReport) -> Option<AxisEnforcement> {
    [report.fs_read, report.fs_write, report.exec, report.net]
        .into_iter()
        .flatten()
        .min()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CountBound, Scope};

    /// All axes restricted, so every axis appears in the report.
    fn fully_restricted() -> Caveats {
        Caveats {
            fs_read: Scope::only(["/r".to_string()]),
            fs_write: Scope::only(["/w".to_string()]),
            exec: Scope::only(["echo".to_string()]),
            net: Scope::only(["example.com".to_string()]),
            max_calls: CountBound::Unlimited,
            valid_for_generation: Scope::All,
        }
    }

    #[test]
    fn landlock_marks_fs_kernel_exec_interceptor_net_advisory() {
        let r = enforcement_report(&fully_restricted(), SandboxKind::Landlock);
        assert_eq!(r.fs_read, Some(AxisEnforcement::Kernel));
        assert_eq!(r.fs_write, Some(AxisEnforcement::Kernel));
        assert_eq!(r.exec, Some(AxisEnforcement::Interceptor));
        assert_eq!(r.net, Some(AxisEnforcement::Advisory));
    }

    /// Landlock V4 (kernel ≥ 6.7) kernel-denies ALL TCP when `net` is the empty
    /// set (deny-all), because we declare `AccessNet` without adding any `NetPort`
    /// rules — deny-by-default. On pre-V4 kernels the `handle_access` is a BestEffort
    /// no-op so `net` stays advisory. The test dynamically queries the probe to stay
    /// correct in both environments (ADR 0013 net-axis Landlock extension, issue #35).
    #[test]
    fn landlock_marks_net_kernel_when_net_fully_denied_and_v4_capable() {
        let net_denied = crate::Caveats {
            net: crate::Scope::none(),
            ..crate::Caveats::top()
        };
        let r = enforcement_report(&net_denied, SandboxKind::Landlock);
        let expected = if crate::sandbox::landlock_net_capable() {
            Some(AxisEnforcement::Kernel)
        } else {
            Some(AxisEnforcement::Advisory)
        };
        assert_eq!(
            r.net, expected,
            "Landlock net enforcement depends on V4 kernel support"
        );
        // fs is not restricted, so those axes must be absent
        assert_eq!(r.fs_read, None);
        assert_eq!(r.fs_write, None);
        assert_eq!(r.exec, None);
    }

    /// Seatbelt (macOS) governs the fs axes in the kernel like Landlock, **and**
    /// the `exec` axis via `process-exec*` (ADR 0014) — so exec is `kernel`, not
    /// `interceptor`. `net` here is a general remote host allowlist, which SBPL
    /// cannot express, so it stays advisory (the empty-net and loopback-only kernel
    /// cases are covered by
    /// [`seatbelt_net_kernel_for_empty_and_loopback_advisory_for_remote_host`]).
    #[test]
    fn seatbelt_marks_fs_and_exec_kernel_net_advisory() {
        let r = enforcement_report(&fully_restricted(), SandboxKind::Seatbelt);
        assert_eq!(r.fs_read, Some(AxisEnforcement::Kernel));
        assert_eq!(r.fs_write, Some(AxisEnforcement::Kernel));
        assert_eq!(r.exec, Some(AxisEnforcement::Kernel));
        assert_eq!(r.net, Some(AxisEnforcement::Advisory));
    }

    /// The macOS exec-axis honesty distinction from Landlock: a restricted `exec`
    /// is `kernel` under Seatbelt but only `interceptor` under Landlock (its exec
    /// axis is held) and a Noop host. ADR 0014.
    #[test]
    fn exec_is_kernel_under_seatbelt_interceptor_elsewhere() {
        let cav = Caveats {
            exec: Scope::only(["git".to_string()]),
            ..Caveats::top()
        };
        assert_eq!(
            enforcement_report(&cav, SandboxKind::Seatbelt).exec,
            Some(AxisEnforcement::Kernel)
        );
        assert_eq!(
            enforcement_report(&cav, SandboxKind::Landlock).exec,
            Some(AxisEnforcement::Interceptor)
        );
        assert_eq!(
            enforcement_report(&cav, SandboxKind::None).exec,
            Some(AxisEnforcement::Interceptor)
        );
    }

    /// ADR 0013 D5 (#110): a minimal-rootfs jail run governs the filesystem axes
    /// (bind-mounts) **and** the `exec` axis (identity by existence) in the kernel;
    /// `net` is not namespaced this tier, so it stays advisory.
    #[test]
    fn minimal_rootfs_marks_fs_and_exec_kernel_net_advisory() {
        let r = enforcement_report(&fully_restricted(), SandboxKind::MinimalRootfs);
        assert_eq!(r.fs_read, Some(AxisEnforcement::Kernel));
        assert_eq!(r.fs_write, Some(AxisEnforcement::Kernel));
        assert_eq!(r.exec, Some(AxisEnforcement::Kernel));
        assert_eq!(r.net, Some(AxisEnforcement::Advisory));
    }

    /// ADR 0013 D5 (#110) acceptance: a restricted `exec` is `kernel` in the
    /// minimal-rootfs mode but only `interceptor` under a Landlock-only boundary
    /// (its exec axis is held — ADR 0011). `kernel` is reserved for the rootfs mode.
    #[test]
    fn exec_is_kernel_under_minimal_rootfs_interceptor_under_landlock() {
        let cav = Caveats {
            exec: Scope::only(["cat".to_string()]),
            ..Caveats::top()
        };
        assert_eq!(
            enforcement_report(&cav, SandboxKind::MinimalRootfs).exec,
            Some(AxisEnforcement::Kernel),
            "minimal-rootfs closes exec by identity ⇒ kernel"
        );
        assert_eq!(
            enforcement_report(&cav, SandboxKind::Landlock).exec,
            Some(AxisEnforcement::Interceptor),
            "a Landlock-only boundary run stays exec→interceptor (ADR 0011)"
        );
    }

    /// ADR 0013 D3 (#111): the Tier-2 micro-VM confines every OS axis in the
    /// kernel — fs + exec by the guest boundary (identity by existence), and net
    /// because the guest has no network device (egress impossible). The strongest
    /// tier: `fence_strength` is therefore `Kernel` even with all axes restricted.
    #[test]
    fn micro_vm_marks_all_axes_kernel() {
        let r = enforcement_report(&fully_restricted(), SandboxKind::MicroVm);
        assert_eq!(r.fs_read, Some(AxisEnforcement::Kernel));
        assert_eq!(r.fs_write, Some(AxisEnforcement::Kernel));
        assert_eq!(r.exec, Some(AxisEnforcement::Kernel));
        assert_eq!(r.net, Some(AxisEnforcement::Kernel));
        assert_eq!(fence_strength(&r), Some(AxisEnforcement::Kernel));
    }

    /// AppContainer honesty (#136): fs is NOT kernel-enforced (ACL narrowing is
    /// deferred) → Interceptor. net is Kernel only for deny-all (empty scope) — a
    /// general remote-host allowlist cannot be kernel-expressed without the egress
    /// proxy (#133), so it stays Advisory. exec stays Interceptor (ACE wiring for
    /// exec is #123, not yet landed).
    #[test]
    fn appcontainer_marks_fs_interceptor_exec_interceptor_net_advisory_for_allowlist() {
        // `fully_restricted()` uses net: Only(["example.com"]) — a non-empty
        // allowlist the launcher cannot kernel-express → Advisory.
        let r = enforcement_report(&fully_restricted(), SandboxKind::AppContainer);
        assert_eq!(r.fs_read, Some(AxisEnforcement::Interceptor));
        assert_eq!(r.fs_write, Some(AxisEnforcement::Interceptor));
        assert_eq!(r.exec, Some(AxisEnforcement::Interceptor));
        assert_eq!(r.net, Some(AxisEnforcement::Advisory));
    }

    /// net → Kernel only when the scope is empty (deny-all): the AppContainer
    /// capability model withholds all network SIDs → kernel-denied egress.
    #[test]
    fn appcontainer_marks_net_kernel_for_deny_all() {
        let net_deny_all = Caveats {
            net: Scope::none(),
            ..Caveats::top()
        };
        let r = enforcement_report(&net_deny_all, SandboxKind::AppContainer);
        assert_eq!(r.net, Some(AxisEnforcement::Kernel));
        // fs/exec are unrestricted (top) — not in the report.
        assert_eq!(r.fs_read, None);
        assert_eq!(r.fs_write, None);
        assert_eq!(r.exec, None);
    }

    /// Seatbelt's net honesty is scope-shaped (ADR 0015): kernel for the two
    /// policies SBPL can express — an **empty** scope (`(deny network*)`) and a
    /// **loopback-only** allowlist (egress confined to the loopback interface) —
    /// and advisory for a general remote host, which SBPL cannot name.
    #[test]
    fn seatbelt_net_kernel_for_empty_and_loopback_advisory_for_remote_host() {
        let net_report = |net| {
            enforcement_report(
                &Caveats {
                    net,
                    ..Caveats::top()
                },
                SandboxKind::Seatbelt,
            )
            .net
        };

        // Empty net (all egress denied) → kernel.
        assert_eq!(net_report(Scope::none()), Some(AxisEnforcement::Kernel));
        // Loopback-only allowlist (off-box egress kernel-impossible) → kernel.
        for host in ["localhost", "127.0.0.1", "::1"] {
            assert_eq!(
                net_report(Scope::only([host.to_string()])),
                Some(AxisEnforcement::Kernel),
                "loopback host {host} must report kernel"
            );
        }
        // A general remote host → advisory (inexpressible in SBPL).
        assert_eq!(
            net_report(Scope::only(["example.com".to_string()])),
            Some(AxisEnforcement::Advisory)
        );
        // A single remote host taints an otherwise-loopback set → advisory.
        assert_eq!(
            net_report(Scope::only([
                "localhost".to_string(),
                "example.com".to_string()
            ])),
            Some(AxisEnforcement::Advisory)
        );
    }

    /// The honesty oracle for a Noop host: NO restricted axis is ever `kernel`.
    #[test]
    fn noop_host_never_reports_kernel() {
        let r = enforcement_report(&fully_restricted(), SandboxKind::None);
        assert_eq!(r.fs_read, Some(AxisEnforcement::Interceptor));
        assert_eq!(r.fs_write, Some(AxisEnforcement::Interceptor));
        assert_eq!(r.exec, Some(AxisEnforcement::Interceptor));
        assert_eq!(r.net, Some(AxisEnforcement::Advisory));
        for axis in [r.fs_read, r.fs_write, r.exec, r.net] {
            assert_ne!(
                axis,
                Some(AxisEnforcement::Kernel),
                "Noop must never claim kernel"
            );
        }
    }

    /// Unrestricted axes (`All`) are omitted — there is nothing to confine.
    #[test]
    fn unrestricted_axes_are_omitted() {
        let top = Caveats::top(); // every axis is All
        let r = enforcement_report(&top, SandboxKind::Landlock);
        assert!(
            r.is_empty(),
            "all-`All` caveats produce an empty report: {r:?}"
        );
        assert_eq!(r.fs_write, None);
    }

    /// A mix: only `fs_write` restricted under Landlock → that one axis kernel,
    /// the rest absent.
    #[test]
    fn only_restricted_axes_appear() {
        let caveats = Caveats {
            fs_write: Scope::only(["/w".to_string()]),
            ..Caveats::top()
        };
        let r = enforcement_report(&caveats, SandboxKind::Landlock);
        assert_eq!(r.fs_write, Some(AxisEnforcement::Kernel));
        assert_eq!(r.fs_read, None);
        assert_eq!(r.exec, None);
        assert_eq!(r.net, None);
    }

    #[test]
    fn axis_enforcement_serializes_snake_case() {
        assert_eq!(
            serde_json::to_value(AxisEnforcement::Kernel).unwrap(),
            serde_json::json!("kernel")
        );
        assert_eq!(
            serde_json::to_value(AxisEnforcement::Interceptor).unwrap(),
            serde_json::json!("interceptor")
        );
        assert_eq!(
            serde_json::to_value(AxisEnforcement::Advisory).unwrap(),
            serde_json::json!("advisory")
        );
    }

    /// ADR 0012 D2 regression: the order is **ascending** `Advisory < Interceptor
    /// < Kernel`, NOT the descending declaration order. A naive `#[derive(Ord)]`
    /// would invert this — making `Kernel < Advisory` — and silently fail
    /// `fence_strength` OPEN (picking the strongest axis as the floor).
    #[test]
    fn axis_enforcement_orders_ascending_advisory_to_kernel() {
        use AxisEnforcement::{Advisory, Interceptor, Kernel};
        assert!(Advisory < Interceptor);
        assert!(Interceptor < Kernel);
        assert!(
            Advisory < Kernel,
            "the fail-open footgun: Advisory must be < Kernel"
        );
        // The strongest claim is the MAX; the weakest (the GLB the fence takes) is
        // the MIN.
        assert_eq!(
            [Interceptor, Kernel, Advisory].into_iter().max(),
            Some(Kernel)
        );
        assert_eq!(
            [Interceptor, Kernel, Advisory].into_iter().min(),
            Some(Advisory)
        );
    }

    /// A fence is only as strong as its weakest restricted axis: fully restricted
    /// under Landlock is fs=Kernel, exec=Interceptor, net=Advisory ⇒ `Advisory`.
    #[test]
    fn fence_strength_is_the_weakest_restricted_axis() {
        let r = enforcement_report(&fully_restricted(), SandboxKind::Landlock);
        assert_eq!(fence_strength(&r), Some(AxisEnforcement::Advisory));
    }

    /// Only the fs axes restricted under Landlock ⇒ both `Kernel`, nothing weaker
    /// present ⇒ the fence is `Kernel`.
    #[test]
    fn fence_strength_all_kernel_when_only_fs_restricted() {
        let caveats = Caveats {
            fs_read: Scope::only(["/r".to_string()]),
            fs_write: Scope::only(["/w".to_string()]),
            ..Caveats::top()
        };
        let r = enforcement_report(&caveats, SandboxKind::Landlock);
        assert_eq!(fence_strength(&r), Some(AxisEnforcement::Kernel));
    }

    /// An empty report (top grant, nothing restricted) has no strength — there is
    /// nothing to confine (ADR 0012 D1: a vacuous top ⇒ `None`, never a hole).
    #[test]
    fn fence_strength_empty_report_is_none() {
        let r = enforcement_report(&Caveats::top(), SandboxKind::Landlock);
        assert!(r.is_empty());
        assert_eq!(fence_strength(&r), None);
    }

    /// One restricted axis with no kernel backend ⇒ the fence is that axis's
    /// (interceptor) strength.
    #[test]
    fn fence_strength_single_axis_no_backend() {
        let caveats = Caveats {
            fs_write: Scope::only(["/w".to_string()]),
            ..Caveats::top()
        };
        let r = enforcement_report(&caveats, SandboxKind::None);
        assert_eq!(fence_strength(&r), Some(AxisEnforcement::Interceptor));
    }

    /// #114 / ADR 0013 D6 report guard: `exec → kernel` is **identity, not
    /// behavior**. A granted *interpreter* (`sh`) still earns `exec → kernel`
    /// under Seatbelt — only un-granted *programs* are excluded — which must not
    /// be misread as constraining the interpreter's interior (that is governed
    /// only by the fs/net axes, absent here because they are unrestricted).
    #[test]
    fn exec_kernel_is_identity_not_interpreter_behavior() {
        let interp = Caveats {
            exec: Scope::only(["sh".to_string()]),
            ..Caveats::top()
        };
        let r = enforcement_report(&interp, SandboxKind::Seatbelt);
        assert_eq!(
            r.exec,
            Some(AxisEnforcement::Kernel),
            "a granted interpreter still earns exec→kernel (identity, not behavior)"
        );
        // exec→kernel does NOT imply the interior is constrained: fs/net are All
        // (unrestricted) here, so they are absent from the report.
        assert_eq!(r.fs_read, None);
        assert_eq!(r.fs_write, None);
        assert_eq!(r.net, None);
    }
}
