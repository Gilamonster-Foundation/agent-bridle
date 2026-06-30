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
    Kernel,
    /// The in-process L2 leash gates this axis at the spawn/open chokepoint —
    /// it holds for the engine's own operations, **not** for a permitted
    /// external child's interior (a `find -exec` child's reads escape it).
    Interceptor,
    /// Validated at admission, then **ambient** — nothing backstops the spawned
    /// interior. Honest "we checked the request, we cannot confine the effect."
    Advisory,
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
/// - **`exec`** — `interceptor`: the spawn funnel (`before_exec` /
///   `check_exec`) gates each spawn the engine makes, but no OS execute
///   allow-list confines a permitted child's *own* `exec` (the Landlock exec
///   axis is held — agent-bridle#31/#57), so it is never `kernel` yet.
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
            // Real OS sandboxes that govern the filesystem axes — Landlock
            // (Linux), Seatbelt (macOS), AppContainer (Windows) — enforce them in
            // the kernel.
            SandboxKind::Landlock | SandboxKind::Seatbelt | SandboxKind::AppContainer => {
                AxisEnforcement::Kernel
            }
            SandboxKind::None => AxisEnforcement::Interceptor,
        })
    };
    EnforcementReport {
        fs_read: fs(&effective.fs_read),
        fs_write: fs(&effective.fs_write),
        exec: is_restricted(&effective.exec).then_some(AxisEnforcement::Interceptor),
        net: is_restricted(&effective.net).then_some(match active {
            // AppContainer's capability model governs network too; the others do
            // not gate a spawned program's egress this increment (#31/#57).
            SandboxKind::AppContainer => AxisEnforcement::Kernel,
            SandboxKind::Landlock | SandboxKind::Seatbelt | SandboxKind::None => {
                AxisEnforcement::Advisory
            }
        }),
    }
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

    /// Seatbelt (macOS) governs the same fs axes as Landlock: kernel fs,
    /// interceptor exec, advisory net.
    #[test]
    fn seatbelt_marks_fs_kernel_exec_interceptor_net_advisory() {
        let r = enforcement_report(&fully_restricted(), SandboxKind::Seatbelt);
        assert_eq!(r.fs_read, Some(AxisEnforcement::Kernel));
        assert_eq!(r.fs_write, Some(AxisEnforcement::Kernel));
        assert_eq!(r.exec, Some(AxisEnforcement::Interceptor));
        assert_eq!(r.net, Some(AxisEnforcement::Advisory));
    }

    #[test]
    fn appcontainer_marks_fs_kernel_exec_interceptor_net_kernel() {
        let r = enforcement_report(&fully_restricted(), SandboxKind::AppContainer);
        assert_eq!(r.fs_read, Some(AxisEnforcement::Kernel));
        assert_eq!(r.fs_write, Some(AxisEnforcement::Kernel));
        assert_eq!(r.exec, Some(AxisEnforcement::Interceptor));
        assert_eq!(r.net, Some(AxisEnforcement::Kernel));
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
}
