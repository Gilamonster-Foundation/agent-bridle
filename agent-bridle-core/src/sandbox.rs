//! OS-level sandbox plumbing.
//!
//! On Linux, Landlock is the *authoritative* boundary (DESIGN §6): an
//! in-process leash alone is not airtight against brush's PATH-separator exec
//! bypass, so the shell tool's exec/fs guarantees are meant to be gated on
//! Landlock being active. The kernel-real ruleset is a documented **P3 TODO**;
//! for P0 the plumbing exists (the [`Sandbox`] trait, the [`SandboxKind`] field
//! recorded in every result) but resolves to a [`NoopSandbox`] reporting
//! [`SandboxKind::None`]. Off-Linux the leash is honestly advertised as
//! advisory/best-effort — no overclaiming.

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
        // P3 TODO(linux-landlock): build and enforce a real Landlock ruleset
        // from `effective` here when the `linux-landlock` feature is active and
        // the kernel supports it; only then return SandboxKind::Landlock.
        Ok(())
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
}
