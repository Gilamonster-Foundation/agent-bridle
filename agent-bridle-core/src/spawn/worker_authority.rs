//! The authority a trusted worker re-mints its [`ToolContext`] from.
//!
//! Constructible only by decoding a core-framed [`super::TrustedWorkerRequest`]
//! (no public constructor), so a worker cannot assemble one from tool-specific
//! payload fields. [`WorkerAuthority::authorize`] mints through
//! [`Gate::authorize`] — the one mint site — stamping the sandbox kind from the
//! fence evidence core captured at spawn (#499).

use crate::{
    Caveats, EnforcementFloor, FenceEvidence, Gate, Scope, Tool, ToolContext, ToolError, ToolResult,
};

/// Core-captured authority carried to a trusted worker: the effective caveats,
/// the per-axis strength floor, and the evidence of the fence it runs under.
#[derive(Debug)]
pub struct WorkerAuthority {
    pub(super) caveats: Caveats,
    pub(super) strength_floor: EnforcementFloor,
    pub(super) fence: FenceEvidence,
}

impl WorkerAuthority {
    /// The effective caveats frozen by the supervisor at spawn.
    #[must_use]
    pub fn caveats(&self) -> &Caveats {
        &self.caveats
    }

    /// The per-axis strength floor delegated by the supervisor.
    #[must_use]
    pub fn strength_floor(&self) -> EnforcementFloor {
        self.strength_floor
    }

    /// The fence evidence copied from the [`crate::ConfinedChild`] at spawn.
    #[must_use]
    pub fn fence(&self) -> &FenceEvidence {
        &self.fence
    }

    /// Mint the worker's context through [`Gate::authorize`], re-applying the
    /// delegated floor and reporting the fence's actual sandbox kind.
    pub fn authorize(&self, tool: &dyn Tool) -> ToolResult<ToolContext> {
        let generation = match &self.caveats.valid_for_generation {
            Scope::All => 0,
            Scope::Only(values) => values
                .iter()
                .copied()
                .next()
                .ok_or_else(|| ToolError::denied("worker grant has no valid generation"))?,
        };
        Gate::new(generation)
            .with_enforcement_floor(self.strength_floor)
            .with_sandbox_kind(self.fence.sandbox_kind)
            .authorize(tool, &self.caveats)
    }
}
