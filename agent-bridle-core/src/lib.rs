//! `agent-bridle-core` — the capability-enforcement core.
//!
//! This crate is the **leash**: it owns the [`Tool`] trait, the [`Gate`] (the
//! single mint site for a [`ToolContext`]), the [`Registry`], the [`Sandbox`]
//! plumbing, and the result [`ToolEnvelope`]. It re-exports the canonical
//! authority types ([`Caveats`], [`Scope`], [`CountBound`]) from
//! `agent-mesh-protocol` so every host and tool speaks one lattice.
//!
//! The non-bypassable invariant (DESIGN §2): a [`Tool`] can only act through a
//! [`ToolContext`], and a `ToolContext` can only be minted inside
//! [`Gate::authorize`]. So the only path to running a tool runs through the
//! leash, and the tool receives the *meet* of granted-and-required authority —
//! least authority by construction.
//!
//! Dependency budget is deliberately tiny — `anyhow`, `serde`, `serde_json`,
//! `async-trait`, `agent-mesh-protocol`. No tokio. No brush. Heavy runtimes
//! live in leaf tool crates only.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

// ── The leash: canonical authority lattice (re-exported, single source) ──────
pub use agent_mesh_protocol::{Caveats, CountBound, Scope};

mod context;
mod envelope;
mod error;
mod gate;
mod registry;
mod sandbox;
mod tool;

pub use context::ToolContext;
pub use envelope::{Denial, DenialKind, ToolEnvelope};
pub use error::{ToolError, ToolResult};
pub use gate::Gate;
pub use registry::{Registry, RegistryBuilder};
pub use sandbox::{best_available_sandbox, NoopSandbox, Sandbox, SandboxKind};
#[cfg(all(target_os = "linux", feature = "linux-landlock"))]
pub use sandbox::{landlock_is_supported, LandlockSandbox};
pub use tool::Tool;

#[cfg(test)]
mod tests {
    use super::*;

    /// A trivial tool used to drive the gate in crate-level tests.
    struct T;
    #[async_trait::async_trait]
    impl Tool for T {
        fn name(&self) -> &str {
            "t"
        }
        fn schema(&self) -> serde_json::Value {
            serde_json::json!({})
        }
        async fn invoke(
            &self,
            _args: serde_json::Value,
            _cx: &ToolContext,
        ) -> ToolResult<serde_json::Value> {
            Ok(serde_json::Value::Null)
        }
    }

    /// The mint-token is un-constructible outside this crate.
    ///
    /// `ToolContext` exposes no public constructor and no public fields. The
    /// `compile_fail` doctest below proves a downstream crate cannot forge one;
    /// here we assert the *only* way to get one is through the gate, and that
    /// what it carries is the meet (≤ granted).
    #[test]
    fn context_minted_only_by_gate_and_carries_meet() {
        let granted = Caveats {
            exec: Scope::only(["echo".to_string()]),
            max_calls: CountBound::AtMost(3),
            ..Caveats::top()
        };
        let gate = Gate::new(0);
        let cx = gate.authorize(&T, &granted).expect("authorize");
        // effective ⊑ granted (least authority).
        assert!(cx.caveats().leq(&granted));
        // The default `required()` is top, so effective == granted here.
        assert_eq!(*cx.caveats(), granted);
    }

    /// `ToolContext` cannot be constructed outside `agent-bridle-core`: it has
    /// no public constructor and no public fields, so a downstream caller has
    /// no syntax to make one. (Doctest crates are treated as external, so this
    /// proves the cross-crate boundary.)
    ///
    /// ```compile_fail
    /// use agent_bridle_core::ToolContext;
    /// // No public constructor:
    /// let _ = ToolContext::mint(agent_bridle_core::Caveats::top(),
    ///     agent_bridle_core::SandboxKind::None);
    /// ```
    ///
    /// ```compile_fail
    /// use agent_bridle_core::{Caveats, SandboxKind, ToolContext};
    /// // No public fields, no struct literal possible:
    /// let _ = ToolContext { effective: Caveats::top(), sandbox_kind: SandboxKind::None };
    /// ```
    fn _mint_token_is_unconstructible_doctests() {}
}
