//! `charter-bridle` — the live edge between agent-bridle and the Steward's Charter.
//!
//! An agent-bridle leash **denial** *is* a Charter **refusal**, and a refusal is
//! recorded into the **scar**. The Writ enforced becomes Refusal remembered:
//!
//! ```text
//!   writ  (agent-bridle Gate denies)  ─▶  refusal  ─▶  scar
//! ```
//!
//! This is what turns "owned by none, cited by all" from a README claim into a
//! real dependency edge: agent-bridle's structured [`Denial`] is mapped onto
//! [`charter_refusal`] and persisted in a [`charter_scar::ScarLog`]. The leash
//! already *refuses*; here that refusal stops being ephemeral and becomes part
//! of the agent's metabolized memory — an open wound until it's learned from.
//!
//! Integration draft: kept out of the agent-bridle workspace (private cross-repo
//! git-dep), built standalone. See `Cargo.toml`.
//!
//! ```
//! use charter_scar::{ScarKind, ScarLog};
//! use agent_bridle_core::{Denial, DenialKind};
//! use charter_bridle::record_denial;
//!
//! let mut log = ScarLog::new();
//! let denial = Denial {
//!     kind: DenialKind::Exec,
//!     target: "rm".into(),
//!     reason: "rm is not in the writ".into(),
//! };
//! let id = record_denial(&mut log, &denial);
//!
//! assert_eq!(log.entries()[0].id, id);
//! assert_eq!(log.entries()[0].scar.kind, ScarKind::Refusal); // a denial IS a refusal
//! assert_eq!(log.open_wounds().len(), 1);                     // remembered, unhealed
//! assert!(log.verify_chain());
//! ```

use agent_bridle_core::Denial;
use charter_refusal::{Choice, Decision};
use charter_scar::{ScarId, ScarLog};

/// Record one agent-bridle leash denial as a Charter refusal in `log`.
///
/// The leash denied the operation, so it was outside the writ
/// (`authorized = false`); it is declined with the leash's own reason and the
/// refusal is persisted. Returns the scar id.
pub fn record_denial(log: &mut ScarLog, denial: &Denial) -> ScarId {
    Decision::new(
        format!("agent-bridle leash {:?} on {}", denial.kind, denial.target),
        denial.target.clone(),
    )
    .authorized(false)
    .resolve(log, |_| Choice::Refuse(denial.reason.clone()))
    .refusal_scar()
    .cloned()
    .expect("a refusal always records a scar")
}

/// Record every denial from a bridle result (e.g. `ToolEnvelope::denials`).
/// Returns their scar ids, in order.
pub fn record_denials(log: &mut ScarLog, denials: &[Denial]) -> Vec<ScarId> {
    denials.iter().map(|d| record_denial(log, d)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_bridle_core::DenialKind;
    use charter_scar::ScarKind;

    #[test]
    fn a_leash_denial_becomes_a_recorded_refusal() {
        let mut log = ScarLog::new();
        let denial = Denial {
            kind: DenialKind::Exec,
            target: "rm".into(),
            reason: "rm is not in the writ".into(),
        };
        let id = record_denial(&mut log, &denial);

        assert_eq!(log.len(), 1);
        assert_eq!(log.entries()[0].id, id);
        assert_eq!(log.entries()[0].scar.kind, ScarKind::Refusal);
        assert!(log.entries()[0].scar.consequence.contains("not in the writ"));
        assert!(log.entries()[0].scar.action.contains("rm"));
        assert_eq!(log.open_wounds().len(), 1);
        assert!(log.verify_chain());
    }

    #[test]
    fn many_denials_accumulate_in_the_memory() {
        let mut log = ScarLog::new();
        let denials = vec![
            Denial { kind: DenialKind::Exec, target: "rm".into(), reason: "exec outside writ".into() },
            Denial { kind: DenialKind::Open, target: "/etc/shadow".into(), reason: "read outside writ".into() },
        ];
        let ids = record_denials(&mut log, &denials);
        assert_eq!(ids.len(), 2);
        assert_eq!(log.len(), 2);
        assert_eq!(log.open_wounds().len(), 2);
        assert!(log.verify_chain());
    }
}
