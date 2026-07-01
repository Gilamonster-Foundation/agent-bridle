//! The process-level **unbridled** marker (ADR 0018 D1/D5 — epic #139 I12).
//!
//! Unbridle is the operator's explicit escape hatch: drop the confinement
//! *mechanism* (the L3 OS sandbox) so the agent can use the host's native
//! shell/tools, while the OCAP authority grant (checked by the L2 interceptor,
//! now advisory) and the human step-up gate stay in force. This marker records
//! that decision **once, at startup**, after the loader has verified the two-key
//! acknowledgement (ADR 0018 D3). The tool layer reads it to (a) skip the OS
//! sandbox and (b) stamp `disclosure.unbridled` on every envelope.
//!
//! It is a **process mechanism, not per-invocation authority**: it deliberately
//! does *not* ride [`crate::ToolContext`] (authority≠mechanism, ADR 0017 D1). It
//! defaults to **bridled** and is *never* reachable by omission — only an
//! explicit [`set_unbridled`] from an acked loader path flips it.

use std::sync::OnceLock;

static UNBRIDLED: OnceLock<bool> = OnceLock::new();

/// Mark this process **unbridled** (confinement mechanism off). Call this once,
/// from the loader, and **only** after the acked two-key opt-in has been verified
/// (ADR 0018 D3). Idempotent: a second call is a no-op (the first wins).
///
/// This never widens *authority* — the granted [`crate::Caveats`] are unchanged;
/// it only signals that the L3 mechanism is off so the tool layer runs native and
/// discloses honestly.
pub fn set_unbridled() {
    let _ = UNBRIDLED.set(true);
}

/// Whether this process is running **unbridled**. Defaults to `false` (bridled) —
/// confinement stays on unless an acked loader path explicitly called
/// [`set_unbridled`].
#[must_use]
pub fn is_unbridled() -> bool {
    UNBRIDLED.get().copied().unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_bridled_then_set_flips_once() {
        // Never unbridled by omission (the fail-closed default).
        assert!(!is_unbridled(), "must default to bridled");
        set_unbridled();
        assert!(is_unbridled(), "set_unbridled flips the process marker");
        // Idempotent — a second call does not panic or change the state.
        set_unbridled();
        assert!(is_unbridled());
    }
}
