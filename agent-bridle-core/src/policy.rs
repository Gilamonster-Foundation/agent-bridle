//! **OCAP durable-policy schema** — the shared contract for per-verdict
//! permission policy (agent-bridle #220; newt-agent #1126 track O).
//!
//! The accumulation loop: an agent harness prompts for a capability, the human
//! decides, and a *durable* decision is stored as **data** the whole fleet can
//! honor — the leash loosens with use instead of staying naggy or getting
//! bypassed. This module defines only the SCHEMA + pure evaluation: types,
//! parse/serialize, merge, and the precedence law. No enforcement changes here;
//! stores (e.g. newt's `~/.newt/ocap/`) implement against it.
//!
//! ## The file shape
//!
//! One TOML file per verdict — `approve.toml`, `deny.toml`, `ask.toml`,
//! `passkey.toml` — each holding entries per capability class:
//!
//! ```toml
//! # ~/.newt/ocap/approve.toml
//! [[exec]]
//! target = "cargo"
//! note = "build tooling"
//! granted = "2026-07-14"
//!
//! [[fs]]
//! path = "~/workspaces"
//! write = true
//!
//! [[net]]
//! host = "crates.io"
//! ```
//!
//! ## The precedence law (load-bearing)
//!
//! When a target matches entries in several verdict files, the MOST
//! RESTRICTIVE wins: **deny > passkey > ask > approve**. A durable deny can
//! never be shadowed by a durable approve; a passkey step-up outranks a plain
//! ask. Evaluation returns `None` when no durable policy matches — the harness
//! falls through to its interactive prompt (or its default-deny floor).
//!
//! ## Danger-tier invariant (part of the contract)
//!
//! High-danger targets (interpreter exec, broad filesystem roots — as judged by
//! the *consuming* harness's danger table) MUST NOT be durably approvable: a
//! store rejects writing such an entry into `approve.toml` (at most it may
//! offer `passkey.toml`). This module cannot see the harness's danger table,
//! so [`PolicySet::validate_approve`] takes the judgment as a predicate — the
//! contract is that stores CALL it before persisting an approve entry.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// The four durable verdicts — one policy file each. Ordered by restrictiveness
/// (most restrictive first); [`Verdict::precedence`] makes the law explicit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// Never allowed; the prompt is not even offered. `deny.toml`.
    Deny,
    /// Allowed only after a WebAuthn/passkey step-up (presence proof).
    /// `passkey.toml` — schema now; enforcement lands with the presence anchor.
    Passkey,
    /// Always prompt, even if a broader approve would match. `ask.toml` pins
    /// a target to interactive judgment.
    Ask,
    /// Durably allowed without prompting. `approve.toml`.
    Approve,
}

impl Verdict {
    /// Lower = more restrictive = wins ties. deny(0) > passkey(1) > ask(2) >
    /// approve(3).
    pub fn precedence(self) -> u8 {
        match self {
            Self::Deny => 0,
            Self::Passkey => 1,
            Self::Ask => 2,
            Self::Approve => 3,
        }
    }

    /// The canonical policy filename for this verdict (`deny.toml`, …).
    pub fn filename(self) -> &'static str {
        match self {
            Self::Deny => "deny.toml",
            Self::Passkey => "passkey.toml",
            Self::Ask => "ask.toml",
            Self::Approve => "approve.toml",
        }
    }
}

/// An exec-capability entry: a command target (basename or absolute path,
/// matched by the consuming harness's own exec-matching rules).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecEntry {
    /// The command target — a basename (`cargo`) or absolute path.
    pub target: String,
    /// Free-form human note ("build tooling").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// ISO 8601 date/datetime the decision was recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub granted: Option<String>,
    /// Who recorded it: `human` (interactive prompt), `seed` (a shipped
    /// common-settings profile), or a tool name. Free-form provenance.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub by: Option<String>,
}

/// A filesystem-capability entry: a path prefix (with `~` expansion left to
/// the consuming store) and whether writes are covered.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FsEntry {
    /// The covered path prefix (`~` expansion is the store's job).
    pub path: String,
    /// `false`/absent = read-only coverage; `true` covers writes too.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub write: bool,
    /// Free-form human note.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// ISO 8601 date/datetime the decision was recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub granted: Option<String>,
    /// Who recorded it: `human`, `seed`, or a tool name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub by: Option<String>,
}

/// A network-capability entry: a host (exact or the consuming harness's
/// wildcard rules).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetEntry {
    /// The covered host (exact, or the harness's wildcard rules).
    pub host: String,
    /// Free-form human note.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// ISO 8601 date/datetime the decision was recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub granted: Option<String>,
    /// Who recorded it: `human`, `seed`, or a tool name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub by: Option<String>,
}

/// One verdict file's contents: entries per capability class. All classes
/// optional — an empty file is valid (and means "no durable policy of this
/// verdict"). `deny_unknown_fields` keeps typos loud, matching the house
/// model-card discipline.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyFile {
    /// Exec-class entries (`[[exec]]`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exec: Vec<ExecEntry>,
    /// Filesystem-class entries (`[[fs]]`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fs: Vec<FsEntry>,
    /// Network-class entries (`[[net]]`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub net: Vec<NetEntry>,
}

impl PolicyFile {
    /// Parse one verdict file from TOML.
    pub fn parse(contents: &str) -> Result<Self, String> {
        toml::from_str(contents).map_err(|e| format!("ocap policy TOML: {e}"))
    }

    /// Serialize back to TOML (minimal — empty classes are skipped).
    pub fn to_toml(&self) -> Result<String, String> {
        toml::to_string(self).map_err(|e| format!("ocap policy serialize: {e}"))
    }
}

/// The capability classes durable policy can cover. Kept closed and small on
/// purpose — a new class is a contract rev, not a stringly-typed extension
/// (unlike knob maps, a *permission* surface must be enumerable to audit).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityClass {
    /// Command execution.
    Exec,
    /// Filesystem access.
    Fs,
    /// Network access.
    Net,
}

/// A full policy set: the four verdict files, loaded by a store. Evaluation
/// applies the precedence law across them.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct PolicySet {
    /// The loaded verdict files, keyed by verdict.
    pub files: BTreeMap<Verdict, PolicyFile>,
}

impl PolicySet {
    /// Look up the durable verdict for a target, applying the precedence law:
    /// the most restrictive matching verdict wins (deny > passkey > ask >
    /// approve). `None` = no durable policy — the harness falls through to its
    /// interactive prompt / default-deny floor.
    ///
    /// Matching here is EXACT (string equality on target/path/host); a
    /// consuming harness with richer matching (basenames, path prefixes,
    /// wildcards) normalizes the candidate before calling, or evaluates its
    /// own match and uses [`Verdict::precedence`] to combine.
    pub fn evaluate(&self, class: CapabilityClass, target: &str) -> Option<Verdict> {
        let mut best: Option<Verdict> = None;
        for (&verdict, file) in &self.files {
            let hit = match class {
                CapabilityClass::Exec => file.exec.iter().any(|e| e.target == target),
                CapabilityClass::Fs => file.fs.iter().any(|e| e.path == target),
                CapabilityClass::Net => file.net.iter().any(|e| e.host == target),
            };
            if hit && best.is_none_or(|b| verdict.precedence() < b.precedence()) {
                best = Some(verdict);
            }
        }
        best
    }

    /// The danger-tier invariant hook: a store MUST call this before
    /// persisting an entry into `approve.toml`, passing its own danger
    /// judgment. High-danger targets are never durably approvable — the
    /// contract offers `Passkey` as the strongest grant for them.
    pub fn validate_approve(
        class: CapabilityClass,
        target: &str,
        is_high_danger: impl Fn(CapabilityClass, &str) -> bool,
    ) -> Result<(), String> {
        if is_high_danger(class, target) {
            return Err(format!(
                "`{target}` is a high-danger target and cannot be durably approved \
                 (offer passkey step-up instead)"
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set_with(verdict: Verdict, file: PolicyFile) -> PolicySet {
        let mut s = PolicySet::default();
        s.files.insert(verdict, file);
        s
    }

    #[test]
    fn verdict_files_and_precedence_are_canonical() {
        assert_eq!(Verdict::Deny.filename(), "deny.toml");
        assert_eq!(Verdict::Approve.filename(), "approve.toml");
        // The law: deny > passkey > ask > approve.
        assert!(Verdict::Deny.precedence() < Verdict::Passkey.precedence());
        assert!(Verdict::Passkey.precedence() < Verdict::Ask.precedence());
        assert!(Verdict::Ask.precedence() < Verdict::Approve.precedence());
    }

    #[test]
    fn parses_the_documented_approve_file() {
        let f = PolicyFile::parse(
            "[[exec]]\ntarget = \"cargo\"\nnote = \"build tooling\"\ngranted = \"2026-07-14\"\n\n\
             [[fs]]\npath = \"~/workspaces\"\nwrite = true\n\n[[net]]\nhost = \"crates.io\"\n",
        )
        .unwrap();
        assert_eq!(f.exec[0].target, "cargo");
        assert!(f.fs[0].write);
        assert_eq!(f.net[0].host, "crates.io");
        // Round-trip stays minimal (no empty classes, no None provenance).
        let out = f.to_toml().unwrap();
        assert!(!out.contains("by ="), "unset provenance skipped: {out}");
    }

    #[test]
    fn empty_and_unknown_field_behavior() {
        // An empty file is valid — no durable policy of that verdict.
        assert_eq!(PolicyFile::parse("").unwrap(), PolicyFile::default());
        // A typo'd key is a loud error (deny_unknown_fields).
        assert!(PolicyFile::parse("[[exec]]\ntarget=\"x\"\nnotee=\"typo\"\n").is_err());
    }

    #[test]
    fn deny_shadows_approve_and_passkey_outranks_ask() {
        let mut s = PolicySet::default();
        s.files.insert(
            Verdict::Approve,
            PolicyFile::parse("[[exec]]\ntarget=\"rm\"\n").unwrap(),
        );
        s.files.insert(
            Verdict::Deny,
            PolicyFile::parse("[[exec]]\ntarget=\"rm\"\n").unwrap(),
        );
        // A durable deny can never be shadowed by a durable approve.
        assert_eq!(s.evaluate(CapabilityClass::Exec, "rm"), Some(Verdict::Deny));

        let mut s = PolicySet::default();
        s.files.insert(
            Verdict::Ask,
            PolicyFile::parse("[[net]]\nhost=\"api.example\"\n").unwrap(),
        );
        s.files.insert(
            Verdict::Passkey,
            PolicyFile::parse("[[net]]\nhost=\"api.example\"\n").unwrap(),
        );
        assert_eq!(
            s.evaluate(CapabilityClass::Net, "api.example"),
            Some(Verdict::Passkey)
        );
    }

    #[test]
    fn no_match_falls_through_to_the_interactive_floor() {
        let s = set_with(
            Verdict::Approve,
            PolicyFile::parse("[[exec]]\ntarget=\"cargo\"\n").unwrap(),
        );
        assert_eq!(s.evaluate(CapabilityClass::Exec, "python3"), None);
        assert_eq!(
            s.evaluate(CapabilityClass::Fs, "cargo"),
            None,
            "class-scoped"
        );
    }

    #[test]
    fn high_danger_targets_are_never_durably_approvable() {
        let judge = |class: CapabilityClass, target: &str| {
            class == CapabilityClass::Exec && (target == "bash" || target == "python3")
        };
        assert!(PolicySet::validate_approve(CapabilityClass::Exec, "bash", judge).is_err());
        assert!(PolicySet::validate_approve(CapabilityClass::Exec, "cargo", judge).is_ok());
        assert!(PolicySet::validate_approve(CapabilityClass::Net, "bash", judge).is_ok());
    }
}
