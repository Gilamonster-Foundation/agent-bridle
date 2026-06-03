//! The result envelope — the MCP-shaped JSON a tool returns.
//!
//! Tools that run a subprocess-like operation (the shell, exec-style tools)
//! return a uniform shape so a frontend can render them identically and so the
//! recorded [`crate::SandboxKind`] travels with every result (DESIGN §6: "the
//! Gate records `sandbox_kind` in **every** `ToolResult`").

use crate::SandboxKind;

/// Which kind of capability operation the leash refused.
///
/// Mirrors the brush `CommandInterceptor` hooks: an `exec` denial comes from
/// `before_exec` (an out-of-scope program, including a path-separator-spelled
/// one like `/bin/rm`), an `open` denial from `before_open` (a redirection or
/// `source` target outside `fs_read`/`fs_write`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DenialKind {
    /// An external command spawn was denied (`before_exec`).
    Exec,
    /// A file open (redirection/`source`) was denied (`before_open`).
    Open,
}

/// One structured leash denial recorded by the in-process interceptor.
///
/// This is the **structured security signal** that replaces stderr
/// string-matching: a denial is present here *only* when the interceptor
/// actually decided `Deny`, never merely because a permitted command exited
/// non-zero on its own.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Denial {
    /// Whether an `exec` (spawn) or an `open` (file) was refused.
    pub kind: DenialKind,
    /// The exact target the interceptor saw: the program (e.g. `rm`,
    /// `/bin/rm`) for an `exec` denial, or the path for an `open` denial.
    pub target: String,
    /// The human-readable reason from the leash (safe to surface to an agent).
    pub reason: String,
}

/// A structured execution result. Serialized to the MCP content shape via
/// [`ToolEnvelope::into_json`]; absent fields are omitted.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct ToolEnvelope {
    /// Process exit code, when the operation had one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    /// Captured standard output, when relevant.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stdout: Option<String>,
    /// Captured standard error, when relevant.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stderr: Option<String>,
    /// Whether the operation was cut short by a timeout.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timed_out: Option<bool>,
    /// Whether the in-process leash recorded at least one denial during this
    /// invocation. This is a **structured** signal: it is set iff
    /// [`Self::denials`] is non-empty, so a consumer never has to string-match
    /// stderr to detect a security refusal. Omitted (treated as `false`) when
    /// no denial was recorded.
    #[serde(skip_serializing_if = "is_false")]
    pub denied: bool,
    /// The denials the interceptor recorded, in the order they occurred. Empty
    /// (and omitted from JSON) unless [`Self::denied`] is `true`.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub denials: Vec<Denial>,
    /// The OS-level sandbox in force when this ran. Always present so callers
    /// can tell whether the leash was kernel-enforced or advisory.
    pub sandbox_kind: SandboxKind,
}

/// `skip_serializing_if` helper: omit `denied` from JSON when it is `false`.
#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_false(b: &bool) -> bool {
    !*b
}

impl ToolEnvelope {
    /// An envelope stamped with the sandbox kind and nothing else set.
    #[must_use]
    pub fn new(sandbox_kind: SandboxKind) -> Self {
        Self {
            sandbox_kind,
            ..Self::default()
        }
    }

    /// Set the exit code (builder style).
    #[must_use]
    pub fn with_exit_code(mut self, code: i32) -> Self {
        self.exit_code = Some(code);
        self
    }

    /// Set captured stdout (builder style).
    #[must_use]
    pub fn with_stdout(mut self, stdout: impl Into<String>) -> Self {
        self.stdout = Some(stdout.into());
        self
    }

    /// Set captured stderr (builder style).
    #[must_use]
    pub fn with_stderr(mut self, stderr: impl Into<String>) -> Self {
        self.stderr = Some(stderr.into());
        self
    }

    /// Mark whether the operation timed out (builder style).
    #[must_use]
    pub fn with_timed_out(mut self, timed_out: bool) -> Self {
        self.timed_out = Some(timed_out);
        self
    }

    /// Attach the leash denials the interceptor recorded (builder style).
    ///
    /// [`Self::denied`] is set to `true` iff `denials` is non-empty, so the
    /// boolean flag and the list can never disagree. Passing an empty vec is a
    /// no-op (the result stays un-denied), which keeps the common
    /// nothing-was-denied path clean.
    #[must_use]
    pub fn with_denials(mut self, denials: Vec<Denial>) -> Self {
        self.denied = !denials.is_empty();
        self.denials = denials;
        self
    }

    /// Serialize to the JSON content shape tools return.
    ///
    /// # Panics
    /// Never in practice: the envelope contains only JSON-representable scalars.
    #[must_use]
    pub fn into_json(self) -> serde_json::Value {
        serde_json::to_value(self).expect("ToolEnvelope is always JSON-serializable")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn omits_absent_fields_keeps_sandbox_kind() {
        let v = ToolEnvelope::new(SandboxKind::None)
            .with_exit_code(0)
            .with_stdout("hi\n")
            .into_json();
        assert_eq!(v["exit_code"], 0);
        assert_eq!(v["stdout"], "hi\n");
        assert!(v.get("stderr").is_none());
        assert!(v.get("timed_out").is_none());
        assert_eq!(v["sandbox_kind"], "none");
    }

    #[test]
    fn no_denials_omits_denied_and_denials() {
        // The common case: nothing was denied → neither structured field
        // appears in the JSON, so `denied` defaults to false for consumers.
        let v = ToolEnvelope::new(SandboxKind::None)
            .with_exit_code(0)
            .with_denials(Vec::new())
            .into_json();
        assert!(v.get("denied").is_none(), "denied must be omitted: {v}");
        assert!(v.get("denials").is_none(), "denials must be omitted: {v}");
    }

    #[test]
    fn recorded_denials_set_denied_true_and_list() {
        let denials = vec![Denial {
            kind: DenialKind::Exec,
            target: "rm".to_string(),
            reason: "exec of \"rm\" is not within the granted authority".to_string(),
        }];
        let v = ToolEnvelope::new(SandboxKind::None)
            .with_exit_code(126)
            .with_denials(denials)
            .into_json();
        assert_eq!(v["denied"], true);
        assert_eq!(v["denials"][0]["kind"], "exec");
        assert_eq!(v["denials"][0]["target"], "rm");
        assert!(v["denials"][0]["reason"]
            .as_str()
            .unwrap()
            .contains("not within the granted"));
    }

    #[test]
    fn denial_kind_serializes_snake_case() {
        assert_eq!(
            serde_json::to_value(DenialKind::Exec).unwrap(),
            serde_json::json!("exec")
        );
        assert_eq!(
            serde_json::to_value(DenialKind::Open).unwrap(),
            serde_json::json!("open")
        );
    }
}
