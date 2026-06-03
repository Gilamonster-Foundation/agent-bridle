//! The result envelope — the MCP-shaped JSON a tool returns.
//!
//! Tools that run a subprocess-like operation (the shell, exec-style tools)
//! return a uniform shape so a frontend can render them identically and so the
//! recorded [`crate::SandboxKind`] travels with every result (DESIGN §6: "the
//! Gate records `sandbox_kind` in **every** `ToolResult`").

use crate::SandboxKind;

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
    /// The OS-level sandbox in force when this ran. Always present so callers
    /// can tell whether the leash was kernel-enforced or advisory.
    pub sandbox_kind: SandboxKind,
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
}
