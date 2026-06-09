//! Stub [`ShellTool`] — full brush implementation pending reubeno/brush#1184.
//!
//! The tool registers in the registry and advertises its full schema so
//! consumers can introspect the interface. `invoke()` returns a structured
//! error rather than silently absent functionality.
//!
//! To restore the full `CommandInterceptor`-backed implementation:
//! 1. Wait for <https://github.com/reubeno/brush/pull/1184> to merge and ship
//!    a crates.io release.
//! 2. Add brush deps back to `Cargo.toml` (see commented lines there).
//! 3. Restore `caveat_interceptor.rs` and the full `shell_tool.rs` from git
//!    history (`git show HEAD~1:agent-bridle-tool-shell/src/shell_tool.rs`).
//!
//! See <https://github.com/Gilamonster-Foundation/agent-bridle/issues/20>.

use agent_bridle_core::{Tool, ToolContext, ToolError, ToolResult};
use async_trait::async_trait;

/// Maximum permitted timeout constant — kept for schema accuracy.
const MAX_TIMEOUT_SECS: u64 = 300;

/// A shell tool stub.
///
/// Registers under the name `"shell"` and advertises the full argv/free-form
/// interface. Invocations return [`ToolError::Other`] with a message explaining
/// the temporary degradation and pointing to the tracking issue.
#[derive(Debug, Default, Clone, Copy)]
pub struct ShellTool;

impl ShellTool {
    /// Construct the tool.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Tool for ShellTool {
    fn name(&self) -> &str {
        "shell"
    }

    fn schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "program": {
                    "type": "string",
                    "description": "Argv form: the command to run (argv[0]). \
                        Gated by the `exec` caveat. Mutually exclusive with `cmd`."
                },
                "args": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "Argv form: arguments passed to `program` (argv[1..])."
                },
                "cmd": {
                    "type": "string",
                    "description": "Free-form: an sh -c-style command string \
                        (pipelines, redirections, &&, globbing). Confined in-process \
                        by the capability interceptor hook (exec + fs). Mutually \
                        exclusive with `program`."
                },
                "cwd": {
                    "type": "string",
                    "description": "Working directory for the command."
                },
                "timeout_secs": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": MAX_TIMEOUT_SECS,
                    "description": "Wall-clock timeout bound (not a coordination primitive)."
                }
            },
            "additionalProperties": false
        })
    }

    async fn invoke(
        &self,
        _args: serde_json::Value,
        _cx: &ToolContext,
    ) -> ToolResult<serde_json::Value> {
        Err(ToolError::Other(anyhow::anyhow!(
            "shell tool is temporarily unavailable in this build.\n\
             \n\
             The confined shell requires the `CommandInterceptor` hook from our \
             brush fork, which cannot be packaged as a crates.io dependency until \
             the upstream PR merges: https://github.com/reubeno/brush/pull/1184\n\
             \n\
             Tracking: https://github.com/Gilamonster-Foundation/agent-bridle/issues/20"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_is_shell() {
        assert_eq!(ShellTool::new().name(), "shell");
    }

    #[test]
    fn schema_has_program_and_cmd_properties() {
        let s = ShellTool::new().schema();
        let props = s.get("properties").unwrap();
        assert!(props.get("program").is_some());
        assert!(props.get("cmd").is_some());
        assert!(props.get("args").is_some());
        assert!(props.get("cwd").is_some());
        assert!(props.get("timeout_secs").is_some());
    }

    #[tokio::test]
    async fn invoke_returns_unavailable_error() {
        use agent_bridle_core::{Caveats, Gate, Tool};
        // ToolContext has no public constructor; mint one via Gate::authorize.
        struct Passthrough;
        #[async_trait::async_trait]
        impl Tool for Passthrough {
            fn name(&self) -> &str {
                "passthrough"
            }
            fn schema(&self) -> serde_json::Value {
                serde_json::Value::Null
            }
            async fn invoke(
                &self,
                _: serde_json::Value,
                _: &agent_bridle_core::ToolContext,
            ) -> agent_bridle_core::ToolResult<serde_json::Value> {
                Ok(serde_json::Value::Null)
            }
        }
        let cx = Gate::new(0)
            .authorize(&Passthrough, &Caveats::top())
            .expect("authorize");
        let result = ShellTool::new()
            .invoke(serde_json::json!({"cmd": "echo hi"}), &cx)
            .await;
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("reubeno/brush/pull/1184"), "got: {msg}");
    }
}
