//! One shell request every engine parses (#490).
//!
//! The three engines share `cmd`, `cwd`, `env` and `timeout_secs`. Parsing them
//! once means each engine fences `env` the same way (AB-004) and honors the
//! same timeout clamp. Unknown keys are ignored. This closes the argument half
//! of #476; an `export` or `VAR=value` prefix inside `cmd` stays with #476.

use std::collections::BTreeMap;
use std::time::Duration;

use agent_bridle_core::{LimitsPolicy, ToolError, ToolResult};

/// The parsed arguments of one `shell` call.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ShellRequest {
    /// Argv form (safe-subset only): the program to run.
    pub program: Option<String>,
    /// Argv form: literal arguments to `program`.
    pub args: Vec<String>,
    /// Free-form command line.
    pub cmd: Option<String>,
    /// Working directory, as given.
    pub cwd: Option<String>,
    /// Caller env as given. Read it through [`ShellRequest::env`], which fences it.
    env: BTreeMap<String, String>,
    /// Per-call timeout, as given.
    timeout_secs: Option<u64>,
}

impl ShellRequest {
    /// Parse a `shell` call's arguments. Non-string values are dropped.
    pub(crate) fn parse(v: &serde_json::Value) -> ToolResult<Self> {
        let obj = v
            .as_object()
            .ok_or_else(|| ToolError::denied("shell args must be a JSON object"))?;
        let string = |key: &str| obj.get(key).and_then(|x| x.as_str()).map(String::from);
        Ok(Self {
            program: string("program"),
            args: obj
                .get("args")
                .and_then(|x| x.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default(),
            cmd: string("cmd"),
            cwd: string("cwd"),
            env: obj
                .get("env")
                .and_then(|x| x.as_object())
                .map(|m| {
                    m.iter()
                        .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                        .collect()
                })
                .unwrap_or_default(),
            timeout_secs: obj.get("timeout_secs").and_then(serde_json::Value::as_u64),
        })
    }

    /// The required `cmd` of an engine that only takes the free-form shape.
    #[cfg(any(feature = "host-shell", feature = "brush"))]
    pub(crate) fn require_cmd(&self, engine: &str) -> ToolResult<&str> {
        self.cmd
            .as_deref()
            .ok_or_else(|| ToolError::denied(format!("{engine}: missing required `cmd` string")))
    }

    /// The caller env with every denied loader/hook name dropped (AB-004).
    pub(crate) fn env(&self, limits: &LimitsPolicy) -> BTreeMap<String, String> {
        agent_bridle_core::fence_env(&self.env, &limits.env_denylist).0
    }

    /// `timeout_secs` clamped to `1..=max_timeout_secs`; an omitted one keeps
    /// the engine's `configured` timeout.
    pub(crate) fn timeout(&self, limits: &LimitsPolicy, configured: Duration) -> Duration {
        self.timeout_secs.map_or(configured, |secs| {
            Duration::from_secs(secs.clamp(1, limits.max_timeout_secs))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// #490: one parse for every engine; unknown keys are ignored.
    #[test]
    fn parses_the_shared_fields_and_ignores_unknown_keys() {
        let req = ShellRequest::parse(&serde_json::json!({
            "cmd": "ls", "cwd": "/tmp", "env": {"A": "1", "N": 2},
            "timeout_secs": 5, "timeout": 9, "bogus": true,
        }))
        .unwrap();
        assert_eq!(req.cmd.as_deref(), Some("ls"));
        assert_eq!(req.cwd.as_deref(), Some("/tmp"));
        assert_eq!(req.env(&LimitsPolicy::default()).len(), 1);
        assert_eq!(req.timeout_secs, Some(5));
        assert!(ShellRequest::parse(&serde_json::json!("ls")).is_err());
    }

    /// #490: `env()` drops the denied loader/hook names and keeps the rest.
    #[test]
    fn env_drops_denied_names() {
        let req = ShellRequest::parse(&serde_json::json!({
            "env": {"LD_PRELOAD": "/evil.so", "BASH_ENV": "/evil", "SAFE": "keep"},
        }))
        .unwrap();
        let env = req.env(&LimitsPolicy::default());
        assert_eq!(env.keys().collect::<Vec<_>>(), ["SAFE"]);
    }

    /// #490: a given timeout is clamped; an omitted one keeps the configured one.
    #[test]
    fn timeout_clamps_and_defaults_to_the_configured_value() {
        let limits = LimitsPolicy::default();
        let configured = Duration::from_secs(42);
        let t = |v| {
            ShellRequest::parse(&v)
                .unwrap()
                .timeout(&limits, configured)
        };
        assert_eq!(t(serde_json::json!({})), configured);
        assert_eq!(
            t(serde_json::json!({"timeout_secs": 0})),
            Duration::from_secs(1)
        );
        assert_eq!(
            t(serde_json::json!({"timeout_secs": 1_000_000})),
            Duration::from_secs(limits.max_timeout_secs)
        );
        assert_eq!(
            t(serde_json::json!({"timeout_secs": 7})),
            Duration::from_secs(7)
        );
    }

    /// #490: all three engines' schemas carry the shared request fields, and
    /// each `env` description tells the model that denied names are dropped.
    #[test]
    fn every_engine_schema_pins_the_shared_request_fields() {
        for (engine, raw) in [
            ("safe-subset", include_str!("shell_tool.schema.json")),
            ("host", include_str!("host_shell.schema.json")),
            ("brush", include_str!("brush_shell.schema.json")),
        ] {
            let schema: serde_json::Value = serde_json::from_str(raw).unwrap();
            let props = &schema["properties"];
            for field in ["cmd", "cwd", "env", "timeout_secs"] {
                assert!(props[field].is_object(), "{engine} schema lacks `{field}`");
            }
            let env = props["env"]["description"].as_str().unwrap();
            assert!(env.contains("are dropped"), "{engine} env: {env}");
            assert!(!env.contains("additive"), "{engine} env: {env}");
        }
    }
}
