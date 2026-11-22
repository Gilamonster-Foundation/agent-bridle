//! Build the server from the layered mechanism configuration (#495).
//!
//! `[bridle]` in `~/.agent-bridle/config.toml` and the `BRIDLE_*` environment
//! tune **mechanism** only: which shell engine serves the `shell` tool, its
//! limits and sandbox policy, and the confinement floor every call is
//! dispatched with. The grant (authority) is sourced separately, by
//! [`crate::caveats_source`]. A setting this build cannot honor fails startup;
//! it is never replaced by a default.

use agent_bridle::{BridleConfig, Caveats, Registry};

use crate::server::McpServer;

/// The server for `config`, confining every call to `granted`.
pub fn server(config: &BridleConfig, granted: Caveats) -> anyhow::Result<McpServer> {
    Ok(McpServer::new(registry(config)?, granted)
        .with_enforcement_floor(config.gate.default_strength_floor))
}

/// The registry for `config`. `[bridle.shell] engine` selects the engine; left
/// unset, the facade's own rule applies (carried Brush where its worker
/// transport exists, else safe-subset), not `ShellEngine::default()`.
fn registry(config: &BridleConfig) -> anyhow::Result<Registry> {
    #[cfg(any(feature = "shell", feature = "carried-coreutils"))]
    {
        use agent_bridle::{ShellEngine, ShellOptions};
        let engine = match config.shell.engine.as_deref() {
            Some(token) => token
                .parse::<ShellEngine>()
                .map_err(|error| anyhow::anyhow!("[bridle.shell] engine: {error}"))?,
            None => agent_bridle::default_shell_engine(),
        };
        let options = ShellOptions {
            limits: config.limits.clone(),
            sandbox: std::sync::Arc::new(config.sandbox.clone()),
            ..ShellOptions::default()
        };
        agent_bridle::registry_with_shell(engine, options)
            .map_err(|error| anyhow::anyhow!("cannot build the `{engine}` shell engine: {error}"))
    }
    #[cfg(not(any(feature = "shell", feature = "carried-coreutils")))]
    {
        if let Some(token) = &config.shell.engine {
            anyhow::bail!("[bridle.shell] engine = {token:?}, but this build has no shell engine");
        }
        Ok(agent_bridle::registry())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handlers;
    use std::collections::BTreeMap;

    /// The server a config file would produce, with no environment overlay.
    #[cfg(any(feature = "shell", feature = "carried-coreutils"))]
    fn from_toml(file: &str) -> anyhow::Result<McpServer> {
        let (config, _) = agent_bridle_config::resolve(Some(file), &BTreeMap::new(), None)?;
        server(&config, Caveats::top())
    }

    #[cfg(any(feature = "shell", feature = "carried-coreutils"))]
    fn shell_schema(server: &McpServer) -> serde_json::Value {
        let tools = handlers::tools_list(server.registry());
        tools["tools"]
            .as_array()
            .unwrap()
            .iter()
            .find(|tool| tool["name"] == "shell")
            .expect("shell is served")["inputSchema"]
            .clone()
    }

    /// #495: `engine = "safe-subset"` selects the argv engine, whose schema
    /// advertises `program`. Before this the config was never read, so the
    /// default build served carried Brush whatever the file said.
    #[cfg(any(feature = "shell", feature = "carried-coreutils"))]
    #[test]
    fn configured_engine_is_the_one_served() {
        let server = from_toml("[bridle.shell]\nengine = \"safe-subset\"\n").expect("build");
        assert!(
            shell_schema(&server)["properties"]["program"].is_object(),
            "the safe-subset schema advertises `program`"
        );
    }

    /// #495: an unset engine keeps the facade's rule, not
    /// `ShellEngine::default()` (safe-subset).
    #[cfg(any(feature = "shell", feature = "carried-coreutils"))]
    #[test]
    fn unset_engine_keeps_the_default_registry_rule() {
        let server = from_toml("").expect("build");
        let default = McpServer::new(agent_bridle::registry(), Caveats::top());
        assert_eq!(shell_schema(&server), shell_schema(&default));
    }

    /// #495: a setting this build cannot honor fails startup: an unknown
    /// engine token, an engine that is not compiled in or has no transport
    /// here, and the old scalar gate floor.
    #[cfg(any(feature = "shell", feature = "carried-coreutils"))]
    #[test]
    fn unhonorable_settings_fail_startup() {
        use agent_bridle::ShellEngine;
        let unknown = from_toml("[bridle.shell]\nengine = \"bogus\"\n")
            .err()
            .expect("refused");
        assert!(
            unknown.to_string().contains("unknown shell engine"),
            "{unknown}"
        );

        // A workspace `--all-features` build on Linux compiles every engine;
        // then there is no unavailable engine to try.
        if let Some(engine) = ShellEngine::ALL
            .into_iter()
            .find(|engine| engine.validate_available().is_err())
        {
            let error = from_toml(&format!("[bridle.shell]\nengine = \"{engine}\"\n"))
                .err()
                .expect("an unavailable engine must fail startup");
            assert!(error.to_string().contains("cannot build"), "{error}");
        }

        let scalar = from_toml("[bridle.gate]\ndefault_strength_floor = \"kernel\"\n");
        assert!(scalar.is_err(), "a scalar floor must fail startup");
    }

    /// #495: the configured floor reaches the tool. A stub reports the floor
    /// its context was minted with.
    #[tokio::test]
    async fn a_tool_sees_the_configured_floor() {
        struct Floor;
        #[async_trait::async_trait]
        impl agent_bridle::Tool for Floor {
            fn name(&self) -> &str {
                "floor"
            }
            fn schema(&self) -> serde_json::Value {
                serde_json::json!({ "type": "object" })
            }
            async fn invoke(
                &self,
                _args: serde_json::Value,
                cx: &agent_bridle::ToolContext,
            ) -> agent_bridle::ToolResult<serde_json::Value> {
                let floor = cx.strength_floor();
                Ok(serde_json::json!({ "exec": floor.exec(), "net": floor.net() }))
            }
        }
        let toml =
            "[bridle.gate.default_strength_floor]\nexec = \"interceptor\"\nnet = \"kernel\"\n";
        let (config, _) = agent_bridle_config::resolve(Some(toml), &BTreeMap::new(), None).unwrap();
        let registry = Registry::builder().tool(std::sync::Arc::new(Floor)).build();
        let grant = registry.mint_grant(Caveats::top());
        let call = |floor| {
            let (registry, grant) = (&registry, &grant);
            async move {
                let out = handlers::tools_call_with_floor(
                    registry,
                    grant,
                    floor,
                    serde_json::json!({ "name": "floor" }),
                )
                .await;
                out["content"][0]["text"].as_str().unwrap().to_string()
            }
        };
        assert_eq!(
            call(config.gate.default_strength_floor).await,
            r#"{"exec":"interceptor","net":"kernel"}"#
        );
        assert_eq!(
            call(agent_bridle::EnforcementFloor::DEFAULT).await,
            r#"{"exec":"advisory","net":"advisory"}"#
        );
    }
}
