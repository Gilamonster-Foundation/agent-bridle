//! MCP protocol handlers: `initialize`, `tools/list`, `tools/call`.
//!
//! These translate between the MCP wire shapes and the agent-bridle
//! [`Registry`]. The load-bearing one is [`tools_call`]: it dispatches through
//! the registry (the single capability choke point) and — crucially — surfaces
//! a leash **denial** as an MCP *tool error* (`isError: true`) inside an `Ok`
//! result, NOT a JSON-RPC transport error. The MCP boundary must carry the
//! denial reason back to the model so the leash is observable end-to-end.

use agent_bridle::{Caveats, Registry, ToolError};
use serde_json::Value;

use crate::server::PROTOCOL_VERSION;

/// `initialize` → advertise protocol version, the `tools` capability, and our
/// server identity (name + crate version).
#[must_use]
pub fn initialize() -> Value {
    serde_json::json!({
        "protocolVersion": PROTOCOL_VERSION,
        "capabilities": { "tools": {} },
        "serverInfo": {
            "name": "agent-bridle-mcp",
            "version": env!("CARGO_PKG_VERSION"),
        }
    })
}

/// `tools/list` → wrap the registry's tool definitions as MCP tool defs.
///
/// Each entry is `{ name, description, inputSchema }`; the registry already
/// produces `{ name, inputSchema }`, so we add a generic description noting the
/// tool runs under the agent-bridle capability leash.
#[must_use]
pub fn tools_list(registry: &Registry) -> Value {
    let tools: Vec<Value> = registry
        .tool_definitions()
        .into_iter()
        .map(|mut def| {
            if let Value::Object(map) = &mut def {
                map.entry("description").or_insert_with(|| {
                    Value::String(
                        "Capability-confined agent-bridle tool. Dispatch is enforced by the \
                         granted Caveats leash."
                            .to_string(),
                    )
                });
            }
            def
        })
        .collect();
    serde_json::json!({ "tools": tools })
}

/// `tools/call` → `{ name, arguments }` → `registry.dispatch(name, args,
/// &granted)` → MCP content result.
///
/// The whole point: dispatch is confined to `granted`. A leash denial (or any
/// other tool failure) becomes an MCP **tool error** — `{ content: [...],
/// isError: true }` — carrying the reason, so the model sees *why* it was
/// refused without the call collapsing into a transport-level fault.
///
/// This handler returns `Value` (never `Err`) on purpose: a well-formed
/// `tools/call` always yields a `result`. Genuinely malformed params (e.g. a
/// missing/non-string `name`) also come back as an `isError` content result,
/// because they are a tool-level mistake, not a protocol fault.
pub async fn tools_call(registry: &Registry, granted: &Caveats, params: Value) -> Value {
    let Some(name) = params.get("name").and_then(Value::as_str) else {
        return tool_error("missing or non-string `name` in tools/call params");
    };
    let arguments = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| Value::Object(serde_json::Map::new()));

    match registry.dispatch(name, arguments, granted).await {
        Ok(result) => tool_success(&result),
        // A leash denial — the headline case. Surface the reason in-band.
        Err(e @ ToolError::Denied { .. }) => tool_error(&e.to_string()),
        // Other leash/runtime failures are also tool-level outcomes, not
        // transport faults: budget exhausted, generation mismatch, unknown
        // tool, or an error from inside a tool that passed the leash.
        Err(e) => tool_error(&e.to_string()),
    }
}

/// A successful MCP tool result: the tool's JSON value rendered as `text`
/// content. (Structured output is preserved verbatim so a client that prefers
/// the raw envelope can re-parse it.)
fn tool_success(result: &Value) -> Value {
    let text = match result {
        Value::String(s) => s.clone(),
        other => serde_json::to_string(other).unwrap_or_else(|_| other.to_string()),
    };
    serde_json::json!({
        "content": [{ "type": "text", "text": text }],
        "isError": false,
    })
}

/// An MCP tool *error* result: `isError: true` with the reason as `text`
/// content. This is what a leash denial looks like across the MCP boundary.
fn tool_error(reason: &str) -> Value {
    serde_json::json!({
        "content": [{ "type": "text", "text": reason }],
        "isError": true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A grant that allows only `echo` — used by the shell-tool tests.
    #[cfg(feature = "shell")]
    fn echo_grant() -> Caveats {
        use agent_bridle::{CountBound, Scope};
        Caveats {
            exec: Scope::only(["echo".to_string()]),
            max_calls: CountBound::AtMost(4),
            ..Caveats::top()
        }
    }

    #[test]
    fn initialize_shape() {
        let v = initialize();
        assert_eq!(v["protocolVersion"], PROTOCOL_VERSION);
        assert_eq!(v["serverInfo"]["name"], "agent-bridle-mcp");
        assert!(v["capabilities"]["tools"].is_object());
    }

    #[cfg(feature = "shell")]
    #[test]
    fn tools_list_wraps_definitions_with_descriptions() {
        let reg = agent_bridle::registry();
        let v = tools_list(&reg);
        let tools = v["tools"].as_array().unwrap();
        let shell = tools
            .iter()
            .find(|t| t["name"] == "shell")
            .expect("shell present");
        assert!(shell["inputSchema"].is_object());
        assert!(shell["description"].is_string());
    }

    #[cfg(feature = "shell")]
    #[tokio::test]
    async fn call_in_scope_succeeds() {
        let reg = agent_bridle::registry();
        let v = tools_call(
            &reg,
            &echo_grant(),
            serde_json::json!({ "name": "shell", "arguments": { "program": "echo", "args": ["hi"] } }),
        )
        .await;
        assert_eq!(v["isError"], false);
        let text = v["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("hi"), "tool stdout missing: {text}");
    }

    #[cfg(feature = "shell")]
    #[tokio::test]
    async fn call_out_of_scope_is_in_band_denial() {
        let reg = agent_bridle::registry();
        let v = tools_call(
            &reg,
            &echo_grant(),
            serde_json::json!({ "name": "shell", "arguments": { "program": "rm", "args": ["-rf", "/"] } }),
        )
        .await;
        // The denial is an MCP tool error, NOT a transport error: isError=true
        // with the reason carried in the content.
        assert_eq!(v["isError"], true);
        let text = v["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("denied"), "denial reason missing: {text}");
        assert!(text.contains("rm"), "denied program missing: {text}");
    }

    #[tokio::test]
    async fn call_unknown_tool_is_in_band_error() {
        let reg = agent_bridle::registry();
        let v = tools_call(
            &reg,
            &Caveats::top(),
            serde_json::json!({ "name": "no_such_tool", "arguments": {} }),
        )
        .await;
        assert_eq!(v["isError"], true);
        assert!(v["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("no_such_tool"));
    }

    #[tokio::test]
    async fn call_missing_name_is_in_band_error() {
        let reg = agent_bridle::registry();
        let v = tools_call(&reg, &Caveats::top(), serde_json::json!({})).await;
        assert_eq!(v["isError"], true);
    }
}
