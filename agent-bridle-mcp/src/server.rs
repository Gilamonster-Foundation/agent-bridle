//! The MCP stdio JSON-RPC 2.0 server.
//!
//! Framing matches `newt-mcp-server`: **newline-delimited** JSON-RPC 2.0 over
//! stdio — one request object per line, one response object per line. This is
//! the framing MCP clients that drive a child process over stdio expect, and it
//! keeps the loop trivially testable over any `AsyncRead`/`AsyncWrite` pair.
//!
//! The server owns the leashed [`Registry`] and the session's **granted**
//! [`Caveats`] (the leash). Every `tools/call` flows through
//! [`Registry::dispatch`], so the capability gate is on the only path to running
//! a tool — confinement is real *through* the MCP boundary, not just in-proc.
//!
//! Methods handled: `initialize`, `tools/list`, `tools/call`, plus the
//! `shutdown`/`exit` lifecycle. `notifications/*` (no `id`) are accepted and
//! acknowledged silently per JSON-RPC notification semantics.

use agent_bridle::{Caveats, Registry};
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use crate::handlers;

/// The MCP protocol version this server advertises in `initialize`.
///
/// Matches the value `newt-mcp-server` reports, so a client that pins a version
/// sees a consistent surface across the agent line.
pub const PROTOCOL_VERSION: &str = "2024-11-05";

/// A leashed MCP server: a tool [`Registry`] plus the granted [`Caveats`] every
/// dispatch is confined to.
pub struct McpServer {
    registry: Registry,
    granted: Caveats,
}

impl McpServer {
    /// Build a server over `registry`, confining every `tools/call` to
    /// `granted`.
    #[must_use]
    pub fn new(registry: Registry, granted: Caveats) -> Self {
        Self { registry, granted }
    }

    /// Run over real stdin/stdout (the production entry point).
    pub async fn run_stdio(&self) -> anyhow::Result<()> {
        self.run(tokio::io::stdin(), tokio::io::stdout()).await
    }

    /// Run over an arbitrary async reader/writer.
    ///
    /// Reads newline-delimited JSON-RPC requests, dispatches each to the right
    /// MCP handler, and writes one newline-terminated JSON-RPC response per
    /// request that carries an `id`. Returns `Ok(())` when the input reaches
    /// EOF or an `exit` notification is received.
    pub async fn run<R, W>(&self, reader: R, mut writer: W) -> anyhow::Result<()>
    where
        R: tokio::io::AsyncRead + Unpin,
        W: tokio::io::AsyncWrite + Unpin,
    {
        let buf = BufReader::new(reader);
        let mut lines = buf.lines();

        while let Some(line) = lines.next_line().await? {
            if line.trim().is_empty() {
                continue;
            }

            let request: Value = match serde_json::from_str(&line) {
                Ok(v) => v,
                Err(e) => {
                    let resp = error_response(Value::Null, -32700, &format!("Parse error: {e}"));
                    write_response(&mut writer, &resp).await?;
                    continue;
                }
            };

            let id = request.get("id").cloned();
            let method = request.get("method").and_then(Value::as_str).unwrap_or("");
            let params = request.get("params").cloned().unwrap_or(Value::Null);

            // `exit` is a notification that ends the session. Stop the loop
            // before writing anything (it has no response).
            if method == "exit" {
                break;
            }

            let outcome = self.dispatch(method, params).await;

            // JSON-RPC notifications (no `id`) get no response, per spec — but
            // we still let a handler run (e.g. `notifications/initialized`).
            let Some(id) = id else {
                continue;
            };

            let response = match outcome {
                Ok(result) => success_response(id, result),
                Err(e) => error_response(id, -32603, &e.to_string()),
            };
            write_response(&mut writer, &response).await?;
        }

        Ok(())
    }

    /// Route one method to its handler, producing a JSON-RPC `result` value (or
    /// an error to surface as `-32603`). MCP *tool* errors (e.g. a denied
    /// dispatch) are NOT transport errors: they come back inside an `Ok`
    /// `result` with `isError: true` (see [`handlers::tools_call`]).
    async fn dispatch(&self, method: &str, params: Value) -> anyhow::Result<Value> {
        match method {
            "initialize" => Ok(handlers::initialize()),
            "tools/list" => Ok(handlers::tools_list(&self.registry)),
            "tools/call" => Ok(handlers::tools_call(&self.registry, &self.granted, params).await),
            // Lifecycle: a clean shutdown ack. `exit` is handled in the loop.
            "shutdown" => Ok(Value::Null),
            // Client notifications we accept and ignore (no `id` → no response).
            "notifications/initialized" | "initialized" => Ok(Value::Null),
            other => anyhow::bail!("Method not found: {other}"),
        }
    }
}

/// A successful JSON-RPC 2.0 response.
fn success_response(id: Value, result: Value) -> Value {
    serde_json::json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

/// An error JSON-RPC 2.0 response.
fn error_response(id: Value, code: i64, message: &str) -> Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": code, "message": message }
    })
}

/// Write a JSON-RPC response as a single newline-terminated line and flush.
async fn write_response<W: tokio::io::AsyncWrite + Unpin>(
    writer: &mut W,
    response: &Value,
) -> anyhow::Result<()> {
    let mut out = serde_json::to_string(response)?;
    out.push('\n');
    writer.write_all(out.as_bytes()).await?;
    writer.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_bridle::{CountBound, Scope};

    /// A granted leash that allows only `echo`, at most a few calls.
    fn echo_grant() -> Caveats {
        Caveats {
            exec: Scope::only(["echo".to_string()]),
            max_calls: CountBound::AtMost(4),
            ..Caveats::top()
        }
    }

    /// Drive one request line through the server and parse the response line.
    async fn roundtrip(request: &Value) -> Value {
        let server = McpServer::new(agent_bridle::registry(), echo_grant());
        let input = format!("{}\n", serde_json::to_string(request).unwrap());
        let mut output: Vec<u8> = Vec::new();
        server.run(input.as_bytes(), &mut output).await.unwrap();
        let text = String::from_utf8(output).unwrap();
        serde_json::from_str(text.trim()).unwrap()
    }

    #[tokio::test]
    async fn initialize_reports_server_info_and_tool_capability() {
        let resp = roundtrip(&serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}
        }))
        .await;
        let result = &resp["result"];
        assert_eq!(result["protocolVersion"], PROTOCOL_VERSION);
        assert_eq!(result["serverInfo"]["name"], "agent-bridle-mcp");
        assert!(result["capabilities"]["tools"].is_object());
    }

    #[cfg(feature = "shell")]
    #[tokio::test]
    async fn tools_list_includes_shell() {
        let resp = roundtrip(&serde_json::json!({
            "jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}
        }))
        .await;
        let tools = resp["result"]["tools"].as_array().unwrap();
        let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
        assert!(
            names.contains(&"shell"),
            "tools/list missing shell: {names:?}"
        );
        for tool in tools {
            assert!(tool["inputSchema"].is_object());
        }
    }

    #[tokio::test]
    async fn unknown_method_is_method_not_found() {
        let resp = roundtrip(&serde_json::json!({
            "jsonrpc": "2.0", "id": 9, "method": "bogus/method"
        }))
        .await;
        assert_eq!(resp["error"]["code"], -32603);
        assert!(resp["error"]["message"]
            .as_str()
            .unwrap()
            .contains("Method not found"));
    }

    #[tokio::test]
    async fn malformed_json_is_parse_error() {
        let server = McpServer::new(agent_bridle::registry(), echo_grant());
        let mut output: Vec<u8> = Vec::new();
        server
            .run("{not json}\n".as_bytes(), &mut output)
            .await
            .unwrap();
        let resp: Value = serde_json::from_str(String::from_utf8(output).unwrap().trim()).unwrap();
        assert_eq!(resp["error"]["code"], -32700);
    }

    #[tokio::test]
    async fn shutdown_acks_and_exit_ends_loop() {
        // shutdown returns a (null) result; exit then ends the loop with no
        // further response. Both flow through one connection.
        let server = McpServer::new(agent_bridle::registry(), echo_grant());
        let input = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"shutdown\"}\n\
                     {\"jsonrpc\":\"2.0\",\"method\":\"exit\"}\n\
                     {\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"initialize\"}\n";
        let mut output: Vec<u8> = Vec::new();
        server.run(input.as_bytes(), &mut output).await.unwrap();
        let text = String::from_utf8(output).unwrap();
        // Exactly one response (the shutdown ack); the post-exit initialize is
        // never processed.
        let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
        assert_eq!(lines.len(), 1, "expected only the shutdown ack: {text}");
        let resp: Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(resp["id"], 1);
        assert!(resp["result"].is_null());
    }

    #[tokio::test]
    async fn notification_without_id_gets_no_response() {
        let server = McpServer::new(agent_bridle::registry(), echo_grant());
        let input = "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n";
        let mut output: Vec<u8> = Vec::new();
        server.run(input.as_bytes(), &mut output).await.unwrap();
        assert!(
            output.is_empty(),
            "notification must not produce a response: {:?}",
            String::from_utf8(output)
        );
    }
}
