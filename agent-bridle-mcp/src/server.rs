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
use tokio::io::{AsyncWriteExt, BufReader};

use crate::handlers;

/// The MCP protocol version this server advertises in `initialize`.
///
/// Matches the value `newt-mcp-server` reports, so a client that pins a version
/// sees a consistent surface across the agent line.
pub const PROTOCOL_VERSION: &str = "2024-11-05";

/// Maximum bytes a single newline-delimited JSON-RPC frame may occupy before
/// the server rejects it instead of buffering it whole.
///
/// The old `BufReader::lines()` read had no application-level bound: a client
/// (or a compromised upstream) could send one gigantic line with no newline and
/// force the process to grow memory without limit *before* JSON parsing ever ran
/// (agent-bridle#272 — audit AB-019, memory-amplification DoS). 16 MiB is far above
/// any legitimate tool call yet caps the blast radius of a hostile frame.
///
/// TODO(three-Cs): lift this into the `[bridle]` mechanism config alongside the
/// jail `MAX_FRAME` knob (agent-bridle#147) so it is data, not a constant.
const MAX_LINE_BYTES: usize = 16 * 1024 * 1024;

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
    pub async fn run<R, W>(&self, reader: R, writer: W) -> anyhow::Result<()>
    where
        R: tokio::io::AsyncRead + Unpin,
        W: tokio::io::AsyncWrite + Unpin,
    {
        self.run_inner(reader, writer, MAX_LINE_BYTES).await
    }

    /// The read loop, parameterized on the per-frame byte cap so the
    /// oversize-frame guard is testable without allocating [`MAX_LINE_BYTES`].
    async fn run_inner<R, W>(
        &self,
        reader: R,
        mut writer: W,
        max_line_bytes: usize,
    ) -> anyhow::Result<()>
    where
        R: tokio::io::AsyncRead + Unpin,
        W: tokio::io::AsyncWrite + Unpin,
    {
        let mut buf = BufReader::new(reader);

        loop {
            let bytes = match read_frame(&mut buf, max_line_bytes).await? {
                Frame::Eof => break,
                // A frame that exceeded the cap was drained without buffering it
                // whole; refuse it as an Invalid Request and keep serving the
                // next frame rather than parsing a truncated body.
                Frame::Oversize => {
                    let resp = error_response(
                        Value::Null,
                        -32600,
                        &format!("Invalid Request: frame exceeds {max_line_bytes} bytes"),
                    );
                    write_response(&mut writer, &resp).await?;
                    continue;
                }
                Frame::Line(bytes) => bytes,
            };

            if bytes.iter().all(u8::is_ascii_whitespace) {
                continue;
            }

            let request: Value = match serde_json::from_slice(&bytes) {
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

/// One outcome of [`read_frame`]: a complete newline-delimited frame's bytes
/// (newline stripped), a frame that exceeded the byte cap and was discarded, or
/// end of input.
enum Frame {
    /// A complete frame (the trailing newline, if any, is not included).
    Line(Vec<u8>),
    /// The frame exceeded the cap; its bytes were drained up to the next
    /// newline without being buffered whole.
    Oversize,
    /// The reader reached EOF with no pending frame.
    Eof,
}

/// Read one newline-delimited frame, buffering at most `max` bytes.
///
/// Unlike `AsyncBufReadExt::lines`, this never lets a single frame grow the
/// buffer without bound: once a frame's content passes `max` bytes before a
/// newline arrives, the partial buffer is released and the rest of the frame is
/// drained (still one [`BufReader`] chunk at a time) up to the next newline,
/// yielding [`Frame::Oversize`]. The caller decides how to respond; the loop
/// stays bounded regardless of what a hostile peer sends.
async fn read_frame<R>(reader: &mut R, max: usize) -> std::io::Result<Frame>
where
    R: tokio::io::AsyncBufRead + Unpin,
{
    use tokio::io::AsyncBufReadExt;

    let mut buf: Vec<u8> = Vec::new();
    let mut oversize = false;

    loop {
        let chunk = reader.fill_buf().await?;
        if chunk.is_empty() {
            // EOF. A trailing frame with no newline is still delivered.
            return Ok(if oversize {
                Frame::Oversize
            } else if buf.is_empty() {
                Frame::Eof
            } else {
                Frame::Line(buf)
            });
        }

        if let Some(pos) = chunk.iter().position(|&b| b == b'\n') {
            if !oversize && buf.len() + pos <= max {
                buf.extend_from_slice(&chunk[..pos]);
            } else {
                oversize = true;
            }
            reader.consume(pos + 1);
            return Ok(if oversize {
                Frame::Oversize
            } else {
                Frame::Line(buf)
            });
        }

        // No newline in this chunk: accumulate until the cap, then drain.
        let len = chunk.len();
        if !oversize {
            if buf.len() + len <= max {
                buf.extend_from_slice(chunk);
            } else {
                oversize = true;
                buf = Vec::new(); // release the partial buffer; keep draining
            }
        }
        reader.consume(len);
    }
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

    #[cfg(any(feature = "shell", feature = "carried-coreutils"))]
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
    async fn oversize_frame_is_rejected_then_server_recovers() {
        // AB-019 regression: a frame larger than the cap must NOT be buffered
        // whole and parsed — it is refused as an Invalid Request (-32600), and
        // the *next* frame is still served. The cap is injected small here so
        // the test costs bytes, not the 16 MiB production default.
        //
        // Before the fix (`BufReader::lines()`), the oversize line was buffered
        // in full and surfaced as a -32700 parse error, so this asserts the new
        // -32600 contract that the old path could not produce.
        let server = McpServer::new(agent_bridle::registry(), echo_grant());
        let cap = 128;
        let oversize = "x".repeat(cap * 2); // well past the injected cap
        let valid = serde_json::to_string(&serde_json::json!({
            "jsonrpc": "2.0", "id": 7, "method": "initialize", "params": {}
        }))
        .unwrap();
        assert!(valid.len() < cap, "the valid frame must fit under the cap");
        let input = format!("{oversize}\n{valid}\n");
        let mut output: Vec<u8> = Vec::new();
        server
            .run_inner(input.as_bytes(), &mut output, cap)
            .await
            .unwrap();

        let text = String::from_utf8(output).unwrap();
        let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
        assert_eq!(
            lines.len(),
            2,
            "expected an oversize refusal then the recovered response: {text}"
        );
        let refusal: Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(
            refusal["error"]["code"], -32600,
            "oversize frame must be Invalid Request, not a parse error: {text}"
        );
        assert!(refusal["id"].is_null());
        let recovered: Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(
            recovered["id"], 7,
            "the valid frame after an oversize one is still served: {text}"
        );
        assert_eq!(recovered["result"]["protocolVersion"], PROTOCOL_VERSION);
    }

    #[tokio::test]
    async fn frame_exactly_at_cap_is_still_served() {
        // Boundary: a frame whose content length equals the cap is accepted;
        // only strictly-larger frames are refused.
        let server = McpServer::new(agent_bridle::registry(), echo_grant());
        let req = serde_json::json!({
            "jsonrpc": "2.0", "id": 3, "method": "initialize", "params": {}
        });
        let line = serde_json::to_string(&req).unwrap();
        let input = format!("{line}\n");
        let mut output: Vec<u8> = Vec::new();
        // Cap exactly the content length (newline excluded): must be served.
        server
            .run_inner(input.as_bytes(), &mut output, line.len())
            .await
            .unwrap();
        let resp: Value = serde_json::from_str(String::from_utf8(output).unwrap().trim()).unwrap();
        assert_eq!(resp["id"], 3);
        assert_eq!(resp["result"]["protocolVersion"], PROTOCOL_VERSION);
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
