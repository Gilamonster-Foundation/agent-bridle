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
//! Methods handled: `initialize`, `tools/list`, `tools/call`, `ping`, plus the
//! `shutdown`/`exit` lifecycle. `notifications/*` (no `id`) are accepted and
//! acknowledged silently per JSON-RPC notification semantics.
//!
//! Each `tools/call` runs as its own task, so the server keeps reading while a
//! call is in flight (#496). `notifications/cancelled` drops one call; SIGTERM,
//! SIGINT or `exit` drops them all. Dropping a call is what stops its work: the
//! engine's drop guard kills and reaps the worker's process group. Responses
//! therefore arrive in completion order, matched to requests by `id`.

use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;

use agent_bridle::{Caveats, EnforcementFloor, Grant, Registry};
use serde_json::Value;
use tokio::io::{AsyncWriteExt, BufReader};
use tokio::task::{AbortHandle, JoinSet};

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

/// A leashed MCP server: a tool [`Registry`] plus the session [`Grant`] every
/// dispatch is confined to.
pub struct McpServer {
    registry: Arc<Registry>,
    grant: Grant,
    /// The per-axis confinement floor every `tools/call` is dispatched with.
    floor: EnforcementFloor,
}

impl McpServer {
    /// Build a server over `registry`, confining every `tools/call` to
    /// `granted`.
    ///
    /// The `granted` leash is minted into **one** session [`Grant`] here, so a
    /// `max_calls` bound governs the whole session's ledger — every `tools/call`
    /// draws on the same persistent budget (agent-bridle#264 / AB-001). Before
    /// the grant ledger, each dispatch reset the bound, so `AtMost(n)` was
    /// silently unbounded across a session.
    #[must_use]
    pub fn new(registry: Registry, granted: Caveats) -> Self {
        let grant = registry.mint_grant(granted);
        Self {
            registry: Arc::new(registry),
            grant,
            floor: EnforcementFloor::DEFAULT,
        }
    }

    /// Dispatch every `tools/call` with `floor` (`[bridle.gate]
    /// default_strength_floor`, #495). The filesystem axes are always kernel,
    /// so a configured floor can only raise confinement.
    #[must_use]
    pub fn with_enforcement_floor(mut self, floor: EnforcementFloor) -> Self {
        self.floor = floor;
        self
    }

    /// The registry this server dispatches to.
    #[cfg(all(test, any(feature = "shell", feature = "carried-coreutils")))]
    pub fn registry(&self) -> &Registry {
        &self.registry
    }

    /// Run over real stdin/stdout (the production entry point). SIGTERM or
    /// SIGINT drops every call in flight before the server returns (#496), so
    /// stopping the server never leaves a worker running behind it.
    pub async fn run_stdio(&self) -> anyhow::Result<()> {
        // Not `tokio::io::stdin`: its uncancellable blocking read would make
        // the process hang at shutdown (see `crate::stdin`).
        self.run_until(
            crate::stdin::stdin()?,
            tokio::io::stdout(),
            MAX_LINE_BYTES,
            shutdown_signal(),
        )
        .await
    }

    /// Run over an arbitrary async reader/writer.
    ///
    /// Reads newline-delimited JSON-RPC requests, dispatches each to the right
    /// MCP handler, and writes one newline-terminated JSON-RPC response per
    /// request that carries an `id`. Returns `Ok(())` when the input reaches
    /// EOF or an `exit` notification is received.
    #[cfg(test)]
    pub async fn run<R, W>(&self, reader: R, writer: W) -> anyhow::Result<()>
    where
        R: tokio::io::AsyncRead + Unpin,
        W: tokio::io::AsyncWrite + Unpin,
    {
        self.run_inner(reader, writer, MAX_LINE_BYTES).await
    }

    /// [`Self::run`] with an explicit per-frame byte cap, so the oversize-frame
    /// guard is testable without allocating [`MAX_LINE_BYTES`].
    #[cfg(test)]
    async fn run_inner<R, W>(
        &self,
        reader: R,
        writer: W,
        max_line_bytes: usize,
    ) -> anyhow::Result<()>
    where
        R: tokio::io::AsyncRead + Unpin,
        W: tokio::io::AsyncWrite + Unpin,
    {
        self.run_until(reader, writer, max_line_bytes, std::future::pending())
            .await
    }

    /// The serve loop. `shutdown` resolving drops every call in flight and
    /// returns; so does an `exit` notification. At end of input the server
    /// answers the calls still in flight, then returns, so a piped batch of
    /// requests gets all of its answers.
    async fn run_until<R, W>(
        &self,
        reader: R,
        mut writer: W,
        max_line_bytes: usize,
        shutdown: impl Future<Output = ()>,
    ) -> anyhow::Result<()>
    where
        R: tokio::io::AsyncRead + Unpin,
        W: tokio::io::AsyncWrite + Unpin,
    {
        let mut frames = FrameReader::new(BufReader::new(reader), max_line_bytes);
        let mut calls = Calls::default();
        let mut input_open = true;
        tokio::pin!(shutdown);

        while input_open || calls.in_flight() {
            tokio::select! {
                () = &mut shutdown => {
                    calls.drop_all().await;
                    return Ok(());
                }
                finished = calls.next(), if calls.in_flight() => {
                    if let Some(response) = finished? {
                        write_response(&mut writer, &response).await?;
                    }
                }
                frame = frames.next(), if input_open => match frame? {
                    Frame::Eof => input_open = false,
                    // A frame that exceeded the cap was drained without
                    // buffering it whole; refuse it as an Invalid Request and
                    // keep serving the next frame rather than parsing a
                    // truncated body.
                    Frame::Oversize => {
                        let resp = error_response(
                            Value::Null,
                            -32600,
                            &format!("Invalid Request: frame exceeds {max_line_bytes} bytes"),
                        );
                        write_response(&mut writer, &resp).await?;
                    }
                    Frame::Line(bytes) => {
                        if self.handle_frame(&bytes, &mut calls, &mut writer).await? == Flow::Exit {
                            calls.drop_all().await;
                            return Ok(());
                        }
                    }
                },
            }
        }

        Ok(())
    }

    /// Handle one request frame. A `tools/call` is started as its own task;
    /// every other method is answered inline.
    async fn handle_frame<W>(
        &self,
        bytes: &[u8],
        calls: &mut Calls,
        writer: &mut W,
    ) -> anyhow::Result<Flow>
    where
        W: tokio::io::AsyncWrite + Unpin,
    {
        if bytes.iter().all(u8::is_ascii_whitespace) {
            return Ok(Flow::Continue);
        }

        let request: Value = match serde_json::from_slice(bytes) {
            Ok(v) => v,
            Err(e) => {
                let resp = error_response(Value::Null, -32700, &format!("Parse error: {e}"));
                write_response(writer, &resp).await?;
                return Ok(Flow::Continue);
            }
        };

        let id = request.get("id").cloned();
        let method = request.get("method").and_then(Value::as_str).unwrap_or("");
        let params = request.get("params").cloned().unwrap_or(Value::Null);

        match method {
            // `exit` is a notification that ends the session. Stop before
            // writing anything (it has no response).
            "exit" => return Ok(Flow::Exit),
            // The client gave up on a request: drop that call. A cancelled
            // request gets no response. The call stays charged against the
            // grant's budget: it ran (#474).
            "notifications/cancelled" => {
                if let Some(request_id) = params.get("requestId") {
                    calls.cancel(request_id);
                }
                return Ok(Flow::Continue);
            }
            "tools/call" => {
                if id.as_ref().is_some_and(|id| calls.is_live(id)) {
                    let resp = error_response(
                        id.unwrap_or(Value::Null),
                        -32600,
                        "Invalid Request: this id is already in flight",
                    );
                    write_response(writer, &resp).await?;
                    return Ok(Flow::Continue);
                }
                let (registry, grant, floor) =
                    (Arc::clone(&self.registry), self.grant.clone(), self.floor);
                calls.start(id, async move {
                    handlers::tools_call_with_floor(&registry, &grant, floor, params).await
                });
                return Ok(Flow::Continue);
            }
            _ => {}
        }

        let outcome = self.dispatch(method, params);

        // JSON-RPC notifications (no `id`) get no response, per spec — but
        // we still let a handler run (e.g. `notifications/initialized`).
        let Some(id) = id else {
            return Ok(Flow::Continue);
        };

        let response = match outcome {
            Ok(result) => success_response(id, result),
            Err(e) if e.is::<MethodNotFound>() => error_response(id, -32601, &e.to_string()),
            Err(e) => error_response(id, -32603, &e.to_string()),
        };
        write_response(writer, &response).await?;
        Ok(Flow::Continue)
    }

    /// Route one inline method to its handler, producing a JSON-RPC `result`
    /// value (or an error: [`MethodNotFound`] surfaces as `-32601`, anything
    /// else as `-32603`). `tools/call` is not routed here: it runs as its own
    /// task (see [`Self::handle_frame`]). MCP *tool* errors (e.g. a denied
    /// dispatch) are NOT transport errors: they come back inside an `Ok`
    /// `result` with `isError: true` (see [`handlers::tools_call_with_floor`]).
    fn dispatch(&self, method: &str, _params: Value) -> anyhow::Result<Value> {
        match method {
            "initialize" => Ok(handlers::initialize()),
            "tools/list" => Ok(handlers::tools_list(&self.registry)),
            // Lifecycle: a clean shutdown ack. `exit` is handled in the loop.
            "shutdown" => Ok(Value::Null),
            // Liveness: MCP requires a prompt empty result.
            "ping" => Ok(serde_json::json!({})),
            // Client notifications we accept and ignore (no `id` → no response).
            "notifications/initialized" | "initialized" => Ok(Value::Null),
            other => Err(MethodNotFound(other.to_owned()).into()),
        }
    }
}

/// A method the server does not implement: JSON-RPC `-32601`.
#[derive(Debug)]
struct MethodNotFound(String);

impl std::fmt::Display for MethodNotFound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Method not found: {}", self.0)
    }
}

impl std::error::Error for MethodNotFound {}

/// What the serve loop does after one frame.
#[derive(Debug, PartialEq, Eq)]
enum Flow {
    Continue,
    /// An `exit` notification: drop every call and end the session.
    Exit,
}

/// The `tools/call` requests in flight, each one its own task (#496).
#[derive(Default)]
struct Calls {
    /// Each task yields its request id (absent for a call sent as a
    /// notification) and the tool result.
    tasks: JoinSet<(Option<Value>, Value)>,
    /// The live calls that are owed a response, by the JSON text of their id.
    live: HashMap<String, AbortHandle>,
}

impl Calls {
    fn in_flight(&self) -> bool {
        !self.tasks.is_empty()
    }

    fn is_live(&self, id: &Value) -> bool {
        self.live.contains_key(&id.to_string())
    }

    /// Start `call` as its own task.
    fn start(&mut self, id: Option<Value>, call: impl Future<Output = Value> + Send + 'static) {
        let key = id.as_ref().map(Value::to_string);
        let handle = self.tasks.spawn(async move { (id, call.await) });
        if let Some(key) = key {
            self.live.insert(key, handle);
        }
    }

    /// Drop one call. Dropping its future is what stops the work: the engine's
    /// drop guard kills and reaps the worker group. Its response is never sent.
    fn cancel(&mut self, id: &Value) {
        if let Some(handle) = self.live.remove(&id.to_string()) {
            handle.abort();
        }
    }

    /// Wait for the next call to end. `Some(response)` when it is owed one;
    /// `None` for a cancelled call or one sent without an id. A panicking tool
    /// is fatal to the server, as it was when calls ran inline.
    async fn next(&mut self) -> anyhow::Result<Option<Value>> {
        match self.tasks.join_next().await {
            None => Ok(None),
            Some(Ok((Some(id), result))) => Ok(self
                .live
                .remove(&id.to_string())
                .map(|_| success_response(id, result))),
            Some(Ok((None, _))) => Ok(None),
            Some(Err(error)) if error.is_cancelled() => Ok(None),
            Some(Err(error)) => Err(anyhow::anyhow!("a tool call panicked: {error}")),
        }
    }

    /// Drop every call and wait until each task has let go of its future.
    async fn drop_all(&mut self) {
        self.live.clear();
        self.tasks.shutdown().await;
    }
}

/// Resolves on SIGTERM or SIGINT (Ctrl-C elsewhere). A host that stops the
/// server this way must not leave a worker running behind it (#496).
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let (Ok(mut terminate), Ok(mut interrupt)) = (
            signal(SignalKind::terminate()),
            signal(SignalKind::interrupt()),
        ) else {
            return std::future::pending().await;
        };
        tokio::select! {
            _ = terminate.recv() => {}
            _ = interrupt.recv() => {}
        }
    }
    #[cfg(not(unix))]
    if tokio::signal::ctrl_c().await.is_err() {
        std::future::pending::<()>().await;
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

/// One outcome of [`FrameReader::next`]: a complete newline-delimited frame's bytes
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

/// Reads newline-delimited frames, buffering at most `max` bytes of one.
///
/// Unlike `AsyncBufReadExt::lines`, this never lets a single frame grow the
/// buffer without bound: once a frame's content passes `max` bytes before a
/// newline arrives, the partial buffer is released and the rest of the frame is
/// drained (still one [`BufReader`] chunk at a time) up to the next newline,
/// yielding [`Frame::Oversize`]. The caller decides how to respond; the loop
/// stays bounded regardless of what a hostile peer sends.
///
/// The partial frame lives in the reader, not in the future [`Self::next`]
/// returns, and the only await is `fill_buf`. So `next` is cancel-safe: the
/// serve loop can drop it mid-frame (to act on a finished call or a signal) and
/// call it again without losing bytes.
struct FrameReader<R> {
    reader: R,
    max: usize,
    partial: Vec<u8>,
    oversize: bool,
}

impl<R> FrameReader<R>
where
    R: tokio::io::AsyncBufRead + Unpin,
{
    fn new(reader: R, max: usize) -> Self {
        Self {
            reader,
            max,
            partial: Vec::new(),
            oversize: false,
        }
    }

    /// The frame just completed, resetting the partial state for the next.
    fn take(&mut self) -> Frame {
        let line = std::mem::take(&mut self.partial);
        if std::mem::take(&mut self.oversize) {
            Frame::Oversize
        } else {
            Frame::Line(line)
        }
    }

    async fn next(&mut self) -> std::io::Result<Frame> {
        use tokio::io::AsyncBufReadExt;

        loop {
            let chunk = self.reader.fill_buf().await?;
            if chunk.is_empty() {
                // EOF. A trailing frame with no newline is still delivered.
                return Ok(if !self.oversize && self.partial.is_empty() {
                    Frame::Eof
                } else {
                    self.take()
                });
            }

            if let Some(pos) = chunk.iter().position(|&b| b == b'\n') {
                if !self.oversize && self.partial.len() + pos <= self.max {
                    self.partial.extend_from_slice(&chunk[..pos]);
                } else {
                    self.oversize = true;
                    self.partial = Vec::new();
                }
                self.reader.consume(pos + 1);
                return Ok(self.take());
            }

            // No newline in this chunk: accumulate until the cap, then drain.
            let len = chunk.len();
            if !self.oversize {
                if self.partial.len() + len <= self.max {
                    self.partial.extend_from_slice(chunk);
                } else {
                    self.oversize = true;
                    self.partial = Vec::new(); // release it; keep draining
                }
            }
            self.reader.consume(len);
        }
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

    /// #479: `ping` must get an empty result, not an error, or a host that
    /// pings for liveness reads the server as failed.
    #[tokio::test]
    async fn ping_returns_empty_result() {
        let resp = roundtrip(&serde_json::json!({
            "jsonrpc": "2.0", "id": 5, "method": "ping"
        }))
        .await;
        assert_eq!(resp["result"], serde_json::json!({}));
        assert!(resp.get("error").is_none(), "ping errored: {resp}");
    }

    /// AB-021 (#261): an unknown method is `-32601`, not `-32603`.
    #[tokio::test]
    async fn unknown_method_is_method_not_found() {
        let resp = roundtrip(&serde_json::json!({
            "jsonrpc": "2.0", "id": 9, "method": "bogus/method"
        }))
        .await;
        assert_eq!(resp["error"]["code"], -32601);
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

    /// #496: the frame reader keeps a partial frame across a dropped `next`.
    /// The serve loop drops that future whenever a call finishes or a signal
    /// arrives; no bytes may be lost when it does.
    #[tokio::test]
    async fn frame_reader_keeps_a_partial_frame_when_its_future_is_dropped() {
        let (mut tx, rx) = tokio::io::duplex(64);
        let mut frames = FrameReader::new(BufReader::new(rx), 1024);
        tx.write_all(b"{\"half\":").await.unwrap();
        // Poll `next` once so it consumes the first half, then drop it.
        tokio::select! {
            biased;
            frame = frames.next() => panic!("no full frame yet: {:?}", frame.is_ok()),
            () = tokio::task::yield_now() => {}
        }
        tx.write_all(b"true}\n").await.unwrap();
        match frames.next().await.unwrap() {
            Frame::Line(bytes) => assert_eq!(bytes, b"{\"half\":true}"),
            _ => panic!("expected the whole frame"),
        }
    }

    /// #496: a cancelled call is dropped and never answered, the server keeps
    /// serving the next call, and the cancelled call stays charged (#474).
    /// Before, the loop awaited each call before reading the next frame, so
    /// the cancel was never read and this hung.
    #[tokio::test]
    async fn a_cancelled_call_is_dropped_never_answered_and_stays_charged() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use tokio::io::AsyncBufReadExt;

        struct MarkDropped(Arc<AtomicBool>);
        impl Drop for MarkDropped {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }
        /// Blocks until its call is dropped; reports once it has started.
        struct Blocks {
            started: tokio::sync::mpsc::UnboundedSender<()>,
            dropped: Arc<AtomicBool>,
        }
        #[async_trait::async_trait]
        impl agent_bridle::Tool for Blocks {
            fn name(&self) -> &str {
                "blocks"
            }
            fn schema(&self) -> Value {
                serde_json::json!({ "type": "object" })
            }
            async fn invoke(
                &self,
                _args: Value,
                _cx: &agent_bridle::ToolContext,
            ) -> agent_bridle::ToolResult<Value> {
                let _guard = MarkDropped(Arc::clone(&self.dropped));
                let _ = self.started.send(());
                std::future::pending().await
            }
        }
        struct Echo;
        #[async_trait::async_trait]
        impl agent_bridle::Tool for Echo {
            fn name(&self) -> &str {
                "echo"
            }
            fn schema(&self) -> Value {
                serde_json::json!({ "type": "object" })
            }
            async fn invoke(
                &self,
                _args: Value,
                _cx: &agent_bridle::ToolContext,
            ) -> agent_bridle::ToolResult<Value> {
                Ok(serde_json::json!("echoed"))
            }
        }

        let dropped = Arc::new(AtomicBool::new(false));
        let (started, mut has_started) = tokio::sync::mpsc::unbounded_channel();
        let registry = Registry::builder()
            .tool(Arc::new(Blocks {
                started,
                dropped: Arc::clone(&dropped),
            }))
            .tool(Arc::new(Echo))
            .build();
        // Two calls of budget: the cancelled one and one echo.
        let server = McpServer::new(
            registry,
            Caveats {
                max_calls: CountBound::AtMost(2),
                ..Caveats::top()
            },
        );
        let (mut to_server, server_in) = tokio::io::duplex(4096);
        let (server_out, from_server) = tokio::io::duplex(4096);
        let call = |id: u64, tool: &str| {
            format!(
                "{}\n",
                serde_json::json!({
                    "jsonrpc": "2.0", "id": id, "method": "tools/call",
                    "params": { "name": tool }
                })
            )
        };

        let client = async {
            let mut lines = BufReader::new(from_server).lines();
            to_server
                .write_all(call(1, "blocks").as_bytes())
                .await
                .unwrap();
            has_started.recv().await.expect("the blocking call started");
            let cancel = serde_json::json!({
                "jsonrpc": "2.0", "method": "notifications/cancelled",
                "params": { "requestId": 1, "reason": "test" }
            });
            to_server
                .write_all(format!("{cancel}\n").as_bytes())
                .await
                .unwrap();
            to_server
                .write_all(call(2, "echo").as_bytes())
                .await
                .unwrap();
            let second: Value =
                serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
            assert_eq!(second["id"], 2, "{second}");
            assert_eq!(second["result"]["isError"], false, "{second}");

            // The cancelled call was charged: the budget of two is spent.
            to_server
                .write_all(call(3, "echo").as_bytes())
                .await
                .unwrap();
            let third: Value =
                serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
            assert_eq!(third["id"], 3, "{third}");
            assert_eq!(third["result"]["isError"], true, "{third}");
            assert!(
                third["result"]["content"][0]["text"]
                    .as_str()
                    .unwrap()
                    .contains("budget"),
                "{third}"
            );

            drop(to_server);
            assert!(
                lines.next_line().await.unwrap().is_none(),
                "the cancelled call must never be answered"
            );
        };
        let (served, ()) = tokio::join!(server.run(server_in, server_out), client);
        served.unwrap();
        assert!(
            dropped.load(Ordering::SeqCst),
            "cancelling must drop the call's future"
        );
    }

    /// #496: at end of input the server still answers a call in flight. A
    /// piped batch of requests gets all of its answers.
    #[tokio::test]
    async fn a_call_in_flight_at_end_of_input_is_still_answered() {
        /// Finishes only once the test says so, after input has closed.
        struct Waits(tokio::sync::Mutex<Option<tokio::sync::oneshot::Receiver<()>>>);
        #[async_trait::async_trait]
        impl agent_bridle::Tool for Waits {
            fn name(&self) -> &str {
                "waits"
            }
            fn schema(&self) -> Value {
                serde_json::json!({ "type": "object" })
            }
            async fn invoke(
                &self,
                _args: Value,
                _cx: &agent_bridle::ToolContext,
            ) -> agent_bridle::ToolResult<Value> {
                let release = self.0.lock().await.take().expect("called once");
                let _ = release.await;
                Ok(serde_json::json!("late"))
            }
        }
        let (release, released) = tokio::sync::oneshot::channel();
        let registry = Registry::builder()
            .tool(Arc::new(Waits(tokio::sync::Mutex::new(Some(released)))))
            .build();
        let server = McpServer::new(registry, Caveats::top());
        let input = "{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"tools/call\",\"params\":{\"name\":\"waits\"}}\n";
        let mut output: Vec<u8> = Vec::new();
        let serve = server.run(input.as_bytes(), &mut output);
        // The whole input, EOF included, is readable at once; release the call
        // only after the server has had the chance to see it.
        let finish = async {
            tokio::task::yield_now().await;
            let _ = release.send(());
        };
        let (served, ()) = tokio::join!(serve, finish);
        served.unwrap();
        let response: Value =
            serde_json::from_str(String::from_utf8(output).unwrap().trim()).unwrap();
        assert_eq!(response["id"], 7);
        assert_eq!(response["result"]["content"][0]["text"], "late");
    }
}
