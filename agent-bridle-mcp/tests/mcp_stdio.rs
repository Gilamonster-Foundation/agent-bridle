//! Through-the-MCP-boundary integration test (the payoff).
//!
//! Spawns the real `agent-bridle-mcp` binary as a child process and drives it
//! over its stdio JSON-RPC pipe, exactly as an MCP client would. It proves the
//! capability behavior holds *across the MCP boundary*, not merely in-process:
//!
//! 1. `initialize` → the server reports its identity + the `tools` capability.
//! 2. `tools/list` → the `shell` tool is advertised.
//! 3. With NO flag (the fail-closed STUB), `tools/call shell` for `echo` is
//!    **denied** in-band (`isError: true`) — the stub never spawns anything.
//! 4. With `--dangerously-allow-all` (the opt-in UNCONFINED bash), the same
//!    `tools/call shell` for `echo` **runs**, returning stdout in an
//!    `isError: false` content result.
//!
//! The granted leash is supplied via `$AGENT_BRIDLE_CAVEATS` (the same path a
//! real orchestrator uses). With the brush-backed confined shell stubbed out,
//! the `exec` scope no longer gates the stub (it denies regardless) nor the
//! UNCONFINED bash (it is honest about not confining); the leash still mints the
//! context and enforces budget/generation across the boundary.

#![cfg(feature = "shell")]

use std::process::Stdio;
use std::time::Duration;

use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};

/// The restrictive grant: may exec only `echo`. This is the leash the server
/// must enforce through MCP. Exact agent-mesh `Caveats` serde shape.
const GRANT_JSON: &str = r#"{
    "fs_read": "all",
    "fs_write": "all",
    "exec": { "only": ["echo"] },
    "net": "all",
    "max_calls": "unlimited",
    "valid_for_generation": "all"
}"#;

/// A live MCP child driven over stdio.
struct McpChild {
    child: Child,
    stdin: ChildStdin,
    stdout: tokio::io::Lines<BufReader<ChildStdout>>,
}

impl McpChild {
    /// Spawn the binary with `$AGENT_BRIDLE_CAVEATS` set to `grant` and the
    /// given CLI `args` (e.g. `["--dangerously-allow-all"]`).
    fn spawn(grant: &str, args: &[&str]) -> Self {
        let exe = env!("CARGO_BIN_EXE_agent-bridle-mcp");
        let mut child = Command::new(exe)
            .args(args)
            .env("AGENT_BRIDLE_CAVEATS", grant)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn agent-bridle-mcp");
        let stdin = child.stdin.take().expect("child stdin");
        let stdout = child.stdout.take().expect("child stdout");
        Self {
            child,
            stdin,
            stdout: BufReader::new(stdout).lines(),
        }
    }

    /// Send one JSON-RPC request line.
    async fn send(&mut self, request: &Value) {
        let mut line = serde_json::to_string(request).unwrap();
        line.push('\n');
        self.stdin.write_all(line.as_bytes()).await.unwrap();
        self.stdin.flush().await.unwrap();
    }

    /// Read one JSON-RPC response line (bounded by a timer so a hang fails the
    /// test instead of blocking forever — a timeout bound, not a coordination
    /// primitive).
    async fn recv(&mut self) -> Value {
        let line = tokio::time::timeout(Duration::from_secs(20), self.stdout.next_line())
            .await
            .expect("timed out waiting for MCP response")
            .expect("read MCP response line")
            .expect("server closed stdout unexpectedly");
        serde_json::from_str(&line).expect("parse MCP response JSON")
    }

    /// Request/response in one shot.
    async fn call(&mut self, request: &Value) -> Value {
        self.send(request).await;
        self.recv().await
    }

    /// Cleanly stop the child: `exit` notification, then reap.
    async fn shutdown(mut self) {
        self.send(&serde_json::json!({ "jsonrpc": "2.0", "method": "exit" }))
            .await;
        let _ = tokio::time::timeout(Duration::from_secs(10), self.child.wait()).await;
        let _ = self.child.kill().await;
    }
}

/// Drive `initialize` + `tools/list` against a child and return the shell tool
/// names, asserting the protocol handshake and that `shell` is advertised.
async fn handshake(mcp: &mut McpChild) {
    let init = mcp
        .call(&serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}
        }))
        .await;
    assert_eq!(init["result"]["serverInfo"]["name"], "agent-bridle-mcp");
    assert!(init["result"]["capabilities"]["tools"].is_object());

    let list = mcp
        .call(&serde_json::json!({
            "jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}
        }))
        .await;
    let names: Vec<&str> = list["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert!(
        names.contains(&"shell"),
        "tools/list missing shell: {names:?}"
    );
}

#[tokio::test]
async fn stub_shell_denies_through_the_mcp_boundary() {
    // NO flag → the fail-closed STUB. Even an `echo` is denied in-band, and
    // nothing is spawned. The denial is an MCP tool error (isError=true), NOT a
    // transport error, and it hints at the escalation flags.
    let mut mcp = McpChild::spawn(GRANT_JSON, &[]);
    handshake(&mut mcp).await;

    let denied = mcp
        .call(&serde_json::json!({
            "jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": {
                "name": "shell",
                "arguments": { "program": "echo", "args": ["leashed-hello"] }
            }
        }))
        .await;
    assert!(
        denied.get("error").is_none(),
        "denial must be in-band, not a transport error: {denied}"
    );
    assert_eq!(
        denied["result"]["isError"], true,
        "the stub must deny in-band: {denied}"
    );
    let reason = denied["result"]["content"][0]["text"].as_str().unwrap();
    assert!(reason.contains("denied"), "missing denial reason: {reason}");
    assert!(
        reason.contains("--insecure") || reason.contains("--dangerously-allow-all"),
        "stub denial should hint at escalation flags: {reason}"
    );

    mcp.shutdown().await;
}

#[tokio::test]
async fn dangerously_allow_all_runs_through_the_mcp_boundary() {
    // --dangerously-allow-all → an UNCONFINED bash. The same `echo` now runs and
    // returns its stdout in an isError=false content result.
    let mut mcp = McpChild::spawn(GRANT_JSON, &["--dangerously-allow-all"]);
    handshake(&mut mcp).await;

    let allowed = mcp
        .call(&serde_json::json!({
            "jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": {
                "name": "shell",
                "arguments": { "program": "echo", "args": ["leashed-hello"] }
            }
        }))
        .await;
    assert_eq!(
        allowed["result"]["isError"], false,
        "unconfined echo should run: {allowed}"
    );
    let allowed_text = allowed["result"]["content"][0]["text"].as_str().unwrap();
    assert!(
        allowed_text.contains("leashed-hello"),
        "expected echo stdout, got: {allowed_text}"
    );

    mcp.shutdown().await;
}
