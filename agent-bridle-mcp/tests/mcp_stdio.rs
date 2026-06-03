//! Through-the-MCP-boundary integration test (the payoff).
//!
//! Spawns the real `agent-bridle-mcp` binary as a child process and drives it
//! over its stdio JSON-RPC pipe, exactly as an MCP client would. It proves the
//! capability leash holds *across the MCP boundary*, not merely in-process:
//!
//! 1. `initialize` → the server reports its identity + the `tools` capability.
//! 2. `tools/list` → the confined `shell` tool is advertised.
//! 3. `tools/call shell` with an **in-scope** program (`echo`) → stdout comes
//!    back in an `isError: false` content result.
//! 4. `tools/call shell` with an **out-of-scope** program (`rm`) → the leash
//!    denies it and the denial reason is carried back as an MCP **tool error**
//!    (`isError: true`), NOT a transport error.
//!
//! The granted leash is supplied via `$AGENT_BRIDLE_CAVEATS` (the same path a
//! real orchestrator uses), restricted to `exec: Only{echo}`.

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
    /// Spawn the binary with `$AGENT_BRIDLE_CAVEATS` set to `grant`.
    fn spawn(grant: &str) -> Self {
        let exe = env!("CARGO_BIN_EXE_agent-bridle-mcp");
        let mut child = Command::new(exe)
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

#[tokio::test]
async fn leash_holds_through_the_mcp_boundary() {
    let mut mcp = McpChild::spawn(GRANT_JSON);

    // 1. initialize.
    let init = mcp
        .call(&serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}
        }))
        .await;
    assert_eq!(init["result"]["serverInfo"]["name"], "agent-bridle-mcp");
    assert!(init["result"]["capabilities"]["tools"].is_object());

    // 2. tools/list includes the confined shell tool.
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

    // 3. tools/call shell with an IN-SCOPE program → stdout, isError=false.
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
        "echo should run: {allowed}"
    );
    let allowed_text = allowed["result"]["content"][0]["text"].as_str().unwrap();
    assert!(
        allowed_text.contains("leashed-hello"),
        "expected echo stdout, got: {allowed_text}"
    );

    // 4. tools/call shell with an OUT-OF-SCOPE program → DENIED through MCP:
    // an MCP tool error (isError=true) carrying the denial reason, NOT a
    // transport error.
    let denied = mcp
        .call(&serde_json::json!({
            "jsonrpc": "2.0", "id": 4, "method": "tools/call",
            "params": {
                "name": "shell",
                "arguments": { "program": "rm", "args": ["-rf", "/"] }
            }
        }))
        .await;
    assert!(
        denied.get("error").is_none(),
        "denial must be in-band, not a transport error: {denied}"
    );
    assert_eq!(
        denied["result"]["isError"], true,
        "out-of-scope exec must be an MCP tool error: {denied}"
    );
    let reason = denied["result"]["content"][0]["text"].as_str().unwrap();
    assert!(
        reason.contains("denied") && reason.contains("rm"),
        "denial reason must name the refused program: {reason}"
    );
    // The reason explains WHY (out-of-scope authority), so the model can adapt.
    assert!(
        reason.contains("granted authority"),
        "denial should explain the leash: {reason}"
    );

    mcp.shutdown().await;
}
