//! Through-the-MCP-boundary integration test (the payoff).
//!
//! Spawns the real `agent-bridle-mcp` binary as a child process and drives it
//! over its stdio JSON-RPC pipe, exactly as an MCP client would.
//!
//! The shell is the argv + safe-subset engine (ADR 0005); steps 3 and 4 assert
//! real execution and a real in-band leash denial through the MCP boundary.
//!
//! Behaviour tested:
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

/// The in-scope **success** program for this integration test. On Windows `echo`
/// is a `cmd` builtin (no `echo.exe`), so spawning `echo` fails "program not
/// found"; use `cmd /c echo …`. On Unix use `echo`. (agent-bridle#84 — the same
/// portability issue as #43, in the MCP stdio test.)
#[cfg(not(windows))]
const OK_PROGRAM: &str = "echo";
#[cfg(windows)]
const OK_PROGRAM: &str = "cmd";

#[cfg(not(windows))]
fn ok_args() -> Value {
    serde_json::json!(["leashed-hello"])
}
#[cfg(windows)]
fn ok_args() -> Value {
    serde_json::json!(["/c", "echo leashed-hello"])
}

/// The restrictive grant: may exec only the host's success program
/// ([`OK_PROGRAM`]). This is the leash the server must enforce through MCP.
/// Exact agent-mesh `Caveats` serde shape.
fn grant_json() -> String {
    format!(
        r#"{{
    "fs_read": "all",
    "fs_write": "all",
    "exec": {{ "only": ["{OK_PROGRAM}"] }},
    "net": "all",
    "max_calls": "unlimited",
    "valid_for_generation": "all"
}}"#
    )
}

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
    let mut mcp = McpChild::spawn(&grant_json());

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

    // 3. An in-scope program runs: stdout comes back in an isError:false result.
    let allowed = mcp
        .call(&serde_json::json!({
            "jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": {
                "name": "shell",
                "arguments": { "program": OK_PROGRAM, "args": ok_args() }
            }
        }))
        .await;
    assert_eq!(
        allowed["result"]["isError"], false,
        "in-scope program must succeed through the MCP boundary: {allowed}"
    );
    let allowed_text = allowed["result"]["content"][0]["text"].as_str().unwrap();
    assert!(
        allowed_text.contains("leashed-hello"),
        "stdout must carry through: {allowed_text}"
    );

    // 4. An out-of-scope program is denied: the leash reason is carried back as
    // an in-band MCP tool error (isError: true), never a transport error.
    let denied = mcp
        .call(&serde_json::json!({
            "jsonrpc": "2.0", "id": 4, "method": "tools/call",
            "params": {
                "name": "shell",
                "arguments": { "program": "rm", "args": ["-rf", "/tmp/x"] }
            }
        }))
        .await;
    assert!(
        denied.get("error").is_none(),
        "a denial must be in-band, not a transport error: {denied}"
    );
    assert_eq!(
        denied["result"]["isError"], true,
        "out-of-scope exec must surface as an MCP tool error: {denied}"
    );
    let reason = denied["result"]["content"][0]["text"].as_str().unwrap();
    assert!(
        reason.contains("rm") && reason.contains("granted authority"),
        "denial reason must name the refused exec: {reason}"
    );

    mcp.shutdown().await;
}
