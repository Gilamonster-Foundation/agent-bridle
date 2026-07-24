//! Default-registry keystone: the MCP binary serves the carried Brush shell,
//! understands its re-exec dispatch protocol, and runs bundled coreutils.

#![cfg(feature = "carried-coreutils")]

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};

fn shell_quote(path: &Path) -> String {
    format!("'{}'", path.to_string_lossy().replace('\'', "'\\''"))
}

fn unique_temp() -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    std::env::temp_dir().join(format!(
        "ab-mcp-carried-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ))
}

fn grant_json() -> String {
    serde_json::json!({
        "fs_read": "all",
        "fs_write": "all",
        // Authority names the logical carried command, never the worker binary.
        "exec": { "only": ["ls"] },
        "net": "all",
        "max_calls": "unlimited",
        "valid_for_generation": "all"
    })
    .to_string()
}

struct McpChild {
    child: Child,
    stdin: ChildStdin,
    stdout: tokio::io::Lines<BufReader<ChildStdout>>,
}

impl McpChild {
    fn spawn() -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_agent-bridle-mcp"))
            .env("AGENT_BRIDLE_CAVEATS", grant_json())
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

    async fn call(&mut self, request: Value) -> Value {
        let mut line = serde_json::to_string(&request).expect("serialize request");
        line.push('\n');
        self.stdin
            .write_all(line.as_bytes())
            .await
            .expect("write MCP request");
        self.stdin.flush().await.expect("flush MCP request");

        let line = tokio::time::timeout(Duration::from_secs(20), self.stdout.next_line())
            .await
            .expect("timed out waiting for MCP response")
            .expect("read MCP response")
            .expect("MCP server closed stdout");
        serde_json::from_str(&line).expect("parse MCP response")
    }

    async fn shutdown(mut self) {
        let mut exit =
            serde_json::to_string(&serde_json::json!({"jsonrpc": "2.0", "method": "exit"}))
                .expect("serialize exit");
        exit.push('\n');
        let _ = self.stdin.write_all(exit.as_bytes()).await;
        let _ = tokio::time::timeout(Duration::from_secs(10), self.child.wait()).await;
        let _ = self.child.kill().await;
    }
}

#[tokio::test]
async fn default_mcp_shell_runs_carried_ls_and_denies_ungranted_external() {
    let dir = unique_temp();
    std::fs::create_dir_all(&dir).expect("create fixture dir");
    std::fs::write(dir.join("CARRIED_MARKER.txt"), b"carried\n").expect("write marker");

    let mut mcp = McpChild::spawn();

    let list = mcp
        .call(serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}
        }))
        .await;
    let shell = list["result"]["tools"]
        .as_array()
        .expect("tools array")
        .iter()
        .find(|tool| tool["name"] == "shell")
        .expect("shell tool");
    assert!(
        shell["inputSchema"]["properties"]["cmd"].is_object(),
        "default shell must publish the Brush `cmd` schema: {shell}"
    );
    assert!(
        shell["inputSchema"]["properties"].get("program").is_none(),
        "default shell must not be the argv safe-subset engine: {shell}"
    );

    let listed = mcp
        .call(serde_json::json!({
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {
                "name": "shell",
                "arguments": { "cmd": format!("ls {}", shell_quote(&dir)) }
            }
        }))
        .await;
    assert_eq!(
        listed["result"]["isError"], false,
        "carried ls must run through the MCP host's re-exec path: {listed}"
    );
    let listed_text = listed["result"]["content"][0]["text"]
        .as_str()
        .expect("carried ls result text");
    assert!(
        listed_text.contains("CARRIED_MARKER.txt"),
        "carried ls output missing marker: {listed_text}"
    );
    assert!(
        listed_text.contains(r#""engine":"brush""#),
        "result must disclose the selected Brush engine: {listed_text}"
    );

    let denied = mcp
        .call(serde_json::json!({
            "jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": {
                "name": "shell",
                "arguments": { "cmd": "./definitely-not-granted" }
            }
        }))
        .await;
    assert_eq!(
        denied["result"]["isError"], true,
        "an unrelated external must remain denied: {denied}"
    );
    let denial = denied["result"]["content"][0]["text"]
        .as_str()
        .expect("denial text");
    assert!(
        denial.contains("definitely-not-granted"),
        "denial must identify the refused executable: {denial}"
    );

    mcp.shutdown().await;
    std::fs::remove_dir_all(dir).expect("remove fixture dir");
}
