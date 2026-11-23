//! Default-registry keystone: the MCP binary serves the carried Brush shell,
//! understands its re-exec dispatch protocol, and runs bundled coreutils.

#![cfg(all(
    feature = "carried-coreutils",
    any(target_os = "linux", target_os = "macos")
))]

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
        Self::spawn_with(grant_json(), None)
    }

    /// Spawn with an explicit grant and, optionally, a `HOME` whose
    /// `.agent-bridle/config.toml` supplies the mechanism config (#495).
    fn spawn_with(grant: String, home: Option<&Path>) -> Self {
        let mut command = Command::new(env!("CARGO_BIN_EXE_agent-bridle-mcp"));
        if let Some(home) = home {
            command.env("HOME", home);
        }
        let mut child = command
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

/// A `HOME` whose `.agent-bridle/config.toml` holds `config`.
fn home_with_config(config: &str) -> PathBuf {
    let home = unique_temp();
    let dir = home.join(".agent-bridle");
    std::fs::create_dir_all(&dir).expect("create config dir");
    std::fs::write(dir.join("config.toml"), config).expect("write config");
    home
}

/// #495: the server reads `[bridle.shell] engine` from the config file at
/// startup. `safe-subset` serves the argv engine, whose schema advertises
/// `program`; before this the file's `[bridle]` table was never read.
#[tokio::test]
async fn configured_shell_engine_is_served_from_the_config_file() {
    let home = home_with_config("[bridle.shell]\nengine = \"safe-subset\"\n");
    let mut mcp = McpChild::spawn_with(grant_json(), Some(&home));
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
        .expect("shell tool")
        .clone();
    assert!(
        shell["inputSchema"]["properties"]["program"].is_object(),
        "the configured safe-subset engine must be the one served: {shell}"
    );
    mcp.shutdown().await;
    std::fs::remove_dir_all(home).expect("remove home");
}

/// #495: a config this build cannot honor fails startup. It is never replaced
/// by a default engine.
#[tokio::test]
async fn an_unknown_shell_engine_fails_startup() {
    let home = home_with_config("[bridle.shell]\nengine = \"bogus\"\n");
    let output = Command::new(env!("CARGO_BIN_EXE_agent-bridle-mcp"))
        .env("HOME", &home)
        .env("AGENT_BRIDLE_CAVEATS", grant_json())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output();
    let output = tokio::time::timeout(Duration::from_secs(20), output)
        .await
        .expect("the server must exit, not serve")
        .expect("run agent-bridle-mcp");
    assert!(!output.status.success(), "startup must fail: {output:?}");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("unknown shell engine"),
        "the failure must name the bad setting: {output:?}"
    );
    std::fs::remove_dir_all(home).expect("remove home");
}

/// #495: with the default features (which now include the OS backends), an
/// fs-restricted grant runs carried `ls`. Without a compiled backend the no-op
/// sandbox could not meet the kernel filesystem floor and admission refused
/// every fs-restricted grant.
#[cfg(target_os = "macos")]
#[tokio::test]
async fn fs_restricted_grant_runs_carried_ls_with_default_features() {
    let dir = unique_temp();
    std::fs::create_dir_all(&dir).expect("create fixture dir");
    let dir = dir.canonicalize().expect("canonical fixture dir");
    std::fs::write(dir.join("CARRIED_MARKER.txt"), b"carried\n").expect("write marker");
    let grant = serde_json::json!({
        "fs_read": { "only": [dir.to_string_lossy()] },
        "fs_write": "all",
        "exec": { "only": ["ls"] },
        "net": "all",
        "max_calls": "unlimited",
        "valid_for_generation": "all"
    })
    .to_string();
    let home = home_with_config("");
    let mut mcp = McpChild::spawn_with(grant, Some(&home));
    let listed = mcp
        .call(serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {
                "name": "shell",
                "arguments": { "cmd": "ls", "cwd": dir.to_string_lossy() }
            }
        }))
        .await;
    assert_eq!(
        listed["result"]["isError"], false,
        "an fs-restricted grant must run carried ls: {listed}"
    );
    let text = listed["result"]["content"][0]["text"]
        .as_str()
        .expect("result text");
    assert!(text.contains("CARRIED_MARKER.txt"), "{text}");
    assert!(
        text.contains(r#""sandbox_kind":"seatbelt""#),
        "the run must be fenced by the compiled backend: {text}"
    );
    mcp.shutdown().await;
    std::fs::remove_dir_all(dir).expect("remove fixture dir");
    std::fs::remove_dir_all(home).expect("remove home");
}
