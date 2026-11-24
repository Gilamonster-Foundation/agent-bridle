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
    ///
    /// The `require_*` switches are cleared: CI exports them for the fence
    /// tests, and #531 makes the server refuse when they are set and no fence
    /// is built in (`--no-default-features`). These tests are not about the fence.
    fn spawn_with(grant: String, home: Option<&Path>) -> Self {
        let mut command = Command::new(env!("CARGO_BIN_EXE_agent-bridle-mcp"));
        if let Some(home) = home {
            command.env("HOME", home);
        }
        let mut child = command
            // A failing test must not leave the server running.
            .kill_on_drop(true)
            .env("AGENT_BRIDLE_CAVEATS", grant)
            .env_remove("BRIDLE_REQUIRE_LANDLOCK")
            .env_remove("BRIDLE_REQUIRE_SEATBELT")
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
        self.send(request).await;
        self.recv().await
    }

    /// Send one request or notification without waiting for a response.
    async fn send(&mut self, request: Value) {
        let mut line = serde_json::to_string(&request).expect("serialize request");
        line.push('\n');
        self.stdin
            .write_all(line.as_bytes())
            .await
            .expect("write MCP request");
        self.stdin.flush().await.expect("flush MCP request");
    }

    async fn recv(&mut self) -> Value {
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
        .env_remove("BRIDLE_REQUIRE_LANDLOCK")
        .env_remove("BRIDLE_REQUIRE_SEATBELT")
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

/// #495: with the Seatbelt backend compiled in (the default features include
/// it), an fs-restricted grant runs carried `ls`. Without a compiled backend the
/// no-op sandbox cannot meet the kernel filesystem floor and admission refuses
/// every fs-restricted grant, so this test needs `macos-seatbelt` and does not
/// run in the feature subsets that leave it out.
#[cfg(all(target_os = "macos", feature = "macos-seatbelt"))]
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

/// A grant that leaves every axis unrestricted, so the worker runs `sleep` and
/// `touch` natively.
fn unrestricted_grant_json() -> String {
    serde_json::json!({
        "fs_read": "all",
        "fs_write": "all",
        "exec": "all",
        "net": "all",
        "max_calls": "unlimited",
        "valid_for_generation": "all"
    })
    .to_string()
}

/// Whether any process is left in process group `pgid`.
fn group_is_alive(pgid: u32) -> bool {
    std::process::Command::new("/bin/sh")
        .arg("-c")
        // No `--`: dash's `kill` rejects it before a negative pid.
        .arg(format!("kill -0 -{pgid}"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

/// Kills a worker's process group when the test ends, so a failing assertion
/// cannot leave its long `sleep` running. A no-op once the group is gone.
struct ReapGroup(u32);

impl Drop for ReapGroup {
    fn drop(&mut self) {
        let _ = std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg(format!("kill -KILL -{}", self.0))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

async fn wait_until(what: &str, mut ready: impl FnMut() -> bool) {
    for _ in 0..400 {
        if ready() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("timed out waiting for {what}");
}

/// Start, as call id 1, a command that records its process group, sleeps far
/// longer than the test runs, then would touch a marker. Returns that process
/// group (the worker's: it leads its own, and its children stay in it) and the
/// marker path.
async fn start_long_call(mcp: &mut McpChild, dir: &Path) -> (ReapGroup, PathBuf) {
    let pidfile = dir.join("worker.pid");
    let marker = dir.join("ran-to-the-end");
    mcp.send(serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {
            "name": "shell",
            // `ps` reports the group of the child that runs it, which is the
            // group `sleep` will be in. Brush's own `$$` is not that group.
            "arguments": { "cmd": format!(
                "/bin/sh -c 'ps -o pgid= -p $$' > {}; sleep 300; touch {}",
                shell_quote(&pidfile),
                shell_quote(&marker)
            ) }
        }
    }))
    .await;
    let read_pid = || {
        std::fs::read_to_string(&pidfile)
            .ok()
            .and_then(|text| text.trim().parse::<u32>().ok())
    };
    wait_until("the worker to record its process group", || {
        read_pid().is_some()
    })
    .await;
    let group = ReapGroup(read_pid().expect("worker process group"));
    assert!(group_is_alive(group.0), "the worker group must be running");
    (group, marker)
}

/// #496: cancelling a call kills and reaps its worker group, and the server
/// keeps serving. Before, the loop did not read the cancel until the call
/// ended, so the worker ran to the end.
#[tokio::test]
async fn cancelling_a_call_kills_its_worker_group() {
    let dir = unique_temp();
    std::fs::create_dir_all(&dir).expect("create fixture dir");
    let mut mcp = McpChild::spawn_with(unrestricted_grant_json(), None);
    let (group, marker) = start_long_call(&mut mcp, &dir).await;
    let pgid = group.0;

    mcp.send(serde_json::json!({
        "jsonrpc": "2.0", "method": "notifications/cancelled",
        "params": { "requestId": 1, "reason": "test" }
    }))
    .await;
    // The server is still serving. The next response is the ping's: the
    // cancelled call is never answered.
    let pong = mcp
        .call(serde_json::json!({"jsonrpc": "2.0", "id": 2, "method": "ping"}))
        .await;
    assert_eq!(pong["id"], 2, "{pong}");

    wait_until("the cancelled worker group to be gone", || {
        !group_is_alive(pgid)
    })
    .await;
    assert!(!marker.exists(), "the cancelled command must not finish");
    mcp.shutdown().await;
    std::fs::remove_dir_all(dir).expect("remove fixture dir");
}

/// #496: SIGTERM drops every call before the server exits, so stopping the
/// server leaves no worker behind. The worker leads its own process group, so
/// a signal sent to the server's group never reached it.
#[tokio::test]
async fn sigterm_kills_the_worker_group_before_the_server_exits() {
    let dir = unique_temp();
    std::fs::create_dir_all(&dir).expect("create fixture dir");
    let mut mcp = McpChild::spawn_with(unrestricted_grant_json(), None);
    let (group, marker) = start_long_call(&mut mcp, &dir).await;
    let pgid = group.0;

    let server = mcp.child.id().expect("server pid");
    let sent = std::process::Command::new("/bin/sh")
        .arg("-c")
        .arg(format!("kill -TERM {server}"))
        .status()
        .expect("send SIGTERM");
    assert!(sent.success());
    tokio::time::timeout(Duration::from_secs(20), mcp.child.wait())
        .await
        .expect("the server must exit on SIGTERM")
        .expect("wait for the server");

    assert!(
        !group_is_alive(pgid),
        "the worker group must be gone by the time the server has exited"
    );
    assert!(!marker.exists(), "the interrupted command must not finish");
    std::fs::remove_dir_all(dir).expect("remove fixture dir");
}

/// #496: closing stdin does not drop a call in flight. The server answers it,
/// then exits, as a piped batch of requests needs.
#[tokio::test]
async fn a_call_in_flight_when_stdin_closes_is_still_answered() {
    let McpChild {
        mut child,
        mut stdin,
        mut stdout,
    } = McpChild::spawn_with(unrestricted_grant_json(), None);
    let request = serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": { "name": "shell", "arguments": { "cmd": "sleep 1; echo late" } }
    });
    stdin
        .write_all(format!("{request}\n").as_bytes())
        .await
        .expect("write request");
    drop(stdin);

    let line = tokio::time::timeout(Duration::from_secs(20), stdout.next_line())
        .await
        .expect("the call must still be answered")
        .expect("read response")
        .expect("a response line");
    let response: Value = serde_json::from_str(&line).expect("parse response");
    assert_eq!(response["id"], 1, "{response}");
    assert!(
        response["result"]["content"][0]["text"]
            .as_str()
            .expect("result text")
            .contains("late"),
        "{response}"
    );
    let status = tokio::time::timeout(Duration::from_secs(20), child.wait())
        .await
        .expect("the server must exit after answering")
        .expect("wait for the server");
    assert!(status.success(), "{status:?}");
}
