//! Windows route-level proof for the v0.8 Newt `CONFINED` contract.
//!
//! This exercises the production `ShellTool` spawn path with the exact Newt-style
//! caveats: `{fs_read: workspace, fs_write: workspace, net: deny-all,
//! exec: allowlist}` under `EnforcementFloor::CONFINED`. It complements the pure
//! `enforcement_report` tests by proving the route really selects AppContainer
//! and fails closed when `agent-bridle-aclaunch.exe` cannot be found.

#![cfg(all(target_os = "windows", feature = "windows-appcontainer"))]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use agent_bridle_core::{Caveats, EnforcementFloor, Gate, Scope, Tool, ToolContext, ToolError};
use agent_bridle_tool_shell::ShellTool;

static N: AtomicU64 = AtomicU64::new(0);

fn tag(kind: &str) -> String {
    format!(
        "{kind}-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    )
}

fn fresh_dir(kind: &str) -> PathBuf {
    let mut d = std::env::temp_dir();
    d.push(format!("ab-newt-contract-{}", tag(kind)));
    std::fs::create_dir_all(&d).expect("create temp dir");
    let _ = Command::new("icacls")
        .arg(&d)
        .args(["/setintegritylevel", "(OI)(CI)Low"])
        .output();
    d
}

fn ctx_confined(granted: Caveats) -> ToolContext {
    Gate::new(0)
        .with_enforcement_floor(EnforcementFloor::CONFINED)
        .authorize(&ShellTool::new(), &granted)
        .expect("authorize")
}

fn newt_contract(workspace: &Path) -> Caveats {
    let ws = workspace.to_string_lossy().into_owned();
    Caveats {
        fs_read: Scope::only([ws.clone()]),
        fs_write: Scope::only([ws]),
        net: Scope::none(),
        exec: Scope::only(["cmd.exe".to_string()]),
        ..Caveats::top()
    }
}

fn launcher_path() -> PathBuf {
    let mut p = std::env::current_exe().expect("current test executable");
    p.pop(); // deps
    p.pop(); // debug
    p.push("agent-bridle-aclaunch.exe");
    assert!(
        p.exists(),
        "Windows contract proof requires agent-bridle-aclaunch.exe to be built at {p:?}; \
         run `cargo test -p agent-bridle-aclaunch --bins` before this test"
    );
    p
}

struct PathGuard {
    old: Option<std::ffi::OsString>,
}

impl PathGuard {
    fn set(new_path: std::ffi::OsString) -> Self {
        let old = std::env::var_os("PATH");
        std::env::set_var("PATH", new_path);
        Self { old }
    }
}

impl Drop for PathGuard {
    fn drop(&mut self) {
        if let Some(old) = &self.old {
            std::env::set_var("PATH", old);
        } else {
            std::env::remove_var("PATH");
        }
    }
}

fn prepend_launcher_to_path() -> PathGuard {
    let launcher = launcher_path();
    let launcher_dir = launcher.parent().expect("launcher directory");
    let mut paths = vec![launcher_dir.to_path_buf()];
    paths.extend(std::env::split_paths(
        &std::env::var_os("PATH").unwrap_or_default(),
    ));
    PathGuard::set(std::env::join_paths(paths).expect("join PATH"))
}

#[tokio::test]
async fn newt_confined_contract_runs_only_inside_appcontainer() {
    let _path = prepend_launcher_to_path();
    let workspace = fresh_dir("admit");
    let marker = workspace.join("marker.txt");
    std::fs::write(&marker, "ORIG").expect("seed marker");

    let out = ShellTool::new()
        .invoke(
            serde_json::json!({
                "program": "cmd.exe",
                "args": ["/c", "echo", "NEWT_OK", ">", marker.to_string_lossy()],
                "cwd": workspace.to_string_lossy(),
                "timeout_secs": 5
            }),
            &ctx_confined(newt_contract(&workspace)),
        )
        .await
        .expect("invoke");

    assert_eq!(out["exit_code"], 0, "{out}");
    assert_eq!(out["sandbox_kind"], "app_container", "{out}");
    assert_eq!(out["enforcement"]["fs_read"], "kernel", "{out}");
    assert_eq!(out["enforcement"]["fs_write"], "kernel", "{out}");
    assert_eq!(out["enforcement"]["net"], "kernel", "{out}");
    assert_eq!(out["enforcement"]["exec"], "interceptor", "{out}");
    assert!(
        std::fs::read_to_string(&marker)
            .expect("read marker")
            .contains("NEWT_OK"),
        "admitted AppContainer run must write only inside the granted workspace"
    );

    let _ = std::fs::remove_dir_all(&workspace);
}

#[tokio::test]
async fn missing_aclaunch_refuses_newt_confined_contract_before_spawn() {
    let mut empty_path = std::env::temp_dir();
    empty_path.push(format!("ab-empty-path-{}", tag("missing")));
    std::fs::create_dir_all(&empty_path).expect("create empty PATH dir");
    let _path = PathGuard::set(empty_path.into_os_string());

    let mut adjacent = std::env::current_exe().expect("current test executable");
    adjacent.set_file_name("agent-bridle-aclaunch.exe");
    assert!(
        !adjacent.exists(),
        "missing-launcher proof cannot hide an adjacent launcher at {adjacent:?}"
    );

    let workspace = fresh_dir("missing");
    let marker = workspace.join("marker.txt");
    std::fs::write(&marker, "ORIG").expect("seed marker");

    let err = ShellTool::new()
        .invoke(
            serde_json::json!({
                "program": "cmd.exe",
                "args": ["/c", "echo", "HOSTILE_STARTED", ">", marker.to_string_lossy()],
                "cwd": workspace.to_string_lossy(),
                "timeout_secs": 5
            }),
            &ctx_confined(newt_contract(&workspace)),
        )
        .await
        .expect_err("missing AppContainer launcher must deny before spawn");

    assert!(
        matches!(err, ToolError::Denied { ref reason } if reason.contains("agent-bridle-aclaunch.exe not found")),
        "missing launcher must be a typed denial, got {err:?}"
    );
    assert_eq!(
        std::fs::read_to_string(&marker).expect("read marker"),
        "ORIG",
        "hostile command must not start when the AppContainer launcher is unavailable"
    );

    let _ = std::fs::remove_dir_all(&workspace);
}
