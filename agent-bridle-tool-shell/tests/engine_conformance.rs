//! Real-resource conformance lane for engine choice as data (#491).
//!
//! The same requests run through every compiled engine, built by
//! `ShellEngine::build`. Each engine's output cap must be reported through
//! the truncation flags, and every cell its `coverage()` rates `Checked` is
//! sampled once with an out-of-scope request that must be refused without
//! running. A `Checked` cell with no sampler fails the lane, so the table
//! cannot claim a check this lane never exercised.
//!
//! Single-threaded on purpose (`harness = false`, one current-thread runtime):
//! the Brush engine re-executes this binary as its worker.

// The lane runs on Unix only (it uses `yes`, `head` and `touch`).
#![cfg_attr(not(unix), allow(unused_imports, dead_code))]

use std::path::{Path, PathBuf};

use agent_bridle_core::{Caveats, Gate, LimitsPolicy, Scope, Tool, ToolContext};
use agent_bridle_tool_shell::{Check, Operation, Origin, ShellEngine, ShellOptions};

fn main() {
    // Worker mode must be the first branch, before any test fixture runs.
    #[cfg(feature = "brush")]
    if let Some(code) = agent_bridle_tool_shell::maybe_dispatch() {
        std::process::exit(code);
    }
    #[cfg(unix)]
    run();
}

#[cfg(unix)]
fn run() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime");
    let mut ran = 0;
    for engine in ShellEngine::ALL {
        if engine.validate_available().is_err() {
            eprintln!("skip {engine}: not available in this build");
            continue;
        }
        let tool = engine
            .build(ShellOptions {
                limits: LimitsPolicy {
                    max_output_bytes: CAP,
                    ..LimitsPolicy::default()
                },
                ..ShellOptions::default()
            })
            .unwrap_or_else(|error| panic!("{engine} must build: {error}"));
        runtime.block_on(overflow_sets_truncation(engine, &*tool));
        for cell in engine.coverage() {
            if cell.check == Check::Checked {
                runtime.block_on(refuses_out_of_scope(
                    engine,
                    &*tool,
                    cell.operation,
                    cell.origin,
                ));
            }
        }
        ran += 1;
    }
    assert!(ran > 0, "no engine was compiled into this lane");
    println!("engine_conformance: {ran} engine(s) ok");
}

const CAP: usize = 4096;

fn ctx(tool: &dyn Tool, granted: &Caveats) -> ToolContext {
    Gate::new(0).authorize(tool, granted).expect("authorize")
}

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ab-conformance-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("temp dir");
    dir.canonicalize().expect("canonical temp dir")
}

fn only(path: &Path) -> Scope<String> {
    Scope::only([path.to_string_lossy().into_owned()])
}

/// #491: output past the cap is reported, never silently dropped. Host never
/// set `stdout_truncated` before this change.
#[cfg(unix)]
async fn overflow_sets_truncation(engine: ShellEngine, tool: &dyn Tool) {
    let out = tool
        .invoke(
            serde_json::json!({"cmd": format!("yes a | head -c {}", CAP * 2)}),
            &ctx(tool, &Caveats::top()),
        )
        .await
        .unwrap_or_else(|error| panic!("{engine} overflow run: {error}"));
    assert_eq!(out["stdout_truncated"], true, "{engine}: {out}");
    assert!(
        out["stdout"].as_str().unwrap().len() <= CAP,
        "{engine}: stdout exceeds the cap"
    );
}

/// One out-of-scope request per `Checked` cell. The command would leave a
/// marker file if it ran; the call must be refused and the marker absent.
#[cfg(unix)]
async fn refuses_out_of_scope(
    engine: ShellEngine,
    tool: &dyn Tool,
    operation: Operation,
    origin: Origin,
) {
    let tag = format!("{engine}-{operation:?}-{origin:?}").to_lowercase();
    let inside = temp_dir(&format!("{tag}-in"));
    let outside = temp_dir(&format!("{tag}-out"));
    let marker = outside.join("ran");
    let (granted, args) = match (operation, origin) {
        (Operation::Exec, Origin::Shell) => (
            Caveats {
                exec: Scope::only(["echo".to_string()]),
                ..Caveats::top()
            },
            serde_json::json!({"cmd": format!("touch {}", marker.display())}),
        ),
        (Operation::Open, Origin::Shell) => (
            Caveats {
                fs_write: only(&inside),
                ..Caveats::top()
            },
            serde_json::json!({"cmd": format!("echo hi > {}", marker.display())}),
        ),
        (Operation::Enumerate, Origin::Shell) => (
            Caveats {
                fs_read: only(&inside),
                fs_write: only(&inside),
                ..Caveats::top()
            },
            serde_json::json!({
                "cmd": format!("echo {}/*", outside.display()),
                "cwd": inside,
            }),
        ),
        (Operation::Metadata, Origin::Shell) => (
            Caveats {
                fs_read: only(&inside),
                fs_write: only(&inside),
                ..Caveats::top()
            },
            serde_json::json!({"cmd": "echo hi", "cwd": outside}),
        ),
        other => panic!("{engine} rates {other:?} Checked but this lane has no sampler for it"),
    };
    let refused = match tool.invoke(args, &ctx(tool, &granted)).await {
        Err(error) => matches!(error, agent_bridle_core::ToolError::Denied { .. }),
        Ok(out) => out["denied"] == true,
    };
    assert!(refused, "{engine} {operation:?}/{origin:?}: not refused");
    assert!(
        !marker.exists(),
        "{engine} {operation:?}/{origin:?}: the refused command ran"
    );
    let _ = std::fs::remove_dir_all(&inside);
    let _ = std::fs::remove_dir_all(&outside);
}
