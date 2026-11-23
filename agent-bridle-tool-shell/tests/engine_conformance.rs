//! Real-resource conformance lane for engine choice as data (#491).
//!
//! The same requests run through every compiled engine, built by
//! `ShellEngine::build`. Each engine's output cap must be reported through
//! the truncation flags, and every cell its `coverage()` rates `Checked` is
//! sampled once with an out-of-scope request that must be refused without
//! running. A `Checked` cell with no sampler fails the lane, so the table
//! cannot claim a check this lane never exercised.
//!
//! #523: the lane runs once per runtime row (ADR 0029 D2). The rows come from
//! the ADR's own table, read at compile time, and are compared with the rows
//! this host can run: every engine built in, under the fence the host
//! applies. A row the table lists for this OS that the lane does not run, or a
//! row the lane runs that the table omits, fails the lane. The lane prints one
//! line per row it ran and one per row it skipped, with the reason.
//!
//! Single-threaded on purpose (`harness = false`, one current-thread runtime):
//! the Brush engine re-executes this binary as its worker.

// The lane runs on Unix only (it uses `yes`, `head` and `touch`).
#![cfg_attr(not(unix), allow(unused_imports, dead_code))]

use std::path::{Path, PathBuf};

use agent_bridle_core::{
    best_available_sandbox, Caveats, Gate, LimitsPolicy, SandboxKind, SandboxPolicy, Scope, Tool,
    ToolContext,
};
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
    let (host_fence, runnable) = runnable_rows();
    let table: Vec<Row> = adr_rows(host_fence)
        .into_iter()
        .filter(|row| row.fence == host_fence)
        .collect();
    for row in &table {
        if !runnable.contains(row) {
            eprintln!(
                "skip row {} / {:?}: engine not available in this build",
                row.engine, row.fence
            );
        }
    }
    let expected: Vec<Row> = table
        .into_iter()
        .filter(|row| row.engine.validate_available().is_ok())
        .collect();
    let same = runnable.len() == expected.len()
        && runnable.iter().all(|row| expected.contains(row))
        && expected.iter().all(|row| runnable.contains(row));
    assert!(
        same,
        "the rows this host runs {runnable:?} differ from ADR 0029 D2's rows for {} {expected:?}",
        os_name()
    );
    let mut ran = 0;
    for row in runnable {
        let engine = row.engine;
        let tool = engine
            .build(ShellOptions {
                limits: LimitsPolicy {
                    max_output_bytes: CAP,
                    ..LimitsPolicy::default()
                },
                ..ShellOptions::default()
            })
            .unwrap_or_else(|error| panic!("{engine} must build: {error}"));
        println!("row: {} / {} / {:?}", os_name(), engine, row.fence);
        runtime.block_on(reports_the_rows_fence(row, &*tool));
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
        #[cfg(all(target_os = "linux", feature = "linux-landlock"))]
        runtime.block_on(held_read_root_follows_the_object(engine));
        ran += 1;
    }
    assert!(ran > 0, "no engine was compiled into this lane");
    println!("engine_conformance: {ran} engine(s) ok");
}

/// One runtime row: an engine under the fence the host applies (ADR 0029 D2).
#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Row {
    engine: ShellEngine,
    fence: SandboxKind,
}

#[cfg(unix)]
fn os_name() -> &'static str {
    if cfg!(target_os = "macos") {
        "macOS"
    } else {
        "Linux"
    }
}

#[cfg(unix)]
fn fence_from_adr(name: &str) -> Option<SandboxKind> {
    match name {
        "Landlock" => Some(SandboxKind::Landlock),
        "Seatbelt" => Some(SandboxKind::Seatbelt),
        "AppContainer" => Some(SandboxKind::AppContainer),
        "none" => Some(SandboxKind::None),
        _ => None,
    }
}

/// The rows ADR 0029 D2 lists for this OS, one per engine and fence. A cell
/// that says `any` expands to every engine, or to the fence the host applies.
#[cfg(unix)]
fn adr_rows(host_fence: SandboxKind) -> Vec<Row> {
    let adr = include_str!("../../docs/adr/0029-runtime-engine-fence-tool-source.md");
    let mut rows = Vec::new();
    for line in adr
        .lines()
        .filter(|l| l.starts_with(&format!("| {} |", os_name())))
    {
        let cells: Vec<&str> = line.split('|').map(str::trim).collect();
        // ["", os, engine, fence, tool source, admitted by, tested by, ""]
        let engines: Vec<ShellEngine> = if cells[2] == "any" {
            ShellEngine::ALL.to_vec()
        } else {
            ShellEngine::ALL
                .into_iter()
                .filter(|e| cells[2].contains(&format!("`{e}`")))
                .collect()
        };
        let fence = if cells[3] == "any" {
            Some(host_fence)
        } else {
            fence_from_adr(cells[3])
        };
        let fence = fence.unwrap_or_else(|| panic!("ADR 0029 row has an unknown fence: {line}"));
        rows.extend(engines.into_iter().map(|engine| Row { engine, fence }));
    }
    assert!(!rows.is_empty(), "ADR 0029 lists no row for {}", os_name());
    rows
}

/// The rows this host can run: each engine built in and available, under the
/// fence the host applies.
#[cfg(unix)]
fn runnable_rows() -> (SandboxKind, Vec<Row>) {
    let fence = best_available_sandbox(&std::sync::Arc::new(SandboxPolicy::default())).kind();
    let rows = ShellEngine::ALL
        .into_iter()
        .filter(|e| e.validate_available().is_ok())
        .map(|engine| Row { engine, fence })
        .collect();
    (fence, rows)
}

/// The result of a restricted run names the fence the row claims.
#[cfg(unix)]
async fn reports_the_rows_fence(row: Row, tool: &dyn Tool) {
    let dir = temp_dir(&format!("{}-fence", row.engine));
    let granted = Caveats {
        fs_write: only(&dir),
        ..Caveats::top()
    };
    let out = tool
        .invoke(
            serde_json::json!({"cmd": "echo hi", "cwd": dir}),
            &ctx(tool, &granted),
        )
        .await
        .unwrap_or_else(|error| panic!("{} fence run: {error}", row.engine));
    assert_eq!(
        out["sandbox_kind"],
        serde_json::to_value(row.fence).unwrap(),
        "{}: the result names a different fence than the row: {out}",
        row.engine
    );
    let _ = std::fs::remove_dir_all(&dir);
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
            // The path form goes straight to each engine's exec check. A bare
            // name is looked up on PATH first, and under Seatbelt that lookup
            // fails before Brush's filter sees it: the command still never
            // runs, but it reports "command not found", not a denial.
            serde_json::json!({"cmd": format!("/bin/touch {}", marker.display())}),
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
    let outcome = tool.invoke(args, &ctx(tool, &granted)).await;
    let refused = match &outcome {
        Err(error) => matches!(error, agent_bridle_core::ToolError::Denied { .. }),
        Ok(out) => out["denied"] == true,
    };
    assert!(
        refused,
        "{engine} {operation:?}/{origin:?}: not refused: {outcome:?}"
    );
    assert!(
        !marker.exists(),
        "{engine} {operation:?}/{origin:?}: the refused command ran"
    );
    let _ = std::fs::remove_dir_all(&inside);
    let _ = std::fs::remove_dir_all(&outside);
}

/// #494: an engine built with a held read root keeps reading the HELD object
/// after its path is swapped, and cannot read the directory swapped in. The
/// control, built without the held root, follows the pathname instead.
#[cfg(all(target_os = "linux", feature = "linux-landlock"))]
async fn held_read_root_follows_the_object(engine: ShellEngine) {
    use agent_bridle_core::HeldReadRoot;
    if !agent_bridle_core::landlock_is_supported() {
        eprintln!("skip held-root proof for {engine}: Landlock unavailable");
        return;
    }
    let root = temp_dir(&format!("{engine}-held-root"));
    let aside = PathBuf::from(format!("{}.aside", root.display()));
    let _ = std::fs::remove_dir_all(&aside);
    std::fs::write(root.join("held.txt"), "held").expect("write held file");
    // Bind while `root` still names the held object, then swap the path.
    let held = HeldReadRoot::bind(
        root.to_string_lossy().into_owned(),
        std::fs::File::open(&root).expect("open root").into(),
    )
    .expect("bind before the swap");
    std::fs::rename(&root, &aside).expect("move the held object aside");
    std::fs::create_dir(&root).expect("swap in a new directory");
    std::fs::write(root.join("swapped.txt"), "swapped").expect("write swapped file");

    let granted = Caveats {
        fs_read: only(&root),
        ..Caveats::top()
    };
    let cat = |tool: std::sync::Arc<dyn Tool>, file: PathBuf| {
        let granted = granted.clone();
        let cwd = root.clone();
        async move {
            tool.invoke(
                serde_json::json!({"cmd": format!("cat {}", file.display()), "cwd": cwd}),
                &ctx(&*tool, &granted),
            )
            .await
        }
    };
    let with_held = engine
        .build(ShellOptions {
            held_read_roots: vec![held],
            ..ShellOptions::default()
        })
        .expect("build with a held root");
    let held_read = cat(with_held.clone(), aside.join("held.txt")).await;
    let held_read = held_read.unwrap_or_else(|error| panic!("{engine} held read: {error}"));
    assert_eq!(held_read["stdout"], "held", "{engine}: {held_read}");
    let swapped_read = cat(with_held, root.join("swapped.txt"))
        .await
        .unwrap_or_else(|error| panic!("{engine} swapped read: {error}"));
    assert_ne!(
        swapped_read["exit_code"], 0,
        "{engine}: the swapped-in directory is outside the held fence: {swapped_read}"
    );
    assert_eq!(swapped_read["stdout"], "", "{engine}: {swapped_read}");

    // Control: with no held root the path rule follows the pathname.
    let by_path = engine
        .build(ShellOptions::default())
        .expect("build control");
    let control = cat(by_path, root.join("swapped.txt"))
        .await
        .unwrap_or_else(|error| panic!("{engine} control read: {error}"));
    assert_eq!(control["stdout"], "swapped", "{engine} control: {control}");

    let _ = std::fs::remove_dir_all(&root);
    let _ = std::fs::remove_dir_all(&aside);
}
