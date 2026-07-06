//! Integration keystone for carried coreutils (Track 2 Gate 2 / issue #206).
//!
//! Runs the dispatch-capable `dispatch_host` binary with the **environment
//! scrubbed** (`env_clear` — no `PATH`, no host tools), asking the embedded
//! brush engine to run `ls`/`cat`. These succeed ONLY if the carried uutils
//! coreutils dispatch in-process via re-exec of the (dispatch-capable) host
//! binary — proving the "just a filesystem" story. If the dispatch machinery
//! regressed, the shell would find no `ls`/`cat` at all.
#![cfg(feature = "carried-coreutils")]

use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

/// The dispatch-capable helper binary cargo built for us.
fn dispatch_host() -> &'static str {
    env!("CARGO_BIN_EXE_dispatch_host")
}

fn unique_temp(tag: &str) -> PathBuf {
    static N: AtomicU64 = AtomicU64::new(0);
    std::env::temp_dir().join(format!(
        "ab-carried-{}-{}-{}",
        tag,
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ))
}

/// Carried `ls` lists a directory with the environment fully scrubbed — no host
/// `/bin/ls`, no `PATH`. It resolves to the in-process uutils `ls` via the shim's
/// re-exec of the dispatch-capable host binary.
#[test]
fn carried_ls_runs_in_process_with_env_scrubbed() {
    let dir = unique_temp("ls");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("MARKER.txt"), b"x").unwrap();

    let out = Command::new(dispatch_host())
        .env_clear()
        .arg(format!("ls {}", dir.to_string_lossy()))
        .output()
        .expect("run dispatch_host");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "carried ls exited nonzero: stdout={stdout:?} stderr={stderr:?}"
    );
    assert!(
        stdout.contains("MARKER.txt"),
        "carried ls must list the dir with NO host tools: stdout={stdout:?} stderr={stderr:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// Carried `cat` reads a file with the environment fully scrubbed.
#[test]
fn carried_cat_runs_in_process_with_env_scrubbed() {
    let dir = unique_temp("cat");
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("hello.txt");
    std::fs::write(&file, b"carried-cat-ok\n").unwrap();

    let out = Command::new(dispatch_host())
        .env_clear()
        .arg(format!("cat {}", file.to_string_lossy()))
        .output()
        .expect("run dispatch_host");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stdout.contains("carried-cat-ok"),
        "carried cat must read the file with NO host tools: stdout={stdout:?} stderr={stderr:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
