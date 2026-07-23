//! Integration keystone for carried coreutils (Track 2 Gate 2 / issue #206).
//!
//! Runs the dispatch-capable `dispatch_host` binary with the **environment
//! scrubbed** (`env_clear` plus a guaranteed-dead `PATH`), asking the embedded
//! brush engine to run `ls`/`cat`/`wc`. These succeed ONLY if the carried uutils
//! coreutils dispatch in-process via re-exec of the (dispatch-capable) host
//! binary — proving the "just a filesystem" story. If the dispatch machinery
//! regressed, the shell would find none of these commands at all.
#![cfg(feature = "carried-coreutils")]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

/// The dispatch-capable helper binary cargo built for us.
fn dispatch_host() -> &'static str {
    env!("CARGO_BIN_EXE_dispatch_host")
}

/// Shell-quote a path for splicing into a brush command string. brush's
/// parser is POSIX-style: an unquoted `\` is an escape character. Windows
/// paths are backslash-separated, so without this an unquoted path like
/// `C:\Users\...\hello.txt` gets silently mangled to `C:Users...hello.txt`
/// (issue #209 W4 finding) — `\U`, `\A`, etc. get collapsed to the escaped
/// letter. Single-quoting is a no-op on Unix (paths there never contain `'`
/// in these tests) and makes the Windows path safe. Mirrors
/// `agent-bridle-jaild::vm::shell_quote`.
fn shell_quote(p: &Path) -> String {
    format!("'{}'", p.to_string_lossy().replace('\'', "'\\''"))
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

/// A `dispatch_host` command with **host tools removed from PATH**. PATH points
/// at a unique nonexistent location and the helper passes it through the
/// engine's explicit `env` seam, so the unrestricted test caveats cannot seed
/// the host's default executable path. On Windows a fully-empty environment
/// breaks process startup (`SystemRoot`, …), so we also keep only those
/// non-secret, always-required vars.
fn scrubbed() -> Command {
    let mut c = Command::new(dispatch_host());
    c.env_clear();
    c.env("PATH", unique_temp("empty-path"));
    #[cfg(windows)]
    for key in [
        "SystemRoot",
        "SystemDrive",
        "windir",
        "TEMP",
        "TMP",
        "USERPROFILE",
        "NUMBER_OF_PROCESSORS",
    ] {
        if let Ok(v) = std::env::var(key) {
            c.env(key, v);
        }
    }
    c
}

/// Carried `ls` lists a directory with the environment fully scrubbed — no host
/// `/bin/ls`, and a dead `PATH`. It resolves to the in-process uutils `ls` via
/// the shim's re-exec of the dispatch-capable host binary.
#[test]
fn carried_ls_runs_in_process_with_env_scrubbed() {
    let dir = unique_temp("ls");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("MARKER.txt"), b"x").unwrap();

    let out = scrubbed()
        .arg(format!("ls {}", shell_quote(&dir)))
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

    let out = scrubbed()
        .arg(format!("cat {}", shell_quote(&file)))
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

/// Carried `wc` counts lines in multiple files with the environment fully
/// scrubbed. This grounds the command shape used by agents to inspect source
/// files without relying on a host `/usr/bin/wc`.
#[test]
fn carried_wc_counts_lines_with_env_scrubbed() {
    let dir = unique_temp("wc");
    std::fs::create_dir_all(&dir).unwrap();
    let first = dir.join("first.txt");
    let second = dir.join("second.txt");
    std::fs::write(&first, b"one\ntwo\n").unwrap();
    std::fs::write(&second, b"three\nfour\nfive\n").unwrap();

    let out = scrubbed()
        .arg(format!(
            "wc -l {} {}",
            shell_quote(&first),
            shell_quote(&second)
        ))
        .output()
        .expect("run dispatch_host");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "carried wc exited nonzero: stdout={stdout:?} stderr={stderr:?}"
    );
    let counts: Vec<&str> = stdout
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .collect();
    assert_eq!(
        counts,
        ["2", "3", "5"],
        "carried wc must count both files and their total with NO host tools: \
         stdout={stdout:?} stderr={stderr:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
