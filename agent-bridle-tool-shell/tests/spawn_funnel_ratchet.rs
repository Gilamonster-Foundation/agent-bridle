//! Ratchet (#493): tool-shell builds children only through core's funnel.
//!
//! An engine that calls `std::process::Command` itself can start a child that
//! was never admitted, under a fence nothing verified. Core's funnel
//! (`ConfinedCommand`, `SandboxedWorker`, `ConfinedLaunch`) is the only place
//! that may do it. This test scans the crate's sources for a raw
//! `Command::new(` or a bare `.spawn()` and compares the count per file with
//! the known sites below.
//!
//! The counts may only go down. When you remove a site, lower its number; a
//! new site fails here and belongs behind the funnel instead.

use std::path::{Path, PathBuf};

/// Known raw sites: `(file, raw Command::new, bare .spawn())`.
const KNOWN_SITES: &[(&str, usize, usize)] = &[
    // The in-worker spawn: it runs inside the Brush worker, which core already
    // started under the admitted fence, and re-enters the exec filter.
    ("coreutils_dispatch.rs", 0, 1),
    // Test-only: a same-image child for the private-control handshake tests.
    ("private_control.rs", 1, 1),
    // Test-only: a stand-in child for the authentication-cancellation test.
    ("brush_shell.rs", 1, 1),
];

fn rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("read source dir") {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            rust_sources(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

/// Occurrences of `needle` in code lines (comment lines skipped). A needle
/// that starts with an identifier character must not be the tail of a longer
/// identifier, so `ConfinedCommand::new(` does not count as `Command::new(`.
fn count(source: &str, needle: &str) -> usize {
    let is_ident = |c: char| c.is_alphanumeric() || c == '_';
    let whole_word = needle.chars().next().is_some_and(is_ident);
    source
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .map(|line| {
            line.match_indices(needle)
                .filter(|(at, _)| {
                    !whole_word || !line[..*at].chars().next_back().is_some_and(is_ident)
                })
                .count()
        })
        .sum()
}

#[test]
fn children_are_built_only_through_the_core_funnel() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_sources(&src, &mut files);
    assert!(
        !files.is_empty(),
        "no sources found under {}",
        src.display()
    );

    let mut drift = Vec::new();
    for path in files {
        let name = path
            .strip_prefix(&src)
            .expect("under src")
            .to_string_lossy()
            .replace('\\', "/");
        let source = std::fs::read_to_string(&path).expect("read source");
        let found = (count(&source, "Command::new("), count(&source, ".spawn()"));
        let known = KNOWN_SITES
            .iter()
            .find(|(file, _, _)| *file == name)
            .map_or((0, 0), |(_, commands, spawns)| (*commands, *spawns));
        if found != known {
            drift.push(format!(
                "{name}: found {} raw Command::new and {} bare .spawn(), expected {} and {}",
                found.0, found.1, known.0, known.1
            ));
        }
    }
    assert!(
        drift.is_empty(),
        "tool-shell must build children through core's funnel (#493). \
         Route a new site through ConfinedCommand or ConfinedLaunch; \
         lower a count in KNOWN_SITES when you remove one:\n{}",
        drift.join("\n")
    );
}

#[test]
fn the_scanner_ignores_funnel_types_and_comments() {
    let source = "let a = ConfinedCommand::new(x);\n// Command::new(y).spawn()\n\
                  let b = std::process::Command::new(z);\nlet c = b.spawn();\n\
                  let d = worker.spawn(cx);\n";
    assert_eq!(count(source, "Command::new("), 1);
    assert_eq!(count(source, ".spawn()"), 1);
}
