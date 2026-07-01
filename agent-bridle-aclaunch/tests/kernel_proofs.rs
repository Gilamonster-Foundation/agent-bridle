//! Real AppContainer **kernel-enforcement** proofs (#51 / #123, ADR 0009).
//!
//! These spawn actual confined children through the *built* `agent-bridle-aclaunch`
//! binary and assert that the **Windows kernel** — the AppContainer DACL check and
//! the child-process-creation policy — blocks out-of-scope operations. They are the
//! Windows analog of `landlock_kernel_tests` (Linux) and `seatbelt_kernel_tests`
//! (macOS) in `agent-bridle-core`: they prove the *mechanism*, not the launcher's
//! flag-construction logic (which the unit tests in `main.rs` cover).
//!
//! Cargo exposes the compiled launcher to an integration test as
//! `CARGO_BIN_EXE_agent-bridle-aclaunch`, so no PATH lookup is needed.
//!
//! Like the Landlock/Seatbelt proofs (#74), a run with **`BRIDLE_REQUIRE_APPCONTAINER`**
//! set (as the Windows CI job does) must FAIL rather than skip if AppContainers
//! cannot be created here — so CI cannot go green without exercising the real
//! kernel boundary. A local run without the flag legitimately skips.
//!
//! **Write proofs test *modify-in-place* (`FILE_WRITE_DATA`), not directory create
//! (`FILE_ADD_FILE`).** The targets are pre-created so the only variable is the
//! `--fs-write` DACL grant. (An AppContainer spawned from an *elevated* parent — as
//! on the GitHub Windows runner — is denied the directory-create right even with the
//! grant, an elevated-context quirk unrelated to the confinement contract; modify is
//! the portable, faithful check of "can the confined child write here".)
//!
//! fs/exec proofs need no elevation. The net/loopback proofs live separately because
//! the loopback exemption (`NetworkIsolationSetAppContainerConfig`) requires an
//! elevated token.
#![cfg(target_os = "windows")]

use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

const LAUNCHER: &str = env!("CARGO_BIN_EXE_agent-bridle-aclaunch");

static N: AtomicU64 = AtomicU64::new(0);

/// A unique tag (pid + monotonic counter — no wall clock, no rand) for container
/// names and temp dirs, so parallel test threads never collide.
fn tag(kind: &str) -> String {
    format!(
        "{kind}-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    )
}

/// A fresh, empty temp dir owned by this (test) user — so the launcher, running as
/// the same user, has `WRITE_DAC` to grant the AppContainer SID an ACE on it.
///
/// The dir's **mandatory integrity label is lowered to Low** (with object/container
/// inheritance). An AppContainer child runs below Medium integrity; without this,
/// Mandatory Integrity Control's *no-write-up* rule blocks writes independently of
/// the DACL — especially on an elevated CI host where temp dirs default to a higher
/// label. With every test dir at Low, the only variable that decides read/write is
/// the `--fs-read`/`--fs-write` DACL grant we are proving.
fn fresh_dir(kind: &str) -> PathBuf {
    let mut d = std::env::temp_dir();
    d.push(format!("ab-proof-{}", tag(kind)));
    std::fs::create_dir_all(&d).expect("create temp dir");
    let _ = Command::new("icacls")
        .arg(&d)
        .args(["/setintegritylevel", "(OI)(CI)Low"])
        .output();
    d
}

/// Run the launcher with `args`, returning the captured output. Panics if the
/// launcher itself cannot be spawned.
///
/// The child inherits the launcher's current directory, so we run from `C:\Windows`
/// — a directory every AppContainer can read (`ALL_APPLICATION_PACKAGES`). A confined
/// child whose CWD it cannot access dies with "The current directory is invalid"
/// before running. Proofs use absolute paths, so the CWD choice never affects what
/// is read/written.
fn launch(args: &[&str]) -> std::process::Output {
    Command::new(LAUNCHER)
        .args(args)
        .current_dir("C:\\Windows")
        .output()
        .expect("spawn agent-bridle-aclaunch")
}

/// Can this host actually create an AppContainer and run a trivial confined child?
fn appcontainer_available() -> bool {
    launch(&["--name", &tag("probe"), "cmd.exe", "/c", "exit 0"])
        .status
        .success()
}

/// `true` ⇒ the caller should `return` (skip). Panics when AppContainers are
/// *required* (`BRIDLE_REQUIRE_APPCONTAINER`, as CI sets) but unavailable — a
/// flagged run cannot pass without exercising the real kernel boundary (#74 parity).
fn skip_proof_unless_appcontainer() -> bool {
    let required = std::env::var("BRIDLE_REQUIRE_APPCONTAINER")
        .map(|v| !v.is_empty() && v != "0")
        .unwrap_or(false);
    if appcontainer_available() {
        return false;
    }
    if required {
        panic!(
            "BRIDLE_REQUIRE_APPCONTAINER is set but an AppContainer could not be created \
             here — the fs/exec kernel-enforcement proofs cannot be verified (#74 parity)"
        );
    }
    eprintln!(
        "skipping AppContainer proof: cannot create an AppContainer here \
         (set BRIDLE_REQUIRE_APPCONTAINER=1 to require it, as CI does)"
    );
    true
}

const SENTINEL: &str = "ORIG";
const WRITTEN: &str = "WRITTEN_BY_CHILD";

/// fs_write (#51): the kernel lets the confined child modify a `--fs-write`-granted
/// file and **denies** modifying an ungranted user file (AppContainers default-deny
/// user files; only the explicit DACL ACE opens the granted one).
#[test]
fn fs_write_kernel_allows_granted_denies_ungranted() {
    if skip_proof_unless_appcontainer() {
        return;
    }
    let granted = fresh_dir("fsw-grant");
    let denied = fresh_dir("fsw-deny");
    let g_file = granted.join("g.txt");
    let d_file = denied.join("d.txt");
    std::fs::write(&g_file, SENTINEL).expect("seed granted file");
    std::fs::write(&d_file, SENTINEL).expect("seed denied file");

    // One confined child overwrites BOTH files (`echo WRITTEN> file`). Only the
    // granted one may change; the ungranted one must remain the sentinel.
    let out = launch(&[
        "--name",
        &tag("fsw"),
        "--fs-write",
        &granted.to_string_lossy(),
        "cmd.exe",
        "/c",
        "echo",
        WRITTEN,
        ">",
        &g_file.to_string_lossy(),
        "&",
        "echo",
        WRITTEN,
        ">",
        &d_file.to_string_lossy(),
    ]);

    let g = std::fs::read_to_string(&g_file).unwrap_or_default();
    let d = std::fs::read_to_string(&d_file).unwrap_or_default();
    assert!(
        g.contains(WRITTEN),
        "kernel must ALLOW writing the --fs-write-granted file; got {g:?}; launcher stderr: {}",
        String::from_utf8_lossy(&out.stderr).trim()
    );
    assert!(
        d.contains(SENTINEL) && !d.contains(WRITTEN),
        "kernel must DENY writing the ungranted file; it leaked to {d:?}"
    );

    let _ = std::fs::remove_dir_all(&granted);
    let _ = std::fs::remove_dir_all(&denied);
}

/// fs_read (#51): a `--fs-read`-granted file is readable by the confined child; an
/// ungranted user file is **kernel-denied** (its content never reaches stdout).
#[test]
fn fs_read_kernel_allows_granted_denies_ungranted() {
    if skip_proof_unless_appcontainer() {
        return;
    }
    let readable = fresh_dir("fsr-grant");
    let secret = readable.join("secret.txt");
    std::fs::write(&secret, "SECRET_GRANTED_MARKER").expect("write secret");

    let hidden_dir = fresh_dir("fsr-deny");
    let hidden = hidden_dir.join("hidden.txt");
    std::fs::write(&hidden, "SECRET_HIDDEN_MARKER").expect("write hidden");

    let allowed = launch(&[
        "--name",
        &tag("fsr-ok"),
        "--fs-read",
        &readable.to_string_lossy(),
        "cmd.exe",
        "/c",
        "type",
        &secret.to_string_lossy(),
    ]);
    assert!(
        String::from_utf8_lossy(&allowed.stdout).contains("SECRET_GRANTED_MARKER"),
        "kernel must ALLOW reading the --fs-read-granted file; stdout was {:?}",
        String::from_utf8_lossy(&allowed.stdout)
    );

    let denied = launch(&[
        "--name",
        &tag("fsr-no"),
        "cmd.exe",
        "/c",
        "type",
        &hidden.to_string_lossy(),
    ]);
    assert!(
        !String::from_utf8_lossy(&denied.stdout).contains("SECRET_HIDDEN_MARKER"),
        "kernel must DENY reading the ungranted file; leaked stdout was {:?}",
        String::from_utf8_lossy(&denied.stdout)
    );

    let _ = std::fs::remove_dir_all(&readable);
    let _ = std::fs::remove_dir_all(&hidden_dir);
}

/// exec deny-all (#123): with `--no-child-process`
/// (`PROCESS_CREATION_CHILD_PROCESS_RESTRICTED`) the confined child cannot spawn a
/// grandchild — the kernel refuses the inner `CreateProcess`. The grandchild's job
/// is to overwrite a pre-created, `--fs-write`-granted marker; the control run (no
/// flag) proves it otherwise *would*, so the difference is the kernel policy.
#[test]
fn exec_deny_all_kernel_blocks_child_process_creation() {
    if skip_proof_unless_appcontainer() {
        return;
    }
    // Control: no --no-child-process ⇒ the inner cmd.exe runs and overwrites gc.txt.
    let control = fresh_dir("exec-ctl");
    let control_marker = control.join("gc.txt");
    std::fs::write(&control_marker, SENTINEL).expect("seed control marker");
    let control_out = launch(&[
        "--name",
        &tag("exec-ctl"),
        "--fs-write",
        &control.to_string_lossy(),
        "cmd.exe",
        "/c",
        "cmd.exe",
        "/c",
        "echo",
        WRITTEN,
        ">",
        &control_marker.to_string_lossy(),
    ]);
    let ctl = std::fs::read_to_string(&control_marker).unwrap_or_default();
    assert!(
        ctl.contains(WRITTEN),
        "control: without --no-child-process the grandchild must run (else the test proves \
         nothing); marker {ctl:?}; launcher stderr: {}",
        String::from_utf8_lossy(&control_out.stderr).trim()
    );

    // Restricted: --no-child-process ⇒ the kernel blocks the inner CreateProcess,
    // so the grandchild never runs and the marker stays the sentinel.
    let restricted = fresh_dir("exec-deny");
    let restricted_marker = restricted.join("gc.txt");
    std::fs::write(&restricted_marker, SENTINEL).expect("seed restricted marker");
    launch(&[
        "--name",
        &tag("exec-deny"),
        "--no-child-process",
        "--fs-write",
        &restricted.to_string_lossy(),
        "cmd.exe",
        "/c",
        "cmd.exe",
        "/c",
        "echo",
        WRITTEN,
        ">",
        &restricted_marker.to_string_lossy(),
    ]);
    let r = std::fs::read_to_string(&restricted_marker).unwrap_or_default();
    // The outer cmd sets up its `> marker` redirect (truncating the marker to empty)
    // *before* trying to spawn the inner cmd, so a blocked run leaves the marker
    // empty — never `WRITTEN`. The signal is the absence of the grandchild's output;
    // the control run above proves the grandchild otherwise writes it.
    assert!(
        !r.contains(WRITTEN),
        "kernel must BLOCK child-process creation under --no-child-process (#123); the \
         grandchild must not have run, but the marker holds its output: {r:?}"
    );

    let _ = std::fs::remove_dir_all(&control);
    let _ = std::fs::remove_dir_all(&restricted);
}
