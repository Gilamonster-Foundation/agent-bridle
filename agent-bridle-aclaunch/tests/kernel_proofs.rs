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
//! fs/exec proofs need no elevation (ACLs on user-owned temp dirs + the child-process
//! policy). The net/loopback proofs live separately because the loopback exemption
//! (`NetworkIsolationSetAppContainerConfig`) requires an elevated token.
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
/// the DACL — which would confound the proof, especially on an **elevated** CI host
/// where temp dirs are created at a higher label (there fs_read passes but fs_write
/// fails for the wrong reason). With every test dir at Low, the only variable that
/// decides read/write is the `--fs-read`/`--fs-write` DACL grant we are proving.
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

/// Run the launcher with `args`, returning the captured output (stdout/stderr +
/// status). Panics if the launcher itself cannot be spawned.
///
/// The child inherits the launcher's current directory, so we run from `C:\Windows`
/// — a directory every AppContainer can read (`ALL_APPLICATION_PACKAGES`). The
/// crate's own build dir is *not* granted to the container, and a confined child
/// whose CWD it cannot access dies with "The current directory is invalid" before
/// running (which would break a real grandchild spawn). Proofs use absolute paths,
/// so the CWD choice never affects what is read/written.
fn launch(args: &[&str]) -> std::process::Output {
    Command::new(LAUNCHER)
        .args(args)
        .current_dir("C:\\Windows")
        .output()
        .expect("spawn agent-bridle-aclaunch")
}

/// Can this host actually create an AppContainer and run a trivial confined child?
/// A container-less environment (some CI sandboxes) cannot — the proofs then skip,
/// unless `BRIDLE_REQUIRE_APPCONTAINER` demands them.
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

/// fs_write (#51): the kernel allows a write to a `--fs-write`-granted path and
/// **denies** a write to an ungranted user dir (AppContainers default-deny user
/// directories; only the explicit DACL ACE opens the granted one).
#[test]
fn fs_write_kernel_allows_granted_denies_ungranted() {
    if skip_proof_unless_appcontainer() {
        return;
    }
    let granted = fresh_dir("fsw-grant");
    let denied = fresh_dir("fsw-deny");
    let g_file = granted.join("g.txt");
    let d_file = denied.join("d.txt");

    // One confined child attempts BOTH writes (`copy NUL <path>` creates an empty
    // file with no `>` redirection to quote). Only the granted one may land.
    let out = launch(&[
        "--name",
        &tag("fsw"),
        "--fs-write",
        &granted.to_string_lossy(),
        "cmd.exe",
        "/c",
        "copy",
        "NUL",
        &g_file.to_string_lossy(),
        "&",
        "copy",
        "NUL",
        &d_file.to_string_lossy(),
    ]);

    // Rich failure diagnostics (this proof behaves differently on elevated hosts):
    // the launcher's own output (does it report a failed ACL grant?) and the actual
    // resulting ACL + integrity label on the granted dir.
    let diag = || {
        let acl = Command::new("icacls")
            .arg(&granted)
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
            .unwrap_or_default();
        format!(
            "\n  temp_dir = {}\n  launcher stdout: {}\n  launcher stderr: {}\n  granted ACL:\n{}",
            std::env::temp_dir().display(),
            String::from_utf8_lossy(&out.stdout).trim(),
            String::from_utf8_lossy(&out.stderr).trim(),
            acl
        )
    };

    assert!(
        g_file.exists(),
        "kernel must ALLOW the write to the --fs-write-granted path{}",
        diag()
    );
    assert!(
        !d_file.exists(),
        "kernel must DENY the write to the ungranted path (AppContainer default-deny)"
    );

    let _ = std::fs::remove_dir_all(&granted);
    let _ = std::fs::remove_dir_all(&denied);
}

/// fs_read (#51): a `--fs-read`-granted file is readable by the confined child;
/// an ungranted user file is **kernel-denied** (its content never reaches stdout).
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

    // Granted read → the marker reaches stdout.
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

    // Ungranted read → the marker must NOT reach stdout (access denied).
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
/// grandchild — the kernel refuses the inner `CreateProcess`. The control run
/// (same command, no flag) proves the grandchild otherwise *would* run, so the
/// difference is the kernel policy, not the environment.
#[test]
fn exec_deny_all_kernel_blocks_child_process_creation() {
    if skip_proof_unless_appcontainer() {
        return;
    }
    // Control: no --no-child-process ⇒ the inner cmd.exe runs and creates gc.txt.
    let control = fresh_dir("exec-ctl");
    let control_marker = control.join("gc.txt");
    launch(&[
        "--name",
        &tag("exec-ctl"),
        "--fs-write",
        &control.to_string_lossy(),
        "cmd.exe",
        "/c",
        "cmd.exe",
        "/c",
        "copy",
        "NUL",
        &control_marker.to_string_lossy(),
    ]);
    assert!(
        control_marker.exists(),
        "control: without --no-child-process the grandchild must run (else the test proves nothing)"
    );

    // Restricted: --no-child-process ⇒ the kernel blocks the inner CreateProcess,
    // so the grandchild never runs and gc.txt is never created.
    let restricted = fresh_dir("exec-deny");
    let restricted_marker = restricted.join("gc.txt");
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
        "copy",
        "NUL",
        &restricted_marker.to_string_lossy(),
    ]);
    assert!(
        !restricted_marker.exists(),
        "kernel must BLOCK child-process creation under --no-child-process (#123)"
    );

    let _ = std::fs::remove_dir_all(&control);
    let _ = std::fs::remove_dir_all(&restricted);
}
