//! Adversarial filesystem proofs for the Windows AppContainer launcher.
//!
//! These exercise real path objects and real AppContainer children. A path that
//! escapes a granted workspace through a junction or normalization variant must
//! still be denied by NTFS/AppContainer policy, not by command-not-found or a
//! missing test resource.

#![cfg(target_os = "windows")]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

const LAUNCHER: &str = env!("CARGO_BIN_EXE_agent-bridle-aclaunch");
const FSPROBE: &str = env!("CARGO_BIN_EXE_ab-fsprobe");
const SECRET: &str = "SECRET_OUTSIDE_MARKER";
const ORIG: &str = "ORIG";
const WRITTEN: &str = "WRITTEN_BY_CHILD";

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
    d.push(format!("ab-fsadv-{}", tag(kind)));
    std::fs::create_dir_all(&d).expect("create temp dir");
    let _ = Command::new("icacls")
        .arg(&d)
        .args(["/setintegritylevel", "(OI)(CI)Low"])
        .output();
    d
}

fn launch(args: &[&str]) -> std::process::Output {
    Command::new(LAUNCHER)
        .args(args)
        .current_dir("C:\\Windows")
        .output()
        .expect("spawn agent-bridle-aclaunch")
}

fn launch_owned(args: Vec<String>) -> std::process::Output {
    Command::new(LAUNCHER)
        .args(args)
        .current_dir("C:\\Windows")
        .output()
        .expect("spawn agent-bridle-aclaunch")
}

fn wait_for_file(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if path.exists() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("timed out waiting for {path:?}");
}

fn appcontainer_available() -> bool {
    launch(&["--name", &tag("probe"), "cmd.exe", "/c", "exit 0"])
        .status
        .success()
}

fn skip_proof_unless_appcontainer() -> bool {
    let required = std::env::var("BRIDLE_REQUIRE_APPCONTAINER")
        .map(|v| !v.is_empty() && v != "0")
        .unwrap_or(false);
    if appcontainer_available() {
        return false;
    }
    if required {
        panic!("BRIDLE_REQUIRE_APPCONTAINER is set but AppContainer could not be created");
    }
    eprintln!("skipping AppContainer fs proof: cannot create AppContainer here");
    true
}

fn create_junction(link: &Path, target: &Path) {
    let out = Command::new("cmd.exe")
        .args(["/c", "mklink", "/J"])
        .arg(link)
        .arg(target)
        .output()
        .expect("spawn mklink");
    assert!(
        out.status.success(),
        "mklink /J must succeed for this proof; stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout).trim(),
        String::from_utf8_lossy(&out.stderr).trim()
    );
}

fn cleanup_junction(link: &Path) {
    let _ = std::fs::remove_dir(link);
}

fn assert_access_denied(out: &std::process::Output, route: &str) {
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        text.contains("Access is denied."),
        "{route} must fail with an OS access-denied result, not command-not-found or \
         a missing path; status={:?} stdout={} stderr={}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).trim(),
        String::from_utf8_lossy(&out.stderr).trim()
    );
}

#[test]
fn junction_escape_denies_outside_read_and_write() {
    if skip_proof_unless_appcontainer() {
        return;
    }

    let workspace = fresh_dir("junction-ws");
    let outside = fresh_dir("junction-out");
    let junction = workspace.join("escape");
    create_junction(&junction, &outside);

    let secret = outside.join("secret.txt");
    std::fs::write(&secret, SECRET).expect("seed outside secret");
    let via_junction_secret = junction.join("secret.txt");
    assert_eq!(
        std::fs::read_to_string(&via_junction_secret).expect("host positive-control read"),
        SECRET,
        "host positive control must prove the junction reaches the outside file"
    );

    let read = launch(&[
        "--name",
        &tag("jr"),
        "--fs-read",
        &workspace.to_string_lossy(),
        "cmd.exe",
        "/c",
        "type",
        &via_junction_secret.to_string_lossy(),
    ]);
    assert!(
        !String::from_utf8_lossy(&read.stdout).contains(SECRET),
        "AppContainer must deny reading outside via junction; stdout={} stderr={}",
        String::from_utf8_lossy(&read.stdout).trim(),
        String::from_utf8_lossy(&read.stderr).trim()
    );

    let marker = outside.join("marker.txt");
    std::fs::write(&marker, ORIG).expect("seed outside marker");
    let via_junction_marker = junction.join("marker.txt");
    let write = launch(&[
        "--name",
        &tag("jw"),
        "--fs-write",
        &workspace.to_string_lossy(),
        "cmd.exe",
        "/c",
        "echo",
        WRITTEN,
        ">",
        &via_junction_marker.to_string_lossy(),
    ]);
    let marker_text = std::fs::read_to_string(&marker).expect("read outside marker");
    assert!(
        marker_text.contains(ORIG) && !marker_text.contains(WRITTEN),
        "AppContainer must deny writing outside via junction; marker={marker_text:?}; \
         stdout={} stderr={}",
        String::from_utf8_lossy(&write.stdout).trim(),
        String::from_utf8_lossy(&write.stderr).trim()
    );

    cleanup_junction(&junction);
    let _ = std::fs::remove_dir_all(&workspace);
    let _ = std::fs::remove_dir_all(&outside);
}

#[test]
fn profile_read_and_write_are_denied_by_os_policy() {
    if skip_proof_unless_appcontainer() {
        return;
    }

    let profile = std::env::var_os("USERPROFILE")
        .map(PathBuf::from)
        .expect("Windows proof requires USERPROFILE");
    let outside = profile.join(format!("ab-fsadv-profile-{}", tag("profile")));
    std::fs::create_dir_all(&outside).expect("create profile proof dir");
    let secret = outside.join("secret.txt");
    let marker = outside.join("marker.txt");
    std::fs::write(&secret, SECRET).expect("seed profile secret");
    std::fs::write(&marker, ORIG).expect("seed profile marker");
    assert_eq!(
        std::fs::read_to_string(&secret).expect("host profile positive-control read"),
        SECRET
    );

    let read = launch(&[
        "--name",
        &tag("profile-read"),
        "cmd.exe",
        "/c",
        "type",
        &secret.to_string_lossy(),
    ]);
    assert!(
        !String::from_utf8_lossy(&read.stdout).contains(SECRET),
        "profile secret must not leak; stdout={} stderr={}",
        String::from_utf8_lossy(&read.stdout).trim(),
        String::from_utf8_lossy(&read.stderr).trim()
    );
    assert_access_denied(&read, "profile read");

    let write = launch(&[
        "--name",
        &tag("profile-write"),
        "cmd.exe",
        "/c",
        "echo",
        WRITTEN,
        ">",
        &marker.to_string_lossy(),
    ]);
    let marker_text = std::fs::read_to_string(&marker).expect("read profile marker");
    assert!(
        marker_text.contains(ORIG) && !marker_text.contains(WRITTEN),
        "profile marker must not be modified; marker={marker_text:?}; stdout={} stderr={}",
        String::from_utf8_lossy(&write.stdout).trim(),
        String::from_utf8_lossy(&write.stderr).trim()
    );
    assert_access_denied(&write, "profile write");

    let _ = std::fs::remove_dir_all(&outside);
}

#[test]
fn parent_normalization_cannot_escape_workspace_to_sibling() {
    if skip_proof_unless_appcontainer() {
        return;
    }

    let root = fresh_dir("normalize-root");
    let workspace = root.join("workspace");
    let sibling = root.join("sibling");
    std::fs::create_dir_all(&workspace).expect("create workspace");
    std::fs::create_dir_all(&sibling).expect("create sibling");
    let secret = sibling.join("secret.txt");
    let marker = sibling.join("marker.txt");
    std::fs::write(&secret, SECRET).expect("seed sibling secret");
    std::fs::write(&marker, ORIG).expect("seed sibling marker");

    let via_parent_secret = workspace.join("..").join("sibling").join("secret.txt");
    let via_parent_marker = workspace.join("..").join("sibling").join("marker.txt");
    assert_eq!(
        std::fs::read_to_string(&via_parent_secret)
            .expect("host positive-control parent-normalized read"),
        SECRET
    );

    let read = launch(&[
        "--name",
        &tag("norm-read"),
        "--fs-read",
        &workspace.to_string_lossy(),
        "cmd.exe",
        "/c",
        "type",
        &via_parent_secret.to_string_lossy(),
    ]);
    assert!(
        !String::from_utf8_lossy(&read.stdout).contains(SECRET),
        "AppContainer must deny sibling read through .. normalization; stdout={} stderr={}",
        String::from_utf8_lossy(&read.stdout).trim(),
        String::from_utf8_lossy(&read.stderr).trim()
    );
    assert_access_denied(&read, "parent-normalized sibling read");

    let write = launch(&[
        "--name",
        &tag("norm-write"),
        "--fs-write",
        &workspace.to_string_lossy(),
        "cmd.exe",
        "/c",
        "echo",
        WRITTEN,
        ">",
        &via_parent_marker.to_string_lossy(),
    ]);
    let marker_text = std::fs::read_to_string(&marker).expect("read sibling marker");
    assert!(
        marker_text.contains(ORIG) && !marker_text.contains(WRITTEN),
        "AppContainer must deny sibling write through .. normalization; marker={marker_text:?}; \
         stdout={} stderr={}",
        String::from_utf8_lossy(&write.stdout).trim(),
        String::from_utf8_lossy(&write.stderr).trim()
    );
    assert_access_denied(&write, "parent-normalized sibling write");

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn dacl_grant_is_removed_after_normal_exit_and_forced_failure() {
    if skip_proof_unless_appcontainer() {
        return;
    }

    let workspace = fresh_dir("restore");
    let secret = workspace.join("secret.txt");
    std::fs::write(&secret, SECRET).expect("seed secret");
    let profile = tag("restore-profile");

    let allowed = launch(&[
        "--name",
        &profile,
        "--fs-read",
        &workspace.to_string_lossy(),
        "cmd.exe",
        "/c",
        "type",
        &secret.to_string_lossy(),
    ]);
    assert!(
        String::from_utf8_lossy(&allowed.stdout).contains(SECRET),
        "positive control: read grant must allow the secret; stdout={} stderr={}",
        String::from_utf8_lossy(&allowed.stdout).trim(),
        String::from_utf8_lossy(&allowed.stderr).trim()
    );

    let denied_after_normal = launch(&[
        "--name",
        &profile,
        "cmd.exe",
        "/c",
        "type",
        &secret.to_string_lossy(),
    ]);
    assert!(
        !String::from_utf8_lossy(&denied_after_normal.stdout).contains(SECRET),
        "DACL grant must be restored after normal exit; stdout={} stderr={}",
        String::from_utf8_lossy(&denied_after_normal.stdout).trim(),
        String::from_utf8_lossy(&denied_after_normal.stderr).trim()
    );

    let forced_profile = tag("restore-forced-profile");
    let forced = launch(&[
        "--name",
        &forced_profile,
        "--fs-read",
        &workspace.to_string_lossy(),
        "--test-force-process-attribute-failure",
        "cmd.exe",
        "/c",
        "echo",
        "SHOULD_NOT_RUN",
    ]);
    assert!(
        !forced.status.success(),
        "forced failure must fail before spawn"
    );

    let denied_after_failure = launch(&[
        "--name",
        &forced_profile,
        "cmd.exe",
        "/c",
        "type",
        &secret.to_string_lossy(),
    ]);
    assert!(
        !String::from_utf8_lossy(&denied_after_failure.stdout).contains(SECRET),
        "DACL grant must be restored after process-attribute failure; stdout={} stderr={}",
        String::from_utf8_lossy(&denied_after_failure.stdout).trim(),
        String::from_utf8_lossy(&denied_after_failure.stderr).trim()
    );

    let _ = std::fs::remove_dir_all(&workspace);
}

#[test]
fn concurrent_children_do_not_gain_each_others_workspace_grants() {
    if skip_proof_unless_appcontainer() {
        return;
    }

    let left = fresh_dir("concurrent-left");
    let right = fresh_dir("concurrent-right");
    let left_own = left.join("own.txt");
    let left_cross = left.join("cross.txt");
    let right_own = right.join("own.txt");
    let right_cross = right.join("cross.txt");
    for p in [&left_own, &left_cross, &right_own, &right_cross] {
        std::fs::write(p, ORIG).expect("seed marker");
    }

    let left_args = vec![
        "--name".to_string(),
        tag("concurrent-left"),
        "--fs-write".to_string(),
        left.to_string_lossy().into_owned(),
        "cmd.exe".to_string(),
        "/c".to_string(),
        "echo".to_string(),
        WRITTEN.to_string(),
        ">".to_string(),
        left_own.to_string_lossy().into_owned(),
        "&".to_string(),
        "echo".to_string(),
        WRITTEN.to_string(),
        ">".to_string(),
        right_cross.to_string_lossy().into_owned(),
    ];
    let right_args = vec![
        "--name".to_string(),
        tag("concurrent-right"),
        "--fs-write".to_string(),
        right.to_string_lossy().into_owned(),
        "cmd.exe".to_string(),
        "/c".to_string(),
        "echo".to_string(),
        WRITTEN.to_string(),
        ">".to_string(),
        right_own.to_string_lossy().into_owned(),
        "&".to_string(),
        "echo".to_string(),
        WRITTEN.to_string(),
        ">".to_string(),
        left_cross.to_string_lossy().into_owned(),
    ];

    let left_thread = std::thread::spawn(move || {
        Command::new(LAUNCHER)
            .args(left_args)
            .current_dir("C:\\Windows")
            .output()
            .expect("spawn left launcher")
    });
    let right_thread = std::thread::spawn(move || {
        Command::new(LAUNCHER)
            .args(right_args)
            .current_dir("C:\\Windows")
            .output()
            .expect("spawn right launcher")
    });
    let left_out = left_thread.join().expect("left thread");
    let right_out = right_thread.join().expect("right thread");

    assert!(
        std::fs::read_to_string(&left_own)
            .unwrap()
            .contains(WRITTEN),
        "left child must retain its own grant; status={:?} stderr={}",
        left_out.status.code(),
        String::from_utf8_lossy(&left_out.stderr).trim()
    );
    assert!(
        std::fs::read_to_string(&right_own)
            .unwrap()
            .contains(WRITTEN),
        "right child must retain its own grant; status={:?} stderr={}",
        right_out.status.code(),
        String::from_utf8_lossy(&right_out.stderr).trim()
    );
    assert_eq!(std::fs::read_to_string(&left_cross).unwrap(), ORIG);
    assert_eq!(std::fs::read_to_string(&right_cross).unwrap(), ORIG);

    let _ = std::fs::remove_dir_all(&left);
    let _ = std::fs::remove_dir_all(&right);
}

#[test]
fn overlapping_children_on_same_resource_keep_live_grants_and_cleanup_exactly() {
    if skip_proof_unless_appcontainer() {
        return;
    }

    let workspace = fresh_dir("overlap-same-resource");
    let a_start = workspace.join("a-start.txt");
    let a_done = workspace.join("a-done.txt");
    let b_start = workspace.join("b-start.txt");
    let b_after_a = workspace.join("b-after-a.txt");
    let a_resurrected = workspace.join("a-resurrected.txt");
    let b_resurrected = workspace.join("b-resurrected.txt");
    let profile_a = tag("overlap-a");
    let profile_b = tag("overlap-b");

    let mut a = Command::new(LAUNCHER)
        .args([
            "--name",
            &profile_a,
            "--fs-write",
            &workspace.to_string_lossy(),
            FSPROBE,
            "write-sleep-write",
            &a_start.to_string_lossy(),
            "A_START",
            "1000",
            &a_done.to_string_lossy(),
            "A_DONE",
        ])
        .current_dir("C:\\Windows")
        .spawn()
        .expect("spawn overlapping child A");
    wait_for_file(&a_start);

    let mut b = Command::new(LAUNCHER)
        .args([
            "--name",
            &profile_b,
            "--fs-write",
            &workspace.to_string_lossy(),
            FSPROBE,
            "write-sleep-write",
            &b_start.to_string_lossy(),
            "B_START",
            "2500",
            &b_after_a.to_string_lossy(),
            "B_AFTER_A",
        ])
        .current_dir("C:\\Windows")
        .spawn()
        .expect("spawn overlapping child B");
    wait_for_file(&b_start);

    let a_status = a.wait().expect("wait child A");
    assert!(a_status.success(), "child A should complete its own writes");
    let b_status = b.wait().expect("wait child B");
    assert!(
        b_status.success(),
        "child B must keep its still-live grant after child A cleans up"
    );
    assert_eq!(std::fs::read_to_string(&a_done).unwrap(), "A_DONE");
    assert_eq!(std::fs::read_to_string(&b_after_a).unwrap(), "B_AFTER_A");

    let a_after = launch_owned(vec![
        "--name".to_string(),
        profile_a,
        FSPROBE.to_string(),
        "write".to_string(),
        a_resurrected.to_string_lossy().into_owned(),
        "A_RESURRECTED".to_string(),
    ]);
    assert!(
        !a_after.status.success(),
        "child B cleanup must not resurrect child A's expired grant; stdout={} stderr={}",
        String::from_utf8_lossy(&a_after.stdout).trim(),
        String::from_utf8_lossy(&a_after.stderr).trim()
    );
    assert!(!a_resurrected.exists());

    let b_after = launch_owned(vec![
        "--name".to_string(),
        profile_b,
        FSPROBE.to_string(),
        "write".to_string(),
        b_resurrected.to_string_lossy().into_owned(),
        "B_RESURRECTED".to_string(),
    ]);
    assert!(
        !b_after.status.success(),
        "final cleanup must remove child B's expired grant; stdout={} stderr={}",
        String::from_utf8_lossy(&b_after.stdout).trim(),
        String::from_utf8_lossy(&b_after.stderr).trim()
    );
    assert!(!b_resurrected.exists());

    let _ = std::fs::remove_dir_all(&workspace);
}
