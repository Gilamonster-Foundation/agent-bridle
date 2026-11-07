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

    // #438: --fs-write also grants FILE_DELETE_CHILD. Cleanup must revoke it
    // too, or the same profile could still delete here after exit. The relaunch
    // holds --fs-read, which supplies the read rights a delete also needs, so a
    // leftover delete right is the only thing that could let it succeed.
    let doomed = workspace.join("doomed.txt");
    std::fs::write(&doomed, ORIG).expect("seed doomed file");
    let write_profile = tag("restore-write-profile");
    let deleted = launch(&[
        "--name",
        &write_profile,
        "--fs-write",
        &workspace.to_string_lossy(),
        FSPROBE,
        "remove",
        &doomed.to_string_lossy(),
    ]);
    assert!(
        !doomed.exists(),
        "positive control: the write grant must allow delete (#438); stdout={} stderr={}",
        String::from_utf8_lossy(&deleted.stdout).trim(),
        String::from_utf8_lossy(&deleted.stderr).trim()
    );
    let delete_after_normal = launch(&[
        "--name",
        &write_profile,
        "--fs-read",
        &workspace.to_string_lossy(),
        FSPROBE,
        "remove",
        &secret.to_string_lossy(),
    ]);
    assert_access_denied(
        &delete_after_normal,
        "delete after the write grant was revoked",
    );
    assert!(
        secret.exists(),
        "the write grant's delete right must be revoked after normal exit"
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

/// #438: under its `--fs-write` root the confined child can do Git's lock dance
/// in one process, inside a `.git` the PARENT created before launch (so the
/// grant must reach an existing subdirectory, as in #438's
/// `.git/index.lock`): create and write `index.lock`, rename it over a
/// parent-created `index`, delete another parent-created file, create and
/// delete its own, then remove a parent-created empty subdirectory (Git
/// pruning `objects/xx`). Git can't start in an AppContainer on the CI image
/// (#408), so `ab-fsprobe` plays its part. Fails without #438: the grant had no
/// delete right, so the rename was `Access is denied.` (and Git left a stale
/// lock).
#[test]
fn fs_write_root_allows_git_lock_dance() {
    if skip_proof_unless_appcontainer() {
        return;
    }

    let workspace = fresh_dir("lock-dance");
    let git = workspace.join(".git");
    let pruned = git.join("objects").join("ab");
    std::fs::create_dir_all(&pruned).expect("create parent-created .git/objects/ab");
    let index = git.join("index");
    let lock = git.join("index.lock");
    let stale = git.join("stale.txt");
    let own = git.join("own.txt");
    std::fs::write(&index, ORIG).expect("seed parent-created index");
    std::fs::write(&stale, ORIG).expect("seed parent-created stale file");

    let out = launch(&[
        "--name",
        &tag("lock-dance"),
        "--fs-write",
        &workspace.to_string_lossy(),
        FSPROBE,
        "write",
        &lock.to_string_lossy(),
        WRITTEN,
        ";",
        "rename",
        &lock.to_string_lossy(),
        &index.to_string_lossy(),
        ";",
        "remove",
        &stale.to_string_lossy(),
        ";",
        "write",
        &own.to_string_lossy(),
        WRITTEN,
        ";",
        "remove",
        &own.to_string_lossy(),
        ";",
        "rmdir",
        &pruned.to_string_lossy(),
    ]);
    assert!(
        out.status.success(),
        "the child must create, rename over, and delete files and remove a directory \
         under its --fs-write root; status={:?} stdout={} stderr={}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).trim(),
        String::from_utf8_lossy(&out.stderr).trim()
    );
    assert_eq!(
        std::fs::read_to_string(&index).expect("read index"),
        WRITTEN
    );
    assert!(
        !lock.exists() && !stale.exists() && !own.exists() && !pruned.exists(),
        "no lock, stale file, child-created file, or pruned directory may survive"
    );

    let _ = std::fs::remove_dir_all(&workspace);
}

/// #438: the delete right reaches everything UNDER an `--fs-write` root but not
/// the root itself (as with Landlock, where removing the root needs a right on
/// its parent). The child deletes the root's only file (the positive control,
/// which fails without #438) and then tries to remove the now-empty root, which
/// must be OS-denied. Moving the root needs the same right as removing it
/// (DELETE on it, or FILE_DELETE_CHILD on its parent), so this check also
/// covers rename.
#[test]
fn fs_write_root_itself_cannot_be_deleted() {
    if skip_proof_unless_appcontainer() {
        return;
    }

    let workspace = fresh_dir("delete-root");
    let inner = workspace.join("inner.txt");
    std::fs::write(&inner, ORIG).expect("seed inner file");

    let rmdir = launch(&[
        "--name",
        &tag("rmdir-root"),
        "--fs-write",
        &workspace.to_string_lossy(),
        FSPROBE,
        "remove",
        &inner.to_string_lossy(),
        ";",
        "rmdir",
        &workspace.to_string_lossy(),
    ]);
    assert!(
        !inner.exists(),
        "positive control: the child must delete a file under its --fs-write root; \
         stdout={} stderr={}",
        String::from_utf8_lossy(&rmdir.stdout).trim(),
        String::from_utf8_lossy(&rmdir.stderr).trim()
    );
    assert_access_denied(&rmdir, "rmdir of the --fs-write root");
    assert!(workspace.is_dir(), "the --fs-write root must survive");

    let _ = std::fs::remove_dir_all(&workspace);
}

/// #438: the delete right comes only with `--fs-write`. One child holds a write
/// root and a read root: deleting under the write root succeeds (the positive
/// control, which fails without #438) and deleting under the read root is
/// OS-denied.
#[test]
fn fs_read_root_still_denies_delete() {
    if skip_proof_unless_appcontainer() {
        return;
    }

    let write_root = fresh_dir("delete-w");
    let read_root = fresh_dir("delete-r");
    let w_file = write_root.join("w.txt");
    let r_file = read_root.join("r.txt");
    std::fs::write(&w_file, ORIG).expect("seed write-root file");
    std::fs::write(&r_file, ORIG).expect("seed read-root file");

    let out = launch(&[
        "--name",
        &tag("delete-read"),
        "--fs-write",
        &write_root.to_string_lossy(),
        "--fs-read",
        &read_root.to_string_lossy(),
        FSPROBE,
        "remove",
        &w_file.to_string_lossy(),
        ";",
        "remove",
        &r_file.to_string_lossy(),
    ]);
    assert!(
        !w_file.exists(),
        "positive control: the child must delete under its --fs-write root; \
         stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout).trim(),
        String::from_utf8_lossy(&out.stderr).trim()
    );
    assert_access_denied(&out, "delete under an --fs-read root");
    assert!(r_file.exists(), "an --fs-read root must not confer delete");

    let _ = std::fs::remove_dir_all(&write_root);
    let _ = std::fs::remove_dir_all(&read_root);
}

/// #438: the delete right follows the directory entry, not the file. The parent
/// hard-links `<root>\link.txt` to `<outside>\secret.txt` before launch, so both
/// names share one file record and so one security descriptor. The child
/// deletes a file under its root (the positive control) but must not delete the
/// outside name, which a DELETE right on the record would allow.
#[test]
fn fs_write_delete_does_not_follow_a_hard_link_out_of_the_root() {
    if skip_proof_unless_appcontainer() {
        return;
    }

    let workspace = fresh_dir("hardlink-ws");
    let outside = fresh_dir("hardlink-out");
    let own = workspace.join("own.txt");
    let secret = outside.join("secret.txt");
    std::fs::write(&own, ORIG).expect("seed own file");
    std::fs::write(&secret, SECRET).expect("seed outside secret");
    std::fs::hard_link(&secret, workspace.join("link.txt")).expect("hard-link secret into root");

    let out = launch(&[
        "--name",
        &tag("hardlink"),
        "--fs-write",
        &workspace.to_string_lossy(),
        FSPROBE,
        "remove",
        &own.to_string_lossy(),
        ";",
        "remove",
        &secret.to_string_lossy(),
    ]);
    assert!(
        !own.exists(),
        "positive control: the child must delete under its --fs-write root; \
         stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout).trim(),
        String::from_utf8_lossy(&out.stderr).trim()
    );
    assert_access_denied(&out, "delete of a hard link's name outside the root");
    assert!(secret.exists(), "the outside name must survive");

    let _ = std::fs::remove_dir_all(&workspace);
    let _ = std::fs::remove_dir_all(&outside);
}

/// #438: the child may rename anything under its `--fs-write` root, including
/// a path the launcher was also asked to grant (`--fs-read <root>\ro.txt`).
/// That path must carry no ACE of its own: cleanup revokes by name, so an ACE
/// the child moved to a new name would outlive it. After the child renames
/// `ro.txt`, a relaunch of the same profile must be denied at the new name.
#[test]
fn renamed_nested_grant_leaves_no_ace_behind() {
    if skip_proof_unless_appcontainer() {
        return;
    }

    let workspace = fresh_dir("nested-ws");
    let ro = workspace.join("ro.txt");
    let moved = workspace.join("moved.txt");
    std::fs::write(&ro, SECRET).expect("seed nested grant");
    let profile = tag("nested");

    let out = launch(&[
        "--name",
        &profile,
        "--fs-write",
        &workspace.to_string_lossy(),
        "--fs-read",
        &ro.to_string_lossy(),
        FSPROBE,
        "rename",
        &ro.to_string_lossy(),
        &moved.to_string_lossy(),
    ]);
    assert!(
        moved.exists() && !ro.exists(),
        "positive control: the child must rename a file under its --fs-write root; \
         stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout).trim(),
        String::from_utf8_lossy(&out.stderr).trim()
    );

    let after = launch(&[
        "--name",
        &profile,
        "cmd.exe",
        "/c",
        "type",
        &moved.to_string_lossy(),
    ]);
    assert!(
        !String::from_utf8_lossy(&after.stdout).contains(SECRET),
        "no ACE may survive at the renamed path; stdout={} stderr={}",
        String::from_utf8_lossy(&after.stdout).trim(),
        String::from_utf8_lossy(&after.stderr).trim()
    );
    assert_access_denied(&after, "read of the renamed nested grant after exit");

    let _ = std::fs::remove_dir_all(&workspace);
}
