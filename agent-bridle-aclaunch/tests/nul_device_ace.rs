//! Native proof for the opt-in AppContainer `\\.\NUL` device ACE (#408).
//!
//! This test is deliberately strict on the Server CI runner: without the
//! explicit flag Git for Windows must retain its documented NUL-open failure;
//! with it, a per-profile SID receives exactly one non-inheriting
//! `FILE_GENERIC_READ | FILE_GENERIC_WRITE` ACE for the lifetime of that
//! launch. The test reads the device DACL directly rather than treating a
//! successful child as sufficient evidence of cleanup or overlap safety.

#![cfg(target_os = "windows")]

use std::ffi::{c_void, OsStr};
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{
    CloseHandle, LocalFree, ERROR_SUCCESS, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::Authorization::{
    GetNamedSecurityInfoW, GetSecurityInfo, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::Isolation::{
    DeleteAppContainerProfile, DeriveAppContainerSidFromAppContainerName,
};
use windows_sys::Win32::Security::{
    EqualSid, FreeSid, GetAce, ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, DACL_SECURITY_INFORMATION,
    NO_INHERITANCE, PSID,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING, READ_CONTROL,
};
use windows_sys::Win32::System::SystemServices::ACCESS_ALLOWED_ACE_TYPE;

const LAUNCHER: &str = env!("CARGO_BIN_EXE_agent-bridle-aclaunch");
const FSPROBE: &str = env!("CARGO_BIN_EXE_ab-fsprobe");
const NUL_ACCESS: u32 = 0x0012_0089 | 0x0012_0116; // FILE_GENERIC_READ | FILE_GENERIC_WRITE

static N: AtomicU64 = AtomicU64::new(0);

fn tag(kind: &str) -> String {
    format!(
        "{kind}-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    )
}

fn to_wide(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(std::iter::once(0)).collect()
}

fn launch(args: &[&str]) -> Output {
    Command::new(LAUNCHER)
        .args(args)
        .current_dir("C:\\Windows")
        .output()
        .expect("spawn agent-bridle-aclaunch")
}

fn appcontainer_available() -> bool {
    launch(&["--name", &tag("probe"), "cmd.exe", "/c", "exit", "0"])
        .status
        .success()
}

fn required(name: &str) -> bool {
    std::env::var(name)
        .map(|value| !value.is_empty() && value != "0")
        .unwrap_or(false)
}

fn skip_unless_appcontainer() -> bool {
    if appcontainer_available() {
        return false;
    }
    if required("BRIDLE_REQUIRE_APPCONTAINER") {
        panic!("BRIDLE_REQUIRE_APPCONTAINER is set but an AppContainer could not be created");
    }
    eprintln!("skipping NUL-device ACE proof: cannot create an AppContainer here");
    true
}

fn elevated() -> bool {
    Command::new("net")
        .args(["session"])
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

fn skip_unless_nul_dacl_writable() -> bool {
    if elevated() {
        return false;
    }
    if required("BRIDLE_REQUIRE_ELEVATED") || required("BRIDLE_REQUIRE_NATIVE_GIT") {
        panic!(
            "the strict NUL-device ACE proof requires an elevated token with WRITE_DAC on \\\\.\\NUL"
        );
    }
    eprintln!("skipping NUL-device ACE mutation proof: not elevated (needs WRITE_DAC)");
    true
}

fn derive_sid(name: &str) -> PSID {
    let name = to_wide(OsStr::new(name));
    let mut sid: PSID = std::ptr::null_mut();
    let hr = unsafe { DeriveAppContainerSidFromAppContainerName(name.as_ptr(), &mut sid) };
    assert_eq!(
        hr, 0,
        "DeriveAppContainerSidFromAppContainerName failed for {name:?}: HRESULT={hr:#010x}"
    );
    assert!(!sid.is_null(), "derived AppContainer SID must not be null");
    sid
}

/// Return every explicit access-allowed ACE for `sid` on the NUL device.
/// The direct DACL read is the cleanup/overlap oracle; `NUL` must be opened by
/// handle because the named-security APIs do not work for this device object.
fn nul_access_aces(sid: PSID) -> Vec<(u32, u8)> {
    let device = to_wide(OsStr::new(r"\\.\NUL"));
    unsafe {
        let handle: HANDLE = CreateFileW(
            device.as_ptr(),
            READ_CONTROL,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            std::ptr::null(),
            OPEN_EXISTING,
            0,
            std::ptr::null_mut(),
        );
        assert_ne!(
            handle,
            INVALID_HANDLE_VALUE,
            "open \\\\.\\NUL with READ_CONTROL for DACL assertion: {:?}",
            std::io::Error::last_os_error()
        );

        let mut dacl: *mut ACL = std::ptr::null_mut();
        let mut descriptor: *mut c_void = std::ptr::null_mut();
        let result = GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut dacl,
            std::ptr::null_mut(),
            &mut descriptor,
        );
        assert_eq!(
            result, ERROR_SUCCESS,
            "GetSecurityInfo(\\\\.\\NUL) failed: {result}"
        );
        assert!(
            !dacl.is_null(),
            "NUL must have an explicit DACL for this proof"
        );

        let mut matches = Vec::new();
        for index in 0..u32::from((*dacl).AceCount) {
            let mut raw: *mut c_void = std::ptr::null_mut();
            assert_ne!(GetAce(dacl, index, &mut raw), 0, "GetAce({index}) failed");
            let header = &*raw.cast::<ACE_HEADER>();
            if u32::from(header.AceType) != ACCESS_ALLOWED_ACE_TYPE {
                continue;
            }
            let ace = &*(raw.cast::<ACCESS_ALLOWED_ACE>());
            let ace_sid = std::ptr::addr_of!(ace.SidStart).cast_mut().cast::<c_void>();
            if EqualSid(ace_sid, sid) != 0 {
                matches.push((ace.Mask, ace.Header.AceFlags));
            }
        }

        LocalFree(descriptor);
        CloseHandle(handle);
        matches
    }
}

fn assert_exact_nul_ace(sid: PSID, context: &str) {
    assert_eq!(
        nul_access_aces(sid),
        vec![(NUL_ACCESS, NO_INHERITANCE as u8)],
        "{context}: NUL must have one non-inheriting FILE_GENERIC_READ | FILE_GENERIC_WRITE ACE for this launch SID"
    );
}

fn assert_no_nul_ace(sid: PSID, context: &str) {
    assert!(
        nul_access_aces(sid).is_empty(),
        "{context}: the per-launch NUL ACE must be gone"
    );
}

/// The reused-profile refusal must occur before *any* filesystem DACL grant.
/// This separate oracle guards against an early `process::exit` that would leak
/// a requested second launch's SID ACE onto a caller-owned path.
fn path_has_access_allowed_ace_for_sid(path: &Path, sid: PSID) -> bool {
    let path = to_wide(path.as_os_str());
    unsafe {
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let mut descriptor: *mut c_void = std::ptr::null_mut();
        let result = GetNamedSecurityInfoW(
            path.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut dacl,
            std::ptr::null_mut(),
            &mut descriptor,
        );
        assert_eq!(
            result, ERROR_SUCCESS,
            "GetNamedSecurityInfoW({path:?}) failed: {result}"
        );

        let mut found = false;
        if !dacl.is_null() {
            for index in 0..u32::from((*dacl).AceCount) {
                let mut raw: *mut c_void = std::ptr::null_mut();
                assert_ne!(GetAce(dacl, index, &mut raw), 0, "GetAce({index}) failed");
                let header = &*raw.cast::<ACE_HEADER>();
                if u32::from(header.AceType) == ACCESS_ALLOWED_ACE_TYPE {
                    let ace = &*raw.cast::<ACCESS_ALLOWED_ACE>();
                    let ace_sid = std::ptr::addr_of!(ace.SidStart).cast_mut().cast::<c_void>();
                    if EqualSid(ace_sid, sid) != 0 {
                        found = true;
                        break;
                    }
                }
            }
        }
        LocalFree(descriptor);
        found
    }
}

fn native_git() -> Result<PathBuf, String> {
    let exec_path = Command::new("git")
        .arg("--exec-path")
        .output()
        .map_err(|error| format!("host Git is unavailable: {error}"))?;
    if !exec_path.status.success() {
        return Err(format!(
            "host `git --exec-path` failed: status={:?}, stderr={}",
            exec_path.status.code(),
            String::from_utf8_lossy(&exec_path.stderr).trim()
        ));
    }
    let exec_path = String::from_utf8(exec_path.stdout)
        .map_err(|error| format!("host `git --exec-path` was not UTF-8: {error}"))?;
    let git = PathBuf::from(exec_path.trim()).join("git.exe");
    if !git.is_file() {
        return Err(format!("Git executable {git:?} does not exist"));
    }
    let version = Command::new(&git)
        .arg("--version")
        .output()
        .map_err(|error| format!("run {git:?} --version: {error}"))?;
    if !version.status.success() || !String::from_utf8_lossy(&version.stdout).contains(".windows.")
    {
        return Err(format!(
            "{git:?} is not a working Git-for-Windows executable: status={:?}, stdout={}, stderr={}",
            version.status.code(),
            String::from_utf8_lossy(&version.stdout).trim(),
            String::from_utf8_lossy(&version.stderr).trim()
        ));
    }
    Ok(git)
}

/// The local desktop runner is a non-interactive Session 0 service station.
/// Git for Windows loads `user32.dll` during process initialization there and
/// exits with `STATUS_DLL_INIT_FAILED` before it reaches its NUL open.  Keep
/// this exception deliberately narrow: the strict Windows CI gate requires
/// native Git and therefore treats it as a failure instead of a skip.
fn skip_known_session_zero_git_loader_failure(output: &Output) -> bool {
    const STATUS_DLL_INIT_FAILED: i32 = -1_073_741_502; // 0xC0000142

    if output.status.code() != Some(STATUS_DLL_INIT_FAILED) {
        return false;
    }
    if required("BRIDLE_REQUIRE_NATIVE_GIT") {
        panic!(
            "BRIDLE_REQUIRE_NATIVE_GIT is set but Git-for-Windows failed to initialize \
             before its NUL open (STATUS_DLL_INIT_FAILED); stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout).trim(),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    eprintln!(
        "skipping native Git NUL proof only for the known Session 0 \
         STATUS_DLL_INIT_FAILED (0xC0000142); CI sets BRIDLE_REQUIRE_NATIVE_GIT=1"
    );
    true
}

fn configure_hermetic_git(command: &mut Command, safe_directory: Option<&Path>) {
    command
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_SYSTEM", "NUL")
        .env("GIT_CONFIG_GLOBAL", "NUL")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("HOME", "C:\\Windows")
        .env_remove("GIT_CONFIG_PARAMETERS")
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE");
    if let Some(path) = safe_directory {
        let canonical = path.canonicalize().expect("canonicalize safe.directory");
        command
            .env("GIT_CONFIG_COUNT", "1")
            .env("GIT_CONFIG_KEY_0", "safe.directory")
            .env("GIT_CONFIG_VALUE_0", canonical);
    } else {
        command.env("GIT_CONFIG_COUNT", "0");
    }
}

struct GitFixture {
    root: PathBuf,
    repo: PathBuf,
}

/// Test-only owner for the intentionally retained profile used to model a NUL
/// cleanup failure. The simulated path never mutates the host device DACL, so
/// deleting this profile in teardown cannot reactivate a residual ACE.
struct RetainedProfileCleanup {
    name: String,
}

impl Drop for RetainedProfileCleanup {
    fn drop(&mut self) {
        let name = to_wide(OsStr::new(&self.name));
        let hr = unsafe { DeleteAppContainerProfile(name.as_ptr()) };
        if hr != 0 {
            eprintln!(
                "test cleanup: DeleteAppContainerProfile({:?}) failed: HRESULT={hr:#010x}",
                self.name
            );
        }
    }
}

impl Drop for GitFixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn git_fixture(git: &Path) -> GitFixture {
    let mut root = std::env::temp_dir();
    root.push(format!("ab-nul-device-{}", tag("git")));
    std::fs::create_dir_all(&root).expect("create Git fixture root");
    let low = Command::new("icacls")
        .arg(&root)
        .args(["/setintegritylevel", "(OI)(CI)Low"])
        .output()
        .expect("lower fixture integrity");
    assert!(
        low.status.success(),
        "Git fixture must use Low integrity: stdout={} stderr={}",
        String::from_utf8_lossy(&low.stdout).trim(),
        String::from_utf8_lossy(&low.stderr).trim()
    );
    let repo = root.join("repo");
    let mut init = Command::new(git);
    configure_hermetic_git(&mut init, None);
    let output = init
        .args(["init", "--quiet"])
        .arg(&repo)
        .output()
        .expect("initialize Git fixture");
    assert!(
        output.status.success(),
        "Git fixture initialization failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout).trim(),
        String::from_utf8_lossy(&output.stderr).trim()
    );
    GitFixture { root, repo }
}

fn run_confined_git(git: &Path, name: &str, grant_nul: bool, repo: Option<&Path>) -> Output {
    let mut command = Command::new(LAUNCHER);
    command.arg("--name").arg(name);
    if grant_nul {
        command.arg("--nul-device-ace");
    }
    if let Some(repo) = repo {
        command.arg("--fs-write").arg(repo);
    }
    command.arg(git);
    if let Some(repo) = repo {
        command.arg("-C").arg(repo).args(["status", "--porcelain"]);
    } else {
        command.arg("--version");
    }
    configure_hermetic_git(&mut command, repo);
    command
        .current_dir("C:\\Windows")
        .output()
        .expect("run Git through agent-bridle-aclaunch")
}

fn wait_for_file(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(12);
    while Instant::now() < deadline {
        if path.exists() {
            return;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    panic!("timed out waiting for {path:?}");
}

fn fresh_low_workspace(kind: &str) -> PathBuf {
    let mut workspace = std::env::temp_dir();
    workspace.push(format!("ab-nul-device-{}", tag(kind)));
    std::fs::create_dir_all(&workspace).expect("create NUL-device workspace");
    let low = Command::new("icacls")
        .arg(&workspace)
        .args(["/setintegritylevel", "(OI)(CI)Low"])
        .output()
        .expect("lower NUL-device workspace integrity");
    assert!(
        low.status.success(),
        "set Low integrity for NUL-device workspace: stdout={} stderr={}",
        String::from_utf8_lossy(&low.stdout).trim(),
        String::from_utf8_lossy(&low.stderr).trim()
    );
    workspace
}

fn launch_holding_child(
    name: &str,
    workspace: &Path,
    start: &Path,
    end: &Path,
    sleep_ms: &str,
    grant_nul: bool,
) -> Child {
    let mut args = vec!["--name".to_string(), name.to_string()];
    if grant_nul {
        args.push("--nul-device-ace".to_string());
    }
    args.extend([
        "--fs-write".to_string(),
        workspace.to_string_lossy().into_owned(),
        FSPROBE.to_string(),
        "write-sleep-write".to_string(),
        start.to_string_lossy().into_owned(),
        "ready".to_string(),
        sleep_ms.to_string(),
        end.to_string_lossy().into_owned(),
        "done".to_string(),
    ]);
    Command::new(LAUNCHER)
        .args(args)
        .current_dir("C:\\Windows")
        .spawn()
        .expect("spawn holding AppContainer child")
}

#[test]
fn native_git_needs_the_opt_in_nul_ace_and_cleanup_removes_it() {
    if skip_unless_appcontainer() || skip_unless_nul_dacl_writable() {
        return;
    }
    let git = match native_git() {
        Ok(git) => git,
        Err(reason) if !required("BRIDLE_REQUIRE_NATIVE_GIT") => {
            eprintln!("skipping NUL-device native Git proof: {reason}");
            return;
        }
        Err(reason) => panic!("BRIDLE_REQUIRE_NATIVE_GIT is set but {reason}"),
    };

    let denied_name = tag("git-no-nul");
    let denied = run_confined_git(&git, &denied_name, false, None);
    if denied.status.success() {
        if required("BRIDLE_REQUIRE_NATIVE_GIT") {
            panic!(
                "Windows Server CI must retain the no-grant Git NUL denial; stdout={} stderr={}",
                String::from_utf8_lossy(&denied.stdout).trim(),
                String::from_utf8_lossy(&denied.stderr).trim()
            );
        }
        eprintln!(
            "skipping Server-specific NUL denial assertion: this host permits NUL without the grant"
        );
        return;
    }
    if skip_known_session_zero_git_loader_failure(&denied) {
        return;
    }
    let denied_text = format!(
        "{}{}",
        String::from_utf8_lossy(&denied.stdout),
        String::from_utf8_lossy(&denied.stderr)
    );
    assert!(
        denied_text.contains("could not open '/dev/null' for reading and writing")
            && denied_text.contains("Permission denied"),
        "without --nul-device-ace Git must fail at its NUL open, not elsewhere; status={:?} stdout={} stderr={}",
        denied.status.code(),
        String::from_utf8_lossy(&denied.stdout).trim(),
        String::from_utf8_lossy(&denied.stderr).trim()
    );
    let denied_sid = derive_sid(&denied_name);
    assert_no_nul_ace(
        denied_sid,
        "default-off native Git failure must not add a NUL-device ACE",
    );
    unsafe { FreeSid(denied_sid) };

    let version_name = tag("git-with-nul-version");
    let version = run_confined_git(&git, &version_name, true, None);
    assert!(
        version.status.success()
            && String::from_utf8_lossy(&version.stdout).contains("git version"),
        "with --nul-device-ace Git --version must succeed; stdout={} stderr={}",
        String::from_utf8_lossy(&version.stdout).trim(),
        String::from_utf8_lossy(&version.stderr).trim()
    );
    let version_sid = derive_sid(&version_name);
    assert_no_nul_ace(version_sid, "normal git --version cleanup");
    unsafe { FreeSid(version_sid) };

    let fixture = git_fixture(&git);
    let status_name = tag("git-with-nul-status");
    let status = run_confined_git(&git, &status_name, true, Some(&fixture.repo));
    assert!(
        status.status.success(),
        "with --nul-device-ace hermetic git status must succeed; stdout={} stderr={}",
        String::from_utf8_lossy(&status.stdout).trim(),
        String::from_utf8_lossy(&status.stderr).trim()
    );
    let status_sid = derive_sid(&status_name);
    assert_no_nul_ace(status_sid, "normal hermetic git status cleanup");
    unsafe { FreeSid(status_sid) };
}

/// The NUL grant is deliberately installed after the process-attribute setup.
/// A real `CreateProcessW` error is therefore the one post-grant pre-child
/// failure path; it must remove the exact ACE before returning the error.
#[test]
fn create_process_failure_after_nul_grant_removes_the_exact_ace() {
    if skip_unless_appcontainer() || skip_unless_nul_dacl_writable() {
        return;
    }

    let name = tag("nul-create-process-failure");
    let missing_exe = format!(r"C:\\Windows\\ab-nul-missing-{}.exe", tag("exe"));
    let output = launch(&["--name", &name, "--nul-device-ace", &missing_exe]);
    assert!(
        !output.status.success(),
        "a nonexistent executable must reach and fail CreateProcessW"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("CreateProcessW"),
        "the failure must occur after the NUL grant point; stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout).trim(),
        String::from_utf8_lossy(&output.stderr).trim()
    );
    let sid = derive_sid(&name);
    assert_no_nul_ace(sid, "post-CreateProcessW failure cleanup");
    unsafe { FreeSid(sid) };
}

/// If a post-grant cleanup fails, deleting the profile would make its
/// deterministic SID reusable by a later launch. The launcher therefore keeps
/// the profile, preserving the launcher's existing no-reuse behavior. This seam
/// simulates that outcome without touching the host `\\.\NUL` DACL.
#[test]
fn nul_cleanup_failure_retains_the_profile_and_refuses_sid_reuse() {
    if skip_unless_appcontainer() {
        return;
    }

    let name = tag("nul-cleanup-retained-profile");
    let _cleanup = RetainedProfileCleanup { name: name.clone() };
    let first = launch(&[
        "--name",
        &name,
        "--nul-device-ace",
        "--test-force-nul-cleanup-failure",
        "cmd.exe",
        "/c",
        "exit",
        "0",
    ]);
    assert!(
        !first.status.success(),
        "a simulated NUL cleanup failure must make the launcher fail"
    );
    let first_stderr = String::from_utf8_lossy(&first.stderr);
    assert!(
        first_stderr.contains("forced NUL-device ACE cleanup failure"),
        "the test seam must exercise post-child cleanup: stderr={first_stderr}"
    );
    assert!(
        first_stderr.contains("retaining AppContainer profile"),
        "cleanup failure must preserve the profile as the SID-reuse guard: stderr={first_stderr}"
    );

    const REUSED_PROFILE_CHILD_STARTED: &str = "REUSED_PROFILE_CHILD_STARTED";
    let second = launch(&[
        "--name",
        &name,
        "cmd.exe",
        "/c",
        "echo",
        REUSED_PROFILE_CHILD_STARTED,
    ]);
    assert!(
        !second.status.success(),
        "an existing profile must be refused after a NUL cleanup failure"
    );
    assert!(
        !String::from_utf8_lossy(&second.stdout).contains(REUSED_PROFILE_CHILD_STARTED),
        "the reused-SID child must never start; stdout={} stderr={}",
        String::from_utf8_lossy(&second.stdout).trim(),
        String::from_utf8_lossy(&second.stderr).trim()
    );
    assert!(
        String::from_utf8_lossy(&second.stderr).contains("AppContainer SID is null"),
        "the retained profile must preserve the launcher's existing no-reuse refusal: stderr={}",
        String::from_utf8_lossy(&second.stderr).trim()
    );
}

/// `--nul-device-ace` is default-off. Keep the no-flag path's existing
/// same-name behavior intact: Windows supplies no SID for ERROR_ALREADY_EXISTS,
/// so the launcher must refuse before it can start a second child.
#[test]
fn no_nul_flag_preserves_existing_profile_refusal() {
    if skip_unless_appcontainer() {
        return;
    }

    let workspace = fresh_low_workspace("default-off-existing-profile");
    let name = tag("default-off-existing-profile");
    let start = workspace.join("first-start");
    let end = workspace.join("first-end");
    let mut first = launch_holding_child(&name, &workspace, &start, &end, "1500", false);
    wait_for_file(&start);

    const SECOND_CHILD_MARKER: &str = "DEFAULT_OFF_SECOND_CHILD_STARTED";
    let second = launch(&[
        "--name",
        &name,
        "cmd.exe",
        "/c",
        "echo",
        SECOND_CHILD_MARKER,
    ]);
    let first_status = first.wait().expect("wait first default-off launch");

    assert!(
        first_status.success(),
        "the first ordinary launch must still complete"
    );
    assert!(
        !second.status.success(),
        "the default path must preserve its existing same-name refusal"
    );
    assert!(
        !String::from_utf8_lossy(&second.stdout).contains(SECOND_CHILD_MARKER),
        "the second default-off child must never start; stdout={} stderr={}",
        String::from_utf8_lossy(&second.stdout).trim(),
        String::from_utf8_lossy(&second.stderr).trim()
    );
    assert!(
        String::from_utf8_lossy(&second.stderr).contains("AppContainer SID is null"),
        "the default path must retain its baseline error: stderr={}",
        String::from_utf8_lossy(&second.stderr).trim()
    );
    let _ = std::fs::remove_dir_all(&workspace);
}

/// A NUL-device grant is ownership-scoped to a fresh AppContainer SID.  The
/// launcher already refuses an existing name before child setup; the opt-in
/// preserves that rule rather than allowing two live launches to share one ACE
/// and race its cleanup.
#[test]
fn nul_device_ace_refuses_a_live_reused_profile_name_before_spawn() {
    if skip_unless_appcontainer() {
        return;
    }

    let workspace = fresh_low_workspace("same-name");
    let second_only_workspace = fresh_low_workspace("same-name-second-only");
    let name = tag("nul-same-name");
    let start = workspace.join("first-start");
    let end = workspace.join("first-end");
    let mut first = launch_holding_child(&name, &workspace, &start, &end, "8000", false);
    wait_for_file(&start);

    const CHILD_MARKER: &str = "SHOULD_NOT_START";
    let second = launch(&[
        "--name",
        &name,
        "--nul-device-ace",
        "--fs-write",
        &second_only_workspace.to_string_lossy(),
        "cmd.exe",
        "/c",
        "echo",
        CHILD_MARKER,
    ]);
    assert!(
        !second.status.success(),
        "the NUL-device opt-in must reject a live name whose SID is already in use"
    );
    assert!(
        !String::from_utf8_lossy(&second.stdout).contains(CHILD_MARKER),
        "the duplicate-SID child must not start; stdout={} stderr={}",
        String::from_utf8_lossy(&second.stdout).trim(),
        String::from_utf8_lossy(&second.stderr).trim()
    );
    assert!(
        String::from_utf8_lossy(&second.stderr).contains("requires a fresh unique --name"),
        "the duplicate-SID refusal must explain why; stderr={}",
        String::from_utf8_lossy(&second.stderr).trim()
    );
    let sid = derive_sid(&name);
    assert!(
        !path_has_access_allowed_ace_for_sid(&second_only_workspace, sid),
        "the duplicate-SID refusal must occur before a second launch can add an fs ACE"
    );

    let first_status = first.wait().expect("wait first same-name launch");
    assert!(
        first_status.success(),
        "the first normal launch must still complete"
    );
    unsafe { FreeSid(sid) };
    let _ = std::fs::remove_dir_all(&workspace);
    let _ = std::fs::remove_dir_all(&second_only_workspace);
}

#[test]
fn overlapping_nul_grants_keep_the_other_live_sid_and_remove_only_their_own_ace() {
    if skip_unless_appcontainer() || skip_unless_nul_dacl_writable() {
        return;
    }

    let workspace = fresh_low_workspace("overlap");

    let a_name = tag("nul-overlap-a");
    let b_name = tag("nul-overlap-b");
    let a_start = workspace.join("a-start");
    let a_end = workspace.join("a-end");
    let b_start = workspace.join("b-start");
    let b_end = workspace.join("b-end");
    // The sleep bounds work; readiness is the file signal. B deliberately lasts
    // much longer than A so the post-A DACL read observes B's still-live grant.
    let mut a = launch_holding_child(&a_name, &workspace, &a_start, &a_end, "4000", true);
    wait_for_file(&a_start);
    let a_sid = derive_sid(&a_name);
    assert_exact_nul_ace(a_sid, "while launch A is live");

    let mut b = launch_holding_child(&b_name, &workspace, &b_start, &b_end, "9000", true);
    wait_for_file(&b_start);
    let b_sid = derive_sid(&b_name);
    assert_exact_nul_ace(a_sid, "while launches A and B overlap (A)");
    assert_exact_nul_ace(b_sid, "while launches A and B overlap (B)");

    let a_status = a.wait().expect("wait launch A");
    assert!(a_status.success(), "launch A must complete successfully");
    assert_no_nul_ace(a_sid, "after launch A exits");
    assert_exact_nul_ace(b_sid, "launch A cleanup must not remove B's live ACE");

    let b_status = b.wait().expect("wait launch B");
    assert!(b_status.success(), "launch B must complete successfully");
    assert_no_nul_ace(b_sid, "after launch B exits");

    unsafe {
        FreeSid(a_sid);
        FreeSid(b_sid);
    }
    let _ = std::fs::remove_dir_all(&workspace);
}
