//! Native Git ownership regressions for the Windows AppContainer launcher.
//!
//! Git for Windows compares a repository owner with the confined process's
//! `TokenUser`, not its AppContainer SID.  The launcher must therefore leave
//! caller-owned paths alone: a caller that needs an exception supplies an exact
//! `safe.directory` through protected, caller-controlled configuration.

#![cfg(target_os = "windows")]

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, ERROR_SUCCESS, HANDLE, LUID};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, GetNamedSecurityInfoW, SetNamedSecurityInfoW, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, LookupPrivilegeValueW, TokenPrivileges, TokenUser, LUID_AND_ATTRIBUTES,
    OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, TOKEN_PRIVILEGES, TOKEN_QUERY,
    TOKEN_USER,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

const LAUNCHER: &str = env!("CARGO_BIN_EXE_agent-bridle-aclaunch");

static N: AtomicU64 = AtomicU64::new(0);

/// A unique tag (PID + monotonic counter — no wall clock) for AppContainer
/// profiles and temporary fixtures.
fn tag(kind: &str) -> String {
    format!(
        "{kind}-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    )
}

fn fresh_dir(kind: &str) -> PathBuf {
    let mut dir = std::env::temp_dir();
    dir.push(format!("ab-git-owner-{}", tag(kind)));
    std::fs::create_dir_all(&dir).expect("create temporary fixture directory");
    let low = Command::new("icacls")
        .arg(&dir)
        .args(["/setintegritylevel", "(OI)(CI)Low"])
        .output()
        .expect("run icacls to lower fixture integrity");
    assert!(
        low.status.success(),
        "fixture must use Low integrity so AppContainer DACL access is the variable; \
         stdout={} stderr={}",
        String::from_utf8_lossy(&low.stdout).trim(),
        String::from_utf8_lossy(&low.stderr).trim()
    );
    dir
}

fn launch(args: &[&str]) -> Output {
    Command::new(LAUNCHER)
        .args(args)
        .current_dir("C:\\Windows")
        .output()
        .expect("spawn agent-bridle-aclaunch")
}

fn appcontainer_available() -> bool {
    launch(&["--name", &tag("probe"), "cmd.exe", "/c", "exit 0"])
        .status
        .success()
}

/// `true` means that a developer machine cannot run this native boundary test.
/// CI sets `BRIDLE_REQUIRE_APPCONTAINER`, so that environment can never silently
/// skip the AppContainer boundary.
fn skip_unless_appcontainer() -> bool {
    let required = std::env::var("BRIDLE_REQUIRE_APPCONTAINER")
        .map(|value| !value.is_empty() && value != "0")
        .unwrap_or(false);
    if appcontainer_available() {
        return false;
    }
    if required {
        panic!("BRIDLE_REQUIRE_APPCONTAINER is set but an AppContainer could not be created");
    }
    eprintln!(
        "skipping native Git ownership proof: cannot create an AppContainer \
         (set BRIDLE_REQUIRE_APPCONTAINER=1 to require it)"
    );
    true
}

fn native_git_required() -> bool {
    std::env::var("BRIDLE_REQUIRE_NATIVE_GIT")
        .map(|value| !value.is_empty() && value != "0")
        .unwrap_or(false)
}

/// The local desktop runner is a non-interactive Session 0 service station.
/// Git for Windows loads `user32.dll` during process initialization there and
/// exits with `STATUS_DLL_INIT_FAILED` before Git can inspect repository
/// ownership.  Keep this exception deliberately narrow: every other native
/// Git discovery or startup failure is a test failure, and CI requires it.
fn skip_known_session_zero_git_loader_failure(reason: &str) -> bool {
    const STATUS_DLL_INIT_FAILED: &str = "status=Some(-1073741502)"; // 0xC0000142

    if native_git_required() || !reason.contains(STATUS_DLL_INIT_FAILED) {
        panic!("native Git ownership proof requires Git-for-Windows to start: {reason}");
    }
    eprintln!(
        "skipping native Git ownership proof only for the known Session 0 \
         STATUS_DLL_INIT_FAILED (0xC0000142): {reason} \
         (CI sets BRIDLE_REQUIRE_NATIVE_GIT=1)"
    );
    true
}

fn to_wide(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(std::iter::once(0)).collect()
}

fn sid_text(sid: PSID) -> String {
    assert!(!sid.is_null(), "SID must be present");
    unsafe {
        let mut raw: *mut u16 = std::ptr::null_mut();
        assert_ne!(
            ConvertSidToStringSidW(sid, &mut raw),
            0,
            "ConvertSidToStringSidW failed: {:?}",
            std::io::Error::last_os_error()
        );
        let mut len = 0;
        while *raw.add(len) != 0 {
            len += 1;
        }
        let value = String::from_utf16_lossy(std::slice::from_raw_parts(raw, len));
        LocalFree(raw.cast());
        value
    }
}

fn owner_sid(path: &Path) -> String {
    let path_w = to_wide(path.as_os_str());
    unsafe {
        let mut owner: PSID = std::ptr::null_mut();
        let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        let result = GetNamedSecurityInfoW(
            path_w.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut descriptor,
        );
        assert_eq!(
            result, ERROR_SUCCESS,
            "GetNamedSecurityInfoW({path:?}) failed: {result}"
        );
        let value = sid_text(owner);
        LocalFree(descriptor.cast());
        value
    }
}

/// `GetTokenInformation` returns variable-sized data. `usize` storage gives the
/// `TOKEN_USER` view the alignment it requires on every supported Windows target.
struct TokenUser {
    storage: Vec<usize>,
}

impl TokenUser {
    fn current() -> Self {
        unsafe {
            let mut token: HANDLE = std::ptr::null_mut();
            assert_ne!(
                OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token),
                0,
                "OpenProcessToken failed: {:?}",
                std::io::Error::last_os_error()
            );

            let mut bytes = 0_u32;
            let _ = GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut bytes);
            assert!(bytes as usize >= std::mem::size_of::<TOKEN_USER>());
            let words = (bytes as usize).div_ceil(std::mem::size_of::<usize>());
            let mut storage = vec![0_usize; words];
            assert_ne!(
                GetTokenInformation(
                    token,
                    TokenUser,
                    storage.as_mut_ptr().cast(),
                    bytes,
                    &mut bytes,
                ),
                0,
                "GetTokenInformation(TokenUser) failed: {:?}",
                std::io::Error::last_os_error()
            );
            CloseHandle(token);
            Self { storage }
        }
    }

    fn sid(&self) -> PSID {
        unsafe { (&*(self.storage.as_ptr().cast::<TOKEN_USER>())).User.Sid }
    }

    fn text(&self) -> String {
        sid_text(self.sid())
    }
}

/// The reviewed implementation entered its owner-transfer path only when the
/// launcher token held `SeRestorePrivilege` (it enabled a held-but-disabled
/// privilege itself). CI sets the accompanying requirement so this regression
/// cannot claim to cover that old path on a runner where it was unreachable.
/// The fixed launcher never enables or uses this privilege.
fn require_restore_privilege_for_old_owner_transfer_regression() {
    let required = std::env::var("BRIDLE_REQUIRE_OWNER_TRANSFER_REGRESSION")
        .map(|value| !value.is_empty() && value != "0")
        .unwrap_or(false);
    if !required {
        return;
    }

    assert!(
        token_has_privilege("SeRestorePrivilege"),
        "BRIDLE_REQUIRE_OWNER_TRANSFER_REGRESSION is set but the token does not hold SeRestorePrivilege; \
         this runner would not exercise the reviewed owner-transfer path"
    );
}

fn token_has_privilege(privilege_name: &str) -> bool {
    unsafe {
        let mut token: HANDLE = std::ptr::null_mut();
        assert_ne!(
            OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token),
            0,
            "OpenProcessToken failed: {:?}",
            std::io::Error::last_os_error()
        );

        let privilege_name = to_wide(OsStr::new(privilege_name));
        let mut expected: LUID = std::mem::zeroed();
        assert_ne!(
            LookupPrivilegeValueW(std::ptr::null(), privilege_name.as_ptr(), &mut expected),
            0,
            "LookupPrivilegeValueW failed: {:?}",
            std::io::Error::last_os_error()
        );

        let mut bytes = 0_u32;
        let _ = GetTokenInformation(token, TokenPrivileges, std::ptr::null_mut(), 0, &mut bytes);
        assert!(bytes as usize >= std::mem::size_of::<TOKEN_PRIVILEGES>());
        let words = (bytes as usize).div_ceil(std::mem::size_of::<usize>());
        let mut storage = vec![0_usize; words];
        assert_ne!(
            GetTokenInformation(
                token,
                TokenPrivileges,
                storage.as_mut_ptr().cast(),
                bytes,
                &mut bytes,
            ),
            0,
            "GetTokenInformation(TokenPrivileges) failed: {:?}",
            std::io::Error::last_os_error()
        );
        CloseHandle(token);

        let privileges = &*storage.as_ptr().cast::<TOKEN_PRIVILEGES>();
        let entries = std::slice::from_raw_parts(
            std::ptr::addr_of!(privileges.Privileges).cast::<LUID_AND_ATTRIBUTES>(),
            privileges.PrivilegeCount as usize,
        );
        entries.iter().any(|entry| {
            entry.Luid.LowPart == expected.LowPart && entry.Luid.HighPart == expected.HighPart
        })
    }
}

/// The test fixture is created by this trusted test process.  On elevated
/// Windows hosts its default owner can be Administrators, so explicitly make
/// the root and `.git` owned by `TokenUser` before using them as the controlled
/// positive case.  No confined process receives security-descriptor authority.
fn set_owner(path: &Path, owner: &TokenUser) {
    let path_w = to_wide(path.as_os_str());
    unsafe {
        let result = SetNamedSecurityInfoW(
            path_w.as_ptr().cast_mut(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            owner.sid(),
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
        );
        assert_eq!(
            result, ERROR_SUCCESS,
            "SetNamedSecurityInfoW({path:?}, TokenUser) failed: {result}"
        );
    }
}

fn configure_git(
    command: &mut Command,
    assume_different_owner: bool,
    safe_directory: Option<&Path>,
) {
    // This is deliberately caller-controlled process configuration, never
    // `.git/config` or the user's global configuration.  `NUL` gives Windows
    // Git an empty global/system source while `GIT_CONFIG_COUNT=0` suppresses
    // any inherited command-scope configuration.
    command
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_SYSTEM", "NUL")
        .env("GIT_CONFIG_GLOBAL", "NUL")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("HOME", "C:\\Windows")
        .env_remove("GIT_CONFIG_PARAMETERS")
        .env_remove("GIT_CONFIG_KEY_0")
        .env_remove("GIT_CONFIG_VALUE_0")
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE");

    if assume_different_owner {
        command.env("GIT_TEST_ASSUME_DIFFERENT_OWNER", "1");
    } else {
        command.env_remove("GIT_TEST_ASSUME_DIFFERENT_OWNER");
    }

    if let Some(path) = safe_directory {
        let canonical = path
            .canonicalize()
            .expect("canonicalize safe.directory path");
        command
            .env("GIT_CONFIG_COUNT", "1")
            .env("GIT_CONFIG_KEY_0", "safe.directory")
            .env("GIT_CONFIG_VALUE_0", canonical);
    } else {
        command.env("GIT_CONFIG_COUNT", "0");
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
        .map_err(|error| format!("host Git emitted a non-UTF-8 exec path: {error}"))?;
    let git = PathBuf::from(exec_path.trim()).join("git.exe");
    if !git.is_file() {
        return Err(format!("Git executable {git:?} does not exist"));
    }

    let version = Command::new(&git)
        .arg("--version")
        .output()
        .map_err(|error| format!("run {git:?} --version: {error}"))?;
    let stdout = String::from_utf8_lossy(&version.stdout);
    if !version.status.success() || !stdout.contains(".windows.") {
        return Err(format!(
            "{git:?} is not a working Git-for-Windows executable: status={:?}, stdout={}, stderr={}",
            version.status.code(),
            stdout.trim(),
            String::from_utf8_lossy(&version.stderr).trim()
        ));
    }
    Ok(git)
}

fn preflight_confined_git(git: &Path) -> Result<(), String> {
    let mut command = Command::new(LAUNCHER);
    command
        .arg("--name")
        .arg(tag("git-preflight"))
        .arg(git)
        .arg("--version")
        .current_dir("C:\\Windows");
    configure_git(&mut command, false, None);
    let output = command
        .output()
        .map_err(|error| format!("spawn Git through AppContainer: {error}"))?;
    if output.status.success() && String::from_utf8_lossy(&output.stdout).contains("git version") {
        Ok(())
    } else {
        Err(format!(
            "Git-for-Windows cannot start through AppContainer: status={:?}, stdout={}, stderr={}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout).trim(),
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

fn run_unconfined_git(
    git: &Path,
    repo: &Path,
    assume_different_owner: bool,
    safe_directory: Option<&Path>,
) -> Output {
    let mut command = Command::new(git);
    configure_git(&mut command, assume_different_owner, safe_directory);
    command
        .arg("-C")
        .arg(repo)
        .args(["rev-parse", "--is-inside-work-tree"])
        .output()
        .expect("run unconfined Git")
}

fn run_confined_git(
    git: &Path,
    repo: &Path,
    assume_different_owner: bool,
    safe_directory: Option<&Path>,
) -> Output {
    let mut command = Command::new(LAUNCHER);
    command
        .arg("--name")
        .arg(tag("git"))
        .arg("--fs-write")
        .arg(repo)
        .arg(git);
    configure_git(&mut command, assume_different_owner, safe_directory);
    command
        .arg("-C")
        .arg(repo)
        .args(["rev-parse", "--is-inside-work-tree"])
        .current_dir("C:\\Windows")
        .output()
        .expect("run Git through agent-bridle-aclaunch")
}

fn assert_git_succeeds(output: &Output, context: &str) {
    assert!(
        output.status.success() && String::from_utf8_lossy(&output.stdout).trim() == "true",
        "{context}: expected Git to identify the repository; status={:?}, stdout={}, stderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout).trim(),
        String::from_utf8_lossy(&output.stderr).trim()
    );
}

fn assert_dubious_ownership(output: &Output, context: &str) {
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !output.status.success() && text.contains("detected dubious ownership"),
        "{context}: expected Git's ownership rejection, not another failure; status={:?}, \
         stdout={}, stderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout).trim(),
        String::from_utf8_lossy(&output.stderr).trim()
    );
}

struct GitFixture {
    root: PathBuf,
    repo: PathBuf,
    repo_owner: String,
    dot_git_owner: String,
}

impl Drop for GitFixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn git_fixture(git: &Path) -> GitFixture {
    let root = fresh_dir("fixture");
    let repo = root.join("repo");
    let mut init = Command::new(git);
    configure_git(&mut init, false, None);
    let output = init
        .arg("init")
        .arg("--quiet")
        .arg(&repo)
        .output()
        .expect("initialize native Git fixture");
    assert!(
        output.status.success(),
        "Git fixture initialization failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout).trim(),
        String::from_utf8_lossy(&output.stderr).trim()
    );

    let user = TokenUser::current();
    let dot_git = repo.join(".git");
    set_owner(&repo, &user);
    set_owner(&dot_git, &user);
    let expected_owner = user.text();
    let repo_owner = owner_sid(&repo);
    let dot_git_owner = owner_sid(&dot_git);
    assert_eq!(
        repo_owner, expected_owner,
        "fixture root must be TokenUser-owned"
    );
    assert_eq!(
        dot_git_owner, expected_owner,
        "fixture .git must be TokenUser-owned"
    );

    GitFixture {
        root,
        repo,
        repo_owner,
        dot_git_owner,
    }
}

fn assert_fixture_owners_unchanged(fixture: &GitFixture, context: &str) {
    assert_eq!(
        owner_sid(&fixture.repo),
        fixture.repo_owner,
        "{context}: launcher must not change the granted repository owner"
    );
    assert_eq!(
        owner_sid(&fixture.repo.join(".git")),
        fixture.dot_git_owner,
        "{context}: launcher must not change the .git owner"
    );
}

/// Regression for the error paths that used to leave a caller path owned by a
/// now-deleted AppContainer profile. This is the local RED test: the reviewed
/// owner-transfer implementation fails it before Git startup is relevant.
#[test]
fn failed_write_setup_never_changes_caller_owner() {
    if skip_unless_appcontainer() {
        return;
    }
    require_restore_privilege_for_old_owner_transfer_regression();

    let workspace = fresh_dir("forced-failure");
    let before = owner_sid(&workspace);
    let output = launch(&[
        "--name",
        &tag("forced-failure"),
        "--fs-write",
        &workspace.to_string_lossy(),
        "--test-force-process-attribute-failure",
        "cmd.exe",
        "/c",
        "exit 0",
    ]);
    assert!(
        !output.status.success(),
        "forced process-attribute failure must refuse before spawn"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("forced process-attribute failure; refusing before spawn"),
        "the forced post-grant failure hook must have run; stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout).trim(),
        String::from_utf8_lossy(&output.stderr).trim()
    );
    assert_eq!(
        owner_sid(&workspace),
        before,
        "a failed launch must not change the caller-owned granted path"
    );

    let _ = std::fs::remove_dir_all(&workspace);
}

/// Git must see an unchanged TokenUser-owned repository under `--fs-write`.
/// The test first demonstrates the no-trust case, then admits the exact path
/// solely through `GIT_CONFIG_COUNT` supplied by the trusted caller.
#[test]
fn native_git_requires_exact_caller_trust_without_owner_mutation() {
    if skip_unless_appcontainer() {
        return;
    }
    let git = native_git()
        .unwrap_or_else(|reason| panic!("native Git-for-Windows discovery failed: {reason}"));
    if let Err(reason) = preflight_confined_git(&git) {
        if skip_known_session_zero_git_loader_failure(&reason) {
            return;
        }
    }

    let fixture = git_fixture(&git);
    assert_git_succeeds(
        &run_unconfined_git(&git, &fixture.repo, false, None),
        "unconfined control with isolated configuration",
    );

    // This is the regression against the reviewed implementation: it changes
    // the repository owner to the AppContainer SID before Git runs, so Git
    // rejects it before this positive control can succeed.
    assert_git_succeeds(
        &run_confined_git(&git, &fixture.repo, false, None),
        "TokenUser-owned repository through --fs-write without safe.directory",
    );
    assert_fixture_owners_unchanged(&fixture, "normal confined Git launch");

    // Git's supported test seam forces its real ownership decision while
    // keeping this test fixture TokenUser-owned.  It proves no ambient global
    // safe.directory leaks into the test and avoids changing a caller path's
    // owner merely to manufacture a negative case.
    assert_dubious_ownership(
        &run_confined_git(&git, &fixture.repo, true, None),
        "untrusted repository with global and command configuration isolated",
    );
    assert_fixture_owners_unchanged(&fixture, "untrusted confined Git launch");

    let wrong_path = fixture.root.join("different-workspace");
    std::fs::create_dir(&wrong_path).expect("create wrong safe.directory path");
    assert_dubious_ownership(
        &run_confined_git(&git, &fixture.repo, true, Some(&wrong_path)),
        "a sibling safe.directory must not trust this repository",
    );
    assert_fixture_owners_unchanged(&fixture, "wrong safe.directory launch");

    assert_git_succeeds(
        &run_confined_git(&git, &fixture.repo, true, Some(&fixture.repo)),
        "exact caller-supplied safe.directory",
    );
    assert_fixture_owners_unchanged(&fixture, "exact safe.directory launch");
}
