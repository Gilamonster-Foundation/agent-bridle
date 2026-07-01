//! `agent-bridle-aclaunch` — Windows AppContainer process launcher.
//!
//! Spawns `<exe> [args...]` inside a fresh AppContainer profile, waits for it
//! to exit, and exits with the same code.  Stdio (stdin/stdout/stderr) is
//! inherited from the launcher so that Rust `std::process::Stdio` piping works
//! transparently.
//!
//! # CLI
//!
//! ```text
//! agent-bridle-aclaunch [flags] <exe> [args...]
//! ```
//!
//! **Flags:**
//! * `--name <n>` — AppContainer profile name.  Must be unique per run.  If
//!   omitted a name is derived from the current PID.
//! * `--net-allow` — grant `INTERNET_CLIENT` + `INTERNET_CLIENT_SERVER` +
//!   `PRIVATE_NETWORK_CLIENT_SERVER` capability SIDs (deny-by-default without).
//! * `--exec-deny-spawn` — add `PROCESS_CREATION_CHILD_PROCESS_RESTRICTED` to
//!   the creation attributes so the child process cannot create any child
//!   processes at all (kernel-enforced via `PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY`).
//! * `--exec-allow <path>` (repeatable) — grant `FILE_GENERIC_READ | FILE_EXECUTE`
//!   ACEs to the AppContainer SID on `<path>` so the child can read and exec that
//!   specific binary.  ACEs are revoked after the child exits.
//! * `--fs-read <path>` (repeatable) — grant `FILE_GENERIC_READ` ACEs to the
//!   AppContainer SID on `<path>`.  Revoked after child exits.
//! * `--fs-write <path>` (repeatable) — grant `FILE_GENERIC_WRITE` ACEs to the
//!   AppContainer SID on `<path>`.  Revoked after child exits.
//! * `<exe>` — absolute or `PATH`-resolved executable.
//! * `[args...]` — arguments forwarded verbatim to the child process.
//!
//! The launcher creates a temporary AppContainer profile, grants the requested
//! ACEs before spawning, spawns the child, and revokes the ACEs then deletes the
//! profile after the child exits.  Cleanup is best-effort; leaked profiles and
//! ACEs are harmless and can be cleaned up with `icacls`.
//!
//! # Non-Windows builds
//!
//! On non-Windows hosts the binary compiles to an immediate error exit, keeping
//! `cargo check --workspace --all-features` green everywhere.

fn main() {
    #[cfg(target_os = "windows")]
    windows::run();

    #[cfg(not(target_os = "windows"))]
    {
        eprintln!("agent-bridle-aclaunch: not supported on this platform");
        std::process::exit(1);
    }
}

#[cfg(target_os = "windows")]
#[allow(unsafe_code)]
mod windows {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;

    use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, HANDLE, TRUE};
    use windows_sys::Win32::Security::Authorization::{
        BuildTrusteeWithSidW, GetNamedSecurityInfoW, SetEntriesInAclW, SetNamedSecurityInfoW,
        EXPLICIT_ACCESS_W, GRANT_ACCESS, NO_MULTIPLE_TRUSTEE, REVOKE_ACCESS, SE_FILE_OBJECT,
        TRUSTEE_IS_SID, TRUSTEE_IS_UNKNOWN, TRUSTEE_W,
    };
    use windows_sys::Win32::Security::Isolation::{
        CreateAppContainerProfile, DeleteAppContainerProfile,
    };
    use windows_sys::Win32::Security::{
        CreateWellKnownSid, FreeSid, WinCapabilityInternetClientServerSid,
        WinCapabilityInternetClientSid, WinCapabilityPrivateNetworkClientServerSid, ACL,
        DACL_SECURITY_INFORMATION, NO_INHERITANCE, SECURITY_CAPABILITIES, SID_AND_ATTRIBUTES,
        SUB_CONTAINERS_AND_OBJECTS_INHERIT,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_EXECUTE, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
    };
    use windows_sys::Win32::System::Threading::{
        CreateProcessW, DeleteProcThreadAttributeList, GetExitCodeProcess,
        InitializeProcThreadAttributeList, UpdateProcThreadAttribute, WaitForSingleObject,
        EXTENDED_STARTUPINFO_PRESENT, INFINITE, PROCESS_INFORMATION,
        PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
        STARTUPINFOEXW, STARTUPINFOW,
    };
    use windows_sys::Win32::System::WindowsProgramming::PROCESS_CREATION_CHILD_PROCESS_RESTRICTED;

    /// Null-terminate an `OsStr` as a `Vec<u16>`.
    fn to_wide(s: &OsStr) -> Vec<u16> {
        s.encode_wide().chain(std::iter::once(0)).collect()
    }

    /// Build a Windows command-line string from (program, args) for
    /// `CreateProcessW`. Tokens containing spaces or `"` are quoted.
    fn build_cmdline(program: &str, args: &[String]) -> Vec<u16> {
        fn quote(s: &str) -> String {
            if s.chars().any(|c| c == '"' || c == ' ' || c == '\t') {
                format!("\"{}\"", s.replace('"', "\\\""))
            } else {
                s.to_string()
            }
        }
        let mut cmd = quote(program);
        for a in args {
            cmd.push(' ');
            cmd.push_str(&quote(a));
        }
        to_wide(OsStr::new(&cmd))
    }

    /// Create well-known capability SIDs, storing each SID's bytes in `bufs`.
    ///
    /// Each `SID_AND_ATTRIBUTES` returned holds a raw pointer into the
    /// corresponding `Vec<u8>` in `bufs`; the caller must keep `bufs` alive
    /// for the lifetime of the returned slice.
    unsafe fn make_cap_sids(types: &[i32], bufs: &mut Vec<Vec<u8>>) -> Vec<SID_AND_ATTRIBUTES> {
        let mut out: Vec<SID_AND_ATTRIBUTES> = Vec::with_capacity(types.len());
        for &t in types {
            let mut buf = vec![0u8; 256];
            let mut size = buf.len() as u32;
            let ok =
                CreateWellKnownSid(t, std::ptr::null_mut(), buf.as_mut_ptr().cast(), &mut size);
            if ok == 0 {
                eprintln!(
                    "agent-bridle-aclaunch: CreateWellKnownSid({t}) failed: {:?}",
                    std::io::Error::last_os_error()
                );
                continue;
            }
            let ptr = buf.as_mut_ptr().cast();
            bufs.push(buf);
            out.push(SID_AND_ATTRIBUTES {
                Sid: ptr,
                Attributes: 0,
            });
        }
        out
    }

    /// Grant or revoke a DACL ACE for `ac_sid` on `path`.
    ///
    /// `access_mask` is the right set (e.g. `FILE_GENERIC_READ`); `mode` is
    /// `GRANT_ACCESS` or `REVOKE_ACCESS`.  Best-effort: failures are logged and
    /// ignored so that a missing or ACL-protected path does not abort a run.
    unsafe fn set_ace(path: &str, access_mask: u32, mode: i32, ac_sid: *mut std::ffi::c_void) {
        let path_w = to_wide(OsStr::new(path));

        // 1. Retrieve existing DACL.
        let mut p_dacl: *mut ACL = std::ptr::null_mut();
        let mut p_sd: *mut std::ffi::c_void = std::ptr::null_mut();
        let err = GetNamedSecurityInfoW(
            path_w.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut p_dacl,
            std::ptr::null_mut(),
            &mut p_sd,
        );
        if err != 0 {
            eprintln!("agent-bridle-aclaunch: GetNamedSecurityInfoW({path:?}) err={err} (ignored)");
            return;
        }

        // 2. Build a trustee from the AppContainer SID.
        let mut trustee: TRUSTEE_W = std::mem::zeroed();
        BuildTrusteeWithSidW(&mut trustee, ac_sid);
        // BuildTrusteeWithSidW may leave pMultipleTrustee / MultipleTrusteeOperation
        // unset; fill in the no-multiple-trustee sentinel explicitly.
        trustee.pMultipleTrustee = std::ptr::null_mut();
        trustee.MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE;
        trustee.TrusteeForm = TRUSTEE_IS_SID;
        trustee.TrusteeType = TRUSTEE_IS_UNKNOWN;

        let inheritance = if mode == GRANT_ACCESS {
            SUB_CONTAINERS_AND_OBJECTS_INHERIT
        } else {
            NO_INHERITANCE
        };
        let ea = EXPLICIT_ACCESS_W {
            grfAccessPermissions: access_mask,
            grfAccessMode: mode,
            grfInheritance: inheritance,
            Trustee: trustee,
        };

        // 3. Merge the new entry into the existing DACL.
        let mut p_new_dacl: *mut ACL = std::ptr::null_mut();
        let err = SetEntriesInAclW(1, &ea, p_dacl, &mut p_new_dacl);
        LocalFree(p_sd as _);
        if err != 0 {
            eprintln!("agent-bridle-aclaunch: SetEntriesInAclW({path:?}) err={err} (ignored)");
            return;
        }

        // 4. Write the merged DACL back.
        let err = SetNamedSecurityInfoW(
            path_w.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            p_new_dacl,
            std::ptr::null(),
        );
        LocalFree(p_new_dacl as _);
        if err != 0 {
            eprintln!("agent-bridle-aclaunch: SetNamedSecurityInfoW({path:?}) err={err} (ignored)");
        }
    }

    #[derive(Default)]
    struct LaunchArgs {
        container_name: Option<String>,
        net_allow: bool,
        exec_deny_spawn: bool,
        exec_allow: Vec<String>,
        fs_read: Vec<String>,
        fs_write: Vec<String>,
        exe: String,
        child_args: Vec<String>,
    }

    fn parse_args() -> LaunchArgs {
        let raw: Vec<String> = std::env::args().collect();
        let mut la = LaunchArgs::default();
        let mut i = 1usize;
        while i < raw.len() {
            match raw[i].as_str() {
                "--name" => {
                    i += 1;
                    la.container_name = raw.get(i).cloned();
                }
                "--net-allow" => {
                    la.net_allow = true;
                }
                "--exec-deny-spawn" => {
                    la.exec_deny_spawn = true;
                }
                "--exec-allow" => {
                    i += 1;
                    if let Some(p) = raw.get(i) {
                        la.exec_allow.push(p.clone());
                    }
                }
                "--fs-read" => {
                    i += 1;
                    if let Some(p) = raw.get(i) {
                        la.fs_read.push(p.clone());
                    }
                }
                "--fs-write" => {
                    i += 1;
                    if let Some(p) = raw.get(i) {
                        la.fs_write.push(p.clone());
                    }
                }
                _ => break,
            }
            i += 1;
        }
        if i >= raw.len() {
            eprintln!(
                "usage: agent-bridle-aclaunch [--name <n>] [--net-allow] \
                 [--exec-deny-spawn] [--exec-allow <path>]... \
                 [--fs-read <path>]... [--fs-write <path>]... <exe> [args...]"
            );
            std::process::exit(2);
        }
        la.exe = raw[i].clone();
        la.child_args = raw[i + 1..].to_vec();
        la
    }

    pub fn run() {
        let la = parse_args();
        let name = la
            .container_name
            .clone()
            .unwrap_or_else(|| format!("ab{}", std::process::id()));
        let exit_code = unsafe { spawn_in_container(&name, &la) };
        std::process::exit(exit_code as i32);
    }

    /// Create an AppContainer profile, grant ACEs, spawn `exe` inside it, wait,
    /// revoke ACEs, clean up, and return the child's exit code.
    unsafe fn spawn_in_container(name: &str, la: &LaunchArgs) -> u32 {
        // 1. Create the AppContainer profile and retrieve its SID.
        let name_w = to_wide(OsStr::new(name));
        let display_w = to_wide(OsStr::new("agent-bridle container"));
        let desc_w = to_wide(OsStr::new("agent-bridle AppContainer"));
        let mut ac_sid: *mut std::ffi::c_void = std::ptr::null_mut();

        // 0x800700b7 == HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS) — reuse if present.
        let hr = CreateAppContainerProfile(
            name_w.as_ptr(),
            display_w.as_ptr(),
            desc_w.as_ptr(),
            std::ptr::null(),
            0,
            &mut ac_sid,
        );
        if hr != 0 && hr != -2_147_024_713i32 {
            eprintln!(
                "agent-bridle-aclaunch: CreateAppContainerProfile({name:?}) failed: \
                 HRESULT={hr:#010x}"
            );
            std::process::exit(1);
        }
        if ac_sid.is_null() {
            eprintln!("agent-bridle-aclaunch: AppContainer SID is null after profile creation");
            std::process::exit(1);
        }

        // 2. Capability SIDs (network only — requested via --net-allow).
        let cap_types: Vec<i32> = if la.net_allow {
            vec![
                WinCapabilityInternetClientSid,
                WinCapabilityInternetClientServerSid,
                WinCapabilityPrivateNetworkClientServerSid,
            ]
        } else {
            vec![]
        };
        let mut cap_bufs: Vec<Vec<u8>> = Vec::new();
        let mut cap_sids = make_cap_sids(&cap_types, &mut cap_bufs);

        // 3. SECURITY_CAPABILITIES struct.
        let sec_caps = SECURITY_CAPABILITIES {
            AppContainerSid: ac_sid,
            Capabilities: if cap_sids.is_empty() {
                std::ptr::null_mut()
            } else {
                cap_sids.as_mut_ptr()
            },
            CapabilityCount: cap_sids.len() as u32,
            Reserved: 0,
        };

        // 4. Grant path ACEs before spawn: exec-allow paths get READ+EXECUTE,
        //    fs-read paths get READ, fs-write paths get WRITE.
        let all_acl_paths: Vec<(&str, u32)> = la
            .exec_allow
            .iter()
            .map(|p| (p.as_str(), FILE_GENERIC_READ | FILE_EXECUTE))
            .chain(la.fs_read.iter().map(|p| (p.as_str(), FILE_GENERIC_READ)))
            .chain(la.fs_write.iter().map(|p| (p.as_str(), FILE_GENERIC_WRITE)))
            .collect();
        for (path, mask) in &all_acl_paths {
            set_ace(path, *mask, GRANT_ACCESS, ac_sid);
        }

        // 5. Attribute list: 1 slot (security caps) + 1 if child-process policy.
        let attr_count: u32 = if la.exec_deny_spawn { 2 } else { 1 };
        let mut attr_size: usize = 0;
        InitializeProcThreadAttributeList(std::ptr::null_mut(), attr_count, 0, &mut attr_size);
        let mut attr_buf: Vec<u8> = vec![0u8; attr_size];
        let attr_list = attr_buf.as_mut_ptr().cast();

        let ok = InitializeProcThreadAttributeList(attr_list, attr_count, 0, &mut attr_size);
        if ok == 0 {
            eprintln!(
                "agent-bridle-aclaunch: InitializeProcThreadAttributeList failed: {:?}",
                std::io::Error::last_os_error()
            );
            revoke_and_cleanup(name, ac_sid, &cap_sids, &all_acl_paths);
            std::process::exit(1);
        }

        let ok = UpdateProcThreadAttribute(
            attr_list,
            0,
            PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES as usize,
            (&sec_caps as *const SECURITY_CAPABILITIES).cast(),
            std::mem::size_of::<SECURITY_CAPABILITIES>(),
            std::ptr::null_mut(),
            std::ptr::null(),
        );
        if ok == 0 {
            eprintln!(
                "agent-bridle-aclaunch: UpdateProcThreadAttribute(SECURITY_CAPABILITIES) \
                 failed: {:?}",
                std::io::Error::last_os_error()
            );
            DeleteProcThreadAttributeList(attr_list);
            revoke_and_cleanup(name, ac_sid, &cap_sids, &all_acl_paths);
            std::process::exit(1);
        }

        // 6. Optionally restrict child-process creation (exec: Scope::Only([])).
        let child_policy: u32 = PROCESS_CREATION_CHILD_PROCESS_RESTRICTED;
        if la.exec_deny_spawn {
            let ok = UpdateProcThreadAttribute(
                attr_list,
                0,
                PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY as usize,
                (&child_policy as *const u32).cast(),
                std::mem::size_of::<u32>(),
                std::ptr::null_mut(),
                std::ptr::null(),
            );
            if ok == 0 {
                eprintln!(
                    "agent-bridle-aclaunch: UpdateProcThreadAttribute(CHILD_PROCESS_POLICY) \
                     failed: {:?}",
                    std::io::Error::last_os_error()
                );
                DeleteProcThreadAttributeList(attr_list);
                revoke_and_cleanup(name, ac_sid, &cap_sids, &all_acl_paths);
                std::process::exit(1);
            }
        }

        // 7. Spawn the child inside the AppContainer.  `bInheritHandles = TRUE`
        //    so the child receives the launcher's stdin/stdout/stderr.
        let cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
        let mut startup_info_ex: STARTUPINFOEXW = std::mem::zeroed();
        startup_info_ex.StartupInfo.cb = cb;
        startup_info_ex.lpAttributeList = attr_list;

        let mut cmd_line = build_cmdline(&la.exe, &la.child_args);
        let mut proc_info: PROCESS_INFORMATION = std::mem::zeroed();

        let ok = CreateProcessW(
            std::ptr::null(),
            cmd_line.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            TRUE,
            EXTENDED_STARTUPINFO_PRESENT,
            std::ptr::null(),
            std::ptr::null(),
            &startup_info_ex.StartupInfo as *const STARTUPINFOW,
            &mut proc_info,
        );

        DeleteProcThreadAttributeList(attr_list);

        if ok == 0 {
            eprintln!(
                "agent-bridle-aclaunch: CreateProcessW({:?}) failed: {:?}",
                la.exe,
                std::io::Error::last_os_error()
            );
            revoke_and_cleanup(name, ac_sid, &cap_sids, &all_acl_paths);
            std::process::exit(1);
        }

        CloseHandle(proc_info.hThread);
        WaitForSingleObject(proc_info.hProcess as HANDLE, INFINITE);
        let mut exit_code: u32 = 1;
        GetExitCodeProcess(proc_info.hProcess as HANDLE, &mut exit_code);
        CloseHandle(proc_info.hProcess as HANDLE);

        // 8. Revoke ACEs and delete the AppContainer profile.
        revoke_and_cleanup(name, ac_sid, &cap_sids, &all_acl_paths);

        exit_code
    }

    /// Revoke all granted ACEs and free/delete the profile.  Best-effort.
    unsafe fn revoke_and_cleanup(
        name: &str,
        ac_sid: *mut std::ffi::c_void,
        cap_sids: &[SID_AND_ATTRIBUTES],
        acl_paths: &[(&str, u32)],
    ) {
        // Revoke every ACE we granted (mask 0 is ignored for REVOKE_ACCESS).
        for (path, _mask) in acl_paths {
            set_ace(path, 0, REVOKE_ACCESS, ac_sid);
        }
        for sid in cap_sids {
            if !sid.Sid.is_null() {
                FreeSid(sid.Sid);
            }
        }
        if !ac_sid.is_null() {
            FreeSid(ac_sid);
        }
        let name_w = to_wide(OsStr::new(name));
        let hr = DeleteAppContainerProfile(name_w.as_ptr());
        if hr != 0 {
            eprintln!(
                "agent-bridle-aclaunch: DeleteAppContainerProfile({name:?}) failed: \
                 HRESULT={hr:#010x} (profile may need manual cleanup)"
            );
        }
    }
}
