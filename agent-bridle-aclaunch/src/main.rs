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
//! agent-bridle-aclaunch [--name <container-name>] [--net-allow] <exe> [args...]
//! ```
//!
//! * `--name <n>` — AppContainer profile name.  Must be unique per run.  If
//!   omitted a name is derived from the current PID.
//! * `--net-allow` — grant `INTERNET_CLIENT` + `INTERNET_CLIENT_SERVER` +
//!   `PRIVATE_NETWORK_CLIENT_SERVER` capability SIDs.  Without this flag no
//!   network capability SIDs are granted (deny-by-default egress).
//! * `<exe>` — absolute or `PATH`-resolved executable.
//! * `[args...]` — arguments forwarded verbatim to the child process.
//!
//! The launcher creates a temporary AppContainer profile, spawns the child, and
//! deletes the profile after the child exits.  Profile deletion is best-effort;
//! leaked profiles are harmless and can be cleaned up with the userenv APIs or
//! `icacls`.
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

    use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, ERROR_SUCCESS, HANDLE, TRUE};
    use windows_sys::Win32::NetworkManagement::WindowsFirewall::{
        NetworkIsolationGetAppContainerConfig, NetworkIsolationSetAppContainerConfig,
    };
    use windows_sys::Win32::Security::Authorization::{
        GetNamedSecurityInfoW, SetEntriesInAclW, SetNamedSecurityInfoW, EXPLICIT_ACCESS_W,
        GRANT_ACCESS, NO_MULTIPLE_TRUSTEE, SE_FILE_OBJECT, TRUSTEE_IS_SID, TRUSTEE_IS_UNKNOWN,
        TRUSTEE_W,
    };
    use windows_sys::Win32::Security::Isolation::{
        CreateAppContainerProfile, DeleteAppContainerProfile,
    };
    use windows_sys::Win32::Security::{
        CreateWellKnownSid, FreeSid, GetSecurityDescriptorDacl,
        WinCapabilityInternetClientServerSid, WinCapabilityInternetClientSid,
        WinCapabilityPrivateNetworkClientServerSid, ACL, CONTAINER_INHERIT_ACE,
        DACL_SECURITY_INFORMATION, OBJECT_INHERIT_ACE, SECURITY_CAPABILITIES, SID_AND_ATTRIBUTES,
    };
    use windows_sys::Win32::System::Memory::{GetProcessHeap, HeapFree};
    use windows_sys::Win32::System::Threading::{
        CreateProcessW, DeleteProcThreadAttributeList, GetExitCodeProcess,
        InitializeProcThreadAttributeList, UpdateProcThreadAttribute, WaitForSingleObject,
        EXTENDED_STARTUPINFO_PRESENT, INFINITE, PROCESS_INFORMATION,
        PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, STARTUPINFOEXW, STARTUPINFOW,
    };

    // PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY = ProcThreadAttributeValue(14, FALSE, TRUE, FALSE)
    // = (14 & 0xFFFF) | PROC_THREAD_ATTRIBUTE_INPUT (0x00020000) = 0x0002000E
    const PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY: usize = 0x0002000E;
    // PROCESS_CREATION_CHILD_PROCESS_RESTRICTED: the process may not create child processes.
    const PROCESS_CREATION_CHILD_PROCESS_RESTRICTED: u32 = 1;

    // FILE_GENERIC_READ / FILE_GENERIC_WRITE from the Windows SDK (WinNT.h).
    const FILE_GENERIC_READ: u32 = 0x00120089;
    const FILE_GENERIC_WRITE: u32 = 0x00120116;
    const FILE_GENERIC_READ_WRITE: u32 = FILE_GENERIC_READ | FILE_GENERIC_WRITE;

    /// Null-terminate an `OsStr` as a `Vec<u16>`.
    fn to_wide(s: &OsStr) -> Vec<u16> {
        s.encode_wide().chain(std::iter::once(0)).collect()
    }

    /// Grant `ac_sid` the given `access_mask` on `path` (inheriting into subdirs).
    ///
    /// Gets the existing DACL, merges in an `EXPLICIT_ACCESS` ACE for the
    /// AppContainer SID, and applies the merged DACL.  Returns the old security
    /// descriptor (caller must `LocalFree` it) on success, or `null` if the
    /// operation fails (non-fatal: some paths may not be modifiable by this user).
    unsafe fn grant_path_access(
        path: &str,
        ac_sid: *mut std::ffi::c_void,
        access_mask: u32,
    ) -> *mut std::ffi::c_void {
        let path_w = to_wide(OsStr::new(path));

        let mut p_old_dacl: *mut ACL = std::ptr::null_mut();
        let mut p_sd: *mut std::ffi::c_void = std::ptr::null_mut();

        let err = GetNamedSecurityInfoW(
            path_w.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut p_old_dacl,
            std::ptr::null_mut(),
            &mut p_sd,
        );
        if err != ERROR_SUCCESS {
            return std::ptr::null_mut();
        }

        let ea = EXPLICIT_ACCESS_W {
            grfAccessPermissions: access_mask,
            grfAccessMode: GRANT_ACCESS,
            grfInheritance: OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE,
            Trustee: TRUSTEE_W {
                pMultipleTrustee: std::ptr::null_mut(),
                MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
                TrusteeForm: TRUSTEE_IS_SID,
                TrusteeType: TRUSTEE_IS_UNKNOWN,
                ptstrName: ac_sid.cast(),
            },
        };

        let mut p_new_dacl: *mut ACL = std::ptr::null_mut();
        let err = SetEntriesInAclW(1, &ea, p_old_dacl, &mut p_new_dacl);
        if err != ERROR_SUCCESS {
            LocalFree(p_sd);
            return std::ptr::null_mut();
        }

        let err = SetNamedSecurityInfoW(
            path_w.as_ptr() as *mut _,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            p_new_dacl,
            std::ptr::null_mut(),
        );

        LocalFree(p_new_dacl as *mut _);

        if err != ERROR_SUCCESS {
            LocalFree(p_sd);
            std::ptr::null_mut()
        } else {
            p_sd
        }
    }

    /// Restore the DACL saved by `grant_path_access` and free the security descriptor.
    unsafe fn restore_path_dacl(path: &str, p_sd: *mut std::ffi::c_void) {
        if p_sd.is_null() {
            return;
        }
        let path_w = to_wide(OsStr::new(path));
        let mut p_dacl: *mut ACL = std::ptr::null_mut();
        let mut b_present: i32 = 0;
        let mut b_defaulted: i32 = 0;
        GetSecurityDescriptorDacl(p_sd, &mut b_present, &mut p_dacl, &mut b_defaulted);
        if b_present != 0 {
            SetNamedSecurityInfoW(
                path_w.as_ptr() as *mut _,
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                p_dacl,
                std::ptr::null_mut(),
            );
        }
        LocalFree(p_sd);
    }

    /// Grant the AppContainer SID loopback network access (#133, ADR 0016).
    ///
    /// AppContainers cannot connect to the loopback interface (127.0.0.1) by
    /// default — the Windows network isolation layer blocks it. We get the
    /// current exemption list, add our container SID, and apply the new list.
    /// Returns the saved original list + count so the caller can restore them
    /// after the child exits.  Non-fatal on failure: returns (null, 0).
    ///
    /// The returned pointer must be freed with `HeapFree(GetProcessHeap(), ...)`.
    unsafe fn enable_loopback_exemption(
        ac_sid: *mut std::ffi::c_void,
    ) -> (*mut SID_AND_ATTRIBUTES, u32) {
        let mut count: u32 = 0;
        let mut existing: *mut SID_AND_ATTRIBUTES = std::ptr::null_mut();
        if NetworkIsolationGetAppContainerConfig(&mut count, &mut existing) != 0 {
            return (std::ptr::null_mut(), 0);
        }
        // Build new list = existing entries + our SID.
        let mut new_list: Vec<SID_AND_ATTRIBUTES> = Vec::with_capacity(count as usize + 1);
        for i in 0..count as usize {
            new_list.push(*existing.add(i));
        }
        new_list.push(SID_AND_ATTRIBUTES {
            Sid: ac_sid.cast(),
            Attributes: 0,
        });
        let ok = NetworkIsolationSetAppContainerConfig(new_list.len() as u32, new_list.as_ptr());
        if ok != 0 {
            eprintln!(
                "agent-bridle-aclaunch: NetworkIsolationSetAppContainerConfig failed (loopback \
                 exemption): error={ok}"
            );
            if !existing.is_null() {
                HeapFree(GetProcessHeap(), 0, existing as *mut _);
            }
            return (std::ptr::null_mut(), 0);
        }
        (existing, count)
    }

    /// Restore the loopback exemption list saved by `enable_loopback_exemption`.
    unsafe fn restore_loopback_exemption(existing: *mut SID_AND_ATTRIBUTES, count: u32) {
        if count == 0 {
            let _ = NetworkIsolationSetAppContainerConfig(0, std::ptr::null());
        } else if !existing.is_null() {
            let _ = NetworkIsolationSetAppContainerConfig(count, existing);
        }
        if !existing.is_null() {
            HeapFree(GetProcessHeap(), 0, existing as *mut _);
        }
    }

    /// Build a Windows command-line string from (program, args) for
    /// `CreateProcessW`. Uses the canonical MSVC `CommandLineToArgvW` quoting
    /// rules: backslash runs before `"` (or at string end inside a quoted token)
    /// are doubled; `"` is escaped as `\"`. Plain tokens (no whitespace or `"`)
    /// are emitted verbatim.
    fn build_cmdline(program: &str, args: &[String]) -> Vec<u16> {
        fn quote(s: &str) -> String {
            let needs_quoting = s.is_empty() || s.chars().any(|c| matches!(c, '"' | ' ' | '\t'));
            if !needs_quoting {
                return s.to_string();
            }
            let mut out = String::from('"');
            let chars: Vec<char> = s.chars().collect();
            let mut i = 0;
            while i < chars.len() {
                let bs_start = i;
                while i < chars.len() && chars[i] == '\\' {
                    i += 1;
                }
                let n_bs = i - bs_start;
                if i == chars.len() {
                    // Trailing backslashes precede the closing `"` — must be doubled.
                    for _ in 0..n_bs * 2 {
                        out.push('\\');
                    }
                } else if chars[i] == '"' {
                    // Backslashes before `"`: double them, then escape the `"`.
                    for _ in 0..n_bs * 2 {
                        out.push('\\');
                    }
                    out.push_str("\\\"");
                    i += 1;
                } else {
                    // Backslashes not adjacent to `"`: literal.
                    for _ in 0..n_bs {
                        out.push('\\');
                    }
                    out.push(chars[i]);
                    i += 1;
                }
            }
            out.push('"');
            out
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
                std::process::exit(1);
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

    pub fn run() {
        let args: Vec<String> = std::env::args().collect();

        // Parse optional launcher flags and find the exe + child args.
        let mut container_name: Option<String> = None;
        let mut net_allow = false;
        let mut loopback_exemption = false;
        let mut no_child_process = false;
        let mut fs_read: Vec<String> = Vec::new();
        let mut fs_write: Vec<String> = Vec::new();
        let mut i = 1usize;
        while i < args.len() {
            match args[i].as_str() {
                "--name" => {
                    i += 1;
                    container_name = args.get(i).cloned();
                }
                "--net-allow" => {
                    net_allow = true;
                }
                "--loopback-exemption" => {
                    loopback_exemption = true;
                }
                "--no-child-process" => {
                    no_child_process = true;
                }
                "--fs-read" => {
                    i += 1;
                    if let Some(p) = args.get(i) {
                        fs_read.push(p.clone());
                    }
                }
                "--fs-write" => {
                    i += 1;
                    if let Some(p) = args.get(i) {
                        fs_write.push(p.clone());
                    }
                }
                _ => break,
            }
            i += 1;
        }
        if i >= args.len() {
            eprintln!(
                "usage: agent-bridle-aclaunch [--name <n>] [--net-allow] [--loopback-exemption] \
                 [--no-child-process] [--fs-read <path>]... [--fs-write <path>]... \
                 <exe> [args...]"
            );
            std::process::exit(2);
        }
        let exe = &args[i];
        let child_args = &args[i + 1..];

        let name = container_name.unwrap_or_else(|| format!("ab{}", std::process::id()));
        let exit_code = unsafe {
            spawn_in_container(
                &name,
                net_allow,
                loopback_exemption,
                no_child_process,
                &fs_read,
                &fs_write,
                exe,
                child_args,
            )
        };
        std::process::exit(exit_code as i32);
    }

    /// Create an AppContainer profile, spawn `exe` inside it, wait, and return
    /// the child's exit code.  Cleans up the profile before returning.
    unsafe fn spawn_in_container(
        name: &str,
        net_allow: bool,
        loopback_exemption: bool,
        no_child_process: bool,
        fs_read: &[String],
        fs_write: &[String],
        exe: &str,
        child_args: &[String],
    ) -> u32 {
        // 1. Create the AppContainer profile and retrieve its SID.
        let name_w = to_wide(OsStr::new(name));
        let display_w = to_wide(OsStr::new("agent-bridle container"));
        let desc_w = to_wide(OsStr::new("agent-bridle AppContainer"));
        let mut ac_sid: *mut std::ffi::c_void = std::ptr::null_mut();

        // 0x800700b7 == HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS) — if a profile
        // by this name already exists we can reuse it; the SID is stable.
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

        // 2a. FS ACL narrowing (#51, ADR 0009): grant the AppContainer SID access to
        //     the requested paths so the sandboxed process can read/write its workspace.
        //     AppContainers are denied user directories by default; without this grant
        //     the child cannot access its working directory.
        //     We save each path's original security descriptor for cleanup after the child
        //     exits.  Non-fatal per path — system directories are usually already accessible
        //     via ALL_APPLICATION_PACKAGES and may not be modifiable by the current user.
        let mut fs_grants: Vec<(String, *mut std::ffi::c_void)> = Vec::new();

        // Grant read+write for write paths first (superset of read).
        for path in fs_write {
            let psd = grant_path_access(path, ac_sid, FILE_GENERIC_READ_WRITE);
            if psd.is_null() {
                eprintln!(
                    "agent-bridle-aclaunch: could not grant write access to {path:?} \
                     (non-fatal; path may be inaccessible to the AppContainer)"
                );
            }
            fs_grants.push((path.clone(), psd));
        }
        // Grant read-only for remaining read paths not already granted.
        for path in fs_read {
            if fs_grants.iter().any(|(p, _)| p == path) {
                continue;
            }
            let psd = grant_path_access(path, ac_sid, FILE_GENERIC_READ);
            if psd.is_null() {
                eprintln!(
                    "agent-bridle-aclaunch: could not grant read access to {path:?} \
                     (non-fatal; path may be inaccessible to the AppContainer)"
                );
            }
            fs_grants.push((path.clone(), psd));
        }

        // 2b. Loopback exemption (#133, ADR 0016): AppContainers cannot reach the
        //     loopback interface (127.0.0.1) by default. When the egress proxy
        //     pattern is active, the sandboxed child must connect to the parent's
        //     proxy on loopback, so we grant the exemption here. We save the
        //     previous exemption list for restoration after the child exits.
        let (loopback_prev, loopback_prev_count) = if loopback_exemption {
            enable_loopback_exemption(ac_sid)
        } else {
            (std::ptr::null_mut(), 0)
        };

        // 2c. Capability SIDs for network.
        let cap_types: Vec<i32> = if net_allow {
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

        // 4. Attribute list.  Slots: always one for SECURITY_CAPABILITIES;
        //    one more when --no-child-process applies.
        let slot_count: u32 = if no_child_process { 2 } else { 1 };
        let mut attr_size: usize = 0;
        // First call: get the required buffer size (returns FALSE, that is expected).
        InitializeProcThreadAttributeList(std::ptr::null_mut(), slot_count, 0, &mut attr_size);
        let mut attr_buf: Vec<u8> = vec![0u8; attr_size];
        let attr_list = attr_buf.as_mut_ptr().cast();

        let ok = InitializeProcThreadAttributeList(attr_list, slot_count, 0, &mut attr_size);
        if ok == 0 {
            eprintln!(
                "agent-bridle-aclaunch: InitializeProcThreadAttributeList failed: {:?}",
                std::io::Error::last_os_error()
            );
            do_cleanup(name, ac_sid);
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
            do_cleanup(name, ac_sid);
            std::process::exit(1);
        }

        // When exec is fully denied, apply the kernel child-process-creation block.
        // PROCESS_CREATION_CHILD_PROCESS_RESTRICTED causes the kernel to refuse any
        // CreateProcess call the sandboxed process makes (#123, ADR 0013 D7).
        if no_child_process {
            let policy = PROCESS_CREATION_CHILD_PROCESS_RESTRICTED;
            let ok = UpdateProcThreadAttribute(
                attr_list,
                0,
                PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY,
                (&policy as *const u32).cast(),
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
                do_cleanup(name, ac_sid);
                std::process::exit(1);
            }
        }

        // 5. Spawn the child inside the AppContainer.  `bInheritHandles = TRUE`
        //    so the child receives the launcher's stdin/stdout/stderr (which were
        //    set up by agent-bridle before spawning the launcher).
        let cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
        // SAFETY: zero-init is valid for STARTUPINFOW (all pointer fields are
        // allowed to be NULL per Win32 docs when STARTF_USESTDHANDLES is unset).
        let mut startup_info_ex: STARTUPINFOEXW = std::mem::zeroed();
        startup_info_ex.StartupInfo.cb = cb;
        startup_info_ex.lpAttributeList = attr_list;

        let mut cmd_line = build_cmdline(exe, child_args);
        let mut proc_info: PROCESS_INFORMATION = std::mem::zeroed();

        let ok = CreateProcessW(
            std::ptr::null(),             // lpApplicationName: derive from command line
            cmd_line.as_mut_ptr(),        // lpCommandLine: mutable per Win32 docs
            std::ptr::null(),             // lpProcessAttributes
            std::ptr::null(),             // lpThreadAttributes
            TRUE,                         // bInheritHandles: for stdio pipes
            EXTENDED_STARTUPINFO_PRESENT, // dwCreationFlags: required for attr list
            std::ptr::null(),             // lpEnvironment: inherit from launcher
            std::ptr::null(),             // lpCurrentDirectory: inherit from launcher
            // SAFETY: STARTUPINFOEXW starts with STARTUPINFOW; the cast is
            // documented by Win32 for EXTENDED_STARTUPINFO_PRESENT.
            &startup_info_ex.StartupInfo as *const STARTUPINFOW,
            &mut proc_info,
        );

        DeleteProcThreadAttributeList(attr_list);

        if ok == 0 {
            eprintln!(
                "agent-bridle-aclaunch: CreateProcessW({exe:?}) failed: {:?}",
                std::io::Error::last_os_error()
            );
            do_cleanup(name, ac_sid);
            std::process::exit(1);
        }

        // Thread handle is not needed; close it immediately.
        CloseHandle(proc_info.hThread);

        // 6. Wait for the child, collect its exit code.
        WaitForSingleObject(proc_info.hProcess as HANDLE, INFINITE);
        let mut exit_code: u32 = 1;
        GetExitCodeProcess(proc_info.hProcess as HANDLE, &mut exit_code);
        CloseHandle(proc_info.hProcess as HANDLE);

        // 7a. Restore fs DACLs we modified before the child was spawned.
        for (path, psd) in fs_grants {
            restore_path_dacl(&path, psd);
        }

        // 7b. Restore loopback exemption list if we modified it.
        if loopback_exemption {
            restore_loopback_exemption(loopback_prev, loopback_prev_count);
        }

        // 7c. Cleanup: free SIDs and delete the profile.
        do_cleanup(name, ac_sid);

        exit_code
    }

    unsafe fn do_cleanup(name: &str, ac_sid: *mut std::ffi::c_void) {
        // ac_sid was returned by CreateAppContainerProfile; free it with FreeSid
        // per the Win32 docs. The capability SIDs (from CreateWellKnownSid into
        // caller-owned Vec<u8> buffers) must NOT be passed to FreeSid — that is
        // only valid for AllocateAndInitializeSid memory. They are freed when
        // cap_bufs drops in the caller.
        if !ac_sid.is_null() {
            FreeSid(ac_sid);
        }
        // Delete the profile (best-effort; failure is logged but non-fatal).
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
