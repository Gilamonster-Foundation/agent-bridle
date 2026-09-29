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
//! agent-bridle-aclaunch [--name <container-name>] [--net-allow] [--nul-device-ace] <exe> [args...]
//! ```
//!
//! * `--name <n>` — AppContainer profile name.  Must be unique per run.  If
//!   omitted a name is derived from the current PID.
//! * `--net-allow` — grant `INTERNET_CLIENT` + `INTERNET_CLIENT_SERVER` +
//!   `PRIVATE_NETWORK_CLIENT_SERVER` capability SIDs.  Without this flag no
//!   network capability SIDs are granted (deny-by-default egress).
//! * `--nul-device-ace` — explicit, default-off compatibility widening for
//!   native Git on affected Windows Server policies. It temporarily grants this
//!   launch's AppContainer SID read/write access to the host `\\.\NUL` device
//!   DACL; it requires `WRITE_DAC` and fails closed if unavailable. See
//!   `SECURITY.md` before using it directly.
//! * `<exe>` — absolute or `PATH`-resolved executable.
//! * `[args...]` — arguments forwarded verbatim to the child process.
//!
//! The launcher creates a temporary AppContainer profile, spawns the child, and
//! deletes the profile after the child exits. If an opted-in NUL-device ACE
//! cannot be revoked, it deliberately retains that profile so a later launch
//! cannot recreate the deterministic SID. Profile deletion is otherwise
//! best-effort.
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
    use std::fs::OpenOptions;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::{AsRawHandle, AsRawSocket};

    use windows_sys::Win32::Foundation::{
        CloseHandle, LocalFree, SetHandleInformation, ERROR_SUCCESS, HANDLE, HANDLE_FLAG_INHERIT,
        INVALID_HANDLE_VALUE, WAIT_ABANDONED, WAIT_OBJECT_0,
    };
    use windows_sys::Win32::NetworkManagement::WindowsFirewall::{
        NetworkIsolationGetAppContainerConfig, NetworkIsolationSetAppContainerConfig,
    };
    use windows_sys::Win32::Security::Authorization::{
        GetNamedSecurityInfoW, GetSecurityInfo, SetEntriesInAclW, SetNamedSecurityInfoW,
        SetSecurityInfo, EXPLICIT_ACCESS_W, GRANT_ACCESS, NO_MULTIPLE_TRUSTEE, REVOKE_ACCESS,
        SET_ACCESS, SE_FILE_OBJECT, TRUSTEE_IS_SID, TRUSTEE_IS_UNKNOWN, TRUSTEE_W,
    };
    use windows_sys::Win32::Security::Isolation::{
        CreateAppContainerProfile, DeleteAppContainerProfile,
    };
    use windows_sys::Win32::Security::{
        CreateWellKnownSid, DeleteAce, EqualSid, FreeSid, GetAce,
        WinCapabilityInternetClientServerSid, WinCapabilityInternetClientSid,
        WinCapabilityPrivateNetworkClientServerSid, ACCESS_ALLOWED_ACE, ACE_HEADER, ACL,
        CONTAINER_INHERIT_ACE, DACL_SECURITY_INFORMATION, NO_INHERITANCE, OBJECT_INHERIT_ACE,
        SECURITY_ATTRIBUTES, SECURITY_CAPABILITIES, SID_AND_ATTRIBUTES,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING, READ_CONTROL, WRITE_DAC,
    };
    use windows_sys::Win32::System::Console::{
        GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
    };
    use windows_sys::Win32::System::Memory::{GetProcessHeap, HeapFree};
    use windows_sys::Win32::System::Pipes::CreatePipe;
    use windows_sys::Win32::System::SystemServices::ACCESS_ALLOWED_ACE_TYPE;
    use windows_sys::Win32::System::Threading::{
        CreateMutexW, CreateProcessW, DeleteProcThreadAttributeList, GetExitCodeProcess,
        InitializeProcThreadAttributeList, ReleaseMutex, UpdateProcThreadAttribute,
        WaitForSingleObject, EXTENDED_STARTUPINFO_PRESENT, INFINITE, PROCESS_INFORMATION,
        PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
        STARTF_USESTDHANDLES, STARTUPINFOEXW, STARTUPINFOW,
    };

    // PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY = ProcThreadAttributeValue(14, FALSE, TRUE, FALSE)
    // = (14 & 0xFFFF) | PROC_THREAD_ATTRIBUTE_INPUT (0x00020000) = 0x0002000E
    const PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY: usize = 0x0002000E;
    // PROCESS_CREATION_CHILD_PROCESS_RESTRICTED: the process may not create child processes.
    const PROCESS_CREATION_CHILD_PROCESS_RESTRICTED: u32 = 1;

    // FILE_GENERIC_READ / FILE_GENERIC_WRITE from the Windows SDK (WinNT.h).
    const FILE_GENERIC_READ: u32 = 0x00120089;
    const FILE_GENERIC_WRITE: u32 = 0x00120116;
    const FILE_GENERIC_EXECUTE: u32 = 0x001200A0;
    const FILE_GENERIC_READ_EXECUTE: u32 = FILE_GENERIC_READ | FILE_GENERIC_EXECUTE;
    const FILE_GENERIC_READ_WRITE_EXECUTE: u32 =
        FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE;

    /// NUL is a host device object rather than a normal filesystem path.  The
    /// named security APIs used for filesystem grants do not work for it; the
    /// device must be opened and updated through its HANDLE.
    const NUL_DEVICE: &str = r"\\.\NUL";
    const NUL_DEVICE_ACCESS: u32 = FILE_GENERIC_READ | FILE_GENERIC_WRITE;
    const NUL_DACL_MUTEX: &str = r"Global\agent-bridle-aclaunch-nul-device-dacl-v1";
    const HRESULT_ERROR_ALREADY_EXISTS: i32 = -2_147_024_713;

    struct TestPipeCanary {
        read: HANDLE,
        write: HANDLE,
    }

    impl Drop for TestPipeCanary {
        fn drop(&mut self) {
            unsafe {
                if !self.read.is_null() && self.read != INVALID_HANDLE_VALUE {
                    CloseHandle(self.read);
                }
                if !self.write.is_null() && self.write != INVALID_HANDLE_VALUE {
                    CloseHandle(self.write);
                }
            }
        }
    }

    struct TestSocketCanary {
        _peer: std::net::TcpStream,
        _canary: std::net::TcpStream,
    }

    /// Null-terminate an `OsStr` as a `Vec<u16>`.
    fn to_wide(s: &OsStr) -> Vec<u16> {
        s.encode_wide().chain(std::iter::once(0)).collect()
    }

    /// Grant `ac_sid` the given `access_mask` on `path` (inheriting into subdirs).
    ///
    /// Gets the existing DACL, merges in an `EXPLICIT_ACCESS` ACE for the
    /// AppContainer SID, and applies the merged DACL. Returns `true` on success.
    unsafe fn grant_path_access(
        path: &str,
        ac_sid: *mut std::ffi::c_void,
        access_mask: u32,
    ) -> bool {
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
            return false;
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
            return false;
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

        LocalFree(p_sd);
        err == ERROR_SUCCESS
    }

    /// Revoke only the explicit ACE for this launcher's AppContainer SID.
    ///
    /// Whole-DACL snapshot/restore is unsafe when two launchers overlap on the
    /// same path: the first cleanup can erase the second live grant, and the
    /// second cleanup can resurrect the first expired grant. Each profile name
    /// maps to a unique AppContainer SID, so scoped REVOKE_ACCESS cleanup removes
    /// only this launcher's ACE.
    unsafe fn revoke_path_access(path: &str, ac_sid: *mut std::ffi::c_void) {
        if ac_sid.is_null() {
            return;
        }
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
            return;
        }

        let ea = EXPLICIT_ACCESS_W {
            grfAccessPermissions: 0,
            grfAccessMode: REVOKE_ACCESS,
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
        if err == ERROR_SUCCESS {
            let err = SetNamedSecurityInfoW(
                path_w.as_ptr() as *mut _,
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                p_new_dacl,
                std::ptr::null_mut(),
            );
            if err != ERROR_SUCCESS {
                eprintln!(
                    "agent-bridle-aclaunch: cleanup could not revoke AppContainer ACE \
                     from {path:?}: {err}"
                );
            }
            LocalFree(p_new_dacl as *mut _);
        } else {
            eprintln!(
                "agent-bridle-aclaunch: cleanup could not build AppContainer ACE \
                 revocation for {path:?}: {err}"
            );
        }
        LocalFree(p_sd);
    }

    unsafe fn revoke_path_grants(fs_grants: Vec<String>, ac_sid: *mut std::ffi::c_void) {
        for path in fs_grants {
            revoke_path_access(&path, ac_sid);
        }
    }

    /// A cross-launch lock for a single NUL-device DACL read-modify-write
    /// operation.  The lock is deliberately held only while adding or removing
    /// an ACE, never while the child runs: a per-launch AppContainer SID makes
    /// the two live grants independent once the mutation is serialized.
    struct NulDeviceDaclLock {
        handle: HANDLE,
    }

    impl Drop for NulDeviceDaclLock {
        fn drop(&mut self) {
            unsafe {
                let _ = ReleaseMutex(self.handle);
                let _ = CloseHandle(self.handle);
            }
        }
    }

    unsafe fn lock_nul_device_dacl() -> Result<NulDeviceDaclLock, String> {
        let mutex_name = to_wide(OsStr::new(NUL_DACL_MUTEX));
        let handle = CreateMutexW(std::ptr::null(), 0, mutex_name.as_ptr());
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            return Err(format!(
                "could not create the NUL-device DACL mutex: {:?}",
                std::io::Error::last_os_error()
            ));
        }

        match WaitForSingleObject(handle, INFINITE) {
            WAIT_OBJECT_0 => Ok(NulDeviceDaclLock { handle }),
            WAIT_ABANDONED => {
                // A prior launcher crashed while updating the DACL.  We own the
                // mutex now, so serialize this mutation; a dead-SID ACE may be
                // left behind and is documented as the residual crash risk.
                eprintln!(
                    "agent-bridle-aclaunch: acquired abandoned NUL-device DACL mutex; \
                     a prior crashed launch may have left a dead-SID ACE"
                );
                Ok(NulDeviceDaclLock { handle })
            }
            result => {
                CloseHandle(handle);
                Err(format!(
                    "could not acquire the NUL-device DACL mutex (WaitForSingleObject={result}): {:?}",
                    std::io::Error::last_os_error()
                ))
            }
        }
    }

    unsafe fn open_nul_for_dacl() -> Result<HANDLE, String> {
        let device = to_wide(OsStr::new(NUL_DEVICE));
        let handle = CreateFileW(
            device.as_ptr(),
            READ_CONTROL | WRITE_DAC,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            std::ptr::null(),
            OPEN_EXISTING,
            0,
            std::ptr::null_mut(),
        );
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            return Err(format!(
                "could not open {NUL_DEVICE:?} with READ_CONTROL | WRITE_DAC; \
                 the explicit --nul-device-ace grant requires WRITE_DAC and refuses before spawn: {:?}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(handle)
    }

    /// Add exactly one non-inheriting `FILE_GENERIC_READ | FILE_GENERIC_WRITE`
    /// ACE for this launch's AppContainer SID to the host NUL device.
    ///
    /// `SET_ACCESS` gives this fresh SID a single exact ACE.  This must not use
    /// the named file-security APIs: `\\.\NUL` is a device object and only the
    /// handle-based APIs reliably update its DACL.
    unsafe fn grant_nul_device_access(
        ac_sid: *mut std::ffi::c_void,
        force_write_dac_denied: bool,
        force_cleanup_failure: bool,
    ) -> Result<(), String> {
        if ac_sid.is_null() {
            return Err("AppContainer SID is null; cannot grant NUL-device access".to_string());
        }
        // Test-only: take the same post-setup grant failure path without
        // touching the host device DACL on a developer workstation.
        if force_write_dac_denied {
            return Err(
                "forced NUL device ACE refusal: missing WRITE_DAC; refusing before spawn"
                    .to_string(),
            );
        }
        // Test-only: model a completed grant followed by an irrecoverable
        // cleanup failure without touching the shared host device DACL. The
        // test asserts that the profile is retained as the SID-reuse guard.
        if force_cleanup_failure {
            return Ok(());
        }
        let _lock = lock_nul_device_dacl()?;
        let handle = open_nul_for_dacl()?;

        let mut old_dacl: *mut ACL = std::ptr::null_mut();
        let mut descriptor: *mut std::ffi::c_void = std::ptr::null_mut();
        let get_result = GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut old_dacl,
            std::ptr::null_mut(),
            &mut descriptor,
        );
        if get_result != ERROR_SUCCESS {
            if !descriptor.is_null() {
                LocalFree(descriptor);
            }
            CloseHandle(handle);
            return Err(format!(
                "could not read {NUL_DEVICE:?} DACL after requesting WRITE_DAC (GetSecurityInfo={get_result}); \
                 refusing before spawn"
            ));
        }

        let entry = EXPLICIT_ACCESS_W {
            grfAccessPermissions: NUL_DEVICE_ACCESS,
            grfAccessMode: SET_ACCESS,
            grfInheritance: NO_INHERITANCE,
            Trustee: TRUSTEE_W {
                pMultipleTrustee: std::ptr::null_mut(),
                MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
                TrusteeForm: TRUSTEE_IS_SID,
                TrusteeType: TRUSTEE_IS_UNKNOWN,
                ptstrName: ac_sid.cast(),
            },
        };
        let mut new_dacl: *mut ACL = std::ptr::null_mut();
        let merge_result = SetEntriesInAclW(1, &entry, old_dacl, &mut new_dacl);
        if merge_result != ERROR_SUCCESS {
            LocalFree(descriptor);
            CloseHandle(handle);
            return Err(format!(
                "could not build the explicit {NUL_DEVICE:?} ACE (SetEntriesInAclW={merge_result}); \
                 refusing before spawn"
            ));
        }

        let set_result = SetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            new_dacl,
            std::ptr::null_mut(),
        );
        LocalFree(new_dacl.cast());
        LocalFree(descriptor);
        CloseHandle(handle);
        if set_result != ERROR_SUCCESS {
            return Err(format!(
                "could not apply the explicit {NUL_DEVICE:?} ACE (SetSecurityInfo={set_result}); \
                 refusing before spawn"
            ));
        }
        Ok(())
    }

    fn is_this_launch_nul_ace(ace: &ACCESS_ALLOWED_ACE, ac_sid: *mut std::ffi::c_void) -> bool {
        if u32::from(ace.Header.AceType) != ACCESS_ALLOWED_ACE_TYPE
            || ace.Header.AceFlags != NO_INHERITANCE as u8
            || ace.Mask != NUL_DEVICE_ACCESS
        {
            return false;
        }
        let ace_sid = std::ptr::addr_of!(ace.SidStart)
            .cast_mut()
            .cast::<std::ffi::c_void>();
        unsafe { EqualSid(ace_sid, ac_sid) != 0 }
    }

    /// Remove only the exact ACE created by [`grant_nul_device_access`].
    ///
    /// In particular, this does not restore a saved DACL and does not remove a
    /// broader/narrower ACE for the same SID.  The cross-launch mutex protects
    /// the device DACL read-modify-write window, so one launch's cleanup cannot
    /// erase another fresh AppContainer SID's live grant.
    unsafe fn revoke_nul_device_access(ac_sid: *mut std::ffi::c_void) -> Result<(), String> {
        if ac_sid.is_null() {
            return Ok(());
        }
        let _lock = lock_nul_device_dacl()?;
        let handle = open_nul_for_dacl()?;

        let mut dacl: *mut ACL = std::ptr::null_mut();
        let mut descriptor: *mut std::ffi::c_void = std::ptr::null_mut();
        let get_result = GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut dacl,
            std::ptr::null_mut(),
            &mut descriptor,
        );
        if get_result != ERROR_SUCCESS {
            if !descriptor.is_null() {
                LocalFree(descriptor);
            }
            CloseHandle(handle);
            return Err(format!(
                "could not read {NUL_DEVICE:?} DACL during cleanup (GetSecurityInfo={get_result})"
            ));
        }

        let mut matching_ace: Option<u32> = None;
        if !dacl.is_null() {
            for index in 0..u32::from((*dacl).AceCount) {
                let mut raw: *mut std::ffi::c_void = std::ptr::null_mut();
                if GetAce(dacl, index, &mut raw) == 0 {
                    LocalFree(descriptor);
                    CloseHandle(handle);
                    return Err(format!(
                        "GetAce({index}) failed while cleaning up {NUL_DEVICE:?}"
                    ));
                }
                let header = &*raw.cast::<ACE_HEADER>();
                if u32::from(header.AceType) != ACCESS_ALLOWED_ACE_TYPE {
                    continue;
                }
                let ace = &*raw.cast::<ACCESS_ALLOWED_ACE>();
                if is_this_launch_nul_ace(ace, ac_sid) && matching_ace.replace(index).is_some() {
                    LocalFree(descriptor);
                    CloseHandle(handle);
                    return Err(format!(
                        "found multiple exact {NUL_DEVICE:?} ACEs for one launch SID; \
                         refusing ambiguous cleanup"
                    ));
                }
            }
        }

        let result = if let Some(index) = matching_ace {
            if DeleteAce(dacl, index) == 0 {
                Err(format!(
                    "DeleteAce({index}) failed while cleaning up {NUL_DEVICE:?}: {:?}",
                    std::io::Error::last_os_error()
                ))
            } else {
                let set_result = SetSecurityInfo(
                    handle,
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    dacl,
                    std::ptr::null_mut(),
                );
                if set_result == ERROR_SUCCESS {
                    Ok(())
                } else {
                    Err(format!(
                        "could not apply exact {NUL_DEVICE:?} ACE removal (SetSecurityInfo={set_result})"
                    ))
                }
            }
        } else {
            // A failed grant may have reached cleanup before `SetSecurityInfo`
            // completed.  No matching ACE is safe and needs no broader action.
            Ok(())
        };
        LocalFree(descriptor);
        CloseHandle(handle);
        result
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

    /// Return the launcher stdio handles that are intentionally delegated to the
    /// child. Each handle is made inheritable so Windows accepts it in
    /// PROC_THREAD_ATTRIBUTE_HANDLE_LIST; no other inheritable HANDLE is listed.
    unsafe fn delegated_stdio_handles() -> Vec<HANDLE> {
        let mut handles = Vec::new();
        for id in [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
            let handle = GetStdHandle(id);
            if handle.is_null() || handle == INVALID_HANDLE_VALUE {
                continue;
            }
            let ok = SetHandleInformation(handle, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
            if ok == 0 {
                eprintln!(
                    "agent-bridle-aclaunch: SetHandleInformation(stdio) failed: {:?}",
                    std::io::Error::last_os_error()
                );
                std::process::exit(1);
            }
            handles.push(handle);
        }
        handles.sort_unstable();
        handles.dedup();
        handles
    }

    /// A parsed launcher invocation: the confinement knobs plus the exec target.
    /// Kept as a plain value (no Win32 handles) so [`parse_launcher_args`] is a
    /// pure function the unit tests can exercise without spawning anything.
    #[derive(Debug, PartialEq, Eq)]
    pub(crate) struct LauncherArgs {
        pub container_name: Option<String>,
        pub net_allow: bool,
        pub loopback_exemption: bool,
        pub nul_device_ace: bool,
        pub no_child_process: bool,
        pub test_inheritable_file_handle: Option<String>,
        pub test_inheritable_pipe_handle: bool,
        pub test_inheritable_socket_handle: bool,
        pub test_force_process_attribute_failure: bool,
        pub test_force_nul_write_dac_denied: bool,
        pub test_force_nul_cleanup_failure: bool,
        pub fs_read: Vec<String>,
        pub fs_write: Vec<String>,
        pub exe: String,
        pub child_args: Vec<String>,
    }

    /// Parse the launcher arguments (everything after `argv[0]`) into a
    /// [`LauncherArgs`], or `Err(exit_code)` on a usage error (no exec target).
    ///
    /// Leading `--flag` tokens are the launcher's own; the **first non-flag token**
    /// is the exec target and everything after it is forwarded verbatim as the
    /// child's args (so a child may legitimately take its own `--`-prefixed flags).
    /// Pure — no env reads, no process exit — so it is unit-testable.
    pub(crate) fn parse_launcher_args(argv: &[String]) -> Result<LauncherArgs, u32> {
        let mut container_name: Option<String> = None;
        let mut net_allow = false;
        let mut loopback_exemption = false;
        let mut nul_device_ace = false;
        let mut no_child_process = false;
        let mut test_inheritable_file_handle: Option<String> = None;
        let mut test_inheritable_pipe_handle = false;
        let mut test_inheritable_socket_handle = false;
        let mut test_force_process_attribute_failure = false;
        let mut test_force_nul_write_dac_denied = false;
        let mut test_force_nul_cleanup_failure = false;
        let mut fs_read: Vec<String> = Vec::new();
        let mut fs_write: Vec<String> = Vec::new();
        let mut i = 0usize;
        while i < argv.len() {
            match argv[i].as_str() {
                "--name" => {
                    i += 1;
                    container_name = argv.get(i).cloned();
                }
                "--net-allow" => net_allow = true,
                "--loopback-exemption" => loopback_exemption = true,
                "--nul-device-ace" => nul_device_ace = true,
                "--no-child-process" => no_child_process = true,
                "--test-inheritable-file-handle" => {
                    i += 1;
                    test_inheritable_file_handle = argv.get(i).cloned();
                }
                "--test-inheritable-pipe-handle" => test_inheritable_pipe_handle = true,
                "--test-inheritable-socket-handle" => test_inheritable_socket_handle = true,
                "--test-force-process-attribute-failure" => {
                    test_force_process_attribute_failure = true;
                }
                "--test-force-nul-write-dac-denied" => {
                    test_force_nul_write_dac_denied = true;
                }
                "--test-force-nul-cleanup-failure" => {
                    test_force_nul_cleanup_failure = true;
                }
                "--fs-read" => {
                    i += 1;
                    if let Some(p) = argv.get(i) {
                        fs_read.push(p.clone());
                    }
                }
                "--fs-write" => {
                    i += 1;
                    if let Some(p) = argv.get(i) {
                        fs_write.push(p.clone());
                    }
                }
                _ => break,
            }
            i += 1;
        }
        if i >= argv.len() {
            return Err(2);
        }
        Ok(LauncherArgs {
            container_name,
            net_allow,
            loopback_exemption,
            nul_device_ace,
            no_child_process,
            test_inheritable_file_handle,
            test_inheritable_pipe_handle,
            test_inheritable_socket_handle,
            test_force_process_attribute_failure,
            test_force_nul_write_dac_denied,
            test_force_nul_cleanup_failure,
            fs_read,
            fs_write,
            exe: argv[i].clone(),
            child_args: argv[i + 1..].to_vec(),
        })
    }

    pub fn run() {
        let args: Vec<String> = std::env::args().collect();
        let parsed = match parse_launcher_args(&args[1..]) {
            Ok(p) => p,
            Err(code) => {
                eprintln!(
                    "usage: agent-bridle-aclaunch [--name <n>] [--net-allow] \
                     [--loopback-exemption] [--no-child-process] [--fs-read <path>]... \
                     [--fs-write <path>]... [--nul-device-ace] <exe> [args...]"
                );
                std::process::exit(code as i32);
            }
        };

        let name = parsed
            .container_name
            .unwrap_or_else(|| format!("ab{}", std::process::id()));
        let exit_code = unsafe {
            spawn_in_container(
                &name,
                parsed.net_allow,
                parsed.loopback_exemption,
                parsed.nul_device_ace,
                parsed.no_child_process,
                parsed.test_inheritable_file_handle.as_deref(),
                parsed.test_inheritable_pipe_handle,
                parsed.test_inheritable_socket_handle,
                parsed.test_force_process_attribute_failure,
                parsed.test_force_nul_write_dac_denied,
                parsed.test_force_nul_cleanup_failure,
                &parsed.fs_read,
                &parsed.fs_write,
                &parsed.exe,
                &parsed.child_args,
            )
        };
        std::process::exit(exit_code as i32);
    }

    /// Create an AppContainer profile, spawn `exe` inside it, wait, and return
    /// the child's exit code.  Cleans up the profile before returning.
    // Each parameter is a distinct, independent Win32 spawn knob (network
    // capabilities, loopback exemption, child-process policy, the two fs ACL
    // lists, and the exec target) — bundling them into a struct would only move
    // the same fields behind one more indirection without improving clarity.
    #[allow(clippy::too_many_arguments)]
    unsafe fn spawn_in_container(
        name: &str,
        net_allow: bool,
        loopback_exemption: bool,
        nul_device_ace: bool,
        no_child_process: bool,
        test_inheritable_file_handle: Option<&str>,
        test_inheritable_pipe_handle: bool,
        test_inheritable_socket_handle: bool,
        test_force_process_attribute_failure: bool,
        test_force_nul_write_dac_denied: bool,
        test_force_nul_cleanup_failure: bool,
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

        // 0x800700b7 == HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS). A profile
        // name deterministically identifies its SID. Never reuse a still-live
        // profile: an interrupted or failed NUL-device cleanup may have left an
        // ACE for that SID, and recreating it would reactivate the host grant.
        let hr = CreateAppContainerProfile(
            name_w.as_ptr(),
            display_w.as_ptr(),
            desc_w.as_ptr(),
            std::ptr::null(),
            0,
            &mut ac_sid,
        );
        let existing_profile = hr == HRESULT_ERROR_ALREADY_EXISTS;
        if hr != 0 && !existing_profile {
            eprintln!(
                "agent-bridle-aclaunch: CreateAppContainerProfile({name:?}) failed: \
                 HRESULT={hr:#010x}"
            );
            std::process::exit(1);
        }
        if ac_sid.is_null() {
            if nul_device_ace {
                eprintln!(
                    "agent-bridle-aclaunch: --nul-device-ace requires a fresh unique --name; \
                     AppContainer profile {name:?} did not return a fresh SID and cannot \
                     safely own a per-launch device ACE"
                );
                std::process::exit(1);
            }
            eprintln!("agent-bridle-aclaunch: AppContainer SID is null after profile creation");
            std::process::exit(1);
        }

        if existing_profile && nul_device_ace {
            // The system does not return a fresh SID for an existing profile.
            // The opt-in must never attach a per-launch device ACE to an
            // existing deterministic SID, even if a future Windows release
            // happens to return one here.
            FreeSid(ac_sid);
            eprintln!(
                "agent-bridle-aclaunch: --nul-device-ace requires a fresh unique --name; \
                 existing AppContainer profile {name:?} would make per-launch cleanup ambiguous"
            );
            std::process::exit(1);
        }
        // Test-only canary for #319: create a deliberately inheritable launcher
        // HANDLE. The child receives only its numeric value; whether it can use
        // the HANDLE depends solely on process creation inheritance policy.
        let _test_canary_file = if let Some(path) = test_inheritable_file_handle {
            let file = OpenOptions::new()
                .append(true)
                .open(path)
                .unwrap_or_else(|error| {
                    eprintln!(
                        "agent-bridle-aclaunch: could not open test canary file {path:?}: {error}"
                    );
                    do_cleanup(name, ac_sid);
                    std::process::exit(1);
                });
            let handle = file.as_raw_handle() as HANDLE;
            let ok = SetHandleInformation(handle, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
            if ok == 0 {
                eprintln!(
                    "agent-bridle-aclaunch: SetHandleInformation(test canary) failed: {:?}",
                    std::io::Error::last_os_error()
                );
                do_cleanup(name, ac_sid);
                std::process::exit(1);
            }
            std::env::set_var("AB_TEST_CANARY_FILE_HANDLE", (handle as isize).to_string());
            Some(file)
        } else {
            None
        };
        let _test_canary_pipe = if test_inheritable_pipe_handle {
            let attrs = SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: std::ptr::null_mut(),
                bInheritHandle: 1,
            };
            let mut read: HANDLE = std::ptr::null_mut();
            let mut write: HANDLE = std::ptr::null_mut();
            let ok = CreatePipe(&mut read, &mut write, &attrs, 0);
            if ok == 0 {
                eprintln!(
                    "agent-bridle-aclaunch: CreatePipe(test canary) failed: {:?}",
                    std::io::Error::last_os_error()
                );
                do_cleanup(name, ac_sid);
                std::process::exit(1);
            }
            let pipe = TestPipeCanary { read, write };
            let ok = SetHandleInformation(pipe.read, HANDLE_FLAG_INHERIT, 0);
            if ok == 0 {
                eprintln!(
                    "agent-bridle-aclaunch: SetHandleInformation(test canary pipe read) \
                     failed: {:?}",
                    std::io::Error::last_os_error()
                );
                do_cleanup(name, ac_sid);
                std::process::exit(1);
            }
            std::env::set_var(
                "AB_TEST_CANARY_PIPE_HANDLE",
                (pipe.write as isize).to_string(),
            );
            Some(pipe)
        } else {
            None
        };
        let _test_canary_socket = if test_inheritable_socket_handle {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| {
                eprintln!("agent-bridle-aclaunch: create socket canary listener failed: {error}");
                do_cleanup(name, ac_sid);
                std::process::exit(1);
            });
            let addr = listener.local_addr().unwrap_or_else(|error| {
                eprintln!("agent-bridle-aclaunch: read socket canary address failed: {error}");
                do_cleanup(name, ac_sid);
                std::process::exit(1);
            });
            let peer = std::net::TcpStream::connect(addr).unwrap_or_else(|error| {
                eprintln!("agent-bridle-aclaunch: connect socket canary peer failed: {error}");
                do_cleanup(name, ac_sid);
                std::process::exit(1);
            });
            let (canary, _) = listener.accept().unwrap_or_else(|error| {
                eprintln!("agent-bridle-aclaunch: accept socket canary failed: {error}");
                do_cleanup(name, ac_sid);
                std::process::exit(1);
            });
            let socket = canary.as_raw_socket() as HANDLE;
            let ok = SetHandleInformation(socket, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
            if ok == 0 {
                eprintln!(
                    "agent-bridle-aclaunch: SetHandleInformation(test canary socket) \
                     failed: {:?}",
                    std::io::Error::last_os_error()
                );
                do_cleanup(name, ac_sid);
                std::process::exit(1);
            }
            std::env::set_var(
                "AB_TEST_CANARY_SOCKET_HANDLE",
                (socket as isize).to_string(),
            );
            Some(TestSocketCanary {
                _peer: peer,
                _canary: canary,
            })
        } else {
            None
        };

        // 2a. FS ACL narrowing (#51, ADR 0009): grant the AppContainer SID access to
        //     the requested paths so the sandboxed process can read/write its workspace.
        //     AppContainers are denied user directories by default; without this grant
        //     the child cannot access its working directory.
        //     We track each granted path so cleanup can revoke only this profile
        //     SID's explicit ACE after the child exits. Whole-DACL snapshot/restore
        //     is unsafe under overlapping launches on the same resource.
        let mut fs_grants: Vec<String> = Vec::new();

        // Grant read+write for write paths first (superset of read).
        for path in fs_write {
            let granted = grant_path_access(path, ac_sid, FILE_GENERIC_READ_WRITE_EXECUTE);
            if !granted {
                eprintln!(
                    "agent-bridle-aclaunch: could not grant write access to {path:?}; \
                     refusing before spawn because the requested fs_write witness is unavailable"
                );
                revoke_path_grants(fs_grants, ac_sid);
                do_cleanup(name, ac_sid);
                std::process::exit(1);
            }
            fs_grants.push(path.clone());
        }
        // Grant read-only for remaining read paths not already granted.
        for path in fs_read {
            if fs_grants.iter().any(|p| p == path) {
                continue;
            }
            let granted = grant_path_access(path, ac_sid, FILE_GENERIC_READ_EXECUTE);
            if !granted {
                eprintln!(
                    "agent-bridle-aclaunch: could not grant read access to {path:?}; \
                     refusing before spawn because the requested fs_read witness is unavailable"
                );
                revoke_path_grants(fs_grants, ac_sid);
                do_cleanup(name, ac_sid);
                std::process::exit(1);
            }
            fs_grants.push(path.clone());
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

        // 4. Attribute list. Slots: always one for SECURITY_CAPABILITIES;
        //    one more for the explicit stdio HANDLE allow-list; and one more
        //    when --no-child-process applies.
        let mut delegated_handles = delegated_stdio_handles();
        let has_handle_list = !delegated_handles.is_empty();
        let slot_count: u32 = 1 + u32::from(no_child_process) + u32::from(has_handle_list);
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
            revoke_path_grants(fs_grants, ac_sid);
            if loopback_exemption {
                restore_loopback_exemption(loopback_prev, loopback_prev_count);
            }
            do_cleanup(name, ac_sid);
            std::process::exit(1);
        }

        if test_force_process_attribute_failure {
            eprintln!(
                "agent-bridle-aclaunch: forced process-attribute failure; refusing before spawn"
            );
            DeleteProcThreadAttributeList(attr_list);
            revoke_path_grants(fs_grants, ac_sid);
            if loopback_exemption {
                restore_loopback_exemption(loopback_prev, loopback_prev_count);
            }
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
            revoke_path_grants(fs_grants, ac_sid);
            if loopback_exemption {
                restore_loopback_exemption(loopback_prev, loopback_prev_count);
            }
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
                revoke_path_grants(fs_grants, ac_sid);
                if loopback_exemption {
                    restore_loopback_exemption(loopback_prev, loopback_prev_count);
                }
                do_cleanup(name, ac_sid);
                std::process::exit(1);
            }
        }

        if has_handle_list {
            let ok = UpdateProcThreadAttribute(
                attr_list,
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                delegated_handles.as_mut_ptr().cast(),
                delegated_handles.len() * std::mem::size_of::<HANDLE>(),
                std::ptr::null_mut(),
                std::ptr::null(),
            );
            if ok == 0 {
                eprintln!(
                    "agent-bridle-aclaunch: UpdateProcThreadAttribute(HANDLE_LIST) \
                     failed: {:?}",
                    std::io::Error::last_os_error()
                );
                DeleteProcThreadAttributeList(attr_list);
                revoke_path_grants(fs_grants, ac_sid);
                if loopback_exemption {
                    restore_loopback_exemption(loopback_prev, loopback_prev_count);
                }
                do_cleanup(name, ac_sid);
                std::process::exit(1);
            }
        }

        // 5. Spawn the child inside the AppContainer. Stdio is delegated by the
        //    HANDLE_LIST above; arbitrary inheritable launcher handles are not.
        let cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
        // SAFETY: zero-init is valid for STARTUPINFOW (all pointer fields are
        // allowed to be NULL per Win32 docs when STARTF_USESTDHANDLES is unset).
        let mut startup_info_ex: STARTUPINFOEXW = std::mem::zeroed();
        startup_info_ex.StartupInfo.cb = cb;
        if has_handle_list {
            startup_info_ex.StartupInfo.dwFlags |= STARTF_USESTDHANDLES;
            startup_info_ex.StartupInfo.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
            startup_info_ex.StartupInfo.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
            startup_info_ex.StartupInfo.hStdError = GetStdHandle(STD_ERROR_HANDLE);
        }
        startup_info_ex.lpAttributeList = attr_list;

        // 4b. Native Git for Windows currently opens `\\.\NUL` independently
        // of its inherited stdio handles (#408).  This is an explicit,
        // default-off compatibility escape hatch: grant one exact ACE to this
        // fresh AppContainer SID immediately before spawning, then remove that
        // exact ACE on both the CreateProcess failure path and normal exit.
        // It is intentionally later than every other setup failure so there is
        // no unbracketed `process::exit` after the host-device DACL mutation.
        let nul_device_ace_granted = if nul_device_ace {
            match grant_nul_device_access(
                ac_sid,
                test_force_nul_write_dac_denied,
                test_force_nul_cleanup_failure,
            ) {
                Ok(()) => true,
                Err(error) => {
                    eprintln!(
                        "agent-bridle-aclaunch: {error}; refusing before spawn without a NUL-device fallback"
                    );
                    // The forced WRITE_DAC seam returns before any device
                    // access. For a real SetSecurityInfo failure, defensively
                    // remove an exact matching ACE in case the OS reports an
                    // ambiguous partial application.
                    let nul_cleanup_failed = if test_force_nul_write_dac_denied {
                        false
                    } else {
                        match revoke_nul_device_access(ac_sid) {
                            Ok(()) => false,
                            Err(cleanup_error) => {
                                eprintln!(
                                    "agent-bridle-aclaunch: cleanup after failed NUL-device ACE grant also failed: {cleanup_error}"
                                );
                                true
                            }
                        }
                    };
                    DeleteProcThreadAttributeList(attr_list);
                    revoke_path_grants(fs_grants, ac_sid);
                    if loopback_exemption {
                        restore_loopback_exemption(loopback_prev, loopback_prev_count);
                    }
                    if nul_cleanup_failed {
                        retain_profile_after_nul_cleanup_failure(name, ac_sid);
                    } else {
                        do_cleanup(name, ac_sid);
                    }
                    std::process::exit(1);
                }
            }
        } else {
            false
        };

        let mut cmd_line = build_cmdline(exe, child_args);
        let mut proc_info: PROCESS_INFORMATION = std::mem::zeroed();

        let ok = CreateProcessW(
            std::ptr::null(),             // lpApplicationName: derive from command line
            cmd_line.as_mut_ptr(),        // lpCommandLine: mutable per Win32 docs
            std::ptr::null(),             // lpProcessAttributes
            std::ptr::null(),             // lpThreadAttributes
            has_handle_list as i32,       // bInheritHandles: restricted by HANDLE_LIST
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
            let nul_cleanup_failed = if nul_device_ace_granted {
                let cleanup = if test_force_nul_cleanup_failure {
                    Err("forced NUL-device ACE cleanup failure".to_string())
                } else {
                    revoke_nul_device_access(ac_sid)
                };
                match cleanup {
                    Ok(()) => false,
                    Err(error) => {
                        eprintln!(
                            "agent-bridle-aclaunch: cleanup could not revoke this launch's NUL-device ACE: {error}"
                        );
                        true
                    }
                }
            } else {
                false
            };
            revoke_path_grants(fs_grants, ac_sid);
            if loopback_exemption {
                restore_loopback_exemption(loopback_prev, loopback_prev_count);
            }
            if nul_cleanup_failed {
                retain_profile_after_nul_cleanup_failure(name, ac_sid);
            } else {
                do_cleanup(name, ac_sid);
            }
            std::process::exit(1);
        }

        // Thread handle is not needed; close it immediately.
        CloseHandle(proc_info.hThread);

        // 6. Wait for the child, collect its exit code.
        WaitForSingleObject(proc_info.hProcess as HANDLE, INFINITE);
        let mut exit_code: u32 = 1;
        GetExitCodeProcess(proc_info.hProcess as HANDLE, &mut exit_code);
        CloseHandle(proc_info.hProcess as HANDLE);

        // 7a. Revoke only this launch's exact NUL-device ACE. Treat a failure
        // as a launcher failure even if the child succeeded: otherwise the
        // caller could mistake a residual host-device grant for a clean exit.
        let nul_cleanup_failed = if nul_device_ace_granted {
            let cleanup = if test_force_nul_cleanup_failure {
                Err("forced NUL-device ACE cleanup failure".to_string())
            } else {
                revoke_nul_device_access(ac_sid)
            };
            match cleanup {
                Ok(()) => false,
                Err(error) => {
                    eprintln!(
                        "agent-bridle-aclaunch: cleanup could not revoke this launch's NUL-device ACE: {error}"
                    );
                    true
                }
            }
        } else {
            false
        };

        // 7b. Revoke this profile SID's explicit fs ACEs.
        revoke_path_grants(fs_grants, ac_sid);

        // 7c. Restore loopback exemption list if we modified it.
        if loopback_exemption {
            restore_loopback_exemption(loopback_prev, loopback_prev_count);
        }

        // 7d. Cleanup: a failed NUL revocation retains the profile as the
        // deterministic-SID reuse guard; all other paths delete it normally.
        if nul_cleanup_failed {
            retain_profile_after_nul_cleanup_failure(name, ac_sid);
        } else {
            do_cleanup(name, ac_sid);
        }

        if nul_cleanup_failed {
            1
        } else {
            exit_code
        }
    }

    /// Free the returned SID but deliberately retain the profile after a NUL
    /// cleanup failure. Its still-existing profile blocks a later launcher
    /// invocation from recreating the deterministic SID and inheriting a
    /// residual device ACE.
    unsafe fn retain_profile_after_nul_cleanup_failure(name: &str, ac_sid: *mut std::ffi::c_void) {
        if !ac_sid.is_null() {
            FreeSid(ac_sid);
        }
        eprintln!(
            "agent-bridle-aclaunch: retaining AppContainer profile {name:?} after NUL-device \
             ACE cleanup failure; a later launch with this name is refused to prevent SID reuse"
        );
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

    #[cfg(test)]
    mod tests {
        use super::{build_cmdline, parse_launcher_args, LauncherArgs};

        fn v(items: &[&str]) -> Vec<String> {
            items.iter().map(|s| (*s).to_string()).collect()
        }

        /// Decode the NUL-terminated UTF-16 `CreateProcessW` command line back to a
        /// `String` (dropping the trailing NUL) so quoting can be asserted directly.
        fn cmdline(program: &str, args: &[&str]) -> String {
            let w = build_cmdline(program, &v(args));
            assert_eq!(w.last(), Some(&0), "command line must be NUL-terminated");
            String::from_utf16(&w[..w.len() - 1]).expect("valid utf-16")
        }

        #[test]
        fn parse_bare_exe_only() {
            let a = parse_launcher_args(&v(&["cmd.exe"])).expect("parses");
            assert_eq!(
                a,
                LauncherArgs {
                    container_name: None,
                    net_allow: false,
                    loopback_exemption: false,
                    nul_device_ace: false,
                    no_child_process: false,
                    test_inheritable_file_handle: None,
                    test_inheritable_pipe_handle: false,
                    test_inheritable_socket_handle: false,
                    test_force_process_attribute_failure: false,
                    test_force_nul_write_dac_denied: false,
                    test_force_nul_cleanup_failure: false,
                    fs_read: vec![],
                    fs_write: vec![],
                    exe: "cmd.exe".to_string(),
                    child_args: vec![],
                }
            );
        }

        #[test]
        fn parse_all_flags_with_repeated_fs_paths() {
            let a = parse_launcher_args(&v(&[
                "--name",
                "ab42",
                "--net-allow",
                "--loopback-exemption",
                "--nul-device-ace",
                "--no-child-process",
                "--test-inheritable-socket-handle",
                "--test-force-nul-cleanup-failure",
                "--fs-write",
                "C:/ws",
                "--fs-read",
                "C:/etc",
                "--fs-read",
                "C:/lib",
                "child.exe",
                "arg1",
            ]))
            .expect("parses");
            assert_eq!(a.container_name.as_deref(), Some("ab42"));
            assert!(a.net_allow && a.loopback_exemption && a.nul_device_ace && a.no_child_process);
            assert_eq!(a.test_inheritable_file_handle, None);
            assert!(!a.test_inheritable_pipe_handle);
            assert!(a.test_inheritable_socket_handle);
            assert!(!a.test_force_process_attribute_failure);
            assert!(!a.test_force_nul_write_dac_denied);
            assert!(a.test_force_nul_cleanup_failure);
            assert_eq!(a.fs_write, v(&["C:/ws"]));
            assert_eq!(a.fs_read, v(&["C:/etc", "C:/lib"]));
            assert_eq!(a.exe, "child.exe");
            assert_eq!(a.child_args, v(&["arg1"]));
        }

        #[test]
        fn first_non_flag_is_exe_rest_are_child_args_even_if_dash_prefixed() {
            // A child's own `--foo` must be forwarded, not eaten by the launcher.
            let a = parse_launcher_args(&v(&["--net-allow", "child.exe", "--foo", "--fs-read"]))
                .expect("parses");
            assert!(a.net_allow);
            assert_eq!(a.exe, "child.exe");
            assert_eq!(a.child_args, v(&["--foo", "--fs-read"]));
        }

        #[test]
        fn missing_exec_target_is_usage_error() {
            assert_eq!(parse_launcher_args(&v(&[])), Err(2));
            assert_eq!(parse_launcher_args(&v(&["--net-allow"])), Err(2));
            // `--name` consuming the last token leaves no exe.
            assert_eq!(parse_launcher_args(&v(&["--name", "ab1"])), Err(2));
            // A dangling value-flag with no exe after it.
            assert_eq!(parse_launcher_args(&v(&["--fs-read", "C:/x"])), Err(2));
        }

        #[test]
        fn cmdline_leaves_plain_tokens_unquoted() {
            assert_eq!(cmdline("cmd.exe", &["echo", "hi"]), "cmd.exe echo hi");
        }

        #[test]
        fn cmdline_quotes_whitespace_and_empty() {
            assert_eq!(
                cmdline("C:/Program Files/a.exe", &["", "a b"]),
                "\"C:/Program Files/a.exe\" \"\" \"a b\""
            );
        }

        #[test]
        fn cmdline_escapes_embedded_quotes_and_backslashes() {
            // MSVC CommandLineToArgvW rules: `"` → `\"`; a backslash run before a
            // `"` is doubled; a trailing backslash inside a quoted token is doubled.
            assert_eq!(cmdline("p", &["a\"b"]), "p \"a\\\"b\"");
            assert_eq!(cmdline("p", &["a\\b"]), "p a\\b"); // no quoting needed
            assert_eq!(cmdline("p", &["a\\ b"]), "p \"a\\ b\""); // space ⇒ quoted, lone `\` literal
            assert_eq!(cmdline("p", &["a\\"]), "p a\\"); // no whitespace ⇒ unquoted, verbatim
            assert_eq!(cmdline("p", &["a\\\"b"]), "p \"a\\\\\\\"b\""); // `\"` ⇒ `\\\"`
        }
    }
}
