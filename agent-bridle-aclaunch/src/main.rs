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

    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, TRUE};
    use windows_sys::Win32::Security::Isolation::{
        CreateAppContainerProfile, DeleteAppContainerProfile,
    };
    use windows_sys::Win32::Security::{
        CreateWellKnownSid, FreeSid, WinCapabilityInternetClientServerSid,
        WinCapabilityInternetClientSid, WinCapabilityPrivateNetworkClientServerSid,
        SECURITY_CAPABILITIES, SID_AND_ATTRIBUTES,
    };
    use windows_sys::Win32::System::Threading::{
        CreateProcessW, DeleteProcThreadAttributeList, GetExitCodeProcess,
        InitializeProcThreadAttributeList, UpdateProcThreadAttribute, WaitForSingleObject,
        EXTENDED_STARTUPINFO_PRESENT, INFINITE, PROCESS_INFORMATION,
        PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, STARTUPINFOEXW, STARTUPINFOW,
    };

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

    pub fn run() {
        let args: Vec<String> = std::env::args().collect();

        // Parse optional launcher flags and find the exe + child args.
        let mut container_name: Option<String> = None;
        let mut net_allow = false;
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
                _ => break,
            }
            i += 1;
        }
        if i >= args.len() {
            eprintln!("usage: agent-bridle-aclaunch [--name <n>] [--net-allow] <exe> [args...]");
            std::process::exit(2);
        }
        let exe = &args[i];
        let child_args = &args[i + 1..];

        let name = container_name.unwrap_or_else(|| format!("ab{}", std::process::id()));
        let exit_code = unsafe { spawn_in_container(&name, net_allow, exe, child_args) };
        std::process::exit(exit_code as i32);
    }

    /// Create an AppContainer profile, spawn `exe` inside it, wait, and return
    /// the child's exit code.  Cleans up the profile before returning.
    unsafe fn spawn_in_container(
        name: &str,
        net_allow: bool,
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

        // 2. Capability SIDs (network only for now; FS narrowing via ACLs is
        //    deferred — ADR 0009 / agent-bridle#51).
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

        // 4. Attribute list: one slot for PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES.
        let mut attr_size: usize = 0;
        // First call: get the required buffer size (returns FALSE, that is expected).
        InitializeProcThreadAttributeList(std::ptr::null_mut(), 1, 0, &mut attr_size);
        let mut attr_buf: Vec<u8> = vec![0u8; attr_size];
        let attr_list = attr_buf.as_mut_ptr().cast();

        let ok = InitializeProcThreadAttributeList(attr_list, 1, 0, &mut attr_size);
        if ok == 0 {
            eprintln!(
                "agent-bridle-aclaunch: InitializeProcThreadAttributeList failed: {:?}",
                std::io::Error::last_os_error()
            );
            do_cleanup(name, ac_sid, &cap_sids);
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
                "agent-bridle-aclaunch: UpdateProcThreadAttribute failed: {:?}",
                std::io::Error::last_os_error()
            );
            DeleteProcThreadAttributeList(attr_list);
            do_cleanup(name, ac_sid, &cap_sids);
            std::process::exit(1);
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
            do_cleanup(name, ac_sid, &cap_sids);
            std::process::exit(1);
        }

        // Thread handle is not needed; close it immediately.
        CloseHandle(proc_info.hThread);

        // 6. Wait for the child, collect its exit code.
        WaitForSingleObject(proc_info.hProcess as HANDLE, INFINITE);
        let mut exit_code: u32 = 1;
        GetExitCodeProcess(proc_info.hProcess as HANDLE, &mut exit_code);
        CloseHandle(proc_info.hProcess as HANDLE);

        // 7. Cleanup: free SIDs and delete the profile.
        do_cleanup(name, ac_sid, &cap_sids);

        exit_code
    }

    unsafe fn do_cleanup(
        name: &str,
        ac_sid: *mut std::ffi::c_void,
        cap_sids: &[SID_AND_ATTRIBUTES],
    ) {
        // Capability SIDs were allocated by CreateWellKnownSid; free them.
        for sid in cap_sids {
            if !sid.Sid.is_null() {
                FreeSid(sid.Sid);
            }
        }
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
