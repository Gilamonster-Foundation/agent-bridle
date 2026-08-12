//! Token identity probe for Windows AppContainer descendant proofs.

#[cfg(target_os = "windows")]
fn main() {
    let mode = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "print".to_string());
    match mode.as_str() {
        "print" => print_identity(),
        "spawn-cmd" => {
            print_identity();
            let mut child = std::process::Command::new("cmd.exe")
                .args(["/d", "/q", "/k"])
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .expect("spawn cmd grandchild");
            print_child_identity(&child);
            drop(child.stdin.take());
            let _ = child.kill();
            let _ = child.wait();
        }
        "spawn-self" => {
            print_identity();
            let exe = std::env::current_exe().expect("current probe executable");
            let out = std::process::Command::new(exe)
                .arg("print")
                .output()
                .expect("spawn tokenprobe grandchild");
            print!("{}", String::from_utf8_lossy(&out.stdout));
            eprint!("{}", String::from_utf8_lossy(&out.stderr));
            std::process::exit(out.status.code().unwrap_or(1));
        }
        _ => {
            eprintln!("usage: ab-tokenprobe [print|spawn-cmd|spawn-self]");
            std::process::exit(2);
        }
    }
}

#[cfg(target_os = "windows")]
fn print_identity() {
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetCurrentProcessId};

    unsafe {
        print_process_identity(GetCurrentProcess(), GetCurrentProcessId());
    }
}

#[cfg(target_os = "windows")]
fn print_child_identity(child: &std::process::Child) {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::HANDLE;

    unsafe {
        print_process_identity(child.as_raw_handle() as HANDLE, child.id());
    }
}

#[cfg(target_os = "windows")]
unsafe fn print_process_identity(process: windows_sys::Win32::Foundation::HANDLE, pid: u32) {
    use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, HANDLE};
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows_sys::Win32::Security::{
        GetTokenInformation, TokenAppContainerSid, TokenIsAppContainer,
        TOKEN_APPCONTAINER_INFORMATION, TOKEN_QUERY,
    };
    use windows_sys::Win32::System::Threading::OpenProcessToken;

    let mut token: HANDLE = std::ptr::null_mut();
    if OpenProcessToken(process, TOKEN_QUERY, &mut token) == 0 {
        eprintln!(
            "OpenProcessToken(pid={pid}) failed: {}",
            std::io::Error::last_os_error()
        );
        std::process::exit(1);
    }

    let mut is_appcontainer = 0_u32;
    let mut returned = 0_u32;
    if GetTokenInformation(
        token,
        TokenIsAppContainer,
        (&mut is_appcontainer as *mut u32).cast(),
        std::mem::size_of::<u32>() as u32,
        &mut returned,
    ) == 0
    {
        eprintln!(
            "GetTokenInformation(TokenIsAppContainer, pid={pid}) failed: {}",
            std::io::Error::last_os_error()
        );
        CloseHandle(token);
        std::process::exit(1);
    }

    let mut needed = 0_u32;
    let _ = GetTokenInformation(
        token,
        TokenAppContainerSid,
        std::ptr::null_mut(),
        0,
        &mut needed,
    );
    let mut sid = String::from("<none>");
    if needed > 0 {
        let mut buf = vec![0_u8; needed as usize];
        if GetTokenInformation(
            token,
            TokenAppContainerSid,
            buf.as_mut_ptr().cast(),
            needed,
            &mut needed,
        ) != 0
        {
            let info = &*(buf.as_ptr() as *const TOKEN_APPCONTAINER_INFORMATION);
            sid = sid_to_string(info.TokenAppContainer);
        }
    }

    println!("pid={pid} is_appcontainer={is_appcontainer} appcontainer_sid={sid}");
    CloseHandle(token);

    unsafe fn sid_to_string(sid: *mut core::ffi::c_void) -> String {
        if sid.is_null() {
            return "<none>".to_string();
        }
        let mut raw = std::ptr::null_mut();
        if ConvertSidToStringSidW(sid, &mut raw) == 0 || raw.is_null() {
            return format!(
                "<sid-conversion-failed:{}>",
                std::io::Error::last_os_error()
            );
        }
        let mut len = 0_usize;
        while *raw.add(len) != 0 {
            len += 1;
        }
        let out = String::from_utf16_lossy(std::slice::from_raw_parts(raw, len));
        LocalFree(raw.cast());
        out
    }
}

#[cfg(not(target_os = "windows"))]
fn main() {
    eprintln!("ab-tokenprobe: Windows-only fixture");
    std::process::exit(1);
}
