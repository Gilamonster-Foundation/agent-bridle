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
            let out = std::process::Command::new("cmd.exe")
                .args(["/c", "whoami", "/groups"])
                .output()
                .expect("spawn cmd grandchild");
            print!("{}", String::from_utf8_lossy(&out.stdout));
            eprint!("{}", String::from_utf8_lossy(&out.stderr));
            std::process::exit(out.status.code().unwrap_or(1));
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
    use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, HANDLE};
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows_sys::Win32::Security::{
        GetTokenInformation, TokenAppContainerSid, TokenIsAppContainer,
        TOKEN_APPCONTAINER_INFORMATION, TOKEN_QUERY,
    };
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcess, GetCurrentProcessId, OpenProcessToken,
    };

    unsafe {
        let mut token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            eprintln!(
                "OpenProcessToken failed: {}",
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
                "GetTokenInformation(TokenIsAppContainer) failed: {}",
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

        println!(
            "pid={} is_appcontainer={} appcontainer_sid={}",
            GetCurrentProcessId(),
            is_appcontainer,
            sid
        );
        CloseHandle(token);
    }

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
