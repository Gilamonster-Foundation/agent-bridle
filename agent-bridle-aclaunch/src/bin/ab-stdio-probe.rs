//! Console-only standard-handle and `NUL` device probe for AppContainer tests.
//!
//! It deliberately uses no windowing or shell APIs, so it can run in a Session
//! 0 AppContainer. The `NUL` open mirrors Git-for-Windows' startup request:
//! read/write, normal sharing, inheritable security attributes, and an existing
//! object. Its result is reported separately from standard-handle delivery.

#[cfg(target_os = "windows")]
fn main() {
    use windows_sys::Win32::Foundation::{
        CloseHandle, GetHandleInformation, GetLastError, GENERIC_READ, GENERIC_WRITE, HANDLE,
        INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        OPEN_EXISTING,
    };
    use windows_sys::Win32::System::Console::{
        GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
    };

    #[derive(Debug)]
    struct HandleStatus {
        returned: bool,
        usable: bool,
    }

    unsafe fn standard_handle_status(kind: u32) -> HandleStatus {
        let handle = GetStdHandle(kind);
        let returned = !handle.is_null() && handle != INVALID_HANDLE_VALUE;
        let usable = if returned {
            let mut flags = 0_u32;
            GetHandleInformation(handle, &mut flags) != 0
        } else {
            false
        };
        HandleStatus { returned, usable }
    }

    let stdin = unsafe { standard_handle_status(STD_INPUT_HANDLE) };
    let stdout = unsafe { standard_handle_status(STD_OUTPUT_HANDLE) };
    let stderr = unsafe { standard_handle_status(STD_ERROR_HANDLE) };

    let nul = [b'N' as u16, b'U' as u16, b'L' as u16, 0];
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: std::ptr::null_mut(),
        bInheritHandle: 1,
    };
    let handle: HANDLE = unsafe {
        CreateFileW(
            nul.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            &attributes,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            std::ptr::null_mut(),
        )
    };
    let nul_open = handle != INVALID_HANDLE_VALUE;
    let nul_error = if nul_open {
        unsafe {
            CloseHandle(handle);
        }
        0
    } else {
        unsafe { GetLastError() }
    };

    println!(
        "stdin_returned={} stdin_valid={} stdout_returned={} stdout_valid={} \
         stderr_returned={} stderr_valid={} nul_open={} nul_error={}",
        stdin.returned,
        stdin.usable,
        stdout.returned,
        stdout.usable,
        stderr.returned,
        stderr.usable,
        nul_open,
        nul_error,
    );
}

#[cfg(not(target_os = "windows"))]
fn main() {
    eprintln!("ab-stdio-probe: Windows-only fixture");
    std::process::exit(1);
}
