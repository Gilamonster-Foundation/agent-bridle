//! Raw Windows HANDLE probe for AppContainer inherited-handle proofs.
//!
//! The test launcher passes a numeric HANDLE value in an environment variable.
//! This probe tries to write a marker through that handle. A successful write is
//! a leak; an invalid/access-denied handle is the expected confined result.

#[cfg(target_os = "windows")]
fn main() {
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::Foundation::{GetHandleInformation, GetLastError};
    use windows_sys::Win32::Storage::FileSystem::WriteFile;

    let (kind, raw, marker): (&str, String, &[u8]) =
        if let Ok(raw) = std::env::var("AB_TEST_CANARY_FILE_HANDLE") {
            ("file", raw, b"LEAKED_FILE_HANDLE\n")
        } else if let Ok(raw) = std::env::var("AB_TEST_CANARY_PIPE_HANDLE") {
            ("pipe", raw, b"LEAKED_PIPE_HANDLE\n")
        } else {
            panic!("AB_TEST_CANARY_FILE_HANDLE or AB_TEST_CANARY_PIPE_HANDLE must be set");
        };
    let value = raw
        .parse::<isize>()
        .expect("canary HANDLE value must be an isize");
    let handle = value as HANDLE;
    let mut flags = 0_u32;
    let valid = unsafe { GetHandleInformation(handle, &mut flags) };
    if valid == 0 {
        let error = unsafe { GetLastError() };
        eprintln!("HANDLE_WRITE_DENIED kind={kind} last_error={error}");
        return;
    }
    let mut written = 0_u32;
    let ok = unsafe {
        WriteFile(
            handle,
            marker.as_ptr().cast(),
            marker.len() as u32,
            &mut written,
            std::ptr::null_mut(),
        )
    };
    if ok != 0 {
        println!("HANDLE_WRITE_SUCCEEDED kind={kind} bytes={written}");
        std::process::exit(10);
    }

    let error = unsafe { GetLastError() };
    eprintln!("HANDLE_WRITE_DENIED kind={kind} last_error={error}");
}

#[cfg(not(target_os = "windows"))]
fn main() {
    eprintln!("ab-handleprobe: Windows-only fixture");
    std::process::exit(1);
}
