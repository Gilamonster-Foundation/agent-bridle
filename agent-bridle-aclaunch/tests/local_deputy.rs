//! Native Windows local-deputy proof.
//!
//! The parent intentionally exposes a permissive named-pipe deputy. The confined
//! child sends attacker-controlled bytes to that deputy; the deputy then performs
//! an outside-authority filesystem write as the host parent. This distinguishes
//! direct AppContainer containment from confused-deputy channels.

#![cfg(target_os = "windows")]

use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::time::Duration;

use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_PIPE_CONNECTED, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::{
    InitializeSecurityDescriptor, SetSecurityDescriptorDacl, SECURITY_ATTRIBUTES,
    SECURITY_DESCRIPTOR,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, ReadFile, WriteFile, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE,
    OPEN_EXISTING, PIPE_ACCESS_INBOUND,
};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, WaitNamedPipeW, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE,
    PIPE_WAIT,
};

const LAUNCHER: &str = env!("CARGO_BIN_EXE_agent-bridle-aclaunch");
const MSG_WRITE_OUTSIDE: &str = "WRITE_OUTSIDE";
const OUTSIDE_WRITTEN: &str = "DEPUTY_WROTE";
const SECURITY_DESCRIPTOR_REVISION: u32 = 1;

static N: AtomicU64 = AtomicU64::new(0);

fn tag(kind: &str) -> String {
    format!(
        "{kind}-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    )
}

fn fresh_dir(kind: &str) -> PathBuf {
    let mut d = std::env::temp_dir();
    d.push(format!("ab-deputy-{}", tag(kind)));
    std::fs::create_dir_all(&d).expect("create temp dir");
    let _ = Command::new("icacls")
        .arg(&d)
        .args(["/setintegritylevel", "(OI)(CI)Low"])
        .output();
    d
}

fn launch(args: &[&str]) -> std::process::Output {
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

fn skip_proof_unless_appcontainer() -> bool {
    let required = std::env::var("BRIDLE_REQUIRE_APPCONTAINER")
        .map(|v| !v.is_empty() && v != "0")
        .unwrap_or(false);
    if appcontainer_available() {
        return false;
    }
    if required {
        panic!("BRIDLE_REQUIRE_APPCONTAINER is set but AppContainer could not be created");
    }
    eprintln!("skipping AppContainer local-deputy proof: cannot create AppContainer here");
    true
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn create_permissive_pipe(pipe_name: &str) -> HANDLE {
    let mut descriptor: SECURITY_DESCRIPTOR = unsafe { std::mem::zeroed() };
    let init_ok = unsafe {
        InitializeSecurityDescriptor(
            (&mut descriptor as *mut SECURITY_DESCRIPTOR).cast(),
            SECURITY_DESCRIPTOR_REVISION,
        )
    };
    assert_ne!(init_ok, 0, "InitializeSecurityDescriptor failed");

    let dacl_ok = unsafe {
        SetSecurityDescriptorDacl(
            (&mut descriptor as *mut SECURITY_DESCRIPTOR).cast(),
            1,
            std::ptr::null(),
            0,
        )
    };
    assert_ne!(dacl_ok, 0, "SetSecurityDescriptorDacl(NULL DACL) failed");

    let attrs = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: (&mut descriptor as *mut SECURITY_DESCRIPTOR).cast(),
        bInheritHandle: 0,
    };
    let name = wide(pipe_name);
    let handle = unsafe {
        CreateNamedPipeW(
            name.as_ptr(),
            PIPE_ACCESS_INBOUND,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            1,
            4096,
            4096,
            5_000,
            &attrs,
        )
    };
    assert_ne!(
        handle,
        INVALID_HANDLE_VALUE,
        "CreateNamedPipeW failed with {}",
        unsafe { GetLastError() }
    );
    handle
}

fn server_once(pipe: HANDLE, outside_file: PathBuf) -> String {
    let connected = unsafe { ConnectNamedPipe(pipe, std::ptr::null_mut()) };
    if connected == 0 {
        let error = unsafe { GetLastError() };
        if error != ERROR_PIPE_CONNECTED {
            unsafe {
                CloseHandle(pipe);
            }
            return format!("connect_failed:{error}");
        }
    }

    let mut buf = [0u8; 256];
    let mut read = 0u32;
    let ok = unsafe {
        ReadFile(
            pipe,
            buf.as_mut_ptr(),
            buf.len() as u32,
            &mut read,
            std::ptr::null_mut(),
        )
    };
    unsafe {
        CloseHandle(pipe);
    }
    if ok == 0 {
        return format!("read_failed:{}", unsafe { GetLastError() });
    }

    let msg = String::from_utf8_lossy(&buf[..read as usize]).to_string();
    if msg.contains(MSG_WRITE_OUTSIDE) {
        std::fs::write(&outside_file, OUTSIDE_WRITTEN).expect("deputy writes outside file");
        format!("privileged_write:{msg:?}")
    } else {
        format!("ignored:{msg:?}")
    }
}

fn parent_pipe_write(pipe_name: &str, msg: &[u8]) -> Result<(), String> {
    let name = wide(pipe_name);
    unsafe {
        WaitNamedPipeW(name.as_ptr(), 5_000);
    }
    let handle = unsafe {
        CreateFileW(
            name.as_ptr(),
            GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(format!("CreateFileW:{}", unsafe { GetLastError() }));
    }
    let mut written = 0u32;
    let ok = unsafe {
        WriteFile(
            handle,
            msg.as_ptr(),
            msg.len() as u32,
            &mut written,
            std::ptr::null_mut(),
        )
    };
    unsafe {
        CloseHandle(handle);
    }
    if ok == 0 {
        return Err(format!("WriteFile:{}", unsafe { GetLastError() }));
    }
    Ok(())
}

fn pipe_echo_command(pipe_name: &str) -> String {
    format!("echo {MSG_WRITE_OUTSIDE}>{pipe_name}")
}

fn run_deputy_attempt<F>(kind: &str, client: F) -> (String, String, std::process::Output)
where
    F: FnOnce(&str) -> std::process::Output,
{
    let outside_dir = fresh_dir(kind);
    let outside = outside_dir.join("outside.txt");
    std::fs::write(&outside, "ORIG").expect("seed outside file");
    let pipe_name = format!(r"\\.\pipe\{}", tag(kind));
    let pipe = create_permissive_pipe(&pipe_name);
    let pipe_bits = pipe as isize;

    let (tx, rx) = mpsc::channel();
    let outside_for_thread = outside.clone();
    std::thread::spawn(move || {
        let result = server_once(pipe_bits as HANDLE, outside_for_thread);
        let _ = tx.send(result);
    });

    let child = client(&pipe_name);
    let outcome = match rx.recv_timeout(Duration::from_secs(5)) {
        Ok(outcome) => outcome,
        Err(_) => {
            let _ = parent_pipe_write(&pipe_name, b"NOOP");
            rx.recv_timeout(Duration::from_secs(5))
                .unwrap_or_else(|_| "server_timeout".to_string())
        }
    };

    let outside_text = std::fs::read_to_string(&outside).unwrap_or_default();
    let _ = std::fs::remove_dir_all(&outside_dir);
    (outcome, outside_text, child)
}

#[test]
fn named_pipe_deputy_is_denied_for_appcontainer_child() {
    if skip_proof_unless_appcontainer() {
        return;
    }

    let (control_outcome, control_outside, control_child) =
        run_deputy_attempt("control", |pipe_name| {
            Command::new("cmd.exe")
                .args(["/c", &pipe_echo_command(pipe_name)])
                .current_dir("C:\\Windows")
                .output()
                .expect("spawn unconfined pipe client")
        });
    assert!(
        control_child.status.success(),
        "positive control client must run; status={:?} stdout={} stderr={}",
        control_child.status.code(),
        String::from_utf8_lossy(&control_child.stdout).trim(),
        String::from_utf8_lossy(&control_child.stderr).trim()
    );
    assert!(
        control_outcome.starts_with("privileged_write:") && control_outside == OUTSIDE_WRITTEN,
        "positive control must prove the named-pipe deputy can write outside authority; \
         outcome={control_outcome:?} outside={control_outside:?}"
    );

    let (confined_outcome, confined_outside, confined_child) =
        run_deputy_attempt("confined", |pipe_name| {
            launch(&[
                "--name",
                &tag("deputy"),
                "cmd.exe",
                "/c",
                &pipe_echo_command(pipe_name),
            ])
        });

    let confined_stderr = String::from_utf8_lossy(&confined_child.stderr);
    assert!(
        !confined_outcome.starts_with("privileged_write:")
            && confined_outside == "ORIG"
            && !confined_child.status.success()
            && confined_stderr.contains("Access is denied."),
        "AppContainer named-pipe deputy attempt must be denied by OS policy on this host. \
         Positive control proved the pipe/deputy path works; fallback wrote only NOOP if \
         needed to unblock the server. outcome={confined_outcome:?} outside={confined_outside:?} \
         status={:?} stdout={} stderr={}",
        confined_child.status.code(),
        String::from_utf8_lossy(&confined_child.stdout).trim(),
        confined_stderr.trim()
    );
}
