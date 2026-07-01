//! `bridle-jail-init` — the guest **PID 1** for the Tier-2 micro-VM (#111 / ADR
//! 0013 D3). It is the `/init` of the minimal-rootfs initramfs booted by qemu.
//!
//! It mounts the pseudo-filesystems, reads the exec spec from `/.bridle/cmd`
//! (NUL-separated argv baked into the initramfs), runs the single granted program
//! with its stdio on the serial console, prints machine-readable markers around
//! the output so the host can recover stdout + exit code, then powers the VM off.
//!
//! Program *identity* is confined by construction: the initramfs physically
//! contains only the granted program + its closure (ADR 0013 D1), so there is no
//! un-granted ELF in the guest to run.

fn main() {
    #[cfg(target_os = "linux")]
    linux_main();
    #[cfg(not(target_os = "linux"))]
    eprintln!("bridle-jail-init is Linux-only");
}

#[cfg(target_os = "linux")]
fn linux_main() {
    use std::ffi::CString;
    use std::io::Write;

    // Best-effort mount of the pseudo-filesystems the toolchain may touch. Failures
    // are non-fatal (the kernel may have auto-mounted devtmpfs; /proc may be
    // unneeded) — the program either runs or fails visibly between the markers.
    let mount = |src: &str, tgt: &str, fstype: &str| {
        let _ = std::fs::create_dir_all(tgt);
        if let (Ok(s), Ok(t), Ok(f)) = (CString::new(src), CString::new(tgt), CString::new(fstype))
        {
            // SAFETY: mount() with valid C strings and null data; return ignored.
            unsafe {
                libc::mount(s.as_ptr(), t.as_ptr(), f.as_ptr(), 0, std::ptr::null());
            }
        }
    };
    mount("proc", "/proc", "proc");
    mount("sysfs", "/sys", "sysfs");
    mount("devtmpfs", "/dev", "devtmpfs");

    // The exec spec: NUL-separated argv, first element is the absolute program.
    let raw = std::fs::read("/.bridle/cmd").unwrap_or_default();
    let argv: Vec<Vec<u8>> = raw
        .split(|&b| b == 0)
        .filter(|s| !s.is_empty())
        .map(<[u8]>::to_vec)
        .collect();

    println!("-----BRIDLE-VM-STDOUT-BEGIN-----");
    let _ = std::io::stdout().flush();

    let rc: i32 = run(&argv);

    let _ = std::io::stdout().flush();
    let _ = std::io::stderr().flush();
    println!("-----BRIDLE-VM-RC={rc}-----");
    let _ = std::io::stdout().flush();

    // Flush filesystem buffers and power the VM off so qemu exits cleanly.
    // SAFETY: sync()/reboot() are simple syscalls; RB_POWER_OFF halts the guest.
    unsafe {
        libc::sync();
        libc::reboot(libc::RB_POWER_OFF);
    }
    // If reboot returned (it should not), keep PID 1 alive rather than panicking
    // the kernel.
    loop {
        // SAFETY: pause() blocks until a signal; harmless.
        unsafe {
            libc::pause();
        }
    }
}

/// Run the granted program with stdio inherited (→ the serial console). Returns its
/// exit code, or a conventional code for a missing spec / failed exec.
#[cfg(target_os = "linux")]
fn run(argv: &[Vec<u8>]) -> i32 {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;
    use std::process::Command;

    let Some((prog, args)) = argv.split_first() else {
        eprintln!("bridle-jail-init: no command in /.bridle/cmd");
        return 2;
    };
    match Command::new(OsStr::from_bytes(prog))
        .args(args.iter().map(|a| OsStr::from_bytes(a)))
        .status()
    {
        Ok(status) => status.code().unwrap_or(-1),
        Err(e) => {
            // The classic identity outcome: an un-granted program is absent.
            eprintln!(
                "bridle-jail-init: cannot exec {}: {e}",
                String::from_utf8_lossy(prog)
            );
            127
        }
    }
}
