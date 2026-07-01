//! Tier-2 **micro-VM** backend (#111 / ADR 0013 D3, ADR 0009 D2): boot the *same*
//! minimal rootfs (#107) as a qemu guest under a separate kernel.
//!
//! Unlike the Tier-1.5 jail ([`crate::run_jailed`]), the micro-VM **sidesteps host
//! namespaces entirely** — the VMM builds the guest, so no host user namespace is
//! needed even on a host with `apparmor_restrict_unprivileged_userns=1` (#101), and
//! a guest-kernel compromise is still contained. The identity invariant (ADR 0013
//! D1) holds the same way: the initramfs *physically contains only* the granted
//! program + its closure, so no un-granted ELF exists in the guest.
//!
//! Flow: materialize the plan into an initramfs (with the compiled
//! `bridle-jail-init` as `/init`), boot `qemu-system-x86_64 -kernel <host vmlinuz>
//! -initrd <cpio>` with
//! the serial console captured, and recover the program's stdout + exit code from
//! the markers [`bridle-jail-init`](../bin/bridle-jail-init.rs) prints. Runs as
//! root (reads the root-only host kernel, `mknod`s the console); a non-root or
//! VMM-less host fails closed with an error (honest degradation, ADR 0013 D4).

use std::ffi::OsStr;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use agent_bridle_core::{materialize_copy, RootfsPlan, VmPolicy};

const STDOUT_BEGIN: &str = "-----BRIDLE-VM-STDOUT-BEGIN-----";
const RC_PREFIX: &str = "-----BRIDLE-VM-RC=";

/// The outcome of a micro-VM run.
#[derive(Debug)]
pub struct VmOutcome {
    /// The program's exit code (`None` if the markers were not found — a boot or
    /// harness failure rather than a clean program exit).
    pub code: Option<i32>,
    /// The program's stdout, recovered from between the serial markers.
    pub stdout: Vec<u8>,
    /// The full serial console log (kernel boot + guest), for diagnostics.
    pub console: Vec<u8>,
}

/// Whether a micro-VM can be built here: `qemu-system-x86_64` on `PATH` and a
/// readable host kernel image. (KVM is used when available but not required — qemu
/// falls back to TCG.) Used for honest backend selection / fail-closed.
#[must_use]
pub fn microvm_is_supported(vm: &VmPolicy) -> bool {
    which_qemu(&vm.qemu_path).is_some() && find_kernel(&vm.kernel_search).is_some()
}

/// The first existing qemu binary among the configured `candidates`
/// (`VmPolicy::qemu_path`).
fn which_qemu(candidates: &[String]) -> Option<PathBuf> {
    candidates.iter().map(PathBuf::from).find(|p| p.exists())
}

/// The host kernel to boot as the guest kernel: the first existing configured
/// `candidates` entry (`VmPolicy::kernel_search`, default `/boot/vmlinuz`), else
/// the newest `<dir>/vmlinuz-*` beside the first candidate. Readable only as root
/// on Ubuntu.
fn find_kernel(candidates: &[String]) -> Option<PathBuf> {
    for c in candidates {
        let p = PathBuf::from(c);
        if p.exists() {
            return Some(p);
        }
    }
    // Fallback: newest `vmlinuz-*` in the directory of the first candidate.
    let dir = candidates
        .first()
        .map(PathBuf::from)
        .and_then(|p| p.parent().map(Path::to_path_buf))
        .unwrap_or_else(|| PathBuf::from("/boot"));
    let mut versioned: Vec<PathBuf> = std::fs::read_dir(dir)
        .ok()?
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("vmlinuz-"))
        })
        .collect();
    versioned.sort();
    versioned.pop()
}

/// Run `program` (+`args`) inside a micro-VM built from `plan`, using `jail_init`
/// (the compiled `bridle-jail-init`) as the guest `/init`. Requires root.
pub fn run_microvm<I, S>(
    plan: &RootfsPlan,
    program: &Path,
    args: I,
    jail_init: &Path,
    vm: &VmPolicy,
) -> io::Result<VmOutcome>
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    let qemu = which_qemu(&vm.qemu_path).ok_or_else(|| {
        io::Error::new(io::ErrorKind::NotFound, "no configured qemu binary found")
    })?;
    let kernel = find_kernel(&vm.kernel_search).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "no readable guest kernel in the configured search paths (run as root?)",
        )
    })?;

    let staging = unique_dir("microvm")?;
    let argv: Vec<Vec<u8>> = std::iter::once(program.as_os_str().as_bytes().to_vec())
        .chain(args.into_iter().map(|a| a.as_ref().as_bytes().to_vec()))
        .collect();
    let cpio = build_initramfs(plan, &argv, jail_init, &vm.merged_usr_links, &staging)?;

    // Configurable accel / memory / cmdline (VmPolicy). Default accel `kvm:tcg`
    // tries KVM then falls back to TCG (the `:`-fallback is only valid on
    // `-machine accel=`, not `-accel`); no network device ⇒ the guest has no
    // egress at all; `-no-reboot` + the init's power-off makes qemu exit.
    let machine = format!("accel={}", vm.accel);
    let memory = vm.memory_mb.to_string();
    let out = Command::new(&qemu)
        .args([
            "-no-reboot",
            "-display",
            "none",
            "-monitor",
            "none",
            "-serial",
            "stdio",
            "-machine",
            &machine,
            "-m",
            &memory,
        ])
        .arg("-kernel")
        .arg(&kernel)
        .arg("-initrd")
        .arg(&cpio)
        .args(["-append", &vm.kernel_cmdline])
        .output();

    let _ = std::fs::remove_dir_all(&staging);
    let out = out?;
    // Serial (guest) is on stdout; qemu's own diagnostics are on stderr — keep both
    // in the console log so a boot/arg failure is legible.
    let mut console = out.stdout;
    if !out.stderr.is_empty() {
        console.extend_from_slice(b"\n--- qemu stderr ---\n");
        console.extend_from_slice(&out.stderr);
    }
    let (code, stdout) = parse_markers(&console);
    Ok(VmOutcome {
        code,
        stdout,
        console,
    })
}

/// Assemble the initramfs `staging` tree and pack it into a `newc` cpio archive.
/// Must run as root (device nodes via `mknod`). Returns the cpio path.
fn build_initramfs(
    plan: &RootfsPlan,
    argv: &[Vec<u8>],
    jail_init: &Path,
    merged_usr_links: &[String],
    staging: &Path,
) -> io::Result<PathBuf> {
    let root = staging.join("root");
    std::fs::create_dir_all(&root)?;

    // 1. The minimal rootfs: the granted program + its closure + curated data
    //    (files copied; big data dirs stay empty mount-points — unused in the VM).
    materialize_copy(plan, &root)?;

    // 2. The granted program's dynamic loader at its PT_INTERP path (the kernel /
    //    loader open the soname path, which #107 only carries canonicalized).
    let program = Path::new(OsStr::from_bytes(&argv[0]));
    place_interpreter(program, &root)?;

    // 3. Reproduce the host's top-level merged-usr symlinks so library references
    //    (`/lib/<triple>/…`, `/lib64/ld-…`) resolve inside the guest.
    for link in merged_usr_links {
        if let Ok(dest) = std::fs::read_link(PathBuf::from("/").join(link)) {
            let in_root = root.join(link);
            if !in_root.exists() {
                let _ = std::os::unix::fs::symlink(&dest, &in_root);
            }
        }
    }

    // 4. The guest PID 1 (`bridle-jail-init`) at /init, plus its own dynamic
    //    closure + interpreter (glibc, overlapping the program's — copied
    //    idempotently) so the kernel can start it.
    copy_with_closure(jail_init, &root.join("init"))?;
    place_interpreter(jail_init, &root)?;

    // 5. The exec spec the guest init reads (NUL-separated argv).
    std::fs::create_dir_all(root.join(".bridle"))?;
    let mut spec = Vec::new();
    for (i, a) in argv.iter().enumerate() {
        if i > 0 {
            spec.push(0u8);
        }
        spec.extend_from_slice(a);
    }
    std::fs::write(root.join(".bridle/cmd"), &spec)?;

    // 6. The console + null device nodes (before the init mounts devtmpfs, the
    //    kernel connects PID 1's stdio to /dev/console).
    std::fs::create_dir_all(root.join("dev"))?;
    mknod_char(&root.join("dev/console"), 5, 1)?;
    mknod_char(&root.join("dev/null"), 1, 3)?;

    // 7. Pack: `cd root && find . | cpio -o -H newc > cpio` (as root ⇒ device
    //    nodes and perms preserved).
    let cpio = staging.join("initramfs.cpio");
    let status = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "cd {} && find . -print0 | cpio --null -o -H newc > {}",
            shell_quote(&root),
            shell_quote(&cpio)
        ))
        .status()?;
    if !status.success() {
        return Err(io::Error::other("cpio packing failed"));
    }
    Ok(cpio)
}

/// Copy `bin` to `dest`, plus its `ldd` shared-library closure (each at its
/// reported path) — for a binary not already carried by the rootfs plan (the guest
/// init).
fn copy_with_closure(bin: &Path, dest: &Path) -> io::Result<()> {
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::copy(bin, dest)?;
    make_executable(dest)?;
    if let Ok(out) = Command::new("ldd").arg(bin).output() {
        let text = String::from_utf8_lossy(&out.stdout);
        for line in text.lines() {
            let path = if let Some(rhs) = line.trim().split(" => ").nth(1) {
                rhs.split(" (").next().unwrap_or("").trim()
            } else {
                let l = line.trim();
                if l.starts_with('/') {
                    l.split(" (").next().unwrap_or("")
                } else {
                    ""
                }
            };
            if path.starts_with('/') {
                let src = PathBuf::from(path);
                if src.exists() {
                    copy_into_root_at(&src, path, dest_root(dest))?;
                }
            }
        }
    }
    Ok(())
}

/// Copy `bin`'s ELF interpreter (PT_INTERP) into the initramfs `root` at that exact
/// path, so the kernel/loader can start the dynamic binary.
fn place_interpreter(bin: &Path, root: &Path) -> io::Result<()> {
    if let Some(interp) = read_pt_interp(bin) {
        if let Ok(real) = interp.canonicalize() {
            copy_into_root_at(&real, interp.to_string_lossy().as_ref(), root)?;
        }
    }
    Ok(())
}

/// Copy host file `src` to `root` + `rel_path` (an absolute path used as relative),
/// creating parents.
fn copy_into_root_at(src: &Path, rel_path: &str, root: &Path) -> io::Result<()> {
    let target = root.join(rel_path.trim_start_matches('/'));
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if src.is_file() && !target.exists() {
        std::fs::copy(src, &target)?;
    }
    Ok(())
}

/// The initramfs root a `dest` path (`<root>/init`) lives under.
fn dest_root(dest: &Path) -> &Path {
    dest.parent().unwrap_or(dest)
}

/// Read a binary's `PT_INTERP` (dynamic loader path) from its ELF64 program
/// headers; `None` for a static/non-ELF binary.
fn read_pt_interp(path: &Path) -> Option<PathBuf> {
    use std::io::{Read, Seek, SeekFrom};
    use std::os::unix::ffi::OsStrExt;

    let mut f = std::fs::File::open(path).ok()?;
    let mut eh = [0u8; 64];
    f.read_exact(&mut eh).ok()?;
    if &eh[0..4] != b"\x7fELF" || eh[4] != 2 || eh[5] != 1 {
        return None;
    }
    let phoff = u64::from_le_bytes(eh[0x20..0x28].try_into().ok()?);
    let phentsize = u16::from_le_bytes(eh[0x36..0x38].try_into().ok()?) as u64;
    let phnum = u16::from_le_bytes(eh[0x38..0x3a].try_into().ok()?);
    for i in 0..phnum as u64 {
        f.seek(SeekFrom::Start(phoff + i * phentsize)).ok()?;
        let mut ph = [0u8; 56];
        if f.read_exact(&mut ph).is_err() {
            break;
        }
        if u32::from_le_bytes(ph[0..4].try_into().ok()?) == 3 {
            let off = u64::from_le_bytes(ph[8..16].try_into().ok()?);
            let sz = u64::from_le_bytes(ph[32..40].try_into().ok()?);
            if sz == 0 || sz > 4096 {
                return None;
            }
            f.seek(SeekFrom::Start(off)).ok()?;
            let mut buf = vec![0u8; sz as usize];
            f.read_exact(&mut buf).ok()?;
            if let Some(z) = buf.iter().position(|&b| b == 0) {
                buf.truncate(z);
            }
            return (!buf.is_empty()).then(|| PathBuf::from(std::ffi::OsStr::from_bytes(&buf)));
        }
    }
    None
}

fn make_executable(p: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o755))
}

/// Create a character device node via `mknod(2)`.
fn mknod_char(path: &Path, major: u32, minor: u32) -> io::Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    if path.exists() {
        return Ok(());
    }
    let c = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "nul in path"))?;
    let dev = libc::makedev(major, minor);
    // SAFETY: mknod with a valid path and S_IFCHR mode; return code checked.
    let rc = unsafe { libc::mknod(c.as_ptr(), libc::S_IFCHR | 0o600, dev) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn shell_quote(p: &Path) -> String {
    format!("'{}'", p.to_string_lossy().replace('\'', "'\\''"))
}

fn unique_dir(tag: &str) -> io::Result<PathBuf> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    let mut d = std::env::temp_dir();
    d.push(format!(
        "agent-bridle-{}-{}-{}",
        tag,
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&d)?;
    Ok(d)
}

/// Recover `(exit_code, stdout)` from the serial console between the guest init's
/// markers. `\r` (added by the serial line discipline) is stripped.
fn parse_markers(console: &[u8]) -> (Option<i32>, Vec<u8>) {
    let text = String::from_utf8_lossy(console);
    let text = text.replace('\r', "");
    let Some(begin) = text.find(STDOUT_BEGIN) else {
        return (None, Vec::new());
    };
    let after = &text[begin + STDOUT_BEGIN.len()..];
    let after = after.strip_prefix('\n').unwrap_or(after);
    let Some(rc_at) = after.find(RC_PREFIX) else {
        return (None, Vec::new());
    };
    let stdout = after[..rc_at].trim_end_matches('\n');
    let rc_tail = &after[rc_at + RC_PREFIX.len()..];
    let code = rc_tail
        .split("-----")
        .next()
        .and_then(|n| n.trim().parse::<i32>().ok());
    (code, stdout.as_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_markers_extracts_stdout_and_rc() {
        let console = b"[    0.00] Linux version ...\n\
                        -----BRIDLE-VM-STDOUT-BEGIN-----\r\n\
                        hi\r\n\
                        -----BRIDLE-VM-RC=0-----\r\n\
                        [   0.9] reboot: Power down\n";
        let (code, stdout) = parse_markers(console);
        assert_eq!(code, Some(0));
        assert_eq!(stdout, b"hi");
    }

    #[test]
    fn parse_markers_none_when_no_markers() {
        let (code, stdout) = parse_markers(b"kernel panic, no init\n");
        assert_eq!(code, None);
        assert!(stdout.is_empty());
    }

    #[test]
    fn parse_markers_reads_nonzero_rc() {
        let console = b"-----BRIDLE-VM-STDOUT-BEGIN-----\nboom\n-----BRIDLE-VM-RC=127-----\n";
        let (code, _) = parse_markers(console);
        assert_eq!(code, Some(127));
    }

    /// #147 (I8): the micro-VM support probe reads the configured qemu/kernel
    /// search paths (`VmPolicy`), not hard-coded ones. Non-privileged (no VM boot).
    #[test]
    fn microvm_is_supported_reads_config_paths() {
        // A bogus qemu path ⇒ unsupported, regardless of any host `/usr/bin/qemu`.
        let bogus = VmPolicy {
            qemu_path: vec!["/nonexistent/qemu".to_string()],
            ..VmPolicy::default()
        };
        assert!(!microvm_is_supported(&bogus));

        // Two real existing files stand in for qemu + kernel ⇒ supported, proving
        // both configured lists drive the probe (would fail on the old const path).
        let real = VmPolicy {
            qemu_path: vec!["/nonexistent".to_string(), "/bin/sh".to_string()],
            kernel_search: vec!["/bin/sh".to_string()],
            ..VmPolicy::default()
        };
        assert!(
            microvm_is_supported(&real),
            "configured existing qemu + kernel paths must be honored"
        );
    }

    /// ADR 0013 D3 (#111), root + qemu only: the granted toolchain runs inside a
    /// real micro-VM booted from the minimal rootfs, and its output comes back over
    /// the serial console. `fs_read` grants the input *file* (so it is copied into
    /// the initramfs; the guest has no host access). Skips gracefully without
    /// root/qemu or the guest-init binary (`$BRIDLE_JAIL_INIT`, set by
    /// scripts/jail-dev.sh).
    #[test]
    #[ignore = "requires root + qemu; run via scripts/jail-dev.sh"]
    fn microvm_runs_granted_program_from_minimal_rootfs() {
        use agent_bridle_core::{
            build_rootfs_plan, Caveats, NormalizationPolicy, RootfsPolicy, Scope,
        };

        let vm = VmPolicy::default();
        if !crate::is_root() || !microvm_is_supported(&vm) {
            return;
        }
        let Some(jail_init) = std::env::var_os("BRIDLE_JAIL_INIT").map(PathBuf::from) else {
            return; // harness did not provide the compiled guest init
        };
        if !jail_init.exists() {
            return;
        }

        let work = unique_dir("vmwork").expect("workdir");
        let hello = work.join("hello");
        std::fs::write(&hello, b"vm-hi\n").unwrap();

        let cav = Caveats {
            exec: Scope::only(["cat".to_string()]),
            // Grant the FILE (copied into the initramfs), not a dir (left empty).
            fs_read: Scope::only([hello.to_string_lossy().into_owned()]),
            ..Caveats::top()
        };
        let plan = build_rootfs_plan(
            &cav,
            &RootfsPolicy::default(),
            &NormalizationPolicy::default(),
        )
        .expect("plan");
        let cat = plan
            .entries
            .iter()
            .find(|e| !e.is_dir && e.src.file_name().and_then(|n| n.to_str()) == Some("cat"))
            .map(|e| e.src.clone())
            .expect("granted cat in plan");

        let out =
            run_microvm(&plan, &cat, [hello.as_os_str()], &jail_init, &vm).expect("micro-VM run");
        assert_eq!(
            out.code,
            Some(0),
            "cat should exit 0 in the VM; console:\n{}",
            String::from_utf8_lossy(&out.console)
        );
        assert!(
            String::from_utf8_lossy(&out.stdout).contains("vm-hi"),
            "granted cat must read the input file inside the VM; stdout={:?} console:\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.console)
        );

        let _ = std::fs::remove_dir_all(&work);
    }
}
