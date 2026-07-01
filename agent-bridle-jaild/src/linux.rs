//! Linux mount-namespace jail (ADR 0013 D3/D4 / #109). See the crate docs.
//!
//! The privileged work happens in a [`CommandExt::pre_exec`] closure that runs in
//! the forked child *before* `execve`. To stay async-signal-safe, the closure does
//! **no allocation** — every path is pre-converted to a `CString` in the parent
//! and the child only issues raw syscalls over those buffers.

use std::ffi::{CString, OsStr};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use agent_bridle_core::RootfsPlan;

use crate::JailRun;

/// One bind-mount to perform inside the new namespace.
struct BindMount {
    /// Host source path (the real file/dir to expose).
    src: CString,
    /// Target path inside the assembled jail root (host-side, pre-created).
    target: CString,
    /// `true` ⇒ expose read-write; else remount read-only after binding.
    writable: bool,
}

/// Top-level merged-usr compatibility symlinks. On a merged-usr host (Ubuntu,
/// Debian, Fedora…) `/lib -> usr/lib`, `/bin -> usr/bin`, etc. The loader resolves
/// each `DT_NEEDED` library by a `/lib/<triple>/…` (or `ld.so.cache`) path that
/// reaches the canonically-bound file *through* these links, so the jail must
/// reproduce them. (`lib64` is normally pre-created as a real dir by the
/// `PT_INTERP` bind above, whose `!exists()` guard then skips it here.)
const MERGED_USR_LINKS: &[&str] = &["bin", "sbin", "lib", "lib32", "lib64", "libx32"];

pub(crate) fn run_jailed<I, S>(
    plan: &RootfsPlan,
    program: &Path,
    args: I,
    drop_to: Option<(libc::uid_t, libc::gid_t)>,
) -> io::Result<JailRun>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    // --- Parent side: assemble the jail root skeleton on the host. -----------
    // A unique, private directory we will bind onto itself and pivot into. Its
    // children are empty mount-points that receive the plan's bind-mounts inside
    // the child's private namespace (so nothing leaks into the host mount table).
    let jail_root = unique_jail_root()?;

    let mut binds: Vec<BindMount> = Vec::with_capacity(plan.entries.len());
    for e in &plan.entries {
        let rel = e.src.strip_prefix("/").unwrap_or(&e.src);
        let target = jail_root.join(rel);
        if e.is_dir {
            std::fs::create_dir_all(&target)?;
        } else {
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent)?;
            }
            // A bind-mount target must exist and match file-ness; an empty regular
            // file works as the mount-point for any file (incl. device nodes).
            if !target.exists() {
                std::fs::File::create(&target)?;
            }
        }
        binds.push(BindMount {
            src: cstring(&e.src)?,
            target: cstring(&target)?,
            writable: e.writable,
        });
    }

    // The kernel opens a dynamic binary's interpreter (PT_INTERP) by its literal
    // path (e.g. /lib64/ld-linux-x86-64.so.2), but the #107 plan only carries the
    // loader in canonicalized form (/usr/lib/.../ld-…). Bind the real loader at
    // the program's PT_INTERP path too — created here as a REAL directory, BEFORE
    // the merged-usr symlinks (whose `!exists()` guard then skips it) — or execve
    // fails with ENOENT even for the granted program. A static binary has no
    // PT_INTERP and is skipped.
    if let Ok(Some(interp)) = read_pt_interp(program) {
        if let Ok(loader) = interp.canonicalize() {
            let rel = interp.strip_prefix("/").unwrap_or(&interp);
            let target = jail_root.join(rel);
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent)?;
            }
            if !target.exists() {
                std::fs::File::create(&target)?;
            }
            binds.push(BindMount {
                src: cstring(&loader)?,
                target: cstring(&target)?,
                writable: false,
            });
        }
    }

    // Reproduce the host's top-level merged-usr symlinks inside the jail so library
    // references (/lib/<triple>/libc.so.6 → /usr/lib/<triple>/…) resolve.
    for link in MERGED_USR_LINKS {
        let host = PathBuf::from("/").join(link);
        if let Ok(dest) = std::fs::read_link(&host) {
            let in_jail = jail_root.join(link);
            if !in_jail.exists() {
                // Best-effort: a clash with a real bound dir just means the link
                // is unnecessary. Ignore an AlreadyExists race.
                let _ = std::os::unix::fs::symlink(&dest, &in_jail);
            }
        }
    }

    // Pre-built, allocation-free buffers for the async-signal-safe child.
    let c_root = cstring(&jail_root)?;
    let c_slash = CString::new("/").unwrap();
    let c_dot = CString::new(".").unwrap();

    // --- Build the command; the jail is constructed in pre_exec. -------------
    let mut cmd = Command::new(program);
    cmd.args(args);
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

    // SAFETY: the closure runs post-fork, pre-exec. It performs only raw syscalls
    // over CStrings captured by move (no allocation, no locks, no Rust I/O), which
    // is async-signal-safe. Mount/pivot_root failures are reported via the errno
    // pipe (returning Err), so the parent observes a spawn error rather than an
    // unconfined child.
    unsafe {
        cmd.pre_exec(move || {
            // 1. New mount namespace: our mounts are invisible to the host.
            if libc::unshare(libc::CLONE_NEWNS) != 0 {
                return Err(io::Error::last_os_error());
            }
            // 2. Make all mounts private+recursive so binds do not propagate out.
            if libc::mount(
                std::ptr::null(),
                c_slash.as_ptr(),
                std::ptr::null(),
                libc::MS_REC | libc::MS_PRIVATE,
                std::ptr::null(),
            ) != 0
            {
                return Err(io::Error::last_os_error());
            }
            // 3. Bind the jail root onto itself so it is a distinct mount point
            //    (a precondition of pivot_root).
            if libc::mount(
                c_root.as_ptr(),
                c_root.as_ptr(),
                std::ptr::null(),
                libc::MS_BIND | libc::MS_REC,
                std::ptr::null(),
            ) != 0
            {
                return Err(io::Error::last_os_error());
            }
            // 4. Bind every planned entry into the jail (best-effort: a failed
            //    optional data path just leaves it absent; an essential bind that
            //    fails surfaces later as the program's own ENOENT/loader error).
            for m in &binds {
                let rc = libc::mount(
                    m.src.as_ptr(),
                    m.target.as_ptr(),
                    std::ptr::null(),
                    libc::MS_BIND | libc::MS_REC,
                    std::ptr::null(),
                );
                if rc == 0 && !m.writable {
                    // Remount read-only (a bind cannot set ro in one step).
                    libc::mount(
                        std::ptr::null(),
                        m.target.as_ptr(),
                        std::ptr::null(),
                        libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY | libc::MS_REC,
                        std::ptr::null(),
                    );
                }
            }
            // 5. pivot_root using the new_root == put_old idiom (man 2 pivot_root):
            //    chdir(root); pivot_root(".", "."); umount2(".", MNT_DETACH).
            if libc::chdir(c_root.as_ptr()) != 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::syscall(libc::SYS_pivot_root, c_dot.as_ptr(), c_dot.as_ptr()) != 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::umount2(c_dot.as_ptr(), libc::MNT_DETACH) != 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::chdir(c_slash.as_ptr()) != 0 {
                return Err(io::Error::last_os_error());
            }
            // 6. Drop privilege BEFORE exec (after the mounts, which needed root):
            //    supplementary groups, then gid, then uid (order matters — setuid
            //    last, or we lose the privilege to setgid). The jailed program then
            //    runs as the client, never as the broker's root.
            if let Some((uid, gid)) = drop_to {
                if libc::setgroups(0, std::ptr::null()) != 0 {
                    return Err(io::Error::last_os_error());
                }
                if libc::setgid(gid) != 0 {
                    return Err(io::Error::last_os_error());
                }
                if libc::setuid(uid) != 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }

    let result = cmd.output();

    // Host-side cleanup: the binds lived in the child's namespace and vanished
    // when it exited; only the empty skeleton remains here.
    let _ = std::fs::remove_dir_all(&jail_root);

    let out = result?;
    Ok(JailRun {
        status: out.status,
        stdout: out.stdout,
        stderr: out.stderr,
    })
}

/// `CString` from a path's raw bytes (paths are bytes on Linux). Rejects an
/// interior NUL with an `InvalidInput` error.
fn cstring(p: &Path) -> io::Result<CString> {
    CString::new(p.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains an interior NUL"))
}

/// Read a binary's `PT_INTERP` (dynamic loader path) by parsing the ELF program
/// headers. Returns `Ok(None)` for a static binary, a non-ELF file, or a class we
/// do not parse (best-effort: ELF64 little-endian, i.e. x86-64/aarch64). Never
/// errors fatally — a missing interpreter just means no extra bind.
fn read_pt_interp(path: &Path) -> io::Result<Option<PathBuf>> {
    use std::io::{Read, Seek, SeekFrom};

    const PT_INTERP: u32 = 3;
    let mut f = std::fs::File::open(path)?;
    let mut eh = [0u8; 64];
    if f.read_exact(&mut eh).is_err() {
        return Ok(None);
    }
    if &eh[0..4] != b"\x7fELF" || eh[4] != 2 /* ELFCLASS64 */ || eh[5] != 1
    /* ELFDATA2LSB */
    {
        return Ok(None);
    }
    let phoff = u64::from_le_bytes(eh[0x20..0x28].try_into().unwrap());
    let phentsize = u16::from_le_bytes(eh[0x36..0x38].try_into().unwrap()) as u64;
    let phnum = u16::from_le_bytes(eh[0x38..0x3a].try_into().unwrap());
    if phentsize < 56 {
        return Ok(None);
    }
    for i in 0..phnum as u64 {
        f.seek(SeekFrom::Start(phoff + i * phentsize))?;
        let mut ph = [0u8; 56];
        if f.read_exact(&mut ph).is_err() {
            break;
        }
        if u32::from_le_bytes(ph[0..4].try_into().unwrap()) != PT_INTERP {
            continue;
        }
        let p_offset = u64::from_le_bytes(ph[8..16].try_into().unwrap());
        let p_filesz = u64::from_le_bytes(ph[32..40].try_into().unwrap());
        if p_filesz == 0 || p_filesz > 4096 {
            return Ok(None);
        }
        f.seek(SeekFrom::Start(p_offset))?;
        let mut buf = vec![0u8; p_filesz as usize];
        f.read_exact(&mut buf)?;
        if let Some(z) = buf.iter().position(|&b| b == 0) {
            buf.truncate(z);
        }
        if buf.is_empty() {
            return Ok(None);
        }
        return Ok(Some(PathBuf::from(OsStr::from_bytes(&buf))));
    }
    Ok(None)
}

/// A unique, freshly created jail-root directory under the temp dir.
fn unique_jail_root() -> io::Result<PathBuf> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    let mut d = std::env::temp_dir();
    d.push(format!(
        "agent-bridle-jail-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&d)?;
    Ok(d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{is_root, run_jailed};
    use agent_bridle_core::{build_rootfs_plan, Caveats, NormalizationPolicy, RootfsPolicy, Scope};

    fn unique_work(tag: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let mut d = std::env::temp_dir();
        d.push(format!(
            "agent-bridle-jail-work-{}-{}-{}",
            tag,
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// Non-privileged (CI) path: as a non-root caller, building the jail must fail
    /// closed with an error — never panic, never run unconfined. (`unshare(NEWNS)`
    /// needs `CAP_SYS_ADMIN`, so this returns EPERM.)
    #[test]
    fn non_root_fails_closed() {
        if is_root() {
            return; // under the privileged runner this precondition does not hold
        }
        let plan = RootfsPlan::default();
        let r = run_jailed(&plan, Path::new("/bin/true"), std::iter::empty::<&OsStr>());
        assert!(
            r.is_err(),
            "a non-root caller must get an error, not an unconfined run"
        );
    }

    /// ADR 0013 D1 (#109) — the load-bearing proof, root-only. A granted program
    /// runs inside the jail, but an un-granted one is **physically absent**
    /// (`ENOENT`): identity is confined by what *exists*, not by read rules.
    #[test]
    #[ignore = "requires CAP_SYS_ADMIN; run via scripts/jail-dev.sh"]
    fn jail_confines_to_granted_program_identity() {
        assert!(
            is_root(),
            "this proof must run as root (scripts/jail-dev.sh)"
        );

        let work = unique_work("identity");
        std::fs::write(work.join("hello"), b"hi\n").unwrap();
        let cav = Caveats {
            exec: Scope::only(["cat".to_string()]),
            fs_read: Scope::only([work.to_string_lossy().into_owned()]),
            fs_write: Scope::only([work.to_string_lossy().into_owned()]),
            ..Caveats::top()
        };
        let plan = build_rootfs_plan(
            &cav,
            &RootfsPolicy::default(),
            &NormalizationPolicy::default(),
        )
        .expect("rootfs plan");

        // The granted binary's absolute path (as it will exist inside the jail).
        let cat = plan
            .entries
            .iter()
            .find(|e| !e.is_dir && e.src.file_name().map(|n| n == "cat").unwrap_or(false))
            .map(|e| e.src.clone())
            .expect("granted cat must be in the plan");

        // 1. The granted program RUNS, reading a file in the granted work dir.
        let hello = work.join("hello");
        let run = run_jailed(&plan, &cat, [hello.as_os_str()])
            .expect("granted cat should run inside the jail");
        assert!(
            run.status.success(),
            "cat failed in jail: stderr={}",
            String::from_utf8_lossy(&run.stderr)
        );
        assert_eq!(run.stdout, b"hi\n", "cat must read the granted file");

        // 2. An UN-granted program is absent — the identity invariant. /bin/sh was
        //    never planned, so it cannot be exec'd from inside the jail.
        let sh = run_jailed(
            &plan,
            Path::new("/bin/sh"),
            [OsStr::new("-c"), OsStr::new("echo escaped")],
        );
        assert!(
            sh.is_err(),
            "un-granted /bin/sh must be physically absent in the jail (ENOENT), got {sh:?}"
        );

        let _ = std::fs::remove_dir_all(&work);
    }

    /// #113 / ADR 0013 D7, root-only: a granted `python3` starts and `dlopen`s a
    /// stdlib C-extension inside the jail — its stdlib + `lib-dynload` are present
    /// via the runtime-closure fallback (#113) — while an un-granted executable
    /// stays physically absent (D1 holds even with the wider closure). Skips if
    /// python3 is not installed.
    #[test]
    #[ignore = "requires CAP_SYS_ADMIN; run via scripts/jail-dev.sh"]
    fn python_runs_and_dlopens_extension_in_jail() {
        assert!(is_root(), "run as root via scripts/jail-dev.sh");
        let work = unique_work("py");
        let cav = Caveats {
            exec: Scope::only(["python3".to_string()]),
            fs_read: Scope::only([work.to_string_lossy().into_owned()]),
            fs_write: Scope::only([work.to_string_lossy().into_owned()]),
            ..Caveats::top()
        };
        let plan = match build_rootfs_plan(
            &cav,
            &RootfsPolicy::default(),
            &NormalizationPolicy::default(),
        ) {
            Ok(p) => p,
            Err(_) => return, // python3 absent on this host ⇒ skip
        };
        let py = plan
            .entries
            .iter()
            .find(|e| {
                !e.is_dir
                    && e.src
                        .file_name()
                        .and_then(|n| n.to_str())
                        .map(|n| n.starts_with("python3"))
                        .unwrap_or(false)
            })
            .map(|e| e.src.clone())
            .expect("granted python3 must be in the plan");

        // `array` is a lib-dynload C-extension ⇒ forces a runtime `dlopen` of a
        // stdlib `.so` that is NOT in the static closure (present via the fallback).
        let run = run_jailed(
            &plan,
            &py,
            [OsStr::new("-c"), OsStr::new("import array; print('ok')")],
        )
        .expect("python should run in the jail");
        assert!(
            run.status.success(),
            "python failed in jail (missing lib: {:?}) — stderr={}",
            crate::missing_shared_library(&run.stderr),
            String::from_utf8_lossy(&run.stderr)
        );
        assert_eq!(run.stdout, b"ok\n");

        // D1 still holds with the wider closure: an un-granted program is absent.
        assert!(
            run_jailed(
                &plan,
                Path::new("/bin/sh"),
                [OsStr::new("-c"), OsStr::new("echo x")]
            )
            .is_err(),
            "un-granted /bin/sh must remain absent even with the D7 fallback"
        );
        let _ = std::fs::remove_dir_all(&work);
    }
}
