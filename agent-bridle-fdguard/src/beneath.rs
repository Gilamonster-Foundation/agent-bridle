//! Race-free bounded opens beneath a granted root (agent-bridle#351, ADR 0026
//! slice 2).
//!
//! A leash check (`check_path_*`) canonicalizes and tests membership — correct,
//! but *advisory about the future*: a plain `open` afterwards re-resolves the
//! pathname from scratch, and a component swapped for a symlink in between is
//! followed with the caller's full ambient authority (the check→open TOCTOU).
//! These functions make the resolution itself carry the bound: the kernel (or a
//! per-component `O_NOFOLLOW` walk) refuses any escape from `root` **at open
//! time**, so the descriptor handed back is bounded by the grant no matter what
//! the filesystem did in between.
//!
//! - **Linux**: one `openat2(2)` with `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS`
//!   from an `O_DIRECTORY` handle on `root` — the kernel refuses `..`-escapes,
//!   absolute jumps, every symlink (magic `/proc/self/fd` reopen links
//!   included) atomically. `ENOSYS` (pre-5.6 kernel) fails closed: the repo's
//!   Linux floor has the syscall.
//! - **Other Unix (macOS)**: no `openat2`, so an equivalent walk: each
//!   component is opened `openat(dirfd, comp, O_NOFOLLOW | O_DIRECTORY)`
//!   relative to the previous handle, and the final component with the caller's
//!   flags plus `O_NOFOLLOW`. `..`/absolute components are refused up front, so
//!   resolution can never leave `root`; any symlink terminates it (`ELOOP`).
//!
//! Both legs are **Conservative** in the projection vocabulary: an in-`root`
//! symlink is refused too (the caller is expected to pass *canonical* `root`
//! and `rel`, so honest paths contain none). Callers run in the parent, not a
//! fork child — no async-signal-safety constraint here; the `unsafe` is plain
//! FFI, encapsulated so `agent-bridle-core` stays `forbid(unsafe_code)`.

use std::ffi::CString;
use std::fs::File;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path};

/// Open `root/rel` for reading, with resolution bounded beneath `root`.
///
/// An empty `rel` opens `root` itself. See the module docs for the guarantee
/// and platform mechanisms.
pub fn open_beneath_read(root: &Path, rel: &Path) -> io::Result<File> {
    open_beneath(root, rel, OpenKind::Read)
}

/// Open `root/rel` for writing (create if absent; `append` appends, otherwise
/// truncates — the `>` / `>>` shapes), with resolution bounded beneath `root`.
pub fn open_beneath_write(root: &Path, rel: &Path, append: bool) -> io::Result<File> {
    open_beneath(root, rel, OpenKind::Write { append })
}

/// True iff `err` is the kernel refusing the *resolution itself* — an escape
/// or planted symlink stopped by `RESOLVE_BENEATH`/`RESOLVE_NO_SYMLINKS`/
/// `O_NOFOLLOW` (`EXDEV`, `ELOOP`, and BSD's `EMLINK` spelling) — as opposed
/// to an ordinary open failure (`ENOENT`, `EACCES`, …). Callers use this to
/// report an authority denial rather than an I/O error.
pub fn is_resolution_refusal(err: &io::Error) -> bool {
    matches!(
        err.raw_os_error(),
        Some(libc::ELOOP) | Some(libc::EXDEV) | Some(libc::EMLINK)
    )
}

#[derive(Clone, Copy)]
enum OpenKind {
    Read,
    Write { append: bool },
}

impl OpenKind {
    fn flags(self) -> libc::c_int {
        match self {
            OpenKind::Read => libc::O_RDONLY,
            OpenKind::Write { append } => {
                libc::O_WRONLY
                    | libc::O_CREAT
                    | if append {
                        libc::O_APPEND
                    } else {
                        libc::O_TRUNC
                    }
            }
        }
    }
}

fn open_beneath(root: &Path, rel: &Path, kind: OpenKind) -> io::Result<File> {
    // Fail closed on any component that could steer resolution by itself; the
    // kernel-side flags below then only have to stop *filesystem* tricks
    // (symlinks planted after the caller's check).
    let mut components: Vec<&std::ffi::OsStr> = Vec::new();
    for comp in rel.components() {
        match comp {
            Component::Normal(name) => components.push(name),
            Component::CurDir => {}
            other => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("bounded open refuses non-normal path component {other:?}"),
                ));
            }
        }
    }
    open_beneath_impl(root, &components, kind)
}

fn cstr(bytes: &std::ffi::OsStr) -> io::Result<CString> {
    CString::new(bytes.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains a NUL byte"))
}

/// `open(2)` an `O_DIRECTORY` handle on the root itself. `O_NOFOLLOW` is safe
/// here because callers pass a canonical root (its final component is not a
/// symlink); a root swapped for a symlink since canonicalization is refused.
fn open_root(root: &Path) -> io::Result<File> {
    let c = cstr(root.as_os_str())?;
    let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    loop {
        // SAFETY: plain `open` FFI on a valid NUL-terminated path; the returned
        // descriptor is immediately owned by `File`.
        let fd = unsafe { libc::open(c.as_ptr(), flags) };
        if fd >= 0 {
            // SAFETY: `fd` is a freshly opened, owned descriptor.
            return Ok(unsafe { <File as std::os::fd::FromRawFd>::from_raw_fd(fd) });
        }
        let err = io::Error::last_os_error();
        if err.kind() != io::ErrorKind::Interrupted {
            return Err(err);
        }
    }
}

#[cfg(target_os = "linux")]
fn open_beneath_impl(
    root: &Path,
    components: &[&std::ffi::OsStr],
    kind: OpenKind,
) -> io::Result<File> {
    use std::os::fd::AsRawFd;

    let root_dir = open_root(root)?;
    // Join the validated components into one relative path; `openat2` resolves
    // it in a single kernel-checked pass. Empty → the root itself (".").
    let mut rel_bytes: Vec<u8> = Vec::new();
    for (i, comp) in components.iter().enumerate() {
        if i > 0 {
            rel_bytes.push(b'/');
        }
        rel_bytes.extend_from_slice(comp.as_bytes());
    }
    if rel_bytes.is_empty() {
        rel_bytes.push(b'.');
    }
    let rel_c = CString::new(rel_bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains a NUL byte"))?;

    // The stable openat2(2) ABI (`struct open_how`): three u64s. Defined
    // locally because libc's `open_how` is #[non_exhaustive] and cannot be
    // constructed by literal.
    #[repr(C)]
    struct OpenHow {
        flags: u64,
        mode: u64,
        resolve: u64,
    }
    let how = OpenHow {
        flags: (kind.flags() | libc::O_CLOEXEC) as u64,
        mode: match kind {
            OpenKind::Read => 0,
            OpenKind::Write { .. } => 0o666,
        },
        resolve: libc::RESOLVE_BENEATH | libc::RESOLVE_NO_SYMLINKS,
    };

    // `openat2` may return EAGAIN when it detects a racing rename/mount during
    // resolution (its documented "retry" result) — retry a bounded number of
    // times, then surface the error (fail closed, never fall back to an
    // unbounded open). EINTR retries as usual.
    let mut attempts = 0;
    loop {
        // SAFETY: raw `openat2` syscall with a valid dirfd, NUL-terminated
        // relative path, and a properly sized `open_how`; the returned
        // descriptor is immediately owned by `File`.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_openat2,
                root_dir.as_raw_fd(),
                rel_c.as_ptr(),
                std::ptr::addr_of!(how),
                std::mem::size_of::<OpenHow>(),
            )
        };
        if rc >= 0 {
            // SAFETY: `rc` is a freshly opened, owned descriptor.
            return Ok(unsafe { <File as std::os::fd::FromRawFd>::from_raw_fd(rc as i32) });
        }
        let err = io::Error::last_os_error();
        match err.raw_os_error() {
            Some(libc::EINTR) => continue,
            Some(libc::EAGAIN) if attempts < 8 => {
                attempts += 1;
                continue;
            }
            _ => return Err(err),
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn open_beneath_impl(
    root: &Path,
    components: &[&std::ffi::OsStr],
    kind: OpenKind,
) -> io::Result<File> {
    use std::os::fd::AsRawFd;

    let mut dir = open_root(root)?;
    let Some((last, intermediate)) = components.split_last() else {
        // Empty `rel`: the root itself (only meaningful for read; a write open
        // of a directory fails EISDIR from the flags below via reopen).
        return match kind {
            OpenKind::Read => Ok(dir),
            OpenKind::Write { .. } => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "bounded write open of the root directory itself",
            )),
        };
    };

    for comp in intermediate {
        let c = cstr(comp)?;
        let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
        loop {
            // SAFETY: `openat` FFI relative to an owned directory handle; the
            // returned descriptor is immediately owned by `File`.
            let fd = unsafe { libc::openat(dir.as_raw_fd(), c.as_ptr(), flags) };
            if fd >= 0 {
                // SAFETY: freshly opened, owned descriptor.
                dir = unsafe { <File as std::os::fd::FromRawFd>::from_raw_fd(fd) };
                break;
            }
            let err = io::Error::last_os_error();
            if err.kind() != io::ErrorKind::Interrupted {
                return Err(err);
            }
        }
    }

    let c = cstr(last)?;
    let flags = kind.flags() | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    loop {
        // SAFETY: `openat` FFI relative to an owned directory handle; the
        // returned descriptor is immediately owned by `File`.
        let fd = unsafe { libc::openat(dir.as_raw_fd(), c.as_ptr(), flags, 0o666 as libc::c_uint) };
        if fd >= 0 {
            // SAFETY: freshly opened, owned descriptor.
            return Ok(unsafe { <File as std::os::fd::FromRawFd>::from_raw_fd(fd) });
        }
        let err = io::Error::last_os_error();
        if err.kind() != io::ErrorKind::Interrupted {
            return Err(err);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    fn tmp_root(tag: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("fdguard-beneath-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir.canonicalize().unwrap()
    }

    /// In-scope opens work: create-truncate, append, then read back.
    #[test]
    fn in_scope_write_append_read_roundtrip() {
        let root = tmp_root("roundtrip");
        std::fs::create_dir(root.join("sub")).unwrap();
        let rel = Path::new("sub/out.txt");

        let mut f = open_beneath_write(&root, rel, false).expect("create");
        f.write_all(b"one").unwrap();
        drop(f);
        let mut f = open_beneath_write(&root, rel, true).expect("append");
        f.write_all(b"two").unwrap();
        drop(f);

        let mut s = String::new();
        open_beneath_read(&root, rel)
            .expect("read")
            .read_to_string(&mut s)
            .unwrap();
        assert_eq!(s, "onetwo");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// The TOCTOU regression (agent-bridle#351): a path component swapped for a
    /// symlink pointing OUTSIDE the root after the caller's check must be
    /// refused at open time — a plain `open` would follow it.
    #[test]
    fn symlink_component_escape_is_refused() {
        let root = tmp_root("swap");
        let outside = tmp_root("swap-outside");
        std::fs::write(outside.join("victim.txt"), b"outside").unwrap();

        // The "swap": what the check saw as a real directory is now a symlink.
        std::os::unix::fs::symlink(&outside, root.join("sub")).unwrap();

        // Positive control: the unbounded open follows the planted symlink —
        // the exact behavior the mediated open exists to remove.
        assert!(
            std::fs::File::open(root.join("sub/victim.txt")).is_ok(),
            "positive control: a plain open follows the planted symlink"
        );

        let err = open_beneath_read(&root, Path::new("sub/victim.txt"))
            .expect_err("bounded open must refuse the symlinked component");
        assert!(
            matches!(
                err.raw_os_error(),
                Some(libc::ELOOP) | Some(libc::EXDEV) | Some(libc::ENOTDIR)
            ),
            "expected a kernel resolution refusal, got {err:?}"
        );

        let err = open_beneath_write(&root, Path::new("sub/victim.txt"), false)
            .expect_err("bounded write must refuse the symlinked component");
        assert!(
            matches!(
                err.raw_os_error(),
                Some(libc::ELOOP) | Some(libc::EXDEV) | Some(libc::ENOTDIR)
            ),
            "expected a kernel resolution refusal, got {err:?}"
        );
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&outside);
    }

    /// A symlink as the FINAL component is refused too (Conservative: even one
    /// that resolves in-root — honest callers pass canonical paths).
    #[test]
    fn symlink_final_component_is_refused() {
        let root = tmp_root("final");
        std::fs::write(root.join("real.txt"), b"real").unwrap();
        std::os::unix::fs::symlink(root.join("real.txt"), root.join("link.txt")).unwrap();

        let err = open_beneath_read(&root, Path::new("link.txt"))
            .expect_err("final symlink must be refused");
        assert!(
            matches!(err.raw_os_error(), Some(libc::ELOOP) | Some(libc::EMLINK)),
            "expected ELOOP-class refusal, got {err:?}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// `..` and absolute components never reach the kernel: refused up front.
    #[test]
    fn dotdot_and_absolute_rel_are_refused() {
        let root = tmp_root("dotdot");
        assert_eq!(
            open_beneath_read(&root, Path::new("../etc/hosts"))
                .expect_err("..-escape must be refused")
                .kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            open_beneath_read(&root, Path::new("/etc/hosts"))
                .expect_err("absolute rel must be refused")
                .kind(),
            io::ErrorKind::InvalidInput
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// An empty `rel` reads the root directory handle itself.
    #[test]
    fn empty_rel_opens_the_root_for_read() {
        let root = tmp_root("self");
        open_beneath_read(&root, Path::new("")).expect("open root");
        let _ = std::fs::remove_dir_all(&root);
    }
}
