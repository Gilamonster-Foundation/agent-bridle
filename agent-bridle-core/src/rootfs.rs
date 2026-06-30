//! Minimal-rootfs **builder** (ADR 0013 D2 / agent-bridle#107) — the foundation
//! of the Tier-2 program-identity close.
//!
//! ADR 0013's keystone (D1): confine program *identity* by controlling **what
//! exists** in the process's filesystem view, not by allow-listing reads (a
//! readable ELF is a runnable ELF, so `ld.so <readable>` trampolines past
//! Landlock's `Execute`). This module computes the *plan* for a read-only root
//! tree that **physically contains only** the granted program files, their shared
//! library closure, the dynamic loader, the curated runtime data, and the granted
//! `fs_read`/`fs_write` roots — and nothing else executable. With no un-granted
//! ELF present, `find -exec curl`, a `system("curl")`, a shebang to an un-granted
//! interpreter, and an `ld.so` trampoline all fail because the target is absent.
//!
//! This is the **builder only** (the plan + a copy-materializer for tests). Wiring
//! it into a runnable jail (`unshare` + `pivot_root`, read-only bind-mounts, the
//! privileged broker) is #109/#108; booting it as a micro-VM guest is #111. The
//! production materialization is read-only **bind-mounts** (so files are shared,
//! not copied); [`materialize_copy`] is the test/diagnostic path.
//!
//! Linux-only (it shells out to `ldd` to resolve the loader's view of the closure
//! and reads `/proc`); inert until a Tier-1.5/Tier-2 backend consumes it.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::{Caveats, Scope};

/// Curated DATA paths a permitted program reads at runtime — **never
/// executables** (so they do not reopen the loader trampoline): locale, timezone,
/// CA bundles, the resolver/loader config, and the `/dev` + `/proc/self`
/// essentials. The shared libraries are added *specifically* from the per-binary
/// `ldd` closure, NOT by binding `/usr/lib` wholesale, so only the `.so`s the
/// granted binaries actually need are present.
const DATA_PATHS: &[&str] = &[
    "/usr/share",
    "/usr/lib/locale",
    "/etc/ld.so.cache",
    "/etc/ld.so.preload",
    "/etc/alternatives",
    "/etc/nsswitch.conf",
    "/etc/localtime",
    "/etc/resolv.conf",
    "/etc/ssl",
    "/etc/ca-certificates",
    "/proc/self",
    "/dev/null",
    "/dev/zero",
    "/dev/full",
    "/dev/urandom",
    "/dev/random",
];

/// The directories a bare program name is resolved against (mirrors the loader's
/// search, `$PATH` then a conventional fallback). Only used to find the granted
/// binaries' real paths for the plan.
fn search_dirs() -> Vec<PathBuf> {
    if let Ok(path) = std::env::var("PATH") {
        let dirs: Vec<PathBuf> = path
            .split(':')
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
            .collect();
        if !dirs.is_empty() {
            return dirs;
        }
    }
    [
        "/usr/local/bin",
        "/usr/bin",
        "/bin",
        "/usr/local/sbin",
        "/usr/sbin",
        "/sbin",
    ]
    .iter()
    .map(PathBuf::from)
    .collect()
}

/// Resolve a granted `exec` entry (a bare name or a path) to an absolute, existing
/// program file — canonicalized so the plan anchors the real inode.
fn resolve_program(entry: &str) -> Option<PathBuf> {
    let candidate = if entry.contains('/') {
        let p = PathBuf::from(entry);
        p.is_file().then_some(p)
    } else {
        search_dirs()
            .into_iter()
            .map(|d| d.join(entry))
            .find(|c| c.is_file())
    }?;
    candidate.canonicalize().ok()
}

/// The shared-library closure of `bin` as the loader sees it: parse `ldd`'s output
/// for the resolved `=> /abs/path` libraries and the trailing loader line. `ldd`
/// uses `LD_TRACE_LOADED_OBJECTS` (it does not execute the target for a normal
/// dynamic binary), and the granted binaries are trusted system tools. A static
/// binary (no dynamic deps) yields an empty closure — not an error.
fn ldd_closure(bin: &Path) -> Vec<PathBuf> {
    let out = match Command::new("ldd").arg(bin).output() {
        Ok(o) if o.status.success() => o.stdout,
        // "not a dynamic executable" / static / ldd error ⇒ no closure to add.
        _ => return Vec::new(),
    };
    let text = String::from_utf8_lossy(&out);
    let mut libs = BTreeSet::new();
    for line in text.lines() {
        let line = line.trim();
        // "libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x...)"
        if let Some(rhs) = line.split(" => ").nth(1) {
            let path = rhs.split(" (").next().unwrap_or("").trim();
            if path.starts_with('/') {
                if let Ok(c) = PathBuf::from(path).canonicalize() {
                    libs.insert(c);
                }
            }
        } else if line.starts_with('/') {
            // The loader itself: "/lib64/ld-linux-x86-64.so.2 (0x...)".
            let path = line.split(" (").next().unwrap_or("").trim();
            if let Ok(c) = PathBuf::from(path).canonicalize() {
                libs.insert(c);
            }
        }
        // "linux-vdso.so.1 (0x...)" has no path ⇒ skipped (kernel-provided).
    }
    libs.into_iter().collect()
}

/// One path the minimal rootfs exposes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootfsEntry {
    /// The host path to expose at the same location inside the rootfs.
    pub src: PathBuf,
    /// `true` ⇒ exposed read-write (an `fs_write` root); else read-only.
    pub writable: bool,
    /// `true` ⇒ a directory mount-point (bind-mounted in production; an empty
    /// dir in [`materialize_copy`]); `false` ⇒ a single file (copied/bound).
    pub is_dir: bool,
}

/// The plan for a minimal rootfs: exactly the paths to expose, nothing else.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RootfsPlan {
    /// The exposed paths (deduplicated, sorted).
    pub entries: Vec<RootfsEntry>,
}

/// Build the minimal-rootfs plan for `effective` (ADR 0013 D2). Requires `exec` to
/// be **confined** (`Only`) — a minimal rootfs is meaningless when any program may
/// run, so an ambient `exec` is rejected (the caller falls back to the Tier-1
/// boundary). The plan contains: the resolved granted program files + each one's
/// `ldd` shared-library closure (incl. the loader) + the curated [`DATA_PATHS`] +
/// the granted `fs_read` (ro) / `fs_write` (rw) roots — and nothing else.
pub fn build_rootfs_plan(effective: &Caveats) -> Result<RootfsPlan, String> {
    let programs = match &effective.exec {
        Scope::All => {
            return Err("minimal rootfs requires a confined exec scope (exec: Only)".to_string())
        }
        Scope::Only(set) => set,
    };

    // (src, writable, is_dir) accumulated then deduped.
    let mut files: BTreeSet<PathBuf> = BTreeSet::new(); // ro files (binaries + .so + loader + data files)
    let mut ro_dirs: BTreeSet<PathBuf> = BTreeSet::new();
    let mut rw_dirs: BTreeSet<PathBuf> = BTreeSet::new();

    for prog in programs {
        let bin =
            resolve_program(prog).ok_or_else(|| format!("granted program not found: {prog}"))?;
        for so in ldd_closure(&bin) {
            files.insert(so);
        }
        files.insert(bin);
    }

    for d in DATA_PATHS {
        let p = PathBuf::from(d);
        match p.metadata() {
            Ok(m) if m.is_dir() => {
                ro_dirs.insert(p);
            }
            Ok(_) => {
                files.insert(p);
            }
            Err(_) => {} // absent ⇒ skipped (harmless)
        }
    }

    // Granted fs roots: read roots ro, write roots rw (write wins on overlap).
    if let Scope::Only(rd) = &effective.fs_read {
        for p in rd {
            let pb = PathBuf::from(p);
            if pb.is_dir() {
                ro_dirs.insert(pb);
            } else if pb.exists() {
                files.insert(pb);
            }
        }
    }
    if let Scope::Only(wr) = &effective.fs_write {
        for p in wr {
            let pb = PathBuf::from(p);
            if pb.is_dir() {
                ro_dirs.remove(&pb);
                rw_dirs.insert(pb);
            } else if pb.exists() {
                files.insert(pb);
            }
        }
    }

    let mut entries: Vec<RootfsEntry> = Vec::new();
    entries.extend(files.into_iter().map(|src| RootfsEntry {
        src,
        writable: false,
        is_dir: false,
    }));
    entries.extend(ro_dirs.into_iter().map(|src| RootfsEntry {
        src,
        writable: false,
        is_dir: true,
    }));
    entries.extend(rw_dirs.into_iter().map(|src| RootfsEntry {
        src,
        writable: true,
        is_dir: true,
    }));
    entries.sort_by(|a, b| a.src.cmp(&b.src));
    Ok(RootfsPlan { entries })
}

/// Materialize a plan by **copying** file entries (and creating empty mount-point
/// dirs for directory entries) under `dest`, preserving each `src`'s absolute path
/// (so `/usr/bin/cat` lands at `dest/usr/bin/cat`). This is the **test /
/// diagnostic** path — production exposes the same plan via read-only bind-mounts
/// (no copy) through the broker (#108). Directory entries are left as empty
/// mount-points (their contents are bound at run time), so this does NOT recurse
/// into large data trees like `/usr/share`.
pub fn materialize_copy(plan: &RootfsPlan, dest: &Path) -> std::io::Result<()> {
    for e in &plan.entries {
        let rel = e.src.strip_prefix("/").unwrap_or(&e.src);
        let target = dest.join(rel);
        if e.is_dir {
            std::fs::create_dir_all(&target)?; // empty mount-point
        } else {
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent)?;
            }
            // A file entry may be a special file (/dev/null) — skip copy if it is
            // not a regular file, but record the mount-point's parent above.
            if e.src.is_file() {
                std::fs::copy(&e.src, &target)?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unique_dir(tag: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let mut d = std::env::temp_dir();
        d.push(format!(
            "agent-bridle-rootfs-{}-{}-{}",
            tag,
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn ambient_exec_is_rejected() {
        // exec: All ⇒ no minimal rootfs (any program could run).
        let err = build_rootfs_plan(&Caveats::top()).unwrap_err();
        assert!(err.contains("confined exec scope"), "{err}");
    }

    /// ADR 0013 D1 invariant: the built tree contains the granted program (and its
    /// library closure), and **no un-granted program** — identity by what *exists*.
    #[test]
    fn rootfs_contains_granted_program_and_not_ungranted_tools() {
        let work = unique_dir("work");
        let cav = Caveats {
            exec: Scope::only(["cat".to_string()]),
            fs_read: Scope::only([work.to_string_lossy().into_owned()]),
            fs_write: Scope::only([work.to_string_lossy().into_owned()]),
            ..Caveats::top()
        };
        let plan = build_rootfs_plan(&cav).expect("plan");

        // The granted binary and at least one library (its closure) are planned.
        let has_cat = plan
            .entries
            .iter()
            .any(|e| e.src.file_name().map(|n| n == "cat").unwrap_or(false) && !e.is_dir);
        let has_lib = plan
            .entries
            .iter()
            .any(|e| e.src.to_string_lossy().contains("/libc.so"));
        assert!(
            has_cat,
            "granted `cat` must be in the plan: {:?}",
            plan.entries
        );
        assert!(
            has_lib,
            "cat's libc closure must be in the plan: {:?}",
            plan.entries
        );

        // The writable work dir is rw; the loader is present.
        assert!(plan.entries.iter().any(|e| e.writable
            && e.is_dir
            && e.src == work.canonicalize().unwrap_or(work.clone())));
        assert!(plan
            .entries
            .iter()
            .any(|e| e.src.to_string_lossy().contains("ld-")));

        // No un-granted program/interpreter anywhere in the plan (the D1 invariant).
        for tool in [
            "/curl", "/sh", "/bash", "/python3", "/perl", "/head", "/wget", "/nc",
        ] {
            assert!(
                !plan.entries.iter().any(|e| {
                    let s = e.src.to_string_lossy();
                    s.ends_with(tool) || s.contains(&format!("/bin{tool}"))
                }),
                "un-granted tool `{tool}` must NOT be in the minimal rootfs: {:?}",
                plan.entries
            );
        }

        // Materialize (copy) and re-check on the real tree: cat present, sh absent.
        let dest = unique_dir("root");
        materialize_copy(&plan, &dest).expect("materialize");
        let cat_present = dest.join("usr/bin/cat").exists()
            || dest.join("bin/cat").exists()
            || dest.join("usr/local/bin/cat").exists();
        assert!(cat_present, "materialized tree must contain cat");
        for tool in [
            "usr/bin/sh",
            "bin/sh",
            "usr/bin/curl",
            "bin/bash",
            "usr/bin/head",
        ] {
            assert!(
                !dest.join(tool).exists(),
                "materialized minimal rootfs must NOT contain un-granted `{tool}`"
            );
        }

        let _ = std::fs::remove_dir_all(&work);
        let _ = std::fs::remove_dir_all(&dest);
    }
}
