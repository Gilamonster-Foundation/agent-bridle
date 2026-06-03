//! [`ToolContext`] — the mint-token that proves a tool passed the leash.
//!
//! This is the structural core of the design (DESIGN §2). A `ToolContext`:
//!
//! - has **private fields** and **no public constructor**, so it cannot be
//!   forged outside this crate;
//! - is minted **only** by [`crate::Gate::authorize`] (via the crate-private
//!   [`ToolContext::mint`]);
//! - carries the **effective** caveats (`granted.meet(required)`) plus the
//!   [`SandboxKind`] actually in force.
//!
//! A [`crate::Tool`] receives a `&ToolContext` to do anything, so the only path
//! to running a tool runs through the gate. Tools enforce per-operation policy
//! by calling the `check_*` methods below — which consult the *effective*
//! caveats, never the originally granted ones.

use std::path::{Component, Path, PathBuf};

use crate::{Caveats, SandboxKind, Scope, ToolError, ToolResult};

/// Proof that a tool invocation has passed the capability leash, carrying the
/// least-authority caveats it is permitted to act under.
///
/// Constructible only inside this crate (see [`ToolContext::mint`], called
/// solely by [`crate::Gate::authorize`]). There is intentionally no public
/// constructor and no `pub` field — that un-forgeability is the enforcement.
#[derive(Debug, Clone)]
pub struct ToolContext {
    // PRIVATE. Do not add `pub`. Do not add a public constructor.
    effective: Caveats,
    sandbox_kind: SandboxKind,
}

impl ToolContext {
    /// The **only** mint site. Crate-private so that [`crate::Gate::authorize`]
    /// is the single place a `ToolContext` can come into existence.
    pub(crate) fn mint(effective: Caveats, sandbox_kind: SandboxKind) -> Self {
        Self {
            effective,
            sandbox_kind,
        }
    }

    /// The effective (least-authority) caveats this invocation may act under.
    #[must_use]
    pub fn caveats(&self) -> &Caveats {
        &self.effective
    }

    /// The OS-level sandbox actually in force for this invocation.
    #[must_use]
    pub fn sandbox_kind(&self) -> SandboxKind {
        self.sandbox_kind
    }

    /// Leash check: may this invocation execute `program`?
    ///
    /// Allowed iff `exec` is `All`, or `program` is a member of the bounded
    /// `exec` scope. Membership is on the program *token as named in the scope*
    /// — callers should pass the resolved program name (argv0). Out-of-scope
    /// programs are denied here, before the tool spawns anything.
    pub fn check_exec(&self, program: &str) -> ToolResult<()> {
        if scope_allows(&self.effective.exec, program) {
            Ok(())
        } else {
            Err(ToolError::denied(format!(
                "exec of {program:?} is not within the granted authority"
            )))
        }
    }

    /// Leash check: may this invocation reach network `host`?
    pub fn check_net(&self, host: &str) -> ToolResult<()> {
        if scope_allows(&self.effective.net, host) {
            Ok(())
        } else {
            Err(ToolError::denied(format!(
                "network access to {host:?} is not within the granted authority"
            )))
        }
    }

    /// Leash check: may this invocation read `path`?
    ///
    /// See [`Self::check_path_write`] for the canonicalization contract; the
    /// only difference is which axis (`fs_read`) is consulted.
    pub fn check_path_read(&self, path: &Path) -> ToolResult<()> {
        self.check_path(&self.effective.fs_read, path, "read")
    }

    /// Leash check: may this invocation write `path`?
    ///
    /// **Canonicalizes first, then tests membership** (DESIGN §6): the path is
    /// resolved to a real, symlink-free location and rejected if it escapes the
    /// granted scope via `..` or a symlink. Membership is a *containment* test
    /// against each granted scope entry (an entry authorizes that path and its
    /// descendants), computed on canonical paths — **never** a raw string
    /// prefix. This closes the `@repo`/`../../etc` traversal class.
    pub fn check_path_write(&self, path: &Path) -> ToolResult<()> {
        self.check_path(&self.effective.fs_write, path, "write")
    }

    /// Shared path-leash logic for read and write.
    fn check_path(&self, axis: &Scope<String>, path: &Path, op: &str) -> ToolResult<()> {
        // `All` short-circuits — unrestricted on this axis.
        let allowed = match axis {
            Scope::All => return Ok(()),
            Scope::Only(set) => set,
        };

        let canon = canonicalize_for_check(path).map_err(|e| {
            ToolError::denied(format!(
                "{op} of {path:?} denied: cannot canonicalize ({e})"
            ))
        })?;

        for entry in allowed {
            // Each scope entry is itself canonicalized so that a relative or
            // symlinked grant is compared on equal footing. An entry that does
            // not resolve cannot authorize anything.
            let Ok(base) = canonicalize_for_check(Path::new(entry)) else {
                continue;
            };
            if path_is_within(&canon, &base) {
                return Ok(());
            }
        }

        Err(ToolError::denied(format!(
            "{op} of {} (resolved {}) is not within the granted fs_{op} scope",
            path.display(),
            canon.display(),
        )))
    }
}

/// `scope.contains(item)` for the string axes (`exec`, `net`).
fn scope_allows(scope: &Scope<String>, item: &str) -> bool {
    match scope {
        Scope::All => true,
        Scope::Only(set) => set.contains(item),
    }
}

/// Resolve a path for a leash check.
///
/// We must reject symlink escapes *before* membership, but we also must support
/// checking a path whose final component does not exist yet (the common
/// `fs_write` case: creating a new file under an allowed directory). So we
/// canonicalize the deepest existing ancestor and re-attach the trailing
/// not-yet-existing components, rejecting any `..` we cannot resolve away.
///
/// # Dangling-symlink escape (the load-bearing subtlety)
///
/// The tail walk must **not** use [`Path::exists`] — that follows symlinks, so a
/// symlink whose target does not (yet) exist reports `exists() == false`. The
/// old code then treated the symlink's own name as a plain non-existent tail
/// component and never resolved it: the path canonicalized to *itself*
/// (in-scope) while a real `open(O_CREAT)` would follow the link and write
/// **out of scope**. PROVEN escape: `ln -s <outside>/real <allowed>/inno` (real
/// absent), then `echo PWNED > <allowed>/inno` writes `<outside>/real`.
///
/// The fix uses [`Path::symlink_metadata`] (`lstat`, which does **not** follow)
/// to detect a symlink at each step, [`std::fs::read_link`] to read its target,
/// and re-resolves that target (relative to the canonicalized parent). A
/// dangling-or-not symlink whose resolved target escapes scope is then caught by
/// the normal membership test, because the returned path reflects the *target*,
/// not the link's own name. We bound the number of link hops to refuse a symlink
/// cycle.
fn canonicalize_for_check(path: &Path) -> std::io::Result<PathBuf> {
    // Fast path: the whole thing exists (this also resolves all symlinks — so an
    // *existing*-target symlink is fully resolved here and caught downstream).
    if let Ok(c) = path.canonicalize() {
        return Ok(c);
    }

    resolve_unresolved(path, 0)
}

/// Maximum symlink hops before we give up (refuse a cycle / pathological chain).
const MAX_SYMLINK_HOPS: u32 = 40;

/// Resolve a path that does not fully exist, following any symlink components
/// with `lstat` semantics (so a dangling symlink resolves to its *target*, not
/// its own name). `hops` counts symlinks followed so far.
fn resolve_unresolved(path: &Path, hops: u32) -> std::io::Result<PathBuf> {
    if hops > MAX_SYMLINK_HOPS {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "too many symlink hops (possible cycle) while resolving path",
        ));
    }

    // Walk up to the deepest ancestor that exists *as a real entry* — using
    // `symlink_metadata` (lstat), which does NOT follow symlinks. The deepest
    // such entry is canonicalized (resolving symlinks in the existing prefix);
    // then we re-attach the tail one component at a time, lstat-ing each so a
    // symlink in the tail is resolved against its target rather than silently
    // pushed as a plain name.
    let mut existing = path;
    let mut tail: Vec<Component<'_>> = Vec::new();
    loop {
        // `symlink_metadata` succeeds for a dangling symlink (the link entry
        // itself exists) and for any real entry; it fails only when the name is
        // truly absent. That is exactly the boundary we want for the prefix.
        if existing.symlink_metadata().is_ok() {
            break;
        }
        match existing.parent() {
            Some(parent) => {
                if let Some(name) = existing.file_name() {
                    tail.push(Component::Normal(name));
                } else {
                    // No file name (e.g. just `..` or `/`): nothing sane to
                    // attach — bail to the error path below.
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "path has no resolvable existing ancestor",
                    ));
                }
                existing = parent;
            }
            None => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "no existing ancestor to canonicalize",
                ));
            }
        }
    }

    // `existing` is now the deepest entry that exists (possibly a symlink, e.g.
    // a dangling final component). If it is itself a symlink, resolve it before
    // canonicalizing — `canonicalize` on a dangling symlink errors.
    let meta = existing.symlink_metadata()?;
    let mut base = if meta.file_type().is_symlink() {
        resolve_symlink_component(existing, hops)?
    } else {
        existing.canonicalize()?
    };

    // Re-attach the unresolved tail, lstat-ing each step so a symlink that is
    // created later in the tail (an interior symlink whose own target is absent)
    // is still resolved to its target and re-checked against scope.
    for comp in tail.into_iter().rev() {
        match comp {
            Component::Normal(name) => {
                base.push(name);
                // If the just-appended component is a symlink, resolve it now so
                // the returned path reflects the link TARGET (dangling or not),
                // never the link's own in-scope-looking name.
                if let Ok(meta) = base.symlink_metadata() {
                    if meta.file_type().is_symlink() {
                        base = resolve_symlink_component(&base, hops)?;
                    }
                }
            }
            Component::ParentDir => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "refusing to resolve `..` in a non-existent path tail",
                ));
            }
            // CurDir / Prefix / RootDir in the tail are degenerate; reject.
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "unexpected component in path tail",
                ));
            }
        }
    }
    Ok(base)
}

/// Resolve a single symlink at `link` to a canonical-for-check target path,
/// counting one hop. The link target is taken relative to the link's parent
/// directory when it is relative (POSIX symlink semantics), then re-run through
/// [`resolve_unresolved`] so the *target* — which may itself be dangling, or a
/// chain of symlinks — is what we ultimately scope-check.
fn resolve_symlink_component(link: &Path, hops: u32) -> std::io::Result<PathBuf> {
    let target = std::fs::read_link(link)?;
    let resolved = if target.is_absolute() {
        target
    } else {
        match link.parent() {
            Some(parent) => parent.join(target),
            None => target,
        }
    };
    // The target may be dangling or another symlink; recurse with an incremented
    // hop count (this is where a symlink cycle is bounded).
    resolve_unresolved(&resolved, hops + 1)
}

/// True iff `candidate` is `base` itself or a descendant of `base`. Both are
/// expected to be canonical, symlink-free paths, so this component-wise check
/// is sound (it is *not* a string prefix test — `/a/bc` is not within `/a/b`).
fn path_is_within(candidate: &Path, base: &Path) -> bool {
    candidate == base || candidate.starts_with(base)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CountBound, Gate};

    /// Mint a context the only legitimate way: through the gate.
    fn ctx(granted: Caveats) -> ToolContext {
        struct AnyTool;
        #[async_trait::async_trait]
        impl crate::Tool for AnyTool {
            fn name(&self) -> &str {
                "any"
            }
            fn schema(&self) -> serde_json::Value {
                serde_json::json!({})
            }
            async fn invoke(
                &self,
                _args: serde_json::Value,
                _cx: &ToolContext,
            ) -> ToolResult<serde_json::Value> {
                Ok(serde_json::Value::Null)
            }
        }
        let gate = Gate::new(0);
        gate.authorize(&AnyTool, &granted).expect("authorize")
    }

    #[test]
    fn check_exec_allows_in_scope_denies_out_of_scope() {
        let cx = ctx(Caveats {
            exec: Scope::only(["echo".to_string()]),
            ..Caveats::top()
        });
        assert!(cx.check_exec("echo").is_ok());
        assert!(cx.check_exec("rm").is_err());
    }

    #[test]
    fn check_net_allows_in_scope_denies_out_of_scope() {
        let cx = ctx(Caveats {
            net: Scope::only(["example.com".to_string()]),
            ..Caveats::top()
        });
        assert!(cx.check_net("example.com").is_ok());
        assert!(cx.check_net("evil.test").is_err());
    }

    #[test]
    fn check_path_write_denies_outside_scope() {
        let dir = std::env::temp_dir();
        let cx = ctx(Caveats {
            fs_write: Scope::only([dir.to_string_lossy().into_owned()]),
            ..Caveats::top()
        });
        // A new file directly under the allowed dir is fine.
        assert!(cx.check_path_write(&dir.join("brandnew.txt")).is_ok());
        // Somewhere clearly outside is denied.
        assert!(cx.check_path_write(Path::new("/etc/shadow")).is_err());
    }

    /// The load-bearing security test (DESIGN §6): canonicalize BEFORE the
    /// membership test, so a `..` traversal and a symlink that escapes the
    /// granted scope are both denied. A naive string-prefix check would let
    /// both through.
    #[test]
    fn check_path_write_rejects_dotdot_and_symlink_escape() {
        use std::fs;

        // Unique sandbox root so concurrent test runs don't collide.
        let root = std::env::temp_dir().join(format!(
            "agent-bridle-pathtest-{}-{}",
            std::process::id(),
            // A monotonic-ish disambiguator that is NOT used for coordination —
            // just a unique dir name. (Counter, not a clock.)
            COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let allowed = root.join("allowed");
        let secret_dir = root.join("secret");
        fs::create_dir_all(&allowed).expect("mkdir allowed");
        fs::create_dir_all(&secret_dir).expect("mkdir secret");
        let secret_file = secret_dir.join("loot.txt");
        fs::write(&secret_file, b"top secret").expect("write secret");

        // Grant fs_write ONLY to `allowed`.
        let cx = ctx(Caveats {
            fs_write: Scope::only([allowed.to_string_lossy().into_owned()]),
            ..Caveats::top()
        });

        // (a) A file genuinely inside the allowed dir is permitted.
        assert!(cx.check_path_write(&allowed.join("ok.txt")).is_ok());

        // (b) `allowed/../secret/loot.txt` escapes the scope; after
        // canonicalization it resolves under `secret`, NOT `allowed`. DENIED.
        let dotdot = allowed.join("..").join("secret").join("loot.txt");
        assert!(
            cx.check_path_write(&dotdot).is_err(),
            "..-traversal out of scope must be denied (got Ok for {dotdot:?})"
        );

        // (c) A symlink *inside* the allowed dir pointing OUT to the secret dir.
        // String-prefix matching would see the path start with `allowed/` and
        // wrongly allow it; canonicalization follows the link to `secret` and
        // DENIES.
        #[cfg(unix)]
        {
            let link = allowed.join("escape");
            std::os::unix::fs::symlink(&secret_dir, &link).expect("symlink");
            let via_symlink = link.join("loot.txt");
            assert!(
                cx.check_path_write(&via_symlink).is_err(),
                "symlink escape must be denied (got Ok for {via_symlink:?})"
            );
        }

        // Best-effort cleanup of our own scratch.
        let _ = fs::remove_dir_all(&root);
    }

    /// Regression for the **dangling-symlink write escape** (security audit,
    /// 2026-06-03). Mirrors [`check_path_write_rejects_dotdot_and_symlink_escape`]
    /// but for a symlink whose target **does not yet exist** — the gap the old
    /// `exists()`-based tail walk missed.
    ///
    /// Before the fix, `canonicalize_for_check` used `existing.exists()` (which
    /// FOLLOWS symlinks): a symlink inside the allowed dir pointing OUTSIDE it,
    /// whose target was absent, reported `exists() == false`, so the link's own
    /// name was pushed as a plain non-existent tail component and never resolved.
    /// The path canonicalized to *itself* (in-scope) and `path_is_within`
    /// returned true — yet a real `open(O_CREAT)` follows the link and writes out
    /// of scope. PROVEN: `ln -s <outside>/real <allowed>/inno` (real absent),
    /// `echo PWNED > <allowed>/inno` wrote `<outside>/real`.
    #[cfg(unix)]
    #[test]
    fn check_path_write_rejects_dangling_symlink_escape() {
        use std::fs;

        let root = std::env::temp_dir().join(format!(
            "agent-bridle-dangling-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let allowed = root.join("allowed");
        let outside = root.join("outside");
        fs::create_dir_all(&allowed).expect("mkdir allowed");
        fs::create_dir_all(&outside).expect("mkdir outside");

        // Grant fs_write ONLY to `allowed`.
        let cx = ctx(Caveats {
            fs_write: Scope::only([allowed.to_string_lossy().into_owned()]),
            ..Caveats::top()
        });

        // A symlink INSIDE the allowed dir whose target is OUTSIDE and does NOT
        // yet exist. This is the escape the audit found.
        let link = allowed.join("inno");
        let outside_target = outside.join("real"); // intentionally absent
        assert!(
            !outside_target.exists(),
            "precondition: the symlink target must not yet exist"
        );
        std::os::unix::fs::symlink(&outside_target, &link).expect("symlink");

        // (a) Writing THROUGH the dangling out-of-scope symlink must be DENIED —
        // it resolves to `outside/real`, not under `allowed`.
        assert!(
            cx.check_path_write(&link).is_err(),
            "dangling out-of-scope symlink write must be denied (got Ok for {link:?})"
        );
        // The escape would have created the file outside; assert it did not (the
        // check denies *before* any open, so nothing is created).
        assert!(
            !outside_target.exists(),
            "the denied write must not have created the outside file"
        );

        // (b) An in-scope symlink — pointing to a (dangling) name that still
        // resolves INSIDE `allowed` — must be ALLOWED (no false denial).
        let in_link = allowed.join("inside-link");
        let in_target = allowed.join("brandnew.txt"); // absent, but in-scope
        std::os::unix::fs::symlink(&in_target, &in_link).expect("in-scope symlink");
        assert!(
            cx.check_path_write(&in_link).is_ok(),
            "in-scope symlink (resolving inside scope) must be allowed (got Err for {in_link:?})"
        );

        // (c) A plain new in-scope file still succeeds.
        assert!(
            cx.check_path_write(&allowed.join("plain.txt")).is_ok(),
            "plain in-scope create must still succeed"
        );

        // (d) An INTERIOR dangling symlink (not the final component) that escapes
        // must also be denied: `allowed/inno/child.txt` where `inno` -> outside.
        let via_interior = link.join("child.txt");
        assert!(
            cx.check_path_write(&via_interior).is_err(),
            "write through an interior out-of-scope symlink must be denied (got Ok for {via_interior:?})"
        );

        let _ = fs::remove_dir_all(&root);
    }

    /// Test-only unique-name disambiguator (a counter, never a clock).
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    #[test]
    fn caveats_and_sandbox_kind_are_exposed() {
        let cx = ctx(Caveats {
            max_calls: CountBound::AtMost(3),
            ..Caveats::top()
        });
        assert_eq!(cx.caveats().max_calls, CountBound::AtMost(3));
        assert_eq!(cx.sandbox_kind(), SandboxKind::None);
    }
}
