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
    /// Allowed iff `exec` is `All`, or the bounded `exec` scope contains the
    /// program **as named** (the string passed in, typically argv0 or a
    /// PATH-resolved absolute path) **or its basename**
    /// (`Path::new(program).file_name()`).
    ///
    /// This is what makes *bare-name* grants usable: a grant of `["git"]`
    /// allows `git`, `/usr/bin/git`, and `/opt/homebrew/bin/git` alike, because
    /// the resolved absolute path the interceptor hands in has basename `git`.
    /// To pin an exact executable instead, **grant a full path**: a grant of
    /// `["/usr/bin/git"]` matches only `/usr/bin/git`, not a `git` found
    /// elsewhere on PATH.
    ///
    /// Security tradeoff: a bare-name grant authorizes *any* binary named
    /// `git` reachable on PATH (PATH ordering / shadowing decides which one
    /// actually runs). When that ambiguity is unacceptable, grant the full
    /// path to pin exactly. A grant that contains a path separator only ever
    /// matches that exact path (its basename is still considered, but a grant
    /// like `["/bin/echo"]` will not be matched by a bare `echo` because the
    /// grant's own basename `echo` is compared against the program token, not
    /// the reverse — see [`exec_scope_allows`]). Out-of-scope programs are
    /// denied here, before the tool spawns anything.
    pub fn check_exec(&self, program: &str) -> ToolResult<()> {
        if exec_scope_allows(&self.effective.exec, program) {
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

/// `scope.contains(item)` for the exact string axis (`net` host matching).
///
/// This stays a strict membership test — network hosts must match exactly and
/// must NOT be subjected to basename matching. Only `check_net` uses this.
fn scope_allows(scope: &Scope<String>, item: &str) -> bool {
    match scope {
        Scope::All => true,
        Scope::Only(set) => set.contains(item),
    }
}

/// Exec-axis membership: `All`, OR the bounded set contains the program string
/// **as given**, OR the set contains the program's **basename**.
///
/// Basename matching is what lets a bare-name grant (`["git"]`) match the
/// resolved absolute path the brush interceptor hands in (`/usr/bin/git`),
/// while a full-path grant (`["/usr/bin/git"]`) still pins exactly because the
/// program string passed in is compared verbatim first. This is deliberately
/// distinct from [`scope_allows`] (host matching), which must stay exact.
fn exec_scope_allows(scope: &Scope<String>, program: &str) -> bool {
    let set = match scope {
        Scope::All => return true,
        Scope::Only(set) => set,
    };
    // Exact match against the token as named (full-path grants pin here).
    if set.contains(program) {
        return true;
    }
    // Basename match: a bare-name grant matches any resolved path with that
    // basename. `["git"]` allows `/usr/bin/git`; `["echo"]` does NOT allow
    // `/bin/rm` because the basename `rm` is not in the grant.
    if let Some(base) = Path::new(program).file_name().and_then(|b| b.to_str()) {
        if set.contains(base) {
            return true;
        }
    }
    false
}

/// Resolve a path for a leash check.
///
/// We must reject symlink escapes *before* membership, but we also must support
/// checking a path whose final component does not exist yet (the common
/// `fs_write` case: creating a new file under an allowed directory). So we
/// canonicalize the deepest existing ancestor and re-attach the trailing
/// not-yet-existing components, rejecting any `..` we cannot resolve away.
fn canonicalize_for_check(path: &Path) -> std::io::Result<PathBuf> {
    // Fast path: the whole thing exists (this also resolves all symlinks).
    if let Ok(c) = path.canonicalize() {
        return Ok(c);
    }

    // Walk up to the deepest existing ancestor, canonicalize it (resolving any
    // symlinks in the existing prefix), then re-append the tail. Reject `..`
    // and `.` in the tail rather than letting them silently climb — `..` past a
    // canonical, symlink-free base would be an escape we refuse to normalize.
    let mut existing = path;
    let mut tail: Vec<Component<'_>> = Vec::new();
    loop {
        if existing.exists() {
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

    let mut base = existing.canonicalize()?;
    for comp in tail.into_iter().rev() {
        match comp {
            Component::Normal(name) => base.push(name),
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

    /// A bare-name grant must match the RESOLVED ABSOLUTE PATH the interceptor
    /// hands in. This is the usability bug: `["git"]` previously denied
    /// `/usr/bin/git` because membership was exact on the full path. Now the
    /// basename matches.
    #[test]
    fn check_exec_bare_name_grant_matches_resolved_paths() {
        let cx = ctx(Caveats {
            exec: Scope::only(["git".to_string()]),
            ..Caveats::top()
        });
        // Bare name itself.
        assert!(cx.check_exec("git").is_ok());
        // Resolved absolute paths with basename `git`.
        assert!(cx.check_exec("/usr/bin/git").is_ok());
        assert!(cx.check_exec("/opt/homebrew/bin/git").is_ok());
    }

    /// A FULL-PATH grant is the escape hatch for exactness: it pins to exactly
    /// that path and does NOT allow a same-named binary found elsewhere.
    #[test]
    fn check_exec_full_path_grant_pins_exactly() {
        let cx = ctx(Caveats {
            exec: Scope::only(["/usr/bin/git".to_string()]),
            ..Caveats::top()
        });
        // The exact pinned path is allowed.
        assert!(cx.check_exec("/usr/bin/git").is_ok());
        // A `git` somewhere else is denied — full-path grant pins.
        assert!(cx.check_exec("/opt/homebrew/bin/git").is_err());
        // NOTE: a bare `git` carries basename `git`, which is not equal to the
        // full-path grant token, so it is denied too.
        assert!(cx.check_exec("git").is_err());
    }

    /// Path-separator deny is preserved: granting `echo` must not let `/bin/rm`
    /// through, because the basename `rm` was never granted.
    #[test]
    fn check_exec_basename_deny_preserved() {
        let cx = ctx(Caveats {
            exec: Scope::only(["echo".to_string()]),
            ..Caveats::top()
        });
        assert!(cx.check_exec("/bin/rm").is_err());
        // And `echo` granted does allow a resolved `/bin/echo` via basename.
        assert!(cx.check_exec("/bin/echo").is_ok());
    }

    /// `All` allows anything on the exec axis.
    #[test]
    fn check_exec_all_allows_anything() {
        let cx = ctx(Caveats {
            exec: Scope::All,
            ..Caveats::top()
        });
        assert!(cx.check_exec("git").is_ok());
        assert!(cx.check_exec("/usr/bin/anything").is_ok());
        assert!(cx.check_exec("/bin/rm").is_ok());
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
