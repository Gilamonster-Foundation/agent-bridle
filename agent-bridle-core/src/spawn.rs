//! Spawn an **arbitrary** child process confined by a [`ToolContext`]'s caveats.
//!
//! The in-process leash (L2) and the shell tool confine work that runs *inside*
//! the bridle process. But a host often needs to launch a separate program — an
//! MCP capability server, a language runtime — and put *it* under the leash. L2
//! cannot follow a child across `execve`, so on Linux the **only** boundary that
//! confines a spawned program's own syscalls is the Landlock sandbox (L3,
//! [`crate::sandbox`]).
//!
//! [`ConfinedCommand`] is that primitive. It is deliberately *not* a confused
//! deputy: the parent attenuates **before** the spawn (the child is never trusted
//! to confine itself), the environment is **cleared** so nothing ambient leaks
//! (only explicitly-granted vars reach the child — the external-boundary
//! invariant), and exec is admission-checked against the granted `exec` scope.
//!
//! Mechanism (mirrors [`crate::sandbox`]'s contract): `restrict_self` is
//! per-thread and inherited across `fork`/`execve`, so the sandbox is applied on
//! a fresh, throwaway thread that then performs the spawn. The child — and every
//! descendant it forks — inherits the Landlock domain; the thread exits, leaving
//! the caller's own threads unrestricted.
//!
//! Honesty & fail-closed: the achieved [`SandboxKind`] is returned on the
//! [`ConfinedChild`]. When `fs_write` is meaningfully restricted (`Only(..)`) but
//! no OS sandbox can enforce it (e.g. off-Linux, or a kernel without Landlock),
//! the spawn is **refused** rather than launched unconfined — a restrictive
//! grant that cannot be enforced would be a lie. (Today only `fs_write` is
//! L3-enforced; `fs_read`/`exec`/`net` confinement of the child is advisory and
//! not yet part of this guarantee — see [`crate::sandbox`] and ADR 0001.)

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use crate::{
    best_available_sandbox, effective_sandbox_kind, Caveats, SandboxKind, Scope, ToolContext,
    ToolError, ToolResult,
};

/// A spawned child together with the OS sandbox actually in force around it.
///
/// The caller owns `child` (it does its own `wait`/`kill`/pipe plumbing).
/// `sandbox_kind` is the honest record of what confinement was achieved —
/// [`SandboxKind::None`] means the leash on this child is advisory only.
#[derive(Debug)]
pub struct ConfinedChild {
    /// The spawned process.
    pub child: Child,
    /// The OS-level sandbox actually applied to the child.
    pub sandbox_kind: SandboxKind,
}

/// Builder for a subprocess confined by a [`ToolContext`].
///
/// Like [`std::process::Command`], but: the environment starts **empty** (only
/// vars added with [`ConfinedCommand::env`] reach the child), and
/// [`ConfinedCommand::spawn`] admission-checks `exec`, applies the OS sandbox,
/// and fails closed when a restrictive `fs_write` cannot be enforced.
#[derive(Debug)]
pub struct ConfinedCommand {
    program: String,
    args: Vec<OsString>,
    envs: Vec<(OsString, OsString)>,
    cwd: Option<PathBuf>,
    stdin: Option<Stdio>,
    stdout: Option<Stdio>,
    stderr: Option<Stdio>,
}

impl ConfinedCommand {
    /// Start building a confined spawn of `program` (no inherited environment).
    pub fn new(program: impl Into<String>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            envs: Vec::new(),
            cwd: None,
            stdin: None,
            stdout: None,
            stderr: None,
        }
    }

    /// Append a single argument.
    #[must_use]
    pub fn arg(mut self, arg: impl AsRef<OsStr>) -> Self {
        self.args.push(arg.as_ref().to_os_string());
        self
    }

    /// Append several arguments.
    #[must_use]
    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        self.args
            .extend(args.into_iter().map(|a| a.as_ref().to_os_string()));
        self
    }

    /// Grant one environment variable to the child. This is the **only** way an
    /// env var reaches the child — there is no ambient inheritance.
    #[must_use]
    pub fn env(mut self, key: impl AsRef<OsStr>, val: impl AsRef<OsStr>) -> Self {
        self.envs
            .push((key.as_ref().to_os_string(), val.as_ref().to_os_string()));
        self
    }

    /// Set the child's working directory.
    #[must_use]
    pub fn current_dir(mut self, dir: impl AsRef<Path>) -> Self {
        self.cwd = Some(dir.as_ref().to_path_buf());
        self
    }

    /// Configure the child's stdin (e.g. [`Stdio::piped`] for an MCP server).
    #[must_use]
    pub fn stdin(mut self, cfg: Stdio) -> Self {
        self.stdin = Some(cfg);
        self
    }

    /// Configure the child's stdout.
    #[must_use]
    pub fn stdout(mut self, cfg: Stdio) -> Self {
        self.stdout = Some(cfg);
        self
    }

    /// Configure the child's stderr.
    #[must_use]
    pub fn stderr(mut self, cfg: Stdio) -> Self {
        self.stderr = Some(cfg);
        self
    }

    /// Admission-check, confine, and spawn the child.
    ///
    /// Order: (1) `cx.check_exec(program)` — deny before doing anything; (2) if
    /// `fs_write` is restricted but unenforceable here, refuse (fail closed);
    /// (3) on a fresh thread, apply the best available sandbox to that thread,
    /// then `spawn` so the child inherits the domain.
    pub fn spawn(self, cx: &ToolContext) -> ToolResult<ConfinedChild> {
        // (1) Admission: the parent must be permitted to exec this program.
        cx.check_exec(&self.program)?;

        let effective = cx.caveats().clone();
        let sandbox = best_available_sandbox();
        let kind = sandbox.kind();

        // (2) Fail closed: a restrictive write grant we cannot enforce is a lie.
        if confinement_unenforceable(kind, &effective) {
            return Err(ToolError::denied(format!(
                "refusing to spawn {:?}: fs_write is restricted but no OS sandbox is \
                 available to enforce it on a subprocess (sandbox_kind = none)",
                self.program
            )));
        }

        // For a *wrapper-based* backend (macOS Seatbelt) this is the
        // `sandbox-exec -p <profile>` argv that confines the child; empty for
        // thread-confining backends (Landlock, via `apply`) and Noop. Computed
        // here so a fail-closed wrapper error aborts *before* we spawn the thread.
        let prefix = sandbox.command_prefix(&effective)?;

        // The honest kind to report on the child: the backend's kind only when an
        // fs axis is actually restricted (so it confines something), else `None`.
        // Without an fs restriction a wrapper backend applies *nothing* (empty
        // prefix + no-op `apply`), so reporting its kind would overclaim (I9 /
        // ADR 0006 D3). Mirrors the shell engine's `intended_sandbox_kind`.
        let reported_kind = effective_sandbox_kind(kind, &effective);

        // (3) Apply the sandbox on a throwaway thread, then spawn on it so the
        //     child inherits the OS confinement — the per-thread, fork/exec-
        //     inherited Landlock domain and/or the `sandbox-exec` wrapper.
        let Self {
            program,
            args,
            envs,
            cwd,
            stdin,
            stdout,
            stderr,
        } = self;

        let spawned = std::thread::spawn(move || -> ToolResult<Child> {
            // L3 on this very thread, before the spawn. `apply` is fail-closed:
            // if the kernel did not actually enforce, it returns Err and we never
            // spawn.
            sandbox.apply(&effective)?;

            // Wrap the child in the backend's command prefix when it confines via
            // a wrapper (Seatbelt); otherwise spawn the program directly.
            let (spawn_program, spawn_args) = wrap_argv(&prefix, &program, &args);
            let mut cmd = Command::new(&spawn_program);
            cmd.args(&spawn_args);
            cmd.env_clear(); // no ambient environment crosses the boundary …
            for (k, v) in &envs {
                cmd.env(k, v); // … only the explicitly-granted vars.
            }
            if let Some(dir) = &cwd {
                cmd.current_dir(dir);
            }
            if let Some(cfg) = stdin {
                cmd.stdin(cfg);
            }
            if let Some(cfg) = stdout {
                cmd.stdout(cfg);
            }
            if let Some(cfg) = stderr {
                cmd.stderr(cfg);
            }
            cmd.spawn().map_err(ToolError::from)
        })
        .join()
        .map_err(|_| ToolError::denied("confined-spawn thread panicked before exec"))?;

        Ok(ConfinedChild {
            child: spawned?,
            sandbox_kind: reported_kind,
        })
    }
}

/// Spawn `program args` confined by `cx`, with the inherited stdio of the parent.
///
/// The convenience form of [`ConfinedCommand`]: `env_allow` is the child's
/// **entire** environment (nothing else is inherited). For piped stdio (an MCP
/// server), use [`ConfinedCommand`] directly.
pub fn spawn_confined_subprocess(
    program: &str,
    args: &[String],
    cx: &ToolContext,
    env_allow: &[(String, String)],
    cwd: Option<&Path>,
) -> ToolResult<ConfinedChild> {
    let mut cmd = ConfinedCommand::new(program).args(args);
    for (k, v) in env_allow {
        cmd = cmd.env(k, v);
    }
    if let Some(dir) = cwd {
        cmd = cmd.current_dir(dir);
    }
    cmd.spawn(cx)
}

/// Prepend a backend command prefix (Seatbelt's `sandbox-exec -p <profile>`) to
/// a `(program, args)`, yielding the argv to actually spawn. An empty prefix is
/// the identity — thread-confining (Landlock) and Noop backends spawn the
/// program directly. Under Seatbelt the program should be an absolute path
/// (the environment is scrubbed, so `sandbox-exec` cannot resolve a bare name
/// via `PATH`).
fn wrap_argv(prefix: &[String], program: &str, args: &[OsString]) -> (OsString, Vec<OsString>) {
    if prefix.is_empty() {
        return (OsString::from(program), args.to_vec());
    }
    let mut argv: Vec<OsString> = prefix[1..].iter().map(OsString::from).collect();
    argv.push(OsString::from(program));
    argv.extend(args.iter().cloned());
    (OsString::from(&prefix[0]), argv)
}

/// Would confining this child be a *lie*? True iff the kernel/OS cannot enforce a
/// meaningfully-restricted `fs_write` grant.
///
/// Only `fs_write` is L3-enforceable today, so it is the only axis that
/// participates in the fail-closed decision; `fs_read`/`exec`/`net` confinement
/// of a subprocess is advisory until those L3 backends land (ADR 0001).
fn confinement_unenforceable(kind: SandboxKind, caveats: &Caveats) -> bool {
    kind == SandboxKind::None && matches!(caveats.fs_write, Scope::Only(_))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Gate, Tool};

    /// Mint a `ToolContext` the only legitimate way — through the gate.
    fn ctx(granted: Caveats) -> ToolContext {
        struct AnyTool;
        #[async_trait::async_trait]
        impl Tool for AnyTool {
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
        Gate::new(0)
            .authorize(&AnyTool, &granted)
            .expect("authorize")
    }

    #[test]
    fn exec_outside_scope_is_denied_before_any_spawn() {
        let cx = ctx(Caveats {
            exec: Scope::only(["echo".to_string()]),
            ..Caveats::top()
        });
        let res = ConfinedCommand::new("rm").arg("-rf").spawn(&cx);
        assert!(matches!(res, Err(ToolError::Denied { .. })));
    }

    #[test]
    fn unenforceable_predicate_only_trips_on_restricted_write_without_sandbox() {
        let restricted = Caveats {
            fs_write: Scope::only(["/tmp/x".to_string()]),
            ..Caveats::top()
        };
        // Restricted write + no OS sandbox => unenforceable (must refuse).
        assert!(confinement_unenforceable(SandboxKind::None, &restricted));
        // Same grant, but the kernel can enforce it => fine.
        assert!(!confinement_unenforceable(
            SandboxKind::Landlock,
            &restricted
        ));
        // Unrestricted write => nothing to enforce, even with no sandbox.
        assert!(!confinement_unenforceable(
            SandboxKind::None,
            &Caveats::top()
        ));
    }

    /// Builds with **no** available OS sandbox: a restrictive `fs_write` must be
    /// refused rather than spawned unconfined. Gated off where a backend can
    /// actually enforce (Linux+Landlock, macOS+Seatbelt) — there the spawn is
    /// confined, not refused, so this fail-closed path does not fire.
    #[cfg(not(any(
        all(target_os = "linux", feature = "linux-landlock"),
        all(target_os = "macos", feature = "macos-seatbelt")
    )))]
    #[test]
    fn restrictive_write_refused_when_no_sandbox_available() {
        let cx = ctx(Caveats {
            exec: Scope::All,
            fs_write: Scope::only(["/tmp/allowed".to_string()]),
            ..Caveats::top()
        });
        let res = ConfinedCommand::new("true").spawn(&cx);
        assert!(
            matches!(res, Err(ToolError::Denied { .. })),
            "must fail closed when confinement is requested but unenforceable"
        );
    }

    /// The environment is scrubbed: only granted vars reach the child, nothing
    /// ambient (e.g. the parent's `HOME`) leaks. Uses a piped stdout to read the
    /// child's view of its own environment.
    #[cfg(unix)]
    #[test]
    fn environment_is_scrubbed_to_the_granted_allow_list() {
        let env_bin = ["/usr/bin/env", "/bin/env"]
            .into_iter()
            .find(|p| Path::new(p).exists());
        let Some(env_bin) = env_bin else {
            eprintln!("skipping env-scrub test: no env(1) found");
            return;
        };
        // fs_write unrestricted (env(1) writes only to its stdout pipe, not the
        // filesystem), exec pinned to env.
        let cx = ctx(Caveats {
            exec: Scope::only(["env".to_string()]),
            ..Caveats::top()
        });
        let spawned = ConfinedCommand::new(env_bin)
            .env("ALLOWED", "yes")
            .stdout(Stdio::piped())
            .spawn(&cx)
            .expect("spawn env");
        let out = spawned.child.wait_with_output().expect("wait");
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(text.contains("ALLOWED=yes"), "granted var must be present");
        assert!(
            !text.contains("HOME="),
            "ambient parent env must NOT leak into the child: {text:?}"
        );
    }
}

// Kernel-enforcement proof: the *spawned child* (not just the parent thread)
// inherits the Landlock `fs_write` domain. Only meaningful on Linux with the
// feature and a capable kernel.
#[cfg(all(target_os = "linux", feature = "linux-landlock", test))]
mod landlock_child_tests {
    use super::*;
    use crate::{landlock_is_supported, Gate, Tool};
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn ctx(granted: Caveats) -> ToolContext {
        struct AnyTool;
        #[async_trait::async_trait]
        impl Tool for AnyTool {
            fn name(&self) -> &str {
                "any"
            }
            fn schema(&self) -> serde_json::Value {
                serde_json::json!({})
            }
            async fn invoke(
                &self,
                _a: serde_json::Value,
                _c: &ToolContext,
            ) -> ToolResult<serde_json::Value> {
                Ok(serde_json::Value::Null)
            }
        }
        Gate::new(0)
            .authorize(&AnyTool, &granted)
            .expect("authorize")
    }

    fn unique_dir(tag: &str) -> PathBuf {
        static N: AtomicU64 = AtomicU64::new(0);
        let mut d = std::env::temp_dir();
        d.push(format!(
            "agent-bridle-spawn-{}-{}-{}",
            tag,
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn child_inherits_fs_write_domain_out_of_scope_denied_in_scope_allowed() {
        if !landlock_is_supported() {
            eprintln!("skipping: kernel lacks Landlock");
            return;
        }
        let touch = ["/usr/bin/touch", "/bin/touch"]
            .into_iter()
            .find(|p| std::path::Path::new(p).exists());
        let Some(touch) = touch else {
            eprintln!("skipping: no touch(1) found");
            return;
        };

        let allowed = unique_dir("allowed");
        let forbidden = unique_dir("forbidden");
        let cx = ctx(Caveats {
            exec: Scope::only(["touch".to_string()]),
            fs_write: Scope::only([allowed.to_string_lossy().into_owned()]),
            ..Caveats::top()
        });

        // Out of scope: the child's own write is kernel-denied → non-zero exit.
        let mut out = ConfinedCommand::new(touch)
            .arg(forbidden.join("escape.txt"))
            .spawn(&cx)
            .expect("spawn");
        assert_eq!(out.sandbox_kind, SandboxKind::Landlock);
        let status = out.child.wait().expect("wait");
        assert!(
            !status.success(),
            "child write outside fs_write must be kernel-denied"
        );
        assert!(!forbidden.join("escape.txt").exists());

        // In scope: the child write succeeds.
        let mut ok = ConfinedCommand::new(touch)
            .arg(allowed.join("ok.txt"))
            .spawn(&cx)
            .expect("spawn");
        assert!(ok.child.wait().expect("wait").success());
        assert!(allowed.join("ok.txt").exists());

        let _ = fs::remove_dir_all(&allowed);
        let _ = fs::remove_dir_all(&forbidden);
    }
}

// Kernel-enforcement proof for macOS: the *spawned child* (not just the parent)
// is confined by the Seatbelt `sandbox-exec` wrapper that `ConfinedCommand`
// applies — the spawn.rs analog of the Landlock child proof above.
#[cfg(all(target_os = "macos", feature = "macos-seatbelt", test))]
mod seatbelt_child_tests {
    use super::*;
    use crate::{seatbelt_is_supported, Gate, Tool};
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn ctx(granted: Caveats) -> ToolContext {
        struct AnyTool;
        #[async_trait::async_trait]
        impl Tool for AnyTool {
            fn name(&self) -> &str {
                "any"
            }
            fn schema(&self) -> serde_json::Value {
                serde_json::json!({})
            }
            async fn invoke(
                &self,
                _a: serde_json::Value,
                _c: &ToolContext,
            ) -> ToolResult<serde_json::Value> {
                Ok(serde_json::Value::Null)
            }
        }
        Gate::new(0)
            .authorize(&AnyTool, &granted)
            .expect("authorize")
    }

    fn unique_dir(tag: &str) -> PathBuf {
        static N: AtomicU64 = AtomicU64::new(0);
        let mut d = std::env::temp_dir();
        d.push(format!(
            "agent-bridle-spawn-sb-{}-{}-{}",
            tag,
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn child_inherits_fs_write_domain_out_of_scope_denied_in_scope_allowed() {
        if !seatbelt_is_supported() {
            eprintln!("skipping: /usr/bin/sandbox-exec unavailable");
            return;
        }
        let allowed = unique_dir("allowed");
        let forbidden = unique_dir("forbidden");
        let cx = ctx(Caveats {
            // Absolute program path: the environment is scrubbed, so sandbox-exec
            // cannot resolve a bare name via PATH (see `wrap_argv`).
            exec: Scope::only(["/usr/bin/touch".to_string()]),
            fs_write: Scope::only([allowed.to_string_lossy().into_owned()]),
            ..Caveats::top()
        });

        // Out of scope: the child's own write is kernel-denied → non-zero exit.
        let mut out = ConfinedCommand::new("/usr/bin/touch")
            .arg(forbidden.join("escape.txt"))
            .spawn(&cx)
            .expect("spawn");
        assert_eq!(out.sandbox_kind, SandboxKind::Seatbelt);
        let status = out.child.wait().expect("wait");
        assert!(
            !status.success(),
            "child write outside fs_write must be kernel-denied"
        );
        assert!(!forbidden.join("escape.txt").exists());

        // In scope: the child write succeeds.
        let mut ok = ConfinedCommand::new("/usr/bin/touch")
            .arg(allowed.join("ok.txt"))
            .spawn(&cx)
            .expect("spawn");
        assert!(ok.child.wait().expect("wait").success());
        assert!(allowed.join("ok.txt").exists());

        let _ = fs::remove_dir_all(&allowed);
        let _ = fs::remove_dir_all(&forbidden);
    }

    /// Honesty (I9): with no fs axis restricted, the Seatbelt wrapper applies
    /// *nothing*, so the child must be reported as `None`, never `Seatbelt`. This
    /// is the regression for the overclaim where `sandbox_kind` was the raw
    /// backend kind regardless of whether anything was confined.
    #[test]
    fn unrestricted_fs_reports_none_not_seatbelt() {
        if !seatbelt_is_supported() {
            eprintln!("skipping: /usr/bin/sandbox-exec unavailable");
            return;
        }
        // exec restricted but both fs axes `All` — a permissive grant a host might
        // give an MCP server. Nothing fs to confine.
        let cx = ctx(Caveats {
            exec: Scope::only(["/usr/bin/true".to_string()]),
            ..Caveats::top()
        });
        let child = ConfinedCommand::new("/usr/bin/true")
            .spawn(&cx)
            .expect("spawn");
        assert_eq!(
            child.sandbox_kind,
            SandboxKind::None,
            "no fs restriction => nothing confined => must report None, not Seatbelt"
        );
    }
}
