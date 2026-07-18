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

use std::sync::Arc;

use crate::{
    best_available_sandbox, effective_sandbox_kind, enforcement_report, fence_strength,
    AxisEnforcement, Caveats, SandboxKind, SandboxPolicy, ToolContext, ToolError, ToolResult,
};
// Used only by the test modules below (each `use super::*`); kept here so all
// three (`tests`, `landlock_child_tests`, `seatbelt_child_tests`) see it without
// an unused-import warning in the non-test build.
#[cfg(test)]
use crate::Scope;

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
    /// The sandbox mechanism config (read/exec allow-lists). Rides the builder —
    /// NOT the `ToolContext`, which carries only authority (I5-B, #144, ADR 0017
    /// D2). Defaults to today's built-in allow-lists.
    sandbox_policy: Arc<SandboxPolicy>,
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
            sandbox_policy: Arc::new(SandboxPolicy::default()),
        }
    }

    /// Set the sandbox mechanism policy (read/exec allow-lists, ABI floors) the
    /// OS backend will enforce. The default is today's built-in allow-lists.
    #[must_use]
    pub fn sandbox_policy(mut self, policy: Arc<SandboxPolicy>) -> Self {
        self.sandbox_policy = policy;
        self
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
        let effective = cx.caveats().clone();
        self.spawn_with_effective(cx, effective)
    }

    /// The spawn body, parameterized over the **effective** caveats the OS
    /// sandbox confines to (#257). `spawn` passes the context's caveats
    /// verbatim; the egress-proxy path (`spawn_tokio` under a proxied-net
    /// grant) passes [`crate::loopback_fenced_caveats`] — same fs/exec axes,
    /// `net` swapped for the loopback fence. The exec admission-check always
    /// runs against the REAL context (the fence never widens or narrows exec).
    fn spawn_with_effective(
        self,
        cx: &ToolContext,
        effective: Caveats,
    ) -> ToolResult<ConfinedChild> {
        // (1) Admission: the parent must be permitted to exec this program.
        cx.check_exec(&self.program)?;

        let sandbox = best_available_sandbox(&self.sandbox_policy);
        let kind = sandbox.kind();
        // The kind that actually GOVERNS this spawn: the backend's kind only when
        // it will actually confine something (fs or net restricted), else `None`.
        // The fail-closed
        // check is decided against THIS, not the raw probe, so the check and the
        // routing cannot disagree (the adversarial-review fix: a raw
        // `enforcement_report` claim of fs→Kernel for a backend that is not
        // actually applied would otherwise pass a run the path executes
        // unconfined). Also the honest kind reported on the child (I9 / ADR 0006 D3).
        let reported_kind = effective_sandbox_kind(kind, &effective);

        // (2) Fail closed: a restricted axis the governing backend cannot enforce
        // at the principal's strength floor is a grant we'd be lying about.
        if confinement_unenforceable(reported_kind, &effective, cx.strength_floor()) {
            return Err(ToolError::denied(format!(
                "refusing to spawn {:?}: a restricted filesystem/exec/net axis cannot be \
                 enforced on a subprocess at the required strength floor ({:?}) by the \
                 governing sandbox ({:?})",
                self.program,
                cx.strength_floor(),
                reported_kind
            )));
        }

        // For a *wrapper-based* backend (macOS Seatbelt) this is the
        // `sandbox-exec -p <profile>` argv that confines the child; empty for
        // thread-confining backends (Landlock, via `apply`) and Noop. Computed
        // here so a fail-closed wrapper error aborts *before* we spawn the thread.
        let prefix = sandbox.command_prefix(&effective)?;

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
            // Already consumed above into `sandbox` via `best_available_sandbox`.
            sandbox_policy: _,
        } = self;

        let spawned = std::thread::spawn(move || -> ToolResult<Child> {
            // Thread-confining backends (Landlock): apply the sandbox on this
            // throwaway thread before the spawn so the child inherits the
            // Landlock domain. `apply` is fail-closed: if the kernel did not
            // actually enforce, it returns Err and we never spawn.
            //
            // Wrapper-based backends (Seatbelt, AppContainer): confinement is
            // achieved by the `command_prefix` wrapper — no per-thread state is
            // involved, and calling `apply` would be wrong (AppContainer fails
            // closed; Seatbelt is a no-op). Skip `apply` when the prefix is
            // non-empty.
            if prefix.is_empty() {
                sandbox.apply(&effective)?;
            }

            // Wrap the child in the backend's command prefix when it confines via
            // a wrapper (Seatbelt, AppContainer); otherwise spawn the program directly.
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

// ── Async-host spawn (tokio pipe handles) ────────────────────────────────────
//
// `spawn` above returns a `std::process::Child` — the caller owns the pipe
// plumbing. An async host (an MCP-server **stdio** transport speaking JSON-RPC
// over the child's stdin/stdout) needs those pipes as tokio-native, reactor-
// registered handles, and it needs the child reaped when the transport drops.
// `spawn_tokio` is that async-facing sibling: the confinement is **identical**
// (it calls `spawn`, so the admission-check / OS-sandbox / env-scrub are the
// same audited path — the boundary is unchanged), only the returned handle
// types differ. Unix-only and gated on `spawn-tokio`, so core stays tokio-free
// by default (the confinement primitives themselves have no async dependency).
#[cfg(all(unix, feature = "spawn-tokio"))]
pub use tokio_spawn::ConfinedTokioChild;

#[cfg(all(unix, feature = "spawn-tokio"))]
mod tokio_spawn {
    use super::{ConfinedChild, ConfinedCommand, SandboxKind, ToolContext, ToolResult};
    use crate::net_proxy::ProxyHandle;
    use crate::{egress_proxy_plan, ToolError};
    use std::os::fd::OwnedFd;
    use std::process::Child;
    use tokio::net::unix::pipe;

    /// A confined child whose stdio is exposed as **tokio-native** pipe handles,
    /// for an async host (e.g. an MCP-server stdio transport). The async-facing
    /// sibling of [`ConfinedChild`](super::ConfinedChild): the confinement is
    /// identical (produced by [`ConfinedCommand::spawn`]), only the pipe types
    /// differ.
    ///
    /// **Kill-on-drop.** Dropping this SIGKILLs the child and reaps it on a
    /// detached thread — restoring the guarantee a host loses by moving off
    /// `tokio::process::Command::kill_on_drop(true)` onto the std child
    /// underneath (tokio's runtime reaper only tracks *its own* children, so the
    /// std child would otherwise linger as a zombie). Take the pipe ends with
    /// the `take_*` accessors; the child stays owned here so this value's
    /// lifetime governs the process.
    #[derive(Debug)]
    pub struct ConfinedTokioChild {
        /// The OS-level sandbox actually applied to the child — the honest record
        /// (mirrors [`ConfinedChild::sandbox_kind`](super::ConfinedChild)).
        pub sandbox_kind: SandboxKind,
        stdin: Option<pipe::Sender>,
        stdout: Option<pipe::Receiver>,
        stderr: Option<pipe::Receiver>,
        /// `Some` until dropped; owned so kill-on-drop governs the process.
        child: Option<Child>,
        /// The live egress proxy fencing this child's net (#257) — `Some` iff the
        /// grant was a general remote-host allow-list AND the loopback kernel
        /// fence engaged. Owned here so the proxy's lifetime brackets the
        /// child's: it is torn down after the child is killed on drop.
        proxy: Option<ProxyHandle>,
    }

    impl ConfinedTokioChild {
        /// Take the child's stdin pipe (writer). `None` if stdin was not
        /// [`piped`](std::process::Stdio::piped) or was already taken.
        pub fn take_stdin(&mut self) -> Option<pipe::Sender> {
            self.stdin.take()
        }

        /// Take the child's stdout pipe (reader). `None` if stdout was not piped
        /// or was already taken.
        pub fn take_stdout(&mut self) -> Option<pipe::Receiver> {
            self.stdout.take()
        }

        /// Take the child's stderr pipe (reader). `None` if stderr was not piped
        /// or was already taken.
        pub fn take_stderr(&mut self) -> Option<pipe::Receiver> {
            self.stderr.take()
        }

        /// Whether this child's egress is fenced through the loopback proxy
        /// (#257): kernel-fenced to loopback, per-host allow-list enforced by
        /// the proxy it is pointed at via `*_PROXY` env.
        pub fn egress_proxied(&self) -> bool {
            self.proxy.is_some()
        }

        /// The off-allow-list hosts the child tried to reach through the proxy
        /// (#196) — each was refused with 403. Empty when no proxy is in force
        /// or nothing was refused. The exfil-attempt signal a host surfaces as
        /// structured `net` denials.
        pub fn refused_hosts(&self) -> Vec<String> {
            self.proxy
                .as_ref()
                .map(ProxyHandle::refused_hosts)
                .unwrap_or_default()
        }
    }

    impl Drop for ConfinedTokioChild {
        fn drop(&mut self) {
            // Reinstate kill-on-drop. `spawn_tokio` hands back a std child, which
            // tokio's runtime reaper does NOT track — so kill it and `wait` on a
            // detached thread to avoid a zombie without blocking this (possibly
            // async) drop.
            if let Some(mut child) = self.child.take() {
                let _ = child.kill();
                std::thread::spawn(move || {
                    let _ = child.wait();
                });
            }
        }
    }

    impl ConfinedCommand {
        /// Admission-check, confine, and spawn the child — like
        /// [`spawn`](ConfinedCommand::spawn), but the stdio pipes are returned as
        /// **tokio-native** handles wrapped in a kill-on-drop
        /// [`ConfinedTokioChild`], for an async host (an MCP-server stdio
        /// transport).
        ///
        /// The confinement is exactly `spawn`'s (this delegates to it): the
        /// `exec` admission-check, the fail-closed refusal when a restricted fs
        /// axis cannot be kernel-enforced, the OS sandbox, and the env scrub all
        /// happen there. This method only converts the piped std handles into
        /// tokio pipe ends.
        ///
        /// Must be called from within a tokio runtime — the pipe handles register
        /// with the reactor. Unix-only; gated on the `spawn-tokio` feature.
        pub fn spawn_tokio(mut self, cx: &ToolContext) -> ToolResult<ConfinedTokioChild> {
            // #257 (Part A — Leg 4): under a general remote-host `net` grant,
            // fence the child's egress. `egress_proxy_plan` is the ONE shared
            // decision (also the shell engine's): engage only when the loopback
            // kernel fence is actually emittable on this host — a proxy a rogue
            // child can walk around is not confinement, so on fence-less hosts
            // (e.g. Landlock, which cannot address-fence) the wiring stays
            // INERT and the spawn proceeds exactly as before (net advisory,
            // ADR 0015 posture).
            let mut proxy = None;
            let mut effective = cx.caveats().clone();
            if let Some((hosts, fenced)) = egress_proxy_plan(&effective, &self.sandbox_policy) {
                // Fail-closed: the grant calls for a fence + proxy; a proxy
                // that cannot bind must refuse the spawn, never run unfenced.
                let handle = crate::net_proxy::start_for_hosts(hosts).map_err(|e| {
                    ToolError::Exec(std::io::Error::other(format!(
                        "refusing to spawn {:?}: the egress proxy could not bind \
                         loopback ({e})",
                        self.program
                    )))
                })?;
                // Point the child at the proxy through the explicit env
                // grants (the only channel across the boundary).
                for (k, v) in handle.proxy_env() {
                    self = self.env(k, v);
                }
                proxy = Some(handle);
                effective = fenced;
            }

            let ConfinedChild {
                mut child,
                sandbox_kind,
            } = self.spawn_with_effective(cx, effective)?;

            // Convert each *piped* std handle into a tokio pipe end.
            // `pipe::{Sender,Receiver}::from_owned_fd` set O_NONBLOCK and register
            // the fd with the reactor. The `OwnedFd` conversion moves ownership
            // out of the std `Child`, so each fd is closed exactly once (the tokio
            // end owns it; `Child` no longer does after `take`). A handle that was
            // not piped stays `None`. `?` maps the io error via `ToolError::from`.
            let stdin = child
                .stdin
                .take()
                .map(|h| pipe::Sender::from_owned_fd(OwnedFd::from(h)))
                .transpose()?;
            let stdout = child
                .stdout
                .take()
                .map(|h| pipe::Receiver::from_owned_fd(OwnedFd::from(h)))
                .transpose()?;
            let stderr = child
                .stderr
                .take()
                .map(|h| pipe::Receiver::from_owned_fd(OwnedFd::from(h)))
                .transpose()?;

            Ok(ConfinedTokioChild {
                sandbox_kind,
                stdin,
                stdout,
                stderr,
                child: Some(child),
                proxy,
            })
        }
    }
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

/// Would confining this child be a *lie*? Decided against the **real** backend
/// `kind` (the probe the spawn actually confines through — not a stale gate
/// stamp; ADR 0012 D4) and the principal's `floor`.
///
/// Two parts:
/// 1. **The filesystem floor (always).** `fs_read` and `fs_write` *are*
///    kernel-enforceable (Landlock/Seatbelt/AppContainer); a restricted fs axis
///    the active backend cannot kernel-confine is a grant we cannot honor, so we
///    refuse regardless of strength. This keeps the ADR 0003 stub floor for
///    `fs_write` **and** extends it to `fs_read` — closing the spawn-boundary
///    fail-open ADR 0012 D4 found (a restricted `fs_read` was run unconfined
///    under `None` because the old check looked at `fs_write` only).
/// 2. **The strength floor (`exec`/`net`).** Those axes are not yet
///    kernel-enforceable on a subprocess (#31/#57), so they refuse only when the
///    principal's `floor` demands more than the real backend delivers
///    (`fence_strength(report) < floor`). With the default floor
///    ([`AxisEnforcement::Advisory`]) this is a no-op; a strong principal
///    (`floor = Kernel`) fails closed on a restricted `exec`/`net` it cannot
///    kernel-confine (ADR 0012 D3/D10).
#[must_use]
pub fn confinement_unenforceable(
    kind: SandboxKind,
    caveats: &Caveats,
    floor: AxisEnforcement,
) -> bool {
    let report = enforcement_report(caveats, kind);
    let below_kernel = |e: Option<AxisEnforcement>| e.is_some_and(|e| e != AxisEnforcement::Kernel);
    // (1) Filesystem axes: kernel-enforceable, so a restricted-but-not-kernel fs
    // axis is always unenforceable.
    if below_kernel(report.fs_write) || below_kernel(report.fs_read) {
        return true;
    }
    // (2) exec/net: refuse only when the strength floor is not met by reality.
    fence_strength(&report).is_some_and(|s| s < floor)
}

// Async-path proof for `spawn_tokio`: the child's stdio survives the std→tokio
// pipe conversion (a JSON-RPC line round-trips), and kill-on-drop actually kills
// the child. Real-subprocess tests, matching this module's convention (the
// landlock/seatbelt child proofs above also spawn real programs).
#[cfg(all(unix, feature = "spawn-tokio", test))]
mod tokio_spawn_tests {
    use super::*;
    use crate::{Gate, Tool};
    use std::time::Duration;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

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

    fn find_cat() -> Option<&'static str> {
        ["/usr/bin/cat", "/bin/cat"]
            .into_iter()
            .find(|p| Path::new(p).exists())
    }

    /// The MCP-transport use case: a newline-delimited JSON-RPC line written to
    /// the child's tokio stdin comes back on its tokio stdout (`cat` echoes),
    /// proving the std→tokio pipe conversion preserves a working duplex stream.
    #[tokio::test]
    async fn json_line_round_trips_over_tokio_pipes() {
        let Some(cat) = find_cat() else {
            eprintln!("skipping: no cat(1) found");
            return;
        };
        let cx = ctx(Caveats {
            exec: Scope::only(["cat".to_string()]),
            ..Caveats::top()
        });
        let mut child = ConfinedCommand::new(cat)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn_tokio(&cx)
            .expect("spawn_tokio cat");

        let mut stdin = child.take_stdin().expect("stdin piped");
        let stdout = child.take_stdout().expect("stdout piped");
        assert!(child.take_stdin().is_none(), "stdin taken once");

        let msg = r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#;
        stdin.write_all(msg.as_bytes()).await.expect("write");
        stdin.write_all(b"\n").await.expect("write nl");
        stdin.flush().await.expect("flush");

        let mut lines = BufReader::new(stdout).lines();
        let got = tokio::time::timeout(Duration::from_secs(5), lines.next_line())
            .await
            .expect("recv did not time out")
            .expect("recv ok");
        assert_eq!(got.as_deref(), Some(msg));
    }

    /// Kill-on-drop: dropping the [`ConfinedTokioChild`] SIGKILLs the child, which
    /// closes its stdout write end — so the retained reader reaches EOF. `stdin`
    /// is held so `cat` cannot exit on its own from a stdin EOF; the only thing
    /// that ends it is the drop.
    #[tokio::test]
    async fn dropping_the_guard_kills_the_child() {
        let Some(cat) = find_cat() else {
            eprintln!("skipping: no cat(1) found");
            return;
        };
        let cx = ctx(Caveats {
            exec: Scope::only(["cat".to_string()]),
            ..Caveats::top()
        });
        let mut child = ConfinedCommand::new(cat)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn_tokio(&cx)
            .expect("spawn_tokio cat");

        let stdout = child.take_stdout().expect("stdout piped");
        // Hold stdin so `cat` does not exit from a stdin EOF — isolate the kill.
        let _stdin = child.take_stdin().expect("stdin piped");
        drop(child);

        let mut lines = BufReader::new(stdout).lines();
        let eof = tokio::time::timeout(Duration::from_secs(5), lines.next_line())
            .await
            .expect("EOF did not time out")
            .expect("read ok");
        assert_eq!(
            eof, None,
            "kill-on-drop must terminate the child and close its stdout (EOF)"
        );
    }

    // ── #257: spawn_tokio's egress-proxy wiring ─────────────────────────────

    /// Where the loopback fence is NOT emittable (any host whose backend does
    /// not engage for the fenced caveats — e.g. Linux/Landlock, which cannot
    /// address-fence), a remote-host `net` grant spawns with NO proxy: inert,
    /// advisory-net, exactly the pre-#257 behavior (the ADR 0015 posture —
    /// never a proxy the child can walk around).
    #[tokio::test]
    async fn remote_net_grant_without_fence_backend_spawns_inert() {
        let caveats = Caveats {
            exec: Scope::only(["true".to_string()]),
            net: Scope::only(["api.example.com".to_string()]),
            ..Caveats::top()
        };
        // Only meaningful where the fence would NOT engage; on a Seatbelt host
        // this test's premise doesn't hold, so skip there.
        let plan_engages = crate::egress_proxy_plan(
            &caveats,
            &std::sync::Arc::new(crate::SandboxPolicy::default()),
        )
        .is_some();
        if plan_engages {
            eprintln!("skipping: this host CAN emit the loopback fence (engage path)");
            return;
        }
        let cx = ctx(caveats);
        let child = ConfinedCommand::new("true")
            .spawn_tokio(&cx)
            .expect("inert path spawns as before");
        assert!(!child.egress_proxied(), "no fence backend → no proxy");
        assert!(child.refused_hosts().is_empty());
        // Reap deterministically (kill-on-drop covers it regardless).
        drop(child);
    }

    /// The engage path — gated to hosts whose backend CAN emit the loopback
    /// fence (macOS Seatbelt): a remote-host grant spawns the child with the
    /// proxy live, `*_PROXY` granted into its (otherwise empty) env, and an
    /// off-allow-list fetch landing in `refused_hosts()`.
    #[cfg(all(target_os = "macos", feature = "macos-seatbelt"))]
    #[tokio::test]
    async fn remote_net_grant_with_fence_spawns_proxied_and_refuses_off_list() {
        use tokio::io::AsyncReadExt;
        if !crate::seatbelt_is_supported() {
            eprintln!("skipping: /usr/bin/sandbox-exec unavailable");
            return;
        }
        // `sh` prints its proxy env, then tries an off-allow-list CONNECT via
        // /usr/bin/curl (always present on macOS) through the proxy.
        let caveats = Caveats {
            exec: Scope::only(["/bin/sh".to_string()]),
            net: Scope::only(["api.example.com".to_string()]),
            ..Caveats::top()
        };
        let cx = ctx(caveats);
        let mut child = ConfinedCommand::new("/bin/sh")
            .arg("-c")
            .arg(
                "echo \"proxy=$HTTPS_PROXY\"; \
                 /usr/bin/curl -s -m 5 https://evil.example.net/ >/dev/null 2>&1; \
                 exit 0",
            )
            .stdout(Stdio::piped())
            .spawn_tokio(&cx)
            .expect("proxied spawn");
        assert!(child.egress_proxied(), "fence host → proxy must engage");

        let mut stdout = child.take_stdout().expect("stdout piped");
        let mut out = String::new();
        let _ = tokio::time::timeout(Duration::from_secs(10), stdout.read_to_string(&mut out))
            .await
            .expect("child did not finish");
        assert!(
            out.contains("proxy=http://127.0.0.1:"),
            "the child must see the granted *_PROXY env: {out:?}"
        );
        assert!(
            child
                .refused_hosts()
                .contains(&"evil.example.net".to_string()),
            "the off-allow-list host must be refused and recorded: {:?}",
            child.refused_hosts()
        );
    }
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
    fn unenforceable_predicate_fs_axes_always_strength_floor_for_exec() {
        use AxisEnforcement::{Advisory, Kernel};
        let fs_write = Caveats {
            fs_write: Scope::only(["/tmp/x".to_string()]),
            ..Caveats::top()
        };
        let fs_read = Caveats {
            fs_read: Scope::only(["/tmp/x".to_string()]),
            ..Caveats::top()
        };
        let exec = Caveats {
            exec: Scope::only(["echo".to_string()]),
            ..Caveats::top()
        };

        // (1) FS floor — always, regardless of strength: a restricted fs axis with
        // no OS sandbox is unenforceable, for BOTH fs_write and fs_read (the
        // latter is the ADR 0012 D4 spawn-boundary fail-open this closes).
        assert!(confinement_unenforceable(
            SandboxKind::None,
            &fs_write,
            Advisory
        ));
        assert!(confinement_unenforceable(
            SandboxKind::None,
            &fs_read,
            Advisory
        ));
        // The kernel can enforce the fs axes => fine.
        assert!(!confinement_unenforceable(
            SandboxKind::Landlock,
            &fs_write,
            Advisory
        ));
        assert!(!confinement_unenforceable(
            SandboxKind::Landlock,
            &fs_read,
            Advisory
        ));

        // (2) exec is not kernel-enforceable: the default (Advisory) floor permits
        // it; a strong (Kernel) floor fails closed (the opt-in un-stub posture).
        assert!(!confinement_unenforceable(
            SandboxKind::None,
            &exec,
            Advisory
        ));
        assert!(confinement_unenforceable(SandboxKind::None, &exec, Kernel));

        // Unrestricted grant => nothing to enforce, even under a Kernel floor.
        assert!(!confinement_unenforceable(
            SandboxKind::None,
            &Caveats::top(),
            Kernel
        ));
    }

    /// Honesty fix (#136): AppContainer does NOT kernel-confine the fs axis (ACL
    /// narrowing is deferred). A restricted fs scope must NOT engage AppContainer
    /// as the governing kind — effective_sandbox_kind returns None — so the spawn
    /// fails closed via confinement_unenforceable (fs→Interceptor < Kernel).
    /// This is the same fail-closed behavior as SandboxKind::None.
    /// fs restrictions now engage the AppContainer backend (ACL narrowing, #51).
    /// AppContainer DOES engage for fs-only caveats — `--fs-read`/`--fs-write` flags
    /// grant the AppContainer SID access to the workspace paths.
    #[test]
    fn fs_restricted_under_appcontainer_engages_the_launcher() {
        let fs = Caveats {
            fs_write: Scope::only(["/tmp/x".to_string()]),
            ..Caveats::top()
        };
        let governing = effective_sandbox_kind(SandboxKind::AppContainer, &fs);
        assert_eq!(
            governing,
            SandboxKind::AppContainer,
            "fs-only must engage AppContainer (ACL narrowing wired, #51)"
        );
        // fs_write is Kernel: DACL grants + AppContainer default deny-user-dirs (#51).
        let report = enforcement_report(&fs, governing);
        assert_eq!(report.fs_write, Some(AxisEnforcement::Kernel));
        // With AppContainer engaged and fs Kernel, confinement is enforceable.
        assert!(
            !confinement_unenforceable(governing, &fs, AxisEnforcement::Advisory),
            "fs-restricted AppContainer is enforceable (launcher wired)"
        );
    }

    /// exec_fully_denied engages the AppContainer backend: governing == AppContainer,
    /// and the enforcement report marks exec → Kernel (#123).
    #[test]
    fn exec_deny_all_under_appcontainer_is_kernel() {
        let exec_denied = Caveats {
            exec: Scope::only([] as [String; 0]),
            ..Caveats::top()
        };
        let governing = effective_sandbox_kind(SandboxKind::AppContainer, &exec_denied);
        assert_eq!(
            governing,
            SandboxKind::AppContainer,
            "exec deny-all must engage AppContainer"
        );
        // With an AppContainer backend and exec fully denied, the axis is kernel-enforced.
        assert!(
            !confinement_unenforceable(governing, &exec_denied, AxisEnforcement::Advisory),
            "exec deny-all under AppContainer is enforceable (kernel-level block)"
        );
        let report = enforcement_report(&exec_denied, governing);
        assert_eq!(
            report.exec,
            Some(AxisEnforcement::Kernel),
            "exec deny-all must be Kernel under AppContainer"
        );
    }

    /// Builds with **no** available OS sandbox: a restrictive `fs_write` must be
    /// refused rather than spawned unconfined. Gated off where a backend can
    /// actually enforce (Linux+Landlock, macOS+Seatbelt, Windows+AppContainer) —
    /// there the spawn is confined (or fails-closed on missing launcher), not
    /// silently unconfined, so this particular assertion does not apply.
    #[cfg(not(any(
        all(target_os = "linux", feature = "linux-landlock"),
        all(target_os = "macos", feature = "macos-seatbelt"),
        all(target_os = "windows", feature = "windows-appcontainer")
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

    /// #144 (I5-B): `ConfinedCommand::sandbox_policy` is honored — a child spawned
    /// with a widened `base_read_paths` can read a file outside `fs_read` scope
    /// that the default policy denies. Proves the builder threads the policy into
    /// `best_available_sandbox` (mechanism rides the builder, not `ToolContext`).
    #[test]
    fn confined_command_honors_sandbox_policy_base_read() {
        if !landlock_is_supported() {
            eprintln!("skipping: kernel lacks Landlock");
            return;
        }
        let cat = ["/usr/bin/cat", "/bin/cat"]
            .into_iter()
            .find(|p| std::path::Path::new(p).exists());
        let Some(cat) = cat else {
            eprintln!("skipping: no cat(1) found");
            return;
        };

        let allowed = unique_dir("cfg-allowed");
        let extra = unique_dir("cfg-extra");
        fs::write(extra.join("data.txt"), b"configured").unwrap();
        let cx = ctx(Caveats {
            exec: Scope::only(["cat".to_string()]),
            fs_read: Scope::only([allowed.to_string_lossy().into_owned()]),
            ..Caveats::top()
        });

        // Control: default policy → the child cannot read the out-of-scope file.
        let mut denied = ConfinedCommand::new(cat)
            .arg(extra.join("data.txt"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn(&cx)
            .expect("spawn");
        assert!(
            !denied.child.wait().expect("wait").success(),
            "default base read must deny the child reading the out-of-scope file"
        );

        // Widened policy: add `extra` to base_read_paths → the child reads it.
        let mut base = SandboxPolicy::default().base_read_paths;
        base.extra.push(extra.to_string_lossy().into_owned());
        let policy = Arc::new(SandboxPolicy {
            base_read_paths: base,
            ..SandboxPolicy::default()
        });
        let mut ok = ConfinedCommand::new(cat)
            .arg(extra.join("data.txt"))
            .sandbox_policy(policy)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn(&cx)
            .expect("spawn");
        assert!(
            ok.child.wait().expect("wait").success(),
            "a config-widened base_read_paths must let the child read the extra file"
        );

        let _ = fs::remove_dir_all(&allowed);
        let _ = fs::remove_dir_all(&extra);
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

    /// Honesty (I9): a fully permissive grant confines *nothing*, so the Seatbelt
    /// wrapper applies nothing and the child must be reported `None`, never the raw
    /// backend kind. This is the regression for the original overclaim where
    /// `sandbox_kind` was the backend kind regardless of whether anything was
    /// confined.
    #[test]
    fn top_grant_confines_nothing_reports_none() {
        if !seatbelt_is_supported() {
            eprintln!("skipping: /usr/bin/sandbox-exec unavailable");
            return;
        }
        let cx = ctx(Caveats::top());
        let child = ConfinedCommand::new("/usr/bin/true")
            .spawn(&cx)
            .expect("spawn");
        assert_eq!(
            child.sandbox_kind,
            SandboxKind::None,
            "nothing restricted => nothing confined => None, not the raw backend kind"
        );
    }

    /// A restricted `exec` axis engages Seatbelt **even when both fs axes are
    /// `All`**: `process-exec*` kernel-confines the exec axis (ADR 0014), so
    /// reporting `Seatbelt` is honest, not an overclaim — the inverse of the
    /// `top_grant…` guard above. Before ADR 0014 this same grant reported `None`
    /// (the exec axis was left ambient).
    #[test]
    fn restricted_exec_engages_seatbelt() {
        if !seatbelt_is_supported() {
            eprintln!("skipping: /usr/bin/sandbox-exec unavailable");
            return;
        }
        // exec restricted, both fs axes `All` — a grant a host might give an MCP
        // server: confine *what may run*, leave the filesystem ambient.
        let cx = ctx(Caveats {
            exec: Scope::only(["/usr/bin/true".to_string()]),
            ..Caveats::top()
        });
        let child = ConfinedCommand::new("/usr/bin/true")
            .spawn(&cx)
            .expect("spawn");
        assert_eq!(
            child.sandbox_kind,
            SandboxKind::Seatbelt,
            "a restricted exec axis is kernel-confined by process-exec* (ADR 0014)"
        );
    }
}
