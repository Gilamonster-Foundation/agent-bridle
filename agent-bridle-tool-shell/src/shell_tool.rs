//! [`ShellTool`] — the confined shell, **argv + safe-subset engine** (ADR 0005).
//!
//! Per ADR 0005, the object-capability *boundary* is L3 (kernel) and this engine
//! is the L2 *convenience*: `agent-bridle` is the exec funnel — it parses the
//! request itself (see [`crate::parse`]), checks the `exec`/`fs` leash, spawns
//! the program(s) directly, and **refuses the dynamic constructs by design**.
//! When an L3 backstop will actually confine the run — the Landlock `fs_write`
//! (and restricted `fs_read`) axes on a capable Linux build (`linux-landlock`),
//! or the macOS Seatbelt equivalent (`macos-seatbelt`), with a filesystem axis
//! restricted — the children spawn inside a kernel-enforced boundary (a Landlock
//! ruleset applied on a dedicated thread, or a `sandbox-exec` profile wrapping
//! each stage), and `sandbox_kind` reports [`SandboxKind::Landlock`] /
//! [`SandboxKind::Seatbelt`]; this blocks a *permitted* program's own
//! out-of-scope reads/writes, which L2 cannot see once it has spawned. Otherwise
//! the run is honestly *advisory* and `sandbox_kind` is [`SandboxKind::None`] —
//! never overclaiming (I9). The `exec`/`net` axes (#31/#57) and the Windows
//! backend (#51) are follow-ups; see ADR 0006/0009 for the per-OS backend design.
//!
//! The engine (agent-bridle#34 Track A + #45): a sequence of pipelines joined by
//! `&&`/`||`/`;`, each pipeline simple commands with quoted arguments,
//! redirections (`> out`, `>> out`, `< in`, `2> err`, `2>&1`), filename globbing
//! (`*`/`?`/`[…]`), and **allowlisted `$VAR` expansion**. Because `agent-bridle`
//! performs each redirect's open and each glob's directory listing itself, those
//! filesystem touches are leash-checked (`fs_write`/`fs_read`) *before any stage
//! spawns*; a `$VAR` is expanded only if its name is on a small secret-free
//! allowlist (the configured `var_allowlist`), checked before any spawn — a real enforcement
//! point, unlike a spawned program's own opens (L3's job). `2>&1` uses a shared
//! `std::io::pipe()` writer cloned into both stdout and stderr. Process spawning
//! is behind a [`Spawner`] seam (mocked in unit tests; real path in
//! `tests/real_spawn.rs`).

use std::collections::BTreeMap;
use std::io::{PipeReader, PipeWriter, Read};
#[cfg(windows)]
use std::io::{Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::{Child, Stdio};
use std::sync::Arc;
use std::time::Duration;

use agent_bridle_core::{
    best_available_sandbox, confinement_unenforceable, effective_sandbox_kind, enforcement_report,
    human_gate, is_unbridled, loopback_fenced_caveats, net_egress_proxy_hosts, Caveats, Denial,
    DenialKind, Disclosure, EnforcementReport, LimitsPolicy, SandboxKind, SandboxPolicy, Tool,
    ToolContext, ToolEnvelope, ToolError, ToolResult,
};
use async_trait::async_trait;

use crate::net_proxy;
use crate::parse::{
    classify, seg_literal, Arg, Command, Redirect, Refusal, Script, ScriptItem, Seg, Sep, StderrTo,
};

/// What a finished pipeline produced (the last stage's exit code; concatenated
/// output). The unit of the [`Spawner`] seam. The captured output is bounded by
/// the configured cap ([`LimitsPolicy::max_output_bytes`]) so a chatty command
/// cannot return unbounded output. Streaming caps are a follow-up; the timeout
/// bounds runaway producers in the meantime.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Captured {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    /// Whether stdout was clipped at the configured output cap (more was produced).
    pub stdout_truncated: bool,
    /// Whether stderr was clipped at the configured output cap (more was produced).
    pub stderr_truncated: bool,
    /// #196: structured `net` denials observed DURING the run — one per
    /// out-of-allow-list host the egress proxy refused. Unlike `exec`/`open`
    /// denials (decided at pre-spawn admission), a net refusal is only known
    /// after the child has run, so it rides back on the capture and is attached
    /// to the result envelope by the caller. Empty on the common path.
    pub net_denials: Vec<Denial>,
}

/// The pipeline-execution seam.
///
/// The real implementation ([`OsSpawner`]) spawns processes (and expands globs
/// against the real filesystem); tests inject a mock so the parse + leash +
/// sequencing logic is verified without real subprocesses (the workspace norm:
/// no real process/fs in unit tests). A `Spawner` only ever receives a pipeline
/// that already passed the `exec` **and** `fs` (redirect + glob-dir) leash —
/// admission happens in [`ShellTool::invoke`] *before* the spawner runs.
/// Per-invocation spawn *mechanism* config, threaded from `ShellTool`'s fields to
/// the spawner. It rides an explicit parameter, **never** `ToolContext` (which
/// carries only authority — authority≠mechanism, ADR 0017 D2). Bundles the tuning
/// knobs so the `Spawner` seam takes one config, not a growing list of scalars.
pub(crate) struct SpawnCfg {
    /// Captured stdout/stderr cap ([`LimitsPolicy::max_output_bytes`]).
    pub max_output: usize,
    /// Egress audit sink path ([`LimitsPolicy::audit_sink`]; `None` = off).
    pub audit_sink: Option<String>,
    /// Sandbox read/exec allow-lists + ABI floors ([`SandboxPolicy`]).
    pub sandbox: Arc<SandboxPolicy>,
    /// Process is **unbridled** (ADR 0018): drop the L3 OS sandbox and run the
    /// pipeline natively. The L2 grant checks in `invoke` still gate (advisory);
    /// only the kernel mechanism is skipped. Read once from the process marker.
    pub unbridled: bool,
}

pub(crate) trait Spawner: Send + Sync {
    /// Run one leash-approved pipeline to completion, capturing its output. The
    /// effective `caveats` are passed so the real spawner can apply the L3 OS
    /// sandbox (Landlock) before spawning; the mock ignores them. `env` is the
    /// host/operator-supplied environment (the env seam, newt #783): the real
    /// spawner sets these vars on each spawned child (additive over the inherited
    /// ambient env). `env` is structured host input, never model-authored command
    /// text, so it grants no new authority — the exec/fs leash is unaffected.
    /// `cfg` carries the mechanism tuning (output cap, audit sink, sandbox policy).
    fn run(
        &self,
        stages: &[Command],
        cwd: Option<&str>,
        caveats: &Caveats,
        env: &BTreeMap<String, String>,
        cfg: &SpawnCfg,
    ) -> ToolResult<Captured>;
}

/// The real spawner: a `std::process` pipeline wired with OS pipes + redirects,
/// expanding globs against the real filesystem, optionally inside an L3 sandbox.
struct OsSpawner;

impl Spawner for OsSpawner {
    fn run(
        &self,
        stages: &[Command],
        cwd: Option<&str>,
        caveats: &Caveats,
        env: &BTreeMap<String, String>,
        cfg: &SpawnCfg,
    ) -> ToolResult<Captured> {
        // Unbridled (ADR 0018): the operator explicitly dropped the L3 mechanism —
        // run natively, no OS sandbox and no egress proxy. The L2 grant checks in
        // `invoke` already gated this run (advisory); confinement is off by consent.
        if cfg.unbridled {
            return run_pipeline(stages, cwd, &[], env, cfg.max_output);
        }
        // A general remote-host `net` allow-list that cannot be named in SBPL is
        // enforced by the loopback egress proxy (#124, ADR 0016): fence the child
        // to loopback and route it through the proxy. Self-gating — `Some` only
        // where the fence is actually emittable (macOS + seatbelt).
        if let Some((allow_hosts, fenced)) = egress_proxy_plan(caveats, &cfg.sandbox) {
            return run_with_egress_proxy(stages, cwd, &fenced, env, allow_hosts, cfg);
        }
        // When an OS sandbox (Landlock/Seatbelt) will actually confine this run,
        // confine it on a dedicated thread before spawning (ADR 0005 L3 / ADR
        // 0006 D4). Otherwise run directly — no need to spend a thread.
        if intended_sandbox_kind(caveats, &cfg.sandbox) == SandboxKind::None {
            run_pipeline(stages, cwd, &[], env, cfg.max_output)
        } else {
            run_confined(stages, cwd, caveats, env, cfg)
        }
    }
}

/// The egress-proxy plan for `caveats`, or `None` to fall through to the ordinary
/// confinement paths (#124, ADR 0016). `Some((allow_hosts, fenced))` **iff** the
/// grant is a general remote-host `net` allow-list ([`net_egress_proxy_hosts`])
/// *and* the loopback fence it needs is actually emittable on this host — i.e.
/// [`loopback_fenced_caveats`] engages a real backend
/// ([`intended_sandbox_kind`] ≠ `None`; today only macOS Seatbelt). This one
/// helper feeds BOTH the spawn routing ([`OsSpawner::run`]) and the reported
/// `sandbox_kind` ([`ShellTool::invoke`]), so check and routing cannot disagree.
fn egress_proxy_plan(
    caveats: &Caveats,
    sandbox: &Arc<SandboxPolicy>,
) -> Option<(Vec<String>, Caveats)> {
    let allow_hosts = net_egress_proxy_hosts(caveats)?;
    let fenced = loopback_fenced_caveats(caveats);
    if intended_sandbox_kind(&fenced, sandbox) == SandboxKind::None {
        return None; // no loopback fence available → not enforceable; fall through
    }
    Some((allow_hosts, fenced))
}

/// Run the pipeline under the loopback egress proxy (#124, ADR 0016). Mirrors
/// [`run_confined`] but, before spawning: (1) starts a loopback forward proxy
/// bound to the `allow_hosts` — **fail-closed** if it cannot bind; (2) computes
/// the fence prefix from the loopback-`fenced` caveats — fail-closed if the
/// wrapper is missing; (3) injects `*_PROXY` into a clone of the env-seam map so
/// the child routes its HTTP/HTTPS out through the proxy. The [`ProxyHandle`] is
/// held until the confined child has been reaped, then dropped (tearing the
/// listener down) — so the proxy's lifetime brackets the child's.
fn run_with_egress_proxy(
    stages: &[Command],
    cwd: Option<&str>,
    fenced: &Caveats,
    env: &BTreeMap<String, String>,
    allow_hosts: Vec<String>,
    cfg: &SpawnCfg,
) -> ToolResult<Captured> {
    // (1) Fence prefix first (pure, cheap) — fail-closed if the wrapper is gone.
    let prefix = best_available_sandbox(&cfg.sandbox).command_prefix(fenced)?;
    // (2) Start the proxy — fail-closed if it cannot bind loopback (never spawn
    //     an unfenced child that would then egress freely). Audit is opt-in via the
    //     configured audit sink (observability only; off = zero overhead).
    let proxy = net_proxy::start(
        allow_hosts,
        Arc::new(net_proxy::StdResolver),
        net_audit_sink(cfg.audit_sink.as_deref()),
    )
    .map_err(ToolError::Exec)?;
    // (3) Point the child at the proxy via the env seam (a clone — never mutate
    //     the caller's map).
    let mut env = env.clone();
    for (k, v) in proxy.proxy_env() {
        env.insert(k, v);
    }

    let stages = stages.to_vec();
    let cwd = cwd.map(str::to_string);
    let fenced = fenced.clone();
    let max_output = cfg.max_output;
    let sandbox = cfg.sandbox.clone();
    let captured = std::thread::Builder::new()
        .name("agent-bridle-confined".to_string())
        .spawn(move || {
            best_available_sandbox(&sandbox).apply(&fenced)?;
            run_pipeline(&stages, cwd.as_deref(), &prefix, &env, max_output)
        })
        .map_err(ToolError::Exec)?
        .join()
        .map_err(|_| {
            ToolError::Exec(std::io::Error::other("confined execution thread panicked"))
        })?;
    // #196: the child is reaped, so every proxy connection is complete — read the
    // hosts the proxy refused (out of the allow-list) BEFORE tearing it down, and
    // surface each as a structured `net` denial on the capture.
    let refused = proxy.refused_hosts();
    drop(proxy); // hold the proxy until the child is reaped, then tear it down
    let mut captured = captured?;
    captured.net_denials = refused
        .into_iter()
        .map(|host| Denial {
            kind: DenialKind::Net,
            reason: format!("net does not permit '{host}'"),
            target: host,
        })
        .collect();
    Ok(captured)
}

/// Build the egress audit sink from the configured audit path (#124, ADR 0016;
/// `LimitsPolicy::audit_sink`, which the config loader maps from the legacy
/// `BRIDLE_NET_AUDIT` setting — I6, #145). `None`/empty → **no audit** (the
/// default; zero overhead). A path → append each proxied connection as one JSON
/// line (host, port, decision, bytes, duration) for `bridle-netmon` to render
/// live. Audit is **observability only** — it never changes an enforcement
/// decision — so a path that cannot be opened falls back to the null sink rather
/// than failing the run.
fn net_audit_sink(configured: Option<&str>) -> Arc<dyn net_proxy::AuditSink> {
    match configured {
        Some(path) if !path.is_empty() => std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map(|f| Arc::new(net_proxy::JsonlSink::new(f)) as Arc<dyn net_proxy::AuditSink>)
            .unwrap_or_else(|_| Arc::new(net_proxy::NullSink)),
        _ => Arc::new(net_proxy::NullSink),
    }
}

/// The L3 `SandboxKind` that will actually be enforced for these caveats in this
/// build, on this host — the value reported in the result envelope (I9 / ADR
/// 0006 D3). [`effective_sandbox_kind`] is the shared honesty rule: the strongest
/// available backend's kind when a filesystem axis is restricted (so it confines
/// something), else `None` — the fs-only ruleset governs nothing, so never
/// overclaim. The same rule backs the subprocess primitive in core.
fn intended_sandbox_kind(caveats: &Caveats, sandbox: &Arc<SandboxPolicy>) -> SandboxKind {
    effective_sandbox_kind(best_available_sandbox(sandbox).kind(), caveats)
}

/// Run the pipeline on a dedicated thread that first applies the OS sandbox.
///
/// Two confinement mechanisms, honored uniformly (ADR 0006): a thread-confining
/// backend (Landlock) restricts this very thread in `apply` — per-thread,
/// irreversible, inherited across `fork`/`execve`, so it must run on a throwaway
/// thread (never the shared blocking pool) immediately before spawning the
/// children. A wrapper backend (macOS Seatbelt) returns a `sandbox-exec` argv
/// prefix from `command_prefix`, prepended to every stage so the child is
/// spawned already confined. Both are fail-closed (ADR 0006 D4): if confinement
/// cannot be established the run errors rather than proceeding unconfined.
fn run_confined(
    stages: &[Command],
    cwd: Option<&str>,
    caveats: &Caveats,
    env: &BTreeMap<String, String>,
    cfg: &SpawnCfg,
) -> ToolResult<Captured> {
    // Computed before the spawn so a fail-closed wrapper error aborts the run.
    let prefix = best_available_sandbox(&cfg.sandbox).command_prefix(caveats)?;
    let stages = stages.to_vec();
    let cwd = cwd.map(str::to_string);
    let caveats = caveats.clone();
    let env = env.clone();
    let max_output = cfg.max_output;
    let sandbox = cfg.sandbox.clone();
    std::thread::Builder::new()
        .name("agent-bridle-confined".to_string())
        .spawn(move || {
            best_available_sandbox(&sandbox).apply(&caveats)?;
            run_pipeline(&stages, cwd.as_deref(), &prefix, &env, max_output)
        })
        .map_err(ToolError::Exec)?
        .join()
        .map_err(|_| ToolError::Exec(std::io::Error::other("confined execution thread panicked")))?
}

/// The confined shell tool.
///
/// Registers under `"shell"`. Accepts either argv form (`program` + `args`) or a
/// free-form `cmd` string parsed by the safe-subset engine. Leash refusals
/// (out-of-scope `exec`/`fs`, a refused construct) are returned as a **structured
/// denied envelope** (`denied: true`), not a hard error.
#[derive(Clone)]
pub struct ShellTool {
    spawner: Arc<dyn Spawner>,
    env: Arc<dyn EnvProvider>,
    lister: Arc<dyn DirLister>,
    limits: LimitsPolicy,
    /// Sandbox mechanism policy (read/exec allow-lists, ABI floors) the L3 backend
    /// enforces (I5-B, #144). Rides the tool, not the `ToolContext`.
    sandbox: Arc<SandboxPolicy>,
}

impl std::fmt::Debug for ShellTool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ShellTool")
    }
}

impl ShellTool {
    /// Construct the tool with the real OS spawner, environment, and dir lister,
    /// and the default [`LimitsPolicy`].
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(LimitsPolicy::default())
    }

    /// Construct with the real seams and a caller-supplied [`LimitsPolicy`] — the
    /// configurability seam (agent-bridle#143): tune timeouts / output / glob caps.
    #[must_use]
    pub fn with_config(limits: LimitsPolicy) -> Self {
        Self {
            spawner: Arc::new(OsSpawner),
            env: Arc::new(RealEnv),
            lister: Arc::new(RealDirLister),
            limits,
            sandbox: Arc::new(SandboxPolicy::default()),
        }
    }

    /// Set the sandbox mechanism policy (read/exec allow-lists, ABI floors) the L3
    /// backend enforces (I5-B, #144). The default is today's built-in allow-lists.
    #[must_use]
    pub fn with_sandbox_policy(mut self, sandbox: SandboxPolicy) -> Self {
        self.sandbox = Arc::new(sandbox);
        self
    }

    /// Construct with an injected spawner; real environment + dir lister (tests).
    #[cfg(test)]
    fn with_spawner(spawner: Arc<dyn Spawner>) -> Self {
        Self {
            spawner,
            env: Arc::new(RealEnv),
            lister: Arc::new(RealDirLister),
            limits: LimitsPolicy::default(),
            sandbox: Arc::new(SandboxPolicy::default()),
        }
    }

    /// Construct with an injected spawner **and** a fake environment (tests only),
    /// so the `$VAR` allowlist + expansion + the resolved-path leash are
    /// exercised without touching the real process environment.
    #[cfg(test)]
    fn with_spawner_and_env(spawner: Arc<dyn Spawner>, env: Arc<dyn EnvProvider>) -> Self {
        Self {
            spawner,
            env,
            lister: Arc::new(RealDirLister),
            limits: LimitsPolicy::default(),
            sandbox: Arc::new(SandboxPolicy::default()),
        }
    }

    /// Construct with all three seams injected (tests only): a fake spawner, env,
    /// and directory lister, so glob expansion + the per-directory `fs_read`
    /// leash are exercised without a real filesystem (#47).
    #[cfg(test)]
    fn with_seams(
        spawner: Arc<dyn Spawner>,
        env: Arc<dyn EnvProvider>,
        lister: Arc<dyn DirLister>,
    ) -> Self {
        Self {
            spawner,
            env,
            lister,
            limits: LimitsPolicy::default(),
            sandbox: Arc::new(SandboxPolicy::default()),
        }
    }
}

impl Default for ShellTool {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Tool for ShellTool {
    fn name(&self) -> &str {
        "shell"
    }

    fn schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "program": {
                    "type": "string",
                    "description": "Argv form: the command to run (argv[0]). \
                        Gated by the `exec` caveat. Mutually exclusive with `cmd`."
                },
                "args": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "Argv form: arguments passed to `program` (argv[1..]). Taken \
                        literally — no globbing/quoting interpretation."
                },
                "cmd": {
                    "type": "string",
                    "description": "Free-form command line run by the confined safe-subset engine: \
                        pipelines (a | b) joined by &&/||/;, with quoted arguments, redirections \
                        (> out, >> out, < in, 2> err, 2>&1; file targets gated by fs_write/fs_read), \
                        filename globbing (*, ?, [..]; gated by fs_read on the listed directory), \
                        and $VAR/${VAR} expansion (incl. mixed words like $HOME/config and \
                        inside double quotes) for an allowlisted, secret-free set (HOME, PWD, \
                        USER, TMPDIR, ...). Dynamic constructs ($(...), backticks, subshells) are \
                        refused by design; a $VAR outside the allowlist, a $VAR in a redirect \
                        target or combined with a glob, and fd redirections other than \
                        1>/2>/0</2>&1, are refused. Mutually exclusive with `program`."
                },
                "cwd": {
                    "type": "string",
                    "description": "Working directory for the command (must be within fs_read scope)."
                },
                "env": {
                    "type": "object",
                    "additionalProperties": { "type": "string" },
                    "description": "Host/operator-supplied environment variables (string \
                        values) set on the spawned child process(es), additive over the \
                        inherited ambient environment. Pass real env vars here instead of \
                        prepending `export VAR=…;` statements to `cmd` — an `export` builtin \
                        is not a program and the confined engine refuses it. These values are \
                        host input, not model-authored command text, and do NOT widen the \
                        leash: the exec/fs check is on the real program, never on env."
                },
                "timeout_secs": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": self.limits.max_timeout_secs,
                    "description": "Wall-clock timeout bound (not a coordination primitive)."
                }
            },
            "additionalProperties": false
        })
    }

    async fn invoke(
        &self,
        args: serde_json::Value,
        cx: &ToolContext,
    ) -> ToolResult<serde_json::Value> {
        let parsed = ShellArgs::parse(&args, &self.limits)?;
        // Unbridled (ADR 0018): the operator dropped the L3 mechanism. Report
        // `None` (no OS sandbox) — the per-axis report then honestly shows each
        // restricted axis at `advisory` (the L2 interceptor, which still gates the
        // configured grant below), never `kernel`. Authority is unchanged; only the
        // mechanism is off. Every envelope discloses `unbridled` (D5).
        let unbridled = is_unbridled();
        // Honest reporting (ADR 0005 D1 / I9 / ADR 0006 D3): report the L3 kind
        // that will actually be enforced for these caveats on this kernel —
        // Landlock when `fs_write` is restricted on a capable Linux build, else
        // None (advisory). `OsSpawner` applies exactly this, fail-closed.
        //
        // On the egress-proxy path (#124, ADR 0016) the run is governed by the
        // loopback-`fenced` caveats — a real Seatbelt kernel boundary — so the
        // coarse kind is reported from those, derived from the SAME
        // `egress_proxy_plan` helper `OsSpawner::run` routes on (they cannot
        // disagree). The per-axis `net` stays Advisory below (the report is
        // computed from the ORIGINAL grant, whose remote host SBPL cannot confine)
        // — the proxy over-delivers above that floor, it does not raise the claim.
        let sandbox_kind = if unbridled {
            SandboxKind::None
        } else {
            match egress_proxy_plan(cx.caveats(), &self.sandbox) {
                Some((_, fenced)) => intended_sandbox_kind(&fenced, &self.sandbox),
                None => intended_sandbox_kind(cx.caveats(), &self.sandbox),
            }
        };
        // Axis-granular honesty (ADR 0004 D1 / #30): every envelope this run
        // returns carries the per-axis report alongside the coarse sandbox_kind.
        let enforcement = enforcement_report(cx.caveats(), sandbox_kind);

        // Resolve to a script (sequence of pipelines), or surface a refusal.
        let mut script = match parsed.script() {
            Ok(s) => s,
            Err(refusal) => return Ok(refused_envelope(sandbox_kind, enforcement, &refusal)),
        };

        // Lower `$VAR` (#46) through the env seam so the RESOLVED value is what
        // the fs leash checks below and the spawner opens — never a literal
        // `$VAR`. Glob+variable words (`$DIR/*.rs`) lower to a resolved glob (with
        // the re-injection guard); redirect targets (`> $TMPDIR/out`) to a literal
        // path. A non-allowlisted (or basename-injected) variable denies pre-spawn.
        for item in &mut script {
            for stage in &mut item.pipeline {
                // Expand globs (and glob+var words) to literal matches, leash-
                // checking EVERY directory the walk lists (#47) — multi-segment
                // (`*/foo.rs`) and recursive (`**/*.rs`), all before any spawn.
                // argv[0] is left intact; the program-position check below refuses
                // a glob/var program (we never exec a pattern).
                let mut new_argv: Vec<Arg> = Vec::with_capacity(stage.argv.len());
                for (i, arg) in stage.argv.drain(..).enumerate() {
                    let pattern: Option<String> = if i == 0 {
                        None
                    } else {
                        match &arg {
                            Arg::Glob(p) => Some(p.clone()),
                            Arg::VarGlob(segs) => {
                                match expand_varglob(segs, &*self.env, &self.limits.var_allowlist) {
                                    Ok(p) => Some(p),
                                    Err((target, e)) => {
                                        return Ok(deny(
                                            sandbox_kind,
                                            enforcement,
                                            DenialKind::Exec,
                                            &target,
                                            &e,
                                        ))
                                    }
                                }
                            }
                            _ => None,
                        }
                    };
                    match pattern {
                        Some(p) => {
                            let mut leash = |dir: &Path| cx.check_path_read(dir);
                            match expand_glob_walk(
                                &p,
                                parsed.cwd.as_deref(),
                                &*self.lister,
                                &mut leash,
                                self.limits.max_glob_depth,
                                self.limits.max_glob_matches,
                            ) {
                                Ok(ms) => new_argv.extend(ms.into_iter().map(Arg::Lit)),
                                Err(e) => {
                                    return Ok(deny(
                                        sandbox_kind,
                                        enforcement,
                                        DenialKind::Open,
                                        &p,
                                        &e,
                                    ))
                                }
                            }
                        }
                        None => new_argv.push(arg),
                    }
                }
                stage.argv = new_argv;
                for redirect in &mut stage.redirects {
                    let segs = match redirect {
                        Redirect::Stdout { path, .. }
                        | Redirect::Stderr { path, .. }
                        | Redirect::Stdin { path } => path,
                        Redirect::StderrToStdout => continue,
                    };
                    match expand_redirect_target(segs, &*self.env, &self.limits.var_allowlist) {
                        Ok(resolved) => *segs = vec![Seg::Lit(resolved)],
                        Err((target, e)) => {
                            return Ok(deny(
                                sandbox_kind,
                                enforcement,
                                DenialKind::Open,
                                &target,
                                &e,
                            ))
                        }
                    }
                }
            }
        }

        // Atomic admission (ADR 0001): across the WHOLE script, every program
        // (`exec`), every redirect target (`fs_write`/`fs_read`), and every glob's
        // listed directory (`fs_read`) — all filesystem touches bridle performs —
        // must pass *before any stage spawns*. One out-of-scope element denies the
        // whole script with no partial side effects.
        for item in &script {
            for stage in &item.pipeline {
                match stage.argv.first() {
                    Some(Arg::Lit(program)) => {
                        if let Err(e) = cx.check_exec(program) {
                            return Ok(deny(
                                sandbox_kind,
                                enforcement,
                                DenialKind::Exec,
                                program,
                                &e,
                            ));
                        }
                    }
                    Some(Arg::Glob(pattern)) => {
                        return Ok(deny(
                            sandbox_kind,
                            enforcement,
                            DenialKind::Exec,
                            pattern,
                            &ToolError::denied("a glob pattern is not allowed as a program name"),
                        ));
                    }
                    Some(Arg::Var(_segs)) => {
                        return Ok(deny(
                            sandbox_kind,
                            enforcement,
                            DenialKind::Exec,
                            "$VAR",
                            &ToolError::denied("a variable is not allowed as a program name"),
                        ));
                    }
                    // A glob+var word lowers to `Arg::Glob` above; this arm is for
                    // exhaustiveness and mirrors the glob-program refusal.
                    Some(Arg::VarGlob(_)) => {
                        return Ok(deny(
                            sandbox_kind,
                            enforcement,
                            DenialKind::Exec,
                            "$VAR/glob",
                            &ToolError::denied("a glob pattern is not allowed as a program name"),
                        ));
                    }
                    None => {} // the parser guarantees a non-empty stage
                }
                for arg in &stage.argv {
                    match arg {
                        // Every variable referenced must be on the env allowlist
                        // (no secret leak), checked by name before any spawn.
                        Arg::Var(segs) => {
                            for seg in segs {
                                if let Seg::Var(name) = seg {
                                    if !is_allowed_var(name, &self.limits.var_allowlist) {
                                        return Ok(deny(
                                            sandbox_kind,
                                            enforcement,
                                            DenialKind::Exec,
                                            &format!("${name}"),
                                            &ToolError::denied(format!(
                                                "variable ${name} is not in the confined shell's allowlist"
                                            )),
                                        ));
                                    }
                                }
                            }
                        }
                        // Globs / glob+var words were expanded to literals (with
                        // the per-directory fs_read leash) in the pass above.
                        Arg::Glob(_) => unreachable!("glob expanded at admission"),
                        Arg::VarGlob(_) => unreachable!("VarGlob expanded at admission"),
                        Arg::Lit(_) => {}
                    }
                }
                for redirect in &stage.redirects {
                    // Redirect targets were lowered above, so each path is a
                    // single resolved literal — leash-check that resolved path.
                    let (path, checked) = match redirect {
                        Redirect::Stdout { path, .. } | Redirect::Stderr { path, .. } => {
                            let p = seg_literal(path).expect("redirect target lowered");
                            (p, cx.check_path_write(Path::new(p)))
                        }
                        Redirect::Stdin { path } => {
                            let p = seg_literal(path).expect("redirect target lowered");
                            (p, cx.check_path_read(Path::new(p)))
                        }
                        // `2>&1` opens no file — nothing to leash-check.
                        Redirect::StderrToStdout => continue,
                    };
                    if let Err(e) = checked {
                        return Ok(deny(sandbox_kind, enforcement, DenialKind::Open, path, &e));
                    }
                }
            }
        }
        // Leash: a provided cwd must be within fs_read scope.
        if let Some(cwd) = &parsed.cwd {
            if let Err(e) = cx.check_path_read(Path::new(cwd)) {
                return Ok(deny(sandbox_kind, enforcement, DenialKind::Open, cwd, &e));
            }
        }

        // Fail closed (ADR 0012 D4) — AFTER L2 admission (so a specific
        // out-of-scope glob/redirect/exec denial is reported first) but before any
        // spawn: refuse when a restricted axis cannot be enforced on this host at
        // the principal's strength floor. Decided against `sandbox_kind` — the kind
        // that ACTUALLY governs the spawn (`effective_sandbox_kind`, what
        // `OsSpawner` routes through), NOT the raw probe: a backend the run path
        // does not route through collapses to `None` here, so an fs-restricted
        // run on it fails closed instead of executing unconfined via
        // `run_pipeline` (the adversarial-review fix — the check and the routing
        // must agree). The filesystem axes always
        // fail closed when restricted-but-unenforceable (closing the run-unconfined
        // gap the shell shared with ConfinedCommand); exec/net fail closed only for
        // a strong principal (the default floor is permissive).
        // Unbridled skips this fail-closed guard by consent: dropping the L3
        // mechanism is *exactly* what the operator acknowledged (ADR 0018 D1). The
        // L2 grant checks above still ran (advisory), and every axis reports
        // advisory + `disclosure.unbridled` — honest, not silent.
        if !unbridled && confinement_unenforceable(sandbox_kind, cx.caveats(), cx.strength_floor())
        {
            return Ok(deny(
                sandbox_kind,
                enforcement,
                DenialKind::Exec,
                "confinement",
                &ToolError::denied(format!(
                    "a restricted filesystem/exec/net axis cannot be enforced on this host \
                     at the required strength floor ({:?}); refusing to run unconfined",
                    cx.strength_floor()
                )),
            ));
        }

        // Run on a blocking thread, bounded by the timeout. On timeout the
        // blocking task is detached and a timeout envelope is returned.
        let spawner = Arc::clone(&self.spawner);
        let cwd = parsed.cwd.clone();
        let timeout = parsed.timeout;
        let cfg = SpawnCfg {
            max_output: self.limits.max_output_bytes,
            audit_sink: self.limits.audit_sink.clone(),
            sandbox: Arc::clone(&self.sandbox),
            unbridled,
        };
        // Disclosed on every envelope this run returns (ADR 0018 D5/D11 / I11).
        let disclosure = Disclosure {
            unbridled,
            human_gate: human_gate(),
            ..Disclosure::default()
        };
        // Host/operator-supplied environment (the env seam, newt #783): carried
        // through to the child processes. Empty when the dispatch omits `env`.
        let env = parsed.env;
        let caveats = cx.caveats().clone();
        let run = tokio::task::spawn_blocking(move || {
            run_script(&*spawner, &script, cwd.as_deref(), &caveats, &env, &cfg)
        });
        match tokio::time::timeout(timeout, run).await {
            Ok(joined) => {
                let captured = joined
                    .map_err(|e| ToolError::Other(anyhow::anyhow!("shell task panicked: {e}")))??;
                // #196: a run that reached an out-of-allow-list host was refused
                // by the egress proxy — surface those as structured `net` denials
                // (sets `denied: true`; empty is a no-op on the common path).
                Ok(ToolEnvelope::new(sandbox_kind)
                    .with_enforcement(enforcement)
                    .with_disclosure(disclosure)
                    .with_exit_code(captured.exit_code)
                    .with_truncation(captured.stdout_truncated, captured.stderr_truncated)
                    .with_stdout(captured.stdout)
                    .with_stderr(captured.stderr)
                    .with_denials(captured.net_denials)
                    .with_timed_out(false)
                    .into_json())
            }
            Err(_elapsed) => Ok(ToolEnvelope::new(sandbox_kind)
                .with_enforcement(enforcement)
                .with_disclosure(disclosure)
                .with_stderr(format!("command timed out after {}s", timeout.as_secs()))
                .with_timed_out(true)
                .into_json()),
        }
    }
}

/// Execute a [`Script`] with `&&`/`||`/`;` short-circuit semantics, concatenating
/// the output of the pipelines that actually run. The script's exit code is that
/// of the last pipeline that ran (bash AND-OR-list semantics).
fn run_script(
    spawner: &dyn Spawner,
    script: &[ScriptItem],
    cwd: Option<&str>,
    caveats: &Caveats,
    env: &BTreeMap<String, String>,
    cfg: &SpawnCfg,
) -> ToolResult<Captured> {
    let mut stdout = String::new();
    let mut stderr = String::new();
    let mut status: i32 = 0;
    let mut stdout_truncated = false;
    let mut stderr_truncated = false;
    // #196: net denials accumulate across every pipeline stage that runs.
    let mut net_denials: Vec<Denial> = Vec::new();

    for item in script {
        let run_it = match item.sep {
            Sep::Seq => true,
            Sep::And => status == 0,
            Sep::Or => status != 0,
        };
        if run_it {
            let captured = spawner.run(&item.pipeline, cwd, caveats, env, cfg)?;
            stdout.push_str(&captured.stdout);
            stderr.push_str(&captured.stderr);
            stdout_truncated |= captured.stdout_truncated;
            stderr_truncated |= captured.stderr_truncated;
            net_denials.extend(captured.net_denials);
            status = captured.exit_code;
        }
    }

    // The concatenation across pipelines may itself exceed the cap; flag that.
    let stdout_truncated = stdout_truncated || stdout.len() > cfg.max_output;
    let stderr_truncated = stderr_truncated || stderr.len() > cfg.max_output;

    Ok(Captured {
        exit_code: status,
        stdout: cap_string(stdout, cfg.max_output),
        stderr: cap_string(stderr, cfg.max_output),
        net_denials,
        stdout_truncated,
        stderr_truncated,
    })
}

/// Build a structured `denied` envelope for a leash refusal.
fn deny(
    sandbox_kind: SandboxKind,
    enforcement: EnforcementReport,
    kind: DenialKind,
    target: &str,
    err: &ToolError,
) -> serde_json::Value {
    ToolEnvelope::new(sandbox_kind)
        .with_enforcement(enforcement)
        .with_disclosure(unbridle_disclosure())
        .with_denials(vec![Denial {
            kind,
            target: target.to_string(),
            reason: err.to_string(),
        }])
        .into_json()
}

/// The disclosure block stamped on **every** envelope (ADR 0018 D5): reads the
/// process-level unbridle marker so a denied/refused result is as honest about
/// the posture as a successful one.
fn unbridle_disclosure() -> Disclosure {
    Disclosure {
        unbridled: is_unbridled(),
        human_gate: human_gate(),
        ..Disclosure::default()
    }
}

/// Build a structured `denied` envelope for a parser [`Refusal`].
fn refused_envelope(
    sandbox_kind: SandboxKind,
    enforcement: EnforcementReport,
    refusal: &Refusal,
) -> serde_json::Value {
    ToolEnvelope::new(sandbox_kind)
        .with_enforcement(enforcement)
        .with_disclosure(unbridle_disclosure())
        .with_denials(vec![Denial {
            kind: DenialKind::Exec,
            target: refusal.construct(),
            reason: refusal.to_string(),
        }])
        .into_json()
}

/// Parsed, validated `shell` arguments.
struct ShellArgs {
    program: Option<String>,
    args: Vec<String>,
    cmd: Option<String>,
    cwd: Option<String>,
    /// Host/operator-supplied environment for the spawned child(ren) (the env
    /// seam, newt #783). Empty when the dispatch omits `env` (back-compat). Only
    /// string values are taken; non-string entries are ignored.
    env: BTreeMap<String, String>,
    timeout: Duration,
}

impl ShellArgs {
    fn parse(v: &serde_json::Value, limits: &LimitsPolicy) -> ToolResult<Self> {
        let obj = v
            .as_object()
            .ok_or_else(|| ToolError::denied("shell args must be a JSON object"))?;

        let program = obj
            .get("program")
            .and_then(|x| x.as_str())
            .map(String::from);
        let cmd = obj.get("cmd").and_then(|x| x.as_str()).map(String::from);
        let args = obj
            .get("args")
            .and_then(|x| x.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(String::from))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let cwd = obj.get("cwd").and_then(|x| x.as_str()).map(String::from);
        // The env seam (newt #783): a `"env": { "KEY": "VALUE", … }` object whose
        // string values are set on the spawned child(ren). Absent → empty map
        // (back-compat). Non-string values are dropped (the schema is string-only).
        let env = obj
            .get("env")
            .and_then(|x| x.as_object())
            .map(|m| {
                m.iter()
                    .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                    .collect::<BTreeMap<String, String>>()
            })
            .unwrap_or_default();
        let timeout_secs = obj
            .get("timeout_secs")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(limits.default_timeout_secs)
            .clamp(1, limits.max_timeout_secs);

        match (&program, &cmd) {
            (Some(_), Some(_)) => {
                return Err(ToolError::denied(
                    "provide exactly one of `program` or `cmd`, not both",
                ))
            }
            (None, None) => return Err(ToolError::denied("provide one of `program` or `cmd`")),
            _ => {}
        }
        if program.is_none() && !args.is_empty() {
            return Err(ToolError::denied(
                "`args` may only be used together with `program`",
            ));
        }

        Ok(Self {
            program,
            args,
            cmd,
            cwd,
            env,
            timeout: Duration::from_secs(timeout_secs),
        })
    }

    /// Resolve to a script. Argv form is a one-pipeline, one-stage script whose
    /// args are all **literal** (no globbing/parsing); free-form is parsed by the
    /// safe-subset engine.
    fn script(&self) -> Result<Script, Refusal> {
        if let Some(program) = &self.program {
            let mut argv = Vec::with_capacity(1 + self.args.len());
            argv.push(Arg::Lit(program.clone()));
            argv.extend(self.args.iter().cloned().map(Arg::Lit));
            Ok(vec![ScriptItem {
                sep: Sep::Seq,
                pipeline: vec![Command {
                    argv,
                    redirects: Vec::new(),
                }],
            }])
        } else {
            classify(self.cmd.as_deref().unwrap_or(""))
        }
    }
}

// ── variable expansion (allowlist) ──────────────────────────────────────────

/// The environment variables the confined engine will expand (ADR 0005 D3,
/// allowlist-only). Deliberately small and secret-free: no `PATH`, no tokens.
/// A `$VAR` outside this set is denied — so a confined run can never splice a
/// secret (e.g. `$AWS_SECRET_KEY`) into an argument, even when `exec` is tight.
/// Whether `name` may be expanded from the environment, against the configured
/// allowlist ([`LimitsPolicy::var_allowlist`]).
fn is_allowed_var(name: &str, allowlist: &[String]) -> bool {
    allowlist.iter().any(|v| v == name)
}

/// The environment seam (#46): the engine reads `$VAR` values through this, so the
/// allowlist + expansion + the resolved-path `fs` leash stay unit-testable
/// without touching the real process environment (a fake map in tests). Only
/// allowlisted names (the configured `var_allowlist`) are ever read.
pub(crate) trait EnvProvider: Send + Sync {
    /// The value of `name`, or `None` if unset.
    fn get(&self, name: &str) -> Option<String>;
}

/// The real process environment (`std::env::var`).
pub(crate) struct RealEnv;
impl EnvProvider for RealEnv {
    fn get(&self, name: &str) -> Option<String> {
        std::env::var(name).ok()
    }
}

/// Expand a redirect target's segments to a literal path, reading allowlisted
/// `$VAR` through the env seam. Single-literal substitution: the value is **not**
/// re-split or re-globbed (no re-injection). `Err((target, reason))` names a
/// non-allowlisted variable for a structured denial.
fn expand_redirect_target(
    segs: &[Seg],
    env: &dyn EnvProvider,
    allowlist: &[String],
) -> Result<String, (String, ToolError)> {
    let mut out = String::new();
    for seg in segs {
        match seg {
            Seg::Lit(s) => out.push_str(s),
            Seg::Var(name) => {
                if !is_allowed_var(name, allowlist) {
                    return Err((
                        format!("${name}"),
                        ToolError::denied(format!(
                            "variable ${name} is not in the confined shell's allowlist"
                        )),
                    ));
                }
                out.push_str(&env.get(name).unwrap_or_default());
            }
        }
    }
    Ok(out)
}

/// Expand a glob+variable word (e.g. `$DIR/*.rs`) into a resolved glob pattern,
/// reading allowlisted `$VAR` through the env seam.
///
/// **Re-injection guard:** a variable may only contribute to the directory
/// *prefix* (everything up to the last `/`), never to the glob *basename* — so a
/// var value can never inject a glob metachar that widens the match. The existing
/// single-segment globber then treats the (var-derived) directory as a literal
/// path and globs only the source-literal basename. A variable in the basename is
/// refused. `Err((target, reason))` names a non-allowlisted var or the refusal.
fn expand_varglob(
    segs: &[Seg],
    env: &dyn EnvProvider,
    allowlist: &[String],
) -> Result<String, (String, ToolError)> {
    let mut out = String::new();
    let mut last_var_byte: Option<usize> = None; // byte index of the last var-origin char
    let mut last_slash_byte: Option<usize> = None; // byte index of the last '/'
    for seg in segs {
        match seg {
            Seg::Lit(s) => {
                for ch in s.chars() {
                    if ch == '/' {
                        last_slash_byte = Some(out.len());
                    }
                    out.push(ch);
                }
            }
            Seg::Var(name) => {
                if !is_allowed_var(name, allowlist) {
                    return Err((
                        format!("${name}"),
                        ToolError::denied(format!(
                            "variable ${name} is not in the confined shell's allowlist"
                        )),
                    ));
                }
                for ch in env.get(name).unwrap_or_default().chars() {
                    if ch == '/' {
                        last_slash_byte = Some(out.len());
                    }
                    last_var_byte = Some(out.len());
                    out.push(ch);
                }
            }
        }
    }
    // A var char in the basename (at/after the char following the last '/') could
    // inject a glob metachar from its value — refuse (re-injection guard).
    let basename_start = last_slash_byte.map_or(0, |i| i + 1);
    if last_var_byte.is_some_and(|v| v >= basename_start) {
        return Err((
            "$VAR".to_string(),
            ToolError::denied(
                "a variable in a glob's basename is not supported (re-injection guard); \
                 put the variable in the directory prefix, e.g. $DIR/*.rs",
            ),
        ));
    }
    Ok(out)
}

// ── glob expansion (multi-segment + recursive `**`) ─────────────────────────

/// One directory entry the glob walker sees: a name and whether it is a directory
/// (needed to recurse for `**`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GlobEntry {
    pub name: String,
    pub is_dir: bool,
}

/// Lists a directory's entries — the filesystem seam for the glob walker, so unit
/// tests drive multi-segment / `**` expansion without a real filesystem (#47).
pub(crate) trait DirLister: Send + Sync {
    /// The entries of `dir` (names + is-dir), or empty if it cannot be read.
    fn list(&self, dir: &Path) -> Vec<GlobEntry>;
}

/// The real filesystem lister.
pub(crate) struct RealDirLister;
impl DirLister for RealDirLister {
    fn list(&self, dir: &Path) -> Vec<GlobEntry> {
        std::fs::read_dir(dir)
            .map(|rd| {
                rd.filter_map(|e| {
                    let e = e.ok()?;
                    let name = e.file_name().into_string().ok()?;
                    let is_dir = e.file_type().map(|t| t.is_dir()).unwrap_or(false);
                    Some(GlobEntry { name, is_dir })
                })
                .collect()
            })
            .unwrap_or_default()
    }
}

/// Append `name` to the result path `rel`, preserving the pattern's form
/// (relative vs absolute).
fn join_rel(rel: &str, name: &str) -> String {
    if rel.is_empty() {
        name.to_string()
    } else if rel == "/" {
        format!("/{name}")
    } else {
        format!("{rel}/{name}")
    }
}

/// Collect every descendant directory of `(real, rel)` (bounded depth),
/// leash-checking + listing each — the `**` expansion. Hidden directories are not
/// descended (bash globstar default).
fn descend_all(
    real: &Path,
    rel: &str,
    list: &dyn DirLister,
    leash: &mut dyn FnMut(&Path) -> ToolResult<()>,
    depth: usize,
    max_matches: usize,
    out: &mut Vec<(PathBuf, String)>,
) -> ToolResult<()> {
    if depth == 0 || out.len() >= max_matches {
        return Ok(());
    }
    leash(real)?;
    let mut entries = list.list(real);
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    for e in entries {
        if e.is_dir && !e.name.starts_with('.') {
            let child_real = real.join(&e.name);
            let child_rel = join_rel(rel, &e.name);
            out.push((child_real.clone(), child_rel.clone()));
            if out.len() >= max_matches {
                break;
            }
            descend_all(
                &child_real,
                &child_rel,
                list,
                leash,
                depth - 1,
                max_matches,
                out,
            )?;
        }
    }
    Ok(())
}

/// Expand a glob pattern (multi-segment and recursive `**`) against the
/// filesystem via `list`, **leash-checking every directory before listing it**
/// (`leash`) — so the whole walk stays within `fs_read` scope, *before any stage
/// spawns* (atomic admission). Per-component matching uses [`fnmatch`]
/// (`*`/`?`/`[…]` do not cross `/`); `**` matches zero or more directory levels.
/// Bounded by depth + match count. nullglob-off: no match → the literal pattern.
/// A `leash` `Err` (an out-of-scope directory) propagates and denies the command.
fn expand_glob_walk(
    pattern: &str,
    cwd: Option<&str>,
    list: &dyn DirLister,
    leash: &mut dyn FnMut(&Path) -> ToolResult<()>,
    max_depth: usize,
    max_matches: usize,
) -> ToolResult<Vec<String>> {
    let absolute = pattern.starts_with('/');
    let segments: Vec<&str> = pattern.split('/').filter(|s| !s.is_empty()).collect();

    let base_real = if absolute {
        PathBuf::from("/")
    } else {
        cwd.map_or_else(|| PathBuf::from("."), PathBuf::from)
    };
    let base_rel = if absolute {
        "/".to_string()
    } else {
        String::new()
    };
    let mut frontier: Vec<(PathBuf, String)> = vec![(base_real, base_rel)];

    for seg in &segments {
        let mut next: Vec<(PathBuf, String)> = Vec::new();
        if *seg == "**" {
            for (real, rel) in &frontier {
                next.push((real.clone(), rel.clone())); // `**` matches zero levels too
                descend_all(real, rel, list, leash, max_depth, max_matches, &mut next)?;
            }
        } else {
            let seg_hidden = seg.starts_with('.');
            for (real, rel) in &frontier {
                leash(real)?;
                let mut entries = list.list(real);
                entries.sort_by(|a, b| a.name.cmp(&b.name));
                for e in entries {
                    if (seg_hidden || !e.name.starts_with('.')) && fnmatch(seg, &e.name) {
                        next.push((real.join(&e.name), join_rel(rel, &e.name)));
                        if next.len() >= max_matches {
                            break;
                        }
                    }
                }
            }
        }
        frontier = next;
        if frontier.is_empty() {
            break;
        }
    }

    let mut matches: Vec<String> = frontier.into_iter().map(|(_, rel)| rel).collect();
    matches.retain(|m| !m.is_empty()); // drop the "zero-levels" cwd self-match
    matches.sort();
    matches.dedup();
    if matches.is_empty() {
        Ok(vec![pattern.to_string()])
    } else {
        Ok(matches)
    }
}

/// Glob match: `*` (any run), `?` (one char), `[…]` (class with ranges and
/// `!`/`^` negation). `*`/`?`/`[` do not cross `/` (single-segment matching).
fn fnmatch(pattern: &str, name: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let n: Vec<char> = name.chars().collect();
    fnmatch_inner(&p, &n)
}

fn fnmatch_inner(p: &[char], n: &[char]) -> bool {
    match p.first() {
        None => n.is_empty(),
        Some('*') => fnmatch_inner(&p[1..], n) || (!n.is_empty() && fnmatch_inner(p, &n[1..])),
        Some('?') => !n.is_empty() && fnmatch_inner(&p[1..], &n[1..]),
        Some('[') => {
            if n.is_empty() {
                return false;
            }
            match match_class(&p[1..], n[0]) {
                Some((matched, rest)) => matched && fnmatch_inner(rest, &n[1..]),
                // Malformed class (no closing `]`): treat `[` as a literal.
                None => n[0] == '[' && fnmatch_inner(&p[1..], &n[1..]),
            }
        }
        Some(&c) => !n.is_empty() && c == n[0] && fnmatch_inner(&p[1..], &n[1..]),
    }
}

/// Match a `[...]` class against `c`. `p` begins just after `[`. Returns
/// `(matched, remaining pattern after ])`, or `None` if there is no closing `]`.
fn match_class(p: &[char], c: char) -> Option<(bool, &[char])> {
    let mut i = 0;
    let negate = matches!(p.first(), Some('!' | '^'));
    if negate {
        i = 1;
    }
    let mut matched = false;
    let mut first = true;
    while i < p.len() {
        if p[i] == ']' && !first {
            return Some((matched ^ negate, &p[i + 1..]));
        }
        first = false;
        if i + 2 < p.len() && p[i + 1] == '-' && p[i + 2] != ']' {
            if c >= p[i] && c <= p[i + 2] {
                matched = true;
            }
            i += 3;
        } else {
            if c == p[i] {
                matched = true;
            }
            i += 1;
        }
    }
    None
}

// ── process execution ───────────────────────────────────────────────────────

/// Open a file for an `fs_write` redirect target (`>` truncates, `>>` appends).
fn open_for_write(path: &str, append: bool) -> std::io::Result<std::fs::File> {
    #[cfg(windows)]
    if append {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)?;
        file.seek(SeekFrom::End(0))?;
        return Ok(file);
    }

    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(!append)
        .append(append)
        .open(path)
}

/// Kill (and reap) any stages already spawned, so a mid-pipeline error does not
/// orphan processes.
fn kill_all(children: &mut [Child]) {
    for child in children.iter_mut() {
        let _ = child.kill();
        let _ = child.wait();
    }
}

/// Lower a stage's [`Arg`] list into a concrete argv: literals as-is, globs
/// expanded against the real filesystem, and (allowlisted) variables read from
/// the environment as a single literal (no re-split / no re-glob of the value).
/// The allowlist is enforced earlier in [`ShellTool::invoke`].
fn expand_stage_argv(stage: &Command, _cwd: Option<&str>) -> Vec<String> {
    let mut argv = Vec::with_capacity(stage.argv.len());
    for arg in &stage.argv {
        match arg {
            Arg::Lit(s) => argv.push(s.clone()),
            // Concatenate the segments: literals as-is, variables (already
            // allowlisted in `invoke`) read from the env as a single literal —
            // no re-split / no re-glob of the value.
            Arg::Var(segs) => {
                let mut word = String::new();
                for seg in segs {
                    match seg {
                        Seg::Lit(s) => word.push_str(s),
                        Seg::Var(name) => word.push_str(&std::env::var(name).unwrap_or_default()),
                    }
                }
                argv.push(word);
            }
            // Globs (and glob+var words) are expanded to literal matches at
            // admission (with the per-directory fs_read leash), so the spawner
            // never sees them.
            Arg::Glob(_) => unreachable!("glob expanded at admission"),
            Arg::VarGlob(_) => unreachable!("VarGlob lowered/expanded at admission"),
        }
    }
    argv
}

/// Spawn a pipeline of commands wired with OS pipes and file redirections,
/// capturing the last stage's stdout (unless it is redirected to a file) and
/// every stage's stderr. The pipeline's exit code is the last stage's (bash
/// semantics without `pipefail`).
///
/// Deadlock-free: every stage's stderr and the last stage's stdout are drained by
/// their own threads, so no pipe can fill while we `wait()` the children.
///
/// `wrap` is the OS-sandbox command prefix (macOS Seatbelt's `sandbox-exec -p
/// <profile>`), prepended to **every** stage so each spawned program is confined;
/// it is empty for thread-confining (Landlock) and unconfined runs.
fn run_pipeline(
    stages: &[Command],
    cwd: Option<&str>,
    wrap: &[String],
    env: &BTreeMap<String, String>,
    max_output: usize,
) -> ToolResult<Captured> {
    debug_assert!(!stages.is_empty(), "the parser guarantees ≥1 stage");
    let n = stages.len();
    let last = n - 1;

    let mut children: Vec<Child> = Vec::with_capacity(n);
    // The read end feeding the NEXT stage's stdin (from the prior stage's stdout).
    let mut prev_stdin: Option<PipeReader> = None;
    // The read end capturing final stdout (last stage, when not redirected).
    let mut stdout_capture: Option<PipeReader> = None;
    // Reader threads for stages whose stderr is captured separately. Each yields
    // (captured bytes ≤ cap, truncated?).
    let mut stderr_threads: Vec<std::thread::JoinHandle<(Vec<u8>, bool)>> = Vec::new();

    for (i, stage) in stages.iter().enumerate() {
        let is_last = i == last;
        let stage_argv = expand_stage_argv(stage, cwd);
        // Prepend the sandbox wrapper (Seatbelt) so the program is spawned
        // confined: `sandbox-exec -p <profile> <program> <args…>`. Empty wrap is
        // the identity. `sandbox-exec` forwards stdio + cwd to the child, so the
        // pipe/redirect plumbing below is unchanged.
        let argv: Vec<String> = if wrap.is_empty() {
            stage_argv
        } else {
            wrap.iter().cloned().chain(stage_argv).collect()
        };
        let mut cmd = std::process::Command::new(&argv[0]);
        cmd.args(&argv[1..]);
        if let Some(dir) = cwd {
            cmd.current_dir(dir);
        }
        // Host/operator-supplied environment (the env seam, newt #783): set the
        // provided vars on the child, additive over the inherited ambient env.
        // The values are structured host input (never model-authored command
        // text), so they grant no new authority — the exec/fs leash that already
        // admitted this stage checked the *real* program (argv[0]), not env. When
        // a Seatbelt `wrap` prefix is present, `sandbox-exec` forwards its own
        // environment to the wrapped program, so setting it here still reaches the
        // confined child.
        for (k, v) in env {
            cmd.env(k, v);
        }

        // ── stdin: a `< file` redirect wins over the incoming pipe ──────────
        if let Some(path) = stage.stdin_path() {
            let file = ok_or_kill(std::fs::File::open(path), &mut children)?;
            cmd.stdin(Stdio::from(file));
            prev_stdin = None;
        } else {
            cmd.stdin(match prev_stdin.take() {
                Some(reader) => Stdio::from(reader),
                None => Stdio::null(),
            });
        }

        // ── stdout (+ the handle stderr clones for `2>&1`) ──────────────────
        // A `> file` redirect goes to the file; otherwise a `std::io::pipe()` is
        // used so its writer can be cloned for `2>&1` in any position.
        let dup_source: DupSource;
        if let Some((path, append)) = stage.stdout_redirect() {
            let file = ok_or_kill(open_for_write(path, append), &mut children)?;
            let clone = ok_or_kill(file.try_clone(), &mut children)?;
            cmd.stdout(Stdio::from(file));
            dup_source = DupSource::File(clone);
        } else {
            let (reader, writer) = ok_or_kill(std::io::pipe(), &mut children)?;
            let clone = ok_or_kill(writer.try_clone(), &mut children)?;
            cmd.stdout(Stdio::from(writer));
            if is_last {
                stdout_capture = Some(reader);
            } else {
                prev_stdin = Some(reader);
            }
            dup_source = DupSource::Pipe(clone);
        }

        // ── stderr ──────────────────────────────────────────────────────────
        match stage.stderr_disposition() {
            // `2>&1`: stderr writes to the stdout destination (the dup is moved
            // into the child; nothing captured separately).
            StderrTo::Stdout => match dup_source {
                DupSource::File(f) => {
                    cmd.stderr(Stdio::from(f));
                }
                DupSource::Pipe(w) => {
                    cmd.stderr(Stdio::from(w));
                }
            },
            // `2> file`: stderr to its own file.
            StderrTo::File { path, append } => {
                let file = ok_or_kill(open_for_write(&path, append), &mut children)?;
                cmd.stderr(Stdio::from(file));
                // `dup_source` is dropped here (unused) — never retain a writer.
            }
            // Default: capture stderr separately via a piped fd.
            StderrTo::Capture => {
                cmd.stderr(Stdio::piped());
            }
        }

        let mut child = ok_or_kill(cmd.spawn(), &mut children)?;

        if matches!(stage.stderr_disposition(), StderrTo::Capture) {
            let err = child.stderr.take().expect("stderr is piped");
            stderr_threads.push(std::thread::spawn(move || read_capped(err, max_output)));
        }
        children.push(child);
    }

    // The parent now holds no pipe writers, so a captured reader sees EOF once
    // the child(ren) exit. Read stdout (bounded by the cap) concurrently with
    // waiting; a child producing past the cap is cut off via EPIPE.
    let stdout_thread =
        stdout_capture.map(|reader| std::thread::spawn(move || read_capped(reader, max_output)));

    // Wait all stages; the pipeline's exit code is the last stage's.
    let mut exit_code = -1;
    for (i, child) in children.iter_mut().enumerate() {
        let status = child.wait().map_err(ToolError::Exec)?;
        if i == last {
            exit_code = status.code().unwrap_or(-1);
        }
    }

    let (stdout, stdout_truncated) =
        stdout_thread.map_or((Vec::new(), false), |h| h.join().unwrap_or_default());
    let mut stderr = Vec::new();
    let mut stderr_truncated = false;
    for h in stderr_threads {
        let (buf, trunc) = h.join().unwrap_or_default();
        stderr.extend(buf);
        stderr_truncated |= trunc;
    }
    // Concatenated stderr across stages may itself exceed the cap; `capped_utf8`
    // clips it and we flag that too.
    let stderr_truncated = stderr_truncated || stderr.len() > max_output;

    Ok(Captured {
        exit_code,
        stdout: capped_utf8(&stdout, max_output),
        stderr: capped_utf8(&stderr, max_output),
        stdout_truncated,
        stderr_truncated,
        // #196: net denials are attached by run_with_egress_proxy (which owns the
        // proxy handle), not here — a bare pipeline run observes no proxy refusals.
        net_denials: Vec::new(),
    })
}

/// What a stage's stderr clones from for `2>&1` (the stdout destination).
enum DupSource {
    File(std::fs::File),
    Pipe(PipeWriter),
}

/// Map an `io::Result`, killing already-spawned children on error so a failure
/// mid-pipeline never orphans processes.
fn ok_or_kill<T>(result: std::io::Result<T>, children: &mut [Child]) -> ToolResult<T> {
    result.map_err(|e| {
        kill_all(children);
        ToolError::Exec(e)
    })
}

/// Read **at most** `max_output` bytes from `reader` into memory, then probe one
/// more byte to decide whether the source had more. Returns the captured bytes
/// (≤ cap) and whether it was truncated.
///
/// Crucially, peak buffering is bounded by the cap **regardless of how much the
/// child produces** — closing the DoS where a fast producer (`yes`,
/// `cat /dev/zero`) balloons host memory up to the timeout window (#73). The
/// remainder is **not** drained: dropping `reader` closes the pipe read end, so a
/// still-writing child gets `EPIPE`/`SIGPIPE` on its next write (the `| head`
/// model) rather than blocking us — and we never read past `cap + 1` bytes.
fn read_capped(mut reader: impl Read, max_output: usize) -> (Vec<u8>, bool) {
    let mut buf = Vec::new();
    // `take` bounds total bytes read into `buf` to the cap.
    let _ = (&mut reader).take(max_output as u64).read_to_end(&mut buf);
    // One probe read: any byte beyond the cap means the source was truncated.
    let mut probe = [0u8; 1];
    let truncated = matches!(reader.read(&mut probe), Ok(n) if n > 0);
    (buf, truncated)
}

/// Lossy-decode captured output (already bounded to ≤ `max_output` by
/// [`read_capped`]). The `min` is a defensive belt-and-suspenders. Truncation at
/// a byte boundary is safe: [`String::from_utf8_lossy`] replaces any partial
/// trailing sequence rather than panicking.
fn capped_utf8(bytes: &[u8], max_output: usize) -> String {
    let slice = &bytes[..bytes.len().min(max_output)];
    String::from_utf8_lossy(slice).into_owned()
}

/// Cap an already-decoded string to `max_output` at a char boundary
/// (used for the concatenated output of a multi-pipeline script).
fn cap_string(mut s: String, max_output: usize) -> String {
    if s.len() > max_output {
        let mut end = max_output;
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        s.truncate(end);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_bridle_core::{Caveats, Gate, Scope};
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// A spawner that records every pipeline it runs and returns a canned exit
    /// code per program (argv0), default 0 — no real processes.
    #[derive(Default)]
    struct MockSpawner {
        calls: Mutex<Vec<Vec<Command>>>,
        /// The env map handed to each `run` call (parallel to `calls`), so the env
        /// seam (newt #783) is verified without a real process.
        envs: Mutex<Vec<BTreeMap<String, String>>>,
        exit_by_program: HashMap<String, i32>,
        block_ms: u64,
        /// #196: net denials the spawner reports back — the shape
        /// `run_with_egress_proxy` produces from the proxy's refused hosts, so the
        /// Captured→envelope wiring is verified without a real proxy/child.
        net_denials: Vec<Denial>,
    }

    impl MockSpawner {
        fn with_exit(program: &str, code: i32) -> Self {
            let mut m = Self::default();
            m.exit_by_program.insert(program.to_string(), code);
            m
        }

        /// #196: a mock whose `run` reports these net denials (as the real proxy
        /// path would for refused hosts).
        fn with_net_denials(denials: Vec<Denial>) -> Self {
            Self {
                net_denials: denials,
                ..Self::default()
            }
        }
    }

    /// A stage's program word (argv[0]) for test assertions. (A variable in the
    /// program position is denied in `invoke`, so it never reaches the spawner.)
    fn prog(stage: &Command) -> &str {
        match stage.argv.first() {
            Some(Arg::Lit(s) | Arg::Glob(s)) => s,
            Some(Arg::Var(_) | Arg::VarGlob(_)) | None => "",
        }
    }

    impl Spawner for MockSpawner {
        fn run(
            &self,
            stages: &[Command],
            _cwd: Option<&str>,
            _caveats: &Caveats,
            env: &BTreeMap<String, String>,
            _cfg: &SpawnCfg,
        ) -> ToolResult<Captured> {
            self.calls.lock().unwrap().push(stages.to_vec());
            self.envs.lock().unwrap().push(env.clone());
            if self.block_ms > 0 {
                std::thread::sleep(Duration::from_millis(self.block_ms));
            }
            Ok(Captured {
                exit_code: self
                    .exit_by_program
                    .get(prog(&stages[0]))
                    .copied()
                    .unwrap_or(0),
                stdout: String::new(),
                stderr: String::new(),
                net_denials: self.net_denials.clone(),
                ..Default::default()
            })
        }
    }

    fn ctx(granted: Caveats) -> ToolContext {
        Gate::new(0)
            .authorize(&ShellTool::new(), &granted)
            .expect("authorize")
    }

    /// A context for a **strong** principal (fence-strength floor = `Kernel`):
    /// any restricted axis the real backend can't kernel-confine fails closed.
    fn ctx_strong(granted: Caveats) -> ToolContext {
        Gate::new(0)
            .with_strength_floor(agent_bridle_core::AxisEnforcement::Kernel)
            .authorize(&ShellTool::new(), &granted)
            .expect("authorize")
    }

    fn exec_only(names: &[&str]) -> Caveats {
        Caveats {
            exec: Scope::only(names.iter().map(|s| (*s).to_string())),
            ..Caveats::top()
        }
    }

    fn calls(mock: &Arc<MockSpawner>) -> Vec<Vec<Command>> {
        mock.calls.lock().unwrap().clone()
    }

    /// The env map handed to each `run` call, in order (the env seam, newt #783).
    fn envs(mock: &Arc<MockSpawner>) -> Vec<BTreeMap<String, String>> {
        mock.envs.lock().unwrap().clone()
    }

    /// ADR 0012 D4/D8 + ADR 0014: a STRONG principal (floor = `Kernel`) refuses to
    /// run unconfined when a restricted axis cannot be kernel-confined on this host.
    ///
    /// For the `exec` axis the outcome is **backend-dependent** since ADR 0014
    /// closed #57 for macOS: under an active Seatbelt backend `exec` is
    /// kernel-confined via `process-exec*`, so the strong principal *runs*
    /// (reporting `exec → kernel`); under Landlock or a Noop host the exec axis is
    /// still held (#31/#57), so it fails closed *before any spawn*. The default
    /// (permissive, Advisory-floor) principal runs in either case. This closes the
    /// shell's run-unconfined gap and matches `ConfinedCommand`'s fail-closed
    /// posture. The test's expectation is derived from the *same* honesty rule the
    /// production path uses (`intended_sandbox_kind` + `enforcement_report`), so the
    /// two cannot disagree across platforms/features.
    #[tokio::test]
    async fn strong_principal_fails_closed_on_unenforceable_exec() {
        let granted = exec_only(&["echo"]);
        // Does the backend that will actually govern this run kernel-confine `exec`?
        // Seatbelt does (`process-exec*`, ADR 0014); Landlock/Noop do not (#31/#57).
        let exec_is_kernel_confined = enforcement_report(
            &granted,
            intended_sandbox_kind(&granted, &Arc::new(SandboxPolicy::default())),
        )
        .exec
            == Some(agent_bridle_core::AxisEnforcement::Kernel);

        let mock = Arc::new(MockSpawner::default());
        let out = ShellTool::with_spawner(mock.clone())
            .invoke(
                serde_json::json!({"cmd": "echo hi"}),
                &ctx_strong(granted.clone()),
            )
            .await
            .expect("invoke");
        if exec_is_kernel_confined {
            // Seatbelt confines `exec` in the kernel, so the strong principal runs —
            // kernel-confined, not refused.
            assert_ne!(
                out["denied"],
                serde_json::json!(true),
                "kernel-confined exec must run for a strong principal: {out}"
            );
            assert_eq!(
                out["enforcement"]["exec"], "kernel",
                "exec is reported kernel-confined: {out}"
            );
            assert_eq!(ran_programs(&mock), ["echo"], "the program spawned: {out}");
        } else {
            // The exec axis is held (Landlock/Noop): a Kernel floor cannot be met, so
            // refuse before any spawn.
            assert_eq!(
                out["denied"], true,
                "strong principal must fail closed on unenforceable exec: {out}"
            );
            assert!(ran_programs(&mock).is_empty(), "nothing may spawn: {out}");
        }

        // The default (permissive, Advisory-floor) principal runs the same command
        // regardless of backend.
        let mock = Arc::new(MockSpawner::default());
        let out = ShellTool::with_spawner(mock.clone())
            .invoke(serde_json::json!({"cmd": "echo hi"}), &ctx(granted))
            .await
            .expect("invoke");
        assert_ne!(
            out["denied"],
            serde_json::json!(true),
            "default principal still runs: {out}"
        );
    }

    /// #196: a net refusal reported by the spawner (the shape
    /// `run_with_egress_proxy` produces from the proxy's refused hosts) reaches
    /// the result envelope as a structured `net` denial with `denied: true` — the
    /// exact signal a consumer (newt) lifts into a per-host prompt. Unlike an
    /// `exec`/`open` refusal, the command still RAN (the refusal is observed
    /// during the run, not at pre-spawn admission).
    #[tokio::test]
    async fn net_refusal_surfaces_as_a_net_denial_in_the_envelope() {
        let mock = Arc::new(MockSpawner::with_net_denials(vec![Denial {
            kind: DenialKind::Net,
            target: "github.com".to_string(),
            reason: "net does not permit 'github.com'".to_string(),
        }]));
        let out = ShellTool::with_spawner(mock)
            .invoke(
                serde_json::json!({ "cmd": "echo hi" }),
                &ctx(exec_only(&["echo"])),
            )
            .await
            .expect("invoke");
        assert_eq!(
            out["denied"],
            serde_json::json!(true),
            "a net denial sets denied: {out}"
        );
        assert_eq!(out["denials"][0]["kind"], "net");
        assert_eq!(out["denials"][0]["target"], "github.com");
        // The command still executed — a success envelope (has exit_code), not a
        // pre-spawn refused envelope.
        assert!(out.get("exit_code").is_some(), "command still ran: {out}");
    }

    fn ran_programs(mock: &Arc<MockSpawner>) -> Vec<String> {
        calls(mock)
            .iter()
            .map(|pipeline| prog(&pipeline[0]).to_string())
            .collect()
    }

    // ── the env seam (newt #783) ────────────────────────────────────────────

    /// A dispatch carrying `"env": { "FOO": "bar" }` reaches the spawner with that
    /// var on the child's environment map — the seam newt #783 needs so it can
    /// pass the venv environment as real env instead of an `export …;` prefix.
    #[tokio::test]
    async fn env_map_is_passed_to_the_spawner() {
        let mock = Arc::new(MockSpawner::default());
        let out = ShellTool::with_spawner(mock.clone())
            .invoke(
                serde_json::json!({
                    "program": "echo",
                    "args": ["hi"],
                    "env": { "FOO": "bar", "VIRTUAL_ENV": "/venv" },
                }),
                &ctx(exec_only(&["echo"])),
            )
            .await
            .expect("invoke");
        assert_ne!(out["denied"], serde_json::json!(true), "must run: {out}");
        let envs = envs(&mock);
        assert_eq!(envs.len(), 1, "one pipeline ran");
        assert_eq!(envs[0].get("FOO").map(String::as_str), Some("bar"));
        assert_eq!(
            envs[0].get("VIRTUAL_ENV").map(String::as_str),
            Some("/venv"),
            "every env entry reaches the child: {:?}",
            envs[0]
        );
    }

    /// The env map is NEVER part of the leash decision: the leash still checks the
    /// real program. A compound command (`hostname; uname`) with `env` set must
    /// check `hostname` first — never `export`/`env`/an env KEY. This is the exact
    /// newt #783 root cause: prepending `export VIRTUAL_ENV=…;` made the first
    /// stage's argv[0] the literal `export` builtin, which the leash denied. With
    /// env carried as a real map there is no `export` stage at all.
    #[tokio::test]
    async fn env_does_not_change_the_program_the_leash_checks() {
        let mock = Arc::new(MockSpawner::default());
        // Grant exactly the two real programs; `export`/`env`/the env keys are NOT
        // granted, so if any of them were checked the run would be denied.
        let out = ShellTool::with_spawner(mock.clone())
            .invoke(
                serde_json::json!({
                    "cmd": "hostname; uname -s",
                    "env": { "FOO": "bar" },
                }),
                &ctx(exec_only(&["hostname", "uname"])),
            )
            .await
            .expect("invoke");
        assert_ne!(out["denied"], serde_json::json!(true), "must run: {out}");
        // The FIRST program the spawner saw is the real `hostname`, not `export`.
        let programs = ran_programs(&mock);
        assert_eq!(
            programs,
            vec!["hostname".to_string(), "uname".to_string()],
            "the leash/spawner see the real programs, never `export`/env keys: {programs:?}"
        );
        // And the env still reached each child.
        for e in envs(&mock) {
            assert_eq!(e.get("FOO").map(String::as_str), Some("bar"));
        }
    }

    /// `ShellArgs::parse`: the `env` field is populated from the dispatch JSON
    /// `"env"` object when present, and is empty (back-compat) when absent.
    #[test]
    fn parse_env_field_present_and_absent() {
        // Present → populated (string values only).
        let parsed = ShellArgs::parse(
            &serde_json::json!({
                "program": "echo",
                "env": { "FOO": "bar", "BAZ": "qux" },
            }),
            &agent_bridle_core::LimitsPolicy::default(),
        )
        .expect("parse");
        assert_eq!(parsed.env.get("FOO").map(String::as_str), Some("bar"));
        assert_eq!(parsed.env.get("BAZ").map(String::as_str), Some("qux"));
        assert_eq!(parsed.env.len(), 2);

        // Absent → empty map (existing dispatches are unaffected).
        let parsed = ShellArgs::parse(
            &serde_json::json!({ "program": "echo" }),
            &agent_bridle_core::LimitsPolicy::default(),
        )
        .expect("parse");
        assert!(parsed.env.is_empty(), "absent env defaults to empty");
    }

    /// #143: the timeout is bounded/defaulted by the configured `LimitsPolicy`,
    /// not the old hard-coded 300/60. A tuned policy clamps and defaults to its
    /// own values.
    #[test]
    fn parse_timeout_uses_configured_limits() {
        let limits = agent_bridle_core::LimitsPolicy {
            max_timeout_secs: 5,
            default_timeout_secs: 3,
            ..agent_bridle_core::LimitsPolicy::default()
        };
        // A request over the configured max is clamped to it.
        let over = ShellArgs::parse(
            &serde_json::json!({ "program": "echo", "timeout_secs": 9999 }),
            &limits,
        )
        .expect("parse");
        assert_eq!(over.timeout, std::time::Duration::from_secs(5));
        // No timeout specified → the configured default.
        let dflt =
            ShellArgs::parse(&serde_json::json!({ "program": "echo" }), &limits).expect("parse");
        assert_eq!(dflt.timeout, std::time::Duration::from_secs(3));
    }

    /// A fake environment for the `$VAR` tests — exercises the allowlist +
    /// expansion + resolved-path leash without touching the real process env.
    struct FakeEnv(HashMap<String, String>);
    impl EnvProvider for FakeEnv {
        fn get(&self, name: &str) -> Option<String> {
            self.0.get(name).cloned()
        }
    }
    fn fake_env(pairs: &[(&str, &str)]) -> Arc<dyn EnvProvider> {
        Arc::new(FakeEnv(
            pairs
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect(),
        ))
    }

    /// A fake directory lister keyed by path string — drives the glob walker
    /// without a real filesystem (#47).
    struct MapLister(HashMap<String, Vec<GlobEntry>>);
    impl DirLister for MapLister {
        fn list(&self, dir: &Path) -> Vec<GlobEntry> {
            // Normalize to forward slashes so test maps written with `/` work on
            // Windows where PathBuf::join produces `\`-separated paths.
            let key = dir.to_string_lossy().replace('\\', "/");
            self.0.get(&key).cloned().unwrap_or_default()
        }
    }
    fn ent(name: &str, is_dir: bool) -> GlobEntry {
        GlobEntry {
            name: name.to_string(),
            is_dir,
        }
    }
    fn map_lister(dirs: &[(&str, Vec<GlobEntry>)]) -> Arc<dyn DirLister> {
        Arc::new(MapLister(
            dirs.iter()
                .map(|(d, es)| ((*d).to_string(), es.clone()))
                .collect(),
        ))
    }

    // ── $VAR in redirect targets (#46, via the env seam) ────────────────────

    /// `> $TMPDIR/out` expands the allowlisted var through the seam and the
    /// spawner receives the RESOLVED path (never a literal `$VAR`); the resolved
    /// path is what the fs leash checked.
    #[tokio::test]
    async fn redirect_var_is_expanded_and_reaches_spawner_resolved() {
        let tmp = std::env::temp_dir().to_string_lossy().into_owned();
        let mock = Arc::new(MockSpawner::default());
        let tool = ShellTool::with_spawner_and_env(mock.clone(), fake_env(&[("TMPDIR", &tmp)]));
        // fs_write is All (default), so the resolved path passes the leash.
        let out = tool
            .invoke(
                serde_json::json!({"cmd": "echo hi > $TMPDIR/out"}),
                &ctx(exec_only(&["echo"])),
            )
            .await
            .expect("invoke");
        assert_ne!(
            out["denied"],
            serde_json::json!(true),
            "in-scope var: {out}"
        );
        let redir = &calls(&mock)[0][0].redirects[0];
        assert_eq!(
            *redir,
            Redirect::Stdout {
                path: vec![Seg::Lit(format!("{tmp}/out"))],
                append: false,
            }
        );
    }

    /// A non-allowlisted variable in a redirect target denies before any spawn.
    #[tokio::test]
    async fn redirect_var_not_in_allowlist_is_denied() {
        let mock = Arc::new(MockSpawner::default());
        let tool = ShellTool::with_spawner_and_env(mock.clone(), fake_env(&[("SECRET", "/x")]));
        let out = tool
            .invoke(
                serde_json::json!({"cmd": "echo hi > $SECRET"}),
                &ctx(exec_only(&["echo"])),
            )
            .await
            .expect("invoke");
        assert_eq!(out["denied"], true, "non-allowlisted redirect var: {out}");
        assert!(
            ran_programs(&mock).is_empty(),
            "no spawn on a denied redirect"
        );
        assert!(out["denials"][0]["reason"]
            .as_str()
            .unwrap_or_default()
            .contains("SECRET"));
    }

    // ── glob + variable in one word (#46, $DIR/*.rs) ────────────────────────

    /// The re-injection guard, unit-tested directly: a `*` in the VAR VALUE stays
    /// in the (literal) directory prefix and never globs; a variable in the glob
    /// BASENAME is refused.
    #[test]
    fn expand_varglob_keeps_value_metachars_literal_and_refuses_basename_var() {
        // TMPDIR is allowlisted; give it a value containing a glob metachar.
        let env = FakeEnv(HashMap::from([("TMPDIR".to_string(), "/a*b".to_string())]));
        let allow = agent_bridle_core::LimitsPolicy::default().var_allowlist;
        // `$TMPDIR/*.rs` → "/a*b/*.rs": the var's `*` is in the dir prefix
        // (literal); only the source `*.rs` basename globs.
        let pattern = expand_varglob(
            &[Seg::Var("TMPDIR".into()), Seg::Lit("/*.rs".into())],
            &env,
            &allow,
        )
        .unwrap();
        assert_eq!(pattern, "/a*b/*.rs");
        // A variable in the glob basename is refused (would re-inject metachars).
        let err = expand_varglob(
            &[Seg::Var("TMPDIR".into()), Seg::Lit("*.rs".into())],
            &env,
            &allow,
        );
        assert!(err.is_err(), "var in glob basename must be refused");
    }

    /// `$DIR/*.rs` lowers the var (env seam) AND expands the glob at admission
    /// (per-directory fs_read leash), so the spawner receives the literal matches.
    #[tokio::test]
    async fn glob_var_expands_to_resolved_matches_before_spawn() {
        let mock = Arc::new(MockSpawner::default());
        let lister = map_lister(&[
            (".", vec![ent("proj", true)]),
            ("./proj", vec![ent("a.rs", false), ent("b.rs", false)]),
        ]);
        let tool = ShellTool::with_seams(mock.clone(), fake_env(&[("TMPDIR", "proj")]), lister);
        let out = tool
            .invoke(
                serde_json::json!({"cmd": "ls $TMPDIR/*.rs"}), // fs_read All by default
                &ctx(exec_only(&["ls"])),
            )
            .await
            .expect("invoke");
        assert_ne!(
            out["denied"],
            serde_json::json!(true),
            "in-scope glob var: {out}"
        );
        assert_eq!(
            calls(&mock)[0][0].argv,
            vec![
                Arg::Lit("ls".into()),
                Arg::Lit("proj/a.rs".into()),
                Arg::Lit("proj/b.rs".into())
            ]
        );
    }

    /// A variable in the glob basename (`$PREFIX*.rs`) is refused at admission.
    #[tokio::test]
    async fn glob_var_in_basename_is_denied() {
        let mock = Arc::new(MockSpawner::default());
        let tool = ShellTool::with_spawner_and_env(mock.clone(), fake_env(&[("PREFIX", "foo")]));
        let out = tool
            .invoke(
                serde_json::json!({"cmd": "ls $PREFIX*.rs"}),
                &ctx(exec_only(&["ls"])),
            )
            .await
            .expect("invoke");
        assert_eq!(out["denied"], true, "var in glob basename refused: {out}");
        assert!(ran_programs(&mock).is_empty());
    }

    /// A non-allowlisted variable in a glob word denies before any spawn.
    #[tokio::test]
    async fn glob_var_not_in_allowlist_is_denied() {
        let mock = Arc::new(MockSpawner::default());
        let tool = ShellTool::with_spawner_and_env(mock.clone(), fake_env(&[("SECRET", "/s")]));
        let out = tool
            .invoke(
                serde_json::json!({"cmd": "ls $SECRET/*.rs"}),
                &ctx(exec_only(&["ls"])),
            )
            .await
            .expect("invoke");
        assert_eq!(out["denied"], true, "non-allowlisted glob var: {out}");
        assert!(ran_programs(&mock).is_empty());
    }

    /// The RESOLVED redirect path is leash-checked: an allowlisted var whose value
    /// lands outside `fs_write` scope denies (proving the leash sees the resolved
    /// path, not the literal `$VAR`).
    #[tokio::test]
    async fn redirect_var_resolved_path_out_of_fs_write_scope_denied() {
        let tmp = std::env::temp_dir().to_string_lossy().into_owned();
        let mock = Arc::new(MockSpawner::default());
        let tool = ShellTool::with_spawner_and_env(mock.clone(), fake_env(&[("TMPDIR", &tmp)]));
        let granted = Caveats {
            exec: Scope::only(["echo".to_string()]),
            fs_write: Scope::only(["/nonexistent-grant-root".to_string()]),
            ..Caveats::top()
        };
        let out = tool
            .invoke(
                serde_json::json!({"cmd": "echo hi > $TMPDIR/out"}),
                &ctx(granted),
            )
            .await
            .expect("invoke");
        assert_eq!(out["denied"], true, "resolved path outside fs_write: {out}");
        assert!(ran_programs(&mock).is_empty());
    }

    // ── sequencing / leash (carried from earlier increments) ────────────────

    #[tokio::test]
    async fn and_short_circuits_on_failure() {
        let mock = Arc::new(MockSpawner::with_exit("false", 1));
        ShellTool::with_spawner(mock.clone())
            .invoke(
                serde_json::json!({"cmd": "false && echo hi"}),
                &ctx(exec_only(&["false", "echo"])),
            )
            .await
            .expect("invoke");
        assert_eq!(ran_programs(&mock), vec!["false"], "echo must be skipped");
    }

    #[tokio::test]
    async fn out_of_scope_anywhere_denies_the_whole_script() {
        let mock = Arc::new(MockSpawner::default());
        let out = ShellTool::with_spawner(mock.clone())
            .invoke(
                serde_json::json!({"cmd": "echo ok ; rm -rf x"}),
                &ctx(exec_only(&["echo"])),
            )
            .await
            .expect("invoke");
        assert_eq!(out["denied"], true);
        assert!(ran_programs(&mock).is_empty());
    }

    // ── globbing (increment 5) ──────────────────────────────────────────────

    /// A glob arg is EXPANDED at admission (with the per-directory fs_read leash)
    /// to its literal matches before the spawner runs (#47).
    #[tokio::test]
    async fn glob_arg_expanded_to_matches_before_spawn() {
        let mock = Arc::new(MockSpawner::default());
        let lister = map_lister(&[(
            ".",
            vec![ent("a.rs", false), ent("b.rs", false), ent("c.txt", false)],
        )]);
        ShellTool::with_seams(mock.clone(), fake_env(&[]), lister)
            .invoke(
                serde_json::json!({"cmd": "ls *.rs"}), // fs_read is All by default
                &ctx(exec_only(&["ls"])),
            )
            .await
            .expect("invoke");
        assert_eq!(
            calls(&mock)[0][0].argv,
            vec![
                Arg::Lit("ls".into()),
                Arg::Lit("a.rs".into()),
                Arg::Lit("b.rs".into())
            ]
        );
    }

    /// A glob in the program position is refused (we never exec a pattern).
    #[tokio::test]
    async fn glob_as_program_name_denied() {
        let mock = Arc::new(MockSpawner::default());
        let out = ShellTool::with_spawner(mock.clone())
            .invoke(serde_json::json!({"cmd": "*.sh foo"}), &ctx(Caveats::top()))
            .await
            .expect("invoke");
        assert_eq!(out["denied"], true);
        assert!(ran_programs(&mock).is_empty());
    }

    /// The directory a glob lists is an `fs_read`; out of scope ⇒ denied, no spawn.
    #[tokio::test]
    async fn glob_dir_out_of_fs_read_scope_denied() {
        let mock = Arc::new(MockSpawner::default());
        let granted = Caveats {
            exec: Scope::only(["echo".to_string()]),
            // fs_read restricted to the temp dir; the cwd glob lists elsewhere.
            fs_read: Scope::only([std::env::temp_dir().to_string_lossy().into_owned()]),
            ..Caveats::top()
        };
        let out = ShellTool::with_spawner(mock.clone())
            .invoke(serde_json::json!({"cmd": "echo *"}), &ctx(granted))
            .await
            .expect("invoke");
        assert_eq!(out["denied"], true);
        assert_eq!(out["denials"][0]["kind"], "open");
        assert!(ran_programs(&mock).is_empty());
    }

    // ── variable expansion / allowlist (increment 6) ────────────────────────

    /// An allowlisted variable reaches the spawner as an (unexpanded) `Var`.
    #[tokio::test]
    async fn allowlisted_var_reaches_spawner() {
        let mock = Arc::new(MockSpawner::default());
        ShellTool::with_spawner(mock.clone())
            .invoke(
                serde_json::json!({"cmd": "echo $HOME"}),
                &ctx(exec_only(&["echo"])),
            )
            .await
            .expect("invoke");
        let c = calls(&mock);
        assert_eq!(
            c[0][0].argv,
            vec![
                Arg::Lit("echo".into()),
                Arg::Var(vec![Seg::Var("HOME".into())]),
            ]
        );
    }

    /// A variable NOT on the allowlist is denied — the spawner is never called,
    /// so a secret like `$AWS_SECRET_KEY` can never be spliced into an argument.
    #[tokio::test]
    async fn non_allowlisted_var_denied() {
        let mock = Arc::new(MockSpawner::default());
        let out = ShellTool::with_spawner(mock.clone())
            .invoke(
                serde_json::json!({"cmd": "echo $AWS_SECRET_KEY"}),
                &ctx(Caveats::top()),
            )
            .await
            .expect("invoke");
        assert_eq!(out["denied"], true);
        assert_eq!(out["denials"][0]["target"], "$AWS_SECRET_KEY");
        assert!(ran_programs(&mock).is_empty());
    }

    /// A variable in the program position is refused (we never exec a variable).
    #[tokio::test]
    async fn var_as_program_name_denied() {
        let mock = Arc::new(MockSpawner::default());
        let out = ShellTool::with_spawner(mock.clone())
            .invoke(
                serde_json::json!({"cmd": "$HOME foo"}),
                &ctx(Caveats::top()),
            )
            .await
            .expect("invoke");
        assert_eq!(out["denied"], true);
        assert!(ran_programs(&mock).is_empty());
    }

    // ── stderr redirects / 2>&1 (issue #45) ─────────────────────────────────

    /// A `2> file` target is leash-checked (`fs_write`) before any spawn.
    #[tokio::test]
    async fn stderr_to_file_out_of_scope_denied() {
        let mock = Arc::new(MockSpawner::default());
        let granted = Caveats {
            exec: Scope::only(["cmd".to_string()]),
            fs_write: Scope::only([std::env::temp_dir().to_string_lossy().into_owned()]),
            ..Caveats::top()
        };
        let out = ShellTool::with_spawner(mock.clone())
            .invoke(
                serde_json::json!({"cmd": "cmd 2> /etc/passwd"}),
                &ctx(granted),
            )
            .await
            .expect("invoke");
        assert_eq!(out["denied"], true);
        assert_eq!(out["denials"][0]["kind"], "open");
        assert_eq!(out["denials"][0]["target"], "/etc/passwd");
        assert!(ran_programs(&mock).is_empty());
    }

    /// `2>&1` parses to a merge and reaches the spawner (no separate file open).
    #[tokio::test]
    async fn stderr_merge_reaches_spawner() {
        let mock = Arc::new(MockSpawner::default());
        ShellTool::with_spawner(mock.clone())
            .invoke(
                serde_json::json!({"cmd": "cmd 2>&1"}),
                &ctx(exec_only(&["cmd"])),
            )
            .await
            .expect("invoke");
        let c = calls(&mock);
        assert_eq!(c[0][0].stderr_disposition(), StderrTo::Stdout);
    }

    #[tokio::test]
    async fn both_program_and_cmd_is_a_hard_error() {
        let res = ShellTool::new()
            .invoke(
                serde_json::json!({"program": "echo", "cmd": "echo hi"}),
                &ctx(Caveats::top()),
            )
            .await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn timeout_is_reported() {
        let mock = Arc::new(MockSpawner {
            block_ms: 1500,
            ..Default::default()
        });
        let out = ShellTool::with_spawner(mock)
            .invoke(
                serde_json::json!({"program": "anything", "timeout_secs": 1}),
                &ctx(exec_only(&["anything"])),
            )
            .await
            .expect("invoke");
        assert_eq!(out["timed_out"], true);
    }

    // ── pure glob matching / expansion (no real fs) ─────────────────────────

    #[test]
    fn fnmatch_basics() {
        assert!(fnmatch("*.rs", "a.rs"));
        assert!(!fnmatch("*.rs", "a.txt"));
        assert!(fnmatch("a?c", "abc"));
        assert!(!fnmatch("a?c", "ac"));
        assert!(fnmatch("*", ""));
        assert!(fnmatch("a*", "a"));
        assert!(fnmatch("[abc]x", "bx"));
        assert!(!fnmatch("[abc]x", "dx"));
        assert!(fnmatch("[!abc]x", "dx"));
        assert!(fnmatch("[a-c]", "b"));
        assert!(!fnmatch("[a-c]", "d"));
        assert!(fnmatch("foo*bar", "fooXYbar"));
    }

    /// #73 regression: `read_capped` bounds peak buffering to the cap and flags
    /// truncation, without slurping the whole stream. The reader panics if asked
    /// for far more than the cap — which `read_to_end` (the old path) would do on
    /// an endless producer.
    #[test]
    fn read_capped_bounds_buffering_and_flags_truncation() {
        // The default output cap (LimitsPolicy::max_output_bytes == 1 MiB).
        const CAP: usize = 1 << 20;
        // An endless 'x' source that asserts it is never asked for more than the
        // cap plus a small probe/pipe slack.
        struct Endless {
            served: usize,
        }
        impl Read for Endless {
            fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
                self.served = self.served.saturating_add(b.len());
                assert!(
                    self.served <= CAP + 64 * 1024,
                    "read_capped over-read {} bytes (cap {CAP})",
                    self.served
                );
                b.fill(b'x');
                Ok(b.len())
            }
        }
        let (buf, truncated) = read_capped(Endless { served: 0 }, CAP);
        assert_eq!(buf.len(), CAP, "peak buffering bounded by the cap");
        assert!(
            truncated,
            "a source longer than the cap is flagged truncated"
        );

        // A short source is captured whole and NOT flagged.
        let (buf2, trunc2) = read_capped(&b"hello"[..], CAP);
        assert_eq!(buf2, b"hello");
        assert!(!trunc2, "a sub-cap source is not truncated");
    }

    #[test]
    fn glob_walk_single_segment_and_subpath() {
        let lister = map_lister(&[
            (
                ".",
                vec![
                    ent("a.rs", false),
                    ent("b.rs", false),
                    ent("c.txt", false),
                    ent(".hidden.rs", false),
                    ent("src", true),
                ],
            ),
            ("./src", vec![ent("a.rs", false), ent("b.rs", false)]),
        ]);
        let mut allow = |_d: &Path| Ok(());
        // *.rs matches the two .rs files (sorted), hidden excluded.
        assert_eq!(
            expand_glob_walk("*.rs", None, &*lister, &mut allow, 64, 4096).unwrap(),
            vec!["a.rs", "b.rs"]
        );
        // No match → the literal pattern (nullglob off).
        assert_eq!(
            expand_glob_walk("zzz*", None, &*lister, &mut allow, 64, 4096).unwrap(),
            vec!["zzz*"]
        );
        // Sub-path keeps the directory prefix on each match.
        assert_eq!(
            expand_glob_walk("src/*.rs", None, &*lister, &mut allow, 64, 4096).unwrap(),
            vec!["src/a.rs", "src/b.rs"]
        );
    }

    #[test]
    fn glob_walk_multi_segment_and_recursive() {
        let lister = map_lister(&[
            (
                ".",
                vec![ent("a", true), ent("b", true), ent("x.rs", false)],
            ),
            ("./a", vec![ent("foo.rs", false), ent("sub", true)]),
            ("./b", vec![ent("bar.rs", false)]),
            ("./a/sub", vec![ent("deep.rs", false)]),
        ]);
        let mut allow = |_d: &Path| Ok(());
        // Multi-segment: `*/foo.rs` matches only where foo.rs exists.
        assert_eq!(
            expand_glob_walk("*/foo.rs", None, &*lister, &mut allow, 64, 4096).unwrap(),
            vec!["a/foo.rs"]
        );
        // Recursive `**`: `*.rs` at every level (cwd + all subdirs).
        assert_eq!(
            expand_glob_walk("**/*.rs", None, &*lister, &mut allow, 64, 4096).unwrap(),
            vec!["a/foo.rs", "a/sub/deep.rs", "b/bar.rs", "x.rs"]
        );
    }

    #[test]
    fn glob_walk_leashes_every_directory_and_denies_out_of_scope() {
        let lister = map_lister(&[
            (".", vec![ent("a", true), ent("x.rs", false)]),
            ("./a", vec![ent("secret.rs", false)]),
        ]);
        // A leash that refuses to read `./a` denies the whole recursive walk
        // (every directory the walk lists is fs_read-checked before listing).
        let mut deny_a = |d: &Path| {
            if d.to_string_lossy().contains("a") {
                Err(ToolError::denied("out of fs_read scope"))
            } else {
                Ok(())
            }
        };
        assert!(expand_glob_walk("**/*.rs", None, &*lister, &mut deny_a, 64, 4096).is_err());
    }

    /// #143: the total-match cap is config-driven, not a hard-coded const — a
    /// `max_matches` of 2 truncates a 4-match single-segment glob.
    #[test]
    fn glob_walk_respects_configured_match_cap() {
        let lister = map_lister(&[(
            ".",
            vec![
                ent("a.rs", false),
                ent("b.rs", false),
                ent("c.rs", false),
                ent("d.rs", false),
            ],
        )]);
        let mut allow = |_d: &Path| Ok(());
        let got = expand_glob_walk("*.rs", None, &*lister, &mut allow, 64, 2).unwrap();
        assert_eq!(got.len(), 2, "match cap of 2 must bound the result set");
    }

    /// #143: the `**` recursion-depth cap is config-driven — a `max_depth` of 1
    /// descends a single level and never reaches the deeper `sub` directory.
    #[test]
    fn glob_walk_respects_configured_depth_cap() {
        let lister = map_lister(&[
            (".", vec![ent("a", true), ent("x.rs", false)]),
            ("./a", vec![ent("foo.rs", false), ent("sub", true)]),
            ("./a/sub", vec![ent("deep.rs", false)]),
        ]);
        let mut allow = |_d: &Path| Ok(());
        // depth 1: cwd + one level of dirs; `a/sub/deep.rs` is out of reach.
        let got = expand_glob_walk("**/*.rs", None, &*lister, &mut allow, 1, 4096).unwrap();
        assert!(
            !got.iter().any(|m| m.contains("deep.rs")),
            "depth cap of 1 must not reach a/sub/deep.rs; got {got:?}"
        );
    }

    /// #143: the variable allowlist is config-driven — a name absent from the
    /// default set is expandable when configured, and a default name is denied
    /// when configured out. Proves `is_allowed_var` reads the passed allowlist.
    #[test]
    fn var_allowlist_is_config_driven() {
        // A custom var (not in the default set) is allowed when configured.
        let allow_custom = vec!["MY_CUSTOM_VAR".to_string()];
        let env = FakeEnv(HashMap::from([(
            "MY_CUSTOM_VAR".to_string(),
            "/data".to_string(),
        )]));
        let out = expand_redirect_target(&[Seg::Var("MY_CUSTOM_VAR".into())], &env, &allow_custom)
            .unwrap();
        assert_eq!(out, "/data");
        // A default-allowlisted name (HOME) is denied when configured out.
        assert!(!is_allowed_var("HOME", &["PWD".to_string()]));
        assert!(is_allowed_var("PWD", &["PWD".to_string()]));
    }

    /// #145 (I6): the egress audit sink is built from the configured path
    /// (`LimitsPolicy::audit_sink`), not a direct `BRIDLE_NET_AUDIT` env read.
    /// `None` ⇒ the null sink (no file); `Some(path)` ⇒ a JSONL sink writing to
    /// exactly that path. Would fail on the old env-only path.
    #[test]
    fn net_audit_sink_is_config_driven() {
        use crate::net_proxy::{NetAuditEvent, NetDecision, NetKind};
        let ev = NetAuditEvent {
            ts_ms: 0,
            host: "example.test".to_string(),
            port: 443,
            kind: NetKind::Connect,
            decision: NetDecision::Allowed,
            bytes_up: 1,
            bytes_down: 2,
            dur_ms: 3,
        };
        // None → null sink: records silently, no file.
        net_audit_sink(None).record(&ev);

        // Some(path) → JSONL sink appends the event to that exact path.
        let path = std::env::temp_dir().join(format!("ab-audit-{}.jsonl", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let sink = net_audit_sink(path.to_str());
        sink.record(&ev);
        drop(sink);
        let contents = std::fs::read_to_string(&path).expect("configured audit file written");
        assert!(
            contents.contains("example.test"),
            "the configured sink must write the event: {contents}"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// #138 (audit robustness): a *bad* audit path must degrade to the null sink so
    /// the run continues — a broken audit config can never break confinement. The
    /// sink records without panic and no file is created at the unopenable path.
    #[test]
    fn net_audit_sink_bad_path_degrades_to_null() {
        use crate::net_proxy::{NetAuditEvent, NetDecision, NetKind};
        let ev = NetAuditEvent {
            ts_ms: 0,
            host: "example.test".to_string(),
            port: 443,
            kind: NetKind::Http,
            decision: NetDecision::Allowed,
            bytes_up: 1,
            bytes_down: 2,
            dur_ms: 3,
        };
        // A path under a nonexistent directory can't be created → NullSink fallback.
        let bad = std::env::temp_dir()
            .join(format!("ab-nope-{}", std::process::id()))
            .join("does/not/exist/audit.jsonl");
        let sink = net_audit_sink(bad.to_str());
        sink.record(&ev); // must not panic
        assert!(
            !bad.exists(),
            "a bad audit path must not create a file (degraded to null): {bad:?}"
        );
    }
}
