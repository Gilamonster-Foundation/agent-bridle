//! [`ShellTool`] — the confined shell, **argv + safe-subset engine** (ADR 0005).
//!
//! Per ADR 0005, the object-capability *boundary* is L3 (kernel) and this engine
//! is the L2 *convenience*: `agent-bridle` is the exec funnel — it parses the
//! request itself (see [`crate::parse`]), checks the `exec`/`fs` leash, spawns
//! the program(s) directly, and **refuses the dynamic constructs by design**.
//! When an L3 backstop will actually confine the run — today the Landlock
//! `fs_write` axis on a capable Linux build (`linux-landlock`), with `fs_write`
//! restricted — the children spawn inside a kernel-enforced ruleset applied on a
//! dedicated thread, and `sandbox_kind` reports [`SandboxKind::Landlock`]; this
//! blocks a *permitted* program's own out-of-scope writes, which L2 cannot see
//! once it has spawned. Otherwise the run is honestly *advisory* and
//! `sandbox_kind` is [`SandboxKind::None`] — never overclaiming (I9). The
//! `fs_read`/`exec`/`net` axes (#31) and the macOS/Windows backends (#50/#51)
//! are follow-ups; see ADR 0006 for the per-OS backend design.
//!
//! The engine (agent-bridle#34 Track A + #45): a sequence of pipelines joined by
//! `&&`/`||`/`;`, each pipeline simple commands with quoted arguments,
//! redirections (`> out`, `>> out`, `< in`, `2> err`, `2>&1`), filename globbing
//! (`*`/`?`/`[…]`), and **allowlisted `$VAR` expansion**. Because `agent-bridle`
//! performs each redirect's open and each glob's directory listing itself, those
//! filesystem touches are leash-checked (`fs_write`/`fs_read`) *before any stage
//! spawns*; a `$VAR` is expanded only if its name is on a small secret-free
//! allowlist ([`VAR_ALLOWLIST`]), checked before any spawn — a real enforcement
//! point, unlike a spawned program's own opens (L3's job). `2>&1` uses a shared
//! `std::io::pipe()` writer cloned into both stdout and stderr. Process spawning
//! is behind a [`Spawner`] seam (mocked in unit tests; real path in
//! `tests/real_spawn.rs`).

use std::io::{PipeReader, PipeWriter, Read};
use std::path::{Path, PathBuf};
use std::process::{Child, Stdio};
use std::sync::Arc;
use std::time::Duration;

use agent_bridle_core::{
    best_available_sandbox, enforcement_report, Caveats, Denial, DenialKind, EnforcementReport,
    SandboxKind, Scope, Tool, ToolContext, ToolEnvelope, ToolError, ToolResult,
};
use async_trait::async_trait;

use crate::parse::{
    classify, Arg, Command, Redirect, Refusal, Script, ScriptItem, Seg, Sep, StderrTo,
};

/// Maximum permitted (and default-clamped) wall-clock timeout.
const MAX_TIMEOUT_SECS: u64 = 300;
/// Default timeout when the caller does not specify one.
const DEFAULT_TIMEOUT_SECS: u64 = 60;
/// Cap on captured stdout/stderr returned in the envelope (bytes), so a chatty
/// command cannot return unbounded output. Streaming caps are a follow-up; the
/// timeout bounds runaway producers in the meantime.
const MAX_OUTPUT_BYTES: usize = 1 << 20; // 1 MiB

/// What a finished pipeline produced (the last stage's exit code; concatenated
/// output). The unit of the [`Spawner`] seam.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Captured {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

/// The pipeline-execution seam.
///
/// The real implementation ([`OsSpawner`]) spawns processes (and expands globs
/// against the real filesystem); tests inject a mock so the parse + leash +
/// sequencing logic is verified without real subprocesses (the workspace norm:
/// no real process/fs in unit tests). A `Spawner` only ever receives a pipeline
/// that already passed the `exec` **and** `fs` (redirect + glob-dir) leash —
/// admission happens in [`ShellTool::invoke`] *before* the spawner runs.
pub(crate) trait Spawner: Send + Sync {
    /// Run one leash-approved pipeline to completion, capturing its output. The
    /// effective `caveats` are passed so the real spawner can apply the L3 OS
    /// sandbox (Landlock) before spawning; the mock ignores them.
    fn run(&self, stages: &[Command], cwd: Option<&str>, caveats: &Caveats)
        -> ToolResult<Captured>;
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
    ) -> ToolResult<Captured> {
        // When an OS sandbox (Landlock) will actually confine this run, apply it
        // on a dedicated thread before spawning (ADR 0005 L3 / ADR 0006 D4).
        // Otherwise run directly — no need to spend a thread.
        if intended_sandbox_kind(caveats) == SandboxKind::None {
            run_pipeline(stages, cwd)
        } else {
            run_confined(stages, cwd, caveats)
        }
    }
}

/// The L3 `SandboxKind` that will actually be enforced for these caveats in this
/// build, on this kernel — the value reported in the result envelope (I9 / ADR
/// 0006 D3). [`best_available_sandbox`] already accounts for OS, feature, and
/// kernel capability; we additionally report `None` when `fs_write` is
/// unrestricted, because the current Landlock ruleset (the `fs_write` axis) then
/// governs nothing — never overclaim.
fn intended_sandbox_kind(caveats: &Caveats) -> SandboxKind {
    match best_available_sandbox().kind() {
        SandboxKind::Landlock if matches!(caveats.fs_write, Scope::Only(_)) => {
            SandboxKind::Landlock
        }
        _ => SandboxKind::None,
    }
}

/// Run the pipeline on a dedicated thread that first applies the OS sandbox.
///
/// `restrict_self` is per-thread, irreversible, and inherited across `fork`/
/// `execve`, so it must run on a throwaway thread (never the shared blocking
/// pool) immediately before spawning the children. `apply` is fail-closed (ADR
/// 0006 D4): if the kernel does not enforce the ruleset, the run errors rather
/// than proceeding unconfined.
fn run_confined(stages: &[Command], cwd: Option<&str>, caveats: &Caveats) -> ToolResult<Captured> {
    let stages = stages.to_vec();
    let cwd = cwd.map(str::to_string);
    let caveats = caveats.clone();
    std::thread::Builder::new()
        .name("agent-bridle-confined".to_string())
        .spawn(move || {
            best_available_sandbox().apply(&caveats)?;
            run_pipeline(&stages, cwd.as_deref())
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
}

impl std::fmt::Debug for ShellTool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ShellTool")
    }
}

impl ShellTool {
    /// Construct the tool with the real OS spawner.
    #[must_use]
    pub fn new() -> Self {
        Self {
            spawner: Arc::new(OsSpawner),
        }
    }

    /// Construct with an injected spawner (tests only).
    #[cfg(test)]
    fn with_spawner(spawner: Arc<dyn Spawner>) -> Self {
        Self { spawner }
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
                "timeout_secs": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": MAX_TIMEOUT_SECS,
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
        let parsed = ShellArgs::parse(&args)?;
        // Honest reporting (ADR 0005 D1 / I9 / ADR 0006 D3): report the L3 kind
        // that will actually be enforced for these caveats on this kernel —
        // Landlock when `fs_write` is restricted on a capable Linux build, else
        // None (advisory). `OsSpawner` applies exactly this, fail-closed.
        let sandbox_kind = intended_sandbox_kind(cx.caveats());
        // Axis-granular honesty (ADR 0004 D1 / #30): every envelope this run
        // returns carries the per-axis report alongside the coarse sandbox_kind.
        let enforcement = enforcement_report(cx.caveats(), sandbox_kind);

        // Resolve to a script (sequence of pipelines), or surface a refusal.
        let script = match parsed.script() {
            Ok(s) => s,
            Err(refusal) => return Ok(refused_envelope(sandbox_kind, enforcement, &refusal)),
        };

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
                    None => {} // the parser guarantees a non-empty stage
                }
                for arg in &stage.argv {
                    match arg {
                        // A glob lists a directory: that fs_read is leash-checked.
                        Arg::Glob(pattern) => {
                            let dir =
                                resolve_glob_dir(parsed.cwd.as_deref(), split_glob(pattern).0);
                            if let Err(e) = cx.check_path_read(&dir) {
                                return Ok(deny(
                                    sandbox_kind,
                                    enforcement,
                                    DenialKind::Open,
                                    &dir.to_string_lossy(),
                                    &e,
                                ));
                            }
                        }
                        // Every variable referenced must be on the env allowlist
                        // (no secret leak), checked by name before any spawn.
                        Arg::Var(segs) => {
                            for seg in segs {
                                if let Seg::Var(name) = seg {
                                    if !is_allowed_var(name) {
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
                        Arg::Lit(_) => {}
                    }
                }
                for redirect in &stage.redirects {
                    let (path, checked) = match redirect {
                        Redirect::Stdout { path, .. } | Redirect::Stderr { path, .. } => {
                            (path, cx.check_path_write(Path::new(path)))
                        }
                        Redirect::Stdin { path } => (path, cx.check_path_read(Path::new(path))),
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

        // Run on a blocking thread, bounded by the timeout. On timeout the
        // blocking task is detached and a timeout envelope is returned.
        let spawner = Arc::clone(&self.spawner);
        let cwd = parsed.cwd.clone();
        let timeout = parsed.timeout;
        let caveats = cx.caveats().clone();
        let run = tokio::task::spawn_blocking(move || {
            run_script(&*spawner, &script, cwd.as_deref(), &caveats)
        });
        match tokio::time::timeout(timeout, run).await {
            Ok(joined) => {
                let captured = joined
                    .map_err(|e| ToolError::Other(anyhow::anyhow!("shell task panicked: {e}")))??;
                Ok(ToolEnvelope::new(sandbox_kind)
                    .with_enforcement(enforcement)
                    .with_exit_code(captured.exit_code)
                    .with_stdout(captured.stdout)
                    .with_stderr(captured.stderr)
                    .with_timed_out(false)
                    .into_json())
            }
            Err(_elapsed) => Ok(ToolEnvelope::new(sandbox_kind)
                .with_enforcement(enforcement)
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
) -> ToolResult<Captured> {
    let mut stdout = String::new();
    let mut stderr = String::new();
    let mut status: i32 = 0;

    for item in script {
        let run_it = match item.sep {
            Sep::Seq => true,
            Sep::And => status == 0,
            Sep::Or => status != 0,
        };
        if run_it {
            let captured = spawner.run(&item.pipeline, cwd, caveats)?;
            stdout.push_str(&captured.stdout);
            stderr.push_str(&captured.stderr);
            status = captured.exit_code;
        }
    }

    Ok(Captured {
        exit_code: status,
        stdout: cap_string(stdout),
        stderr: cap_string(stderr),
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
        .with_denials(vec![Denial {
            kind,
            target: target.to_string(),
            reason: err.to_string(),
        }])
        .into_json()
}

/// Build a structured `denied` envelope for a parser [`Refusal`].
fn refused_envelope(
    sandbox_kind: SandboxKind,
    enforcement: EnforcementReport,
    refusal: &Refusal,
) -> serde_json::Value {
    ToolEnvelope::new(sandbox_kind)
        .with_enforcement(enforcement)
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
    timeout: Duration,
}

impl ShellArgs {
    fn parse(v: &serde_json::Value) -> ToolResult<Self> {
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
        let timeout_secs = obj
            .get("timeout_secs")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(DEFAULT_TIMEOUT_SECS)
            .clamp(1, MAX_TIMEOUT_SECS);

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
const VAR_ALLOWLIST: &[&str] = &[
    "HOME", "PWD", "OLDPWD", "USER", "LOGNAME", "TMPDIR", "LANG", "LC_ALL", "SHELL", "HOSTNAME",
    "TERM",
];

/// Whether `name` may be expanded from the environment.
fn is_allowed_var(name: &str) -> bool {
    VAR_ALLOWLIST.contains(&name)
}

// ── glob expansion ──────────────────────────────────────────────────────────

/// Split a glob pattern into (directory prefix incl. trailing `/`, basename
/// pattern). `*.rs` → `("", "*.rs")`; `src/*.rs` → `("src/", "*.rs")`.
fn split_glob(pattern: &str) -> (&str, &str) {
    match pattern.rfind('/') {
        Some(i) => (&pattern[..=i], &pattern[i + 1..]),
        None => ("", pattern),
    }
}

/// The directory a glob lists, resolved against the command's `cwd`.
fn resolve_glob_dir(cwd: Option<&str>, dir_part: &str) -> PathBuf {
    let base = || cwd.map_or_else(|| PathBuf::from("."), PathBuf::from);
    if dir_part.is_empty() {
        base()
    } else if Path::new(dir_part).is_absolute() {
        PathBuf::from(dir_part)
    } else {
        base().join(dir_part)
    }
}

/// Expand a glob pattern against a directory listing (the `list_dir` seam lets
/// unit tests avoid the real filesystem). Only the last path segment is globbed;
/// hidden entries are skipped unless the pattern's basename starts with `.`.
/// No match → the literal pattern (bash `nullglob` off).
fn expand_glob(
    pattern: &str,
    cwd: Option<&str>,
    list_dir: &dyn Fn(&Path) -> Vec<String>,
) -> Vec<String> {
    let (dir_part, base) = split_glob(pattern);
    let dir = resolve_glob_dir(cwd, dir_part);
    let base_hidden = base.starts_with('.');
    let mut matches: Vec<String> = list_dir(&dir)
        .into_iter()
        .filter(|name| (base_hidden || !name.starts_with('.')) && fnmatch(base, name))
        .map(|name| format!("{dir_part}{name}"))
        .collect();
    matches.sort();
    if matches.is_empty() {
        vec![pattern.to_string()]
    } else {
        matches
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
fn expand_stage_argv(stage: &Command, cwd: Option<&str>) -> Vec<String> {
    let list_dir = |dir: &Path| -> Vec<String> {
        std::fs::read_dir(dir)
            .map(|rd| {
                rd.filter_map(|e| e.ok().and_then(|e| e.file_name().into_string().ok()))
                    .collect()
            })
            .unwrap_or_default()
    };
    let mut argv = Vec::with_capacity(stage.argv.len());
    for arg in &stage.argv {
        match arg {
            Arg::Lit(s) => argv.push(s.clone()),
            Arg::Glob(pattern) => argv.extend(expand_glob(pattern, cwd, &list_dir)),
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
fn run_pipeline(stages: &[Command], cwd: Option<&str>) -> ToolResult<Captured> {
    debug_assert!(!stages.is_empty(), "the parser guarantees ≥1 stage");
    let n = stages.len();
    let last = n - 1;

    let mut children: Vec<Child> = Vec::with_capacity(n);
    // The read end feeding the NEXT stage's stdin (from the prior stage's stdout).
    let mut prev_stdin: Option<PipeReader> = None;
    // The read end capturing final stdout (last stage, when not redirected).
    let mut stdout_capture: Option<PipeReader> = None;
    // Reader threads for stages whose stderr is captured separately.
    let mut stderr_threads: Vec<std::thread::JoinHandle<Vec<u8>>> = Vec::new();

    for (i, stage) in stages.iter().enumerate() {
        let is_last = i == last;
        let argv = expand_stage_argv(stage, cwd);
        let mut cmd = std::process::Command::new(&argv[0]);
        cmd.args(&argv[1..]);
        if let Some(dir) = cwd {
            cmd.current_dir(dir);
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
            let mut err = child.stderr.take().expect("stderr is piped");
            stderr_threads.push(std::thread::spawn(move || {
                let mut buf = Vec::new();
                let _ = err.read_to_end(&mut buf);
                buf
            }));
        }
        children.push(child);
    }

    // The parent now holds no pipe writers, so a captured reader sees EOF once
    // the child(ren) exit. Drain stdout concurrently with waiting.
    let stdout_thread = stdout_capture.map(|mut reader| {
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = reader.read_to_end(&mut buf);
            buf
        })
    });

    // Wait all stages; the pipeline's exit code is the last stage's.
    let mut exit_code = -1;
    for (i, child) in children.iter_mut().enumerate() {
        let status = child.wait().map_err(ToolError::Exec)?;
        if i == last {
            exit_code = status.code().unwrap_or(-1);
        }
    }

    let stdout = stdout_thread.map_or_else(Vec::new, |h| h.join().unwrap_or_default());
    let mut stderr = Vec::new();
    for h in stderr_threads {
        stderr.extend(h.join().unwrap_or_default());
    }

    Ok(Captured {
        exit_code,
        stdout: capped_utf8(&stdout),
        stderr: capped_utf8(&stderr),
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

/// Lossy-decode at most [`MAX_OUTPUT_BYTES`] of captured output. Truncation at a
/// byte boundary is safe: [`String::from_utf8_lossy`] replaces any partial
/// trailing sequence rather than panicking.
fn capped_utf8(bytes: &[u8]) -> String {
    let slice = &bytes[..bytes.len().min(MAX_OUTPUT_BYTES)];
    String::from_utf8_lossy(slice).into_owned()
}

/// Cap an already-decoded string to [`MAX_OUTPUT_BYTES`] at a char boundary
/// (used for the concatenated output of a multi-pipeline script).
fn cap_string(mut s: String) -> String {
    if s.len() > MAX_OUTPUT_BYTES {
        let mut end = MAX_OUTPUT_BYTES;
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
        exit_by_program: HashMap<String, i32>,
        block_ms: u64,
    }

    impl MockSpawner {
        fn with_exit(program: &str, code: i32) -> Self {
            let mut m = Self::default();
            m.exit_by_program.insert(program.to_string(), code);
            m
        }
    }

    /// A stage's program word (argv[0]) for test assertions. (A variable in the
    /// program position is denied in `invoke`, so it never reaches the spawner.)
    fn prog(stage: &Command) -> &str {
        match stage.argv.first() {
            Some(Arg::Lit(s) | Arg::Glob(s)) => s,
            Some(Arg::Var(_)) | None => "",
        }
    }

    impl Spawner for MockSpawner {
        fn run(
            &self,
            stages: &[Command],
            _cwd: Option<&str>,
            _caveats: &Caveats,
        ) -> ToolResult<Captured> {
            self.calls.lock().unwrap().push(stages.to_vec());
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
            })
        }
    }

    fn ctx(granted: Caveats) -> ToolContext {
        Gate::new(0)
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

    fn ran_programs(mock: &Arc<MockSpawner>) -> Vec<String> {
        calls(mock)
            .iter()
            .map(|pipeline| prog(&pipeline[0]).to_string())
            .collect()
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

    /// A glob arg reaches the spawner as an (unexpanded) `Glob` — expansion is
    /// the spawner's job; the leash (fs_read on the listed dir) passed in invoke.
    #[tokio::test]
    async fn glob_arg_reaches_spawner_after_leash() {
        let mock = Arc::new(MockSpawner::default());
        ShellTool::with_spawner(mock.clone())
            .invoke(
                serde_json::json!({"cmd": "ls *.rs"}), // fs_read is All by default
                &ctx(exec_only(&["ls"])),
            )
            .await
            .expect("invoke");
        let c = calls(&mock);
        assert_eq!(
            c[0][0].argv,
            vec![Arg::Lit("ls".into()), Arg::Glob("*.rs".into())]
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

    #[test]
    fn expand_glob_with_a_fake_lister() {
        let entries = || {
            vec![
                "a.rs".to_string(),
                "b.rs".to_string(),
                "c.txt".to_string(),
                ".hidden.rs".to_string(),
            ]
        };
        let lister = |_dir: &Path| entries();

        // *.rs matches the two .rs files (sorted), hidden excluded.
        assert_eq!(expand_glob("*.rs", None, &lister), vec!["a.rs", "b.rs"]);
        // * excludes the dotfile.
        assert_eq!(
            expand_glob("*", None, &lister),
            vec!["a.rs", "b.rs", "c.txt"]
        );
        // No match → the literal pattern (nullglob off).
        assert_eq!(expand_glob("zzz*", None, &lister), vec!["zzz*"]);
        // Sub-path keeps the directory prefix on each match.
        assert_eq!(
            expand_glob("src/*.rs", None, &lister),
            vec!["src/a.rs", "src/b.rs"]
        );
    }
}
