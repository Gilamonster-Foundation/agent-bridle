//! The [`ShellTool`] — a fail-closed stub with an opt-in unconfined-bash ladder.
//!
//! RESTORE (brush-backed confined shell): the previous contents of this file
//! were the capability-confined, brush-backed shell — it built a brush `Shell`
//! with a `CaveatInterceptor` riding our brush fork's `CommandInterceptor`
//! exec/open hook (git https://github.com/hartsock/brush, rev
//! f0ef7715a02f44c670e7f5d5e59d1c7721ea282c; audit notes also reference rev
//! 4e65a06). That impl is preserved in git history at this commit. Removed here
//! to unblock `cargo publish` (crates.io forbids git deps). When the hook is
//! upstreamed into `reubeno/brush`, restore the brush-backed `ShellTool` and the
//! `caveat_interceptor` module. See the workspace `CHANGELOG` `[Unreleased]`.

use std::io::Read;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use agent_bridle_core::{SandboxKind, Tool, ToolContext, ToolEnvelope, ToolError, ToolResult};
use async_trait::async_trait;

/// Maximum permitted timeout, in seconds. Requests above this are clamped.
const MAX_TIMEOUT_SECS: u64 = 300;
/// Default timeout when the caller does not specify one.
const DEFAULT_TIMEOUT_SECS: u64 = 30;

/// A host-supplied gate that approves (or refuses) one command before it runs.
///
/// Implemented by the host (e.g. `agent-bridle-mcp`'s TTY approver). It is
/// consulted only by [`ShellPolicy::InsecureBashWithApproval`]. The contract is
/// fail-closed: a hook that cannot decide should return `false`.
pub trait ApprovalHook: Send + Sync {
    /// Approve the exact command line about to be run by an UNCONFINED bash.
    /// Returning `false` denies it and nothing is spawned.
    fn approve(&self, command: &str) -> bool;
}

/// How a [`ShellTool`] behaves when invoked.
///
/// The published default is [`ShellPolicy::Denied`]. The two unconfined variants
/// are explicit opt-ins (the host wires them to `--insecure` /
/// `--dangerously-allow-all`) and run an UNCONFINED bash — honest
/// `sandbox_kind = none`, no confinement, until the brush-backed shell returns.
#[derive(Clone)]
pub enum ShellPolicy {
    /// Fail closed: every invocation is denied; nothing is ever spawned.
    Denied,
    /// Run an UNCONFINED bash, but only after the [`ApprovalHook`] approves the
    /// command. A refusal denies the call and spawns nothing.
    InsecureBashWithApproval(Arc<dyn ApprovalHook>),
    /// Run an UNCONFINED bash with NO approval gate. Development only.
    DangerousUnconfined,
}

impl std::fmt::Debug for ShellPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Denied => write!(f, "Denied"),
            Self::InsecureBashWithApproval(_) => write!(f, "InsecureBashWithApproval(<hook>)"),
            Self::DangerousUnconfined => write!(f, "DangerousUnconfined"),
        }
    }
}

/// The agent-bridle `shell` tool.
///
/// See the [crate docs](crate) for the escalation ladder. The published default
/// ([`ShellTool::stub`] / [`ShellTool::new`] / [`Default`]) denies everything;
/// [`ShellTool::insecure_bash`] and [`ShellTool::dangerous_unconfined`] run an
/// UNCONFINED bash and are explicit opt-ins.
#[derive(Debug, Clone)]
pub struct ShellTool {
    policy: ShellPolicy,
}

impl ShellTool {
    /// The fail-closed stub: every invocation is denied, nothing is spawned.
    /// This is the safe published default.
    #[must_use]
    pub fn stub() -> Self {
        Self {
            policy: ShellPolicy::Denied,
        }
    }

    /// Alias for [`ShellTool::stub`] — the safe default constructor.
    #[must_use]
    pub fn new() -> Self {
        Self::stub()
    }

    /// An UNCONFINED bash gated by a per-command [`ApprovalHook`]. Opt-in only.
    #[must_use]
    pub fn insecure_bash(hook: Arc<dyn ApprovalHook>) -> Self {
        Self {
            policy: ShellPolicy::InsecureBashWithApproval(hook),
        }
    }

    /// An UNCONFINED bash with NO approval gate. Development only; opt-in only.
    #[must_use]
    pub fn dangerous_unconfined() -> Self {
        Self {
            policy: ShellPolicy::DangerousUnconfined,
        }
    }
}

impl Default for ShellTool {
    fn default() -> Self {
        Self::stub()
    }
}

/// Parsed, validated arguments for one shell invocation.
#[derive(Debug)]
struct ShellArgs {
    /// The fully-formed command line handed to the runner.
    command: String,
    cwd: Option<String>,
    timeout: Duration,
}

impl ShellArgs {
    fn parse(args: &serde_json::Value) -> ToolResult<Self> {
        let has_program = args.get("program").is_some();
        let has_cmd = args.get("cmd").is_some();

        let cwd = args
            .get("cwd")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string);

        let timeout_secs = args
            .get("timeout_secs")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(DEFAULT_TIMEOUT_SECS)
            .min(MAX_TIMEOUT_SECS);
        let timeout = Duration::from_secs(timeout_secs);

        match (has_program, has_cmd) {
            (true, true) => Err(ToolError::denied(
                "provide either `program` (argv form) or `cmd` (free-form), not both",
            )),
            (false, false) => Err(ToolError::denied(
                "missing required field: one of `program` (argv form) or `cmd` (free-form)",
            )),
            (true, false) => Self::parse_argv(args, cwd, timeout),
            (false, true) => Self::parse_freeform(args, cwd, timeout),
        }
    }

    /// Argv form: `program` (string) + optional `args` (array of strings). The
    /// tokens are sh-quoted into one command line so they pass literally — no
    /// word-splitting, no expansion.
    fn parse_argv(
        args: &serde_json::Value,
        cwd: Option<String>,
        timeout: Duration,
    ) -> ToolResult<Self> {
        let program = args
            .get("program")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| ToolError::denied("`program` must be a string"))?
            .to_string();

        let arg_list = match args.get("args") {
            None | Some(serde_json::Value::Null) => Vec::new(),
            Some(serde_json::Value::Array(a)) => a
                .iter()
                .map(|v| {
                    v.as_str()
                        .map(str::to_string)
                        .ok_or_else(|| ToolError::denied("`args` must be an array of strings"))
                })
                .collect::<ToolResult<Vec<_>>>()?,
            Some(_) => return Err(ToolError::denied("`args` must be an array of strings")),
        };

        let mut command = sh_quote(&program);
        for a in &arg_list {
            command.push(' ');
            command.push_str(&sh_quote(a));
        }

        Ok(Self {
            command,
            cwd,
            timeout,
        })
    }

    /// Free-form: `cmd` (string), run `sh -c`-style. The string is the script.
    fn parse_freeform(
        args: &serde_json::Value,
        cwd: Option<String>,
        timeout: Duration,
    ) -> ToolResult<Self> {
        let command = args
            .get("cmd")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| ToolError::denied("`cmd` must be a string"))?
            .to_string();

        Ok(Self {
            command,
            cwd,
            timeout,
        })
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
                        Mutually exclusive with `cmd`."
                },
                "args": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "Argv form: arguments passed to `program` (argv[1..])."
                },
                "cmd": {
                    "type": "string",
                    "description": "Free-form: an sh -c-style command string \
                        (pipelines, redirections, &&, globbing). Mutually \
                        exclusive with `program`."
                },
                "cwd": {
                    "type": "string",
                    "description": "Working directory for the command."
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
        _cx: &ToolContext,
    ) -> ToolResult<serde_json::Value> {
        // Parse/validate FIRST so a malformed call is rejected uniformly across
        // every policy (and never reaches a spawn). The leash context is unused
        // here: the stub denies regardless, and the unconfined paths are honest
        // about NOT confining (sandbox_kind = none) — the brush-backed confined
        // shell is what consulted `cx.check_exec`, and it returns upstream.
        let parsed = ShellArgs::parse(&args)?;

        match &self.policy {
            // Fail closed. Never spawn anything.
            ShellPolicy::Denied => Err(ToolError::denied(
                "shell unavailable in this build: the confined brush-backed shell is pending \
                 upstream; run the host with --insecure (per-command approval) or \
                 --dangerously-allow-all to use an UNCONFINED bash",
            )),
            // UNCONFINED bash, gated by the approval hook.
            ShellPolicy::InsecureBashWithApproval(hook) => {
                if !hook.approve(&parsed.command) {
                    return Err(ToolError::denied("operator declined the command"));
                }
                run_unconfined_bash(parsed)
            }
            // UNCONFINED bash, no gate.
            ShellPolicy::DangerousUnconfined => run_unconfined_bash(parsed),
        }
    }
}

/// Single-quote a shell token, escaping embedded single quotes the POSIX way
/// (`'` → `'\''`). Guarantees the token is passed literally.
fn sh_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for ch in s.chars() {
        if ch == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

/// Run an UNCONFINED `bash -lc <command>` (falling back to `sh -c` if bash is
/// not on `PATH`), capturing stdout/stderr, bounded by a wall-clock timeout.
///
/// UNCONFINED on purpose: this is the opt-in escalation while the brush-backed
/// confined shell is stubbed out. The envelope reports `sandbox_kind = none`
/// honestly and records NO denials (there is no leash here).
fn run_unconfined_bash(parsed: ShellArgs) -> ToolResult<serde_json::Value> {
    let ShellArgs {
        command,
        cwd,
        timeout,
    } = parsed;

    // Prefer bash (login shell so a dev's profile applies); fall back to sh.
    let (shell, login_flag): (&str, &[&str]) = if which_on_path("bash").is_some() {
        ("bash", &["-l", "-c"])
    } else {
        ("sh", &["-c"])
    };

    let mut cmd = Command::new(shell);
    cmd.args(login_flag)
        .arg(&command)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(dir) = &cwd {
        cmd.current_dir(dir);
    }

    let mut child = cmd
        .spawn()
        .map_err(|e| ToolError::Exec(io_ctx("spawn unconfined bash", e)))?;

    // Drain stdout/stderr on their own threads so a chatty command cannot
    // deadlock by filling a pipe buffer before it exits.
    let out_pipe = child.stdout.take();
    let err_pipe = child.stderr.take();
    let out_handle = std::thread::spawn(move || drain_opt(out_pipe));
    let err_handle = std::thread::spawn(move || drain_opt(err_pipe));

    // Hand-rolled wait-with-timeout: poll `try_wait` on a short interval until
    // the child exits or the wall-clock bound elapses. No new deps.
    let (status, timed_out) = match wait_with_timeout(&mut child, timeout) {
        Some(status) => (Some(status), false),
        None => {
            // Bound hit: kill the child and reap it so its pipe writers close
            // and the drain threads see EOF.
            let _ = child.kill();
            let _ = child.wait();
            (None, true)
        }
    };

    let stdout = out_handle
        .join()
        .map_err(|_| ToolError::Other(anyhow::anyhow!("stdout reader thread panicked")))??;
    let stderr = err_handle
        .join()
        .map_err(|_| ToolError::Other(anyhow::anyhow!("stderr reader thread panicked")))??;

    // UNCONFINED — honest sandbox_kind, no denials recorded.
    let mut envelope = ToolEnvelope::new(SandboxKind::None)
        .with_timed_out(timed_out)
        .with_stdout(stdout);

    if timed_out {
        envelope = envelope.with_stderr(format!(
            "{stderr}command timed out after {}s",
            timeout.as_secs()
        ));
    } else {
        envelope = envelope.with_stderr(stderr);
        if let Some(code) = status.and_then(|s| s.code()) {
            envelope = envelope.with_exit_code(code);
        }
    }

    Ok(envelope.into_json())
}

/// Poll a child for up to `timeout`, returning its [`ExitStatus`] if it exits in
/// time, or `None` if the bound elapses first. A counter-free wall-clock bound
/// (a timeout, not a coordination primitive).
///
/// [`ExitStatus`]: std::process::ExitStatus
fn wait_with_timeout(
    child: &mut std::process::Child,
    timeout: Duration,
) -> Option<std::process::ExitStatus> {
    let deadline = Instant::now() + timeout;
    let poll = Duration::from_millis(10);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status),
            Ok(None) => {
                if Instant::now() >= deadline {
                    return None;
                }
                std::thread::sleep(poll.min(deadline.saturating_duration_since(Instant::now())));
            }
            // A wait error means we cannot reap it; treat as "still running" so
            // the caller's timeout path kills it. Avoid a busy spin.
            Err(_) => {
                if Instant::now() >= deadline {
                    return None;
                }
                std::thread::sleep(poll);
            }
        }
    }
}

/// Read an optional pipe to EOF, returning its bytes as a lossy UTF-8 string.
/// A `None` pipe (capture not set up) yields an empty string.
fn drain_opt<R: Read>(reader: Option<R>) -> ToolResult<String> {
    let Some(mut reader) = reader else {
        return Ok(String::new());
    };
    let mut buf = Vec::new();
    reader
        .read_to_end(&mut buf)
        .map_err(|e| ToolError::Exec(io_ctx("drain pipe", e)))?;
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// Locate an executable by bare name on the process `PATH`. Used only to choose
/// bash vs sh for the unconfined runner.
fn which_on_path(name: &str) -> Option<std::path::PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path).find_map(|dir| {
        let p = dir.join(name);
        p.is_file().then_some(p)
    })
}

/// Wrap a context string around an io::Error.
fn io_ctx(ctx: &str, e: std::io::Error) -> std::io::Error {
    std::io::Error::new(e.kind(), format!("{ctx}: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_bridle_core::{Caveats, CountBound, Gate, Scope};

    /// Mint a context for the shell tool through the gate, the only legitimate
    /// way. Even the stub goes through the gate so the leash-mint path stays
    /// exercised.
    fn authorize(tool: &ShellTool, granted: &Caveats) -> ToolResult<ToolContext> {
        Gate::new(0).authorize(tool, granted)
    }

    fn echo_grant() -> Caveats {
        Caveats {
            exec: Scope::only(["echo".to_string()]),
            max_calls: CountBound::AtMost(8),
            ..Caveats::top()
        }
    }

    /// Test-only unique-name disambiguator (a counter, never a clock).
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    /// Build a unique scratch marker path under the temp dir (counter, not a
    /// clock), pre-removed so a stale file can't mask a failure.
    fn fresh_marker(tag: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!(
            "ab-shell-{tag}-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let _ = std::fs::remove_file(&p);
        p
    }

    /// An approval hook that returns a fixed answer and records whether it was
    /// asked — so a test can prove `approve` is (or is not) consulted.
    struct FixedApprover {
        answer: bool,
        asked: Arc<std::sync::atomic::AtomicBool>,
    }
    impl ApprovalHook for FixedApprover {
        fn approve(&self, _command: &str) -> bool {
            self.asked.store(true, std::sync::atomic::Ordering::Relaxed);
            self.answer
        }
    }

    // ── The fail-closed stub ────────────────────────────────────────────────

    #[tokio::test]
    async fn stub_denies_and_never_spawns() {
        // The published default: Denied. A `touch MARKER` command must be
        // refused AND prove nothing ran — the marker must not appear.
        let marker = fresh_marker("stub-nospawn");
        let tool = ShellTool::stub();
        let cx = authorize(&tool, &echo_grant()).unwrap();
        let cmd = format!("touch {}", marker.display());
        let err = tool
            .invoke(serde_json::json!({ "cmd": cmd }), &cx)
            .await
            .unwrap_err();
        assert!(matches!(err, ToolError::Denied { .. }), "got {err:?}");
        assert!(
            !marker.exists(),
            "the stub must NOT spawn anything: marker was created"
        );
    }

    #[tokio::test]
    async fn new_is_an_alias_for_stub() {
        // `new()` and `Default` are both the safe stub.
        let cx = authorize(&ShellTool::new(), &echo_grant()).unwrap();
        let err = ShellTool::new()
            .invoke(serde_json::json!({ "cmd": "echo hi" }), &cx)
            .await
            .unwrap_err();
        assert!(matches!(err, ToolError::Denied { .. }), "got {err:?}");
        assert!(matches!(ShellTool::default().policy, ShellPolicy::Denied));
    }

    // ── --insecure: per-command approval over an UNCONFINED bash ─────────────

    #[tokio::test]
    async fn insecure_bash_runs_when_approved() {
        let asked = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let hook = Arc::new(FixedApprover {
            answer: true,
            asked: Arc::clone(&asked),
        });
        let tool = ShellTool::insecure_bash(hook);
        let cx = authorize(&tool, &echo_grant()).unwrap();
        let out = tool
            .invoke(serde_json::json!({ "cmd": "echo hi" }), &cx)
            .await
            .expect("invoke");
        assert!(
            asked.load(std::sync::atomic::Ordering::Relaxed),
            "the approval hook must have been consulted"
        );
        assert_eq!(out["exit_code"], 0, "echo must exit 0: {out:?}");
        assert!(
            out["stdout"].as_str().unwrap().contains("hi"),
            "stdout was {:?}",
            out["stdout"]
        );
        // UNCONFINED is reported honestly.
        assert_eq!(out["sandbox_kind"], "none");
        assert_eq!(out["timed_out"], false);
    }

    #[tokio::test]
    async fn insecure_bash_denied_when_not_approved() {
        // Hook refuses → Err(Denied) and NOTHING spawns (marker absent).
        let marker = fresh_marker("insecure-declined");
        let asked = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let hook = Arc::new(FixedApprover {
            answer: false,
            asked: Arc::clone(&asked),
        });
        let tool = ShellTool::insecure_bash(hook);
        let cx = authorize(&tool, &echo_grant()).unwrap();
        let cmd = format!("touch {}", marker.display());
        let err = tool
            .invoke(serde_json::json!({ "cmd": cmd }), &cx)
            .await
            .unwrap_err();
        assert!(
            asked.load(std::sync::atomic::Ordering::Relaxed),
            "the approval hook must have been consulted"
        );
        assert!(matches!(err, ToolError::Denied { .. }), "got {err:?}");
        assert!(
            !marker.exists(),
            "a declined command must NOT spawn: marker was created"
        );
    }

    #[tokio::test]
    async fn insecure_bash_argv_form_runs_when_approved() {
        // Argv form is sh-quoted into the command line and runs the same way.
        let hook = Arc::new(FixedApprover {
            answer: true,
            asked: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        });
        let tool = ShellTool::insecure_bash(hook);
        let cx = authorize(&tool, &echo_grant()).unwrap();
        let out = tool
            .invoke(
                serde_json::json!({ "program": "echo", "args": ["argv-hi"] }),
                &cx,
            )
            .await
            .expect("invoke");
        assert_eq!(out["exit_code"], 0);
        assert!(out["stdout"].as_str().unwrap().contains("argv-hi"));
    }

    // ── --dangerously-allow-all: UNCONFINED bash, no gate ────────────────────

    #[tokio::test]
    async fn dangerous_unconfined_runs_without_hook() {
        let tool = ShellTool::dangerous_unconfined();
        let cx = authorize(&tool, &echo_grant()).unwrap();
        let out = tool
            .invoke(serde_json::json!({ "cmd": "echo dangerous" }), &cx)
            .await
            .expect("invoke");
        assert_eq!(out["exit_code"], 0, "{out:?}");
        assert!(out["stdout"].as_str().unwrap().contains("dangerous"));
        assert_eq!(out["sandbox_kind"], "none");
    }

    #[tokio::test]
    async fn unconfined_nonzero_exit_is_reported() {
        let tool = ShellTool::dangerous_unconfined();
        let cx = authorize(&tool, &echo_grant()).unwrap();
        let out = tool
            .invoke(serde_json::json!({ "cmd": "exit 3" }), &cx)
            .await
            .expect("invoke");
        assert_eq!(out["exit_code"], 3, "{out:?}");
        // No leash here, so never flagged denied.
        assert!(out.get("denied").is_none(), "{out:?}");
    }

    #[tokio::test]
    async fn unconfined_times_out() {
        let tool = ShellTool::dangerous_unconfined();
        let cx = authorize(&tool, &echo_grant()).unwrap();
        let out = tool
            .invoke(
                serde_json::json!({ "cmd": "sleep 30", "timeout_secs": 1 }),
                &cx,
            )
            .await
            .expect("invoke");
        assert_eq!(out["timed_out"], true, "{out:?}");
        assert!(
            out["stderr"].as_str().unwrap().contains("timed out"),
            "{out:?}"
        );
    }

    // ── ShellArgs::parse (unchanged logic, kept under test) ──────────────────

    #[test]
    fn schema_has_both_argv_and_freeform() {
        let s = ShellTool::stub().schema();
        assert_eq!(s["properties"]["program"]["type"], "string");
        assert_eq!(s["properties"]["cmd"]["type"], "string");
        // Neither is `required` — exactly one must be supplied (validated at
        // parse time), and they are mutually exclusive.
        assert!(s.get("required").is_none());
    }

    #[test]
    fn parse_argv_quotes_each_token() {
        let parsed = ShellArgs::parse(&serde_json::json!({
            "program": "echo",
            "args": ["a b", "it's"]
        }))
        .expect("parse");
        // Each token single-quoted; the embedded quote escaped the POSIX way.
        assert_eq!(parsed.command, "'echo' 'a b' 'it'\\''s'");
    }

    #[test]
    fn parse_freeform_passes_cmd_through() {
        let parsed =
            ShellArgs::parse(&serde_json::json!({ "cmd": "echo hi | cat" })).expect("parse");
        assert_eq!(parsed.command, "echo hi | cat");
    }

    #[test]
    fn parse_both_program_and_cmd_is_mutually_exclusive() {
        let err = ShellArgs::parse(&serde_json::json!({
            "program": "echo",
            "cmd": "echo hi"
        }))
        .unwrap_err();
        assert!(matches!(err, ToolError::Denied { .. }), "got {err:?}");
    }

    #[test]
    fn parse_neither_program_nor_cmd_is_rejected() {
        let err = ShellArgs::parse(&serde_json::json!({ "args": ["x"] })).unwrap_err();
        assert!(matches!(err, ToolError::Denied { .. }), "got {err:?}");
    }

    #[test]
    fn parse_args_must_be_strings() {
        let err = ShellArgs::parse(&serde_json::json!({
            "program": "echo",
            "args": [1, 2]
        }))
        .unwrap_err();
        assert!(matches!(err, ToolError::Denied { .. }), "got {err:?}");
    }

    #[test]
    fn parse_clamps_timeout_to_max() {
        let parsed = ShellArgs::parse(&serde_json::json!({
            "cmd": "true",
            "timeout_secs": 100_000
        }))
        .expect("parse");
        assert_eq!(parsed.timeout, Duration::from_secs(MAX_TIMEOUT_SECS));
    }

    #[test]
    fn parse_defaults_timeout_when_absent() {
        let parsed = ShellArgs::parse(&serde_json::json!({ "cmd": "true" })).expect("parse");
        assert_eq!(parsed.timeout, Duration::from_secs(DEFAULT_TIMEOUT_SECS));
    }

    /// A malformed call is rejected at parse time under EVERY policy, before any
    /// spawn — proven here on the unconfined policy (which would otherwise run).
    #[tokio::test]
    async fn malformed_args_rejected_even_under_unconfined() {
        let tool = ShellTool::dangerous_unconfined();
        let cx = authorize(&tool, &echo_grant()).unwrap();
        let err = tool
            .invoke(
                serde_json::json!({ "program": "echo", "cmd": "echo hi" }),
                &cx,
            )
            .await
            .unwrap_err();
        assert!(matches!(err, ToolError::Denied { .. }), "got {err:?}");
    }
}
