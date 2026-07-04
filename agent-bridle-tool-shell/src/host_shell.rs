//! The **sandboxed-host shell engine** (ADR 0019, #194): full-shell semantics
//! with the guarantee entirely on L3.
//!
//! Unlike the safe-subset [`ShellTool`](crate::ShellTool), this engine does
//! **no L2 parsing**. It spawns the OS shell (`/bin/sh -c <cmd>`, or an
//! embedder-configured shell) with the whole process tree inside the L3 jail via
//! [`ConfinedCommand`], which admission-checks `exec`, **fails closed** when a
//! restricted `fs_write` cannot be enforced, applies Landlock (Linux) / Seatbelt
//! (macOS), and reports the honest [`SandboxKind`]. The engine contributes zero
//! enforcement; the jail is everything.
//!
//! Honesty posture (ADR 0019 D2): it serves *fs restricted (kernel-jailed),
//! exec/net unrestricted*. A restricted `exec` or `net` grant is **refused** with
//! a structured "engine unavailable for this grant" denial — inside a full shell
//! the engine cannot bound the shell's forked children (a single `check_exec` on
//! `/bin/sh` says nothing about what it runs), so claiming to confine them would
//! be a lie (I9). Restricted-exec/net requests belong on the safe-subset engine.

use std::collections::BTreeMap;
use std::process::Stdio;
use std::sync::Arc;

use agent_bridle_core::{
    Caveats, ConfinedCommand, Denial, DenialKind, Disclosure, SandboxKind, SandboxPolicy, Scope,
    Tool, ToolContext, ToolEnvelope, ToolError, ToolResult,
};
use async_trait::async_trait;

/// The engine identity stamped on the disclosure (ADR 0019 D4).
const ENGINE_NAME: &str = "sandbox-host";

/// Default cap on captured output bytes (mirrors the safe-subset engine's
/// [`LimitsPolicy`](agent_bridle_core::LimitsPolicy) default; kept local so the
/// engine has no extra config surface for the MVP).
const DEFAULT_MAX_OUTPUT: usize = 64 * 1024;

/// The sandboxed-host shell engine — a [`Tool`] that runs a free-form command
/// through the OS shell inside the L3 jail (ADR 0019). Registered under
/// `"shell"` so it is a construction-time engine choice (the embedder builds the
/// registry with this instead of [`ShellTool`](crate::ShellTool)); the two honor
/// the same `Tool` / `Caveats` / envelope contract.
#[derive(Clone)]
pub struct HostShellTool {
    shell: String,
    max_output: usize,
    sandbox: Arc<SandboxPolicy>,
}

impl std::fmt::Debug for HostShellTool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostShellTool")
            .field("shell", &self.shell)
            .finish_non_exhaustive()
    }
}

impl Default for HostShellTool {
    fn default() -> Self {
        Self::new()
    }
}

impl HostShellTool {
    /// The engine with the default shell (`/bin/sh`) and built-in sandbox policy.
    #[must_use]
    pub fn new() -> Self {
        Self {
            shell: "/bin/sh".to_string(),
            max_output: DEFAULT_MAX_OUTPUT,
            sandbox: Arc::new(SandboxPolicy::default()),
        }
    }

    /// Set the shell binary the engine spawns (embedder-configured, ADR 0019
    /// D5.3 — never a per-dispatch model input). Default `/bin/sh`.
    #[must_use]
    pub fn with_shell(mut self, shell: impl Into<String>) -> Self {
        self.shell = shell.into();
        self
    }

    /// Set the sandbox mechanism policy the L3 backend enforces.
    #[must_use]
    pub fn sandbox_policy(mut self, policy: Arc<SandboxPolicy>) -> Self {
        self.sandbox = policy;
        self
    }

    /// A structured "engine unavailable for this grant" denial (ADR 0019 D5.2) —
    /// `denied: true`, so a consumer can adapt (reshape, or select the
    /// safe-subset engine), never a silent fallback.
    fn engine_unavailable(&self, kind: DenialKind, axis: &str) -> serde_json::Value {
        ToolEnvelope::new(SandboxKind::None)
            .with_disclosure(self.disclosure())
            .with_denials(vec![Denial {
                kind,
                target: format!("sandbox-host engine ({axis} restricted)"),
                reason: format!(
                    "the sandbox-host engine does not serve a restricted `{axis}` grant: \
                     inside a full shell it cannot bound the shell's forked children, so it \
                     refuses rather than claim confinement it does not have (ADR 0019 D2). \
                     Use the safe-subset engine for a restricted `{axis}` grant."
                ),
            }])
            .into_json()
    }

    fn disclosure(&self) -> Disclosure {
        Disclosure {
            engine: Some(ENGINE_NAME.to_string()),
            ..Disclosure::default()
        }
    }
}

/// Is a scope restricted (an allow-list), i.e. NOT the ambient `All`? A
/// restricted `exec`/`net` is the case the sandbox-host engine cannot honestly
/// serve (ADR 0019 D2).
fn is_restricted<T: Ord + Clone>(scope: &Scope<T>) -> bool {
    !matches!(scope, Scope::All)
}

#[async_trait]
impl Tool for HostShellTool {
    fn name(&self) -> &str {
        "shell"
    }

    fn schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "cmd": {
                    "type": "string",
                    "description": "A command line run by the OS shell (`/bin/sh -c`) with the \
                                    whole process tree inside the kernel filesystem jail. Full \
                                    shell semantics — pipes, `$(...)`, loops — are allowed \
                                    because the kernel, not a parser, bounds their filesystem \
                                    reach. Requires exec+net to be unrestricted (else refused)."
                },
                "env": {
                    "type": "object",
                    "additionalProperties": { "type": "string" },
                    "description": "Environment for the child (no ambient inheritance)."
                },
                "cwd": { "type": "string", "description": "Working directory (within fs_read)." }
            },
            "required": ["cmd"]
        })
    }

    async fn invoke(
        &self,
        args: serde_json::Value,
        cx: &ToolContext,
    ) -> ToolResult<serde_json::Value> {
        let cmd = args
            .get("cmd")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| ToolError::denied("sandbox-host: missing required `cmd` string"))?
            .to_string();

        // ADR 0019 D2 — honesty. The engine only serves fs-restricted; a
        // restricted exec/net grant is refused (the shell forks children this
        // engine cannot bound). fs restriction is handled by ConfinedCommand's
        // fail-closed spawn below.
        let caveats: &Caveats = cx.caveats();
        if is_restricted(&caveats.exec) {
            return Ok(self.engine_unavailable(DenialKind::Exec, "exec"));
        }
        if is_restricted(&caveats.net) {
            return Ok(self.engine_unavailable(DenialKind::Net, "net"));
        }

        let env: BTreeMap<String, String> = args
            .get("env")
            .and_then(serde_json::Value::as_object)
            .map(|m| {
                m.iter()
                    .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                    .collect()
            })
            .unwrap_or_default();
        let cwd = args.get("cwd").and_then(serde_json::Value::as_str);
        let max_output = self.max_output;

        // Build the confined spawn: `/bin/sh -c <cmd>`, empty env + granted vars,
        // piped output. ConfinedCommand admission-checks exec (the shell binary,
        // permitted under exec=All), fail-closes on unenforceable fs, applies the
        // OS jail, and reports the honest kind.
        let mut command = ConfinedCommand::new(&self.shell)
            .arg("-c")
            .arg(&cmd)
            .sandbox_policy(Arc::clone(&self.sandbox))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (k, v) in &env {
            command = command.env(k, v);
        }
        if let Some(dir) = cwd {
            command = command.current_dir(dir);
        }

        // The spawn + blocking wait runs off the async runtime. `spawn` itself
        // enforces the fail-closed fs check and applies the jail on the spawn
        // thread, so the child inherits confinement.
        let confined = command.spawn(cx)?;
        let sandbox_kind = confined.sandbox_kind;
        let child = confined.child;

        let output = tokio::task::spawn_blocking(move || child.wait_with_output())
            .await
            .map_err(|e| ToolError::Exec(std::io::Error::other(format!("join: {e}"))))?
            .map_err(ToolError::Exec)?;

        let stdout = cap_utf8(&output.stdout, max_output);
        let stderr = cap_utf8(&output.stderr, max_output);
        Ok(ToolEnvelope::new(sandbox_kind)
            .with_disclosure(self.disclosure())
            .with_exit_code(output.status.code().unwrap_or(-1))
            .with_stdout(stdout)
            .with_stderr(stderr)
            .with_timed_out(false)
            .into_json())
    }
}

/// Lossy-decode captured bytes and cap at `max` bytes (on a char boundary).
fn cap_utf8(bytes: &[u8], max: usize) -> String {
    let s = String::from_utf8_lossy(bytes);
    if s.len() <= max {
        return s.into_owned();
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…[truncated]", &s[..end])
}
