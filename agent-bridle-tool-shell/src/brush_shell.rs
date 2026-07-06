//! The carried **brush engine** (agent-bridle#20 / Track 2): a bash-in-Rust
//! shell run **in-process**, confined by the `CommandInterceptor` L2 leash.
//!
//! Unlike [`HostShellTool`](crate::HostShellTool) — which *refuses* a restricted
//! `exec`/`net` grant because it cannot bound a real `/bin/sh`'s forked children
//! — this engine's interceptor fires on every resolved program name and every
//! opened path *inside* brush (`before_exec` at the single external-spawn funnel,
//! `before_open` at `Shell::open_file`). So it **serves** restricted `exec`/`fs`
//! grants, in-process, on any platform, and records each denial into a shared
//! sink surfaced as structured `denials` on the envelope.
//!
//! It uses the temporary `brush-ocap-*` fork carrying the upstream hook PR
//! (reubeno/brush#1184). Enforcement is L2 (advisory `sandbox_kind = None`); an
//! L3 backstop is a follow-up. The curated builtin set removes `exec` (the one
//! builtin that spawns outside the `before_exec` funnel — a proven bypass).

use std::collections::HashMap;
use std::io::Read;
use std::sync::{Arc, LazyLock, Mutex};

use agent_bridle_core::{
    default_exec_path, Denial, Disclosure, SandboxKind, Scope, Tool, ToolContext, ToolEnvelope,
    ToolError, ToolResult,
};
use async_trait::async_trait;
use brush_builtins::{default_builtins, BuiltinSet};
use brush_core::builtins::Registration;
use brush_core::extensions::{DefaultErrorFormatter, ShellExtensionsImpl};
use brush_core::openfiles::{OpenFile, OpenFiles};
use brush_core::variables::ShellVariable;
use brush_core::{Shell, ShellFd};

use crate::caveat_interceptor::{CaveatInterceptor, DenialSink};

/// The engine identity stamped on the disclosure (ADR 0005 D2 / ADR 0019 D4).
const ENGINE_NAME: &str = "brush";
/// Default cap on captured output bytes (mirrors the other engines' default).
const DEFAULT_MAX_OUTPUT: usize = 64 * 1024;
/// Minimal, standard `PATH` used when `exec` is RESTRICTED: external commands
/// must still *resolve* so they reach the interceptor's `before_exec` gate
/// (which then denies the out-of-scope ones). Under full-access the full ambient
/// path is used instead (see [`BrushShellTool::invoke`]).
const RESTRICTED_PATH: &str = "/usr/local/bin:/usr/bin:/bin";
/// Builtins removed from the confined shell because they reach `spawn`/`exec`
/// *without* going through the interceptor funnels. The brush-fork audit found
/// exactly one: `exec` (its non-subshell branch calls `cmd.exec()` directly). A
/// confined shell needs nothing to replace into, so removing it closes a live
/// authority leak at zero cost. Every other spawn/open path funnels through a
/// hook and is intentionally kept.
const REMOVED_BUILTINS: &[&str] = &["exec"];

/// The brush [`ShellExtensions`](brush_core::extensions::ShellExtensions) carried
/// by this engine: the default error formatter plus the capability interceptor.
type LeashedExtensions = ShellExtensionsImpl<DefaultErrorFormatter, CaveatInterceptor>;

/// The engine's input schema (shared `cmd`/`env`/`cwd` contract with the other
/// engines), parsed once from the embedded data file — knowledge in data, not an
/// inline literal (three-Cs).
static DEFAULT_SCHEMA: LazyLock<Arc<serde_json::Value>> = LazyLock::new(|| {
    Arc::new(
        serde_json::from_str(include_str!("host_shell.schema.json"))
            .expect("embedded host_shell.schema.json must be valid JSON"),
    )
});

/// The carried brush engine — a [`Tool`] that runs a free-form command string
/// through an in-process bash-in-Rust shell confined by the `CommandInterceptor`
/// leash. Registered under `"shell"` (the ADR 0005 D2 seam), a peer of
/// [`ShellTool`](crate::ShellTool) / [`HostShellTool`](crate::HostShellTool).
#[derive(Clone)]
pub struct BrushShellTool {
    max_output: usize,
    schema: Arc<serde_json::Value>,
}

impl std::fmt::Debug for BrushShellTool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BrushShellTool").finish_non_exhaustive()
    }
}

impl Default for BrushShellTool {
    fn default() -> Self {
        Self::new()
    }
}

impl BrushShellTool {
    /// The engine with default output cap and the embedded schema.
    #[must_use]
    pub fn new() -> Self {
        Self {
            max_output: DEFAULT_MAX_OUTPUT,
            schema: DEFAULT_SCHEMA.clone(),
        }
    }

    /// Override the tool's input schema (three-Cs: Configuration).
    #[must_use]
    pub fn with_schema(mut self, schema: serde_json::Value) -> Self {
        self.schema = Arc::new(schema);
        self
    }

    fn disclosure(&self) -> Disclosure {
        Disclosure {
            engine: Some(ENGINE_NAME.to_string()),
            ..Disclosure::default()
        }
    }
}

#[async_trait]
impl Tool for BrushShellTool {
    fn name(&self) -> &str {
        "shell"
    }

    fn schema(&self) -> serde_json::Value {
        (*self.schema).clone()
    }

    async fn invoke(
        &self,
        args: serde_json::Value,
        cx: &ToolContext,
    ) -> ToolResult<serde_json::Value> {
        let cmd = args
            .get("cmd")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| ToolError::denied("brush: missing required `cmd` string"))?
            .to_string();
        let cwd = args
            .get("cwd")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string);

        // PATH parity: the FULL ambient path when `exec` is unrestricted (so the
        // agent's own tools — `~/.cargo/bin`, `/opt/homebrew/bin`, … — resolve
        // like a host shell); a minimal standard path when `exec` is RESTRICTED,
        // so externals still resolve to reach the `before_exec` gate that denies
        // the out-of-scope ones. The host env is never inherited otherwise.
        let path_value = if matches!(cx.caveats().exec, Scope::All) {
            default_exec_path()
        } else {
            RESTRICTED_PATH.to_string()
        };

        let sink: DenialSink = Arc::new(Mutex::new(Vec::new()));
        let interceptor = CaveatInterceptor::new(cx.clone(), Arc::clone(&sink));
        let max_output = self.max_output;

        // brush's shell API is async and blocks on a per-invocation current-thread
        // runtime; run it off the async runtime on a blocking worker.
        let captured = tokio::task::spawn_blocking(move || {
            run_in_brush(cmd, cwd, path_value, interceptor, max_output)
        })
        .await
        .map_err(|e| ToolError::Exec(std::io::Error::other(format!("join: {e}"))))??;

        // Any denial the interceptor recorded lifts the envelope to `denied:true`.
        let denials: Vec<Denial> = sink.lock().map(|g| g.clone()).unwrap_or_default();

        Ok(ToolEnvelope::new(SandboxKind::None)
            .with_disclosure(self.disclosure())
            .with_exit_code(captured.exit_code)
            .with_stdout(captured.stdout)
            .with_stderr(captured.stderr)
            .with_timed_out(false)
            .with_denials(denials)
            .into_json())
    }
}

/// What a finished brush run produced.
struct Captured {
    exit_code: i32,
    stdout: String,
    stderr: String,
}

/// Drive a brush shell to completion for one command, capturing stdout/stderr
/// via real OS pipes (an `Arc<Mutex<Vec<u8>>>` will not satisfy brush's fd
/// `Stream`; pipes are mandatory). The shell is built with the supplied
/// [`CaveatInterceptor`] so exec/open are confined in-process. IO must be enabled
/// on the runtime (not just time): `$(...)` sets up real pipes via tokio's IO
/// driver, and with IO enabled the inner program hits the `before_exec` funnel
/// (a legible recorded denial) rather than panicking.
fn run_in_brush(
    cmd: String,
    cwd: Option<String>,
    path_value: String,
    interceptor: CaveatInterceptor,
    max_output: usize,
) -> ToolResult<Captured> {
    let (out_reader, out_writer) =
        std::io::pipe().map_err(|e| ToolError::Exec(brush_io("create stdout pipe", &e)))?;
    let (err_reader, err_writer) =
        std::io::pipe().map_err(|e| ToolError::Exec(brush_io("create stderr pipe", &e)))?;

    // Drain the read ends on background threads so a chatty command cannot
    // deadlock by filling the pipe buffer before the shell exits.
    let out_handle = std::thread::spawn(move || drain(out_reader, max_output));
    let err_handle = std::thread::spawn(move || drain(err_reader, max_output));

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| ToolError::Exec(brush_io("build shell runtime", &e)))?;

    let working_dir = cwd.map(std::path::PathBuf::from);

    let exit_code = rt.block_on(async move {
        let mut fds: HashMap<ShellFd, OpenFile> = HashMap::new();
        fds.insert(OpenFiles::STDOUT_FD, OpenFile::from(out_writer));
        fds.insert(OpenFiles::STDERR_FD, OpenFile::from(err_writer));

        let mut shell: Shell<LeashedExtensions> =
            Shell::builder_with_extensions::<LeashedExtensions>()
                .command_interceptor(interceptor)
                .builtins(confined_builtins())
                .do_not_inherit_env(true)
                .no_editing(true)
                .interactive(false)
                .fds(fds)
                .maybe_working_dir(working_dir)
                .build()
                .await
                .map_err(|e| ToolError::Exec(brush_io("build shell", &e)))?;

        shell
            .env_mut()
            .set_global("PATH", ShellVariable::new(path_value))
            .map_err(|e| ToolError::Exec(brush_io("seed PATH", &e)))?;

        let result = shell
            .run_dash_c_command(cmd)
            .await
            .map_err(|e| ToolError::Exec(brush_io("run command", &e)))?;

        // Drop the shell so it releases its clones of the pipe writers; only then
        // do the reader threads see EOF.
        drop(shell);

        Ok::<i32, ToolError>(i32::from(u8::from(result.exit_code)))
    })?;

    let stdout = out_handle
        .join()
        .map_err(|_| ToolError::denied("stdout reader thread panicked"))??;
    let stderr = err_handle
        .join()
        .map_err(|_| ToolError::denied("stderr reader thread panicked"))??;

    Ok(Captured {
        exit_code,
        stdout,
        stderr,
    })
}

/// The curated builtin set: the bash-mode default set with [`REMOVED_BUILTINS`]
/// stripped out (robust-by-construction — a removed builtin is simply gone, so a
/// confined shell running `exec` gets "command not found", never a spawn).
fn confined_builtins() -> HashMap<String, Registration<LeashedExtensions>> {
    let mut builtins = default_builtins::<LeashedExtensions>(BuiltinSet::BashMode);
    for name in REMOVED_BUILTINS {
        builtins.remove(*name);
    }
    builtins
}

/// Read a pipe to EOF (capped at `max` bytes), returning lossy UTF-8.
fn drain(mut reader: std::io::PipeReader, max: usize) -> ToolResult<String> {
    let mut buf = Vec::new();
    reader
        .read_to_end(&mut buf)
        .map_err(|e| ToolError::Exec(brush_io("drain pipe", &e)))?;
    if buf.len() > max {
        buf.truncate(max);
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// Wrap a brush/IO error with context as an [`std::io::Error`].
fn brush_io(ctx: &str, e: &impl std::fmt::Display) -> std::io::Error {
    std::io::Error::other(format!("{ctx}: {e}"))
}
