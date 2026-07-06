//! Carried-coreutils dispatch **as a library** (Track 2 Gate 2, agent-bridle#20
//! / issue #206).
//!
//! Brush's bundled `uu_*` coreutils run busybox-style: a shim builtin re-executes
//! the current process as `current_exe() --invoke-bundled <name> <args…>`, and a
//! dispatcher at the top of the binary's `main` turns that back into a call of
//! the `uu_*::uumain`. That dispatcher normally lives in the `brush-shell`
//! *binary*, so an **embedder** (whose `current_exe()` is the host binary, e.g.
//! `newt`) can't use the carried coreutils.
//!
//! This module lifts the dispatcher + shim registration into a library so any
//! embedder can make its own binary dispatch-capable with one line in `main`:
//!
//! ```no_run
//! if let Some(code) = agent_bridle_tool_shell::maybe_dispatch() {
//!     std::process::exit(code);
//! }
//! ```
//!
//! We keep the **re-exec (fork+exec)** model on purpose. "fork and call `uumain`
//! in-process" is unsafe here: agent-bridle runs under a multithreaded runtime,
//! and `fork()` without a following `exec` leaves other threads' locks
//! (allocator, …) held forever in the child — `uumain` allocates on its first
//! line and would deadlock. `execve` resets the address space, so re-exec is
//! safe *and* portable (works on Windows too).
//!
//! Cribbed from our brush fork's `brush-shell/src/bundled.rs` (same license); to
//! be upstreamed to reubeno/brush as the dispatch-as-a-library follow-up to the
//! CommandInterceptor hook (reubeno/brush#1184).

use std::collections::HashMap;
use std::ffi::OsString;
use std::io::Write;
use std::path::PathBuf;
use std::sync::OnceLock;

use brush_core::builtins::{BoxFuture, ContentOptions, ContentType, Registration};
use brush_core::commands::{self, CommandArg, ExecutionContext};
use brush_core::extensions::ShellExtensions;
use brush_core::ExecutionExitCode;

/// The leading flag that signals a bundled-command dispatch. Deliberately
/// obscure so it does not collide with real flags or script tokens.
pub const DISPATCH_FLAG: &str = "--invoke-bundled";

/// Signature of a bundled command's entry point — matches `uu_*::uumain`.
pub type BundledFn = fn(args: Vec<OsString>) -> i32;

/// Process-wide registry. Set once, read on each shim invocation + dispatch.
static REGISTRY: OnceLock<HashMap<String, BundledFn>> = OnceLock::new();

/// Cached path to the running executable.
static SELF_EXE: OnceLock<Option<PathBuf>> = OnceLock::new();

/// Install the bundled-command registry. Idempotent (first call wins).
#[allow(
    clippy::implicit_hasher,
    reason = "registry uses the default hasher; callers build with HashMap::new()"
)]
pub fn install(commands: HashMap<String, BundledFn>) {
    let _ = REGISTRY.set(commands);
}

/// Install the registry from all compiled-in providers. Call once, before
/// [`maybe_dispatch`] / [`register_shims`], so both the dispatch fast-path and
/// the shell's shim builtins see a populated registry.
pub fn install_default_providers() {
    let mut commands: HashMap<String, BundledFn> = HashMap::new();
    commands.extend(brush_coreutils_builtins::bundled_commands());
    install(commands);
}

/// Run the bundled-command fast path if the process was invoked for it.
///
/// If invoked as `<self> --invoke-bundled <NAME> [ARGS…]`, runs the registered
/// function and returns `Some(code)`; the caller exits with it. Returns `None`
/// for a normal invocation, so the embedder's usual startup proceeds. If the
/// registry was never installed (a non-dispatch-capable build), we install the
/// default providers on demand so a dispatch-capable `main` need only call this.
#[must_use]
pub fn maybe_dispatch() -> Option<i32> {
    let mut raw = std::env::args_os();
    let _argv0 = raw.next();
    let first = raw.next()?;
    if first != DISPATCH_FLAG {
        return None;
    }

    if REGISTRY.get().is_none() {
        install_default_providers();
    }

    let rest: Vec<OsString> = raw.collect();
    let Some((name, args)) = rest.split_first() else {
        eprintln!("carried-coreutils: {DISPATCH_FLAG} requires a command name");
        return Some(u8::from(ExecutionExitCode::InvalidUsage).into());
    };
    let Some(name_str) = name.to_str() else {
        eprintln!(
            "carried-coreutils: unknown bundled command: {}",
            name.to_string_lossy()
        );
        return Some(u8::from(ExecutionExitCode::NotFound).into());
    };
    let Some(func) = REGISTRY.get().and_then(|r| r.get(name_str)) else {
        eprintln!("carried-coreutils: unknown bundled command: {name_str}");
        return Some(u8::from(ExecutionExitCode::NotFound).into());
    };

    let mut argv: Vec<OsString> = Vec::with_capacity(1 + args.len());
    argv.push(name.clone());
    argv.extend(args.iter().cloned());
    Some(func(argv))
}

/// Path to the running executable (cached).
fn self_exe() -> Option<&'static PathBuf> {
    SELF_EXE
        .get_or_init(|| std::env::current_exe().ok())
        .as_ref()
}

/// Help/usage content provider for the shim builtin.
#[allow(
    clippy::needless_pass_by_value,
    clippy::unnecessary_wraps,
    reason = "signature dictated by brush_core::builtins::CommandContentFunc"
)]
fn shim_content(
    name: &str,
    content_type: ContentType,
    _options: &ContentOptions,
) -> Result<String, brush_core::Error> {
    match content_type {
        ContentType::ShortDescription => Ok(format!("{name} - carried bundled command")),
        ContentType::DetailedHelp => Ok(format!(
            "{name} - carried bundled command (runs via `<self> {DISPATCH_FLAG} {name}`)\n"
        )),
        ContentType::ShortUsage | ContentType::ManPage => Ok(String::new()),
    }
}

/// Builtin execute function shared by all shims: re-exec the running executable
/// as `<self> --invoke-bundled <name> <args>`. The path separator in the exe
/// path routes `SimpleCommand::execute` straight to the external-exec path
/// (which funnels through the `before_exec` interceptor — the leash still holds)
/// and inherits the shell's redirection state.
fn shim_execute<SE: ShellExtensions>(
    context: ExecutionContext<'_, SE>,
    args: Vec<CommandArg>,
) -> BoxFuture<'_, Result<brush_core::ExecutionResult, brush_core::Error>> {
    Box::pin(async move {
        let exe_path = if let Some(p) = self_exe() {
            p.to_string_lossy().into_owned()
        } else {
            let _ = writeln!(
                context.stderr(),
                "carried-coreutils: cannot determine path to running executable"
            );
            return Ok(ExecutionExitCode::CannotExecute.into());
        };

        let bundled_name = context.command_name.clone();
        let mut child_args: Vec<CommandArg> = Vec::with_capacity(args.len() + 2);
        child_args.push(CommandArg::String(String::new())); // argv[0], dropped
        child_args.push(CommandArg::String(DISPATCH_FLAG.into()));
        child_args.push(CommandArg::String(bundled_name.clone()));
        child_args.extend(args.into_iter().skip(1));

        let mut cmd = commands::SimpleCommand::new(
            commands::ShellForCommand::ParentShell(context.shell),
            context.params,
            exe_path,
            child_args,
        );
        cmd.use_functions = false;
        cmd.argv0 = Some(bundled_name);

        let spawn_result = cmd.execute().await?;
        let wait_result = spawn_result.wait().await?;
        Ok(wait_result.into())
    })
}

/// A [`Registration`] for the shim builtin (reused for every bundled name).
fn shim_registration<SE: ShellExtensions>() -> Registration<SE> {
    Registration {
        execute_func: shim_execute::<SE>,
        content_func: shim_content,
        disabled: false,
        special_builtin: false,
        declaration_builtin: false,
    }
}

/// Register a shim builtin for every name in the installed registry, using
/// `register_builtin_if_unset` so brush's own builtins win on conflict. Call
/// [`install_default_providers`] first.
pub fn register_shims<SE: ShellExtensions>(shell: &mut brush_core::Shell<SE>) {
    let Some(registry) = REGISTRY.get() else {
        return;
    };
    for name in registry.keys() {
        shell.register_builtin_if_unset(name.clone(), shim_registration::<SE>());
    }
}
