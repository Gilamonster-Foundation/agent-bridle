//! `agent-bridle-mcp` — an MCP (Model Context Protocol) stdio server over the
//! agent-bridle capability-governed tool [`registry`](agent_bridle::registry).
//!
//! MCP is the lingua franca of the agent line (DESIGN §4): any MCP client —
//! hermes-thoon's `mcp_servers:`, `claude mcp add`, newt-mcp-server's own
//! client side — can drive this process over stdio and call the **Caveats-
//! confined** Rust tools. The server speaks newline-delimited JSON-RPC 2.0 and
//! handles `initialize`, `tools/list`, `tools/call`, and `shutdown`/`exit`.
//!
//! The leash is real and configurable: the session's granted [`Caveats`] are
//! sourced from `$AGENT_BRIDLE_CAVEATS` (JSON), else
//! `~/.agent-bridle/config.toml` `[caveats]`, else a loudly-warned unconfined
//! default. Every `tools/call` is dispatched through the registry against that
//! grant, so confinement holds *through* the MCP boundary.
//!
//! Out of scope here (later increments, DESIGN §8): the Python sidecar / host
//! tools dir, web/scm tools, and per-host newt integration. This frontend
//! exposes only the compiled Rust registry tools.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod caveats_source;
mod handlers;
mod server;
#[cfg(feature = "shell")]
mod tty_approver;

use agent_bridle::registry;
use caveats_source::GrantedCaveats;
use server::McpServer;

/// Which shell policy the operator selected on the command line.
///
/// The default `shell` tool is a fail-closed stub; the two flags below opt in
/// to an UNCONFINED bash while the brush-backed confined shell is pending
/// upstream. The flags require the `shell` feature (the tool that honors them);
/// under `--no-default-features` they are accepted but inert (no shell tool).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ShellMode {
    /// Fail-closed stub (deny-only). The safe default.
    Stub,
    /// `--insecure`: UNCONFINED bash gated by per-command TTY approval.
    InsecureWithApproval,
    /// `--dangerously-allow-all`: UNCONFINED bash with NO approval gate.
    DangerousUnconfined,
}

/// Hand-parse the shell mode from `args` (no clap). Unknown flags are ignored
/// so future flags don't break older binaries; the LAST escalation flag wins.
fn parse_shell_mode<I: IntoIterator<Item = String>>(args: I) -> ShellMode {
    let mut mode = ShellMode::Stub;
    for arg in args {
        match arg.as_str() {
            "--dangerously-allow-all" => mode = ShellMode::DangerousUnconfined,
            "--insecure" => mode = ShellMode::InsecureWithApproval,
            _ => {}
        }
    }
    mode
}

/// Build the registry honoring the selected shell mode. The unconfined modes
/// require the `shell` feature; without it the stub registry is used and a
/// warning is printed (there is no shell tool to escalate).
fn build_registry(mode: ShellMode) -> agent_bridle::Registry {
    match mode {
        ShellMode::Stub => registry(),
        #[cfg(feature = "shell")]
        ShellMode::InsecureWithApproval => {
            use agent_bridle::{registry_with_shell, ShellTool};
            use std::sync::Arc;
            eprintln!(
                "WARNING: --insecure: the `shell` tool runs an UNCONFINED bash; \
                 each command requires approval on /dev/tty. This is NOT the \
                 confined brush-backed shell."
            );
            registry_with_shell(ShellTool::insecure_bash(Arc::new(
                tty_approver::TtyApprover,
            )))
        }
        #[cfg(feature = "shell")]
        ShellMode::DangerousUnconfined => {
            use agent_bridle::{registry_with_shell, ShellTool};
            eprintln!(
                "WARNING: --dangerously-allow-all: the `shell` tool runs an \
                 UNCONFINED bash with NO approval gate. Development use only."
            );
            registry_with_shell(ShellTool::dangerous_unconfined())
        }
        #[cfg(not(feature = "shell"))]
        ShellMode::InsecureWithApproval | ShellMode::DangerousUnconfined => {
            eprintln!(
                "WARNING: an unconfined shell flag was given, but this build has no \
                 `shell` feature — there is no shell tool to escalate. Ignoring."
            );
            registry()
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Source the leash. stdout is reserved for the JSON-RPC stream, so the
    // provenance banner (and any unconfined WARNING) goes to stderr.
    let granted = GrantedCaveats::load()?;
    eprintln!("{}", granted.banner());

    // Parse the shell escalation flag (no clap; hand-parsed). No flag → the
    // fail-closed stub. CRITICAL: approval is read from /dev/tty, NEVER stdin
    // (stdin is the MCP JSON-RPC stream).
    let mode = parse_shell_mode(std::env::args().skip(1));

    // Build the registry for this binary's compiled feature set and serve it
    // over stdio, confined to the granted leash.
    let server = McpServer::new(build_registry(mode), granted.caveats);
    server.run_stdio().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_flag_is_stub() {
        assert_eq!(parse_shell_mode(Vec::<String>::new()), ShellMode::Stub);
    }

    #[test]
    fn insecure_flag_parsed() {
        assert_eq!(
            parse_shell_mode(["--insecure".to_string()]),
            ShellMode::InsecureWithApproval
        );
    }

    #[test]
    fn dangerous_flag_parsed() {
        assert_eq!(
            parse_shell_mode(["--dangerously-allow-all".to_string()]),
            ShellMode::DangerousUnconfined
        );
    }

    #[test]
    fn unknown_flags_ignored_and_last_escalation_wins() {
        assert_eq!(
            parse_shell_mode([
                "--frob".to_string(),
                "--insecure".to_string(),
                "--dangerously-allow-all".to_string(),
            ]),
            ShellMode::DangerousUnconfined
        );
    }
}
