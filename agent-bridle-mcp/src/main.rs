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

use agent_bridle::registry;
use caveats_source::GrantedCaveats;
use server::McpServer;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Source the leash. stdout is reserved for the JSON-RPC stream, so the
    // provenance banner (and any unconfined WARNING) goes to stderr.
    let granted = GrantedCaveats::load()?;
    eprintln!("{}", granted.banner());

    // Unbridle (ADR 0018): the loader verified the two-key ack, so flip the core
    // process marker BEFORE any tool runs. This drops the L3 mechanism (native
    // execution) while the configured grant + step-up still gate; every result
    // discloses `unbridled`. Never reached without the acked `Unbridled` source.
    if granted.is_unbridled() {
        agent_bridle::set_unbridled();
        // The human-gate posture (ADR 0018 D10/D11): Autonomous (no human gate)
        // only when the distinct second ack was supplied; otherwise Supervised-free
        // keeps the passkey gate. Disclosed on every envelope (R5).
        agent_bridle::set_human_gate(if granted.is_autonomous() {
            agent_bridle::HumanGate::None
        } else {
            agent_bridle::HumanGate::Passkey
        });
    }

    // Build the registry for this binary's compiled feature set (shell on by
    // default) and serve it over stdio, confined to the granted leash.
    let server = McpServer::new(registry(), granted.caveats);
    server.run_stdio().await
}
