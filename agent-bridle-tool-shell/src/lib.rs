//! `agent-bridle-tool-shell` — the agent-bridle `shell` tool.
//!
//! # Fail-closed stub (current state)
//!
//! The published `shell` tool is a **fail-closed stub**: by default it spawns
//! NOTHING and returns a denial. The real, capability-confined, brush-backed
//! shell — which rode a `CommandInterceptor` exec/open hook in our brush fork
//! to confine commands *in-process*, cross-OS — depended on a **git** source
//! for brush, and crates.io forbids any git dependency in a published manifest.
//! To unblock `cargo publish` for the whole agent-bridle → newt line, the brush
//! deps and the confined implementation were removed; the confined impl is
//! preserved in git history at this commit and returns when the brush hook is
//! upstreamed into `reubeno/brush` (see the workspace `CHANGELOG`).
//!
//! # The escalation ladder
//!
//! A consumer that needs to actually run commands *now* opts in explicitly,
//! trading confinement for function — there is no confined middle ground until
//! brush lands:
//!
//! - [`ShellTool::stub`] (= [`ShellTool::new`], the [`Default`]) — **Denied**.
//!   The safe published default; never spawns anything.
//! - [`ShellTool::insecure_bash`] — runs an **UNCONFINED** `bash -lc <command>`
//!   (falling back to `sh -c`) but only after an [`ApprovalHook`] approves each
//!   command. Reported honestly as `sandbox_kind = none`.
//! - [`ShellTool::dangerous_unconfined`] — runs an **UNCONFINED** bash with NO
//!   approval gate. For development only.
//!
//! The host (`agent-bridle-mcp`) wires these to `--insecure` (per-command TTY
//! approval) and `--dangerously-allow-all`; with no flag it uses the stub.
//!
//! The tool accepts **two input shapes** (unchanged from the confined design,
//! so the schema is stable): **argv form** (`program` + `args`) and a
//! **free-form `cmd`** string. The argv form is sh-quoted into one command
//! line; both paths build a single shell command string.
//!
//! The crate compiles with the `shell` feature off — it then exposes nothing —
//! so the workspace builds under `--no-default-features`.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

#[cfg(feature = "shell")]
mod shell_tool;

#[cfg(feature = "shell")]
pub use shell_tool::{ApprovalHook, ShellPolicy, ShellTool};
