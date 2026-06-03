//! `agent-bridle-tool-shell` — a capability-confined, brush-backed shell tool.
//!
//! brush is the carried, batteries-included shell/coreutils runtime ("the
//! hands"); this crate puts it on the [`agent_bridle_core`] leash. The tool
//! takes an **argv form** (`program` + `args`), not a free-form `sh -c` string,
//! so the invoked command is *known* and therefore gateable: brush 0.5 bypasses
//! PATH and the builtin table for any command containing a path separator
//! (DESIGN §6), which makes free-form scripts ungateable in-process until the
//! Track-B brush exec/open hook lands. The free-form `cmd` superset is deferred
//! to that hook.
//!
//! The crate compiles with the `shell` feature off — it then exposes nothing —
//! so the workspace builds under `--no-default-features`.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

#[cfg(feature = "shell")]
mod shell_tool;

#[cfg(feature = "shell")]
pub use shell_tool::ShellTool;
