//! `agent-bridle-tool-shell` — a capability-confined, brush-backed shell tool.
//!
//! brush is the carried, batteries-included shell/coreutils runtime ("the
//! hands"); this crate puts it on the [`agent_bridle_core`] leash. The tool
//! accepts **two input shapes**:
//!
//! - **argv form** (`program` + `args`) — a single named command;
//! - **free-form `cmd`** — an `sh -c`-style command string (pipelines,
//!   redirections, `&&`, globbing).
//!
//! Both are now confined *in-process* by the [`CaveatInterceptor`], which rides
//! the `CommandInterceptor` exec/open hook in our brush fork. brush 0.5 bypasses
//! `PATH` and the builtin table for any command containing a path separator
//! (DESIGN §6) — so `/bin/rm` would otherwise run even with an empty `PATH` and
//! an `exec` allow-list. The hook fires at the single external-spawn funnel
//! (catching that bypass) and at every `Shell::open_file` (redirections and
//! `source`), so free-form scripts are gateable too. This makes the confined
//! shell a **true superset** of an `sh -c` cmd-string shell, cross-OS — the
//! prerequisite for superseding an unconfined `shell_run`.
//!
//! Landlock remains the authoritative Linux backstop (recorded as
//! `sandbox_kind`); off-Linux the in-process hook is the enforcement.
//!
//! The crate compiles with the `shell` feature off — it then exposes nothing —
//! so the workspace builds under `--no-default-features`.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

#[cfg(feature = "shell")]
mod caveat_interceptor;
#[cfg(feature = "shell")]
mod shell_tool;

#[cfg(feature = "shell")]
pub use caveat_interceptor::CaveatInterceptor;
#[cfg(feature = "shell")]
pub use shell_tool::ShellTool;
