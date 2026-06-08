//! `agent-bridle-tool-shell` — capability-confined shell tool (stub release).
//!
//! The full brush-backed implementation with `CommandInterceptor` exec/open
//! interception is temporarily disabled pending the upstream PR that adds the
//! hook to `reubeno/brush`:
//!
//!   <https://github.com/reubeno/brush/pull/1184>
//!
//! In this stub release, [`ShellTool`] registers in the tool registry and
//! advertises its complete JSON schema, but [`Tool::invoke`] returns a
//! structured error explaining the situation. No functionality is silently
//! missing — the error message links to the tracking issue.
//!
//! **Restoring full support:** once the upstream PR merges and brush ships a
//! crates.io release containing `CommandInterceptor`, restore from git history:
//!
//! ```text
//! git show <pre-stub-commit>:agent-bridle-tool-shell/src/shell_tool.rs
//! git show <pre-stub-commit>:agent-bridle-tool-shell/src/caveat_interceptor.rs
//! ```
//!
//! Then add brush back to `Cargo.toml` (see commented lines there) and publish
//! a new agent-bridle version. See the tracking issue for the full checklist:
//! <https://github.com/Gilamonster-Foundation/agent-bridle/issues/20>

#![forbid(unsafe_code)]
#![warn(missing_docs)]

#[cfg(feature = "shell")]
mod shell_tool;

#[cfg(feature = "shell")]
pub use shell_tool::ShellTool;
