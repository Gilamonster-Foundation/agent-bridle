//! `agent-bridle-tool-shell` — capability-confined shell tool (argv + safe-subset engine).
//!
//! Per **ADR 0005** the object-capability *boundary* is L3 (kernel) and this
//! crate is the L2 *convenience* engine: `agent-bridle` is the **exec funnel**,
//! parsing each request itself ([`crate::parse`]) and running only what it can
//! confine. [`ShellTool`] accepts either argv form (`program` + `args`) or a
//! free-form `cmd` string, checks the `exec`/`fs` leash, spawns the program
//! directly, and **refuses the dynamic constructs by design** (`$(...)`,
//! backticks, subshells — the undecidable interiors of ADR 0001). Until an L3
//! backstop is active (deferred — agent-bridle#35), a run is honestly
//! *advisory*: the result's `sandbox_kind` reports what actually enforced it
//! (I9), today [`agent_bridle_core::SandboxKind::None`].
//!
//! **Increments 1–4** of agent-bridle#34: a sequence of pipelines joined by
//! `&&`/`||`/`;` (short-circuit semantics), each pipeline simple commands with
//! quoted arguments and **file redirections** (`> out`, `>> out`, `< in`) whose
//! targets are leash-checked (`fs_write`/`fs_read`). Globbing and fd-number
//! redirections are added incrementally; until then they are refused as
//! *unsupported* (distinct from the *dynamic* constructs refused by design). The
//! process spawning is behind a `Spawner` seam (mocked in unit tests; real path
//! in `tests/real_spawn.rs`). `brush-bridle-core` remains the deferred, reversible
//! full-bash alternative engine behind the same registry seam (ADR 0005 D4 —
//! tracked on agent-bridle#20).

#![forbid(unsafe_code)]
#![warn(missing_docs)]

#[cfg(feature = "shell")]
mod parse;
#[cfg(feature = "shell")]
mod shell_tool;

#[cfg(feature = "shell")]
pub use shell_tool::ShellTool;
