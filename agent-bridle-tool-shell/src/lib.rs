//! `agent-bridle-tool-shell` — capability-confined shell tool (argv + safe-subset engine).
//!
//! Per **ADR 0005** the object-capability *boundary* is L3 (kernel) and this
//! crate is the L2 *convenience* engine: `agent-bridle` is the **exec funnel**,
//! parsing each request itself ([`crate::parse`]) and running only what it can
//! confine. [`ShellTool`] accepts either argv form (`program` + `args`) or a
//! free-form `cmd` string, checks the `exec`/`fs` leash, spawns the program
//! directly, and **refuses the dynamic constructs by design** (`$(...)`,
//! backticks, subshells — the undecidable interiors of ADR 0001). The L3
//! backstop is wired (agent-bridle#35): when it will actually confine the run —
//! today the Landlock `fs_write` axis on a capable Linux build with `fs_write`
//! restricted — children spawn inside a kernel-enforced ruleset and
//! `sandbox_kind` reports [`agent_bridle_core::SandboxKind::Landlock`]; else the
//! run is honestly *advisory* with [`agent_bridle_core::SandboxKind::None`]
//! (I9, never overclaiming). Read/exec/net axes + macOS/Windows backends are
//! follow-ups (ADR 0006).
//!
//! The engine (agent-bridle#34 Track A + #45): a sequence of pipelines joined by
//! `&&`/`||`/`;` (short-circuit semantics), each pipeline simple commands with
//! quoted arguments, **redirections** (`> out`, `>> out`, `< in`, `2> err`,
//! `2>&1`), **filename globbing** (`*`/`?`/`[…]`) and **allowlisted `$VAR`
//! expansion** — every filesystem/env touch bridle performs (redirect opens,
//! glob directory listings, variable allowlist) is leash-/policy-checked before
//! any spawn. The dynamic constructs (`$(…)`, backticks, subshells) stay refused
//! by design. The process spawning is behind a `Spawner` seam (mocked in unit
//! tests; real path in `tests/real_spawn.rs`). `brush-bridle-core` remains the
//! deferred, reversible
//! full-bash alternative engine behind the same registry seam (ADR 0005 D4 —
//! tracked on agent-bridle#20).

#![forbid(unsafe_code)]
#![warn(missing_docs)]

#[cfg(feature = "brush")]
mod brush_shell;
#[cfg(feature = "brush")]
mod brush_worker;
#[cfg(feature = "brush")]
mod caveat_interceptor;
#[cfg(feature = "carried-coreutils")]
mod coreutils_dispatch;
#[cfg(feature = "host-shell")]
mod host_shell;
// #257: the loopback egress proxy moved to agent-bridle-core (shared with
// `ConfinedCommand::spawn_tokio` and external no-subprocess callers). This
// alias keeps every `crate::net_proxy::…` path — and the audit re-exports
// below — resolving unchanged, now to the single core implementation.
#[cfg(feature = "shell")]
pub(crate) use agent_bridle_core::net_proxy;
mod output_observer;
#[cfg(feature = "shell")]
mod parse;
#[cfg(feature = "shell")]
mod shell_tool;

pub use output_observer::{ShellInvocationId, ShellOutputObserver, ShellOutputStream};
#[cfg(feature = "shell")]
pub use shell_tool::ShellTool;

/// The sandboxed-host engine (ADR 0019 / #194): full-shell semantics with the
/// guarantee entirely on L3. Opt-in via the `host-shell` feature; a
/// construction-time alternative to [`ShellTool`] behind the ADR 0005 D2 seam.
#[cfg(feature = "host-shell")]
pub use host_shell::HostShellTool;

/// The carried **brush** engine (agent-bridle#20 / Track 2): a bash-in-Rust
/// shell run in a dedicated sandboxed worker. Its `CommandInterceptor` provides
/// the L2 leash while the worker and descendants inherit the available L3
/// boundary. Opt-in via the `brush` feature; a construction-time alternative to
/// [`ShellTool`] behind the ADR 0005 D2 seam, using the temporary `brush-ocap-*`
/// fork (reubeno/brush#1184).
#[cfg(feature = "brush")]
pub use brush_shell::BrushShellTool;

/// Carried-coreutils dispatch (agent-bridle#20 / issue #206). An embedder's
/// binary calls [`maybe_dispatch`] at the top of `main` to become
/// dispatch-capable, so the brush engine's carried `ls`/`cat`/… shims (which
/// re-exec `<self> --invoke-bundled <name>`) resolve in-process against the host
/// binary — carried coreutils with no host tools. [`register_shims`] /
/// [`install_default_providers`] are used by the engine internally.
#[cfg(feature = "carried-coreutils")]
pub use coreutils_dispatch::{install_default_providers, maybe_dispatch, register_shims};

/// Network egress audit surface (#124, ADR 0016): the loopback proxy records
/// every proxy-visible connection as a [`NetAuditEvent`] through an [`AuditSink`]
/// (default off; enable via the `BRIDLE_NET_AUDIT` setting). The `bridle-netmon`
/// binary renders the JSON-lines stream as a live monitor.
#[cfg(feature = "shell")]
pub use net_proxy::{AuditSink, JsonlSink, NetAuditEvent, NetDecision, NetKind, NullSink};
