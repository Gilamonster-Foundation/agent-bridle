//! `agent-bridle-tool-shell` — capability-confined safe-subset, Brush, and host-shell engines.
//!
//! Per **ADR 0005** the object-capability *boundary* is L3 (kernel) and this
//! crate supplies complementary L2 engines. The lean [`ShellTool`] is an
//! **exec funnel**: it parses each request itself ([`crate::parse`]), accepts
//! argv form (`program` + `args`) or a restricted free-form `cmd`, checks the
//! `exec`/`fs` leash, spawns directly, and refuses dynamic constructs by
//! design (command substitution `$(...)`, arithmetic expansion `$((...))`,
//! backticks, and subshells). [`BrushShellTool`] instead carries full Brush
//! grammar in a dedicated worker; its interceptor gates the worker's own
//! external spawns and opens. When effective caveats engage an available
//! Landlock, Seatbelt, or AppContainer backend, the worker/process tree
//! inherits that L3 boundary; otherwise the run honestly reports
//! [`agent_bridle_core::SandboxKind::None`] (I9). Coverage is per-axis and
//! scope-shaped: inspect the result's enforcement report rather than inferring
//! every guarantee from the coarse sandbox kind.
//!
//! The engine (agent-bridle#34 Track A + #45): a sequence of pipelines joined by
//! `&&`/`||`/`;` (short-circuit semantics), each pipeline simple commands with
//! quoted arguments, **redirections** (`> out`, `>> out`, `< in`, `2> err`,
//! `2>&1`), **filename globbing** (`*`/`?`/`[…]`) and **allowlisted `$VAR`
//! expansion** — every filesystem/env touch bridle performs (redirect opens,
//! glob directory listings, variable allowlist) is leash-/policy-checked before
//! any spawn. Those dynamic constructs stay refused by the safe-subset engine.
//! The process spawning is behind a `Spawner` seam (mocked in unit tests; real
//! path in `tests/real_spawn.rs`). Brush is the carried full-grammar alternative
//! behind the same construction-time registry seam.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

#[cfg(feature = "brush")]
mod brush_shell;
#[cfg(feature = "brush")]
mod brush_worker;
#[cfg(feature = "brush")]
mod caveat_interceptor;
#[cfg(feature = "brush")]
mod coreutils_dispatch;
#[cfg(all(feature = "brush", any(target_os = "linux", target_os = "macos")))]
mod private_control;
#[cfg(all(feature = "brush", not(any(target_os = "linux", target_os = "macos"))))]
mod private_control {
    use serde::de::DeserializeOwned;

    pub(crate) fn receive_worker_request<P: DeserializeOwned>(
    ) -> Result<agent_bridle_core::TrustedWorkerRequest<P>, String> {
        Err("authenticated private worker control is unavailable on this platform".to_string())
    }

    #[cfg(feature = "carried-coreutils")]
    pub(crate) fn authenticate_carried_dispatch(
        _name: &std::ffi::OsStr,
        _args: &[std::ffi::OsString],
    ) -> Result<(), String> {
        Err("authenticated carried dispatch is unavailable on this platform".to_string())
    }
}
#[cfg(feature = "host-shell")]
mod host_shell;
#[cfg(feature = "brush")]
mod shell_inspect;
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
/// the worker-local L2 leash; when an effective native backend engages, the
/// worker and descendants inherit that L3 boundary. Opt-in via the `brush`
/// feature; a construction-time alternative to [`ShellTool`] behind the ADR
/// 0005 D2 seam, using the temporary `brush-ocap-*` fork
/// (reubeno/brush#1184).
#[cfg(feature = "brush")]
pub use brush_shell::BrushShellTool;

/// Whether this target provides the kernel-authenticated private transport
/// required by [`BrushShellTool`] and carried-coreutils re-exec.
///
/// A host must use this probe before advertising or selecting the Brush engine.
/// Unsupported targets fail closed at invocation; they must select the
/// safe-subset [`ShellTool`] instead of treating full access as authentication.
#[cfg(feature = "brush")]
#[must_use]
pub const fn brush_private_control_supported() -> bool {
    cfg!(any(target_os = "linux", target_os = "macos"))
}
#[cfg(feature = "brush")]
pub use shell_inspect::{
    inspect_shell, DescendantExec, InspectedCommand, InspectedConstruct, InspectedRedirect,
    RedirectOperation, ShellConstructKind, ShellInspection, ShellInspectionError,
};

/// Private Brush-worker dispatch. An embedder's binary calls
/// [`maybe_dispatch`] at the top of `main` so the sandboxed worker re-exec
/// resolves before normal application startup.
#[cfg(feature = "brush")]
pub use coreutils_dispatch::maybe_dispatch;

/// Carried-coreutils registration (agent-bridle#20 / issue #206). With
/// `carried-coreutils`, the Brush engine's non-conflicting shims re-exec
/// `<self> --invoke-bundled <name>` and resolve against the dispatch-capable
/// host binary. These functions are used by the engine internally.
#[cfg(feature = "carried-coreutils")]
pub use coreutils_dispatch::{install_default_providers, register_shims};

/// Network egress audit surface (#124, ADR 0016): the loopback proxy records
/// every proxy-visible connection as a [`NetAuditEvent`] through an [`AuditSink`]
/// (default off; enable via the `BRIDLE_NET_AUDIT` setting). The `bridle-netmon`
/// binary renders the JSON-lines stream as a live monitor.
#[cfg(feature = "shell")]
pub use net_proxy::{AuditSink, JsonlSink, NetAuditEvent, NetDecision, NetKind, NullSink};
