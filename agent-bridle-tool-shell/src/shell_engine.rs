//! Engine choice as data (#491, ADR 0005 D2).
//!
//! Every engine registers as the one `shell` tool; which one a host runs is a
//! per-host choice. [`ShellEngine`] names it, [`ShellOptions`] carries the
//! options every engine takes, and [`ShellEngine::build`] constructs it, so a
//! host such as `agent-bridle-mcp` selects an engine from config instead of
//! code. [`ShellEngine::coverage`] says what each engine checks before the
//! kernel fence. That table is L2 convenience, not authority: the fence (L3)
//! is what confines.

use std::sync::Arc;

use agent_bridle_core::{LimitsPolicy, SandboxPolicy, Tool, ToolError, ToolResult};
use serde::{Deserialize, Serialize};

/// Which engine interprets the `shell` tool's commands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum ShellEngine {
    /// The argv + safe-subset parser: refuses `$(...)`, backticks and other
    /// dynamic constructs, and spawns argv directly. Portable default.
    #[default]
    SafeSubset,
    /// A real `/bin/sh -c` (ADR 0019). Full grammar; enforcement rests on the
    /// kernel fence, and a restricted `exec` or `net` grant is refused.
    Host,
    /// Carried bash-in-Rust in an authenticated worker. Its filters check the
    /// worker's own external spawns; the fence confines everything else.
    Brush,
}

impl ShellEngine {
    /// Every engine, in a fixed order.
    pub const ALL: [Self; 3] = [Self::SafeSubset, Self::Host, Self::Brush];

    /// The canonical config token (kebab-case), also the disclosed engine name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SafeSubset => "safe-subset",
            Self::Host => "host",
            Self::Brush => "brush",
        }
    }

    /// Whether this build and platform can run the engine.
    pub fn validate_available(self) -> Result<(), String> {
        if !self.compiled() {
            return Err(format!(
                "shell engine '{self}' is not compiled into this build (enable the `{}` feature)",
                self.feature()
            ));
        }
        #[cfg(feature = "brush")]
        return self.validate_worker_transport(crate::brush_private_control_supported());
        #[cfg(not(feature = "brush"))]
        Ok(())
    }

    #[cfg_attr(not(any(feature = "brush", test)), allow(dead_code))]
    fn validate_worker_transport(self, supported: bool) -> Result<(), String> {
        if self == Self::Brush && !supported {
            return Err("brush is unavailable on this platform: authenticated worker transport is not implemented; select safe-subset (portable, limited shell grammar)".into());
        }
        Ok(())
    }

    const fn feature(self) -> &'static str {
        match self {
            Self::SafeSubset => "shell",
            Self::Host => "host-shell",
            Self::Brush => "brush",
        }
    }

    const fn compiled(self) -> bool {
        match self {
            Self::SafeSubset => cfg!(feature = "shell"),
            Self::Host => cfg!(feature = "host-shell"),
            Self::Brush => cfg!(feature = "brush"),
        }
    }

    /// Build the engine with `options`. Refuses an engine this build or
    /// platform cannot run; never falls back to another engine.
    pub fn build(self, options: ShellOptions) -> ToolResult<Arc<dyn Tool>> {
        self.validate_available().map_err(ToolError::denied)?;
        #[allow(unused_variables)]
        let ShellOptions {
            limits,
            sandbox,
            output_observer,
            execution_lease,
        } = options;
        match self {
            #[cfg(feature = "shell")]
            Self::SafeSubset => {
                let mut tool =
                    crate::ShellTool::with_config(limits).with_sandbox_policy((*sandbox).clone());
                if let Some(observer) = output_observer {
                    tool = tool.with_output_observer(observer);
                }
                if let Some(lease) = execution_lease {
                    tool = tool.with_execution_lease(lease);
                }
                Ok(Arc::new(tool))
            }
            #[cfg(feature = "host-shell")]
            Self::Host => {
                let mut tool = crate::HostShellTool::new()
                    .with_limits(limits)
                    .with_sandbox_policy(sandbox);
                if let Some(observer) = output_observer {
                    tool = tool.with_output_observer(observer);
                }
                if let Some(lease) = execution_lease {
                    tool = tool.with_execution_lease(lease);
                }
                Ok(Arc::new(tool))
            }
            #[cfg(feature = "brush")]
            Self::Brush => {
                let mut tool = crate::BrushShellTool::new()
                    .with_limits(limits)?
                    .with_sandbox_policy(sandbox);
                if let Some(observer) = output_observer {
                    tool = tool.with_output_observer(observer);
                }
                if let Some(lease) = execution_lease {
                    tool = tool.with_execution_lease(lease);
                }
                Ok(Arc::new(tool))
            }
            #[allow(unreachable_patterns)]
            _ => unreachable!("validate_available refused an uncompiled engine"),
        }
    }

    /// What this engine checks before the kernel fence, per operation and
    /// origin. L2 convenience, not authority: a cell that is not
    /// [`Check::Checked`] is confined only by the fence, if at all.
    #[must_use]
    pub const fn coverage(self) -> &'static [Cell] {
        match self {
            Self::SafeSubset => SAFE_SUBSET,
            Self::Host => HOST,
            Self::Brush => BRUSH,
        }
    }
}

use Check::{Checked, FenceOnly, NotPerformed, UnrestrictedOnly};
use Operation::{Enumerate, Exec, Metadata, Mutation, Net, Open};
use Origin::{Program, Shell};

// The parser resolves every program name, redirect target, glob
// directory and cwd against the caveats before it spawns. It has
// no builtins that mutate the filesystem or open sockets. Spawned
// programs and their descendants are confined by the fence alone.
const SAFE_SUBSET: &[Cell] = &[
    Cell::new(Exec, Shell, Checked),
    Cell::new(Open, Shell, Checked),
    Cell::new(Enumerate, Shell, Checked),
    Cell::new(Metadata, Shell, Checked),
    Cell::new(Mutation, Shell, NotPerformed),
    Cell::new(Net, Shell, NotPerformed),
    Cell::new(Exec, Program, FenceOnly),
    Cell::new(Open, Program, FenceOnly),
    Cell::new(Enumerate, Program, FenceOnly),
    Cell::new(Metadata, Program, FenceOnly),
    Cell::new(Mutation, Program, FenceOnly),
    Cell::new(Net, Program, FenceOnly),
];

// `/bin/sh` is opaque: nothing is checked per operation. A
// restricted exec or net grant is refused before the shell starts.
const HOST: &[Cell] = &[
    Cell::new(Exec, Shell, UnrestrictedOnly),
    Cell::new(Open, Shell, FenceOnly),
    Cell::new(Enumerate, Shell, FenceOnly),
    Cell::new(Metadata, Shell, FenceOnly),
    Cell::new(Mutation, Shell, FenceOnly),
    Cell::new(Net, Shell, UnrestrictedOnly),
    Cell::new(Exec, Program, UnrestrictedOnly),
    Cell::new(Open, Program, FenceOnly),
    Cell::new(Enumerate, Program, FenceOnly),
    Cell::new(Metadata, Program, FenceOnly),
    Cell::new(Mutation, Program, FenceOnly),
    Cell::new(Net, Program, UnrestrictedOnly),
];

// The exec filter checks every external program the worker
// starts, carried utilities included. Shell opens go through
// `Shell::open_file` only; they stay FenceOnly until #243 lists
// the builtins and guards the history flush. Carried utilities
// are programs: their own syscalls never re-enter the filters.
const BRUSH: &[Cell] = &[
    Cell::new(Exec, Shell, Checked),
    Cell::new(Open, Shell, FenceOnly),
    Cell::new(Enumerate, Shell, FenceOnly),
    Cell::new(Metadata, Shell, FenceOnly),
    Cell::new(Mutation, Shell, FenceOnly),
    Cell::new(Net, Shell, FenceOnly),
    Cell::new(Exec, Program, FenceOnly),
    Cell::new(Open, Program, FenceOnly),
    Cell::new(Enumerate, Program, FenceOnly),
    Cell::new(Metadata, Program, FenceOnly),
    Cell::new(Mutation, Program, FenceOnly),
    Cell::new(Net, Program, FenceOnly),
];

impl std::fmt::Display for ShellEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for ShellEngine {
    type Err = String;

    /// Parse an engine token: the canonical names plus aliases (`subset`,
    /// `safe`, `sandbox-host`, `landlock`, `seatbelt`, `brush-ocap`).
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().replace('_', "-").as_str() {
            "safe-subset" | "subset" | "safe" => Ok(Self::SafeSubset),
            "host" | "sandbox-host" | "landlock" | "seatbelt" => Ok(Self::Host),
            "brush" | "brush-ocap" => Ok(Self::Brush),
            other => Err(format!(
                "unknown shell engine '{other}' (expected one of: safe-subset, host, brush)"
            )),
        }
    }
}

/// Options every engine takes. The default is today's built-in policy.
#[derive(Clone, Default)]
pub struct ShellOptions {
    /// Timeouts, output cap and env denylist.
    pub limits: LimitsPolicy,
    /// The OS-sandbox mechanism policy for the fence.
    pub sandbox: Arc<SandboxPolicy>,
    /// Presentation-only observer for bounded output chunks.
    pub output_observer: Option<Arc<dyn crate::ShellOutputObserver>>,
    /// Caller resources held until the child is reaped.
    pub execution_lease: Option<crate::ExecutionLease>,
}

impl std::fmt::Debug for ShellOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShellOptions")
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

/// One cell of [`ShellEngine::coverage`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cell {
    /// The operation.
    pub operation: Operation,
    /// Who performs it.
    pub origin: Origin,
    /// What the engine does about it before the fence.
    pub check: Check,
}

impl Cell {
    const fn new(operation: Operation, origin: Origin, check: Check) -> Self {
        Self {
            operation,
            origin,
            check,
        }
    }
}

/// An operation a shell run can perform.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Operation {
    /// Starting a program.
    Exec,
    /// Opening a file.
    Open,
    /// Listing a directory (globs).
    Enumerate,
    /// `stat`, `chdir`.
    Metadata,
    /// `unlink`, `mkdir`, `rename`, `chmod`.
    Mutation,
    /// Opening a socket.
    Net,
}

/// Who performs an operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Origin {
    /// The shell engine itself.
    Shell,
    /// An admitted program and its descendants.
    Program,
}

/// What an engine does about one operation before the kernel fence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Check {
    /// The engine checks it against the caveats and refuses an out-of-scope one.
    Checked,
    /// Unchecked by the engine; only the fence confines it.
    FenceOnly,
    /// Served only when the grant leaves this axis unrestricted.
    UnrestrictedOnly,
    /// The engine never performs it.
    NotPerformed,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_str_canonical_and_aliases() {
        for (token, engine) in [
            ("safe-subset", ShellEngine::SafeSubset),
            ("subset", ShellEngine::SafeSubset),
            ("safe_subset", ShellEngine::SafeSubset),
            ("host", ShellEngine::Host),
            ("sandbox-host", ShellEngine::Host),
            ("landlock", ShellEngine::Host),
            ("seatbelt", ShellEngine::Host),
            ("BRUSH", ShellEngine::Brush),
            ("brush-ocap", ShellEngine::Brush),
        ] {
            assert_eq!(token.parse::<ShellEngine>().unwrap(), engine, "{token}");
        }
        assert!("bogus".parse::<ShellEngine>().is_err());
        for engine in ShellEngine::ALL {
            assert_eq!(engine.as_str().parse::<ShellEngine>().unwrap(), engine);
        }
        assert_eq!(ShellEngine::default(), ShellEngine::SafeSubset);
    }

    #[test]
    fn explicit_brush_requires_transport_while_others_do_not() {
        let unavailable = ShellEngine::Brush
            .validate_worker_transport(false)
            .unwrap_err();
        assert!(unavailable.contains("authenticated worker transport"));
        assert!(unavailable.contains("safe-subset"));
        assert!(ShellEngine::Brush.validate_worker_transport(true).is_ok());
        assert!(ShellEngine::Host.validate_worker_transport(false).is_ok());
        assert!(ShellEngine::SafeSubset
            .validate_worker_transport(false)
            .is_ok());
    }

    /// #491: `build()` refuses an engine whose feature is off, and never
    /// substitutes another.
    #[test]
    fn build_refuses_an_uncompiled_engine() {
        for engine in ShellEngine::ALL {
            match engine.build(ShellOptions::default()) {
                Ok(tool) => assert_eq!(tool.name(), "shell"),
                Err(error) => assert!(
                    !engine.compiled() || engine.validate_available().is_err(),
                    "{engine}: {error}"
                ),
            }
        }
    }

    /// #491: pins the coverage table. Changing a cell is a deliberate edit.
    #[test]
    fn coverage_is_pinned() {
        use Check::*;
        use Operation::*;
        use Origin::*;
        let checked = |engine: ShellEngine| -> Vec<(Operation, Origin)> {
            engine
                .coverage()
                .iter()
                .filter(|c| c.check == Checked)
                .map(|c| (c.operation, c.origin))
                .collect()
        };
        assert_eq!(
            checked(ShellEngine::SafeSubset),
            [
                (Exec, Shell),
                (Open, Shell),
                (Enumerate, Shell),
                (Metadata, Shell)
            ]
        );
        assert_eq!(checked(ShellEngine::Host), []);
        assert_eq!(checked(ShellEngine::Brush), [(Exec, Shell)]);
        let cell = |engine: ShellEngine, op, origin| {
            engine
                .coverage()
                .iter()
                .find(|c| c.operation == op && c.origin == origin)
                .unwrap()
                .check
        };
        for origin in [Shell, Program] {
            assert_eq!(cell(ShellEngine::Host, Exec, origin), UnrestrictedOnly);
            assert_eq!(cell(ShellEngine::Host, Net, origin), UnrestrictedOnly);
        }
        assert_eq!(cell(ShellEngine::Brush, Open, Shell), FenceOnly);
        for engine in ShellEngine::ALL {
            assert_eq!(engine.coverage().len(), 12, "{engine}: one cell per pair");
            for c in engine.coverage() {
                if c.origin == Program && engine != ShellEngine::Host {
                    assert_eq!(c.check, FenceOnly, "{engine} {c:?}");
                }
            }
        }
    }
}
