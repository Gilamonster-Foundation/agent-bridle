//! The confinement funnel for an engine that starts several children under one
//! admitted fence (#493).
//!
//! [`ConfinedCommand`](super::ConfinedCommand) admits, applies and spawns one
//! program. A pipeline engine starts many: it parses a script, checks every
//! stage, then spawns stage after stage with redirect files it opens itself.
//! It used to admit the fence on its own, drop it, and call
//! [`Sandbox::apply`] and [`Sandbox::command_prefix`] directly, so nothing
//! verified that what it applied was what it admitted.
//!
//! Here the same steps happen in core, in the funnel's order:
//!
//! 1. [`LaunchPlan`] decides the mechanism once: the unbridled posture, the
//!    backend caveats and the reported kind.
//! 2. [`ConfinedLaunch::admit`] checks every stage program against the `exec`
//!    grant and admits one [`AdmittedFence`].
//! 3. [`ConfinedLaunch::run`] verifies that fence against what it is about to
//!    apply, applies it on a throwaway thread, and runs the engine's body
//!    there. The body builds children only through [`AppliedFence::command`],
//!    which refuses a program that was not admitted.
//!
//! The sandbox methods take an [`ApplyToken`] only core can make, so this
//! module and `ConfinedCommand` are the only callers.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;

use super::wrap_argv;
use crate::sandbox::best_available_sandbox;
use crate::{
    admit, effective_sandbox_kind_with_policy, egress_proxy_plan, unenforceable_axis,
    AdmissionDecision, AdmittedFence, ApplyToken, BackendProjection, Caveats, ConfinedAxis,
    ConfinementMechanism, DenialKind, ResolvedAuthority, ResolvedScope, RuntimeClosure, Sandbox,
    SandboxKind, SandboxPolicy, Scope, StdioPosture, ToolContext, ToolError, ToolResult,
};

/// Why a launch was refused, in the terms an engine reports: the denial kind
/// and target the refused axis maps to, and the underlying error.
#[derive(Debug)]
pub struct LaunchRefusal {
    /// The denial kind for the refused axis.
    pub kind: DenialKind,
    /// What was refused: `filesystem`, `network`, `confinement`,
    /// `appcontainer-device-ace`, or a program name.
    pub target: String,
    /// The underlying refusal.
    pub error: ToolError,
}

impl LaunchRefusal {
    fn axis(axis: Option<ConfinedAxis>, error: ToolError) -> Self {
        let (kind, target) = match axis {
            Some(ConfinedAxis::FsRead | ConfinedAxis::FsWrite) => (DenialKind::Open, "filesystem"),
            Some(ConfinedAxis::Net) => (DenialKind::Net, "network"),
            Some(ConfinedAxis::Exec) | None => (DenialKind::Exec, "confinement"),
        };
        Self {
            kind,
            target: target.to_string(),
            error,
        }
    }
}

/// The mechanism decision for one invocation, made once and reused by every
/// later step, so reporting, admission and apply cannot disagree.
#[derive(Debug, Clone)]
pub struct LaunchPlan {
    policy: Arc<SandboxPolicy>,
    unbridled: bool,
    backend_caveats: Caveats,
    /// The hosts a loopback egress proxy must admit, when the backend caveats
    /// are the loopback-fenced form of a remote-host `net` allow-list.
    egress_hosts: Option<Vec<String>>,
    mechanism: ConfinementMechanism,
}

impl LaunchPlan {
    /// Decide the mechanism for `cx` under `policy`. Pure: starts nothing.
    ///
    /// Unbridled (ADR 0018), the operator dropped the L3 mechanism, so the
    /// kind is `None`. Otherwise the backend caveats are the context's, or
    /// their loopback-fenced form when a remote-host `net` allow-list needs
    /// the egress proxy, and the kind is what the best available backend will
    /// actually enforce for them.
    #[must_use]
    pub fn new(cx: &ToolContext, policy: &Arc<SandboxPolicy>) -> Self {
        let unbridled = crate::is_unbridled();
        let (egress_hosts, backend_caveats) = match egress_proxy_plan(cx.caveats(), policy) {
            Some((hosts, fenced)) if !unbridled => (Some(hosts), fenced),
            _ => (None, cx.caveats().clone()),
        };
        let kind = if unbridled {
            SandboxKind::None
        } else {
            effective_sandbox_kind_with_policy(
                best_available_sandbox(policy).kind(),
                &backend_caveats,
                policy,
            )
        };
        // Stdio stays `Unaudited`: a pipeline wires stages with raw pipes and
        // redirect files, never the per-channel audited shape
        // (agent-bridle#416 round 3).
        let mechanism = ConfinementMechanism::new(kind, policy.child_network)
            .with_appcontainer_nul_device_ace(policy.appcontainer_nul_device_ace)
            .with_appcontainer_mount_manager_ace(policy.appcontainer_mount_manager_ace);
        Self {
            policy: Arc::clone(policy),
            unbridled,
            backend_caveats,
            egress_hosts,
            mechanism,
        }
    }

    /// The mechanism every envelope of this invocation reports.
    #[must_use]
    pub fn mechanism(&self) -> ConfinementMechanism {
        self.mechanism
    }

    /// Whether the run is unbridled (ADR 0018).
    #[must_use]
    pub fn unbridled(&self) -> bool {
        self.unbridled
    }

    /// The caveats the backend is asked to enforce.
    #[must_use]
    pub fn backend_caveats(&self) -> &Caveats {
        &self.backend_caveats
    }

    /// An explicitly requested host device ACE (`NUL`, MountPointManager)
    /// cannot degrade to an ordinary run: refuse unless the AppContainer
    /// backend is available, and always while unbridled.
    pub fn require_device_aces(&self) -> Result<(), LaunchRefusal> {
        let available = best_available_sandbox(&self.policy).kind();
        match device_ace_refusal(&self.policy, self.unbridled, available) {
            None => Ok(()),
            Some(error) => Err(LaunchRefusal {
                kind: DenialKind::Exec,
                target: "appcontainer-device-ace".to_string(),
                error,
            }),
        }
    }

    /// Refuse when a restricted axis cannot meet the principal's strength
    /// floor under this mechanism. Unbridled skips it by consent.
    pub fn check_strength(&self, cx: &ToolContext) -> Result<(), LaunchRefusal> {
        if self.unbridled {
            return Ok(());
        }
        match unenforceable_axis(cx.caveats(), self.mechanism, cx.strength_floor()) {
            None => Ok(()),
            Some(unmet) => Err(LaunchRefusal::axis(
                Some(unmet.axis),
                ToolError::denied(format!("{unmet}; refusing to run unconfined")),
            )),
        }
    }
}

/// The device-ACE rule behind [`LaunchPlan::require_device_aces`]: `None` when
/// no ACE was requested, or when one was and the bridled run has the
/// AppContainer backend that grants it.
fn device_ace_refusal(
    policy: &SandboxPolicy,
    unbridled: bool,
    available: SandboxKind,
) -> Option<ToolError> {
    let flags = policy.appcontainer_device_ace_flags();
    if flags.is_empty() || (!unbridled && available == SandboxKind::AppContainer) {
        return None;
    }
    let why = if unbridled {
        "cannot run while unbridled"
    } else {
        "requires the Windows AppContainer backend"
    };
    Some(ToolError::denied(format!(
        "the AppContainer device-ACE opt-in {why}; refusing without the requested {} grant",
        flags.join(" ")
    )))
}

/// AppContainer cannot express a non-empty `exec` allow-list natively. On the
/// pipeline route core has checked every stage program against that list
/// ([`ConfinedLaunch::admit`]) and [`AppliedFence::command`] refuses any other
/// program, so the route-local bound is the grant itself. The rule applies only
/// when AppContainer is the **effective** kind: exec-only caveats do not engage
/// it and keep the no-backend `Unbounded` refusal. It changes neither the
/// backend's native claim nor its report: `exec` still reports `interceptor`.
fn appcontainer_checked_exec(
    kind: SandboxKind,
    caveats: &Caveats,
    mut resolved: ResolvedAuthority,
) -> ResolvedAuthority {
    if kind == SandboxKind::AppContainer
        && matches!(&caveats.exec, Scope::Only(programs) if !programs.is_empty())
    {
        resolved.exec = ResolvedScope::from_scope(&caveats.exec);
    }
    resolved
}

/// A fence admitted for a set of programs, ready to run bodies under.
#[derive(Clone)]
pub struct ConfinedLaunch {
    programs: Arc<BTreeSet<String>>,
    egress_hosts: Option<Vec<String>>,
    route: Route,
}

#[derive(Clone)]
enum Route {
    /// Unbridled: no fence, by the operator's acknowledged opt-in.
    Native,
    Fenced(Arc<Fenced>),
}

struct Fenced {
    sandbox: Box<dyn Sandbox>,
    admitted: AdmittedFence,
    /// The caveats `run` applies: the admitted fence's own, copied out once at
    /// admission. `run` re-verifies them against the fence before every apply.
    apply_caveats: Caveats,
    /// The backend engages for these caveats. When it does not there is
    /// nothing to apply and the body runs on the caller's thread.
    engaged: bool,
}

impl std::fmt::Debug for ConfinedLaunch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConfinedLaunch")
            .field("programs", &self.programs)
            .finish_non_exhaustive()
    }
}

impl ConfinedLaunch {
    /// Admit `programs` under `plan`.
    ///
    /// A requested device ACE must be grantable
    /// ([`LaunchPlan::require_device_aces`]), and every program must be in the
    /// `exec` grant. Bridled, the backend's
    /// conservative projection of `plan`'s caveats is admitted as one
    /// [`AdmittedFence`] (ruleset grain, the same admission `ConfinedCommand`
    /// uses), then the per-axis strength floor is checked. A backend that
    /// enforces nothing projects unbounded authority, so a restricted grant is
    /// refused here, not spawned fail-open. Unbridled, only the exec check
    /// runs.
    pub fn admit(
        plan: &LaunchPlan,
        cx: &ToolContext,
        programs: impl IntoIterator<Item = String>,
    ) -> Result<Self, LaunchRefusal> {
        Self::admit_observed(plan, cx, programs, |_| {})
    }

    // Private continuation seam: lets a test re-derive the caveats to apply
    // after admission (the #317 bug class), to prove `run` refuses them.
    fn admit_observed(
        plan: &LaunchPlan,
        cx: &ToolContext,
        programs: impl IntoIterator<Item = String>,
        after_admission: impl FnOnce(&mut Caveats),
    ) -> Result<Self, LaunchRefusal> {
        plan.require_device_aces()?;
        let programs: BTreeSet<String> = programs.into_iter().collect();
        for program in &programs {
            cx.check_exec(program).map_err(|error| LaunchRefusal {
                kind: DenialKind::Exec,
                target: program.clone(),
                error,
            })?;
        }
        let programs = Arc::new(programs);
        if plan.unbridled {
            return Ok(Self {
                programs,
                egress_hosts: None,
                route: Route::Native,
            });
        }

        let sandbox = best_available_sandbox(&plan.policy);
        let caveats = &plan.backend_caveats;
        let kind = plan.mechanism.kind();
        let projection = BackendProjection {
            resolved: appcontainer_checked_exec(
                kind,
                caveats,
                sandbox.resolved_authority(caveats, StdioPosture::Unaudited),
            ),
            runtime_closure: sandbox.runtime_closure(caveats),
        };
        // Which axis the scope bound rejects, for the refusal's denial kind.
        let rejected = match admit(&projection.resolved, caveats, &projection.runtime_closure) {
            AdmissionDecision::Admit => None,
            AdmissionDecision::Reject(reject) => Some(reject.axis),
        };
        let admitted = AdmittedFence::admit(
            caveats,
            RuntimeClosure::for_policy(&plan.policy),
            plan.mechanism,
            cx.strength_floor(),
            |_| projection,
        )
        .map_err(|error| {
            let axis = rejected.or_else(|| {
                unenforceable_axis(cx.caveats(), plan.mechanism, cx.strength_floor())
                    .map(|unmet| unmet.axis)
            });
            LaunchRefusal::axis(axis, error)
        })?;
        plan.check_strength(cx)?;
        let mut apply_caveats = admitted.mechanism_caveats().clone();
        after_admission(&mut apply_caveats);
        Ok(Self {
            programs,
            egress_hosts: plan.egress_hosts.clone(),
            route: Route::Fenced(Arc::new(Fenced {
                sandbox,
                admitted,
                apply_caveats,
                engaged: kind != SandboxKind::None,
            })),
        })
    }

    /// The hosts a loopback egress proxy must admit for this launch (#124,
    /// ADR 0016), when the admitted fence is the loopback-fenced form of a
    /// remote-host `net` allow-list. The engine starts that proxy, points the
    /// children at it, and keeps it alive around [`Self::run`].
    #[must_use]
    pub fn egress_hosts(&self) -> Option<&[String]> {
        self.egress_hosts.as_deref()
    }

    /// Run `body` under the admitted fence.
    ///
    /// The caveats about to be applied must content-address to the fence
    /// admission stamped ([`AdmittedFence::verify_applied`]); a fence swapped
    /// or re-derived after admission is refused before anything is applied.
    /// A thread-confining backend (Landlock) is applied on a throwaway thread
    /// and `body` runs on it, so every child it starts inherits the domain and
    /// its own opens are bounded too. A wrapper backend (Seatbelt,
    /// AppContainer) confines through the prefix [`AppliedFence::command`]
    /// prepends. Both fail closed: if confinement cannot be established the
    /// run errors and `body` never runs.
    pub fn run<T: Send + 'static>(
        &self,
        body: impl FnOnce(&AppliedFence) -> ToolResult<T> + Send + 'static,
    ) -> ToolResult<T> {
        let fenced = match &self.route {
            Route::Native => {
                // Dropping the mechanism is what the operator acknowledged:
                // redirect opens stay unbounded too (#351).
                return body(&AppliedFence {
                    prefix: Vec::new(),
                    programs: Arc::clone(&self.programs),
                    fs_read: Scope::All,
                    fs_write: Scope::All,
                });
            }
            Route::Fenced(fenced) => Arc::clone(fenced),
        };
        let caveats = fenced.apply_caveats.clone();
        fenced.admitted.verify_applied(&caveats)?;
        let mut applied = AppliedFence {
            prefix: Vec::new(),
            programs: Arc::clone(&self.programs),
            fs_read: caveats.fs_read.clone(),
            fs_write: caveats.fs_write.clone(),
        };
        if !fenced.engaged {
            return body(&applied);
        }
        // Computed before the thread so a fail-closed wrapper error aborts
        // the run, from the ADMITTED caveats `apply` consumes below.
        applied.prefix = fenced
            .sandbox
            .command_prefix(&caveats, ApplyToken::core())?;
        std::thread::Builder::new()
            .name("agent-bridle-confined".to_string())
            .spawn(move || {
                // Wrapper backends confine through the prefix; their `apply`
                // is not the mechanism and is skipped, as in `ConfinedCommand`.
                if applied.prefix.is_empty() {
                    fenced.sandbox.apply(&caveats, ApplyToken::core())?;
                }
                body(&applied)
            })
            .map_err(ToolError::Exec)?
            .join()
            .map_err(|_| {
                ToolError::Exec(std::io::Error::other("confined execution thread panicked"))
            })?
    }
}

/// The fence [`ConfinedLaunch::run`] applied, handed to the engine's body.
#[derive(Debug)]
pub struct AppliedFence {
    prefix: Vec<String>,
    programs: Arc<BTreeSet<String>>,
    fs_read: Scope<String>,
    fs_write: Scope<String>,
}

impl AppliedFence {
    /// The read scope the engine's own opens (redirects) are bounded by.
    #[must_use]
    pub fn fs_read(&self) -> &Scope<String> {
        &self.fs_read
    }

    /// The write scope the engine's own opens (redirects) are bounded by.
    #[must_use]
    pub fn fs_write(&self) -> &Scope<String> {
        &self.fs_write
    }

    /// The command for one admitted program. Refuses a program
    /// [`ConfinedLaunch::admit`] did not check.
    ///
    /// The child gets the backend's wrapper prefix, its own process group, and
    /// no ambient environment: a fixed minimal baseline (`PATH`, `LC_ALL`; on
    /// Windows `SystemRoot`, `LOCALAPPDATA`, `PATHEXT`), to which the engine
    /// adds only delegated variables (AB-016, #323).
    pub fn command(&self, program: &str, args: &[String]) -> ToolResult<FencedCommand> {
        if !self.programs.contains(program) {
            return Err(ToolError::denied(format!(
                "program {program:?} was not admitted for this launch"
            )));
        }
        let args: Vec<OsString> = args.iter().map(OsString::from).collect();
        let (spawn_program, spawn_args) = wrap_argv(&self.prefix, program, &args);
        let mut cmd = Command::new(spawn_program);
        cmd.args(spawn_args);
        // Each child leads its own process group so a timeout can stop the
        // whole group, descendants included (AB-006, #269).
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt as _;
            cmd.process_group(0);
        }
        cmd.env_clear();
        cmd.env("PATH", crate::default_exec_path());
        #[cfg(unix)]
        cmd.env("LC_ALL", "C");
        #[cfg(windows)]
        {
            // Well-known non-secret platform paths, not ambient authority.
            // Without `LOCALAPPDATA`, `CreateProcessW` for an AppContainer
            // child fails with `ERROR_ENVVAR_NOT_FOUND (203)`.
            for var in ["SystemRoot", "LOCALAPPDATA"] {
                if let Some(value) = std::env::var_os(var) {
                    cmd.env(var, value);
                }
            }
            cmd.env(
                "PATHEXT",
                std::env::var_os("PATHEXT")
                    .unwrap_or_else(|| OsString::from(".COM;.EXE;.BAT;.CMD")),
            );
        }
        Ok(FencedCommand { cmd })
    }
}

/// A child being built under an [`AppliedFence`]. Deliberately narrower than
/// [`std::process::Command`]: the program, wrapper prefix, process group and
/// environment baseline are fixed by [`AppliedFence::command`].
#[derive(Debug)]
pub struct FencedCommand {
    cmd: Command,
}

impl FencedCommand {
    /// Set the working directory.
    pub fn current_dir(&mut self, dir: impl AsRef<std::path::Path>) -> &mut Self {
        self.cmd.current_dir(dir);
        self
    }

    /// Add one delegated environment variable over the baseline.
    pub fn env(
        &mut self,
        key: impl AsRef<std::ffi::OsStr>,
        value: impl AsRef<std::ffi::OsStr>,
    ) -> &mut Self {
        self.cmd.env(key, value);
        self
    }

    /// Set stdin.
    pub fn stdin(&mut self, cfg: impl Into<Stdio>) -> &mut Self {
        self.cmd.stdin(cfg);
        self
    }

    /// Set stdout.
    pub fn stdout(&mut self, cfg: impl Into<Stdio>) -> &mut Self {
        self.cmd.stdout(cfg);
        self
    }

    /// Set stderr.
    pub fn stderr(&mut self, cfg: impl Into<Stdio>) -> &mut Self {
        self.cmd.stderr(cfg);
        self
    }

    /// Start the child. Ambient descriptors the parent left open are closed
    /// first so they are not inherited as un-delegated capabilities (#319);
    /// this runs last so it applies whatever stdio was chosen.
    pub fn launch(mut self) -> std::io::Result<Child> {
        #[cfg(unix)]
        agent_bridle_fdguard::deny_inherited_fds(&mut self.cmd);
        self.cmd.spawn()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Gate, Tool};

    fn ctx(granted: &Caveats) -> ToolContext {
        struct AnyTool;
        #[async_trait::async_trait]
        impl Tool for AnyTool {
            fn name(&self) -> &str {
                "any"
            }
            fn schema(&self) -> serde_json::Value {
                serde_json::Value::Null
            }
            async fn invoke(
                &self,
                _: serde_json::Value,
                _: &ToolContext,
            ) -> ToolResult<serde_json::Value> {
                Ok(serde_json::Value::Null)
            }
        }
        Gate::new(0)
            .authorize(&AnyTool, granted)
            .expect("authorize")
    }

    fn policy() -> Arc<SandboxPolicy> {
        Arc::new(SandboxPolicy::default())
    }

    /// A requested device ACE never degrades to an ordinary or unbridled run
    /// (moved from tool-shell with the rule, #493).
    #[test]
    fn device_ace_policy_has_no_shell_or_unbridled_fallback() {
        for (enabled, flag) in [
            (
                SandboxPolicy {
                    appcontainer_nul_device_ace: true,
                    ..SandboxPolicy::default()
                },
                "--nul-device-ace",
            ),
            (
                SandboxPolicy {
                    appcontainer_mount_manager_ace: true,
                    ..SandboxPolicy::default()
                },
                "--mount-manager-ace",
            ),
        ] {
            assert!(
                device_ace_refusal(&enabled, false, SandboxKind::AppContainer).is_none(),
                "the explicit widening may use only the AppContainer route"
            );
            for (unbridled, available) in [
                (false, SandboxKind::None),
                (true, SandboxKind::AppContainer),
            ] {
                let error = device_ace_refusal(&enabled, unbridled, available)
                    .expect("the requested device ACE must never degrade to a fallback");
                assert!(
                    error
                        .to_string()
                        .contains(&format!("refusing without the requested {flag}")),
                    "the refusal must name the skipped mechanism: {error}"
                );
            }
        }
        assert!(
            device_ace_refusal(&SandboxPolicy::default(), false, SandboxKind::None).is_none(),
            "default-off preserves ordinary no-backend behavior"
        );
    }

    /// #493: the AppContainer exec rule substitutes the grant only when
    /// AppContainer is the effective kind and the allow-list is non-empty.
    #[test]
    fn appcontainer_exec_rule_has_exactly_todays_scope() {
        let only_ls = Caveats {
            exec: Scope::only(["ls".to_string()]),
            ..Caveats::top()
        };
        let unbounded = || ResolvedAuthority {
            exec: ResolvedScope::Unbounded,
            ..ResolvedAuthority::from_delegated(&Caveats::top())
        };
        let granted = ResolvedScope::from_scope(&only_ls.exec);

        let under = appcontainer_checked_exec(SandboxKind::AppContainer, &only_ls, unbounded());
        assert_eq!(under.exec, granted, "the checked grant bounds exec");

        for kind in [
            SandboxKind::None,
            SandboxKind::Landlock,
            SandboxKind::Seatbelt,
        ] {
            let other = appcontainer_checked_exec(kind, &only_ls, unbounded());
            assert_eq!(
                other.exec,
                ResolvedScope::Unbounded,
                "{kind:?} must not borrow the rule"
            );
        }
        let none = Caveats {
            exec: Scope::none(),
            ..Caveats::top()
        };
        let deny_all = appcontainer_checked_exec(SandboxKind::AppContainer, &none, unbounded());
        assert_eq!(
            deny_all.exec,
            ResolvedScope::Unbounded,
            "exec deny-all stays native"
        );
        let all =
            appcontainer_checked_exec(SandboxKind::AppContainer, &Caveats::top(), unbounded());
        assert_eq!(
            all.exec,
            ResolvedScope::Unbounded,
            "unrestricted exec is untouched"
        );
    }

    /// #500: this funnel checks the backend closure against the plan's
    /// harness-private markers, as `ConfinedCommand` does. `empty()` would
    /// check an embedder's policy against the default markers instead.
    #[test]
    fn the_launch_closure_takes_its_markers_from_the_policy() {
        let code = include_str!("launch.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        assert!(code.contains("RuntimeClosure::for_policy(&plan.policy)"));
        assert!(!code.contains("RuntimeClosure::empty()"));
    }

    /// #493: a program outside the `exec` grant is refused at admission, and
    /// the applied fence refuses to build a command for a program that was
    /// never admitted.
    #[test]
    fn only_admitted_programs_can_be_built() {
        let granted = Caveats {
            exec: Scope::only(["echo".to_string()]),
            ..Caveats::top()
        };
        let cx = ctx(&granted);
        let plan = LaunchPlan::new(&cx, &policy());
        let refused = ConfinedLaunch::admit(&plan, &cx, ["rm".to_string()]).unwrap_err();
        assert_eq!(refused.kind, DenialKind::Exec);
        assert_eq!(refused.target, "rm");

        let cx = ctx(&Caveats::top());
        let plan = LaunchPlan::new(&cx, &policy());
        let launch = ConfinedLaunch::admit(&plan, &cx, ["echo".to_string()]).expect("admit");
        let built = launch
            .run(|fence| {
                assert!(fence.command("echo", &[]).is_ok());
                Ok(fence.command("rm", &[]).map(|_| ()))
            })
            .expect("run");
        assert!(
            matches!(built, Err(ToolError::Denied { .. })),
            "an unadmitted program must be refused: {built:?}"
        );
    }

    /// Admit `granted`, re-derive the caveats to apply with `tamper`, and
    /// require `run` to refuse before the body runs.
    fn assert_re_derived_fence_is_refused(granted: &Caveats, tamper: impl FnOnce(&mut Caveats)) {
        let cx = ctx(granted);
        let plan = LaunchPlan::new(&cx, &policy());
        let launch = ConfinedLaunch::admit_observed(&plan, &cx, ["echo".to_string()], tamper)
            .expect("the unmodified grant must admit");
        let ran = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = Arc::clone(&ran);
        let result = launch.run(move |_| {
            flag.store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        });
        assert!(
            matches!(result, Err(ToolError::Denied { .. })),
            "a re-derived fence must be refused: {result:?}"
        );
        assert!(
            !ran.load(std::sync::atomic::Ordering::SeqCst),
            "the body must not run under a fence that failed verification"
        );
    }

    /// #493: the pipeline twin of
    /// `verify_applied_rejects_a_substituted_widened_fence` (the #317 bug
    /// class). Caveats re-derived between admission and run do not recompute
    /// to the admitted fence CID, so `run` refuses and the body never runs.
    /// This shape admits on every build, so the refusal is always exercised.
    #[test]
    fn run_rejects_a_fence_re_derived_after_admission() {
        assert_re_derived_fence_is_refused(&Caveats::top(), |caveats| {
            caveats.fs_write = Scope::only(["/tmp/ab-493-elsewhere".to_string()]);
        });
    }

    /// #493: the same refusal for a WIDENED fence. Admission analyzed a write
    /// scope of one directory; apply is handed that directory plus another.
    #[cfg(all(target_os = "linux", feature = "linux-landlock"))]
    #[test]
    fn run_rejects_a_fence_widened_after_admission() {
        if !crate::landlock_is_supported() {
            eprintln!("skipping: Landlock unavailable");
            return;
        }
        let dir = std::env::temp_dir();
        let dir = dir
            .canonicalize()
            .expect("temp dir")
            .to_string_lossy()
            .into_owned();
        let granted = Caveats {
            fs_write: Scope::only([dir.clone()]),
            ..Caveats::top()
        };
        assert_re_derived_fence_is_refused(&granted, move |caveats| {
            caveats.fs_write = Scope::only([dir, "/".to_string()]);
        });
    }
}
