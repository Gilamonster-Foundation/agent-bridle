# RFC: Integrating newt-agent, agent-bridle, and NVIDIA OpenShell

> **Decision record:** [ADR 0027 — OpenShell as an enforcement projection of Bridle authority](../adr/0027-openshell-authority-projection.md).
> **Companions:** [semantic crosswalk](openshell-semantic-crosswalk.md) · [upstream contribution proposals](openshell-upstream-contributions.md).
> This is the full study behind the ADR: decision matrix, threat model, migration path, prototype plan, PR train, exit criteria. It follows the ADR 0026 projection template ("POSIX is a projection of Bridle authority; the same law governs OpenShell").

**Status:** Draft, v3.1 — adversarially reviewed three times; *no implementation authorized*
**Author:** architecture coordinator (integration study)
**Date:** 2026-08-13
**Verdict of review pass 1:** survive-with-amendments. Recommendation (B; C→B→A; reject D; gate E) stands; six findings folded into v2.
**Verdict of review pass 2:** recommendation stands; the v2 text still carried an **impossible-conjunction error** and under-specified security objects. v3 adds a normative model (§A), invariants (§B), and test obligations (§C).
**Verdict of review pass 3:** recommendation stands; pass 3 found the v3 identity/evidence objects still over-claimed. v3.1 makes the remote grain **honest** (sandbox, not process), models enforcement as a **product** (mechanism × evidence) instead of a lying scalar `min()`, splits **requested vs attested image**, adds a **normative exec admission theorem**, reorders the **PR train** (identity primitives before remote execution), and fixes **U1's signer/verifier** to the gateway-receipt model. **This is a security contract; unsafe states must be unrepresentable, fail-closed, or explicitly weaker-and-visible.**

**Changelog v3→v3.1 (review-pass-3; §A is authoritative — these supersede the F2/F4/F5 wording below):**
- **R3-1 — remote identity grain is the SANDBOX, not the process.** `RemoteWorkerBinding` proved only what the desk *intended to authorize for a sandbox*, not which process/executable produced a result; once a narrow credential is inside a hostile sandbox, another process there can use it and the executable can be swapped. Renamed to **`SandboxPrincipalBinding`** with the honest theorem "authority delegated to THIS sandbox environment." Per-process remote identity (Outcome B) is a named upstream/TCB dependency, not something the binding supplies. Same-sandbox credential theft / executable-swap are added as adversarial cases (1c/1d). See §A.3.
- **R3-2 — enforcement is a PRODUCT, not a scalar `min()`.** Reporting Kernel-Landlock as `Interceptor` lied about the mechanism and, since the fs floor is structurally `Kernel` (`report.rs:370-395`, admission `report[axis] >= floor[axis]` at `report.rs:348-349`), forced a refuse anyway. v3.1 models `EnforcementClaim { mechanism, evidence }` (componentwise order); OpenShell fs stays **mechanism-Kernel, evidence-CannotProve**; **restricted-fs RemoteFence refuses pre-U1 unless the operator sets an explicit, visible CannotProve evidence floor**. See §A.4.
- **R3-4 — requested vs attested image are different facts.** `SandboxImageCid` conflated intent and proof. Split into **`RequestedImageCid`** (pinned intent, in `StaticFenceCid`) and **`AttestedImageCid`** (evidence, Cannot-Prove today). See §A.5, U3.
- **R3-5 — exec is identity authority: a normative fail-closed admission theorem.** Restrictive `exec` over a direct-exec worker with no verified executable-closure mechanism **REFUSES**. See §A.6.
- **R3-3 — PR train reordered.** 5a seam → **5b identity/provenance primitives (zero remote exec)** → 5c OpenShell RemoteFence (structurally cannot accept a result without 5b). RemoteFence is **not** threaded through `best_available_sandbox`. See §9.
- **R3-6 — U1 signer/verifier fixed.** The sandbox holds no signing key (the **gateway** signs the sandbox JWT; the supervisor presents it as bearer — `sandbox_jwt.rs:6-7`). U1 becomes a **gateway-emitted signed receipt** over an authenticated supervisor report; it proves "the trusted supervisor reported applying this policy and the gateway authenticated it," **not** enforcement against a compromised supervisor. The supervisor is in B's TCB. See U1.
- **Invariants refined:** I3 → **I3a** (mechanism honesty) + **I3b** (evidence honesty); I5 → **I5a** (sandbox-principal binding) + **I5b** (execution identity — remote unavailable unless separately attested). I1/I2/I4/I6 preserved.

**Changelog v2→v3 (each item is a conceded review-pass-2 finding; note F2/F4/F5 are superseded by R3 above):**
- **F1 — separate execution backend from enforcement mechanism.** v2 still said "`SandboxKind::OpenShell`" and implied a single process could get desk-local Landlock for fs *and* an OpenShell fence for net. **Retracted.** A process has exactly one **ExecutionBackend** (`Local` | `RemoteFence`); each authority axis is enforced by an **EnforcementMechanism** *that lives where the execution runs*. Desk-local Landlock cannot reach a remote container. The "additive" split is valid only at the fleet level (some commands Local, some Remote), never within one execution. See §A.1.
- **F2 — separate authority identity from execution identity.** *(Object renamed and grain corrected by R3-1: `RemoteWorkerBinding` → `SandboxPrincipalBinding`, sandbox-grain not process-grain.)* AgentKey possession (**AuthorityIdentity**) is a different grain from the kernel-local process/image proof (**ExecutionIdentity**); the remote binding recommends the **brokered** key model (root key never enters the worker). See §A.3.
- **F3 — split fence authority from gate authority.** The projection theorem must quantify over **FenceCaveats** (`fs_read/fs_write/exec/net`), not all `EffectiveCaveats`. **GateCaveats** (`max_calls`, `valid_for_generation`, presence) are Gate-only; on the direct-exec path they are **Unsupported**, not "Exact by not projecting." A grant that needs a global GateCaveat over unmediated exec must **fail admission**. See §A.2.
- **F4 — reconcile mechanism strength with evidence strength.** *(Model corrected by R3-2: NOT a scalar `min()` — a product `EnforcementClaim{mechanism, evidence}`.)* `AxisEnforcement` is a **MechanismStrength** — a pure function of `(effective, mechanism)` (`report.rs:211-219`), no evidence input. OpenShell fs stays **Kernel** mechanism with **CannotProve** evidence pre-U1; it is **not** relabelled Interceptor. See §A.4.
- **F5 — strengthen persistent-fence identity.** Today the fence id is only `FenceBody{mechanism_caveats, mechanism}` (`admitted.rs:183-186`); reuse keyed on `(grant × fs/exec scope)` is unsound. v3 defines a content-addressed **`StaticFenceCid`** over all security-relevant static inputs; reuse requires CID equality. See §A.5.
- **F6 — abstraction before OpenShell.** PR 5 split into **5a** (the execution seam; local behavior unchanged, no OpenShell dep) then **5b** (OpenShell via the seam). See §9.

**Changelog v1→v2 (each item is a conceded review-pass-1 finding):**
- **C1 (was "one small core PR"):** retracted. The `Sandbox` trait is a *local-confinement* contract (`apply` confines the current thread; `command_prefix` wraps local argv); OpenShell is a *remote execution service* with no local child to confine. B requires a **new persistent-fence execution seam** in `spawn.rs`/`best_available_sandbox`, and the local `verify_applied` non-equivocation backstop goes vacuous for a remote fence. **C1-bis (verified against a prior evaluation, reinforces C1):** the seam must *also* supply a **new remote-worker-authentication** mechanism — Bridle's existing worker auth is kernel-local by construction (`agent-bridle-tool-shell/src/private_control.rs`: `SCM_CREDENTIALS` from the worker's real parent + `same_image` dev/ino identity + a pre/post parent snapshot; `agent-bridle-jaild` peer auth via `SO_PEERCRED`). A containerized/remote worker shares no kernel socket, parent, or image with the desk and **fails every check**. This is where B's seam meets E's identity work: the natural remote-worker credential is a mesh AgentKey (attenuated, per-AgentKey dock-pinned), not a kernel peer-cred. PR 5 re-scoped (§9); matrix size/migration rows re-read (§2).
- **C2 (the AND-invariant):** degraded honestly. For the *direct in-sandbox exec path* (wyvern's unconfined `bash`), Bridle is **not** in the per-operation decision path — it authored the fence once, pre-provisioning. `max_calls`/`valid_for_generation`/presence are enforced **only on the mediated MCP channel**, and fs revocation cannot reach a running workload until `DeleteSandbox`. §5.2 and threat rows T18–T19 added.
- **C3 (C prototype safety):** the naive C leaks the operator root key (`~/.newt/identity.pem`) into hostile `bash`, and nested Bridle seccomp/Landlock likely fails closed inside the OpenShell workload. §8 respecified: slice-1 worker = **wyvern** (no confinement to break), desk-minted attenuated AgentKey injected (root key never crosses), in-image capability probe added, `agent-bridle-mcp` placement pinned. Threat row T20.
- **C4 (fence lifetime):** "sandbox-per-grant" made precise — fence = *(session grant × fs/exec scope)*; fs-widen (from Newt's denial→repair loop) forces a new sandbox + workspace-volume handoff. §3 + performance row.
- **C5 (fs epistemic grade / what B buys):** stated plainly — on Linux, native Landlock is **strictly stronger** on fs (local, observed per-invocation); OpenShell's fs "Kernel" is *Kernel-modulo-remote-TCB*. B is a **net + credential + outer-fence acquisition, and an fs downgrade** to be used additively, never as a substitute for desk-local Landlock. The applied-policy hash echo becomes a **certification blocker**, not an open question.
- **C6 (missed authority channel):** the agent-driven policy path (`SubmitPolicyAnalysis` is sandbox-callable; auto-approve on empty prover delta; prover analyzes a different artifact than what is enforced) and provider-profile mutations are widening channels *originating inside the sandbox TCB*. Widen-guard scope expanded (PR 8); precondition `proposal_approval_mode: manual`; threat row T21.
- **D-rejection stands** (§0) but with the caveat that B's own widen-guard is built on the same interceptor substrate D is rejected for — so that guard is *corroborating, not load-bearing*; the always-on kernel/netns fence is what carries B's mediation.

**Pinned commits (interoperability evidence must re-pin):**
- agent-bridle `d1cb545` (v0.8.0-rc.1) + #319/#348 fdguard delta on origin
- newt-agent `4ab6a7be` (branch `step-01-completed-spill-renderer`; delta vs main is TUI-only)
- OpenShell `0f8fad23` (NVIDIA/OpenShell, `feat(sandbox): add stop and start #2653`)
- agent-mesh `9de0a8a` (v0.6.4, one commit past dock-closure `5ff8f3f`)
- wyvern-agent `2fb7107` origin/main (engine/scaffold; the local `1353057` flight-tier is stale)

> **Governing invariant (scope clarified in v2):**
> `achieved_runtime_authority ⊑ projected_execution_authority ⊑ effective_bridle_authority ⊑ delegated_authority`
> OpenShell policy is an **enforcement projection** of Bridle authority, never an independent source of it.
> `ALLOW = Bridle_authorized AND projection_valid AND runtime_floor_satisfied AND OpenShell_allows` — never an OR.
> **v2 scope note:** this is a *scope-level* AND — Bridle authors a bound the always-on kernel/netns fence enforces continuously. It is a *per-operation* AND **only on the mediated MCP tool channel**. On the direct in-sandbox exec path it degrades to "OpenShell enforces a Bridle-authored bound; Bridle's dynamic axes (budget, generation, presence) and prompt revocation do not apply." See §5.2, C2.

---

## 0. Executive summary

- **Recommended target architecture: B — OpenShell as a Bridle `Sandbox`/enforcer backend** (`agent-bridle-openshell` leaf crate + a **non-trivial `agent-bridle-core` change**: a new `SandboxKind` variant, its honest per-axis `enforcement_report` mapping, **and a persistent-fence execution seam** — the current `Sandbox` trait cannot express a remote fence, see C1/§3/F-note). Bridle's `AdmittedFence::admit` remains the sole adjudicator; OpenShell receives a *compiled, post-admission* policy and can only narrow. Topology **A** (a three-layer compiler) is the *deployment face* of the same code, not a competing design — the compiler is the backend's `project` closure.
- **What B actually buys (and what it does not) — corrected in v3 (F1):** B is a **net-enforcement + credential-non-equivocation + outer-fence acquisition**. It gives Bridle, for the first time on Linux, host-allowlist egress enforcement for arbitrary child processes (Interceptor-grade proxy + kernel deny-direct backstop — Bridle's own egress proxy is macOS-only today), credential placeholder/proxy substitution (Bridle has no counterpart), and an outer boundary for *deliberately unconfined* workers (wyvern; Newt's open `b1-os-isolation`). The acquisition is **per-execution-backend, not per-axis on one process**: a command that runs **Local** keeps native desk-local Landlock (fs = Kernel, observed in-process); a command that runs in an OpenShell sandbox (**RemoteFence**) has **all** its axes enforced by in-sandbox mechanisms — its fs is OpenShell's in-sandbox Landlock (**mechanism-Kernel with CannotProve evidence** — §A.4; the mechanism is honestly Kernel, but Bridle cannot prove *this* invocation received the ruleset), and it is **not** additionally constrained by desk-local Landlock, which cannot reach a remote container. Because the fs floor is structurally Kernel, a **restricted-fs RemoteFence execution refuses admission pre-U1** unless the operator sets an explicit, visible `CannotProve` evidence floor — it is never silently admitted. The "additive" benefit is a **fleet** property (route fs-sensitive work Local, egress-sensitive/unconfined work Remote), never a within-process axis split. See §A.1/§A.4.
- **Rejected: D — Bridle as an OpenShell authority subsystem.** OpenShell's only sanctioned interposition point (gateway interceptors) cannot mediate `ExecSandbox` (streaming), reads, or the new `StopSandbox`/`StartSandbox`, has an unauthenticated transport to the interceptor, and is blind to prior state. Complete mediation cannot be built on it. Revisit only if upstream closes those gaps.
- **Migration path: C → B → A, with E (the swarm) as a parallel track gated on a transport prerequisite.** C (Newt or a worker *inside* one OpenShell sandbox, reached by an `agent-bridle-mcp` authority) is the cheapest interop proof and it exercises the real wire. B is the actual integration. A is B deployed as a compiler service. **E** — your Drake-Swarm shape, `newt → agent-mesh → OpenShell → wyvern` — is the aspirational capstone but is **blocked at the transport layer**: agent-mesh is QUIC/UDP with relay disabled, OpenShell egress is a TCP-only HTTP CONNECT proxy behind an nftables UDP reject. E is unreachable until a TCP/WebSocket mesh `Transport` and per-AgentKey dock pinning exist. Do not start with E.
- **The honest ceiling:** OpenShell can *prove* (kernel/e2e-verified) filesystem confinement and deny-by-default egress; it can only *log* — unsigned, lossy, self-reported — that any control is actually active, and it records no *running-image* digest. So `AppliedPolicyCid`/`RuntimeEvidenceCid`/`AttestedImageCid` are **Cannot-Prove** upstream today (distinct from `RequestedImageCid`, the digest Bridle *pins* — intent, not proof; §A.5). The integration is safe to *build* and *demo*; it is not safe to *certify* until the assurance residuals below are closed with native hostile-child evidence.

---

## A. Execution / enforcement / identity model (v3 — NORMATIVE)

> **Label note:** the normative sections **§A / §B / §C** (this block) are distinct from the candidate **topologies A–E** (§2). "§A.4" is a section reference; "topology B" / "B backend" / "A as its face" refer to topologies. The `§` prefix always marks a section.

**This section is authoritative.** Where any looser language elsewhere in this RFC (or in v1/v2) conflicts with it, this section wins. It resolves the six review-pass-2 findings. All claims are grounded in the current tree (agent-bridle `d1cb545`+#348).

### A.1 Three separated concepts — execution ≠ mechanism ≠ evidence (F1)

**Fact — no separation exists today.** `SandboxKind` (`sandbox.rs:45-78`) enumerates only *per-OS, desk-local mechanisms that are simultaneously execution models* (Landlock, Seatbelt, AppContainer, MinimalRootfs, MicroVm, None). The `Sandbox` trait (`sandbox.rs:84-157`) bundles both: `apply(&Caveats)` confines the **calling thread** (Landlock `restrict_self`, per-thread, irreversible, inherited only across *that thread's own* `fork`/`execve` — `sandbox.rs:1128-1131`), and `command_prefix` wraps **local argv** (`sandbox-exec`/`aclaunch`). `best_available_sandbox` (`sandbox.rs:546-571`) returns exactly **one** `Box<dyn Sandbox>` by a returning cascade — there is **no composition**; one spawn gets one backend (`spawn.rs:508-509`).

**Contract — separate the three concepts:**

1. **ExecutionBackend** — *where/how* the command runs: `Local` (a desk-local child) or `RemoteFence(handle)` (a process inside an OpenShell sandbox). **One execution has exactly one ExecutionBackend.**
2. **EnforcementMechanism** — *which* mechanism enforces *each* fence axis, **at the execution location**. A mechanism can only enforce an axis of an execution that runs *where the mechanism lives*.
3. **Evidence** — *what proves* a mechanism was applied to *this* invocation (§A.4), distinct from mechanism identity.

**The impossible-conjunction ban.** `restrict_self` confines only the calling desk thread; it has no reach into a remote container. Therefore a process inside an OpenShell sandbox is **not**, and **cannot** be, constrained by desk-local Landlock. For a RemoteFence execution, *every* axis is enforced by an in-sandbox mechanism or by nothing. The v2 "native Landlock for fs + OpenShell for net on the same process" framing is **retracted**; that split is valid only at the **fleet** level.

**Required answer — "for a worker executing inside OpenShell, what enforces `fs_read`/`fs_write`, and what strength may Bridle claim?"** The mechanism is **OpenShell's in-sandbox Landlock** (the supervisor's `restrict_self` on the workload), MechanismStrength **Kernel** (it constrains the child interior — honestly Kernel, not Interceptor). Its per-invocation **evidence is CannotProve** pre-U1 (only a self-reported `LOADED` integer). The claim is the **product** `(mechanism=Kernel, evidence=CannotProve)` (§A.4) — *not* a scalar downgrade to Interceptor. Native desk-local Landlock (a Local execution) is `(Kernel, observed-in-process)`; a remote fs axis is therefore **evidence-weaker for the same caveats**, and because the fs floor is structurally Kernel, a restricted-fs RemoteFence **refuses pre-U1** unless the operator accepts an explicit `CannotProve` evidence floor.

### A.2 Fence authority vs Gate authority (F3)

**Fact — the split already exists.** `report.rs:147-153`: the four `fs_read/fs_write/exec/net` are "OS-confinement axes"; `max_calls`/`valid_for_generation` are "gate-enforced budget/causality, **not** OS-confinement axes." Both gate axes are enforced only inside `Gate::authorize` — a software generation check (`gate.rs:228-238`) and an atomic compare-and-decrement budget (`gate.rs:244-270`), called per authorize (`gate.rs:211,216`); `SandboxKind` is consumed only later at the mint site (`gate.rs:219-223`). No OS mechanism backs them.

**Contract — name the product and quantify projection over the fence subset:**

```
EffectiveCaveats = FenceCaveats × GateCaveats
FenceCaveats = { fs_read, fs_write, exec, net }      -- projectable to a mechanism
GateCaveats  = { max_calls, valid_for_generation }   -- Gate-only ( + presence/step-up, composed via StepUpPolicy )

project : (FenceCaveats, RuntimeCapabilities) -> OpenShellPolicySpec | Unsupported
theorem :  authority(project(fence(c))) ⊑ fence(c)          -- I1, never widen
```

GateCaveats are **not projected**. Per-caveat behavior by path:

| GateCaveat | Mediated MCP / Gate path | Direct in-sandbox exec (unmediated shell) |
|---|---|---|
| `max_calls` | **Exact** (Gate charges the budget per authorize) | **Unsupported** — the Gate is not in the syscall path |
| `valid_for_generation` | **Exact** (Gate checks the generation per authorize) | **Unsupported** |
| presence / step-up | **Exact** (discharge verified per authorize) | **Unsupported** |

**Admission rule (fail-closed, I2).** If a grant carries a *restrictive* GateCaveat (non-`⊤` `max_calls`, bounded `valid_for_generation`, or a presence requirement) **and** the execution model exposes a direct unmediated exec path (a worker that can run arbitrary shell, not a mediated-tool-only surface), `admit` MUST **refuse**. No mechanism enforces a per-operation budget or presence gate over unmediated bash. The grant is satisfiable only if the worker has **no** direct-exec authority (every op crosses the Gate) or the grant does not restrict the GateCaveat. Do not admit and pretend (adversarial case 8).

### A.3 Authority identity vs execution identity — the remote grain is sandbox, NOT process (F2; R3-1)

Three distinct grains, never conflated:

- **ExecutionIdentity** — proves facts about a *specific process / executable*. **Local:** the kernel-local proof — `SCM_CREDENTIALS` from the real parent (fail-closed on absence, `private_control.rs:394-418`), `same_image` dev/ino (`private_control.rs:36-44,71-76`), a parent pre/post snapshot (`verify_parent`, `private_control.rs:450-464`); `SO_PEERCRED` in `jaild` (`broker.rs:98-131`). **Remote:** **unavailable** across the container boundary (C1-bis) — no shared kernel socket, parent, or image inode.
- **AuthorityIdentity** — proves *possession of delegated cryptographic authority* (a mesh AgentKey / attenuation-only Grant chain, `child ⊑ parent`). Possessing a key says nothing about which process or image holds it.

**The remote binding proves sandbox-grain delegation, not per-process execution (Outcome A — chosen, intentionally weaker, made visible).** A desk-side broker can bind *what Bridle intended to authorize for a sandbox*; it **cannot** prove *which process/executable inside that sandbox produced a result*. Keeping the root AgentKey outside the sandbox fixes root-key exposure (T20) but does **not** restore `SCM_CREDENTIALS` / real-parent continuity / `same_image` / `SO_PEERCRED`. Once a narrow credential lives inside a hostile sandbox, **another process in the same sandbox can exercise it**, and the worker executable can be replaced in place — neither is detectable by the binding. We therefore **do not** claim remote ExecutionIdentity. The remote object is renamed to make its grain honest:

```
SandboxPrincipalBinding {   // theorem: "this authority was delegated to THIS sandbox execution ENVIRONMENT"
                            //          NOT "this particular process/executable performed the work"
    authority_cid,          // the EffectiveAuthorityCid / grant exercised (mesh AuthorityId/GrantId)
    sandbox_instance_cid,   // OpenShell sandbox UUID, content-addressed              [net-new]
    requested_image_cid,    // the digest-pinned image Bridle REQUESTED (intent, NOT proof of what ran; §A.5, HIGH 4)  [net-new]
    enforcement_plan_cid,   // the admitted plan (mechanisms + fence caveats)         [net-new]
    static_fence_cid,       // §A.5                                                   [net-new]
    generation,             // causal, per valid_for_generation (NOT wall-clock; caveats.rs:159-161)
    expiry_generation,      // causal window (freshness = generations, per step_up)
    audience,               // session/dock scope the binding is valid for
}
```

It is a content-addressed object built with the existing `content-addressable` `ContentId` + `to_canonical_dagcbor` machinery, **domain-tagged** in the mesh's `Tagged{kind, body}` style (`authority.rs:43-44`, e.g. `"agent-bridle/sandbox-principal-binding/v1"`) — note `FenceBody` today is **not** domain-tagged (`admitted.rs:182-192`), a gap this design must not copy. Construction MUST follow the `ResolvedGrant::bind` pattern (`authority.rs:298-311`): only constructible when the body's CID equals the named authority — mismatch is *unrepresentable*, not merely checked. The desk accepts a remote result **only if** the proof resolves to a `SandboxPrincipalBinding` whose fields match the intended authority, sandbox instance, requested image, plan, and current generation (I5a); a binding minted for S1 fails for S2, a stale one fails the generation check.

**What this does NOT catch, stated prominently:** a *different process in the same sandbox* using the narrow credential, and a *replaced executable in the same sandbox*, both pass `SandboxPrincipalBinding` — the grain is the sandbox, not the process (adversarial cases 1c/1d). Cross-sandbox replay is caught; intra-sandbox substitution is **not**.

**Outcome B (real remote execution attestation) is an upstream/TCB dependency, not available today.** Per-process remote identity would require a trusted in-sandbox observer to attest `{sandbox instance, actual process identity, actual executable identity, generation, authority, enforcement plan, result}`. OpenShell provides no such attestation at the pinned commit; its supervisor is the only in-sandbox trusted component and it does not sign per-process statements (see HIGH 6 / U1). If B ever needs fixed-worker remote identity, that is a **named certification dependency on a supervisor/broker workload-attestation mechanism** (SPIFFE-SVID-style, issuer/verifier/audience specified), not something `SandboxPrincipalBinding` supplies. Until then, the remote principal grain **is** the sandbox environment, and callers that require process-grain identity must run **Local**, not RemoteFence.

**Trust model: brokered (root key never enters the worker).** A trusted desk-side broker (the dock registry that already gates responders) mints the `SandboxPrincipalBinding` for an identified sandbox and hands the worker only a narrow, sandbox-scoped, short-lived credential. This bounds root-key exposure and cross-sandbox replay; it does **not** bound intra-sandbox reuse (above), which is inherent to the sandbox grain.

### A.4 Enforcement claim is a PRODUCT of mechanism × evidence, not a scalar min() (F4; R3-2)

**Fact.** `AxisEnforcement` (`Kernel > Interceptor > Advisory`, hand-ordered ascending `rank`, `report.rs:88-132`) is computed by `enforcement_report(effective, mechanism)` — a **pure function of `(effective, mechanism)`** with **no** evidence input (`report.rs:211-219`). Its variants have *mechanical* meaning: **Kernel** = OS rules constrain the spawned program's **interior** (`report.rs:94`); **Interceptor** = in-process chokepoint only, child interior **not** constrained; **Advisory** = admission validation, no runtime backstop. Admission is `report[axis] >= floor[axis]` for every restricted axis (`report.rs:348-349`), and the **filesystem floor is structurally pinned to `Kernel`** — `fs_read = fs_write = Kernel` is unrepresentable otherwise (`report.rs:370-395`, hand-written serde, `deny_unknown_fields`).

**Why the v2 `min(MechanismStrength, EvidenceCap)` was wrong.** OpenShell's in-sandbox Landlock **does** constrain the child interior — it is a **Kernel-class mechanism** with weak evidence, *not* an Interceptor. Collapsing it to `Interceptor` **lies about the mechanism class** (overloading `Interceptor` to mean "Kernel but poorly evidenced"), and — because the fs floor is Kernel — it makes `report.fs = Interceptor >= floor.fs = Kernel` **false**, so admission refuses anyway, for the wrong stated reason. Model the claim as a **product**:

```
EnforcementClaim { mechanism: MechanismStrength, evidence: EvidenceStrength }
order:  (m1,e1) ⊒ (m2,e2)  iff  m1 ⊒ m2  AND  e1 ⊒ e2        -- componentwise (verify vs the assurance algebra before adopting)
EvidenceStrength:  Attested  ⊐  Reported  ⊐  CannotProve      -- per-invocation; NET-NEW type (assurance manifest is claim-level only)

admit(axis)  iff  claim.mechanism ⊒ floor.required_mechanism
              AND  claim.evidence  ⊒ floor.required_evidence
```

- The OpenShell fs mechanism stays **Kernel** in `enforcement_report` (honest: the child interior is Landlock-constrained). `AxisEnforcement` is **not** corrupted.
- Its per-invocation **evidence** is **CannotProve** pre-U1 (a self-reported `LOADED` integer is not proof this invocation received the intended ruleset), rising to **Attested** once U1 lands.
- The floor gains a **required_evidence** component alongside the existing required_mechanism; the fs mechanism floor stays Kernel.

**Explicit fs admission rule pre-U1 (the load-bearing consequence — YES, it is intentional).** For a RemoteFence execution with a restricted `fs_read`/`fs_write` Caveat: `claim = (mechanism=Kernel, evidence=CannotProve)`. The mechanism floor (Kernel) is met, but any `required_evidence` above `CannotProve` is **not**. Therefore:

> **Restricted-filesystem RemoteFence authority cannot be admitted with an evidence floor above `CannotProve` until U1 closes the per-invocation evidence requirement.** Pre-U1, such an execution is admitted **only** if the operator has *explicitly* set the fs evidence floor to `CannotProve` — a visible, recorded downgrade — otherwise `admit` **refuses**, fail-closed. It is never silently admitted by pretending the mechanism is weaker than Kernel.

This keeps four questions separately answerable (R3-2): *what mechanism exists* (Kernel), *what authority it enforces* (the fence caveats), *what evidence we have that THIS execution received it* (CannotProve pre-U1), *what the caller requires* (mechanism + evidence floors).

### A.5 Static fence identity — requested image only; attested image is evidence-side (F5; HIGH 4)

**Fact.** A fence's identity today is `FenceBody { mechanism_caveats, mechanism }` (`admitted.rs:183-186`, un-domain-tagged) — it omits the runtime closure (`RuntimeClosure` exists at `admitted.rs:97-100` but has no CID), image, spec, floor, and capability probes. Reuse keyed on `(grant × fs/exec scope)` is **unsound**.

**Contract — a content-addressed `StaticFenceCid`** (net-new; domain-tagged) over *all* security-relevant static inputs. It carries the **RequestedImageCid** (what Bridle pinned) — strong intent, a legitimate part of the static identity — and **never** the attested running image (which is evidence, not identity):

```
StaticFenceCid = H_tagged(
    static_authority     = fence(mechanism_caveats),   // existing Caveats
    mechanism            = ConfinementMechanism,        // existing
    runtime_closure_cid  = H(RuntimeClosure),           // value exists (admitted.rs:97-100); CID net-new
    requested_image_cid,                                // net-new; digest-pinned INTENT (NOT proof of what ran)
    openshell_spec_cid,                                 // net-new (static sandbox spec)
    enforcement_floor    = EnforcementFloor,            // existing
    runtime_capabilities,  // nft present? Landlock ABI? seccomp-filter permitted? (probed)
    policy_compiler_version,
    authority_generation_baseline
)
```

**RequestedImageCid vs AttestedImageCid (HIGH 4).** A digest-qualified image reference proves *what Bridle asked to run*; it is **not** evidence of *what OpenShell actually launched*. These are separate facts, held to the same epistemic discipline as `OpenShellPolicyCid` (ours, canonical intent) vs `AppliedPolicyCid` (attested runtime): `RequestedImageCid` is intent and lives in `StaticFenceCid`/`SandboxPrincipalBinding`; **`AttestedImageCid`** is evidence, **Cannot-Prove today** (OpenShell records no running-image digest — U3), and enters only the evidence dimension (§A.4), never the static identity. `SandboxPrincipalBinding` MUST NOT imply actual-image proof.

**Reuse rule (I4):** a coarse `(grant × scope)` key MAY index the cache, but reuse requires **`StaticFenceCid` equality**. Dynamic net policy binds via a *separate* `(OpenShellPolicyCid, generation)` and **never** mutates `StaticFenceCid` (adversarial case 11). Any static-input change → different `StaticFenceCid` → no reuse (adversarial cases 5, 6).

### A.6 Exec is identity authority — a normative fail-closed admission theorem (HIGH 5; R3-5)

Bridle's `exec` axis is **identity authority**: *no ungranted program may execute*. It is **not** satisfied by bounding a program's behavior via fs/net. OpenShell has **no kernel exec allowlist**; every binary present in the image may execute, and the running image is unattested (§A.5). Therefore, normatively:

> For any execution (Local or RemoteFence) that carries **direct exec authority** (can create arbitrary processes): a **restrictive `exec` Caveat** (`Only(_)`, not `All`) is admissible **only if** a concrete mechanism proves `actual_executable_closure ⊆ granted_exec_scope`, **or** execution is fully mediated so arbitrary direct process creation is impossible. Absent such a mechanism, `admit` **REFUSES** (`Unknown ⇒ refuse`), fail-closed, before any spawn.

For a RemoteFence worker with a shell, no such mechanism exists at the pinned OpenShell commit (image closure is unpinned/unattested; there is no in-sandbox exec broker). Consequently a restrictive `exec` grant over a direct-exec RemoteFence worker is **refused**, not approximated. A worker may hold restrictive `exec` only if it is **mediated-tool-only** (no arbitrary process creation), exactly as the GateCaveat rule in §A.2. `RequestedImageCid` is intent, never exec proof (adversarial cases 13a–13c).

### B. Formal / security invariants (refined in R3)

- **I1 — No authority widening.** For every enforceable projected (fence) axis: `authority(project(fence(c))) ⊑ fence(c)`. Property-tested; TLA+/Lean non-amplification model reusing the ADR 0026 harness. *(Preserved.)*
- **I2 — No unsupported-caveat masquerading.** A caveat not enforced on a given execution path MUST NOT be reported as enforced because another path would enforce it (GateCaveats on direct-exec → Unsupported, not Exact). *(Preserved.)*
- **I3a — Mechanism honesty.** The reported mechanism (`AxisEnforcement`) equals the mechanism actually relied upon. OpenShell in-sandbox Landlock is reported **Kernel**, never downgraded to Interceptor to signal weak evidence.
- **I3b — Evidence honesty.** The reported per-invocation evidence ≤ the evidence actually possessed (`Attested ⊐ Reported ⊐ CannotProve`). Admission requires `mechanism ⊒ required_mechanism AND evidence ⊒ required_evidence`; confidence never alters mechanism identity.
- **I4 — Fence-identity completeness.** Any security-relevant static-input change produces a different `StaticFenceCid` or forces invalidation; reuse requires CID equality, never a coarse key alone. The static identity carries `RequestedImageCid` only. *(Preserved.)*
- **I5a — Sandbox-principal binding.** A remote result is accepted only if its proof binds the intended authority, sandbox/fence instance, requested image, enforcement plan, generation/lifetime, and audience — at **sandbox** grain.
- **I5b — Execution identity.** *Local:* the kernel process/image proof holds and is unchanged. *Remote:* per-process execution identity is **unavailable** unless separately attested by a **named** mechanism (Outcome B / U1-class). I5 MUST NOT claim remote process identity the architecture cannot prove.
- **I6 — No local-identity downgrade.** Introducing remote execution MUST NOT weaken the existing local `SCM_CREDENTIALS`/`SO_PEERCRED`/real-parent/`same_image` path. The local path is unchanged; the remote path *adds* a separate, weaker-grain binding, never relaxes the local one. *(Preserved.)*

### C. Test / proof obligations (implementation acceptance criteria — NOT built in this docs PR)

Each maps to the invariant it guards; express as future property tests or model-checkable invariants.

| # | Adversarial case | Guards | Expected |
|---|---|---|---|
| 1a | captured credential used from a *different* sandbox | I5a | reject (`sandbox_instance_cid` mismatch) |
| 1b | credential reused after a generation change | I5a | reject (past `expiry_generation`) |
| **1c** | **different process in the SAME sandbox uses the narrow credential** | I5b | **NOT caught by the binding** — documented sandbox-grain limit; only Local grain or Outcome-B attestation catches it |
| **1d** | **worker executable replaced in the SAME sandbox** | I5b | **NOT caught by the binding** — same as 1c; RequestedImageCid is intent, not runtime proof |
| 2 | correct credential + wrong enforcement-plan CID | I5a | reject (`enforcement_plan_cid` mismatch) |
| 3 | correct credential + wrong requested-image CID | I5a | reject (`requested_image_cid` mismatch) |
| 4 | valid sandbox binding attached to a result from an **unattested** process | I5b | accepted only at sandbox grain; MUST NOT be reported as process-attested |
| 5 | fence reused after runtime closure changes | I4 | no reuse (`StaticFenceCid` differs) |
| 6 | fence reused after static OpenShell policy changes | I4 | no reuse (`StaticFenceCid` differs) |
| 7a | provider reports `LOADED` but applied-policy CID differs | I3b | evidence = CannotProve; refuse if evidence floor above it; **mechanism stays Kernel** (never relabelled Interceptor) |
| 7b | `mechanism=Kernel, evidence=CannotProve` preserved as **two** facts | I3a+I3b | claim carries both; evidence never changes mechanism class |
| 8 | **restricted-fs RemoteFence, pre-U1** | I3b | refuse **unless** operator explicitly set fs evidence floor = CannotProve (visible downgrade) — §A.4 |
| 9 | direct exec attempts to claim `max_calls` enforcement | I2 | admission refuses the grant (§A.2) |
| 10 | local worker with wrong parent/image | I6 | reject (unchanged local proof) |
| 11 | dynamic net-policy generation mutates static fs/exec identity | I4 | impossible — `StaticFenceCid` excludes dynamic policy |
| 12 | requested image CID ≠ observed/attested running image | I3b/I4 | RequestedImageCid unchanged (intent); AttestedImageCid = CannotProve; never conflated |
| 13a | `exec={worker}`, image also contains `/bin/bash`, run `/bin/bash` | A.6 | refuse before execution OR kernel-denied |
| 13b | `exec=none`, remote direct exec requested | A.6 | refuse |
| 13c | image-reference CID known but running image unattested | A.6 | MUST NOT become exact exec proof |
| 14 | **5c RemoteFence cannot compile/accept a result without 5b identity objects** | R3-3 | type error / admission refuse — 5b lands before 5c |
| 15 | U1 report from wrong sandbox identity | HIGH 6 | rejected (gateway authenticates the sandbox channel) |
| 16 | U1 stale-generation report | HIGH 6 | rejected (generation/sequence bound in the receipt) |

---

## 1. The three planes, as actually built

**newt-agent (harness/orchestration).** The reasoning loop (`newt_core::agentic`) already funnels every confined execution through exactly three Bridle seams (`bridle_registry().dispatch`, `ConstrainedExecutor`, `ConfinedCommand::spawn_tokio` for MCP), and a CI ratchet (`ocap_check.py` + `spawn-inventory.toml`) mechanically forbids new raw-spawn sites. Enforcement types are *deliberately* in the reasoning crate so bypass is uncompilable (witness types `LeasedMcpCall`, `AdmittedServer`). Consequences for this study: "Newt on Bridle, never raw OpenShell" is nearly free; the headless worker shape already exists as `newt-acp-worker` (stdio, edits-only, per-turn attenuated signed Caveats); and Newt's own open `b1-os-isolation` deviation is *exactly* the hole an OpenShell outer sandbox closes — this integration is the closing move for Newt's OCAP epic, not a bolt-on.

**agent-bridle (authority).** Authority = mesh `Caveats` (6 axes: `fs_read`,`fs_write`,`exec`,`net` OS-confinement + `max_calls`,`valid_for_generation` gate-enforced), a meet-semilattice with **no join/amplify operation anywhere**. `effective = granted.meet(required)` is minted once in `Gate::authorize`; `AdmittedFence::admit` is the sole adjudicator, taking a `project: FnOnce(&Caveats)->BackendProjection` — *the only place a `Sandbox` participates* — and fail-closing on `Unknown`. Achieved strength is `Kernel > Interceptor > Advisory`, hand-ordered, GLB'd per fence, never stored. fs floors are structurally pinned to `Kernel` (unrepresentable otherwise). The `Sandbox` trait (4 methods) is the backend contract; `SandboxKind` is a closed enum by design so every new mechanism must *state* its per-axis truth. ADR 0026 (POSIX projection, merged) is the template: no new authority carrier, project-only-what-you-can-mediate-honestly, `Unknown ⇒ refuse`, per-platform honesty, no merge without a hostile-child native test + assurance row.

**OpenShell (execution).** Gateway control plane (gRPC, OIDC/mTLS/sandbox-JWT auth, proto-annotation authz) + per-sandbox in-container supervisor (root PID 1, `apparmor=unconfined`, `CAP_SYS_ADMIN/NET_ADMIN/SYS_PTRACE`) that drops the workload to an unprivileged UID under Landlock + seccomp + a per-sandbox netns whose nftables rejects all non-proxy TCP/UDP. Egress is an explicit HTTP CONNECT proxy with TLS MITM (ephemeral per-sandbox CA), OPA/Rego host+L7 policy, proxy-side DNS (rebinding-safe), and **credential placeholders substituted at the proxy** (workload never holds secrets — invariant 3 substantially pre-solved). Policy is a 5-domain YAML/proto spec (filesystem/landlock/process static; network/middleware dynamic) with a hot-reload that kills in-flight relays on every policy-generation change.

**agent-mesh + wyvern (the swarm substrate).** `Caveats` lives here (Bridle re-exports it). A content-addressed `Grant`/`Derivation`/`verify_chain` machinery exists — attenuation-only, fail-closed, rooted at an operator-configured trusted root — but is **entirely unused on the wire**. Docks (PR #75) give a verified-caller `RequestContext` bound to the QUIC session key. wyvern's worker is ~700 lines: one flat loop, four tools, and an **unconfined `bash -lc`** — its entire security model is "the sandbox around me," which is precisely why the OpenShell topology is coherent.

---

## 2. Architecture decision matrix

Scores: ✅ strong · ⚠️ conditional/partial · ❌ weak/blocked. "≈" = same as another row by construction.

| Axis | A (3-layer compiler) | **B (OpenShell as Bridle backend)** | C (agent in sandbox + bridle-mcp) | D (Bridle via OpenShell extension) | E (newt→mesh→OpenShell→wyvern swarm) |
|---|---|---|---|---|---|
| **Security / one authority root** | ✅ compiler binds grant→policy | ✅ `admit` is sole adjudicator; policy is post-admission | ⚠️ sound iff outer sandbox bounds all bypass | ❌ interceptor can't mediate exec/stream/stop | ⚠️ ≈B for authority; +hostile-worker & auto-team risk |
| **Complete mediation** | ✅ | ✅ | ⚠️ depends on sandbox completeness | ❌ 25-RPC allowlist omits Exec/Stop/Start/reads | ⚠️ ≈C, per worker |
| **Implementation size** | ⚠️ compiler + service | ✅ leaf crate + 1 small core PR | ✅ smallest (config + mcp wiring) | ❌ needs upstream API changes | ❌ B + mesh transport + dock pinning + wyvern responder |
| **Coupling** | ✅ OpenShell types isolated in backend | ✅ ditto; Newt never sees OpenShell | ✅ Newt sees only mcp | ⚠️ Bridle must speak gateway internals | ✅ cleanest: Newt speaks mesh; wyvern speaks mesh; neither sees the other's core |
| **Upstream compatibility** | ✅ uses public gRPC/policy API | ✅ same | ✅ same | ❌ needs new upstream extension points | ✅ (OpenShell side ≈B) |
| **Linux** | ✅ | ✅ | ✅ | ⚠️ | ✅ |
| **macOS / Windows** | ⚠️ OpenShell is Linux-container-centric; keep native Bridle backends there | ✅ Bridle already has Seatbelt/AppContainer; OpenShell backend is *additive* | ⚠️ needs a Linux sandbox host | ❌ | ⚠️ desk anywhere, sandboxes Linux |
| **Docker/Podman** | ✅ | ✅ | ✅ | ⚠️ | ✅ |
| **microVM** | ✅ | ✅ strongest isolation for the fence | ✅ | ⚠️ | ✅ |
| **Kubernetes** | ✅ (gateway on k3s, sandboxes as pods) | ✅ | ✅ | ⚠️ | ✅ (the swarm's natural substrate) |
| **Local inference (Ollama/vLLM/dgx1)** | ✅ config-only redirect | ✅ | ✅ | ⚠️ | ⚠️ `inference.local:443` bypasses OPA — must be a projected route |
| **Remote inference** | ✅ | ✅ | ✅ | ⚠️ | ✅ credential-stripped at proxy |
| **Credential handling** | ✅ placeholder+proxy substitution | ✅ (invariant 3 ~solved by OpenShell) | ✅ | ⚠️ interceptor sees redacted only | ✅ workers never hold secrets |
| **Observability** | ⚠️ unsigned/lossy OCSF | ⚠️ same | ⚠️ same | ⚠️ | ⚠️ same + mesh provenance gaps |
| **Formal-verification potential** | ✅ projection theorem is small & TLA/Lean-able | ✅ reuses ADR 0026 pattern + assurance manifest | ⚠️ bypass proof is a hostile-test obligation, not a theorem | ❌ | ⚠️ ≈B + mesh chain proofs (exist, unused) |
| **Performance** | ⚠️ sandbox create ~seconds (persistent, amortized *iff* fs/exec scope stable per session) | ⚠️ amortized only within a fixed fs/exec scope; an fs-widen forces a new sandbox + volume handoff (C4) | ✅ | ⚠️ | ⚠️ per-worker sandbox cost |
| **Migration risk** | ⚠️ largest single step | ⚠️ incremental & additive, but core gains a persistent-fence exec seam (C1) — not a pure leaf | ✅ lowest | ❌ blocked on upstream | ❌ highest (transport gap) |
| **fs axis vs native Landlock** | downgrade | **downgrade** (Kernel-modulo-remote-TCB, C5) | downgrade | — | downgrade |
| **net axis vs native Bridle** | **upgrade** (host-allowlist egress for children; Bridle proxy is macOS-only) | **upgrade** | upgrade | — | upgrade |

**Reading of the matrix (v2):** B still wins on coupling, upstream-compat, and migration *direction* (additive), and it is the only design that gives Bridle host-allowlist egress + credential non-equivocation on Linux. But it is **not small** (C1) and it is **axis-split**: a net/credential/outer-fence *upgrade* and an fs *downgrade* versus Bridle's own Landlock (C5). A is B's deployment face. C is the cheapest *proof* and a necessary de-risking step, not an end state. D is rejected. E is the most elegant and the one your Drake-Swarm design wants — gated behind a transport prerequisite and the auto-team residual, so it is a *later* track, not the first move.

---

## 3. Recommended target architecture — **B, with A as its face**

> **Read §A first — it is the normative model.** This section describes the backend shape; §A governs the execution/mechanism/identity separation, the fence/gate split, the strength-vs-evidence cap, and the fence identity. Any conflict resolves to §A.

Bridle stays the sole authority. Add one leaf crate `agent-bridle-openshell` (holds tonic/tokio, gateway client, lifecycle — off the trusted core, per the jaild/aclaunch precedent) **plus a core change that is larger than a new enum arm** (C1). The backend's job is a total function **over the fence subset** (§A.2), never over the gate axes:

```
project : (FenceCaveats, RuntimeCapabilities) -> OpenShellPolicySpec | Unsupported
    such that   authority(project(fence(c))) ⊑ fence(c)     (I1, never widen)
    where       fence(c) = { fs_read, fs_write, exec, net }        -- NOT max_calls / valid_for_generation
```

The backend is registered under an **ExecutionBackend::RemoteFence** (§A.1), not as another local `SandboxKind` variant selected by `best_available_sandbox`; a RemoteFence execution receives its enforcement entirely from in-sandbox mechanisms.

**The core-surgery reality (C1).** The existing `Sandbox` trait is a *local-confinement* contract: `apply(&Caveats)` confines the calling thread (Landlock `restrict_self` on a throwaway spawn thread) and `command_prefix` wraps *local* argv (Seatbelt/`aclaunch`). OpenShell has **no local child to confine** — the workload is spawned by the supervisor inside a remote container. So B cannot be "implement two trait methods":
- Core needs a **third execution mode — a persistent remote fence** — introduced as an `ExecutionBackend` selection *above* `ConfinedCommand::spawn`. **`best_available_sandbox` stays a LOCAL enforcement-mechanism selector and MUST NOT be extended to select or auto-discover a remote backend** (R3-3): `ExecutionBackend::Local → best_available_sandbox() → local child`; `ExecutionBackend::RemoteFence → remote backend, no best_available_sandbox() call`. Today's local path uses a fresh-boxed backend *per spawn* (one hardcoded `cfg` arm per kind); the remote path is a distinct, reusable, seconds-to-create fence that never enters that cascade. This touches `spawn.rs`, the most audit-sensitive file in Bridle (home of the #317 nineteen-violation audit); it must carry the same admission discipline, not be bolted on.
- **Remote-worker authentication is a distinct sub-problem the seam must solve (C1-bis).** Bridle authenticates a spawned worker with kernel-local primitives — `SCM_CREDENTIALS` from the real parent, `same_image` (dev/ino) identity, and a parent pre/post snapshot in `agent-bridle-tool-shell/src/private_control.rs`; `SO_PEERCRED` in `agent-bridle-jaild`. None of these can authenticate a worker running in a remote container: no shared kernel socket, no parent relation, no shared image inode. The remote fence therefore needs a **cryptographic worker identity** in place of peer-creds — the mesh AgentKey (attenuated, per-AgentKey dock-pinned) is the natural fit, which is why B's execution seam and E's identity/dock work are coupled and should be designed together even though B ships first.
- The local `verify_applied` backstop (recompute the CID of "the caveats about to be applied", refuse on mismatch — spawn.rs:607) **goes vacuous** for a remote fence: "about to be applied" becomes a gRPC hop ending in a self-reported integer. B must replace it with an *evidence-returning* admission (see the applied-policy hash-echo, now a certification blocker, §10) or explicitly record the lost backstop as an assurance residual.
- A `ConfinementMechanism` config carrier must transport *probed* runtime state (nft presence, `hard_requirement`, Landlock ABI) into the honesty mapping, since the same OpenShell-projected EnforcementMechanism enforces differently per probe. (The OpenShell mechanism needs a `enforcement_report` arm as a *mechanism identity*, but it is reached via `ExecutionBackend::RemoteFence`, **not** auto-selected as a local `SandboxKind` by `best_available_sandbox` — §A.1.)

- **Where the compiler lives:** inside the backend crate, desk-side (in the trusted host, *not* in the sandbox). It is exactly `AdmittedFence::admit`'s `project` closure. `admit` runs first; the compiler only ever sees post-`meet` effective caveats.
- **How projection is validated:** the backend implements `resolved_authority`/`runtime_closure` as a *conservative hostile-child upper bound* computed from the **same** routine that emits the policy (anti-drift), so `admit` can prove `resolved ⊑ delegated ∪ runtime_closure` at ruleset grain and refuse on `Superset|Incomparable|Unknown`. Anything OpenShell cannot bound (exec identity, ICMP/SCTP, audit-mode endpoints) resolves `Unknown ⇒ refuse`.
- **How dynamic policy updates are authorized:** narrowing (revoke, tighten) compiles freely and pushes via `UpdateConfig`; **widening requires a new grant → new `EffectiveAuthorityCid` → new `EnforcementPlanCid` → new policy submission.** A gateway interceptor on `UpdateConfig` (which *is* interceptable) denies any policy transition not carrying a valid enforcement-plan CID the authority service authored. The interceptor can't see prior state, but the authority service can — it wrote every admitted policy.
- **How isolation evidence returns to Bridle:** today, weakly — a self-reported version integer. The backend must therefore treat runtime attestation as `partial` (assurance-manifest row), and the *real* evidence for a `Kernel` claim is our own native hostile-child test run inside the pinned image at integration time. Upstream asks (below) would upgrade this.
- **How strength floors operate (product model, §A.4):** the backend emits an `EnforcementClaim{mechanism, evidence}` per axis; admission requires `mechanism ⊒ required_mechanism AND evidence ⊒ required_evidence`. fs mechanism is honestly **Kernel** iff it compiled `landlock.compatibility: hard_requirement` + non-empty paths (else it fails the fs *mechanism* floor and `admit` refuses); its **evidence is CannotProve** pre-U1. Since the fs floor is structurally Kernel and any evidence floor above CannotProve is unmet, a **restricted-fs RemoteFence refuses pre-U1** unless the operator sets an explicit `CannotProve` fs evidence floor. The mechanism is **never** relabelled Interceptor to signal weak evidence. net → mechanism `Interceptor` for host allowlists (proxy-enforced) with a kernel deny-direct backstop, only if nft presence is probed. exec → §A.6 (restrictive exec over a direct-exec worker refuses; no OpenShell exec-closure primitive).
- **How denials/downgrades propagate to Newt:** unchanged — Bridle's structured `Denial{kind,target,reason}` envelope flows back through the existing tool-result oracle; a projection that would widen returns `Unsupported`, which Newt surfaces as "axis unsupported on this backend," never a silent success.

**Lifecycle reconciliation — the fence key, made precise (C4).** "Sandbox-per-grant" was underspecified: Bridle's `Registry::Grant` is session-scoped with a shared budget, but Newt mints *per-turn attenuated* caveats and its denial→repair loop widens an axis mid-session. Those cannot each spawn a fresh seconds-scale sandbox. Define instead:

> **Indexing key = (session grant identity × fs/exec scope); reuse gate = `StaticFenceCid` equality (§A.5).** The coarse `(grant × scope)` pair MAY index the fence cache, but a cached sandbox is **reused only if its full `StaticFenceCid` matches** — i.e. identical runtime closure, image, spec, floor, and capability probes, not merely identical fs/exec caveats (I4; F5). The `net` axis is narrowed per-invocation via dynamic `UpdateConfig` (cheap, hot-reloaded, kills in-flight relays) bound by `(OpenShellPolicyCid, generation)`, which **never** mutates `StaticFenceCid`. `max_calls`/`valid_for_generation`/presence stay at the Bridle Gate on the mediated channel and are **not** fence properties (§A.2).

Consequences that must be built, not assumed:
- **fs-widen protocol.** fs is create-time-static and additive-only (additions inert until restart). So a denial→repair fs widen = a *new* fence with a new fs scope. Workspace state lives in the old sandbox's driver-owned volume, so the widen requires either a **volume handoff** (re-attach the named volume to the new sandbox) or a **workspace-mount indirection** (workspace on a mount the new fence re-attaches). Pick one in the prototype; do not hand-wave "amortized."
- **Revocation latency is bounded, not instant (C2/F8).** Bridle revoke → deny-all net push is fast but polled (10 s default supervisor interval). fs authority of a running workload **cannot be revoked** short of `DeleteSandbox` — `StopSandbox` suspends but does not revoke the JWT and is not interceptable. State plainly: **hard revoke = delete**; between prompt-revoke and delete, a workload retains its fs scope. Measure and publish the revoke-to-delete bound.
- `StopSandbox` = suspension (policies/providers/data survive, sessions torn down); `DeleteSandbox` = end-of-fence + identity revocation. **Never** reuse one sandbox across differing fs/exec scopes (non-equivocation), and **never** create per-invocation.

---

## 4. Migration path

```
   ┌─────────────────────────────────────────────────────────────┐
   │ C  interop demo  →  B  real backend  →  A  compiler-as-face  │   (main line)
   └─────────────────────────────────────────────────────────────┘
                                   ╎
                                   ╎ (parallel, gated)
   ┌───────────────────────────────────────────────────────────────────────────┐
   │ E-0 TCP/WS mesh Transport + per-AgentKey dock pinning  →  E  swarm over mesh │
   └───────────────────────────────────────────────────────────────────────────┘
```

1. **C — interop demo (smallest vertical proof).** One OpenShell sandbox on gnuc (or nuc k3s). Inside it: a headless `newt-acp-worker` (or wyvern) whose only tool authority is an `agent-bridle-mcp` server. The sandbox is the outer fence. Prove one allowed op, one denied op, evidence returned, and — the load-bearing test — an **adversarial attempt to perform the denied op *without* going through the mcp tool path** (direct `bash`, direct socket, inherited fd). Because wyvern's `run_command` is unconfined, this test *is* the sandbox-completeness proof. Separate "demo works" from "certified."
2. **B — OpenShell backend.** Land `agent-bridle-openshell` + the templated core PR. Now Newt's confined exec can target an OpenShell fence via the existing `bridle_registry` seam, invisible to `newt_core`. This is the integration.
3. **A — compiler as a service.** Expose the backend's `project` as a standalone policy-compilation service for non-Newt callers. Pure repackaging once B is solid.
4. **E — the swarm.** Only after **E-0**: a `Transport` impl that tunnels signed mesh envelopes over TCP/TLS or WebSocket (CONNECT-relayable), *plus* a per-AgentKey dock allowlist on the responder (the newt dock-registry pattern, since agent-mesh's built-in team gate is UserKey-only and residual-1-weak). Then E is B with mesh as the tool channel and wyvern workers as the sandboxed principals — the Drake Swarm, with roles enforced as Caveats attenuations rather than convention.

---

## 5. Trust-boundary diagrams

### 5.1 Process boundaries (topology B / E)
```
 TRUSTED HOST (gnuc / desk)                          UNTRUSTED SANDBOX (OpenShell)
 ┌───────────────────────────────────┐               ┌──────────────────────────────┐
 │ Newt reasoning loop (newt_core)   │               │ supervisor (root, PID1)  ▓TCB▓│
 │  └ Gate::authorize → AdmittedFence │   gRPC/mTLS   │  ├ Landlock+seccomp+netns     │
 │  └ agent-bridle-openshell.project ─┼──────────────▶│  └ drops → workload (uid≥1000)│
 │ agent-bridle-core (trusted)        │  (create/     │       ├ wyvern / acp-worker   │
 │ Vault (cred broker)                │   policy/     │       └ run_command (UNCONF.) │
 │ dgx1 inference (only inference)    │   stop)       │  egress → CONNECT proxy (MITM)│
 └───────────────────────────────────┘               └──────────────────────────────┘
   ▓ supervisor is inside the sandbox TCB; workload hardening is what stands between
     the model and the supervisor. Native hostile-child tests target the WORKLOAD posture.
```

### 5.2 Authority flow (one root, two projections)
```
 principal ─▶ Bridle: effective = granted.meet(required)   [sole mint site]
                 │
                 ├─ projection 1 (mesh Grant/Derivation chain, attenuation-only)
                 │     → what the worker is AUTHORIZED to do        [E only; unused today]
                 └─ projection 2 (agent-bridle-openshell → OpenShellPolicySpec)
                       → what the worker CAN PHYSICALLY do   [projects FENCE axes only, §A.2]
   invariant:  both descend from the SAME EffectiveAuthorityCid, bound in the CID chain.
               projection 2 quantifies over FenceCaveats (fs/exec/net + read); GateCaveats
               (max_calls, valid_for_generation, presence) are NOT projected (§A.2).
   ALLOW = Bridle_authorized ∧ projection_valid ∧ runtime_floor_satisfied ∧ OpenShell_allows

   ── TWO ENFORCEMENT REGIMES (C2), do not conflate ───────────────────────────
   MEDIATED CHANNEL (MCP tool calls):  per-operation AND. Gate::authorize runs
       each call → budget CAS, generation check, presence gate, THEN OpenShell fence.
   DIRECT EXEC PATH (worker's bash):   NO per-op Bridle check. Bridle authored the
       fence once, pre-provisioning. Only the OpenShell kernel/netns fence mediates.
       ⇒ max_calls / valid_for_generation / presence are UNENFORCED on this path.
       ⇒ a hostile worker doing 10⁴ direct ops burns no budget, trips no gesture.
       ⇒ the fence still bounds fs/net to the Bridle-authored scope — that holds.
   Projection 1 note: authority crosses the mesh TODAY as cert-chain Caveats
       attenuation (AgentKey::delegate, child ⊑ parent re-checked per link), NOT as
       the Grant/Derivation DAG (which is unused on the wire; Elevation fail-closed
       pending deferred attestation signatures). E may use either; name the choice.
```

### 5.3 Credential flow (non-equivocation preserved)
```
 Vault ─issues short-lived, sandbox-id-bound cred─▶ OpenShell provider store (gateway-side)
                                                         │ injects PLACEHOLDER (openshell:resolve:env:*)
 workload sees only placeholder ──request──▶ CONNECT proxy ──substitutes real cred per-request,
     scoped to provider profile endpoints; cross-endpoint use → 403; SigV4 sign w/o disclosure.
   model-controlled child NEVER reads the secret. (This is OpenShell's strongest Bridle alignment.)
```

### 5.4 Network flow
```
 workload ─(netns; nft rejects all non-proxy TCP/UDP)─▶ CONNECT proxy (host-side veth gw)
     proxy-side DNS (no workload resolver) → resolved-IP set is what's dialed (rebinding-safe)
     OPA host+L7 policy (MUST be enforcement=enforce, not audit) → upstream (real TLS)
   the ONE authorized egress in E = the mesh dock back to the desk (once a TCP transport exists)
```

### 5.5 CID / provenance chain (honest status)
```
 INTENT (identity)                                          EVIDENCE (proof of what ran)
 DelegatedGrantCid ─▶ EffectiveAuthorityCid ─▶ EnforcementPlanCid ─▶ OpenShellSandboxSpecCid
   ─▶ RequestedImageCid (pinned digest; INTENT, in StaticFenceCid)     ▲ signed edges:
   ─▶ OpenShellPolicyCid(ours, canonical)  ══╗                         grant→effective→plan
   ── evidence side (separate; §A.4/§A.5) ───╫──────────────────────  (Ed25519, existing)
   ─▶ AttestedImageCid    : Cannot-Prove (OpenShell records no running-image digest — U3)
   ─▶ AppliedPolicyCid    : Cannot-Prove pre-U1 (self-reported int; U1 = gateway receipt)
   ─▶ RuntimeEvidenceCid  : Cannot-Prove (unsigned, lossy OCSF)
   ─▶ ExecutionResultCid  : partial       + [ModelIdentityCid for swarm votes]
   ══╝ RequestedImageCid ≠ AttestedImageCid; gateway policy_hash is NOT canonical (correlation token only).
```

---

## 6. Threat model (combined design)

| # | Attack | Vector in this design | Mitigation / residual |
|---|---|---|---|
| T1 | **Bypass** (op possible w/o tool path) | wyvern `run_command` is unconfined `bash -lc`; model runs arbitrary code | Outer OpenShell sandbox is the fence; **C's adversarial test is the proof obligation**; exec axis reported bounded-by-image, never Kernel |
| T2 | **Confused deputy** (sandbox→sandbox) | worker A talks a responder/arbiter B into using B's authority | Roles = Caveats attenuations: arbiter grant is read-only, structurally can't write; per-AgentKey dock allowlist; mesh `meet caller grant ⊑ caller` bound |
| T3 | **Ambient authority** | inherited fds/env/sockets into workload | supervisor strips supervisor-only env, clears cap bounding set, closes fds; **but `OPENSHELL_ENDPOINT` is NOT stripped**; Bridle side: #319 fdguard + env-empty confined spawn |
| T4 | **Credential theft** | model reads API key | placeholder+proxy substitution (§5.3); **residual:** interceptor/middleware transports unauthenticated, gateway trusts interceptor payloads unsigned |
| T5 | **Policy substitution** | apply policy B after validating A | same-artifact validate→encode→hash (no re-read); our canonical `OpenShellPolicyCid`; **residual:** gateway `policy_hash` non-canonical, effective≠validated when provider composition active |
| T6 | **Stale policy** | evidence under P1 mistaken for P2 | policy-generation counter kills in-flight relays on change; **residual:** no signed applied-policy attestation — bind evidence to our CID, treat version int as correlation only |
| T7 | **Downgrade** | claim sandbox exists = enforcement active | `enforcement_report` honesty; fs floor refuses without `hard_requirement`; probe nft presence at admission; **audit-mode L7 = allow-and-log MUST be rejected by compiler** |
| T8 | **Symlink / path** | escape fs fence | Landlock is DAC-independent (e2e-proven); Bridle fs_cap openat2 RESOLVE_BENEATH; residual E1 (symlink root ⇒ Unknown) |
| T9 | **Alternate executable identity** | binary ≠ resolved path | Bridle `exec-behavior-bound` residual; OpenShell binds egress to binary path (spoofable cmdline excluded) — exec identity remains Cannot-Prove |
| T10 | **Inherited FDs** | fd ≥3 leaks across spawn | #319 fdguard (`close_range`) on Bridle confined spawns; supervisor closes on workload spawn |
| T11 | **Proxy bypass** | direct egress skipping CONNECT proxy | nftables reject + bypass monitor; **residuals:** missing `nft` silently skips fence, chain policy `accept` lets ICMP/SCTP through, `inference.local:443` bypasses OPA entirely |
| T12 | **DNS rebinding** | TOCTOU on resolve→connect | proxy resolves once, dials the resolved set (rebinding-safe by construction) ✅ |
| T13 | **Sandbox-to-sandbox deputy** | mesh peer reaches unintended responder | **residual 1 (auto-team, LOAD-BEARING):** shared-UserKey admission, no PoP, no AgentKey pinning → E requires desk-supplied per-AgentKey allowlist |
| T14 | **Control-plane compromise** | gateway is full-admin | **precondition:** OIDC/mTLS MUST be configured (unauth default = platform_admin, scope openshell:all); dedicated workspace per trust domain (authz bottoms out at workspace grain, no per-sandbox owner) |
| T15 | **Malicious sandbox image** | poisoned base image runs, or image swapped between request and launch | pin `template.image` by digest → **`RequestedImageCid`** (intent); but OpenShell records no *running-image* digest, so **`AttestedImageCid` is Cannot-Prove** (U3). The binding proves what we asked for, never what ran (R3-4); do not treat RequestedImageCid as runtime proof |
| T16 | **Malicious MCP server** | rogue tool provider | Newt `AdmittedServer` witness + #1301 project-untrusted model; caveats-confined child |
| T17 | **Malicious child process** | spawned helper escapes | ConstrainedExecutor Kernel floor fails closed w/o kernel enforcement; OpenShell seccomp denylist (default-allow — residual) |
| **T18** | **Budget/generation/presence bypass via direct exec (C2)** | worker's unconfined `bash` runs unmediated by the Gate; gate-enforced axes never fire | **No mitigation on the direct path** — these axes exist only on the mediated MCP channel. Consequence: never advertise `max_calls`/step-up as enforced for direct-exec workers; if a call budget must bind a worker, the worker must have **no** direct-exec authority (mediated-only tool surface) or the budget is enforced at the inference-capability Gate (the dgx1 fair-share meter), not at exec |
| **T19** | **Revocation gap on fs (C2)** | prompt-revoke a grant; workload keeps fs scope until DeleteSandbox | fs is static/inert-until-restart; `StopSandbox` doesn't revoke JWT & isn't interceptable → **hard revoke = delete**; publish the revoke-to-delete latency bound; net revoke is fast-but-polled (~10 s) |
| **T20** | **Identity-key theft from inside the sandbox (C3)** | `newt-acp-worker` needs `~/.newt/identity.pem` (operator ROOT UserKey); one `cat` from hostile bash; + auto-team ⇒ stolen key mints admission to every same-UserKey responder | **Never place the root key in the sandbox.** Desk mints an *attenuated AgentKey* (child ⊑ parent) and injects only that; root key stays desk-side. Slice-1 worker = wyvern (no key needed). Registry-gate responders (T13) so a leaked AgentKey ≠ blanket reach |
| **T21** | **Agent-driven policy widening from inside the TCB (C6)** | `SubmitPolicyAnalysis` is sandbox-callable; `auto` approval + empty prover-delta auto-approves; prover analyzes a proto→YAML round-trip that drops `deny_rules`/`credential_binding`/`allow_encoded_slash`; provider-profile mutations change effective policy with no `UpdateConfig` | precondition **`proposal_approval_mode: manual`**; widen-guard (PR 8) must cover `SubmitPolicyAnalysis` + all approve RPCs + `ImportProviderProfiles`/`UpdateProviderProfiles`/`AttachSandboxProvider` + global-policy path — **not just `UpdateConfig`**; treat the prover as advisory, never as the gate |
| **T22** | **B's widen-guard inherits D's disqualifying substrate (F7)** | the guard is a gateway interceptor: unauthenticated transport, `validate_current_state` always None, static registration, Stop/Start/Delete invisible to it | Accept the guard as **corroborating, not load-bearing**; the load-bearing control is the always-on kernel/netns fence + the authority service tracking prior state itself. Do not let a green interceptor stand in for enforcement |

---

## 7. Semantic policy crosswalk (summary; full table in [openshell-semantic-crosswalk.md](openshell-semantic-crosswalk.md))

| Bridle axis | OpenShell primitive | Label | Strength-floor consequence |
|---|---|---|---|
| **Fence axes** (project; §A.2) | | | |
| `fs_read`/`fs_write` | OpenShell in-sandbox Landlock | **Narrower; `(mechanism=Kernel, evidence=CannotProve)`** | mechanism honestly Kernel with `hard_requirement` + non-empty paths; evidence CannotProve pre-U1 (§A.4). fs floor is structurally Kernel → **restricted-fs RemoteFence refuses pre-U1** unless operator sets explicit CannotProve evidence floor; mechanism never relabelled Interceptor |
| `exec` | (none) | **Unsupported / Cannot-Prove** | never `Kernel`; keep exec mediation inside the boundary; image-as-closure is unpinned |
| `net` (host) | CONNECT proxy + OPA + nft | **Narrower** | `Interceptor` for allowlists + kernel deny-direct backstop; MUST emit `enforce`, probe nft; `inference.local` carve-out projected explicitly |
| **Gate axes** (NOT projected; §A.2) | | | |
| `max_calls` | (none) | Mediated path: **Exact** (Gate) · Direct exec: **Unsupported** | Gate-only; a grant needing a *global* budget over unmediated exec MUST fail admission (I2, adv. case 8) — never "Exact by not projecting" |
| `valid_for_generation` | (none) | Mediated path: **Exact** (Gate) · Direct exec: **Unsupported** | Gate-only; same admission rule as `max_calls` |
| presence/step-up | (none — draft-approval ≠ presence) | Mediated path: **Exact** (Gate) · Direct exec: **Unsupported** | Gate-only; StepUpPolicy composes on top of Caveats |
| credential use | placeholder + proxy substitution | **Exact (mechanism)** | best alignment; keep Vault gateway-side |
| dynamic change | `UpdateConfig` static/dynamic split | **Narrower freely; widen⇒new grant** | interceptor on UpdateConfig; authority service tracks prior state |
| applied-policy proof | version int self-report | **Cannot-Prove** | assurance `partial`, never `proved`; our CID is authoritative |
| image identity | tag only | **Cannot-Prove** | pin by digest ourselves; upstream ask |

`Approximation`/`Cannot-Prove` never silently pass a floor.

---

## 8. Prototype plan (the smallest vertical proof — topology C)

**Goal:** `Newt/worker → Bridle authorization → OpenShell sandbox → one allowed op → one denied op → evidence returned → CID chain verified`, plus an adversarial bypass test.

1. **Substrate:** one OpenShell gateway on gnuc (Docker driver) *or* nuc k3s (verify nuc reachability first — env notes flag nuc1 SSH refusal / nuc2 subnet). OIDC or mTLS configured (never the unauth default). One dedicated workspace. `proposal_approval_mode: manual` (T21).
2. **Inside the sandbox: use wyvern `2fb7107`, NOT `newt-acp-worker` (C3/T20)** — wyvern needs no identity key and has no confinement to break, so it is the honest first slice. Its only tool authority is an `agent-bridle-mcp` endpoint. **Pin `agent-bridle-mcp` placement:** for slice 1 it runs *in-sandbox over stdio* and every "evidence" claim from it is explicitly **demonstrative only** (attacker-writable inside the fence); the trustworthy desk-side variant needs an agent-bridle-mcp *server* transport that does not exist yet (a mini-E-0, out of scope for slice 1, noted in the writeup). Pin `template.image` by digest.
3. **Identity:** if a later slice uses a newt worker, the desk mints an **attenuated AgentKey** (child ⊑ parent) and injects only that; the operator root key `~/.newt/identity.pem` **never crosses the boundary** (T20).
4. **In-image capability probe (new, blocking):** before trusting any Bridle-nested confinement, probe inside the pinned image for Landlock ABI availability and whether `seccomp(SET_MODE_FILTER)` is permitted — OpenShell's workload seccomp conditionally EPERMs it, which would make a nested Bridle `ConstrainedExecutor` spawn **fail closed** (non-functional), not merely weaker (C3). Record the result; if nested confinement is unavailable, the design is "outer-fence-only" and must say so.
5. **Allowed op:** a file write inside the granted `fs_write` scope → succeeds; evidence (OCSF + our CID) returned.
6. **Denied op:** a write outside scope / an egress to a non-allowlisted host → OpenShell denies. (Note the AND here is *scope-level*: the fence enforces a Bridle-authored bound; Bridle is not re-consulted per-op on the direct path — C2. Do not describe this as "Bridle also denied at runtime.")
7. **Adversarial bypass (the real test):** from the model's unconfined `run_command`, attempt the denied op directly — raw `bash`, direct socket, inherited fd, `/proc` re-open. **Must fail at the sandbox boundary.** Native hostile-child evidence, not a mock. Record as an `ASM-OPENSHELL-*` assurance row.
8. **CID chain:** verify `DelegatedGrantCid → EffectiveAuthorityCid → EnforcementPlanCid → OpenShellSandboxSpecCid → OpenShellPolicyCid(ours)`; mark applied/runtime rows `partial` with honest reason.
9. **Pin the exact OpenShell commit** in the evidence bundle (it evolves daily).

Separate prototype success from security certification explicitly in the writeup.

---

## 9. PR train (small, independently reviewable; owner per PR)

**Track 1 — C interop demo**
1. `[OpenShell-ops, docs]` Reproducible gateway-on-gnuc + dedicated-workspace + `proposal_approval_mode:manual` + digest-pinned image recipe (no code). — *owner: workspace/newt*
2. `[wyvern-agent]` A wyvern launch profile whose only tool authority is an `agent-bridle-mcp` endpoint (no other tools). **Not** newt-acp-worker for slice 1 (T20). — *owner: wyvern-agent*
3. `[agent-bridle]` `agent-bridle-mcp` caveats profile + example for the in-sandbox worker; document the in-sandbox-stdio-vs-desk-side trust distinction (C3.3). — *owner: agent-bridle*
4. `[workspace, tests]` In-image capability probe (Landlock ABI + `seccomp(SET_MODE_FILTER)` permitted?) + Native hostile-child bypass test harness (the §8.7 test) + `ASM-OPENSHELL-BYPASS` assurance row. — *owner: newt-agent*

**Track 2 — B backend. Identity/provenance land BEFORE usable remote execution (F6 + R3-3). Strict order: 5a → 5b → 5c, each green before the next.**
- **5a `[agent-bridle-core]` — the execution seam, NO OpenShell dependency.** Introduce the **ExecutionBackend** distinction (`Local` | `RemoteFence`) separate from `EnforcementMechanism` (§A.1). `ExecutionBackend::Local → best_available_sandbox() → local child`; `RemoteFence → remote backend, **never** routed through `best_available_sandbox`` (R3-3). Acceptance: existing local behavior **unchanged**; all existing enforcement/provenance tests green; **no** OpenShell dep; the local `SCM_CREDENTIALS`/`SO_PEERCRED`/`same_image` identity path **not weakened** (I6, adv. case 10); cancellation / wait / kill / stream / drop semantics for a remote handle explicitly modeled (even though only `Local` is implemented here); `verify_applied` unchanged on the `Local` path. Ships with **zero** behavior change — pure seam. — *owner: agent-bridle*
- **5b `[agent-bridle-core / agent-bridle-openshell-types]` — identity & provenance primitives, ZERO remote-execution capability (R3-3).** The net-new, **domain-tagged** content-addressed types (§A.3–§A.6): `SandboxPrincipalBinding`, `StaticFenceCid`, `RequestedImageCid`, `AttestedImageCid`, `EnforcementPlanCid`, `RuntimeClosureCid`, `OpenShellSandboxSpecCid`, and the `EnforcementClaim{mechanism, evidence}` product with its `EvidenceStrength` type + componentwise admission — each constructed via the `ResolvedGrant::bind` "mismatch-is-unrepresentable" pattern (`authority.rs:298-311`). Brokered flow: the desk mints a `SandboxPrincipalBinding`; the worker never holds the root key. **No sandbox lifecycle, no remote exec** — this crate cannot run anything; it only makes the bindings/claims that 5c must present. This guarantees a mergeable 5c **cannot** accept a remote result without these objects (adv. case 14). — *owner: agent-bridle*
- **5c `[agent-bridle-openshell]` — OpenShell RemoteFence, using 5b's primitives.** New leaf crate (tonic/tokio, off core): the `RemoteFence` backend, remote lifecycle (create/reuse/delete), remote exec, the `project` compiler (`FenceCaveats` → canonical `OpenShellPolicySpec`), `resolved_authority`/`runtime_closure` conservative bounds, `OpenShellPolicyCid` canonical hash, the **product claim** so fs = `(Kernel, CannotProve)` pre-U1 (§A.4 — mechanism stays Kernel, admission refuses restricted fs unless the operator sets a CannotProve floor), the §A.6 exec-admission refusal, and fail-closed throughout. Accepting a remote result is **type-gated** on a valid `SandboxPrincipalBinding` + `StaticFenceCid` from 5b. Depends on 5a+5b; introduces **no** new `SandboxKind` that `best_available_sandbox` would auto-select. — *owner: agent-bridle*
- **6 `[agent-bridle-openshell, tests]`** Property tests: `authority(project(fence(c))) ⊑ fence(c)` (I1); admission **refuses** a restrictive GateCaveat over a direct-exec worker (I2, case 9) and a restrictive exec over a direct-exec worker (§A.6, cases 13a–c); the §C adversarial cases as red→green tests — including 1c/1d (same-sandbox reuse *not* caught, asserted as a documented limit), 8 (fs refuse pre-U1), 12 (requested≠attested image), 14 (5c can't accept a result without 5b objects). — *owner: agent-bridle*
- **7 `[agent-bridle-openshell]` (scope-expanded, C6)** Gateway-interceptor widen-guard covering **`UpdateConfig` + `SubmitPolicyAnalysis` + all draft-approve RPCs + `ImportProviderProfiles`/`UpdateProviderProfiles`/`AttachSandboxProvider` + the global-policy path**; documented as *corroborating, not load-bearing* (T22). — *owner: agent-bridle*
- **8 `[agent-bridle, formal]`** TLA+/Lean projection non-amplification model over the **fence subset** (reuse ADR 0026 harness) + assurance rows (`held`→`partial` on native evidence). — *owner: agent-bridle*
- **9 `[newt-agent]`** Wire the OpenShell backend behind the existing `bridle_registry` seam; no `newt_core` type changes; implement fence reuse keyed by **`StaticFenceCid` equality** (not the coarse `(grant × scope)` alone, I4) + the fs-widen volume-handoff (C4). — *owner: newt-agent*

**Track 3 — A face** (after B)
11. `[agent-bridle-openshell]` Expose `project` as a standalone compilation service for non-Newt callers. — *owner: agent-bridle*

**Track 4 — E swarm** (parallel, gated; do not start before E-0)
12. `[agent-mesh]` E-0a: TCP/TLS (or WebSocket) `Transport` impl reusing `stream.rs` framing + handshake, CONNECT-relayable. — *owner: agent-mesh*
13. `[agent-mesh]` E-0b: auto-team hardening — proof-of-possession in `ensure_trustable`, bind handshake cert to `conn.remote_id()` (residual 1). — *owner: agent-mesh*
14. `[newt-agent]` Per-AgentKey dock allowlist for the desk responder (wyvern readiness #47). — *owner: newt-agent*
15. `[wyvern-agent]` MeshDispatcher + wire codec + responder auth per readiness ladder #44–#50. **Name the authority-crossing choice:** cert-chain Caveats attenuation (works today) vs. the mesh `Grant`/`verify_chain` DAG (needs wiring + an attestation signer to unblock `Elevation`). Default to cert-chain for slice 1. — *owner: wyvern-agent*
16. `[agent-bridle / wyvern]` Bind `ModelIdentityCid` into `ExecutionResultCid` so arbiter votes are auditable by model family. — *owner: shared*

No mega-PR. Each PR carries its own regression test; Bridle PRs carry an assurance-manifest row or a formal-model delta.

---

## 10. Exit criteria (before declaring the integration *safe*, not merely *working*)

0. **The invariants I1, I2, I3a, I3b, I4, I5a, I5b, I6 (§B) hold**, each with the mapped adversarial cases of §C green as red→green tests. In particular: I2 (restrictive GateCaveat over direct-exec fails admission) and §A.6 (restrictive exec over direct-exec fails admission); I3a (OpenShell fs reported **Kernel** mechanism, never relabelled Interceptor) + I3b (evidence CannotProve pre-U1; `EnforcementClaim{mechanism, evidence}` product; **restricted-fs RemoteFence refuses pre-U1** unless explicit CannotProve floor); I4 (reuse gated on `StaticFenceCid` equality; `RequestedImageCid` only); I5a (`SandboxPrincipalBinding` field-match at sandbox grain) + I5b (remote process identity NOT claimed; same-sandbox reuse cases 1c/1d asserted as limits); I6 (local identity path unchanged).
1. **Projection theorem holds over the fence subset:** property test `authority(project(fence(c))) ⊑ fence(c)` green across generated caveats (I1); TLA+/Lean non-amplification model checked (reusing ADR 0026 harness).
2. **Native hostile-child evidence** (not mock) for every axis claimed above `Advisory`: the §8.7 bypass test fails closed for fs and net, run inside the pinned image; `ASM-OPENSHELL-*` rows carry `evidence_cid`, status `partial`→`held` only with that evidence.
3. **fs Kernel floor proven:** `hard_requirement` + non-empty paths compiled; a policy that would run Landlock best-effort/empty is refused by the compiler, with a test.
4. **net honesty proven:** compiler emits `enforce` (never `audit`), probes nft presence at admission, and refuses when the deny-direct fence is unverifiable; `inference.local` carve-out is an explicitly projected route or refused.
5. **No-widen-without-grant proven:** UpdateConfig widen-guard denies a hand-crafted widening transition lacking a fresh enforcement-plan CID.
6. **Non-equivocation proven:** validated policy == applied policy via our canonical `OpenShellPolicyCid`; a substitution/TOCTOU attempt is rejected.
7. **Control-plane preconditions asserted in code/deploy:** refuse to operate against an unauthenticated gateway; one workspace per trust domain; image digest-pinned.
8. **Honest register:** assurance manifest carries `AppliedPolicyCid`/`RuntimeEvidenceCid`/`AttestedImageCid` as `Cannot-Prove` (distinct from `RequestedImageCid`, our pinned intent) with reasons until closed. **"SKIP is not PASS."**
9. **U1 applied-policy attestation is a CERTIFICATION DEPENDENCY with a real trust path (R3-6).** The sandbox holds no signing key (the **gateway** signs the sandbox JWT; the supervisor presents it as bearer — `sandbox_jwt.rs:6-7`), so U1 is a **gateway-emitted signed receipt** over an authenticated supervisor report binding `{sandbox identity, applied-policy CID, generation, report sequence, gateway identity}`. It proves "the trusted supervisor reported applying this effective policy and the gateway authenticated the report" — **not** enforcement against a compromised supervisor (the supervisor is in B's TCB). Until it lands, the fs axis carries **evidence CannotProve** (mechanism stays Kernel), so a restricted-fs RemoteFence refuses pre-U1 unless the operator sets an explicit CannotProve floor; native Landlock (Local) remains the process-observed path.
10. **fs-vs-Landlock honesty asserted, per-execution (F1/R3-2):** routing is by **ExecutionBackend**, not per-axis on one process. An fs-sensitive command runs **Local** (native Landlock, `(Kernel, observed-in-process)`); a **RemoteFence** command has *all* axes enforced in-sandbox, its fs claim `(mechanism=Kernel, evidence=CannotProve)` — the mechanism is **not** relabelled Interceptor, and the restricted-fs case **refuses pre-U1**. The v2 "one process gets desk-local Landlock for fs *and* the OpenShell fence for net" wording is **retracted** as an impossible conjunction (§A.1).
11. **E-gate (if pursued):** a **TCP framing** mesh transport (not tunneled QUIC — the CONNECT proxy MITMs TLS and doesn't speak QUIC) crosses the boundary in a test, with envelope-sig + Olm ratchet as the in-tunnel confidentiality controls; residual 1 (auto-team PoP + AgentKey pinning) closed; a hostile worker on a dock cannot reach a responder outside its per-AgentKey allowlist.

**Certification is withheld** until 0–10 hold. Prototype/demo success (§8) is explicitly *not* certification.

---

## Appendix — open questions for a second review pass

Resolved in v2 (moved to blockers/decisions): the applied-policy hash-echo is now a **certification blocker** (exit 9), not an open question; the AND-invariant scope and the fs-downgrade framing are decided (§0/§5.2). Remaining genuinely-open:

- `RequestedImageCid` (our digest-pin) is settled as *intent*; the open question is whether `AttestedImageCid` (proof of the running image) is worth an upstream ask now or deferred — it is Cannot-Prove until OpenShell records a running-image digest (U3).
- **The upstream engagement question:** several fixes are one-to-few-field upstream PRs to NVIDIA/OpenShell (applied-policy hash echo over the *effective composed* artifact; add `StopSandbox`/`StartSandbox` to the interceptor allowlist; populate `validate_current_state`). Pursue upstream, or carry a fork/shim? (Constraint: do not fork unless demonstrably necessary.)
- For E: the transport must be **TCP framing** (not tunneled QUIC — the CONNECT proxy MITMs TLS and doesn't speak QUIC). Open sub-question: reuse `stream.rs` framing over a raw CONNECT tunnel, or ride streamable-HTTP? Both are TCP; which is less work and less MITM-exposed?
- Does the swarm want arbiters as *separate sandboxes* (strong isolation, higher cost) or read-only-grant workers in a shared sandbox (cheaper, weaker; but shared-sandbox re-introduces the exec-mediation gap)? Model-diversity requires arbiters pinned to distinct model families regardless; `ModelIdentityCid` in the evidence chain is required either way.
- Is "outer-fence-only" (no nested Bridle confinement inside the sandbox, because nested seccomp/Landlock may be unavailable — §8.4) acceptable for the worker, or must slice 2 negotiate nested enforcement? This decides whether the worker can be a full Newt or must stay wyvern-shaped.
- k3s substrate: verify nuc1/nuc2 reachability and roles before A/E assume a Kubernetes deployment target.

---

*This RFC has had three adversarial review passes (C1–C6 in v2; F1–F6 + invariants in v3; R3-1…R3-6 + product-lattice + sandbox-grain identity + exec theorem in v3.1, normative in §A/§B/§C). Per the study charter it should get at least one more independent hostile review — with fresh eyes on the `SandboxPrincipalBinding` grain (R3-1), the `EnforcementClaim` product and fs-refuse-pre-U1 rule (R3-2), and the U1 gateway-receipt trust path (R3-6) — before any implementation GO.*
