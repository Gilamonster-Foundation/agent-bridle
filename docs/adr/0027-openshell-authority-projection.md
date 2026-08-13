# ADR 0027 — OpenShell as an enforcement projection of Bridle authority

- Status: **Proposed** (2026-08-13)
- Date: 2026-08-13
- Context: NVIDIA's [OpenShell](https://github.com/NVIDIA/OpenShell) is a
  rapidly-evolving agent-sandbox runtime (container/microVM/Kubernetes execution,
  an L7 egress proxy, a supervisor, credential brokering). The recurring question
  — "can Bridle use OpenShell as an execution backend without acquiring a *second*
  source of model authority?" — is exactly the shape ADR 0026 answered for POSIX:
  a foreign mechanism is admitted only as a **projection** of the `Caveats`
  algebra, never as an independent grant. This ADR is the
  architecture-before-implementation gate for that integration, spanning
  agent-bridle (authority), newt-agent (harness), and OpenShell (execution), with
  agent-mesh + wyvern-agent as the swarm substrate. It decides the target
  architecture and migration order **before** any adapter crate or core change is
  written.
- Governed by / harmonizes with: **ADR 0002** (`Caveats` meet-semilattice, the
  unforgeable `ToolContext`, no `join`/`widen`), **ADR 0020** (authority product
  lattice), **ADR 0012** (fence strength as a GLB), **ADR 0017**
  (configurability/honesty-disclosure split), **ADR 0023** (three-tier proof
  discipline — a claim with no tier is prose), and above all **ADR 0026** (the
  projection template: no new authority carrier, project only what can be
  mediated honestly, `Unknown ⇒ refuse`, per-platform honesty, no merge without a
  hostile-child native test + assurance row).
- Scope: the *authority architecture* of an OpenShell integration — which of four
  candidate topologies Bridle adopts, why, the migration order, and the exit
  criteria. It does **not** authorize an implementation; a GO here authorizes
  proposing an implementation phase (the PR train in the companion RFC).

Companion RFC (full study, decision matrix, threat model, crosswalk, PR train):
[openshell-integration-rfc.md](../design/openshell-integration-rfc.md).
Upstream contribution proposals:
[openshell-upstream-contributions.md](../design/openshell-upstream-contributions.md).

## Question

Bridle confines a child by composing per-OS mechanisms (Landlock, seccomp,
Seatbelt, AppContainer) behind one `Caveats` algebra, with `AdmittedFence::admit`
as the sole adjudicator and a per-axis `Kernel > Interceptor > Advisory` honesty
report. OpenShell is a *remote* execution service with its own policy engine,
its own egress proxy, and its own (weaker) evidence surface. Four ways to combine
them were evaluated:

- **A** — three-layer compiler: Newt → Bridle → OpenShell, Bridle grants compiled
  into OpenShell policies.
- **B** — OpenShell as a Bridle `Sandbox`/enforcer backend (a new `SandboxKind`).
- **C** — an agent inside an OpenShell sandbox, tool authority via
  `agent-bridle-mcp`; the sandbox is the outer fence.
- **D** — Bridle exposed *through* OpenShell's gateway/supervisor extension
  points (interceptors) as an authority subsystem.
- **E** — the swarm: `newt → agent-mesh → OpenShell → wyvern`, the Drake-Swarm
  shape with roles enforced as `Caveats` attenuations.

The governing invariant, unchanged:

```
achieved_runtime_authority ⊑ projected_execution_authority
    ⊑ effective_bridle_authority ⊑ delegated_authority
```

OpenShell policy must be an *enforcement projection* of Bridle authority. No
operation may become possible merely because OpenShell permits it:

```
ALLOW = Bridle_authorized ∧ projection_valid ∧ runtime_floor_satisfied ∧ OpenShell_allows   (never OR)
```

## Decision

**GO to propose implementation of topology B — OpenShell as a Bridle `Sandbox`
backend — as the target, with A as its deployment face, C as the first
de-risking proof, D rejected, and E (the swarm) as a later gated track.** This is
an architecture GO only; it does not authorize production enforcement code.

Load-bearing conclusions (evidence and file:line citations in the companion RFC):

1. **B is the target, but it is not a trivial core change.** The `Sandbox` trait
   is a *local-confinement* contract (`apply` confines the calling thread;
   `command_prefix` wraps local argv). OpenShell has no local child to confine, so
   B requires a **new persistent-remote-fence execution seam** in `spawn.rs` /
   `best_available_sandbox` (the most audit-sensitive path in core), plus a new
   `SandboxKind::OpenShell` with an honest per-axis `enforcement_report`, plus a
   `ConfinementMechanism` carrier for probed runtime state. The heavy mechanism
   (tonic/tokio, gateway client, lifecycle) lives in a leaf crate
   `agent-bridle-openshell`, keeping core `forbid(unsafe)` and tokio-free per the
   jaild/aclaunch precedent.

2. **B is an axis-split acquisition, stated honestly (ADR 0017).** On Linux,
   native Landlock is **strictly stronger** on the filesystem axis (local,
   observed per-invocation, fail-closed in-process). OpenShell's filesystem
   "Kernel" is *Kernel-modulo-an-unverified-remote-TCB* — a self-reported
   `LOADED` integer with a full-admin-by-default gateway in the path. B is a
   **net-enforcement + credential-non-equivocation + outer-fence acquisition** and
   a **filesystem downgrade**. `best_available_sandbox` must therefore prefer
   native Landlock for the fs axis where available and use the OpenShell fence for
   host-allowlist egress, placement, and the outer boundary — never the reverse.

3. **The `∧`-invariant is scope-level, not per-syscall, on the direct-exec path.**
   For a worker's unconfined shell, Bridle is not in the per-operation decision
   path — it authored the fence once, pre-provisioning. `max_calls`,
   `valid_for_generation`, and step-up are enforced **only on the mediated MCP
   channel**; fs revocation cannot reach a running workload short of
   `DeleteSandbox`. This is acceptable (the fence still bounds fs/net to the
   Bridle-authored scope) but must be reported honestly, not described as runtime
   co-enforcement.

4. **D is rejected.** OpenShell's only sanctioned interposition point (gateway
   interceptors) cannot mediate `ExecSandbox` (streaming), reads, or
   `StopSandbox`/`StartSandbox`; its transport to the interceptor is
   unauthenticated; and `validate_current_state` is always empty. Complete
   mediation cannot be built on it. B's own no-widen-without-grant interceptor is
   therefore **corroborating, not load-bearing** — the always-on kernel/netns
   fence carries B's mediation.

5. **Migration: C → B → A, with E gated on a transport prerequisite.** C (a
   wyvern worker inside one sandbox, authority via `agent-bridle-mcp`) is the
   cheapest interop proof and the one that exercises the real hostile-bypass test.
   E is blocked at the transport layer: agent-mesh is QUIC/UDP with relay
   disabled, OpenShell egress is a TCP-only HTTP CONNECT proxy that MITMs TLS and
   rejects UDP — so iroh cannot be tunnelled and E needs a new **TCP framing**
   mesh transport plus per-AgentKey dock pinning (the auto-team residual is
   load-bearing against a hostile worker). Do not start with E.

## Consequences

- **Crate boundary.** New leaf crate `agent-bridle-openshell`; a bounded,
  templated-but-non-trivial change to `agent-bridle-core` (enum arm + report arms
  + the persistent-fence exec seam). OpenShell-specific types stay out of
  `agent-bridle-core`; Bridle-specific types stay out of Newt's reasoning core
  (which reaches the backend only through the existing `bridle_registry` seam).

- **Evidence honesty (ADR 0023).** OpenShell can *prove* (kernel/e2e-verified)
  filesystem confinement and deny-by-default egress; it can only *log* — unsigned,
  lossy, self-reported — that a control is actually active, and it pins no image
  digest. `AppliedPolicyCid` / `RuntimeEvidenceCid` / `SandboxImageCid` are
  therefore `partial` / `Cannot-Prove` in the assurance manifest until closed. An
  **applied-policy attestation** (upstream hash-echo over the *effective composed*
  policy) is a **certification blocker**, not an open question.

- **Fail-closed projection.** The backend's `project : (EffectiveCaveats,
  RuntimeCapabilities) → OpenShellPolicySpec | Unsupported` must satisfy
  `authority(project(c)) ⊑ c` (property-tested; TLA+/Lean non-amplification model
  reusing the ADR 0026 harness). It must compile `landlock.compatibility:
  hard_requirement` (never best-effort), emit L7 `enforcement: enforce` (never the
  `audit` default), probe nftables presence at admission, and account for the
  `inference.local:443` OPA carve-out — or resolve the axis `Unknown ⇒ refuse`.

- **Deployment preconditions become invariants.** Refuse to operate against an
  unauthenticated OpenShell gateway (its default principal is full admin); one
  workspace per trust domain (authz bottoms out at workspace grain, no per-sandbox
  owner); `proposal_approval_mode: manual`; `template.image` digest-pinned.

- **A GO does not authorize** a production `bridle-openshell` backend advertised
  as secure, nor any enforcement claim above `Advisory` without a native
  hostile-child test + an `ASM-OPENSHELL-*` assurance row. Per the study charter,
  the companion RFC has had one adversarial review pass (findings C1–C6 folded in)
  and should receive at least one more independent hostile review before an
  implementation GO.
