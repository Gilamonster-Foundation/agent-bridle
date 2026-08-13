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

**GO to propose implementation of topology B — OpenShell as a Bridle remote
execution/enforcement backend — as the target, with A as its deployment face, C
as the first de-risking proof, D rejected, and E (the swarm) as a later gated
track.** This is an architecture GO only; it does not authorize production
enforcement code. The normative model, formal invariants (I1–I6), and test
obligations are in the companion RFC **§A/§B/§C**; that section is the security
contract later PRs are held against. (Review pass 2 folded findings F1–F6 into it.)

Load-bearing conclusions (evidence and file:line citations in the companion RFC):

1. **B is the target, but it is not a trivial core change, and it is NOT a new
   `SandboxKind`.** The `Sandbox` trait is a *local-confinement* contract (`apply`
   confines the calling thread; `command_prefix` wraps local argv;
   `best_available_sandbox` returns one non-composable `Box<dyn Sandbox>`).
   OpenShell has no local child to confine. B therefore introduces an
   **ExecutionBackend** distinction (`Local` | `RemoteFence`) *separate from* the
   **EnforcementMechanism** (RFC §A.1) — not another `SandboxKind` variant that
   `best_available_sandbox` would auto-select — plus a persistent-remote-fence
   execution seam in `spawn.rs` (the most audit-sensitive path in core). The heavy
   mechanism (tonic/tokio, gateway client, lifecycle) lives in the leaf crate
   `agent-bridle-openshell`, keeping core `forbid(unsafe)` and tokio-free per the
   jaild/aclaunch precedent. The seam must additionally supply a **remote-worker
   identity** (RFC §A.3): Bridle's existing worker auth is kernel-local
   (`SCM_CREDENTIALS` + `same_image` dev/ino in `private_control.rs`;
   `SO_PEERCRED` in jaild) and a containerized worker passes none of it. That is a
   distinct grain from authority: **AuthorityIdentity** (AgentKey possession) ≠
   **ExecutionIdentity** (process/image proof). The remote path binds them with a
   content-addressed **`RemoteWorkerBinding`** (authority × sandbox instance ×
   image × plan × generation × audience), constructed mismatch-unrepresentably per
   the `ResolvedGrant::bind` pattern, with the signing key held by a desk-side
   **broker**, never by the hostile worker.

2. **B is a per-execution acquisition, stated honestly (ADR 0017); NOT a within-
   process axis split.** A single process has one ExecutionBackend and cannot be
   jointly constrained by desk-local Landlock *and* a remote fence — `restrict_self`
   confines only the calling desk thread and has no reach into a container. A
   **Local** execution keeps native Landlock (fs Kernel, observed in-process); a
   **RemoteFence** execution has *all* axes enforced by in-sandbox mechanisms, its
   fs by OpenShell's in-sandbox Landlock (mechanism-Kernel). The claim Bridle
   advertises separates **MechanismStrength** (`AxisEnforcement`, a pure function
   of `(effective, mechanism)`) from **EvidenceStrength**: `effective_claim =
   min(MechanismStrength, EvidenceCap)`, and pre-U1 the OpenShell fs/net EvidenceCap
   is **Interceptor**, so the backend must **not** report `Kernel` (RFC §A.4). A
   remote fs axis is thus *evidence-weaker* than the same command run locally. The
   "additive" benefit (Landlock-strong fs *and* OpenShell egress) is a **fleet**
   property — route fs-sensitive work Local, egress-sensitive/unconfined work
   Remote — never a per-axis split on one process.

3. **Fence authority vs Gate authority (the `∧`-invariant is scope-level on the
   direct-exec path).** Projection quantifies over **FenceCaveats**
   (`fs_read/fs_write/exec/net`), never over **GateCaveats** (`max_calls`,
   `valid_for_generation`, presence), which are enforced only inside
   `Gate::authorize` (RFC §A.2). On the mediated MCP channel GateCaveats are
   **Exact**; on the direct-exec path they are **Unsupported** — a hostile worker
   running arbitrary shell burns no budget and trips no gesture, and fs revocation
   cannot reach it short of `DeleteSandbox`. Therefore a grant that requires a
   restrictive GateCaveat as a *global* semantic over an unmediated-exec worker
   **MUST fail admission** (I2) rather than be reported as enforced (I3). The fence
   still bounds fs/net to the Bridle-authored scope; that, and only that, is the
   direct-path guarantee.

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

- **Crate boundary & PR order (F6).** New leaf crate `agent-bridle-openshell`; a
  non-trivial change to `agent-bridle-core` that **lands the abstraction before
  OpenShell**: PR 5a introduces the `ExecutionBackend` seam with **zero** behavior
  change and no OpenShell dependency (existing tests stay green; the local
  identity path is untouched, I6), then PR 5b implements the `RemoteFence` backend
  on top. The net-new, **domain-tagged** content-addressed types
  (`RemoteWorkerBinding`, `StaticFenceCid`, `SandboxImageCid`, `EnforcementPlanCid`,
  `RuntimeClosureCid`, `OpenShellSandboxSpecCid`) follow the `ResolvedGrant::bind`
  mismatch-unrepresentable pattern. OpenShell-specific types stay out of
  `agent-bridle-core`; Bridle-specific types stay out of Newt's reasoning core
  (which reaches the backend only through the existing `bridle_registry` seam).

- **Fence identity completeness (F5, I4).** Today a fence's identity is only
  `FenceBody{mechanism_caveats, mechanism}` (`admitted.rs:183-186`). A remote fence
  must be identified by a `StaticFenceCid` over *all* security-relevant static
  inputs (static authority, mechanism, runtime-closure CID, image CID, spec CID,
  enforcement floor, capability probes, compiler version, generation baseline);
  fence **reuse requires `StaticFenceCid` equality**, never a coarse `(grant ×
  scope)` key alone. Dynamic net policy binds via a separate `(OpenShellPolicyCid,
  generation)` and never mutates the static identity.

- **Evidence honesty (ADR 0023).** OpenShell can *prove* (kernel/e2e-verified)
  filesystem confinement and deny-by-default egress; it can only *log* — unsigned,
  lossy, self-reported — that a control is actually active, and it pins no image
  digest. `AppliedPolicyCid` / `RuntimeEvidenceCid` / `SandboxImageCid` are
  therefore `partial` / `Cannot-Prove` in the assurance manifest until closed. An
  **applied-policy attestation** (upstream hash-echo over the *effective composed*
  policy) is a **certification blocker**, not an open question.

- **Fail-closed projection over the fence subset (I1).** The backend's `project :
  (FenceCaveats, RuntimeCapabilities) → OpenShellPolicySpec | Unsupported` must
  satisfy `authority(project(fence(c))) ⊑ fence(c)` (property-tested; TLA+/Lean
  non-amplification model reusing the ADR 0026 harness). It projects **only** the
  fence axes; GateCaveats are never projected. It must compile
  `landlock.compatibility: hard_requirement` (never best-effort), emit L7
  `enforcement: enforce` (never the `audit` default), probe nftables presence at
  admission, and account for the `inference.local:443` OPA carve-out — or resolve
  the axis `Unknown ⇒ refuse`. A grant with a restrictive GateCaveat over an
  unmediated-exec worker fails admission (I2).

- **Deployment preconditions become invariants.** Refuse to operate against an
  unauthenticated OpenShell gateway (its default principal is full admin); one
  workspace per trust domain (authz bottoms out at workspace grain, no per-sandbox
  owner); `proposal_approval_mode: manual`; `template.image` digest-pinned.

- **A GO does not authorize** a production `bridle-openshell` backend advertised
  as secure, nor any enforcement claim above `Advisory` without a native
  hostile-child test + an `ASM-OPENSHELL-*` assurance row. Per the study charter,
  the companion RFC has had two adversarial review passes (C1–C6 in v2; F1–F6 +
  invariants I1–I6 + test obligations in v3) and should receive at least one more
  independent hostile review before an
  implementation GO.
