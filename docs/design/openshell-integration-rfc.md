# RFC: Integrating newt-agent, agent-bridle, and NVIDIA OpenShell

> **Decision record:** [ADR 0027 — OpenShell as an enforcement projection of Bridle authority](../adr/0027-openshell-authority-projection.md).
> **Companions:** [semantic crosswalk](openshell-semantic-crosswalk.md) · [upstream contribution proposals](openshell-upstream-contributions.md).
> This is the full study behind the ADR: decision matrix, threat model, migration path, prototype plan, PR train, exit criteria. It follows the ADR 0026 projection template ("POSIX is a projection of Bridle authority; the same law governs OpenShell").

**Status:** Draft, v2 — adversarially reviewed once; *no implementation authorized*
**Author:** architecture coordinator (integration study)
**Date:** 2026-08-13
**Verdict of review pass 1:** survive-with-amendments. Recommendation (B; C→B→A; reject D; gate E) stands; six findings folded in below.

**Changelog v1→v2 (each item is a conceded red-team finding):**
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
- **What B actually buys (and what it does not):** B is a **net-enforcement + credential-non-equivocation + outer-fence acquisition**. It gives Bridle, for the first time on Linux, host-allowlist egress enforcement for arbitrary child processes (Interceptor-grade proxy + kernel deny-direct backstop — Bridle's own egress proxy is macOS-only today), credential placeholder/proxy substitution (Bridle has no counterpart), and an outer boundary for *deliberately unconfined* workers (wyvern; Newt's open `b1-os-isolation`). On the **filesystem axis it is a downgrade**: native Landlock is local, observed per-invocation, and fail-closed in-process; OpenShell's fs "Kernel" is *Kernel-modulo-an-unverified-remote-TCB* (self-reported `LOADED` integer, full-admin-by-default gateway in the path). **Use B additively for net/credentials/placement — never as a substitute for desk-local Landlock on fs.**
- **Rejected: D — Bridle as an OpenShell authority subsystem.** OpenShell's only sanctioned interposition point (gateway interceptors) cannot mediate `ExecSandbox` (streaming), reads, or the new `StopSandbox`/`StartSandbox`, has an unauthenticated transport to the interceptor, and is blind to prior state. Complete mediation cannot be built on it. Revisit only if upstream closes those gaps.
- **Migration path: C → B → A, with E (the swarm) as a parallel track gated on a transport prerequisite.** C (Newt or a worker *inside* one OpenShell sandbox, reached by an `agent-bridle-mcp` authority) is the cheapest interop proof and it exercises the real wire. B is the actual integration. A is B deployed as a compiler service. **E** — your Drake-Swarm shape, `newt → agent-mesh → OpenShell → wyvern` — is the aspirational capstone but is **blocked at the transport layer**: agent-mesh is QUIC/UDP with relay disabled, OpenShell egress is a TCP-only HTTP CONNECT proxy behind an nftables UDP reject. E is unreachable until a TCP/WebSocket mesh `Transport` and per-AgentKey dock pinning exist. Do not start with E.
- **The honest ceiling:** OpenShell can *prove* (kernel/e2e-verified) filesystem confinement and deny-by-default egress; it can only *log* — unsigned, lossy, self-reported — that any control is actually active, and it pins no image digest. So `AppliedPolicyCid`/`RuntimeEvidenceCid`/`SandboxImageCid` are "Cannot Prove" upstream today. The integration is safe to *build* and *demo*; it is not safe to *certify* until the assurance residuals below are closed with native hostile-child evidence.

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

Bridle stays the sole authority. Add one leaf crate `agent-bridle-openshell` (holds tonic/tokio, gateway client, lifecycle — off the trusted core, per the jaild/aclaunch precedent) **plus a core change that is larger than a new enum arm** (C1). The backend's job is a total function:

```
project : (EffectiveCaveats, RuntimeCapabilities) -> OpenShellPolicySpec | Unsupported
    such that   authority(OpenShellPolicySpec) ⊑ EffectiveCaveats     (never widen)
```

**The core-surgery reality (C1).** The existing `Sandbox` trait is a *local-confinement* contract: `apply(&Caveats)` confines the calling thread (Landlock `restrict_self` on a throwaway spawn thread) and `command_prefix` wraps *local* argv (Seatbelt/`aclaunch`). OpenShell has **no local child to confine** — the workload is spawned by the supervisor inside a remote container. So B cannot be "implement two trait methods":
- Core needs a **third execution mode — a persistent remote fence** — threaded through `ConfinedCommand::spawn` and `best_available_sandbox` (today: fresh-boxed backend *per spawn*, one hardcoded `cfg` arm per kind; a seconds-to-create reusable sandbox cannot live behind a per-spawn constructor). This touches `spawn.rs`, the most audit-sensitive file in Bridle (home of the #317 nineteen-violation audit). It must be done with the same admission discipline, not bolted on.
- **Remote-worker authentication is a distinct sub-problem the seam must solve (C1-bis).** Bridle authenticates a spawned worker with kernel-local primitives — `SCM_CREDENTIALS` from the real parent, `same_image` (dev/ino) identity, and a parent pre/post snapshot in `agent-bridle-tool-shell/src/private_control.rs`; `SO_PEERCRED` in `agent-bridle-jaild`. None of these can authenticate a worker running in a remote container: no shared kernel socket, no parent relation, no shared image inode. The remote fence therefore needs a **cryptographic worker identity** in place of peer-creds — the mesh AgentKey (attenuated, per-AgentKey dock-pinned) is the natural fit, which is why B's execution seam and E's identity/dock work are coupled and should be designed together even though B ships first.
- The local `verify_applied` backstop (recompute the CID of "the caveats about to be applied", refuse on mismatch — spawn.rs:607) **goes vacuous** for a remote fence: "about to be applied" becomes a gRPC hop ending in a self-reported integer. B must replace it with an *evidence-returning* admission (see the applied-policy hash-echo, now a certification blocker, §10) or explicitly record the lost backstop as an assurance residual.
- A `ConfinementMechanism` config carrier must transport *probed* runtime state (nft presence, `hard_requirement`, Landlock ABI) into the honesty mapping, since the same `SandboxKind::OpenShell` enforces differently per probe.

- **Where the compiler lives:** inside the backend crate, desk-side (in the trusted host, *not* in the sandbox). It is exactly `AdmittedFence::admit`'s `project` closure. `admit` runs first; the compiler only ever sees post-`meet` effective caveats.
- **How projection is validated:** the backend implements `resolved_authority`/`runtime_closure` as a *conservative hostile-child upper bound* computed from the **same** routine that emits the policy (anti-drift), so `admit` can prove `resolved ⊑ delegated ∪ runtime_closure` at ruleset grain and refuse on `Superset|Incomparable|Unknown`. Anything OpenShell cannot bound (exec identity, ICMP/SCTP, audit-mode endpoints) resolves `Unknown ⇒ refuse`.
- **How dynamic policy updates are authorized:** narrowing (revoke, tighten) compiles freely and pushes via `UpdateConfig`; **widening requires a new grant → new `EffectiveAuthorityCid` → new `EnforcementPlanCid` → new policy submission.** A gateway interceptor on `UpdateConfig` (which *is* interceptable) denies any policy transition not carrying a valid enforcement-plan CID the authority service authored. The interceptor can't see prior state, but the authority service can — it wrote every admitted policy.
- **How isolation evidence returns to Bridle:** today, weakly — a self-reported version integer. The backend must therefore treat runtime attestation as `partial` (assurance-manifest row), and the *real* evidence for a `Kernel` claim is our own native hostile-child test run inside the pinned image at integration time. Upstream asks (below) would upgrade this.
- **How strength floors operate:** the backend emits `enforcement_report` per axis. fs → `Kernel` **only** if it compiled `landlock.compatibility: hard_requirement` + non-empty paths (else the axis fails the structural fs floor and `admit` refuses). net → `Interceptor` for host allowlists (proxy-enforced) with a kernel deny-direct backstop, and only if nft presence is probed at admission. exec → never `Kernel` (no OpenShell primitive); bounded-by-image, reported honestly.
- **How denials/downgrades propagate to Newt:** unchanged — Bridle's structured `Denial{kind,target,reason}` envelope flows back through the existing tool-result oracle; a projection that would widen returns `Unsupported`, which Newt surfaces as "axis unsupported on this backend," never a silent success.

**Lifecycle reconciliation — the fence key, made precise (C4).** "Sandbox-per-grant" was underspecified: Bridle's `Registry::Grant` is session-scoped with a shared budget, but Newt mints *per-turn attenuated* caveats and its denial→repair loop widens an axis mid-session. Those cannot each spawn a fresh seconds-scale sandbox. Define instead:

> **fence key = (session grant identity × fs/exec scope).** One OpenShell sandbox is created per distinct fs/exec scope within a session and **reused** while that scope holds. The `net` axis is narrowed per-invocation via dynamic `UpdateConfig` (cheap, hot-reloaded, kills in-flight relays). `max_calls`/`valid_for_generation`/presence stay at the Bridle Gate on the mediated channel and are **not** fence properties.

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
                       → what the worker CAN PHYSICALLY do
   invariant:  both descend from the SAME EffectiveAuthorityCid, bound in the CID chain.
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
 workload ─(netns; nft rejects all non-proxy TCP/UDP)─▶ CONNECT proxy (10.200.0.1)
     proxy-side DNS (no workload resolver) → resolved-IP set is what's dialed (rebinding-safe)
     OPA host+L7 policy (MUST be enforcement=enforce, not audit) → upstream (real TLS)
   the ONE authorized egress in E = the mesh dock back to the desk (once a TCP transport exists)
```

### 5.5 CID / provenance chain (honest status)
```
 DelegatedGrantCid ─▶ EffectiveAuthorityCid ─▶ EnforcementPlanCid ─▶ OpenShellSandboxSpecCid
   ─▶ OpenShellPolicyCid(ours, canonical)  ══╗
        [SandboxImageCid: IMPOSSIBLE upstream — no digest pinning]           ▲ signed edges:
   ─▶ AppliedPolicyCid    : Cannot Prove (self-reported int)                 grant→effective→plan
   ─▶ RuntimeEvidenceCid  : Cannot Prove (unsigned, lossy OCSF)              (Ed25519, existing)
   ─▶ ExecutionResultCid  : partial       + [ModelIdentityCid for swarm votes]
   ══╝ gateway policy_hash is NOT canonical → use only as a correlation token.
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
| T15 | **Malicious sandbox image** | poisoned base image runs | **no digest pinning upstream** → pin `template.image` by digest ourselves; `SandboxImageCid` else Cannot-Prove |
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
| `fs_read`/`fs_write` | Landlock `filesystem_policy` | **Exact@create / Narrower after** | `Kernel` **only** with `hard_requirement` + non-empty paths + native test; else refuse |
| `exec` | (none) | **Unsupported / Cannot-Prove** | never `Kernel`; keep exec mediation inside the boundary; image-as-closure is unpinned |
| `net` (host) | CONNECT proxy + OPA + nft | **Narrower** | `Interceptor` for allowlists + kernel deny-direct backstop; MUST emit `enforce`, probe nft; `inference.local` carve-out projected explicitly |
| `max_calls` | (none) | **Exact by not projecting** | stays at Bridle Gate; = swarm fair-share meter for dgx1 |
| `valid_for_generation` | (none) | **Exact by not projecting** | stays at Bridle Gate |
| presence/step-up | (none — draft-approval ≠ presence) | **Unsupported** | stays at Bridle Gate |
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

**Track 2 — B backend**
5. `[agent-bridle-core]` **(re-scoped, C1 — no longer "small")** Add `SandboxKind::OpenShell` + exhaustive `enforcement_report`/`effective_sandbox_kind` arms + a `ConfinementMechanism` probe-carrier **+ a persistent-remote-fence execution seam in `spawn.rs`/`best_available_sandbox`** that admits with the same discipline as the local path and records the loss of the local `verify_applied` backstop as an assurance residual. Split into 5a (enum+report+carrier) and 5b (exec seam) if reviewable separately; 5b is the audit-sensitive one. — *owner: agent-bridle*
6. `[agent-bridle-openshell]` New leaf crate (tonic/tokio here, off core): `Sandbox` impl + `project` compiler (effective Caveats → canonical `OpenShellPolicySpec`), `resolved_authority`/`runtime_closure` conservative bounds, `OpenShellPolicyCid` canonical hash (port `examples/governance-interceptor` protoJSON-v2). — *owner: agent-bridle*
7. `[agent-bridle-openshell, tests]` Property test: `authority(project(c)) ⊑ c` for generated caveats; `Unsupported` on unmediatable axes. — *owner: agent-bridle*
8. `[agent-bridle-openshell]` **(scope-expanded, C6)** Gateway-interceptor widen-guard denying any policy-affecting transition lacking a valid enforcement-plan CID — covering **`UpdateConfig` + `SubmitPolicyAnalysis` + all draft-approve RPCs + `ImportProviderProfiles`/`UpdateProviderProfiles`/`AttachSandboxProvider` + the global-policy path**; documented as *corroborating, not load-bearing* (T22). — *owner: agent-bridle*
9. `[agent-bridle, formal]` TLA+/Lean projection non-amplification model (reuse ADR 0026 harness) + assurance rows (`held`→`partial` on native evidence). — *owner: agent-bridle*
10. `[newt-agent]` Wire the OpenShell backend behind the existing `bridle_registry` seam; no `newt_core` type changes; define the fence key = (session grant × fs/exec scope) + fs-widen volume-handoff (C4). — *owner: newt-agent*

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

1. **Projection theorem holds:** property test `authority(project(c)) ⊑ c` green across generated caveats; TLA+/Lean non-amplification model checked (reusing ADR 0026 harness).
2. **Native hostile-child evidence** (not mock) for every axis claimed above `Advisory`: the §8.7 bypass test fails closed for fs and net, run inside the pinned image; `ASM-OPENSHELL-*` rows carry `evidence_cid`, status `partial`→`held` only with that evidence.
3. **fs Kernel floor proven:** `hard_requirement` + non-empty paths compiled; a policy that would run Landlock best-effort/empty is refused by the compiler, with a test.
4. **net honesty proven:** compiler emits `enforce` (never `audit`), probes nft presence at admission, and refuses when the deny-direct fence is unverifiable; `inference.local` carve-out is an explicitly projected route or refused.
5. **No-widen-without-grant proven:** UpdateConfig widen-guard denies a hand-crafted widening transition lacking a fresh enforcement-plan CID.
6. **Non-equivocation proven:** validated policy == applied policy via our canonical `OpenShellPolicyCid`; a substitution/TOCTOU attempt is rejected.
7. **Control-plane preconditions asserted in code/deploy:** refuse to operate against an unauthenticated gateway; one workspace per trust domain; image digest-pinned.
8. **Honest register:** assurance manifest carries `AppliedPolicyCid`/`RuntimeEvidenceCid`/`SandboxImageCid` as `partial`/`Cannot-Prove` with reasons until closed. **"SKIP is not PASS."**
9. **Applied-policy attestation is a CERTIFICATION BLOCKER, not an open question (C5).** A fs/net `Kernel` claim requires the enforcer to attest *which policy it actually applied*, bound to our `OpenShellPolicyCid`. Today's `ReportPolicyStatus{version:int, LOADED}` cannot carry a `Kernel` claim. The upstream fix (echo the applied-policy hash) must cover the **effective composed** artifact (provider composition legitimately makes loaded ≠ submitted), and until it lands, OpenShell's fs axis is reported at most **Interceptor-grade / `partial`**, never `Kernel` — and native Landlock is preferred on any host where it is available.
10. **fs-vs-Landlock honesty asserted:** the RFC's own §0 statement — B is a net/credential/outer-fence acquisition and an fs downgrade — is reflected in backend selection: `best_available_sandbox` prefers native Landlock for the fs axis on Linux hosts and uses the OpenShell fence for net/placement/outer-boundary, never the reverse.
11. **E-gate (if pursued):** a **TCP framing** mesh transport (not tunneled QUIC — the CONNECT proxy MITMs TLS and doesn't speak QUIC) crosses the boundary in a test, with envelope-sig + Olm ratchet as the in-tunnel confidentiality controls; residual 1 (auto-team PoP + AgentKey pinning) closed; a hostile worker on a dock cannot reach a responder outside its per-AgentKey allowlist.

**Certification is withheld** until 1–10 hold. Prototype/demo success (§8) is explicitly *not* certification.

---

## Appendix — open questions for a second review pass

Resolved in v2 (moved to blockers/decisions): the applied-policy hash-echo is now a **certification blocker** (exit 9), not an open question; the AND-invariant scope and the fs-downgrade framing are decided (§0/§5.2). Remaining genuinely-open:

- Is `template.image` digest-pinning (ours) sufficient for `SandboxImageCid`, or must we also pursue upstream image attestation? (Leaning: our digest-pin suffices for `partial`; upstream needed for `proved`.)
- **The upstream engagement question:** several fixes are one-to-few-field upstream PRs to NVIDIA/OpenShell (applied-policy hash echo over the *effective composed* artifact; add `StopSandbox`/`StartSandbox` to the interceptor allowlist; populate `validate_current_state`). Pursue upstream, or carry a fork/shim? (Constraint: do not fork unless demonstrably necessary.)
- For E: the transport must be **TCP framing** (not tunneled QUIC — the CONNECT proxy MITMs TLS and doesn't speak QUIC). Open sub-question: reuse `stream.rs` framing over a raw CONNECT tunnel, or ride streamable-HTTP? Both are TCP; which is less work and less MITM-exposed?
- Does the swarm want arbiters as *separate sandboxes* (strong isolation, higher cost) or read-only-grant workers in a shared sandbox (cheaper, weaker; but shared-sandbox re-introduces the exec-mediation gap)? Model-diversity requires arbiters pinned to distinct model families regardless; `ModelIdentityCid` in the evidence chain is required either way.
- Is "outer-fence-only" (no nested Bridle confinement inside the sandbox, because nested seccomp/Landlock may be unavailable — §8.4) acceptable for the worker, or must slice 2 negotiate nested enforcement? This decides whether the worker can be a full Newt or must stay wyvern-shaped.
- k3s substrate: verify nuc1/nuc2 reachability and roles before A/E assume a Kubernetes deployment target.

---

*This RFC has had one adversarial review pass (findings C1–C6 folded in as v2). Per the study charter it should get at least one more independent hostile review — with fresh eyes on the re-scoped PR 5 exec seam (C1) and the fs-downgrade claim (C5) — before any implementation GO.*
