# Semantic Policy Crosswalk — Bridle Caveats/enforcement axes ↔ OpenShell primitives (DRAFT)

Pinned: agent-bridle `d1cb545` (+#319 delta on origin), OpenShell `0f8fad23`, newt-agent `4ab6a7be`.
Labels: **Exact | Narrower | Approximation | Unsupported | Cannot Prove**. `Approximation` and `Cannot Prove` must not silently pass a strength floor.

> **v3 alignment (normative model = RFC §A).** This crosswalk predates the v3
> corrections; where it conflicts, RFC **§A** wins. Two structural corrections
> apply throughout: **(a)** the four `fs_read/fs_write/exec/net` are the projectable
> **FenceCaveats**; `max_calls`/`valid_for_generation` are Gate-only **GateCaveats**
> and are **not** projected (RFC §A.2) — so their old "Exact by not projecting"
> label is replaced by "mediated = Exact / direct-exec = Unsupported." **(b)** the
> reported strength is `min(MechanismStrength, EvidenceCap)` (RFC §A.4): OpenShell's
> in-sandbox Landlock is *mechanism-Kernel* but the **claim is capped at
> Interceptor until applied-policy attestation (U1)** — never report bare `Kernel`.

Bridle authority = mesh `Caveats` (6 fields): `fs_read`, `fs_write`, `exec`, `net` (**FenceCaveats**, OS-confinement, `Scope<String>`), `max_calls`, `valid_for_generation` (**GateCaveats**, gate-enforced only). Achieved **MechanismStrength** lattice: `Kernel > Interceptor > Advisory`; the advertised claim is capped by **EvidenceStrength** (§A.4).

## Axis rows

### 1. `fs_read` / `fs_write` → `filesystem_policy.read_only` / `read_write` (in-sandbox Landlock)
- **Mapping label: Narrower; MechanismStrength `Kernel` under the conditions below, but reported claim CAPPED at `Interceptor` until per-invocation applied-policy attestation (U1) — never bare `Kernel` (§A.4). Enforced by OpenShell's *in-sandbox* Landlock, not desk-local Landlock (§A.1).**
- Conditions the projection compiler MUST emit:
  - `landlock.compatibility: hard_requirement` — the default `best_effort` runs the sandbox with ZERO fs restriction on 3 failure paths (landlock.rs:157-179, 269-289, 309-332), each returning Ok. Default = fail-open; hard_requirement makes each fatal. A projection that omits this silently violates the fs Kernel floor.
  - Non-empty path lists — empty `filesystem_policy` short-circuits Landlock entirely (landlock.rs:146; the one default-ALLOW in OpenShell's model). `Scope::All` on fs axes → do NOT emit empty policy; either refuse (floor demands Kernel bound) or emit explicit broad roots.
  - Typo hazard: any string ≠ literal `"hard_requirement"` silently becomes best_effort (policy.rs:141-150). Compiler must emit the exact literal and property-test it.
- Lifecycle: fs policy is STATIC (additive-only post-create; additions inert until restart — validation.rs:855-917). So fs authority is fixed at sandbox creation → matches AdmittedFence semantics only when sandbox is created per-grant (E/B pattern), not per-invocation reuse with varying caveats.
- **Runtime closure**: supervisor baseline enrichment (proxy support files, /etc, GPU nodes — openshell-sandbox lib.rs:1291-1460) is exactly Bridle's `RuntimeClosure`; the backend must declare these enriched paths and pass harness-disjointness (refuse if they reach `.newt/.ssh/...`).
- Evidence: application is self-reported (`ReportPolicyStatus{version, LOADED}` — an integer; no hash, no signature). Landlock-active exists only as log lines. → per ADR 0023, achieved `Kernel` claim requires our own native hostile-child test inside a pinned-image sandbox at integration time; runtime attestation is **Cannot Prove** upstream today.

### 2. `exec` → (no OpenShell primitive)
- **Mapping label: Unsupported (kernel grain) / Approximation (image-as-closure) / Cannot Prove (image identity).**
- OpenShell has no exec allowlist: `process` policy is run_as identity only; seccomp is a fixed denylist (default-allow, seccomp.rs:6-13,146); any binary present in the image executes freely. `network_policies.binaries` binds *egress* to binaries, not execution.
- Best available: the sandbox image IS the exec closure — but OpenShell does **no image digest pinning** (only `SandboxTemplate.image` tag; no digest resolved/recorded anywhere), so the closure has no verifiable identity → **Cannot Prove**. Upstream ask #1: digest-pin + record image identity.
- Practical resolution per topology: keep exec mediation *inside* the boundary (wyvern's 4-tool surface, or bridle-in-sandbox) and treat OpenShell's boundary as the outer fence bounding what an un-mediated exec can reach (fs/net axes). Report exec axis honestly as bounded-by-image (Advisory→Interceptor at best), never Kernel.

### 3. `net` (host-grain `Scope<String>`) → `network_policies` (CONNECT proxy + OPA + netns/nft)
- **Mapping label: Narrower (host→host+port+L7 available), strength `Interceptor` with a kernel deny-direct backstop; Kernel claim conditional and currently Cannot Prove remotely.**
- Strong parts: deny-by-default Rego (`default allow_network = false`); DNS resolved proxy-side, workload netns rejects all UDP incl. :53; resolved-IP set is what's dialed (no re-resolution → rebinding-safe, destination.rs:101-132); SSRF always-blocked classes; per-sandbox netns + veth + nftables reject of direct TCP/UDP; seccomp blocks AF_PACKET/VSOCK and non-ROUTE netlink.
- Honesty deductions the backend's `enforcement_report` must encode:
  - Host filtering is userspace OPA in the proxy → **Interceptor**, not Kernel (analogous to bridle's egress-proxy classification). The nft fence gives kernel-grade "no direct egress", i.e. the `net:none`-style DenyDirect property, but host-allowlist selectivity is proxy-enforced.
  - Fail-open paths that would demote to Advisory/Unknown if not excluded by deployment: missing `nft` binary → bypass rules silently skipped (netns/mod.rs:264-278); bypass-rule install failure non-fatal (427-438); `ct`/`log` rules optional; nft chain policy `accept` — ICMP/SCTP/other-L4 fall through (nft_ruleset.rs:53,106-201; netns routing still bounds destination but not protocol).
  - **L7 `enforcement` defaults to `audit` = allow-and-log** (l7/mod.rs:202-206; relay.rs:702 …). Projection MUST emit `enforcement: enforce` on every endpoint. Anything else is Advisory.
  - **`inference.local:443` bypasses OPA entirely** (proxy.rs:1218-1243) — the inference route is an un-mediated authority channel unless the projection accounts for it (see Inference row).
  - `tls: skip` endpoints and protocol-less endpoints degrade to L4 raw relay — fine, but label those endpoints L4/Interceptor, no L7 claims.
- Bridle vocabulary: keep `Caveats.net` host-grain (Option A of the network investigation). OpenShell port/method/path rules enter as mechanism-side narrowing via the `#[non_exhaustive]` `NetRule` (`Rest{..}` placeholders, #153) and resolved-scope `classes`. No trusted-core vocabulary expansion needed for slice 1.

### 4. `max_calls` / `valid_for_generation` (GateCaveats — NOT projected, §A.2)
- **Mediated MCP/Gate path: Exact** (`Gate::authorize` budget CAS `gate.rs:244-270` + generation check `gate.rs:228-238`). **Direct in-sandbox exec path: Unsupported** — the Gate is not in the syscall path, so an unmediated shell op consumes no budget and honors no generation bound. Do **not** label these "Exact by not projecting" (I2). OpenShell has no call budgets (RFC 0011 Phase 6 quotas unimplemented). **Admission rule:** a grant carrying a restrictive `max_calls`/`valid_for_generation` over a worker that has direct-exec authority MUST **fail admission** (§A.2, adversarial case 8).
- Swarm fair-share of dgx1 inference = `max_calls` metering at the Bridle gate fronting the inference capability (mode-3 justification), optionally hard-bounded by OpenShell L7 rate middleware later (none built-in today).

### 5. Step-up / presence / attestation
- **Exact via Bridle (desk-side); Unsupported natively in OpenShell.** OpenShell's draft-policy approve flow is operator approval of *policy changes*, not per-act human presence; do not conflate. `Presence`/`Discharge` stays in the Gate before any mesh dispatch/OpenShell call.

### 6. Credential non-equivocation → provider placeholders + proxy substitution
- **Mapping label: Exact in mechanism — this is OpenShell's best alignment with Bridle.** Workload sees only `openshell:resolve:env:v7_*` placeholders (process.rs:166-173; provider_credentials.rs:853); proxy substitutes real creds per-request AFTER destination + L7 admission, scoped to the provider profile's endpoints; cross-endpoint use → 403; endpoint-mismatch emits a High finding; SigV4 signing without disclosure; Bedrock model-path force-rewrite.
- Deductions: middleware/interceptor transports have NO client auth (server-TLS only) — anything on those channels is inside the TCB without being authenticated; gateway "does not verify signature annotations" from interceptors (architecture/gateway.md:138-140). Vault integration should feed the provider store gateway-side; workers never receive raw material.

### 7. Dynamic policy changes → `UpdateConfig` (static/dynamic split)
- Static domains (fs additive-only, landlock, process frozen) + dynamic network domains map well to: **narrowing freely desk-side; widening only via a new Bridle grant → new CID → new UpdateConfig**.
- Enforcement of "no widening without Bridle": bind via gateway interceptor on `UpdateConfig` (IS in the 25-method allowlist) — deny any policy transition not carrying a valid EnforcementPlanCid annotation. BUT: interceptor bindings are static config, unauthenticated transport, and `validate_current_state` is always None (multiplex.rs:586-593) — the interceptor cannot see the prior policy, so widen-vs-narrow comparison needs the authority service to track state itself (it can: it authored every admitted policy).
- Hot reload semantics are GOOD: policy generation counter; in-flight relays (incl. idle streams) are killed on any generation change (relay.rs select! on `wait_until_stale`) — no stale-authorization continuation. Fail-closed quarantine generation on invalid candidate (default `fail_closed`).
- Revocation: Bridle revoke → compile deny-all/quarantine network policy push (narrowing, immediate, kills relays) + `StopSandbox` for hard revoke. Note stop/start does NOT revoke the sandbox JWT (nothing revokes it before delete) — treat stop as suspension, delete as revocation of identity.

### 8. Provenance / CID chain → (mostly absent upstream)
- OpenShell-side identities available today: sandbox UUID + `spiffe://openshell/sandbox/<uuid>` JWT subject; `policy_hash` (SHA-256, gateway-computed); `version` counter; `config_revision`; provider-env revision.
- **`policy_hash` is NOT canonical**: hashes prost bytes; nested proto maps (L7Allow.query/params, persisted queries) have unspecified encoding order; only top-level maps sorted; framing inconsistent (policy.rs:4391-4424). Also the delivered hash for a version can differ from the stored revision hash when provider composition is active (policy.rs:1875), and the supervisor never verifies hash-vs-bytes (grpc_client.rs:783-800). → `OpenShellPolicyCid` must be computed by OUR compiler over OUR canonical encoding of the spec we submit; treat gateway `policy_hash` as a correlation token only. The repo's own `examples/governance-interceptor/src/policy_hash.rs` ("openshell-governance-protojson-sha256-v2", recursive key-sorted protoJSON, length-framed) is the right pattern and proves upstream appetite.
- `SandboxImageCid`: **impossible today** (no digest pinning). `AppliedPolicyCid`/`RuntimeEvidenceCid`: **Cannot Prove** (self-reported ints; unsigned, lossy, opt-in OCSF; no attestation path). Chain today is honest only as: DelegatedGrantCid → EffectiveAuthorityCid → EnforcementPlanCid → OpenShellSandboxSpecCid → OpenShellPolicyCid (ours, canonical) → [gap: applied/evidence = partial, ASM row]. Upstream asks: signed applied-policy attestation (hash echo in ReportPolicyStatus would be a 1-field PR), image digest pinning, signed/structured OCSF export.

### 9. Evidence honesty summary (strength-floor consequences)
| Bridle demands | OpenShell provides | Verdict |
|---|---|---|
| fs Kernel floor | in-sandbox Landlock hard_requirement + non-empty paths + native test | Mechanism-Kernel achievable; **reported claim capped at Interceptor until U1 attestation** (§A.4), never bare Kernel |
| exec bound | image contents, unpinned | Refuse Kernel; Advisory/bounded-by-image; keep exec mediation inside boundary |
| net bound | proxy Interceptor + nft DenyDirect backstop | Interceptor for allowlists; deployment must guarantee nft present (probe at admission) |
| budgets/generation | none | Gate-only: **mediated = Exact, direct-exec = Unsupported** (§A.2); restrictive grant over direct-exec worker → fail admission |
| presence/step-up | none | Gate-only: **mediated = Exact, direct-exec = Unsupported** (§A.2) |
| applied-policy proof | version int self-report | Cannot Prove → assurance manifest `partial`, never `proved` |
| image identity | tag only | Cannot Prove → upstream PR or pin-by-digest ourselves in template.image |
| audit trail | unsigned lossy OCSF | Advisory evidence only |

### 10. Control-plane preconditions (deployment floors, not per-axis)
Any deployment where these are false is `Unknown ⇒ refuse`:
- OIDC or mTLS configured — otherwise **unauthenticated dev principal = full admin** (multiplex.rs:944-955, roles openshell-admin, scope openshell:all).
- Dedicated workspace per trust domain; authz bottoms out at workspace grain (no per-sandbox owner; any workspace `user` can Exec/Stop/Delete ANY sandbox in it; empty admin_role ⇒ everyone is platform_admin — workspace_authz.rs:172-174).
- Docker driver runs supervisor as UID 0, `apparmor=unconfined`, CAP_SYS_ADMIN/NET_ADMIN/SYS_PTRACE — the sandbox TCB includes the supervisor; workload hardening (privilege drop, caps cleared, landlock, seccomp) is what stands between workload and supervisor. Native hostile-child tests must target the workload posture, not the container posture.
- Interceptor allowlist gaps: Stop/Start NOT interceptable (PR #2653 didn't extend routes.rs); reads and streaming (Exec!) not interceptable — an authority interceptor CANNOT mediate exec sessions; complete mediation therefore cannot be built on interceptors alone (rules out pure-D).

## Topology-relevant lifecycle note
Bridle enforcement is invocation-scoped/parent-owned (fresh backend per spawn); OpenShell sandboxes are persistent store objects. Reconciliation: **sandbox-per-grant** (fence lifetime = grant lifetime; static fs/exec fixed at creation from the effective caveats; dynamic net narrowed per-invocation), NOT sandbox-per-invocation (seconds-scale create) and NOT shared-sandbox-across-grants (violates non-equivocation). Stop/start = suspension of the same fence (policies/providers/data survive, sessions torn down); delete = end of fence; JWT lives until delete.
