# Upstream contribution proposals — NVIDIA/OpenShell

Companion to [ADR 0027](../adr/0027-openshell-authority-projection.md) and the
[integration RFC](openshell-integration-rfc.md). These are the changes to
[NVIDIA/OpenShell](https://github.com/NVIDIA/OpenShell) that would let it serve
faithfully as an *enforcement projection* of Bridle authority. They are grounded
in a read of OpenShell at commit **`0f8fad23`** (the study pin; re-verify against
`main` before filing — OpenShell moves daily).

**Status: proposals, not filed.** Whether to pursue any of these upstream versus
carry a local shim is a deliberate decision (constraint: *do not fork unless an
adapter or upstream extension is demonstrably impossible*). Filing issues/PRs on
NVIDIA's public repo is an outward-facing action reserved for an explicit human
GO. Each item below notes whether a **local shim** is a viable alternative.

Legend for **Blocking?**: does the absence of this upstream block *our*
certification (not merely inconvenience us)?

---

## U1 — Applied-policy attestation (echo the effective-policy hash in `ReportPolicyStatus`)  ·  **Blocking: YES**

**Gap.** The only feedback the enforcer gives the control plane about what it
actually loaded is `ReportPolicyStatus{ sandbox_id, version:uint32,
status:LOADED|FAILED, load_error }` (`proto/openshell.proto:414-416`, msg
`:1947-1957`; handler `crates/openshell-server/src/grpc/policy.rs:3119-3196`,
which trusts the self-report and CAS-updates `current_policy_version`). There is
**no policy hash, no serialized applied policy, no signature** in that message —
`active_version` is a supervisor self-assertion of an integer, and the gateway
never verifies that the bytes the supervisor loaded match the bytes it stored.
Consequently an external authority cannot bind runtime evidence to *which* policy
was enforced. In the product model (RFC §A.4, R3-2) this leaves the OpenShell
fs/net **mechanism at Kernel** (honest — in-sandbox Landlock constrains the child
interior) but the **per-invocation evidence at CannotProve**. Since the fs floor is
structurally Kernel, a restricted-fs RemoteFence **refuses admission pre-U1** unless
the operator sets an explicit CannotProve evidence floor. **U1 is precisely the
change that raises the evidence dimension** (CannotProve → Attested) so a
mechanism-Kernel fence becomes admissible against a Kernel/Attested floor. It does
**not** change the mechanism class — that was already Kernel.

**Proposal — trust path corrected (R3-6).** The sandbox holds **no signing key**:
the **gateway** signs the Ed25519 sandbox JWT at create time and the supervisor
merely presents it as a bearer credential (`crates/openshell-server/src/auth/sandbox_jwt.rs:6-7`).
So U1 is **not** "the sandbox signs an attestation." The realizable model is:

```
trusted supervisor  --applied_policy_hash over the bearer-authenticated ReportPolicyStatus-->  gateway
gateway  verifies the sandbox-authenticated channel, then EMITS/STORES a gateway-signed receipt binding:
    { sandbox identity, applied-policy CID/hash, policy generation, report sequence, gateway identity }
```

The hash MUST cover the **effective composed** policy (provider composition makes
loaded ≠ submitted — `crates/openshell-server/src/grpc/policy.rs:1860-1878`); pair
with a canonical hash (U2).

**What the receipt proves — stated precisely.** *"The trusted OpenShell supervisor
reported applying this effective policy, and the gateway authenticated that
report."* It does **NOT** prove correct enforcement against a **compromised
supervisor** — the supervisor (root PID 1 in the sandbox) is part of **B's TCB**;
that is an explicit trust assumption, not something U1 removes. A stronger root
(remote attestation / measured boot of the supervisor) would be a separate,
larger dependency, not this PR. If a workload-signing design (SPIFFE-SVID issuer /
verifier / audience / key-custody) is later preferred, it must be specified
concretely against the then-current OpenShell — the SVID path is not wired for
policy attestation at the pinned commit.

**Size.** Small-to-medium: one proto field + a gateway-side signed-receipt store;
the supervisor already computes the change-detection hash
(`crates/openshell-sandbox/src/lib.rs:2559`).

**Local shim?** No. Attestation of the enforcer's actual state cannot be
synthesized from outside the enforcer; this is the one item that genuinely needs
upstream. A native hostile-child probe at provisioning attests the mechanism class
at t0, not the applied policy per generation — so it raises evidence to at most
`Reported`, never `Attested`.

---

## U2 — Canonical, domain-separated policy hash  ·  **Blocking: NO (we compute our own)**

**Gap.** The production `deterministic_policy_hash` (`crates/openshell-server/src/grpc/policy.rs:4391-4424`)
hashes prost-encoded protobuf bytes. Nested proto `map<>` fields (`L7Allow.query`,
`.params`, `graphql_persisted_queries`) have unspecified wire order; only the
top-level `network_policies`/`network_middlewares` maps are explicitly sorted; the
framing is inconsistent (only the middleware section is length-framed). Two
semantically identical policies can hash differently. The gateway also *overwrites*
the stored revision hash with a recomputed effective hash at read time
(`policy.rs:1875`), so `GetSandboxConfigResponse.policy_hash` and the stored
`SandboxPolicyRevision.policy_hash` for the same version can diverge.

**Proposal.** Adopt the recursive, key-sorted, length-framed protoJSON digest that
already exists **in the OpenShell tree** as example code:
`examples/governance-interceptor/src/policy_hash.rs`
(`HASH_ALGORITHM = "openshell-governance-protojson-sha256-v2"`, prefix
`sha256:v2:`), whose own test proves nested map-order independence — exactly the
property the production hash lacks. This is an upstream-appetite signal: the right
pattern is already written, just not on the production path.

**Size.** Medium: replace the production hash function; it's used as a
change-detection/dedup token so the blast radius is contained, but it touches the
revision store.

**Local shim?** **Yes.** Our `agent-bridle-openshell` backend computes its own
canonical `OpenShellPolicyCid` over the spec it submits and treats the gateway
`policy_hash` only as a correlation token. Upstreaming U2 would let U1's attested
hash agree with ours end-to-end; without it, we bridge via our own CID. So U2 is
*desirable to make U1 fully useful*, not independently blocking.

---

## U3 — Running-image digest recording — `RequestedImageCid` vs `AttestedImageCid` (R3-4)  ·  **Blocking: NO for intent; attested-image is Cannot-Prove without it**

**The two facts, kept separate (HIGH 4).** *Requested* image identity (what Bridle
pinned) is **not** *attested* image identity (what OpenShell actually launched):

- **`RequestedImageCid`** — we pin `template.image` to a `…@sha256:…` digest
  ourselves. This is strong **intent**, available now, and is part of
  `StaticFenceCid` and `SandboxPrincipalBinding`. It requires no upstream work.
- **`AttestedImageCid`** — proof of the running image. **Cannot-Prove today.** No
  image digest is resolved, recorded, or surfaced in the gateway:
  `SandboxTemplate.image` (`proto/openshell.proto:827`) is a *tag* reference; the
  server fills a default when empty (`crates/openshell-server/src/grpc/sandbox.rs:264-269`);
  the OCSF `Image` object carries only `name`, no digest
  (`crates/openshell-ocsf/src/objects/container.rs:23-28`).

`SandboxPrincipalBinding` carries `RequestedImageCid` and MUST NOT imply
`AttestedImageCid` — same epistemic discipline as `OpenShellPolicyCid` (intent) vs
`AppliedPolicyCid` (attested).

**Proposal.** Resolve and record the image **digest** at sandbox creation, store it
on `SandboxStatus`, surface it in the OCSF `Image` object (and ideally
`gh attestation verify` the digest — the VM-kernel path already does this at
`.github/workflows/release-vm-kernel.yml:254`). This is what turns
`AttestedImageCid` from Cannot-Prove into evidence.

**Size.** Small-to-medium: digest resolution at create, one status field, one OCSF field.

**Local shim?** For **`RequestedImageCid`**: yes, fully (we pin the digest). For
**`AttestedImageCid`**: no — recording what actually ran cannot be synthesized from
outside the gateway. Do not let the requested digest masquerade as runtime proof.

---

## U4 — Interceptor allowlist completeness (Stop/Start, and the opt-out principle)  ·  **Blocking: NO (fence carries mediation), but recommended**

**Gap.** `INTERCEPTABLE_METHODS` is a hard 25-entry opt-**in** allowlist
(`crates/openshell-gateway-interceptors/src/routes.rs:16-43`, unary-only). PR #2653
added `StopSandbox`/`StartSandbox` RPCs but **did not add them to the allowlist**,
so an external interceptor cannot see, mutate, or deny stop/start. Reads
(`GetSandbox`, `ListSandboxes`) and all streaming data-plane RPCs (`ExecSandbox`,
`ForwardTcp`, `ConnectSupervisor`, `RelayStream`) are also non-interceptable. This
contradicts RFC 0010's own stated intent that interceptors cover "all relevant
gateway RPCs, not a hand-maintained subset" (`rfc/0010-gateway-interceptors/README.md:124-133`).

**Proposal.** (a) Add `StopSandbox`/`StartSandbox` to `INTERCEPTABLE_METHODS`
(one-line fix + tests). (b) Longer term, invert to opt-out with explicit
justification per exempted RPC, per RFC 0010.

**Size.** (a) trivial; (b) larger, design-touching.

**Local shim?** Partial. Our design treats the interceptor widen-guard as
*corroborating, not load-bearing* (the always-on kernel/netns fence does the real
mediation), so this is not certification-blocking — but closing (a) removes a
blind spot where a workspace `user` can suspend/resume a fence unobserved by the
authority service.

---

## U5 — Populate `validate_current_state` for interceptors  ·  **Blocking: NO**

**Gap.** `EvaluationContext.validate_current_state` is **always `None`** in
production (`crates/openshell-server/src/multiplex.rs:586-593`), so an interceptor
in the `validate` phase cannot see prior state to compare a proposed change against
— it sees only the proposed request. RFC 0010 specifies read-only prior state.

**Proposal.** Populate `validate_current_state` from the store for the validate
phase, as RFC 0010 intended.

**Size.** Medium (a store read on the hot path; must respect the secret-redaction
path already in place).

**Local shim?** **Yes.** Our authority service authored every admitted policy, so it
already knows the prior state and does the widen-vs-narrow comparison itself. This
would make an interceptor-only deployment (topology D-lite) more viable, but our
recommended B does not depend on it.

---

## U6 — Authenticate the interceptor transport (mTLS/bearer)  ·  **Blocking: NO for B; YES for any D-shaped variant**

**Gap.** The gateway dials interceptors with `ClientTlsConfig` system-roots only —
**no client cert, no bearer token** (`crates/openshell-gateway-interceptors/src/plan.rs:885-896`)
— contradicting RFC 0010 §275-278 ("connections require authentication… mTLS and
bearer-token"). The gateway also "treats configured interceptors as trusted sources
and does not verify signature annotations in their profile payloads"
(`architecture/gateway.md:138-140`).

**Proposal.** Implement mTLS/bearer to the interceptor per RFC 0010; verify
interceptor-supplied signature annotations.

**Size.** Medium.

**Local shim?** For **B**: not needed (we don't put authority decisions on the
interceptor). For any future **D**-shaped deployment where Bridle *is* the
interceptor, this is a hard prerequisite — which is one more reason the RFC rejects
D on today's substrate.

---

## U7 — A "strict" enforcement profile (fail-closed defaults)  ·  **Blocking: NO (compiler enforces on our side)**

**Gap.** Several controls default **fail-open**, each a place where "sandbox exists"
≠ "enforcement active": Landlock `compatibility` defaults to `best_effort` — three
failure paths run the workload with *zero* filesystem restriction while only
logging a High finding (`crates/openshell-supervisor-process/src/sandbox/linux/landlock.rs:157-179,269-289,309-332`);
L7 endpoint `enforcement` defaults to `audit` = allow-and-log
(`crates/openshell-supervisor-network/src/l7/mod.rs:202-206`); a missing `nft`
binary silently skips the direct-egress fence (`.../netns/mod.rs:264-278`);
`inference.local:443` bypasses OPA network policy entirely
(`.../proxy.rs:1218-1243`); and an unauthenticated gateway defaults to a
full-admin principal (`crates/openshell-server/src/multiplex.rs:944-955`).

**Proposal.** A gateway/deployment profile flag (e.g. `strict_enforcement = true`)
that flips these to fail-closed: `hard_requirement` Landlock, `enforce` L7, refuse
to start without an egress fence, no `inference.local` OPA carve-out, refuse the
unauthenticated principal. This is opinionated and may meet upstream resistance;
frame it as an *opt-in hardening profile*, not a default change.

**Size.** Medium; politically the largest.

**Local shim?** **Yes.** Our `project` compiler already emits `hard_requirement` +
`enforce`, probes nft presence at admission, projects the `inference.local` route
explicitly, and refuses an unauthenticated gateway as a precondition. So U7 is a
"make the safe thing easy for everyone" contribution, not something we need.

---

## U8 — Mediate agent-driven policy widening (`SubmitPolicyAnalysis` + provider mutations)  ·  **Blocking: NO (we gate on our side), but security-relevant upstream**

**Gap.** `SubmitPolicyAnalysis` is **sandbox-callable** (`proto/openshell.proto:494`);
with `proposal_approval_mode=auto`, an empty prover delta auto-approves
(`crates/openshell-server/src/grpc/policy.rs:893-924`). The prover round-trips
proto→YAML into its own serde types with `IgnoredAny`, so `deny_rules`,
`credential_binding`, `allow_encoded_slash` are **invisible to the SMT model**
(`policy.rs:519-521`, prover `crates/openshell-prover/src/policy.rs`). Provider
mutations (`ImportProviderProfiles`/`UpdateProviderProfiles`/`AttachSandboxProvider`)
and the global-policy path change effective policy without an `UpdateConfig`, and
the global path self-marks `loaded` before any sandbox confirms
(`policy.rs:2381-2519`). These are policy-widening channels *originating inside the
sandbox TCB* whose gate is a prover blind to enforced fields.

**Proposal.** (a) Make the prover analyze the *same* artifact that is enforced
(drop the lossy re-parse). (b) Make `SubmitPolicyAnalysis`, the approve RPCs, and
provider mutations interceptable so an external authority can gate them. (c)
Document `proposal_approval_mode: manual` as the secure default for
externally-governed deployments.

**Size.** (a) medium; (b) small (allowlist additions); (c) docs.

**Local shim?** **Yes.** We require `proposal_approval_mode: manual` as a
deployment precondition and extend our widen-guard to cover these RPCs. Upstreaming
(a) is a genuine correctness/security improvement for OpenShell independent of us.

---

## Summary

| # | Contribution | Blocking our cert? | Local shim viable? | Upstream size |
|---|---|---|---|---|
| U1 | Applied-policy attestation (hash echo, effective policy) | **YES** | **No** | small |
| U2 | Canonical policy hash | no | yes (our CID) | medium |
| U3 | Image digest pinning | no | yes (pin ref) | small–med |
| U4 | Interceptor allowlist: Stop/Start | no | partial | trivial (a) |
| U5 | Populate `validate_current_state` | no | yes | medium |
| U6 | Authenticate interceptor transport | no (B) / yes (D) | n/a for B | medium |
| U7 | Strict fail-closed profile | no | yes (compiler) | medium |
| U8 | Mediate agent-driven policy widening | no | yes | small–med |

**The one that must go upstream is U1** — attestation of the enforcer's actual
applied policy cannot be synthesized from outside the enforcer, and without it the
fs/net axes cannot honestly carry a `Kernel` claim. Everything else has a viable
local shim in `agent-bridle-openshell`; upstreaming them is "make the safe thing
the easy thing" rather than a dependency. Recommended engagement order if a GO is
given: **U4(a)** (trivial goodwill PR) → **U1 + U2** (the attestation pair, the
substantive contribution) → **U8(a)** (prover fidelity) → the rest as appetite
allows.
