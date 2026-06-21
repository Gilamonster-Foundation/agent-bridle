# ADR 0002 — Object-capability security as agent-bridle's design contract (hard invariants)

- Status: Accepted
- Date: 2026-06-21
- Context: the whole of `agent-bridle` (core gate, tool-shell, tool-web,
  Landlock sandbox, MCP frontend) and its relationship to
  `agent-mesh-protocol::Caveats`
- Supersedes nothing; **extends** ADR 0001 (which decided the *three
  enforcement layers*) by stating the *binding contract the layers exist to
  uphold*.
- Companion prose (the "why", at length): the position paper *The Age of the
  Confused Deputy* (`knowledge:board/papers/2026-06-18_age-of-the-confused-deputy.md`),
  `agent-bridle/docs/DESIGN.md`, and
  `newt-agent/docs/decisions/agentic_object_capability_security.md`.

## Question

ADR 0001 and DESIGN.md describe *how* bridle enforces. This ADR answers a
different question, the one that lets us add tools and crates without eroding
the guarantee: **what are the invariants that make agent-bridle an
object-capability enforcer, such that violating any one of them is a release
blocker — and where is each one enforced today?**

This is the design contract restated as testable teeth. The prose argues it;
this document is the checklist a reviewer (human or agent) holds a PR against.

## The thesis, in one paragraph

An LLM agent harness is Hardy's **confused deputy** [1] at machine scale: it
runs with the operator's **full ambient authority** while taking instruction
from **untrusted channels** (model continuation, tool output, fetched pages,
file and issue text). Prompt injection is literally *confuse the deputy*. You
cannot fix a structural authority defect with prompt hygiene or
injection classifiers — those claw authority back *after* identity and
authority have been fused. The fix is to never fuse them: model authority as a
bounded **meet-semilattice**, make delegation **attenuation-only** (no
reachable amplify), and enforce the resulting capability **at the point of use,
through a token a tool cannot forge**. Then a fully tricked model is merely a
deputy with a small badge — confused, perhaps, but **harmless by
construction**. OCAP does not make the agent un-confusable; it makes confusion
*non-escalating and survivable*. The operative principle is therefore not
"prevent confusion" but **grant so little that confusion cannot exceed the
task's blast radius** (least authority as the safety mechanism, not as
hygiene).

## The hard invariants (the contract)

Each invariant is a **MUST**. The enforcement column names the mechanism (not
line numbers — those rot); the status is honest about what is shipped versus in
flight, in the same spirit as the rest of the project ("never overclaim").

### A. Authority is bounded by construction

| # | Invariant (MUST) | Enforced by | Status |
|---|---|---|---|
| **I1** | A tool can perform **no** authority-bearing action without a `ToolContext`, and a `ToolContext` is constructible **only** inside `Gate::authorize()`. There is no public constructor, no `pub` field, no `Default`, no `Clone`-from-parts path. | `agent-bridle-core`: private fields on `ToolContext` + crate-private `ToolContext::mint`; `#![forbid(unsafe_code)]`; `compile_fail` doctests proving it cannot be forged outside the gate. | **Enforced (by construction)** |
| **I2** | Effective authority handed to a tool is `granted.meet(required)` — the **meet**, never the max, of what the session was granted and what the tool declared. | `Gate::authorize` computes `effective = granted.meet(&tool.required())` and mints that. | **Enforced** |
| **I3** | The authority algebra contains **no reachable amplify operation**: for all `a, b`, `meet(a,b) ⊑ a ∧ meet(a,b) ⊑ b`. Delegation can only attenuate. | `agent_mesh_protocol::Caveats` — `Scope = All \| Only(set)`, `meet` = intersection with `All` as identity; the `meet_never_amplifies` **property test** is the law. bridle *depends on* this type and MUST NOT reinvent it. | **Enforced (property-tested upstream)** |

### B. Enforcement is at the point of use; static reasoning is never authoritative

| # | Invariant (MUST) | Enforced by | Status |
|---|---|---|---|
| **I4** | Every actual `exec`/`open` is checked against the unforgeable `effective` caveats **at the moment it executes**, depth-agnostic. No static/AST verdict may ever *clear* what runtime would deny (it may only *defer* or *fail-fast deny*). | `agent-bridle-tool-shell` `CaveatInterceptor::before_exec` / `before_open`, firing at the brush fork's single external-spawn funnel and `Shell::open_file`. See ADR 0001 (L1 additive, L2 authoritative). | **Enforced (L2)** |
| **I5** | **Fail closed.** Absence of a grant grants **nothing**. A missing/empty/unparseable caveat set denies all authority-bearing operations. | `CaveatInterceptor` denies when context is `None`; the MCP frontend defaults a missing grant to the empty caveat set (#25 — "a missing grant grants nothing"). | **Enforced** |
| **I6** | Path checks **canonicalize with no-follow first, then test containment** component-wise. No string-prefix matching; `..` in an unresolved tail is refused; a dangling symlink cannot widen scope. | `agent-bridle-core` `canonicalize_for_check` (`lstat`/`O_NOFOLLOW`, bounded hop resolution, reject `..`) before `path_is_within`. Closed the dangling-symlink write escape (§Evidence). | **Enforced** |
| **I7** | There is **no in-shell path to replace-process or otherwise escape the spawn funnel.** The confined builtin set omits `exec` (and any builtin that reaches `cmd.exec()` directly). | `shell_tool` curated `confined_builtins` / `REMOVED_BUILTINS`. Closed the `exec`-builtin bypass (§Evidence). | **Enforced** |
| **I8** | `net` is **default-deny**: host allowlist, SSRF screening (reject private/loopback/link-local), DNS-pin the resolved IP (anti-rebinding), and re-check **every redirect hop**. | `agent-bridle-tool-web` net enforcer (`hickory-dns` resolve + pin + per-hop recheck). | **Enforced** |
| **I9** | The system **never overclaims**: every tool result records which sandbox actually enforced it (`sandbox_kind`), so an advisory-only run is never reported as kernel-confined. | result envelope carries `sandbox_kind`; `SandboxKind::{Landlock, None}`. | **Enforced** |

### C. Kernel backstop for permitted programs' interiors

| # | Invariant (MUST) | Enforced by | Status |
|---|---|---|---|
| **I10** | Once a *permitted* external program runs, its **own syscalls** are confined by the kernel where available; an empty `fs_write` scope denies all writes at the kernel. Neither L1 nor L2 can see inside a spawned binary — only L3 can. | `agent-bridle-core` `LandlockSandbox` (Linux ≥ 6.7), applied on a dedicated thread for the `fs_write` axis; `NoopSandbox` elsewhere (and `I9` forbids overclaiming when noop). | **Enforced on Linux; no-op (honestly reported) elsewhere** |

### D. Time is causal, never wall-clock

| # | Invariant (MUST) | Enforced by | Status |
|---|---|---|---|
| **I11** | Caveat validity keys on a **causal generation counter** (`valid_for_generation`), never on wall-clock. Wall-clock is a claim, never a coordination primitive. | `Caveats.valid_for_generation: Scope<u64>`; `Gate::check_generation`. | **Enforced** |

### E. The external-systems boundary

| # | Invariant (MUST) | Enforced by | Status |
|---|---|---|---|
| **I12** | A sub-principal reaches an external system **only** by (A) *projection* onto a native scoped token it is handed (fine-grained PAT, NATS user-JWT, Vault policy) or (B) *brokerage* through a bridge that holds the real secret and re-identifies as the full user. **Secrets never move** to the sub-principal; attribution is reconstructed from a content-addressed, causal log, not the remote's identity field. | Design contract realized by the `drake-keysmith`/Vault broker pattern and projection mints; see paper §5.4. | **Partial — pattern defined, brokers exist, not yet a uniform bridle surface** |

### F. Reflexive governance (in flight — stated so it is built to spec, not bolted on)

| # | Invariant (MUST) | Enforced by | Status |
|---|---|---|---|
| **I13** | **Mutating policy is itself a capability.** *Attenuating* one's own grant (a tighter rule, a `deny`) is always permitted. *Amplifying* it — a standing `allow` that widens the down-set — is the one move the local lattice forbids and MUST require the **human root**, surfaced as `attest` (a WebAuthn/FIDO2 gesture). Confusion cannot widen the writ; neither can autonomy. | Planned (paper §7.5). The grant should arrive as a **signed, admin-rooted, fail-closed policy artifact**; a worker's permitted mutation range is `{none, attenuate-only, ephemeral-only, full}`. | **Planned** |
| **I14** | For **irreversible** effects, the client gate is **advisory** (a patched binary can skip it); the *guarantee* MUST also live **off-box** in an effect-side verifier (git `pre-receive`, send-relay, mesh peer) that recomputes the act's challenge `BLAKE3(domain ‖ tool ‖ canonical(args) ‖ resource ‖ generation ‖ nonce)` and rejects the effect unless a valid attestation rides along. Same challenge formula on both planes. | Planned (paper §7.5). | **Planned** |

## Status legend & the honesty rule

**Enforced** = shipped and tested on `main`. **Partial** = mechanism exists but
is not yet a uniform, enforced surface. **Planned** = designed, not yet built.
A PR MUST NOT move an invariant *down* this ladder silently; a regression of an
**Enforced** invariant is a release blocker. New "Planned" invariants are
welcome; downgrading the language of an existing one is not.

## Consequences

- **Adding a tool** does not get to define its own security vocabulary. A tool
  declares `required: Caveats` and receives a `ToolContext`; it has no other way
  to act (I1). Per-tool regex allow/deny lists are **forbidden** — they do not
  compose and they re-introduce the fused-authority bug the lattice removes.
- **Adding an axis** to `Caveats` happens in `agent-mesh-protocol`, with the
  `meet`/`leq` laws and the `meet_never_amplifies` property test extended — never
  by special-casing in bridle (I3).
- **The strength of the `fs_*` leash today rests on I7 (`exec` scope) plus I10
  (Landlock).** Until L3 is universal, an `exec`-permitted program's interior is
  confined only where Landlock runs; I9 keeps us honest about where that is.
- **The client gate binds a confused *model*, not a compromised *binary*.** That
  scope boundary is deliberate (threat model, paper §3); closing it for
  irreversible effects is I14's job (off-box verifier), not the client gate's.
  Do not let a slide or a README imply the client gate stops a patched harness.

## Relationship to ADR 0001

ADR 0001 decided the **three layers** (L1 static-additive, L2 runtime-
authoritative, L3 kernel-backstop) and "attenuate, don't predict." This ADR
states the **invariants those layers serve** and assigns each invariant to a
layer/mechanism. Where they could appear to conflict, ADR 0001's "no layer's
verdict overrides a more authoritative layer" is the tie-breaker, and is
restated here as the second half of I4.

## Evidence (why runtime/kernel, not static, is authoritative)

Two enforcement bypasses were found by **adversarial, empirical** audit — not by
structural reasoning — and closed; each is now a regression test that fails on
the old code:

1. **`exec`-builtin bypass** — the carried shell's `exec` builtin called
   `cmd.exec()` directly, skipping `before_exec`; under `exec: Only{echo}`,
   `exec /usr/bin/touch MARKER` ran. Fixed by I7 (curated builtins, no `exec`).
2. **Dangling-symlink `fs_write` escape** — check-time canonicalization followed
   symlinks, so a symlink to a not-yet-existing target canonicalized in-scope
   while `open(O_CREAT)` wrote through it out-of-scope. Fixed by I6 (no-follow).

Both shared one root cause — *the structural/expected view diverging from
runtime reality* — which is exactly why I4 makes runtime authoritative and I9
forbids overclaiming.

## References

[1] N. Hardy, *The Confused Deputy*, ACM SIGOPS OSR 22(4), 1988.
[2] M. S. Miller, *Robust Composition*, PhD thesis, JHU, 2006.
[3] A. Birgisson et al., *Macaroons*, NDSS 2014 (append-only caveats).
[4] *Biscuit* (`biscuit-auth`) — offline-attenuable signed tokens.
[5] M. Salaün, *Landlock*, Linux kernel, 2021– (L3).
[6] E. Debenedetti et al., *Defeating Prompt Injections by Design (CaMeL)*,
    Google DeepMind, 2025.

Full citations and the argument behind every invariant: *The Age of the Confused
Deputy* (knowledge:board/papers/).
