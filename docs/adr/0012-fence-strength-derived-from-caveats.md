# ADR 0012 — Fence strength is derived from Caveats, never domain-keyed

- Status: Accepted (2026-06-30)
- Date: 2026-06-30
- Context: ADR 0004 D3 decided *that* "fence strength" is **derived** from the
  declared `Caveats` and the available backend, that presets are curated lattice
  points (not a parallel mode/strength enum), and that a domain may *select* a
  preset but must never *key* strength directly — but it left the **mechanism**
  to issue #32. The primitive it builds on now exists: `enforcement_report(effective,
  active) -> EnforcementReport` (`agent-bridle-core/src/report.rs:95`) is a pure,
  IO-free classification of each **restricted** (`Only(_)`) Caveat axis as
  `AxisEnforcement::{Kernel|Interceptor|Advisory}` (the ADR 0004 D1 / #30 report),
  already threaded into the result envelope (`envelope.rs:85`, omitted when empty).
  The single mint site `Gate::authorize` already computes `effective =
  granted.meet(&tool.required())` and stamps a `SandboxKind` into every
  `ToolContext` (`gate.rs:118,130`); the subprocess boundary already has a
  fail-closed refusal (`confinement_unenforceable`, `spawn.rs:271`) — but only for
  `fs_write`. What is missing is (1) the **scalar** strength #32 specs, (2) the
  **launch-time disposition** that turns "this axis cannot be kernel-honored" into
  refuse-vs-run-advisory, and (3) a resolution of the divergence between the two
  inputs the derivation depends on.
- **Resolves ADR 0004 D3** (issue #32) and **extends ADR 0004 D1/D2** (the
  per-axis honesty report and the un-stub gate). Governed by ADR 0002 (the
  meet-semilattice + unforgeable `ToolContext`) and consistent with ADR 0006/0009
  (per-OS backends behind `SandboxKind`).
- Related issues: **#32** (this ADR — ADR 0004 D3's tracking issue), #30 (the
  per-axis report this aggregates), #31 (the un-stub fail-closed gate this feeds),
  #57 / DESIGN §6 (the held `exec` axis the scalar stays honest about), #58 /
  ADR 0010 (command packs that may *raise* the floor). The
  `NamedPermissionPreset` / `/mode` / "loadouts" alignment lives in **newt-agent**
  and is an explicit deferral (D8).

## Question

ADR 0004 D3 says strength is *derived*, never a stored enum, never domain-keyed —
but a principle is not a mechanism. **What exactly is "fence strength," computed
from what, where is it enforced, and how does that enforcement avoid both (a)
re-introducing a second source of truth that can drift from the lattice, and (b)
a fail-open seam between where the strength verdict is *minted* and where the
subprocess is *actually confined*?** Concretely: the verdict is a function of two
inputs — the effective `Caveats` and the active backend — and while the `Caveats`
half is provably non-amplifying (`meet` is a GLB; there is no `join`/`widen` op in
the lattice — `agent-mesh-protocol` `caveats.rs` exposes only `meet`/`leq`/
constructors, count of `join`/`widen`/`lub` = 0), the **backend** half is read in
two unsynchronized places: the Gate's stamped `sandbox_kind` (`gate.rs:49`, set
once by `with_sandbox(...).kind()`) and the spawn site's independent re-probe
`best_available_sandbox()` (`spawn.rs:150`; likewise the shell admission pass).
A strength gate computed at mint from the stored stamp can clear a run the spawn
site then executes under a *weaker* real backend — and today the only spawn-time
backstop, `confinement_unenforceable`, checks `fs_write` alone (`spawn.rs:271`).

## Decision

Fence strength is a **pure aggregation of the #30 `EnforcementReport`** — a
function of a function of `(effective Caveats × active SandboxKind)`, recomputed
every time, never stored as its own field. A single launch-time **disposition
knob** (`strength_floor`) selects refuse-vs-run-advisory; it makes **no
confinement claim** and never reaches the envelope, so it cannot drift from the
lattice. The authoritative fail-closed check runs at the **confinement boundary**
against the **really-probed** backend (not only at mint against the stamp),
closing the divergence the adversarial review found. The following sub-decisions
resolve D3.

### D1 — Strength is the greatest-lower-bound of the per-axis report (pure, never stored)

Add `fence_strength(report: &EnforcementReport) -> Option<AxisEnforcement>`: the
**GLB (min)** over the *present* (= restricted, `Only(_)`) axes' `AxisEnforcement`,
and `None` when the report `is_empty()` (no axis restricted ⇒ nothing to confine
⇒ vacuous top ⇒ admit). Because the report itself is the existing pure
`enforcement_report(effective, active)` (`report.rs:95`), the scalar is a function
*of a function* of `(effective Caveats, active SandboxKind)` — **never a field, no
IO**. It cannot diverge from the lattice it summarizes because it is recomputed
from it on every read. The scalar is the **floor/minimum claim**: it equals the
*weakest* restricted axis, so it can never read "Strong/Kernel" while any
restricted axis is `Interceptor` or `Advisory`. A scalar necessarily loses
per-axis information; consumers that need to know *which* axis dropped strength
still read the #30 report (the scalar is a convenience, not a replacement).

### D2 — `AxisEnforcement` gets an explicit ascending `Ord` — never a naive derive

`fence_strength` needs a total order on `AxisEnforcement`, which today derives
only `PartialEq`/`Eq` (`report.rs:22`). The variants are declared **descending**
(`Kernel, Interceptor, Advisory`), so a naive `#[derive(Ord)]` would make
`Kernel < Advisory` and invert the min — `fence_strength` would then pick the
*strongest* axis as the floor and a Strong principal would be admitted whenever
*any* axis is Kernel even if others are Advisory (a silent **fail-open**).
Therefore: give `AxisEnforcement` a **total `Ord` with `Advisory < Interceptor <
Kernel`** — either by reordering the variants ascending or by an explicit `impl
Ord` — and ship a **regression test asserting `Advisory < Kernel`**. `serde` is
`rename_all`-by-name, so the wire format is unaffected by a reorder.

### D3 — One launch-time disposition knob: `strength_floor`, default = strictest

Add a single datum `strength_floor: AxisEnforcement` carried on the `Gate`, set by
a builder mirroring `with_sandbox` (`gate.rs:92`) and **defaulting to the
strictest (`Kernel`)** so the floor is **fail-closed by omission**. It is a
*disposition*, not a confinement description: it selects, for any restricted axis
the backend cannot honor at the floor, whether to **refuse** (Strong, floor =
`Kernel`) or **run and report advisory** (weak/wrapper-only, floor = `Advisory`).
It is the one stored datum the design adds; its non-claim status is what keeps the
honesty rule structural (D9). It is **launch-time, immutable from inside**: the
floor rides into the `ToolContext` as a private field with no setter (siblings the
already-private `sandbox_kind`; `ToolContext` has private fields and the single
crate-private mint ctor, `context.rs:37`), so a running tool can neither lower the
floor nor raise its own achieved strength (I1 mint-token, I3 no-reachable-amplify,
I13 self-amplification needs the human root).

### D4 — The authoritative fail-closed check is at the confinement boundary, against the real backend

This is the keystone that resolves the adversarial **strength-divergence** finding.
The verdict depends on the active backend, and the Gate's stamped `sandbox_kind`
(`gate.rs:49`) is read independently of the spawn/shell sites' own
`best_available_sandbox()` probe (`spawn.rs:150`) — they are not unified, so a
mint-time-only check can clear a run the boundary then executes under a weaker
reality (e.g. a Strong gate stamped `Landlock` with `fs_read: Only(_)` clearing a
spawn that lands on `NoopSandbox`, where `confinement_unenforceable` — `fs_write`
only — does not refuse, and the child reads outside its read roots unconfined).
Therefore:

1. **Unify the backend input.** The Gate's stamped `sandbox_kind` MUST be sourced
   from the *same* probe the confinement sites use (`best_available_sandbox().kind()`);
   a host stamping a stronger kind than the host can deliver is precisely the
   divergence and is forbidden. The recommended wiring is for the Gate to own the
   `Sandbox` (or its probed kind) that the spawn/shell sites then confine through,
   rather than each leg re-probing in isolation.
2. **Generalize the boundary backstop.** Replace the `fs_write`-only
   `confinement_unenforceable(kind, caveats)` (`spawn.rs:271`) with a check over
   the **honest report against the real backend**: refuse *before* spawning iff
   `fence_strength(enforcement_report(effective, effective_sandbox_kind(best_available_sandbox().kind(), effective))) < Some(floor)` — i.e. **any** restricted axis whose
   *actual* enforcement is below the floor (not just `fs_write`). The boundary
   reads the floor from the `ToolContext` (D3) and the backend it is about to use,
   so it is **self-enforcing even if any mint/spawn skew remains**.

The mint-time comparison stays as an **early fail-fast** at the single choke point
(`Gate::authorize`, `gate.rs:108`: compute `enforcement_report(&effective,
self.sandbox_kind)` and refuse to mint when `fence_strength(...) < Some(floor)`),
but it is *not* the sole authority — the boundary check is. The decision compares
two **derived** values: the per-axis report (honesty) and the floor (disposition).
Only the report ever reaches the envelope.

### D5 — Presets = a curated `Caveats` lattice point + a `strength_floor`, applied by meet only

A preset is `Preset { granted: Caveats, strength_floor: AxisEnforcement }`, applied
to the host grant by **`host_grant.meet(preset.granted)`** — `meet` never amplifies
(property-tested `meet_never_amplifies`, `caveats.rs:401`), so a preset can only
**tighten** authority. Named constructors `code()` / `strong()` / `weak()` /
`wrapper_only()`; `code()` is the **strictest** (the highest-risk ocap case — an
agent that writes and runs arbitrary programs), bundling `floor = Kernel` plus a
tight `exec`/`net`/`fs` point. The wrapper-only ("YOLO") tier carries
`floor = Advisory` but still flows through the single interceptor so audit and
the chokepoint are preserved. Building a preset up from deny-all needs
`Caveats::bottom()` upstream in `agent-mesh-protocol` (today only `top()` exists;
`deny_all()` is duplicated at `caveats_source.rs:31`) — a cross-repo prerequisite
(D8).

### D6 — Narrow-only is type-enforced in **both** directions

- **Authority can only meet-down.** The meet-semilattice exposes `meet`/`leq`/
  constructors but **no `join`/`widen` op reachable from data** (`caveats.rs`), so
  there is no code path that can widen a grant. A drifted or malicious preset can
  only **over-restrict** — a fail-closed usability bug, never a security hole.
- **The floor can only `Ord::max`-up on delegation.** A child's floor is
  `child_floor = parent_floor.max(requested)` — the exact raise-only pattern of
  step-up `Presence` (`step_up.rs:40-58`, "attenuation may only *raise* a required
  presence"). agent-bridle exposes **only the curated preset constructors**, never
  a public arbitrary-floor setter a per-label domain map could call directly (D8).

### D7 — Meet-on-delegation is a **free consequence**, not a new policed rule

A child's `effective ⊑ parent` by the meet law (`gate.rs:118`) **and** the backend
cannot strengthen on delegation — so the child's per-axis report and its min only
**drop**, and "a child can attenuate, never be minted stronger-claiming than its
parent can honor" (ADR 0004 D3) holds *by construction*. For this to be sound the
backend must be **attenuated on delegation too** (`child_kind = min(parent_kind,
best_available)`, or derived solely from `best_available` at the leaf) so the
guarantee rests on the type system, not on the accident of the backend being a
physical global — this is the second half of the adversarial mitigation in D4.

### D8 — A domain selects a preset; it never keys strength — and this part defers to newt

`code = strictest` and "no domain keys strength directly" are **not type-enforceable
inside agent-bridle**: the domain→preset binding (`NamedPermissionPreset`, `/mode`,
loadouts) lives in **newt-agent**, where no such Rust symbol exists in this repo.
agent-bridle therefore ships the enforceable half — the **derivation** (D1), the
**strictest in-tree default** (`floor = Kernel` by omission, D3), and **curated
preset constructors only** (no arbitrary public setter, D6) — and records
`code = strictest` / `route /mode through curated presets, never a raw strength
keyed off a domain label` as a **co-agreed newt invariant**. The concrete `Caveats`
point for each named preset (what `code()` grants — which exec toolchain, net
policy, fs roots) depends on newt's tool roster and is co-designed there;
agent-bridle ships the derivation and the strictest defaults, newt fills the
lattice points.

### D9 — Honesty is structural: the floor never becomes a confinement field

The `strength_floor` / preset **setting** is never emitted as a confinement field —
**only the derived #30 report reaches the envelope** (`envelope.rs:85`), guarded by
a test that the floor never serializes into a result. So no prose, schema, or field
can describe an `advisory` axis as confined, regardless of the selected strength
(ADR 0004 D1; the `noop_host_never_reports_kernel` oracle, `report.rs:173`). The
scalar is the floor/minimum claim (D1), so it cannot over-claim. The counter-
intuitive rule "**unconfined ⇒ admit even under Strong**" (an empty report = a
top-grant restricting nothing passes a Strong gate) is correct — there is nothing
to confine — but must be documented and tested so it is not misread as a fail-open
hole. A weak/wrapper-only principal is admitted while the envelope still carries
the truthful advisory axes: **strength chooses disposition, never overrides
honesty**.

### D10 — Feeds #31's un-stub gate; tightens automatically as backstops land

The fail-closed disposition is a function of two derived inputs — the per-axis
report (D1, honesty) and the floor (D3). Rule: for each restricted axis whose
report `< floor`, **Strong (floor = `Kernel`) refuses; weak/wrapper-only
(floor = `Advisory`) permits but reports advisory**. Because `exec` is
unconditionally `Interceptor` and `net` `Advisory` unless `AppContainer`
(`report.rs:113,114-121`), a Strong principal **refuses every `exec:Only` /
`net:Only` run on Linux/macOS today** — exactly the stub's `find -exec curl`
denial, so the un-stub (#31) cannot silently lower the operative floor below the
fail-closed stub. The strength never *manufactures* a Kernel claim; it only selects
refuse-vs-advisory over an axis the **report** already classified. When #57
(Landlock Execute + read co-confinement, or a seccomp `execve` filter) and a `net`
backstop land and move those axes to `Kernel` in #30, the **same unchanged
aggregation** starts admitting Strong runs — the floor rises automatically, no
code change to the derivation. A future ADR 0010 command-pack that **raises** the
required `sandbox_kind` (its D10) feeds this by tightening the floor, never
loosening.

## Consequences

**Positive**

- **Single source of truth.** The scalar is recomputed from the #30 report every
  time, so it cannot drift from the lattice — the explicit ADR 0004 D3 rejection of
  a parallel mode/strength enum is satisfied by construction.
- **Meet-on-delegation is free** (D7): child `effective ⊑ parent` + a non-
  strengthening backend ⇒ the child's report and its min only drop. "Never
  stronger-claiming than the parent can honor" is a consequence of the existing
  `meet` law, not a new invariant to police.
- **Honesty is structural, not procedural** (D9): the floor never reaches the
  envelope, so an advisory axis can never be described as confined regardless of
  the selected strength.
- **Narrow-only in both directions** (D6): authority can only meet-down (no `join`
  exists), the floor can only `max`-up (the `Presence` precedent) — a drifted or
  malicious preset can only over-restrict.
- **Preserves the stub's fail-closed floor through the un-stub** (#31): Strong +
  `exec:Only` / `net:Only` refuses exactly the runs the stub denied.
- **`code = strictest` by construction** (D5/D8): strength is bundled in the preset
  and there is deliberately no domain→strength function, so the highest-risk ocap
  case cannot be accidentally mapped to weak.
- **Pure, IO-free, `#![forbid(unsafe_code)]`-clean, off-Linux-safe.** It adds no
  kernel dependency of its own and lands ahead of the deeper L3 axes, tightening
  automatically as #57/#31 backstops arrive.

**Negative / risks**

- **The `Ord` footgun** (D2): a naive derive over the current descending
  declaration silently inverts the GLB into a fail-open. Mandatorily an explicit
  ascending `Ord` + a regression test — not a derive.
- **The mint↔spawn backend seam** (D4): the verdict is only as honest as the
  unification of the Gate's stamped kind with the spawn/shell site's real probe,
  and the boundary backstop must be generalized from `fs_write`-only to the full
  per-axis report. This wiring is load-bearing and must be verified by test, not
  assumed (it is the one place the adversarial review found a fail-open).
- **Cross-repo prerequisite** (D5/D8): presets need `Caveats::bottom()` upstream in
  `agent-mesh-protocol`; until then they build from the duplicated `deny_all()`
  (`caveats_source.rs:31`), so the preset layer cannot fully land in agent-bridle
  alone.
- **The "unconfined ⇒ admit even under Strong" rule** (D9) is correct but counter-
  intuitive and must be documented + tested so it is not read as a hole.
- **A scalar loses information** vs the per-axis report; the #30 report remains the
  thing to read when a consumer needs to know *which* axis dropped strength.

**Out of scope (this ADR)**

- The newt-side `NamedPermissionPreset` / `/mode` / loadout mapping (D8) — co-
  agreed there, not decided here.
- Whether the scalar is *surfaced* in the envelope alongside `enforcement` or
  computed on demand — recommend compute-on-demand (or, if surfaced, always
  recomputed and explicitly marked derived) to honor "never a stored enum."
- How #32 composes with ADR 0007 step-up `Presence` (whether a satisfied gesture
  can raise an otherwise-advisory run to admissible) — a different strength axis,
  left to a later ADR.

## Options considered and rejected

- **A stored / parallel `FenceStrength` (or `Mode`) enum beside `Caveats`** —
  REJECTED (ADR 0004 D3): a second source of truth drifts from the lattice. The
  scalar must be *derived* from the #30 report, recomputed every read (D1).
- **A naive `#[derive(Ord)]` on `AxisEnforcement`** — REJECTED (D2): the current
  descending declaration order would make `Kernel < Advisory`, inverting the GLB
  into a silent fail-open. An explicit ascending `Ord` + regression test is
  mandatory.
- **Domain-keyed strength (`code ⇒ weak`) or a public arbitrary-floor setter** —
  REJECTED (D5/D8): backwards on the threat model — the code agent is the
  highest-risk ocap case, so `code` is the *strictest* preset. agent-bridle exposes
  only curated preset constructors; the domain→preset binding is a co-agreed newt
  invariant, never a per-label raw strength.
- **Mint-time-only fail-closed, with the Gate's stored `sandbox_kind` as the sole
  authority** — REJECTED (D4): it diverges from the spawn-time re-probe and
  fail-opens on backend-dependent axes with no `fs_write`-style backstop (`fs_read`
  today; `exec` once #57 lands). The authoritative check moves to the confinement
  boundary against the real backend, and the stamp is unified to the same probe.
- **Surfacing the scalar or the floor as a confinement field in the envelope** —
  REJECTED (D9): it would let a selected strength describe an advisory axis as
  confined. Only the derived #30 report is emitted; the floor is a non-claim
  disposition and is tested to never serialize.
- **Deny on an empty report (treat a top-grant as needing confinement)** —
  REJECTED (D1/D9): an all-`All` grant restricts nothing, so there is nothing to
  confine; the vacuous top admits even under Strong. Denying it would be a
  fail-closed *usability* bug that misreads "nothing restricted" as "nothing
  enforced."
- **Presets that can widen `granted`** — REJECTED (D6): unrepresentable. Presets
  apply by `meet` only; there is no `join`/`widen` op in the lattice, so a preset
  can only tighten.
