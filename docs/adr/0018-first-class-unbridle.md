# ADR 0018 — First-class "unbridle": an honest, acknowledged, loud confinement-off mode

- Status: **Proposed** (2026-07-01) — for review; do not implement until ratified
- Date: 2026-07-01
- Context: ADR 0017 D8 sketched an "unbridle" mode; this ADR formalizes it as the
  implementation-level decision for epic #139's **I12** (#151). The operator's
  original ask was the ability to "**completely unbridle** a system when needed"
  without weakening the OCAP invariants. I11 (#150) has landed the envelope
  `Disclosure` block that carries `unbridled`, so the disclosure channel now
  exists.
- Governed by ADR 0002 (the leash is the only path to running a tool; `effective ⊑
  granted`), ADR 0004 (per-axis honesty), ADR 0007 (step-up is a *third* leash
  outcome, host-orchestrated), ADR 0012 (fence strength from caveats), and ADR 0017
  (authority≠mechanism, enforcement≠disclosure; D8 in particular). Cross-refs the
  fail-open work (#158) and the caveats source
  (`agent-bridle-mcp/src/caveats_source.rs`).
- **Reviewer refinements (2026-07-01).** Review of the D1–D7 draft surfaced that
  unbridle and the **step-up / human-gesture axis** (ADR 0007) are orthogonal, and
  that the draft collapses them into a single "free" state. This revision adds
  **D8–D11** (the two-axis model, the mode lattice, the second ack for removing the
  human, and disclosure of the human-gate posture), resolves the two open questions
  in D3/D5, and appends a **ratification roadmap** (the issue series that walks the
  platform to make the vision real). The canonical ack token is updated to
  `i-understand-this-is-dangerous` (D3).

## Question

How do we provide a **complete confinement-off switch** that (a) never weakens the
honesty guarantees (no envelope may claim confinement it does not have), (b) is
**impossible to reach by accident or omission**, (c) is **loud** and auditable,
and (d) adds **no second authority channel** and no second `ToolContext::mint`
path?

## Decision

### D1 — Unbridle is a resolution-layer *mode*, not a new code path

`BridleMode::Unbridle` resolves — **in the loader**, before any tool runs — to a
principal of `granted = Caveats::top()`, `strength_floor = Advisory`, and
`sandbox_kind = None`. There is **no** `bypass_checks`, no `UnsafeToolContext`, no
second mint site. The existing `Gate::authorize` chokepoint runs unchanged; with
`granted = top()`, `effective = granted.meet(required)` simply yields exactly what
each tool asks for. Unbridle changes **zero** lines in `gate.rs` / `context.rs` /
`report.rs`.

### D2 — Honest by construction (it cannot lie)

Because `top()` restricts nothing, `enforcement_report` is empty and
`sandbox_kind = None` — the run is *structurally incapable* of claiming
confinement. The honesty lattice (ADR 0004/0012) needs no special-case: there is
nothing to overclaim. This is why unbridle is safe to add without touching the
enforcement core — it lives entirely at the authority-resolution layer (ADR 0017
D1: authority ≠ mechanism).

### D3 — Never by omission: a two-key, acknowledged opt-in (fail-closed absence)

Unbridle requires **both**:

1. **Intent** — `mode = unbridle` in resolved config (`BRIDLE_MODE=unbridle`, file,
   or API), and
2. **Acknowledgement** — the exact runtime token
   `AGENT_BRIDLE_UNBRIDLE=i-understand-this-is-dangerous`.

A missing, empty, or non-matching ack (including a bare `=1`/`=true` or the old
`=i-understand`) is a **hard, loud refusal**, *not* a silent downgrade: the process
fails closed to the normal deny-all default and prints why. The two-key design means
neither a stray config setting **nor** a stray env var can unbridle on its own —
accidental unbridle is not reachable. This preserves ADR 0017 D3's "fail-closed
absence" as an absolute.

> **Resolved (2026-07-01, review).** Ack token is
> `i-understand-this-is-dangerous` — long and self-describing, so it cannot be set
> by muscle memory or pasted without reading it. It stays **env-only** (works
> headless; a TTY confirm would break CI and the whole point is a deliberate,
> auditable opt-in that a machine operator sets once). A human-present *host* MAY
> layer an interactive confirm on top as its own UX (ADR 0003/0007: that is the
> host's call, not the core's); the core never requires a TTY.

### D4 — Distinct, auditable provenance

Add `CaveatsSource::Unbridled { ack: String }` to the caveats source, **never**
conflated with `FailClosedDefault` or `Env`. The provenance records the ack value
so an audit log shows *that* and *how* the operator acknowledged. `GrantedCaveats::banner()`
gains an `Unbridled` arm (D5).

### D5 — Loud and disclosed on every result

- A **shouting** multi-line startup banner (unmistakable — this is not a normal
  run) plus `tracing::warn!`.
- `disclosure.unbridled = true` (I11 / ADR 0017 D6) on **every** result envelope,
  so downstream consumers and logs always see it — never quiet.

> **Resolved (2026-07-01, review).** A process-level marker, set once by the loader
> at startup from the acked mode (**not** inferred from `top()`+`None` — a normal
> permissive `Caveats::top()` grant is *not* "unbridled"), read when a tool builds
> its `ToolEnvelope`. It is a **process mechanism, not per-invocation authority**, so
> it does not ride `ToolContext` (authority≠mechanism, ADR 0017 D1 stays intact). The
> same marker carries the **human-gate posture** so the envelope can distinguish the
> two unbridled modes (D11).

### D6 — Per-process and reversible

Unbridle is decided once at process startup from `(config mode, ack)`; it is not
persisted and not global beyond the process. A fresh process without the ack is
bridled again. There is no on-disk "stay unbridled" state.

### D7 — Unbridle ≠ fail-open (distinct hammers)

Unbridle (this ADR) is *total*: "I want **no** confinement, and I acknowledge it."
The separate `--ocap-fail-open` work (#158) is *partial and mechanism-specific*:
"confinement for capability X isn't fully implemented; allow with **degraded**
OCAP rather than fail closed." Both are loud, human-acknowledged opt-ins, but they
differ in scope and are decided independently. This ADR does not resolve #158; it
only fixes the boundary so the two cannot be confused (distinct provenance, distinct
tokens, distinct disclosure fields).

### D8 — Unbridle is *one* axis; step-up (the human gesture) is the orthogonal second

Unbridle collapses only the **capability/sandbox axis** (`granted`,
`strength_floor`, `sandbox_kind` → `top()`/`Advisory`/`None`). It does **not** touch
the **step-up axis** (ADR 0007): the `StepUpPolicy` + `DischargeProvider` gesture
ceremony the *host* orchestrates. Step-up is **caveat-independent by construction** —
`step_up.rs`: *"Caveats decides whether the authority exists, this decides what
gesture admits its use."* An unbridled principal (`granted = top()`) can therefore
**still** owe a `Passkey`/FIDO gesture for a host-designated HIGH-consequence act,
because `Gate::evaluate` derives `NeedsDischarge` from the `StepUpPolicy`, not from
the caveats (ADR 0007 D1/D2).

The consequence Shawn's review asked for: **unbridle removes the *machine* leash; it
does not remove the *human* leash unless the human is removed too (D10).** "Free to
act, but the red button still needs a key" is not only expressible, it is the
recommended posture for a *trusted-but-supervised* autonomous agent.

*Architecture note (grounding, not a decision):* step-up is orchestrated by the host
(ADR 0007 D5), not by `Registry::dispatch` — which today mints via **plain**
`gate.authorize` (registry.rs, the single mint site) and never consults a
`StepUpPolicy`. So D8 holds *by construction* for a host that runs the
`evaluate → obtain → authorize_with_discharge` ceremony, but the **default dispatch
path does not yet enforce step-up at all**. Making step-up hold *under unbridle on
the default path* is roadmap item **R2** (thread `StepUpPolicy` into `Registry`).

### D9 — The mode lattice: two axes, four postures, one off-grid escape hatch

The capability axis (D1) and the human-gesture axis (D8) compose into four postures:

| capability axis ↓ / human axis → | **step-up in force** (host runs the gesture ceremony) | **no step-up in force** |
| --- | --- | --- |
| **bridled** (`effective ⊑ policy`, `sandbox_kind ≠ None`) | **Guarded** — default: machine leash **and** human leash | **Confined-headless** — sandbox holds; no gestures (CI) |
| **unbridled** (`top()`, `None`) | **Supervised-free** — no machine leash, but FIDO still gates HIGH-consequence acts | **Autonomous** (`--yolo`) — no machine leash, no human gate |

**"No step-up in force" is reached two different ways — this distinction is
load-bearing.** *Step-up **absent*** — no gesture ceremony is wired at all (the
default `Registry::dispatch` path today, or a headless CI host with no
authenticator). It costs nothing and needs no ack; it is simply the absence of a
host ceremony. *Step-up **acked-off*** — a host that *does* have a ceremony
deliberately disables it, which is only legal **under unbridle** and costs the D10
ack. **Confined-headless** is the *absent* case (free, CI); **Autonomous** is the
*acked-off* case (D10). R6 rejects the *acked-off* combination while bridled (there
is nothing to deliberately disable if the machine leash is on) — it does **not**
forbid the trivially-free absent case.

**Reachability, ordered by danger (all four cells):**

1. **Confined-headless** — bridled, no ceremony. Free (no acks). Least dangerous of
   the "no human" cells: the sandbox still holds.
2. **Guarded** — the default. Free (no acks). Both leashes on.
3. **Supervised-free** — costs the unbridle two-key (D3). No sandbox, but the human
   gate remains. *Holds only where the host runs the `evaluate → obtain →
   authorize_with_discharge` ceremony (ADR 0007); on the default dispatch path it
   becomes real only after **R2**.*
4. **Autonomous** — costs the unbridle two-key **plus** the distinct second ack of
   D10 — three tokens in total (mode + unbridle ack + no-step-up ack). The most
   dangerous cell, and the hardest to reach.

`--ocap-fail-open` (#158) is **not a cell in this lattice.** It is a
mechanism-degradation escape for one integration (the brush `CommandInterceptor`
hook being absent), off-grid per D7. Folding it into the mode grid is precisely the
conflation this ADR forbids.

On the `--ocap-disabled` spelling raised in review: under D1, unbridle already makes
capability enforcement a **no-op** (`top()` has nothing to attenuate), so a separate
"disable OCAP" toggle would subtract nothing on the capability axis. The only thing
left to turn off is **step-up** — which is D10. We therefore name the human-gesture
axis directly and **do not** introduce an `--ocap-disabled` flag (it would be a
redundant, confusing alias for "unbridled").

### D10 — Removing the human too costs a *second* key (the autonomous ack)

Reaching the **Autonomous** posture (unbridled **and** step-up off) requires the
unbridle two-key (D3) **plus** a distinct second acknowledgement — proposed
`AGENT_BRIDLE_NO_STEPUP=i-accept-no-human-in-the-loop` (exact string TBD in R4),
under the *same* fail-closed-absence rules (missing/empty/non-matching ⇒ hard loud
refusal). Disabling the ceremony is the **host's** action (ADR 0007 D5); this ack
gates the host's decision to skip step-up while unbridled. Rationale: the posture
with neither machine nor human in the loop must never be reachable by a single
token, and must be the loudest to disclose (D11). The unbridle ack **never** implies
the no-step-up ack.

### D11 — Disclosure carries the human-gate posture (the two unbridled modes must differ)

Extend the I11 `Disclosure` block: alongside `disclosure.unbridled: bool`, add
`disclosure.human_gate` — the step-up floor the host will still enforce, one of
`none | prompt | passkey`. Set from the same loader-set process marker as D5 (never
inferred). Without it, **Supervised-free** and **Autonomous** are indistinguishable
on the envelope, collapsing the exact distinction D8/D9 draw — a consumer could not
tell "free but FIDO-gated" from "no human at all." Honesty (ADR 0004/0017) demands
the envelope disclose *which* unbridled posture is in force, not merely *that* the
run is unbridled.

## Consequences

- **Positive:** a clean, honest, auditable off-switch with *zero* blast radius on
  the security core (no gate/context/report changes); composes with the existing
  provenance, banner, and I11 disclosure; satisfies the operator's "completely
  unbridle" requirement without a second authority path.
- **Negative / residual risk:** an unbridled process has **no** confinement — the
  two-key opt-in, the shouting banner, and the per-envelope disclosure are the
  mitigations against silent misuse. The ack token is a **footgun-guard, not a
  security boundary** (an operator who can set env on their own machine can
  unbridle by definition; the goal is to make it impossible to do *by accident*,
  and impossible to do *quietly*).
- **Honesty invariant upheld:** because unbridle yields `top()` + `None`, no
  envelope can claim confinement — the mode cannot produce a dishonest report.

## Implementation sketch (I12 / #151, after ratification)

1. Loader: on `BridleMode::Unbridle`, read `AGENT_BRIDLE_UNBRIDLE`; if it equals
   the ack token, resolve `GrantedCaveats { caveats: Caveats::top(), source:
   CaveatsSource::Unbridled { ack } }`; otherwise hard-fail closed with a message.
2. `GrantedCaveats::banner()`: add the shouting `Unbridled` arm; call it at startup.
3. A process-level `Unbridled` marker (set by the loader) that tool envelope
   construction reads to stamp `disclosure.unbridled = true` (D5, resolved; extended
   by D11 to also stamp `disclosure.human_gate`).
4. Tests: `top()`+`None` ⇒ empty report / no confinement claim; ack required
   (missing ack fails closed; bare `=1` rejected); provenance is `Unbridled`, never
   `FailClosedDefault`; `disclosure.unbridled` on every envelope; the gate remains
   the only mint path.

Note: the sketch covers D1–D6 (I12 / #151, roadmap **R1**). D8–D11 add work beyond
#151 — most importantly threading step-up into the default dispatch path (**R2**) so
that "unbridled but human-gated" holds without a bespoke host ceremony. See the
roadmap.

## Ratification roadmap — the issue series (walking the platform)

This is the machine-readable source for generating the issue series that makes the
two-axis vision real. Each entry becomes one GitHub issue; `depends_on` encodes the
ordering (a DAG, root = R1). Generate with a small script over this block once the
ADR is ratified. Layers walk the platform bottom-up: **core loader → dispatch →
step-up independence → the autonomous ack → disclosure → config surface → embedder
UX → boundary hardening → per-OS honesty → docs**.

```yaml
# ADR 0018 realization — issue series. epic: #139  ·  adr: 0018-first-class-unbridle
epic: 139
adr: 0018-first-class-unbridle
milestone: "two-axis-unbridle"
issues:
  - id: R1
    title: "I12 — land first-class unbridle core (loader ack, provenance, banner, disclosure)"
    layer: core/loader
    depends_on: []
    tracks: ["#151"]
    decisions: [D1, D2, D3, D4, D5, D6]
    labels: [enhancement, security, unbridle]
    summary: >
      Implement ADR 0018 D1–D6. Loader resolves BridleMode::Unbridle only with the
      two-key opt-in (mode=unbridle AND AGENT_BRIDLE_UNBRIDLE=i-understand-this-is-dangerous),
      else hard-fails closed. Adds CaveatsSource::Unbridled{ack}, the shouting banner,
      and a process-level marker that stamps disclosure.unbridled on every envelope.
    acceptance:
      - "mode=unbridle without a matching ack (missing / empty / =1 / old =i-understand) fails closed loudly"
      - "resolved principal is top() + Advisory + None; enforcement_report is empty"
      - "provenance is CaveatsSource::Unbridled{ack}, never FailClosedDefault or Env"
      - "disclosure.unbridled=true on every envelope, driven by the acked mode (not inferred from top()+None)"
      - "Gate::authorize remains the only mint site; gate.rs / context.rs / report.rs unchanged"

  - id: R2
    title: "Thread StepUpPolicy into Registry::dispatch (make step-up enforce on the default path)"
    layer: core/dispatch
    depends_on: [R1]
    decisions: [D8]
    labels: [enhancement, security, step-up]
    summary: >
      Today Registry::dispatch mints via plain gate.authorize and never consults a
      StepUpPolicy — step-up only fires through the host's evaluate/authorize_with_discharge
      ceremony. Add an optional StepUpPolicy + DischargeProvider seam to Registry so the
      default dispatch path can return/resolve NeedsDischarge. This is the linchpin that
      makes "unbridled but human-gated" (D8) real without a bespoke embedder loop.
    acceptance:
      - "Registry accepts an optional StepUpPolicy + DischargeProvider; absent = today's behavior (no gestures)"
      - "dispatch returns/threads Decision::NeedsDischarge when the policy demands a gesture; nothing minted/charged on a refusal"
      - "the gate stays the single mint site; meet() non-amplification preserved (ADR 0007 D1)"
      - "regression: a Passkey-required selector under a normal grant demands a gesture on the default path"

  - id: R3
    title: "Unbridle keeps step-up: prove the axes are independent"
    layer: core
    depends_on: [R1, R2]
    decisions: [D8, D9]
    labels: [security, step-up, unbridle, test]
    summary: >
      Ensure unbridle resolution (R1) does not clear or bypass the host's StepUpPolicy,
      and pin it with regression tests: an unbridled principal (top()) with a Passkey
      selector still yields NeedsDischarge.
    acceptance:
      - "unbridled + Passkey selector ⇒ NeedsDischarge (Supervised-free posture holds)"
      - "test asserts caveat-independence: top() caveats do not lower the presence floor"
      - "no code path launders unbridle into skipping a demanded gesture"

  - id: R4
    title: "Autonomous posture: the second ack to remove the human (AGENT_BRIDLE_NO_STEPUP)"
    layer: core/loader
    depends_on: [R1, R3]
    decisions: [D10]
    labels: [enhancement, security, unbridle, step-up]
    summary: >
      Add the distinct second acknowledgement that lets an unbridled host skip the
      step-up ceremony. Only when BOTH the unbridle ack AND the no-step-up ack are
      present may step-up be disabled; same fail-closed-absence rules; the banner
      escalates to the loudest form.
    acceptance:
      - "no-step-up requires unbridle already engaged; the unbridle ack never implies it"
      - "missing / non-matching second ack ⇒ step-up stays active (fail-closed to Supervised-free)"
      - "Autonomous posture requires all three tokens (mode + unbridle ack + no-step-up ack)"
      - "startup banner distinguishes Supervised-free from Autonomous"

  - id: R5
    title: "Disclosure carries the human-gate posture (disclosure.human_gate)"
    layer: core/envelope
    depends_on: [R1]
    decisions: [D11]
    labels: [enhancement, honesty, disclosure]
    summary: >
      Extend the I11 Disclosure block with human_gate ∈ {none,prompt,passkey}, stamped
      from the loader marker, so Supervised-free and Autonomous are distinguishable on
      every envelope.
    acceptance:
      - "Disclosure gains human_gate; serialized on every envelope alongside unbridled"
      - "value is driven by the acked posture, never inferred from caveats"
      - "test: Supervised-free and Autonomous envelopes differ in human_gate"

  - id: R6
    title: "Config surface for the two-axis mode lattice (agent-bridle-config)"
    layer: config
    depends_on: [R1, R4]
    decisions: [D3, D9, D10]
    labels: [enhancement, config]
    summary: >
      Express the capability axis (bridle mode) and the human-gesture axis (step-up
      posture) across the file/env/API precedence chain; document the BRIDLE_* env
      convention; reject the illegal *acked-off* combination (the D10 no-step-up ack
      while bridled — there is nothing to deliberately disable if the machine leash is
      on). The free "step-up absent" case (no ceremony, e.g. CI) is always legal.
    acceptance:
      - "both axes settable via file, env, and API with the documented precedence"
      - "the D10 no-step-up ACK while bridled is rejected with an explicit message; step-up-absent (no ceremony) is not rejected"
      - "config round-trips and is covered by tests for each of the four postures"

  - id: R7
    title: "Embedder UX: render the four postures, the FIDO prompt under unbridle, the banners (newt-agent)"
    layer: embedder
    repo: newt-agent
    depends_on: [R2, R3, R5]
    decisions: [D8, D9, D11]
    labels: [enhancement, ux, integration]
    summary: >
      The host owns the gesture ceremony and the 'standard permission modes' UX (ADR
      0003/0007). Define how the embedder renders Guarded / Confined-headless /
      Supervised-free / Autonomous, drives the DischargeProvider (FIDO/passkey) even
      while unbridled, and surfaces the loud banners + disclosure.
    acceptance:
      - "unbridled session still prompts on the authenticator for HIGH-consequence acts"
      - "each posture has an unmistakable indicator; Autonomous is the loudest"
      - "the embedder reads disclosure.unbridled + human_gate, never infers posture"

  - id: R8
    title: "Boundary hardening: unbridle ≠ fail-open (#158) — provenance + disclosure separation"
    layer: core
    depends_on: [R1]
    decisions: [D7]
    labels: [security, honesty, test]
    summary: >
      Pin the D7 boundary with tests/docs: unbridle provenance and fail-open provenance
      are distinct, their disclosure fields are distinct, and neither token unlocks the
      other. Keep #158 off the mode grid.
    acceptance:
      - "CaveatsSource::Unbridled is never produced by the fail-open path and vice versa"
      - "the unbridle ack does not enable fail-open; the fail-open flag does not unbridle"
      - "a doc/test asserts the two remain independently decided"

  - id: R9
    title: "Per-OS honesty parity for unbridle (Linux / macOS / Windows CI matrix)"
    layer: platform
    depends_on: [R1]
    decisions: [D2]
    labels: [security, honesty, ci]
    summary: >
      Assert that an unbridled run reports sandbox_kind=None and an empty enforcement
      report identically on every OS backend, and that the capability matrix (ADR 0004
      D1 / #30) records no confinement claim under unbridle on each host.
    acceptance:
      - "unbridle yields None + empty report on Linux, macOS, and Windows"
      - "CI matrix asserts the reported posture matches the host's true (nil) confinement under unbridle"
      - "no backend overclaims when unbridled"

  - id: R10
    title: "Ratify ADR 0018 (Accepted) + operator/doc updates for the four postures"
    layer: docs
    depends_on: [R1, R2, R3, R4, R5, R6, R7, R8, R9]
    decisions: [D1, D2, D3, D4, D5, D6, D7, D8, D9, D10, D11]
    labels: [docs]
    summary: >
      Flip ADR 0018 to Accepted; cross-link ADR 0007 (step-up under unbridle) and ADR
      0003 (embedder fail-open vs core unbridle); write the operator guide for the four
      postures and the three tokens.
    acceptance:
      - "ADR 0018 Status: Accepted; open questions removed (resolved)"
      - "ADR 0007 and ADR 0003 cross-reference the two-axis model"
      - "operator guide documents Guarded / Confined-headless / Supervised-free / Autonomous and how to reach each"
```

## References

ADR 0002, 0003 (embedder fail-open allowance), 0004, 0007 (step-up contract), 0012,
0016, 0017 (D1/D2/D3/D6/D8). Epic #139; issues #151 (I12), #150 (I11, merged — the
disclosure channel), #158 (fail-open, distinct — off the mode grid, D7/R8).
