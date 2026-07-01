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
  granted`), ADR 0004 (per-axis honesty), ADR 0012 (fence strength from caveats),
  and ADR 0017 (authority≠mechanism, enforcement≠disclosure; D8 in particular).
  Cross-refs the fail-open work (#158) and the caveats source
  (`agent-bridle-mcp/src/caveats_source.rs`).

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
2. **Acknowledgement** — the exact runtime token `AGENT_BRIDLE_UNBRIDLE=i-understand`.

A missing, empty, or non-matching ack (including a bare `=1`/`=true`) is a **hard,
loud refusal**, *not* a silent downgrade: the process fails closed to the normal
deny-all default and prints why. The two-key design means neither a stray config
setting **nor** a stray env var can unbridle on its own — accidental unbridle is
not reachable. This preserves ADR 0017 D3's "fail-closed absence" as an absolute.

> Open question for review: the exact ack token string (`i-understand`) and
> whether it should additionally require a TTY / interactive confirm for
> human-present sessions. Proposed: keep it env-only (works headless) but make the
> banner unmistakable (D5).

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

> Open question for review (implementation): how the "unbridled" flag reaches
> envelope construction. It must be driven by the *acked mode*, **not** inferred
> from `top()`+`None` (a normal permissive grant of `Caveats::top()` is *not*
> "unbridled"). Proposed: a process-level `Unbridled` marker set once by the loader
> at startup (process mechanism, not per-invocation authority — so it does not ride
> `ToolContext`), read when a tool builds its `ToolEnvelope`. This keeps
> authority≠mechanism (ADR 0017 D1) intact.

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
   construction reads to stamp `disclosure.unbridled = true` (D5 open question).
4. Tests: `top()`+`None` ⇒ empty report / no confinement claim; ack required
   (missing ack fails closed; bare `=1` rejected); provenance is `Unbridled`, never
   `FailClosedDefault`; `disclosure.unbridled` on every envelope; the gate remains
   the only mint path.

## References

ADR 0002, 0004, 0012, 0016, 0017 (D1/D2/D3/D6/D8). Epic #139; issues #151 (I12),
#150 (I11, merged — the disclosure channel), #158 (fail-open, distinct).
