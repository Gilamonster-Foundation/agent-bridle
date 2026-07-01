# ADR 0017 — Total configurability via a layered `BridleConfig`, with an authority-vs-mechanism and enforcement-vs-disclosure split

- Status: Accepted (2026-07-01)
- Date: 2026-07-01
- Context: The bridle's tunable behavior is scattered across `const`s and always-on
  code paths; the only runtime config seam is the `Caveats` grant
  (`agent-bridle-mcp/src/caveats_source.rs`: `AGENT_BRIDLE_CAVEATS` +
  `~/.agent-bridle/config.toml`, default **deny-all**). We want every hard-coded
  value parameterized, every feature/behavior toggleable **and** tunable, all
  dimensions (hosts, network traffic, and the automatic *normalizations* the system
  performs to assist an agent) adjustable, and the ability to **completely
  unbridle** a system when needed — without weakening the OCAP invariants.
- Governed by ADR 0002 (the leash is the only path to running a tool; `effective ⊑
  granted`), ADR 0004 (per-axis honesty), ADR 0012 (fence strength derived from
  caveats), ADR 0008 (core leanness). Interacts with ADR 0006/0009 (per-OS
  backends) and ADR 0015/0016 (net over-delivery + disclosure precedent).
- Epic: #139 (I1–I14). Ratifies the approved implementation plan.

## Question

How do we make the bridle **totally configurable** — including a first-class "off"
switch — without adding a second authority channel, without letting configuration
inflate an honesty claim, and without bloating `agent-bridle-core`?

## Decision

Introduce a layered **`BridleConfig`** that tunes **mechanism** only. Its types live
in `agent-bridle-core` (serde-only); the file/env loader lives in a new
`agent-bridle-config` crate. Behavior composes around — never inside — the mint
chokepoint and the honesty lattice. The following invariants are binding for the
whole epic.

### D1 — Authority ≠ mechanism (two separate channels)

`Caveats` remains the sole **authority** channel (per-invocation, rides
`ToolContext`, `effective = granted.meet(required)`). `BridleConfig` is
**mechanism**: limits, path lists, feature toggles, backend selection, VM/proxy
parameters (per-process / per-principal). Config **never** widens authority and is
**never** an input to `meet`. This separation is what keeps "unbridle" and the
threading model honest.

### D2 — The mint chokepoint and the honesty lattice are not modified

`Gate::authorize` stays the only `ToolContext::mint` caller; there is **no**
`bypass_checks` / `UnsafeToolContext` / second mint site. `enforcement_report` /
`fence_strength` / `confinement_unenforceable` keep deriving the **achieved**
confinement from `(Caveats, SandboxKind)`. `gate.rs`/`context.rs`/`report.rs` stay
essentially untouched: config reaches mechanism via the *existing* gate stamps
(`with_strength_floor`, `with_sandbox`) plus **explicit policy parameters** to
out-of-band builders (`build_rootfs_plan`, `net_proxy::start`, `run_microvm`,
`ShellTool::with_config`, …). Config is **not** stamped onto `ToolContext`.

### D3 — Defaults reproduce today, byte-for-byte

Every `Default` returns the current constant; each is guarded by an **anti-drift**
test asserting `Policy::default() == <the const>`. A build with no config is
identical to today. Absence stays **deny-all** for the `Caveats` grant (a security
property), and unbridle is **never** reached by omission.

### D4 — Precedence: defaults → file → env → API

Layered per-field overlay merge (`Option`-typed partials), so a single override
(`BRIDLE_LIMITS_MAX_TIMEOUT_SECS=120`) changes only that field. Env convention
`BRIDLE_<AREA>_<FIELD>`; legacy env (`BRIDLE_REQUIRE_*`, `BRIDLE_NET_AUDIT`,
`BRIDLE_JAILD_SOCKET`, `BRIDLE_JAIL_INIT`) kept as mapped aliases; an
`AGENT_BRIDLE_CONFIG` JSON blob is the inline escape hatch. Resolution is a **pure
function** of `(file, env, api)` — unit-testable without touching process state.

### D5 — Security-relevant lists extend by default; shrinking is explicit

`PathList { base, extra, replace }`: `resolve()` returns `base ∪ extra` unless
`replace=true` (which uses only `extra`). Config can safely **widen** a list (add a
read path) without accidentally deleting a loader path that would break
confinement; **shrinking** a security list requires the explicit `replace` opt-in.
A widening is surfaced (`PathList::widens`) for disclosure — never silent.

### D6 — Enforcement ≠ disclosure

`EnforcementReport` remains the "never overclaim confinement" honesty lattice and is
**not** touched by config. A **new, separate** envelope `disclosure` block carries
what an operator should *know* — `unbridled`, `normalizations_disabled`,
`net_over_delivery`, `backend_forced`, non-default `limits` — quiet-by-default,
except `unbridled: true`, which always serializes. Disclosure never participates in
`fence_strength`. (This mirrors the ADR 0016 over-delivery/audit precedent.)

### D7 — Tuning stays honest; backend override is downgrade-only

Tuning only ever changes report **inputs** (`granted`, stamped `sandbox_kind`,
`strength_floor`); the report recomputes from the *achieved* state, so config cannot
make it lie. `strength_floor` may be config-raised (only *tightens* above the
`Advisory` bottom). A backend override is **downgrade / select-among-available
only** — `applied = min_capability(requested, best_available())` — with the report
derived from `applied` and a fail-closed if a restricted grant then can't be met.
Force-asserting an unavailable/uncompiled backend (which would let the envelope
claim `kernel` with no kernel rule) is **forbidden**.

### D8 — Unbridle is an honest, acknowledged, loud resolution-layer mode

`BridleMode::Unbridle` resolves (in the loader) to `granted = Caveats::top()` +
`strength_floor = Advisory` + `sandbox_kind = None`. Because `top()` restricts
nothing, the report is empty and no confinement is claimed — it is honest *by
construction*, changing **zero** lines in gate/context/report. It requires an
explicit acknowledgement (`AGENT_BRIDLE_UNBRIDLE=i-understand`; a bare value is
rejected, not silently ignored), gets a distinct provenance
(`CaveatsSource::Unbridled`), a shouting banner + `tracing::warn!`, and
`disclosure.unbridled = true` on **every** envelope.

### D9 — Dimensions grow additively (net → verbs/paths/gRPC)

`Caveats.net` stays `Scope<String>` (owned by `agent-mesh-protocol`). A separate
`NetPolicy` *refines* interpretation via a single `decide(&NetRequest) ->
NetDecision` entry point used by both `check_net` and the proxy. `NetRule` /
`HostMatch` are `#[non_exhaustive]`, so REST (`{scheme, host, method, path}`) and
gRPC (`{service, method}`) predicates are added later without breaking configs. A
structured rule is proxy-enforced (userspace) ⇒ the report keeps a non-loopback net
allow-list `advisory`, never `kernel`.

## Consequences

- **Positive:** one coherent, documented, layered config; every knob tunable;
  first-class honest "off"; existing behavior preserved by default; the honesty
  lattice and mint chokepoint provably intact; a clean seam for finer net OCAP.
- **Cost:** a new `agent-bridle-config` crate; policy parameters threaded through
  builder/constructor signatures (zero-arg constructors retained as
  `= with_config(Default::default())` for compatibility); duplicated literal
  defaults in core guarded by anti-drift tests until each const is folded into its
  policy default during wiring.
- **Scope of change split into #140–#153**; behavior-changing steps (I9 config
  `strength_floor`, I10 backend override, I12 unbridle, I13 `NetPolicy`) each carry
  their own ADR amendment; I2–I8 are inert/parameterization steps.
