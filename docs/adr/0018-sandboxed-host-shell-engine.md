# ADR 0018 — Sandboxed-host shell engine: full-shell semantics with the guarantee entirely on L3

- Status: **Proposed** (#194)
- Date: 2026-07-03
- Context: ADR 0005 decoupled the shell **engine** (L2, convenience) from the
  **boundary** (L3, the kernel jail) and made engines pluggable behind the D2
  seam ("the same L3 jail wraps the process tree regardless of engine"). The
  default engine (D3, #34) is the argv + safe-subset executor, which
  **structurally refuses** the dynamic constructs (`$(...)`, backticks, `eval`,
  computed command names). Embedder field experience (#194:
  Gilamonster-Foundation/newt-agent#297/#850) shows real agent sessions hit
  those refusals within a handful of turns — models emit command substitution
  constantly — and operators respond by reaching for the fully-unbridled escape
  (ADR 0005 D5), i.e. the agent routes around the leash entirely. Meanwhile the
  L3 story has matured far past what ADR 0005 D3 could lean on: per-axis
  honesty + fence strength (ADR 0004/0012), the Landlock exec *boundary*
  (ADR 0011), Seatbelt `exec → Kernel` (ADR 0014), the loopback net fence +
  egress proxy (ADR 0015/0016), Tier-2 program identity via minimal rootfs
  (ADR 0013), and a layered `BridleConfig` with an authority-vs-mechanism split
  (ADR 0017).
- **Extends ADR 0005** (adds a second engine behind the D2 seam; D3 stays the
  default; D4's `brush-bridle-core` stays deferred and reversible) and
  **ADR 0006** (a new opt-in engine feature). **Governed by** ADR 0002 (no new
  mint site; the engine receives a `ToolContext` like any tool and the jail
  only ever *denies more*, so `effective ⊑ granted` is undisturbed), ADR 0004 /
  ADR 0012 (per-axis honesty + fence-strength refusal decide when the engine
  may run at all), and ADR 0017 D1 (engine selection is a **mechanism** knob,
  never an authority channel).
- Related: **#194** (this proposal), #20/#28 (the deferred brush engines this
  does not foreclose), #31/#57 (exec frontier), #144 (config-driven sandbox
  policy this reuses), Gilamonster-Foundation/newt-agent#868 (the embedder
  adoption surface).

## Question

Between the safe-subset engine (refuses dynamic constructs by design) and the
embedder's unbridled escape (no confinement at all), there is a missing third
posture: **full POSIX shell semantics with every restricted axis held by the
kernel jail — or honestly refused**. Can we ship that as an engine that
performs *no L2 enforcement at all*, so the guarantee rests entirely on the L3
backends the ADR 0011–0016 line already built — without the brush fork (#20),
without upstream (reubeno/brush#1184), and without overclaiming (ADR 0002 I9)?

## Decision

### D1 — A second engine behind the ADR 0005 D2 seam: spawn the OS shell as the jailed tree root

The `host-shell` engine (cargo feature, per ADR 0006) spawns a real POSIX shell
(`/bin/sh -c <cmd>`; D6 for the binary choice) as the **root of the confined
process tree**, inside the same L3 jail the safe-subset engine applies
per-stage — applied **once, to the whole tree**, which every backend already
supports by inheritance (Landlock rulesets and Seatbelt profiles both bind the
process and its descendants). The engine does **no parsing, no argv0 leash, no
redirect admission**: dynamic constructs run *because the kernel — not the
parser — bounds their reach*. L2 contributes only the existing cwd-within-
`fs_read` admission, the structured `env` seam, and the timeout harness,
reused verbatim.

This is ADR 0005 D1 taken to its limit: the engine is pure convenience, the
boundary is the jail. It is additive and reversible — the subset engine remains
the default (D3 unchanged), and a future interceptor/brush engine (#20/#28)
slots behind the same seam and merely *narrows* what routes here.

### D2 — Engaging condition: run only what the jail can hold; refuse the rest

The engine reuses the ADR 0012 machinery (`confinement_unenforceable`) with one
change of *inputs*, not of logic: because there is no in-process leash, an axis
that the active backend cannot hold at kernel grain has **no interceptor
fallback to claim** — its reality is `advisory` at best. Per axis, per backend:

| axis | Linux (Landlock) | macOS (Seatbelt) | reported |
|---|---|---|---|
| `fs_read` / `fs_write` restricted | ruleset over the tree | SBPL profile over the tree | `kernel`, else **refuse** (existing fail-closed rule) |
| `exec` restricted | ADR 0011 boundary ruleset (`Execute` + read-base); **identity** only under the ADR 0013 rootfs | ADR 0014 D1–D4 profile: `exec → kernel`, interpreters included | `kernel` where the backend honestly claims it (ADR 0014); boundary-grain disclosure on Linux per ADR 0011 D7; else refuse-or-advisory per the ADR 0012 floor |
| `net` empty | (netns/seccomp per #35 lineage) | `(deny network*)` | `kernel` |
| `net` loopback / remote allow-list | — | ADR 0015 fence / ADR 0016 egress proxy (proxy env injected through the env seam — a full shell propagates it to every child for free) | per ADR 0015/0016 |

Two honesty notes. First, the safe-subset engine's structural refusal of
dynamic constructs is a *stronger advisory posture* (ADR 0005 D3) — so on a
host where a restricted axis would be advisory under this engine but
interceptor-checked under the subset engine, the subset engine is the honest
server and this engine **refuses**; no request ever gets a *weaker* real
posture by switching engines. Second, where the jail holds every restricted
axis at kernel grain, this engine is **stronger than the interceptor path** —
the interceptor is blind to a permitted child's interior (ADR 0011); the jail
is not.

### D3 — Selection is a mechanism knob in `BridleConfig` (ADR 0017), never authority

`shell.engine = "subset" | "host"` in the layered config (defaults → file →
env → API, ADR 0017 D4), defaulting to `subset` (D3 of ADR 0005 reproduced
byte-for-byte, ADR 0017 D3). The knob selects *mechanism*; the grant is
unchanged, the mint chokepoint is unchanged (ADR 0017 D2), and per D2 above the
engine can only ever *refuse more* than the caveats allow — so configuration
cannot inflate an honesty claim (ADR 0017 D6/D7: the engine's per-axis report
states what actually held). An embedder may also select per-registry-build; a
per-dispatch override is deferred until a concrete need appears.

### D4 — What the envelope says

Unchanged shape. `sandbox_kind` reports the real backend; the per-axis
enforcement report follows D2's table; the envelope additionally names the
engine (`engine: "host-shell"`) so embedders and audit trails can distinguish
which mechanism ran. Refusals reuse the structured denial shape with a
distinct reason (`engine cannot hold <axis> at <floor> on this host`), so an
embedder can fall back to the subset engine legibly rather than by parsing
prose.

### D5 — Out of scope for the first pass

PTY/interactive use (batch `-c` only); Windows (deferred with the AppContainer
launcher lineage, ADR 0009 D6 — the engine reports itself unavailable and the
subset engine still serves); auto-fallback routing (subset-refusal → retry on
host-shell) — an ergonomic that needs its own decision once the engine exists;
per-dispatch engine override (D3).

### D6 — The shell binary is fixed, not granted

`/bin/sh` (POSIX mode), overridable only through `BridleConfig` (a mechanism
knob with a loud disclosure line, ADR 0017 D6), never through the grant — a
caveat that names a shell would be a second authority channel (ADR 0017 D1).
The binary itself must be within the jail's exec allow-list on backends that
enforce one (it is the tree root the profile is built around).

## Development plan

Each phase is one PR, TDD, `just check` green, with the envelope/report
honesty assertions as the spine of the test suite.

1. **Engine skeleton behind the `host-shell` feature.** Spawn `/bin/sh -c`
   through the existing spawner/timeout/env plumbing; serve **only** grants
   with every axis unrestricted (the ADR 0017 D8 "unbridle" shape, now with a
   jail-ready home); envelope parity tests against the subset engine
   (exit codes, stdout/stderr, timeout, env seam). Mock spawner; no OS
   sandbox yet. Report: all axes as today's honest `None`-backend posture.
2. **Filesystem jail.** Wrap the tree root with the config-driven
   Landlock/Seatbelt fs policy (#144 / ADR 0017 D5 reused verbatim); un-gate
   restricted-fs grants; fail-closed parity tests (restricted fs + no backend
   ⇒ refuse, exactly `confinement_unenforceable`).
3. **Exec axis.** macOS: apply the ADR 0014 profile tree-wide; serve
   restricted-exec grants at `kernel`. Linux: ADR 0011 boundary ruleset;
   disclosure per D7 grain; refuse-vs-serve matrix tests across ADR 0012
   floors. (Tier-2 identity via the ADR 0013 rootfs is a later, optional
   phase — the jaild lineage.)
4. **Net axis.** Empty-net kernel deny; ADR 0015 loopback fence; ADR 0016
   proxy env injection through the env seam; tests that a shell child
   inherits the proxy variables.
5. **`BridleConfig` knob + disclosure.** `shell.engine` per D3; disclosure
   lines per ADR 0017 D6; docs + README refresh (crate README rule).
6. **Embedder adoption** (tracked downstream,
   Gilamonster-Foundation/newt-agent#868): `[shell] engine` config surface;
   re-point `--yolo` at this engine where the caveat shape qualifies, making
   its "fs tools keep the workspace fence" banner true for the shell itself.

## Consequences

- The "usable full shell" no longer waits on reubeno/brush#1184, the crates.io
  git-dep ban, or a fork (#20 stays deferred; ADR 0005 D4 untouched).
- The engine's value scales with exactly the investments already being made
  (ADR 0011/0013/0014/0015/0016): every L3 axis close automatically widens
  what this engine can honestly serve. Nothing is throwaway.
- Embedders get a third posture between safe-subset and unbridled, and the
  unbridled escape can shrink to the genuinely-unconfinable cases.
- Risk to name: a full shell *runs* what the subset engine would have refused;
  on hosts where a restricted axis is only advisory the refusal rule (D2)
  keeps that surface closed, at the cost of "why won't it run here"
  legibility — mitigated by D4's structured refusal reason.

## Alternatives considered

- **Wait for reubeno/brush#1184 + a crates.io brush** — unbounded external
  timeline to strengthen L2, the layer ADR 0005 D1 moved the guarantee off of.
- **`brush-bridle-core` fork now** (ADR 0005 D4) — costs unchanged (published
  fork name, rebase treadmill, dynamic constructs advisory-until-L3); stays
  the recorded fallback, deliberately resisted.
- **A different embeddable shell** (nushell, …) — no interception hook either;
  buys nothing over D1 while adding non-POSIX semantics agents don't emit.
- **Auto-fallback from the subset engine now** — deferred (D5): routing policy
  deserves its own decision after the engine's refusal surface is real.

## Tracking

- Proposal + discussion: **#194**
- Phase issues: to be filed on acceptance (one per Development-plan phase)
- Downstream: Gilamonster-Foundation/newt-agent#868
