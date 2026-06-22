# ADR 0003 — The confined shell is a stub today: honest exec-confinement state (and the embedder's fail-open allowance)

- Status: Accepted
- Date: 2026-06-21
- Context: `agent-bridle-tool-shell` (the stub release), the `SandboxKind`
  honesty path (ADR 0002 I9) and the `LandlockSandbox` backstop (I10), and the
  relationship to embedders that fail closed downstream (newt-agent).
- **Extends ADR 0002** (the hard invariants) by recording the *current
  operational state* of the exec-confinement path — in the same "never
  overclaim" spirit (I9 + the status legend). It changes no invariant.
- Companion (the downstream view): `newt-agent/docs/decisions/ocap_confinement_model.md`.
  Prose: *The Age of the Confused Deputy*; `docs/DESIGN.md`.

## Question

ADR 0002 states the invariant **contract** (what MUST hold). This ADR answers a
narrower, time-sensitive question so no one — human or agent — reads the contract
as a description of *today*: **with the brush `CommandInterceptor` not yet
upstream (reubeno/brush#1184), what does the confined shell actually do right
now, what does that mean for embedders, and how do we keep the story honest?**

## The current state (honest)

- **The brush-backed confined shell is a STUB.** `agent-bridle-tool-shell` ships
  with the brush deps removed (`Cargo.toml`: "STUB RELEASE — full brush-backed
  shell is temporarily disabled pending reubeno/brush#1184"). `ShellTool`
  registers but **fails closed on every invocation** — `invoke` returns
  *"shell tool is temporarily unavailable in this build"* (tested:
  `invoke_returns_unavailable_error`). This is **I5 (fail closed) doing its job**:
  absent the real interceptor, exec authority is denied, not waved through.
- **`sandbox_kind` honestly reports `None`** (I9). Nothing is labeled
  kernel-confined, because nothing runs through a kernel sandbox. The
  `LandlockSandbox` backstop (I10) confines a *permitted external program's
  interior* — but a permitted program only runs through the real shell, and the
  real shell is stubbed, so I10 is **not exercised today**.
- Therefore the **operative exec floor in a stub build is: fail-closed (deny
  everything).** The usable confined shell + its Landlock backstop are the
  **target**, gated on reubeno/brush#1184 + agent-bridle#20.

This does not weaken ADR 0002. I1–I3 (the lattice, no-amplify), I5 (fail-closed),
I6 (canonical path containment), I9 (`sandbox_kind` honesty) remain enforced.
What is *pending* is the interceptor that makes confined exec **usable** rather
than merely fail-closed — exactly the state ADR 0002's status legend and the
`Cargo.toml` notes already anticipate. No invariant moves down the ladder here;
this ADR only timestamps where the shell sits on it.

## What this means for embedders — and the fail-open allowance

agent-bridle fails closed by construction (I5). That is correct, but in a stub
build it means a downstream harness's `run_command` denies **everything**, which
can make the agent unusable for legitimate work the leash hasn't yet been taught.
agent-bridle does not paper over this and does not silently open — the policy
choice belongs to the **embedder**, and must be disclosed:

- **newt-agent** embeds the stub, so it fails closed on exec by default, and
  **deliberately provides a fail-OPEN allowance: `--yolo` / `--disable-ocap`
  (`NEWT_DISABLE_OCAP=1`).** It routes `run_command` *around* bridle to the plain
  host shell (`sandbox_kind = none`) for that invocation — the human's explicit,
  per-invocation choice to **unbridle** the agent. It is not insistence; it is an
  *allowance*: the bridle is on by default, and the human may take it off. (newt
  keeps its `web_fetch` net leash and its native-fs fence on under `--yolo`; only
  the spawned subprocess is unconfined.) See
  `newt-agent/docs/decisions/ocap_confinement_model.md`.

The division of labor: **bridle's job is to fail closed; whether to offer a
fail-open escape — and how loudly — is the embedder's**, and it must be explicit
and disclosed. agent-bridle never opens silently.

## Honesty rule (reaffirmed for this surface)

No agent-bridle doc — and no embedder doc — may present the brush-backed confined
shell or its Landlock backstop as **active** while the shell is a stub.
`sandbox_kind` (here) and `verify_b1()` (downstream, in newt-agent) are the source
of truth: if they say `none` / `Absent`, no prose may say "confined." When
brush#1184 lands and the real shell is wired, **this ADR is revisited** and the
relevant ADR 0002 invariants move up the ladder — never silently.

## Consequences

- Reviewers hold PRs to: the stub shell fails closed (I5); `sandbox_kind` never
  overclaims (I9); the reubeno/brush#1184 + agent-bridle#20 dependency is named,
  not hidden.
- Embedders document their own fail-open allowance (if any) honestly and
  cross-link this ADR, so bridle and its hosts tell one consistent story about
  what confinement buys *today* versus at target.
