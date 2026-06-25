# ADR 0005 — Decouple the shell engine from the boundary: L3 is the boundary, L2 is convenience

- Status: Accepted (ratified 2026-06-24); **extended by ADR 0006** (per-OS L3
  backend selection + engines as opt-in cargo features)
- Date: 2026-06-24
- Context: `agent-bridle-tool-shell` (a fail-closed stub today — ADR 0003); the
  brush `CommandInterceptor` (L2) lives on a fork blocked by crates.io's git-dep
  ban + upstream reubeno/brush#1184 (#20, `brush_confined_shell_handshake.md`);
  ADR 0004 D2 (#31) the L3 axis coverage; the `Caveats` / `ToolContext` /
  result-envelope contract (ADR 0002 I1–I3).
- **Amends ADR 0001** — reframes L2 from *authoritative* to *convenience*; the
  object-capability **boundary is L3**. **Extends ADR 0003** (a usable confined
  shell no longer waits on upstream brush) and **ADR 0004** (D2's L3 is now *the*
  boundary, not a backstop).
- Origin: the design discussion following the ADR 0004 review
  (`docs/reviews/2026-06-24-ocap-shell-axis-coverage-review.md`).

## Question

The only authoritative in-process enforcer we have for a free-form shell is the
brush `CommandInterceptor` (L2). It requires a brush **fork** that crates.io
won't let us publish and that waits on upstream (#20). That one dependency gates
shipping *any* usable confined shell — today the shell is a fail-closed stub, so
the only ways to run a command are "deny everything" or `--yolo` (fully
unbridled, ADR 0003).

Can we ship a usable confined shell **now** — without the fork, without upstream,
without overclaiming (I9), and **without foreclosing a future full-bash engine**?

## Decision

### D1 — Decouple the boundary from the engine (amends ADR 0001)

The object-capability **boundary is L3** (kernel: deny-by-default egress +
execute/read/write confinement of a *permitted program's interior*, ADR 0004 D2).
The shell **engine** — whatever parses input and spawns processes — is **L2 and
is convenience**: legible per-operation denials, ergonomics, cross-OS
best-effort. This *amends* ADR 0001's "L2 runtime interception is authoritative":
L2 remains the in-process leash and the legibility layer, but the **guarantee
rests on L3**; until L3 is active for a restricted axis, that axis is honestly
**advisory** (`sandbox_kind` = `None`, I9). This is not a downgrade — ADR 0002
already states the `fs_*` leash "rests on I7 + I10"; this names it and relocates
the guarantee to where it can ship without anyone's permission.

### D2 — A pluggable confined-shell-engine seam

An *engine* is anything implementing the Tool contract (I1–I3): it declares
`required: Caveats`, receives a `ToolContext`, checks `exec`/`open` at its own
funnel, and returns the envelope (`sandbox_kind` + denials). Engines are selected
by **cargo feature** (DESIGN §4/§5 knock-out). Adding or swapping an engine
touches no other engine and moves no invariant. The same L3 jail wraps the
process tree regardless of engine.

### D3 — Default engine this pass: **argv + safe-subset** (bridle is the funnel)

Implemented directly — no shell interpreter, no fork (#34):

- **pipelines** `a | b` — spawn N processes, OS-pipe stdout→stdin; check each
  argv0 against `exec` scope;
- **globs** `*.rs` — expand via `glob` against `fs_read` scope; refuse escapes;
- **sequencing/branching** `&&`, `||`, `;` — exit-code logic over argv commands;
- **redirections** `>`, `>>`, `<`, `2>&1` — bridle opens the target (canonical
  `fs_read`/`fs_write` check, I6) and wires the fd.

It **structurally refuses** the dynamic constructs — command substitution
`$(...)`/backticks, `eval`, process substitution `<(...)`/`>(...)`, dynamic
`$VAR`-as-command, functions, control flow with computed command names. These are
exactly ADR 0001's *undecidable, opaque ⇒ never-cleared* interiors; refusing them
is **least authority by construction**, not a missing feature. Net: the bulk of
real agent usage works while the dynamic attack surface is excluded by
construction — a *stronger advisory posture* than an in-process hook over full
bash, which runs those constructs and is blind to a permitted external's
children.

### D4 — `brush-bridle-core` is the deferred, **reversible** alternative engine

If full-bash fidelity is genuinely needed, `brush-bridle-core` ships as a
**renamed brush fork published to crates.io** and is wired as a *feature-gated
engine behind the D2 seam* — **no upstream acceptance, no git dep** (#20,
reshaped). It is recorded here as supported-and-addable so the choice stays
**contractually open**. Adopt it only when the safe subset provably cannot
express something agents repeatedly need *and* `--yolo` is too blunt. Costs to
weigh then: owning a published fork name + a perpetual rebase treadmill, and that
it runs the dynamic constructs (advisory until L3). Choosing argv now does **not**
foreclose this — it defers a pure addition and avoids the stickier costs up front.

### D5 — Interim escape hatch unchanged

Anyone needing full bash *today* uses the embedder's disclosed fail-open
allowance (`newt --yolo` / `NEWT_DISABLE_OCAP=1`, ADR 0003) — unbridled,
`sandbox_kind = none`, honestly. D3 raises the floor from "fail-closed stub **or**
fully unbridled" to "**useful + confined-advisory** or fully unbridled."

## Consequences

- The usable confined shell **no longer waits** on reubeno/brush#1184 or the
  crates.io git-dep policy. #20 is reshaped: brush is *an optional reversible
  engine*, not *the path*.
- **ADR 0004 D2 (#31) is now the boundary work, not a backstop.** L3
  (deny-by-default egress + execute/read/write allow-list of permitted interiors)
  is what makes any engine's restricted axes real; until it lands, restricted
  `exec`/`net`/`read` are advisory (D1/I9) and a strong principal fails closed
  (ADR 0004 D3).
- **Landlock is deferred this pass** (Linux-only — we won't couple the first
  usable confined shell to one OS) and tracked as a serious Linux-only
  *publishable* L3 variant (#35).
- The argv+safe-subset executor is **shared plumbing**: a future brush engine
  adds bash parsing atop the same funnel/leash/L3 jail — additive, not throwaway.
- No invariant moves down the ladder; when L3 lands, the relevant ADR 0002
  invariants move *up*, never silently (ADR 0003's revisit rule).

## Tracking

- Default engine (D3): **#34** (argv + safe-subset executor).
- L3 boundary (D1/D2): **#31** (ADR 0004 D2 axis coverage); **#35** (Landlock,
  Linux-only publishable variant); axis-granular honesty **#30** (ADR 0004 D1);
  fence strength **#32** (ADR 0004 D3).
- Reversible alternative engine (D4): **#20** (reshaped — `brush-bridle-core` as
  a feature-gated full-bash engine; relates to #28).

## Alternatives considered

- **`brush-bridle-core` now.** Rejected for this pass: front-loads the
  irreversible-ish costs (published fork, rebase treadmill, dynamic surface
  advisory-until-L3) for a capability we are not sure we need — *less* reversible
  than deferring it (D4).
- **Pure argv-only** (no pipes/globs/`&&`). Rejected: too ergonomically thin; the
  agent routes around it to `--yolo`, defeating the leash.
- **Landlock as the boundary this pass.** Deferred (#35): Linux-only; the first
  usable confined shell should not be single-OS.
- **`LD_PRELOAD` interposition as the boundary.** Rejected: advisory only
  (bypassed by static binaries / raw syscalls / `unsetenv`) — not a boundary.
- **In-process hook (the fork) as the boundary.** Rejected as *the boundary*: it
  cannot see a permitted external's children (the swamp-tool holes) and depends
  on the fork — kept only as convenience (L2) under D1.
