# ADR 0004 — Axis-granular confinement honesty, the un-stub gate, and fence strength is derived (never domain-keyed)

- Status: Proposed
- Date: 2026-06-24
- Context: `agent-bridle-core` `LandlockSandbox` (the `fs_write` first increment,
  I10) and result-envelope `sandbox_kind` (I9); `agent-bridle-tool-shell` (the
  stub today — ADR 0003 — and the brush-backed target shell on the dev branch);
  the `agent_mesh_protocol::Caveats` axes `{fs_read, fs_write, exec, net,
  max_calls, valid_for_generation}`.
- **Extends ADR 0002** (refines **I9** from a single `SandboxKind` to a per-axis
  report; adds a release gate on un-stubbing the shell that operationalizes
  ADR 0002's own consequence "an `exec`-permitted program's interior is confined
  only where Landlock runs"). **Extends ADR 0003** (the un-stub event ADR 0003
  says "is revisited" when brush#1184 lands — this is that revisit, written
  ahead of time so the bar is known). Changes no existing invariant's language
  down the ladder.
- Origin: a grounded adversarial review of the "Object-Capability Shell — Wrap
  vs. Reimplement" design note (`docs/reviews/2026-06-24-ocap-shell-axis-coverage-review.md`).

## Question

ADR 0002 I10 backstops a *permitted external program's interior* with Landlock —
but only the **`fs_write`** axis (the "first increment"). ADR 0003 records that
the shell is a **fail-closed stub** today, so I10 "is not exercised." Both are
honest. The unanswered question is the one that bites at the moment the stub is
replaced by the real brush-backed shell (reubeno/brush#1184 + agent-bridle#20):

> When a *permitted* external tool runs (`grep`, `find`, `sed`, `awk` — none are
> uutils coreutils, so all run as external binaries), its own `fs_read`,
> child-`exec`, and `net` egress are invisible to L2 (the brush interceptor only
> sees brush's own spawns/opens) and **ungoverned by L3** (Landlock = `fs_write`
> only). So `find … -exec curl …`, `awk 'BEGIN{system("curl …")}'`, and
> `grep -f /etc/shadow` read secrets, spawn children, and exfiltrate over the
> network **while the result envelope reports `sandbox_kind: Landlock`**. How do
> we un-stub the shell without (a) overclaiming confinement at axis grain or
> (b) silently regressing from "fail-closed stub" to "fail-open on three of four
> axes for permitted externals"?

These attacks were verified line-by-line against the dev-branch target shell
(see the review). They are not a contradiction of the contract — ADR 0002's
consequences already say the `fs_*` leash "rests on I7 (`exec` scope) plus I10
(Landlock)" and that the interior is "confined only where Landlock runs." This
ADR turns that acknowledged limit into a **gate** and a **report**, so it cannot
be crossed silently.

## Decision

### D1 — I9 becomes axis-granular (refinement, not a downgrade)

A single `SandboxKind ∈ {Landlock, None}` cannot honestly describe a run where
`fs_write` is kernel-confined but `fs_read`/`exec`/`net` are advisory. Reporting
`Landlock` for such a run satisfies I9 coarsely ("*something* was kernel-enforced")
while misleading at the grain a caller reasons about. Therefore:

- The result envelope MUST report, **per Caveat axis** that the effective grant
  restricts (i.e. is `Only(_)`, not `All`), the enforcement actually achieved:
  `kernel` (an OS ruleset enforces it against the spawned program's interior),
  `interceptor` (in-process L2 only — holds for brush's own ops, **not** for a
  permitted external child), or `advisory` (validated at admission, then ambient).
- `sandbox_kind` is retained as the coarse summary (back-compat) but is the
  **minimum**, never the maximum, claim: a `Landlock` summary with an `advisory`
  `net` axis is the honest, expected shape once the real shell lands.
- The honesty rule of ADR 0003 is reaffirmed at axis grain: **no prose, schema,
  or field may describe an axis as confined that the report marks `advisory`.**

This is additive and testable in `agent-bridle-core` (a pure
`enforcement_report(effective, active_kind) -> per-axis` function) ahead of the
shell, and is the primitive D2/D3 build on.

### D2 — The un-stub gate (a release gate on agent-bridle#20 / brush#1184)

Replacing the fail-closed stub with the real shell MUST NOT ship a confinement
**regression** for permitted external programs. Concretely, the un-stub PR is a
release blocker unless, for any axis the effective grant restricts:

1. that axis is **kernel-backstopped** for the spawned interior — `fs_write` via
   I10 today; `net` via Landlock network rules (kernel ≥ 6.7) **or** a network
   namespace with deny-by-default egress through a brokered proxy **or** a seccomp
   `connect`/`socket` filter; `fs_read` via a Landlock read ruleset with a curated
   loader/system-path allow-list; child-`exec` via a seccomp `execve` filter or a
   namespace with no shell present — **or**
2. the run is **honestly reported `advisory`** on that axis per D1 **and** the
   embedder has selected an enforcement strength (D3) that permits advisory runs.

The default for a principal launched at **strong** strength is **fail closed**
(refuse the invocation, as the stub does today) when a restricted `exec` or `net`
axis cannot be kernel-honored — i.e. *do not run a shell-out-capable external
under "`net: none`" if "`net: none`" cannot be enforced against its children.*
This preserves the stub's safety property through the transition: today's floor
is fail-closed; the un-stub must not lower it silently.

> Why this matters: the stub denies `find -exec curl …` (fail-closed). A naive
> un-stub *allows* it (Landlock confines only the write it never makes). That is a
> downgrade of the operative exec floor — exactly what ADR 0002's status ladder
> forbids doing silently.

### D3 — Fence strength is **derived** from declared Caveats; presets, not domains, set it

The capability primitive is already `Caveats` (the meet-semilattice, I2/I3);
this team already has capability-keyed presets (`NamedPermissionPreset`, `/mode`,
loadouts). We adopt three rules so strength can never be set by the wrong thing:

- **Strength is derived, not declared.** "How hard a fence" a run needs is a
  function of the **declared Caveats** (which axes are restricted) and the
  **available backend** (which axes it can honor) — computed at the existing mint
  / apply site, surfaced via D1. There is **no separate mode/strength enum** that
  can drift from the lattice. (The note's "declare capabilities, not modes" — the
  positive half is already the architecture.)
- **Presets are curated lattice points.** strong / weak / wrapper-only ("YOLO")
  are named `Caveats` constructors + a strength setting, fed into `granted`. The
  wrapper-only tier still flows through the single interceptor (audit + chokepoint
  preserved; the honest alternative to a logged YOLO is users routing to raw
  binaries — strictly worse).
- **Domains may select a preset; a domain MUST NOT key strength directly.**
  Mapping `code ⇒ weak` is **backwards on threat model**: a code agent that writes
  and runs arbitrary programs is the **highest-risk** ocap scenario (`-exec`,
  `system()`, reaching raw binaries), not the lightest. `code` is the *strictest*
  preset; it wants weak only for dev *friction*, which must be a named, accepted
  tradeoff (an explicit launch-time choice), never an accident of a domain label.
- **Strength is a launch-time property of the principal, immutable from inside,
  non-self-escalating** — consistent with I1 (mint-token), I3 (no reachable
  amplify), I11 (generation), and I13 (amplifying one's own writ needs the human
  root). A child delegation carries the **meet** of fence strength too: a child
  can attenuate, never be minted *stronger-claiming than its parent can honor*.

## Consequences

- **Reviewers** hold the un-stub PR to D2: every restricted axis is either
  kernel-backstopped or honestly `advisory`; `sandbox_kind` plus the per-axis
  report (D1) never describe an `advisory` axis as confined (I9 at axis grain);
  the operative exec floor does not drop below the stub's fail-closed default for
  a strong principal (D3).
- **Sequencing** of the L3 axes (the "genuinely deep" cost the note predicts):
  `fs_read` (Landlock read ruleset + loader allow-list) and child-`exec`/`net`
  egress (seccomp / netns-with-brokered-proxy / Landlock-net ≥ 6.7). Until an
  axis ships a backstop, that axis is `advisory` and a strong principal fails
  closed on it (D2/D3) — never "wrapped + sandboxed" in prose.
- **I10 wording** ("Landlock … Linux ≥ 6.7") is the *network*-rule floor; the
  shipped `fs_write` ruleset is the 5.13-era fs floor (`AccessFs`, ABI V3
  best-effort). The per-axis report (D1) makes this precise instead of folding two
  kernel floors into one number.
- **No new security vocabulary per tool** (ADR 0002 consequence) — D1/D3 live in
  `agent-bridle-core` over `Caveats`; a tool still only declares `required` and
  reads its `ToolContext` + the report.
- This ADR is **Proposed**: it adds `Planned` refinements (D1 primitive may land
  ahead of the shell; D2/D3 land with the un-stub) and downgrades nothing. When
  the real shell lands, the relevant ADR 0002 invariants move *up* the ladder
  per D1/D2, never silently (ADR 0003's revisit rule).

## Alternatives considered

- **Un-stub with `fs_write`-only Landlock and call it "confined."** Rejected:
  silent 3-axis regression vs the stub and an I9 overclaim at axis grain.
- **Keep one coarse `SandboxKind` and document the gap in prose only.** Rejected:
  prose is not a report; a caller automating on `sandbox_kind == Landlock` would
  still trust an ambient `net`. D1 makes the gap machine-readable.
- **A separate strength/mode enum parallel to `Caveats`.** Rejected: a second
  source of truth drifts from the lattice (I3); strength must be *derived*.
- **Domain-keyed strength presets.** Rejected (D3): conflates fence strength
  (untrust axis) with data-sensitivity/friction, and gets the code agent —
  the highest-risk case — exactly backwards.
