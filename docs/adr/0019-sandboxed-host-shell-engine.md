# ADR 0019 — Sandboxed-host shell engine: full-shell semantics with the guarantee entirely on L3

- Status: **Proposed** (for review)
- Date: 2026-07-04
- Context: **extends ADR 0005** (the object-capability boundary is L3; the shell
  *engine* is L2 convenience, pluggable behind the D2 seam) and **ADR 0006**
  (per-OS L3 backends + engines as opt-in cargo features). Also ADR 0011 (a
  Landlock `Execute` allow-list cannot honestly report `exec → Kernel` at
  program-identity grain — the loader trampoline; exec is boundary-grain at
  best) and ADR 0004 D1 (per-axis enforcement honesty).
- Origin: the embedder field report on issue #194 — under a *restricted exec*
  preset, real agent sessions hit the safe-subset engine's structural refusals
  (`$(...)`, backticks, dynamic constructs) within a handful of turns; models
  emit command substitution constantly. Operators respond by reaching for
  `--yolo --full-access` — i.e. the agent **routes around the leash to the fully
  unbridled path**, the exact failure mode ADR 0005's "Alternatives considered"
  warned pure-argv would cause. Today the practical outcome is binary:
  safe-subset **or** nothing-at-all.

## Question

Between the safe-subset engine (which *structurally refuses* dynamic constructs)
and the unbridled escape (no confinement at all) there is a missing third
posture: **full shell semantics with the filesystem axes kernel-confined and
exec/net honestly advisory**. Can we ship that as an engine behind the ADR 0005
D2 seam — without the brush fork, without waiting on upstream, and without
overclaiming (ADR 0002 I9)?

## Decision

### D1 — Adopt Option C: the sandboxed-host engine

A new, feature-gated engine behind the ADR 0005 D2 seam that performs **no L2
parsing at all**. It spawns the OS shell (`/bin/sh -c <cmd>`, or an
embedder-configured shell) with the **entire process tree inside the L3 jail**
derived from the caveats. The engine contributes **zero enforcement**; the jail
is everything. This is ADR 0005 D1 taken to its limit, and it is **additive**:
the safe-subset engine remains the default, the funnel/leash/jail plumbing is
shared (ADR 0005 D3's "shared plumbing" consequence), and **no invariant moves**.

### D2 — Honesty posture: it serves exactly the caveat shape the jail can enforce

The engine reports only what a per-OS L3 backend actually delivers (ADR 0004 D1 /
ADR 0006 D3–D4). `intended_sandbox_kind(caveats, sandbox)` is the oracle: if it
resolves to `None` **and any served axis is restricted**, the engine **refuses**
rather than run advisory-but-claiming-nothing on a restricted grant.

| axis | posture | rationale |
|---|---|---|
| `fs_read` / `fs_write` | **Kernel** when a backend is active (Landlock / Seatbelt); **refuse** otherwise | same fail-closed rule as today: restricted-but-not-kernel fs is unenforceable, so it is refused, never run advisory |
| `exec` | **not served** — refuse any request whose effective `exec` scope is restricted | the engine cannot check even argv0 inside a full shell; honest posture is refusal (D5.2), not a hollow `Advisory` claim. Boundary-grain Landlock `Execute` co-confinement (ADR 0011) can later *tighten* this without changing the contract. Restricted-exec requests stay on the safe-subset engine |
| `net` | **refuse** when restricted, until the netns/seccomp sibling (#31/#35) lands; `All`-scope runs are honest | mirrors exec |

So the engine serves exactly: **fs restricted (kernel-jailed), exec/net
unrestricted** — *"full shell, fenced filesystem."* That is precisely the
contract embedders' yolo flags *claim* today and do not deliver (a `--yolo`
banner that says "fs tools keep the workspace fence" while the shell itself runs
unfenced). With this engine an embedder can retire raw-host-shell bypasses for
the common case: full shell semantics, workspace fence intact, dynamic
constructs allowed **because the kernel — not the parser — bounds their reach**.

### D3 — Selection: a cargo feature, chosen by the embedder at construction

- **Cargo feature** `host-shell` gates the engine and its (OS-inert, ADR 0006 D1)
  deps.
- **The embedder chooses the engine at registry construction.** This *extends*
  the D2 seam: ADR 0006 D5 makes brush a **compile-time swap** of the one `shell`
  tool, because brush *replaces* the subset engine. The sandboxed-host engine is
  **complementary**, not a replacement — an embedder may legitimately want both
  (safe-subset as the default, sandboxed-host for the full-shell case) — so the
  choice is **construction-time**, not a compile-time swap. Both honor the same
  `Tool` / `Caveats` / result-envelope contract and the `Spawner` seam.
- **Explicit selection first.** Auto-fallback (the subset engine refuses a
  dynamic construct → retry on the sandboxed-host engine *iff* the caveat shape
  qualifies) is a deferred ergonomic behind its own decision; if ever adopted it
  is the embedder's *visible* construction-time policy, never a silent swap
  (D5.2).

### D4 — Per-OS L3 (reuses ADR 0006), one jail over the whole tree

- **Linux:** one combined Landlock ruleset over `fs_read`/`fs_write` applied to
  the shell process *before* exec, inherited by the whole tree; pair with the
  ADR 0011 seccomp backstop as it lands.
- **macOS:** derive one SBPL profile from the caveats and wrap the shell in
  `sandbox-exec` — Seatbelt confines a process **and its descendants**, so one
  profile on `/bin/sh -c` covers the tree (D5.1).
- **Windows:** deferred (#51) — honestly unavailable (the engine refuses; the
  subset engine still serves).
- **Envelope:** shape unchanged; `sandbox_kind` reports the real backend; the
  **engine identity** is disclosed (ADR 0017 D6 disclosure block) so an embedder
  can log which engine ran.

### D5 — Resolutions to the open questions (issue #194)

1. **Seatbelt profile for a whole tree.** Reuse #50 / ADR 0014's SBPL generation
   *verbatim*, applied **once to the tree root** — Seatbelt is inherited by
   descendants, so the single `/bin/sh -c` profile bounds the tree.
   Write-implies-read overlaps and `/dev/null`/tmp conventions are handled by the
   same derivation as the per-stage path (authored + verified on a Mac, #50).
2. **exec-restricted refusal: structured denial, not silent fallback.** A request
   whose `exec` scope is restricted gets a structured *"engine unavailable for
   this grant"* denial, **not** a silent route to the subset engine. Silent
   fallback would surprise the operator (they asked for the full shell, got the
   subset) and *hide the honesty boundary*; a structured denial lets the model
   adapt its command shape and lets the embedder select the subset engine
   explicitly.
3. **Which shell binary, and does it need a caveat?** The shell is
   **embedder-configured** (default `/bin/sh`), fixed at engine construction —
   **never a per-dispatch model input** (letting the model pick the interpreter
   is an exec-choice the caveats cannot bound). It needs **no separate caveat**:
   the engine only serves `exec = All`, so the shell is exec'd within the ambient
   grant; when `exec` is restricted the engine refuses (D5.2). The chosen shell
   is disclosed in the envelope for legibility.
4. **Command packs (ADR 0010) in front of C?** Packs are an **L1 exec-surface
   classifier for *restricted* exec** (`find -exec`, `awk 'system(...)'`). The
   sandboxed-host engine serves `exec = unrestricted`, so there is **nothing for
   exec-surface packs to refuse** — they are moot here *by design*; the **L3 fs
   jail is the guarantee** (the issue's "C is exempt — the jail is the answer").
   Packs remain load-bearing only for the subset engine's restricted-exec path;
   any fs-surface pack still composes with the jail as non-load-bearing
   defense-in-depth.
5. **PTY / interactive.** Confirmed **out of scope** — batch `/bin/sh -c <cmd>`
   only, exactly like the subset engine. Interactive/PTY is a separate concern.

## Consequences

- The binary "safe-subset **or** unbridled" outcome gains a real middle: full
  shell semantics with the workspace fence intact. This **narrows what routes to
  `--yolo`** — the field-report failure mode that motivated this ADR.
- **No invariant moves.** The jail is the same L3 that confines the subset engine
  (ADR 0006 orthogonality: engine ⟂ backend). The engine contributes zero
  enforcement and is I9-honest — `sandbox_kind` is the real backend, and it
  refuses rather than run a restricted served-axis unconfined.
- **exec/net restricted grants stay on the subset engine** (or await the
  #31/#35/ADR 0011 boundary work). This engine does not weaken any axis; it
  refuses the ones it cannot honestly bound.
- If the interceptor/brush engine (ADR 0005 D4) ever arrives, it slots behind the
  **same seam** and *narrows* what routes to C. Nothing here is thrown away.

## Tracking

- Engine implementation (D1/D3): **#194**.
- Per-OS L3 (D4): Linux Landlock **#35**; macOS Seatbelt **#50** / ADR 0014;
  Windows **#51**; exec/net boundary **#31**, ADR 0011.
- Seam extension (D3): amends ADR 0006 D5 — an engine may be a **complementary
  construction-time choice**, not only a compile-time swap.

## Alternatives considered

- **A — keep waiting on reubeno/brush#1184.** Rejected: waits on someone else's
  schedule to strengthen the L2 layer ADR 0005 D1 already *demoted to
  convenience*, and per ADR 0011 an in-process hook is blind to a permitted
  child's interior regardless. Unbounded timeline, wrong layer.
- **B — `brush-bridle-core` fork now (ADR 0005 D4).** Rejected for this pass: the
  costs D4 names (published fork name, perpetual rebase treadmill, dynamic
  constructs advisory-until-L3) are unchanged and the operator preference is to
  keep resisting. C does not foreclose it; D4 stays the recorded fallback.
- **D — a different embeddable shell (nushell, …).** Rejected: none expose a
  spawn-interception hook, so they buy nothing over C while adding non-POSIX
  semantics agents don't emit.
- **Silent subset fallback for exec-restricted grants.** Rejected (D5.2): hides
  the honesty boundary and surprises the operator.
- **host-shell as a compile-time swap (like brush, ADR 0006 D5).** Rejected: the
  subset and sandboxed-host engines are *complementary* (an embedder wants both),
  so selection is a construction-time choice, not a replacement.
