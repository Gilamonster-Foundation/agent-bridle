# ADR 0010 — Command packs: a data-driven L1 escape-surface layer for the leash

- Status: Proposed (2026-06-30)
- Date: 2026-06-30
- Context: ADR 0001 defines the three OCAP layers — **L1** static decomposition / atomic
  admission + per-node sub-attenuation, **L2** the in-process `before_exec`/`before_open`
  funnel, **L3** the kernel sandbox — and explicitly **reserves L1 but leaves it empty**.
  Today the authoritative leash is the L2 funnel in
  `agent-bridle-tool-shell/src/caveat_interceptor.rs`, whose `before_exec(program, _args)`
  **ignores `_args`**: `ToolContext::check_exec` consults the `exec` scope against argv0 only.
  That is correct for the path-separator bypass it was built for (`/bin/rm` denied even spelled
  out — DESIGN §6), but it is exactly why "swamp tools" escape: `find . -exec rm {} \;` passes
  (`find` is in scope; it then `fork`/`exec`s `rm` *inside its own process*, never re-entering
  the funnel), as do `awk 'BEGIN{system("curl …|sh")}'`, `grep -f /etc/shadow`, `sed -i`,
  `xargs rm`, `tar --to-command`, and `git -c core.sshCommand=…`. These are **not** ADR 0001's
  undecidability wall — they are *statically-known literal* flags on *named* binaries, the
  precise "statically-knowable interior" L1 says we can classify before any side effect. The
  knowledge ("for `find`, `-exec` is an exec surface; for `awk`, `system(` is") is per-command
  and currently nowhere — partly hardcoded in `confined_builtins()`/`REMOVED_BUILTINS`, one
  command at a time. newt-agent shipped **language packs** (a pluggable, TOML-driven, merge-by-
  `name`, fail-tolerant data model for a language's API surface); this ADR decides whether and
  how to generalize that *mechanism* — with an inverted trust posture — into agent-bridle.
- **Extends ADR 0001** (fills the reserved L1 layer with concrete data) and is governed by
  ADR 0002 (the meet-semilattice + unforgeable `ToolContext` invariants), ADR 0004 (axis-
  granular honesty), and ADR 0005 (the safe-subset engine that bounds the argv this layer scans).
- Related issues: **#58** (this design), #31 (un-stub gate — "refuse documented shell-out
  flags" is a command-pack escape), #34 (the safe-subset engine), #57 / DESIGN §6 (the L3
  exec/interior gap a pack declares but cannot itself enforce), #20/#28 (the deferred brush AST
  engine this layer's parser ultimately rides on).

## Question

A language pack *parses static text* and the worst outcome of a wrong rule is a missing symbol
in a prompt. A "command pack" would feed a *deny/allow* decision and the worst outcome of a
wrong rule is a **leash escape**. **Should agent-bridle fill ADR 0001's empty L1 layer with a
data-driven, pluggable command-pack mechanism — and if so, on what trust posture does the
language-pack plumbing carry over without becoming a new attack surface?**

## Decision

Adopt the language-pack **mechanism** (pure TOML; built-ins + global dir + project dir +
inline; merge-by-`name`; template + worked example; engine-agnostic data model that survives a
regex→AST swap) and **invert the trust model**: a command pack is a *danger-list whose gaps
must deny, not allow*. It introduces **no new authority type, no new gate, no new mint site**;
it only routes a slice of argv to an *existing* `check_*` against the *already-attenuated*
effective `Caveats`. The `meet` law and the unforgeable `ToolContext` are undisturbed. The
following sub-decisions resolve issue #58's open questions (a–k).

### D1 — Data model: declare the *escape surface*, not a safe-flags allowlist

A pack is keyed by `name` (the merge id) and claims binaries by **basename** (matching
`exec`-scope semantics; a pack named like a built-in *replaces* it). Five blocks escalate
identity → structure → output → teach → **safety**; the safety blocks are the heart:

- `[doc]` — optional pedagogical face (when-to-use, danger one-liner) — see D12.
- `[[flag]]` / `[[subcommand]]` — structure, each with an `effect` (`read|write|meta|exec|net`)
  mapping onto the existing Caveat axes so admission can reason about argv.
- `[[destructive]]` — mutates state but stays **inside** the leash (an `fs_write` the agent may
  not have wanted, e.g. `find -delete`); names the governing `axis`.
- `[[escape]]` — breaks **out** of the leash; the category L2 cannot see. Typed by *how* it
  escapes (D3), with a `takes`/`delim` payload locator (`next_arg`, `argv_until ; +`,
  `=value`, or `in_program` regexes for sub-language operators like `awk` `system(`).

The polarity is fixed (Q-g): **allowlist the escapes-to-block, never the args-to-permit**, so a
drifted pack fails toward over-restriction (safe), not under-restriction.

### D2 — The narrow-only invariant is **type-enforced** (the keystone) — Q-a

A pack's output type is "additional restrictions," with **no code path from pack data to a
widened `Scope`**. The worst a malicious or drifted pack can do is over-restrict (a fail-closed
usability bug). A pack may *only* map a surface onto an existing axis check; asserting `safe =
true` (an un-checkable claim) is **unrepresentable in the schema**. This is what makes "the
leash confines a novel command without hardcoding it" sound rather than a new attack surface;
without it, packs are trusted *code*, not data, and the whole pitch collapses.

### D3 — `escape.kind` is a **closed** security enum — Q (§4.2)

Unlike a language pack's free-form `kind`, each value names a concrete enforcement response:

| `kind` | What escapes | Maps to |
|---|---|---|
| `child_exec` | spawns a child the funnel never saw (`find -exec`, `xargs`, `timeout`) | `check_exec(child_argv0)` |
| `eval` | runs a string as code in-process (`awk system()`, `sed e`, `perl -e`) | `Refuse` (+ D10) |
| `file_read_injection` | reads an agent/attacker-named file as control input (`grep -f`, `ssh -F`) | `check_path_read(path)` |
| `net_fetch` | reaches the network from a "local" tool (`git clone http`, remote `tar`) | `check_net(host)` |
| `shell_out` | hands a string to `/bin/sh -c` (`git -c core.sshCommand=`, `vim -c`) | `Refuse` (+ D10) |

Only `[doc]`/symbol-style labels stay free-form. `max_calls`/`valid_for_generation` are
session-scoped, have no per-command analogue, and are **out of the schema entirely**.

### D4 — Three integration seams; non-amplifying — §5

- **Seam 1 — the funnel stops ignoring `args`.** `before_exec` resolves a pack for `program`'s
  basename, walks argv per the pack rules, and for each escape calls the **already-existing**
  per-axis `check_*` on the *same* `ToolContext`. `find . -exec rm {} \;` under `exec:
  Only{find}` now **denies** — the pack surfaces `rm` to `check_exec`, which the `meet` already
  excluded — *before* `find` ever forks. The escape inherits basename-vs-full-path matching, the
  canonicalizing `check_path` (`..`/symlink rejection), and exact-host `net` matching for free.
- **Seam 2 — tractable only because the engine already bounds the argv.** The safe-subset engine
  (ADR 0005) refuses `$(…)`, `eval`, process substitution, and `$VAR`-as-command — the
  undecidable interiors. What survives is a *bounded list of literal argv vectors*; a pack scans
  those. Removing the unbounded surface is what makes bounded per-command analysis sound. A
  literal `-exec rm` is classified and denied; an `awk` program the pack cannot bound
  (`on_unparseable = "refuse"`) is treated as opaque and denied — **never cleared**.
- **Seam 3 — composes with L3, honestly.** A pack strengthens L2's *earliness and legibility*
  (a swamp-tool denial becomes pre-spawn and structured). Where L3 (Landlock) is live they are
  belt-and-suspenders; where a pack is missing or a novel flag slips through, L3 still confines
  the child. A pack-mediated deny is real L2 enforcement and never lets the `ToolResult` claim a
  `sandbox_kind` it does not have (ADR 0004). This realizes ADR 0001's per-node sub-attenuation
  *as data*: the pack's escape table is the declaration of "the slice after `-exec` is a fresh
  exec node — re-gate it."

### D5 — Unpacked command ⇒ fall to the safe-subset, **never deny-unknown** — Q-c

A command pack is *purely additive sharpening* for commands whose argument-internal escapes the
funnel cannot see. An un-packed command runs under exactly today's behavior. Deny-unknown would
make packs mandatory and pack-coverage-bound and would **invert agent-bridle's actual
guarantee** — the funnel already confines novel commands today, depth- and command-agnostic.
**A pack must make the leash tighter/more legible for *known-dangerous* commands; it must never
be the gate that decides an *unknown* command is allowed at all.**

### D6 — An **extension** of the caveat/scope model, not a fourth trust root — Q-d

A pack rule is "for command C, argv pattern P implies a sub-attenuation / opaque-node flag,"
expressed in the *existing* vocabulary — the declarative front-end to ADR 0001's already-blessed
per-node sub-attenuation. It inherits the existing threat model and stays inside the
meet-semilattice, so D2 holds by construction. A genuinely new layer would need its own threat
model and its own audit; this does not.

### D7 — Load posture: fail-**closed** for `[[escape]]`, fail-tolerant elsewhere — §6.1

Language-pack loading skips a malformed rule and keeps going. We **invert that for danger
declarations**: a malformed `[[escape]]`/`[[destructive]]` loads the pack in an `unknown`
posture (its claimed binaries fall to the plain funnel) — never silently dropped to an opening.
`[doc]`/structure blocks stay fail-tolerant. **Merge precedence flips for safety fields: the
most-restrictive layer wins** (a project pack may *forbid* `find -exec` but can never
*un-forbid* what a stricter layer or the built-in forbade). Tolerant loading is sound *only
because* L2 still fires at every spawn/open — "no L1 hints" lands on today's behavior, not a
hole (ADR 0001's "L1 cannot clear what L2/L3 would deny").

### D8 — Two-tier trust: built-ins enforce, drop-ins **tighten-only** — Q-f

Mirroring DESIGN §8's trusted-in-process / untrusted-Landlocked split: **built-in packs** ship
in-binary, are first-class, and may inform *enforcement*. **Drop-in / community packs**
(`~/.bridle/command-packs/`, project `.bridle/command-packs/`) are **tighten-only** — they may
add restrictions but are never the sole reason a novel command is *cleared*. **Signing buys
provenance ("who do I blame"), not correctness** — a signed-but-wrong `kubectl.toml` is still
wrong; the safety mechanism is D2's narrow-only invariant, not the signature. Natural seam for
the content-addressable + OCAP-signing work: an unsigned drop-in is admissible only in the
restrict-only direction; a signed pack from a trusted key may relax where unsigned may only
tighten.

### D9 — Adversarial conformance test per built-in pack — required CI gate — Q-f/g

The only verification ADR 0001 trusts is the behavioral one (cf. DESIGN §5's CI presence test).
Every built-in pack ships a **deny-fixture** (`find -exec curl …`, `awk 'system()'`) and the
loader asserts L2 *actually* denied it; **a pack whose own deny-fixture passes through is
rejected at load** and fails CI. This is the command-pack analogue of the presence test and is a
**blocking** gate for built-in packs.

### D10 — A pack may **raise the required `sandbox_kind`**, never silently degrade — Q-e

A pack can *declare* `awk system()` and `grep -f`'s in-child open but **cannot enforce** them
in-process (the child's own syscalls — the L3 gap, DESIGN §6 "no universal open-file hook").
For `eval`/`shell_out`/`file_read_injection` escapes it cannot back in-process, a pack may
require an L3 backstop — **refuse-if-no-Landlock** — rather than admitting under an advisory
`SandboxKind::None` and reproducing the expected-vs-runtime divergence ADR 0004 forbids. The
honesty rule holds: a pack never lets the envelope claim confinement it does not have.

### D11 — Granularity: a **hybrid** of capability tags + per-command refinements — Q-h

A small shared vocabulary of dangerous behaviors — `spawns-subprocess`, `reads-arg-as-path`,
`interprets-arg-as-program`, `writes-arg-as-path`, `network-capable` — carries the *enforcement
response per tag, coded once* (closer to OCAP's "classify the authority, not the tool" and far
less drift-prone). Tags are the floor; per-command argv refinements capture positional escapes
tags cannot ("argument 2 only after `-exec`"). The tag set is the closed `kind` enum of D3.

### D12 — Phasing: enforcement face first; bootstrap engine → AST — Q-b/i/j

Ship the **enforcement face** (escape surface only) first — it is the higher-value,
agent-bridle-native half. The pedagogical `[doc]` face and `[output]` parsing land second, with
the pack as the *single source* a gilabot help surface renders from (don't duplicate; feed —
§7). The engine starts as an argv-substring/flag-table bootstrap and evolves toward the
`brush-parser` argv-grammar AST walk ADR 0001's L1 already plans (paralleling newt's regex→AST
migration); the data model is engine-agnostic and does not change. **Learn-from-runs** (mining
the `DenialSink` corpus) may *propose and prioritize* pack content for human ratification —
**never auto-author enforcement** (it is reactive, blind to argument-internal escapes, and
corpus-poisonable).

### D13 — Scope-creep boundary — Q-k

Built-in packs cover only the **core swamp tools** (`find`, `git`, `grep`, `awk`, `sed`,
`xargs`, `tar`, `p4`). Per-version / per-vendor argv tables (GNU vs. BSD vs. busybox `find`) are
**out of scope for v1** — keep packs coarse and lean on L3 for the residual. `p4`'s non-POSIX
argument grammar needing a richer rule shape than a flat flag table is the **canary**: if the
schema must grow per-tool special cases to fit one binary, that is the signal we are building a
policy registry we must own forever, not a feature — stop and reconsider.

## Consequences

**Positive**

- Closes the L2 args-blind gap as **data, not Rust**: a novel command (`p4`, `jj`, `rclone`,
  `kubectl`) is a drop-in file, not a recompile, and `confined_builtins()`/`REMOVED_BUILTINS`
  become generated/declared instead of hand-maintained.
- Denials become **pre-spawn and structured** (`Denial{kind: Exec, target: "rm"}`) instead of
  relying on L3 to catch `find`'s child after `mkdir ok` already ran (ADR 0001's partial-side-
  effect limit).
- **One artifact, two faces** (§7): "escape surface" becomes a single fact that is both a
  teaching point (gilabot) and an enforcement point (the leash), authored once.
- Sound by construction: D2 (narrow-only) + D5 (safe-subset default) + D6 (extension) keep the
  whole mechanism inside the existing threat model — it can only ever tighten.

**Negative / risks**

- **Maintenance + drift** (Q-g): per-command knowledge must track tool evolution; mitigated by
  the block-the-escapes polarity (drift → over-restriction) and D13's coarse-only scope.
- **The L3 honesty dependency** (D10): `eval`-class escapes are only *declared*, not enforced,
  without Landlock — so the refuse-if-no-Landlock posture is load-bearing and must not be
  marketed away.
- **A new config the security boundary reads** (Q-f): drop-ins are attacker-reachable — handled
  by D8 (tighten-only) + D9 (adversarial conformance) + the narrow-only invariant.

**Out of scope (this ADR)**

- The full TOML schema definition and the bootstrap parser (a build spec — this ADR fixes the
  *decisions*; #58 §4 carries the worked `find`/`awk`/`git` examples).
- Behavior *prediction*. A pack declares **static facts about argument grammar**; the moment it
  asserts what `awk 'BEGIN{system($COMPUTED)}'` will *do*, it recreates the undecidability
  ADR 0001 rejects. The pack points the leash at the node; L2/L3 still judge the node at use.

## Options considered and rejected

- **Deny-unknown default** (purest OCAP) — rejected (D5): it makes packs mandatory and *inverts*
  agent-bridle's best property (depth-/command-agnostic confinement of novel commands today).
- **A fourth trust root / new layer** — rejected (D6): needs its own threat model and audit; the
  extension stays inside the meet-semilattice so narrow-only holds for free.
- **Free-form `kind`** (as in language packs) — rejected (D3): a `safe = true` claim is not
  checkable; only a closed enum maps to a concrete, confirmable enforcement response.
- **Capability tags only** — rejected as insufficient alone (D11): tags cannot express
  positional escapes ("arg 2 only after `-exec`"); kept as the hybrid floor.
- **Importing language-pack tolerant loading wholesale** — rejected for safety blocks (D7): a
  dropped danger declaration must fail closed, not be silently skipped.
