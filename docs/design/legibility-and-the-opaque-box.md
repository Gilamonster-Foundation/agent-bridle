# Legibility and the opaque box — why we embed an interpreter at all

**Status:** position paper. No invariant moves; no enforcement claim changes.
This is the *value* argument for a layer ADR 0005 correctly demoted as a
*security* claim.
**Relates to:** ADR 0001 (three layers), ADR 0005 (L3 is the boundary, L2 is
convenience), ADR 0019 (sandboxed host shell engine), ADR 0010 (command packs),
`docs/design/ocap-policy-schema.md` (the accumulation loop).

## Why

ADR 0005 says the object-capability boundary is L3 and that the shell engine is
"convenience." As a statement about *where the guarantee rests*, that is right
and we should not soften it. But it has left a gap in the written design: if L2
is merely convenience, an obvious reader asks why we carry a forked shell
engine at all instead of shelling out to `/bin/bash` inside the L3 jail.

The answer is that **enforcement and legibility are different products, and only
one of them is available from `/bin/bash`.** This document makes that argument
so the engine is defended on its own merits rather than as a security layer it
has already been told it is not.

## The opaque box

Every agent harness in the field today — ours included, before bridle — runs

```
bash -c "<string the model wrote>"
```

and receives back exactly three things: stdout, stderr, an exit code. That is an
**opaque box**. The harness does not know what ran. It knows what it *asked* to
run, as text, and it knows what fell out the other end.

What is unavailable from inside the box:

| Want | Why `bash -c` cannot give it |
|---|---|
| **What actually ran** | The harness holds pre-expansion source text. The resolved argv after word splitting, globbing, `$(…)`, parameter expansion, alias and function resolution, and `$PATH` lookup exists only inside bash. |
| **Sound approval** | Approving a command by regex/prefix-matching the *source string* is defeated by `eval`, `$(…)`, `sh -c "$VAR"`, `cmd=$(pick); $cmd`, aliases, and `PATH` shadowing. This is not a hardening problem to be patched — it is a **category error**, and it is the same error ADR 0002 rejects when it rejects prompt hygiene. |
| **Attribution** | A write to `~/.ssh/config` arrives with no link back to the line of script that caused it, let alone the tool call that produced the line. |
| **Atomic admission** | `mkdir ok && rm -rf /` performs `mkdir ok` before anything can object (ADR 0001, limit 1). |
| **Structured denial** | You get "exit 1," not a tree-shaped account of which node was non-compliant and why. |
| **Checkpointing** | No way to pause mid-pipeline, ask a human, and resume. |
| **Replay** | No journal of effects, so no deterministic re-execution and no audit that is anything better than scrollback. |

L3 does not close this. A kernel sandbox tells you *"something under this process
tree tried to open `/etc/shadow`"* — true, load-bearing, and nearly useless for
explaining to a human what the agent was trying to do. Enforcement without
legibility produces denials nobody can act on.

## Brush's real asset is not bash compatibility

It is that **`brush-core` and `brush-parser` are libraries.** The compatibility
surface is what makes adoption cheap — agents already write bash, and we do not
have to teach them a new language. But the compatibility is the *ticket*, not
the *prize*.

The prize is that an embedded interpreter turns every dispatch point into a
**hook**. We do not have to infer intent from a string; we hold the parsed AST
(L1) and we see each `exec`/`open` at the funnel with its arguments already
resolved (L2). The entire list in the table above becomes reachable — not
because brush is secure, but because brush is *in-process and inspectable*.

This reframes the fork cost. The `brush-ocap-*` fork (ADR 0019) is not overhead
we tolerate to obtain a weak second leash behind Landlock. It is how we obtain
the only view of agent behaviour that is legible at the level a human reasons
about.

## Two axes, not a renumbering

To avoid muddying established vocabulary: L1/L2/L3 remain exactly as ADR 0001
and ADR 0005 define them. They answer **"where does the guarantee rest?"**

This paper adds an orthogonal question — **"what is each part *for*?"** — with
three answers that do **not** map one-to-one onto L1/L2/L3:

- **Legibility.** Parsed intent, resolved argv, an effect journal, and a
  provenance chain from tool call → script node → syscall. Spans L1 and L2.
  *Explicitly not a security boundary.* This is where the product value is.
- **Authority.** Capabilities as first-class values: `Caveats`, the mint-token
  `ToolContext`, `effective = granted.meet(required)`. **Orthogonal to the
  layers** — it is the thing every layer checks against, not a layer itself.
- **Enforcement.** The property that stays true when legibility and authority
  are both wrong, because the code implementing them has a bug. Landlock +
  seccomp + namespaces + jaild. Exactly ADR 0005's L3.

Stating these separately is what keeps I9 (honest disclosure) honest. The
failure mode we are guarding against is the historical one: **Safe.pm, Java's
SecurityManager, Python's `rexec`, Node's `vm`, Deno's permission flags** — every
one of them presented a legibility-or-policy layer as an enforcement boundary,
and every one was bypassed. The mistake is never "built the legibility layer."
It is "claimed the legibility layer was the boundary." We build both and label
them correctly.

## Legibility is a product, not a consolation prize

Concretely, the things only the embedded engine can deliver:

1. **Atomic admission** — refuse before the first side effect when a statically
   known node is non-compliant (ADR 0001 L1). Denial with zero damage is a
   different product from denial after partial damage.
2. **Denials a human can act on** — "line 3, `curl` → `evil.example`, `net`
   caveat is `none`" instead of "`EPERM`."
3. **The accumulation loop** — prompted permission → durable verdict →
   fewer prompts (`docs/design/ocap-policy-schema.md`). That loop needs a
   *stable, canonical identity for the operation*, which means resolved argv.
   Source-text keys are unstable under trivially equivalent rewrites, so a
   verdict store built on them neither accumulates nor is safely reusable.
4. **Right-granularity step-up** — prompting on the operation that needs
   authority, not on the whole shell invocation (ADR 0007).
5. **Provenance** — the effect journal is the artifact that makes an agent's run
   auditable after the fact. This is the line's standing thesis pointed at side
   effects instead of at data.
6. **Per-node sub-attenuation** — ADR 0001's long-term direction (give
   `producer` read-only and `consumer` write-only in `producer | consumer`)
   is *only expressible* if something in-process understands the pipeline as a
   structure. `bash -c` cannot be told this.

None of the six is a security claim. All six are why the engine earns its keep.

## File descriptors are already capabilities

An observation absent from our docs that sharpens the L3 design.

Unix is usually described as lacking capabilities. That is not quite right. A
**file descriptor is already an unforgeable, transferable, revocable reference
to a resource**, and passing an fd over a unix socket is capability delegation
in the strict ocap sense. POSIX has had ocap primitives since the beginning.

The defect is that Unix *also* offers ambient authority alongside them:
`open("/etc/shadow")` resolves a string against a global namespace using your
uid, and nobody handed you that authority. Both mechanisms coexist, and the
ambient one dominates because it is the ergonomic default.

This yields a crisp statement of the target property, and it is a *structural*
property rather than a policy check:

> A confined child obtains a resource **only** by inheriting a handle (fd, or a
> preopened directory) — **never** by pathname resolution against an ambient
> root.

Read that way, several things line up:

- It is precisely FreeBSD's **Capsicum** (`cap_enter()` + `openat`-only), and
  approximately what Landlock's path-beneath rules approximate on Linux (ADR
  0011, ADR 0009).
- It explains why I6's canonicalize-with-no-follow-then-test rule is
  load-bearing rather than fussy: any check that resolves a *name* is
  re-deriving authority from the ambient namespace, and the gap between
  check-time and use-time resolution is exactly where the dangling-symlink
  `fs_write` escape lived. A handle, once held, has no such gap — which is the
  whole argument for handles in one sentence.
- It suggests the strongest available formulation of the fs axis is to shrink
  ambient path resolution rather than to filter it — the direction WASI Preview
  2 takes to its conclusion (a component has *no* filesystem until the host
  passes a preopen), and worth evaluating as a future engine under the ADR 0005
  D2 seam.

Not a proposal to implement today. It is the property we should be able to say
we are approximating, and by how much. Concretely, **we do not provide it yet**:
the current `ConfinedCommand` spawn boundary delegates *environment* explicitly
but relies on the platform **CLOEXEC convention** for descriptors — it does not
close ambient file descriptors on spawn, so a descriptor the parent left open
(CLOEXEC cleared) is inherited by the confined child. That is the exact ambient
authority this section argues against, tracked as **agent-bridle#319**; the
target property above is where the spawn boundary should get to, not what it
ships today.

## Open questions

- **What is the minimum effect surface an agent actually needs?** If the honest
  answer is "read these dirs, write this dir, exec these ~40 binaries, one
  egress host," then a large part of the confinement problem dissolves into
  *start with nothing and hand over those*, and per-operation filtering matters
  much less than we assume. This is the quantitative question behind #311.
- **Can the effect journal support deterministic replay**, or only audit? Replay
  is a much stronger claim and needs the journal to capture every nondeterminism
  source, not just effects.
- **What is the stable canonical operation identity** that the verdict store
  keys on? (3) above depends on getting this right, and it is not obviously just
  "resolved argv" once cwd, env, and fd inheritance are in scope.

## References

Extends the ADR 0002 reference list; numbering is local to this document.

1. M. S. Miller, *Robust Composition: Towards a Unified Approach to Access
   Control and Concurrency Control*, PhD thesis, Johns Hopkins University, 2006.
   The primary source for the ocap model, attenuation, revocable forwarders, and
   membranes. (= ADR 0002 ref [2].)
2. N. Hardy, *The Confused Deputy*, ACM SIGOPS OSR 22(4), 1988.
3. **Endo / SES (Hardened JavaScript)**, `github.com/endojs/endo` — the only
   successful ocap *retrofit* onto a mainstream language, and therefore the most
   instructive prior art we have. It works because JS permits freezing the
   primordials and a Compartment has no native-extension escape hatch. Read
   `lockdown()` and the Compartment model.
4. **WASI Preview 2 / the component model** — capability-secure by construction
   via preopens; the endpoint of the fd argument above.
5. R. Watson et al., **Capsicum**, USENIX Security 2010 — capability mode for
   UNIX; the `openat`-only discipline.
6. M. Salaün, **Landlock**, Linux kernel 2021– (= ADR 0002 ref [5]).
7. `github.com/dckc/awesome-ocap` — curated index of ocap languages and systems.

**Negative prior art, read deliberately as such:** Perl's `Safe.pm`/`Opcode`
compartments, Java's `SecurityManager` (removed in JDK 24, JEP 486), Python's
`rexec`/`Bastion` (withdrawn), Node's `vm` module (never a security boundary),
and Deno's flag-based permission grants (coarse, ambient within a grant,
repeatedly bypassed via subprocess and FFI). The common defect is a legibility
or policy layer presented as an enforcement boundary. It is the failure this
document exists to keep us out of.
