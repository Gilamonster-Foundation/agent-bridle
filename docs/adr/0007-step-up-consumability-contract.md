# ADR 0007 — Step-up consumability contract: fail-closed presence, the no-authenticator fallback, and fresh-per-act semantics

- Status: Accepted (2026-06-29)
- Date: 2026-06-29
- Context: `agent-bridle-core` `step_up` (shipped as code in PR #24, with **no
  ADR** — docs/adr stops at 0006): the `Presence` ladder (step_up.rs:46-58), the
  content-addressed `Challenge` / `ContentId` binding (step_up.rs:88-112,
  157-176), `AttestRequirement` (incl. `freshness_generations`,
  step_up.rs:202-212), `Discharge` / `Attestation` / `DischargeVerifier`
  (step_up.rs:251-336), and the `Gate` entry points `evaluate` /
  `authorize_with_discharge` (gate.rs:170-243). Downstream: the newt-agent OCAP
  facade **P3 (step-up)** — the `[k]ey allow` menu item and the session-start
  ceremony — which will consume this surface.
- **Extends ADR 0002** (the OCAP design contract & hard invariants). Step-up is a
  *third leash outcome* between allow and deny; it adds **no authority** (a
  discharge never widens the grant — `effective` is still `granted.meet(required)`)
  so it cannot break attenuation. This ADR changes **no** existing invariant down
  ADR 0002's status ladder; it ratifies the consumability contract that was
  already implemented but never written down.
- Related issues: **#61** (the `DischargeProvider` seam + orchestration — the
  ceremony side newt implements), **#62** (the production Ed25519
  `DischargeVerifier` behind a cargo feature), **#63** (fresh-per-act: single-use
  discharges + the `freshness_generations` window — the implementer of D4),
  **#64** (external-consumer dependency strategy — how newt depends on this crate).

## Question

PR #24 shipped step-up as code. newt's P3 must build against it — wire `attest`
as `[k]ey allow` and a session-start ceremony — but two contract decisions are
**undocumented**, and newt cannot rely on undocumented behavior:

1. **The no-authenticator fallback (design §10 Q3).** A HIGH-consequence action
   requires `Presence::Passkey`, but the host has no hardware authenticator
   available. What is the gate's contract? Does a soft `Prompt` (or a `None`
   "no gesture achievable") ever satisfy the requirement? Can the gate silently
   downgrade? And can the host even *tell* that the denial was "needs a gesture I
   can't collect" rather than some other refusal?

2. **Freshness / single-use.** newt must require a **fresh step-up per act** for
   HIGH-consequence targets (interpreters, broad fs) — not one gesture amortized
   across a whole session (requirement F6). `AttestRequirement::freshness_generations`
   exists (step_up.rs:209-211) and is *documented* as "Enforced via the Challenge
   generation binding," but newt needs the precise division of labor written down:
   what the **gate** enforces vs. what the **host** must enforce.

This ADR answers both as a contract. It is **design-only**: the seam (#61), the
production verifier (#62), and the fresh-per-act ledger (#63) implement against it.

## Decision

### D1 — Step-up is a liveness condition, never new authority (recap)

A discharge sharpens *when* a Writ may be exercised; it never enlarges *what* the
Writ permits. The gate still mints `effective = granted.meet(required)` on the
step-up path exactly as on the base path (gate.rs:183 in `evaluate`, gate.rs:214
in `authorize_with_discharge`) — the same provably non-amplifying `meet`. The
`Presence` ladder is **totally ordered** `None < Prompt < Passkey`
(step_up.rs:46-58, `derive(PartialOrd, Ord)`); a requirement may only ever *raise*
the demanded presence, so "you can get more restrictive, never less" holds on the
presence axis too. Everything below is a refinement *within* this frame, not a new
trust root.

### D2 — The gate is **fail-closed** on presence and never auto-downgrades

A discharge satisfies a requirement **iff** `discharge.presence >= required.presence`.
Concretely, and as a guarantee newt may rely on:

- A `Prompt`-strength discharge can **never** satisfy a `Passkey` requirement.
- A `None`-strength discharge (the "no authenticator available, no gesture
  achievable" case) can **never** satisfy a `Prompt` *or* a `Passkey` requirement.
- The gate **never silently downgrades** a requirement to fit a weaker discharge.
  There is no code path from "Passkey required, weaker presented" to "allowed."

This is enforced where every `DischargeVerifier` checks presence first
(the rejection precedes any crypto check), and the gate denies on a verifier
`Err` *before* charging or minting (gate.rs:224-229) — a rejected discharge
consumes no call and produces no context. Regression-pinned by
`presence_too_weak_fails_closed` (Prompt vs Passkey) and, added by this issue,
`no_authenticator_presence_none_cannot_satisfy_passkey` (None vs Passkey).

### D3 — The no-authenticator fallback is the **host's** call, surfaced (not hidden) — answers §10 Q3

When a step-up is owed, `Gate::evaluate` returns
`Decision::NeedsDischarge(AttestRequirement)` and mints/charges **nothing**
(step_up.rs:356-365). The requirement is *returned to the host*, carrying
`required.presence`. Therefore:

- The host can read `required.presence` and **distinguish** "this action needs a
  gesture I cannot currently collect (e.g. `Passkey` but no authenticator)" from
  any other denial. The gate does not collapse that distinction into an opaque
  refusal.
- Whether to offer an **advisory `Prompt` fallback** when hardware presence is
  unavailable is a **host (newt) UX decision**, not the gate's. The host may
  choose to refuse, or to collect a soft `Prompt` and proceed under its own,
  explicitly-advisory responsibility.
- Crucially, this is not a hole: if the host collects a `Prompt` and re-presents
  it against a `Passkey` requirement, the gate **still denies** it (D2). A host
  that proceeds on a soft gesture is doing so *outside* the gate's guarantee and
  must own that — the gate never launders a `Prompt` into a satisfied `Passkey`.

So §10 Q3 is decided: **gate fail-closed; the `Prompt` advisory fallback is the
host's call; `Decision::NeedsDischarge` exposes enough (the required `Presence`)
for the host to make that call deliberately.**

### D4 — Freshness & single-use: gate enforces single-use + the window; host owns "HIGH-consequence"

The contract for fresh-per-act (F6) divides as follows. **Implementation lands in
#63**; this ADR ratifies the intended semantics so newt may rely on them:

- **Single-use (gate-enforced).** A verified `Discharge` is **single-use**: the
  gate records each accepted, challenge-bound gesture and refuses a replay of the
  same `(content_id, generation, nonce)` — i.e. the same bound `Challenge`. One
  human gesture authorizes **exactly one** act. (Without this, the same valid
  discharge re-presented twice would mint twice — one tap covering two
  HIGH-consequence acts, the F6 failure.)
- **`freshness_generations` (gate-enforced window).** The field is the
  host-facing amortization window, measured in **causal generations, never
  wall-clock**: `0` ⇒ the discharge must be bound to the **current** generation
  (HIGH-consequence, fresh-per-act); `N > 0` ⇒ a (typically LOW-consequence)
  gesture may be reused for up to `N` generations old. The field must
  *demonstrably affect behavior* — #63 either honors the full window or, if
  deferred, **rejects `N > 0` with an explicit error** rather than silently
  ignoring it (newt must never receive a false amortization guarantee).
- **HIGH-consequence is the host's definition (host-enforced).** The gate does
  not decide which tools are HIGH-consequence, nor when to bump the generation.
  newt expresses fresh-per-act by authoring `freshness_generations: 0` on its
  HIGH-consequence selectors **and** bumping the gate generation per act, so each
  act is a distinct `Challenge` and each requires its own gesture.

### D5 — The consumability contract: what the gate enforces vs. what the host must enforce

The single table newt builds against. The **gate** (pure, synchronous, no IO):

- mints only `effective = granted.meet(required)` — non-amplification (D1);
- enforces the presence floor, fail-closed, no auto-downgrade (D2);
- re-derives the bound `Challenge` itself and rejects a discharge that answers a
  different action/generation/nonce — what-you-see-is-what-you-sign anti-theater
  (gate.rs:223, `wrong_challenge_is_denied`); it trusts neither the provider nor
  the verifier to self-attest the binding;
- enforces single-use and the `freshness_generations` window (D4, via #63);
- never performs the gesture and never calls a `DischargeProvider`.

The **host** (newt — capabilities, IO, policy):

- runs the ceremony via the `DischargeProvider` seam (#61) and supplies the
  single-use `nonce`;
- supplies a `DischargeVerifier` (the Ed25519 one, #62, or a richer WebAuthn one
  later) — but the gate re-checks presence and challenge regardless of what the
  verifier reports;
- authors the `StepUpPolicy` (presence per selector), defines HIGH-consequence,
  and chooses the generation-bump cadence (D4);
- decides whether to offer the advisory `Prompt` fallback when hardware presence
  is unavailable (D3);
- records the returned `Attestation` as a Scar in its causal log.

## Consequences

- **newt's P3 becomes buildable against a written contract.** The seam (#61),
  verifier (#62), and fresh-per-act (#63) issues each cite and implement a clause
  here; #64 makes the surface dependable out-of-tree.
- **No invariant moves down the ladder.** Step-up remains additive over ADR 0002;
  the gate stays the single mint site, and the third outcome cannot widen a grant.
- **The fail-closed default is the safe one.** A missing authenticator, a
  too-weak gesture, a mismatched challenge, or a replay all land on *denial*, not
  on a silent allow. The only way a soft gesture ever "passes" is a host that
  deliberately steps outside the gate's guarantee (D3) — and it cannot do so by
  fooling the gate.
- **`freshness_generations` stops being dead.** #63 makes it affect behavior or
  reject the unsupported case; either way newt gets a truthful guarantee.

## Alternatives considered

- **Let a `Prompt` satisfy a `Passkey` when no authenticator exists (auto-downgrade).**
  Rejected: it makes the strongest requirement silently the weakest exactly when
  the stakes are highest, and hides the downgrade from the policy author. The
  advisory path is legitimate only as an *explicit host choice* the gate never
  blesses (D3).
- **Hide the requirement, return an opaque deny.** Rejected: the host could not
  distinguish "needs a gesture I can't collect" from other refusals and so could
  not offer a sensible fallback or a useful message. `Decision::NeedsDischarge`
  carrying `required.presence` is the deliberate seam.
- **Wall-clock freshness.** Rejected: the design is causal-generation-only
  (step_up.rs:208-211 says so); clocks are not a sound liveness coordinate here.
- **Session-amortized one gesture.** Rejected for HIGH-consequence (F6): one tap
  must not cover many acts. Single-use + `freshness_generations: 0` is the
  fresh-per-act mechanism (D4).

## Follow-ups

- **#61** — `DischargeProvider` host-capability seam + `evaluate→obtain→authorize`
  orchestration (the ceremony side; the dual of `DischargeVerifier`).
- **#62** — production `Ed25519Verifier` behind an off-by-default cargo feature.
- **#63** — the implementer of D4: single-use discharge ledger + the
  `freshness_generations` window (or an explicit unsupported-`N` error).
- **#64** — external-consumer dependency strategy so newt can depend on the
  finished, stable step-up surface.
