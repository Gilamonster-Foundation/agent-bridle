/-
  Ceremony Suite — Enforcement boundary & the two-stream composition (P0)

  Mechanizes the "OCAP two-stream sequencing" decision
  (knowledge/board/2026-07-16_ocap-two-streams-sequencing-DECIDED.md) AGAINST
  the frozen algebra of `Authority.lean`. It exists to answer one question with
  a proof rather than prose:

    Does deciding "brush-first / ceremony-in-parallel, L3-gated brush default,
    fall back to safe-subset when no fence" VIOLATE the ratified v0.3.1 spec?

  The load-bearing sub-decision under test (verbatim from the board note):

    "Brush is the confined default WHERE an L3 fence is actively enforcing;
     fall back to safe-subset's structural refusal when L3 is unavailable."

  RESULT (what the theorems below establish):
    • The L3-gate is NOT a new law and NOT a fourth Authority axis. It is the
      existing `Effect` meet, driven by an *enforceable ceiling* the active
      fence supplies (ADR 0002 I9/I10 "never overclaim"; only L3 sees inside a
      spawned binary). `boundaryVerdict = attenuate desired (fence ceiling)`.
    • The safe-subset fallback is FORCED, not a bolt-on policy: it is exactly
      what the honest (non-overclaiming) brush verdict reduces to under
      `advisory` (`fallback_is_forced`).
    • Stream A (brush enforces `Caveats`) and Stream B (ceremony proves
      `Authority`) COMPOSE: projection to the enforced carrier is a meet-
      homomorphism (`proj_effect_meet`) — the ADR 0020 D7 "siblings, not two
      competing models" claim, mechanized. So enforcement can never grant above
      what the authority algebra permits; layered-parallel converges.

  It imports only `Ceremony.P0.Authority` and introduces no new operation over
  it. That IS the confirmation: the sequencing is *inside* the frozen system.

  The temporal half — a fence that DROPS between grant and exec must not fail
  open (spec I4, "checked at the moment it executes") — is modeled separately
  in `formal/tla/EnforcementGate.tla`.
-/
import Ceremony.P0.Authority
namespace Ceremony.P0

/-! ### The enforcement fence — ADR 0002 I9/I10 `sandbox_kind`, NOT a new axis

`Fence` is *enforcement strength* (is a kernel L3 fence active right now?), a
distinct concept from the `Assurance` axis (how strongly the human is present).
It is deliberately NOT lifted into `Authority` as a fourth coordinate: it does
not decide *what/how-present/how-long*; it bounds only *what the boundary can
faithfully enforce*, which lands on `Effect` via the meet below. -/
inductive Fence
  | advisory   -- NoopSandbox: L1/L2 cannot see inside a spawned binary (I10)
  | kernel     -- Landlock / seatbelt / AppContainer actively confining
deriving DecidableEq, Repr

/-- A shell request, abstracted to the one bit the decision turns on: does it
    use dynamic constructs (`$(…)`, pipes, `eval`) whose containment only a
    kernel fence can provide? `dynamic = false` is structurally safe. -/
structure Request where
  dynamic : Bool
deriving DecidableEq, Repr

/-! ### The two engines -/

/-- safe-subset engine: STRUCTURAL refusal of dynamic constructs — least
    authority by construction, fence-independent (it never runs `$(…)`). -/
def safeSubset (q : Request) : Effect :=
  if q.dynamic then .deny else .allow

/-- brush engine, stated as its *honest* verdict (ADR 0002 I9: never report an
    advisory run as confined). Under `kernel` the op is confined ⇒ honest
    `allow`. Under `advisory` a dynamic op cannot be confined, so running it and
    calling it confined would OVERCLAIM ⇒ the honest verdict is `deny`
    (fail-closed, I5/L3); a static op is structurally safe regardless. -/
def brushHonest (f : Fence) (q : Request) : Effect :=
  match f, q.dynamic with
  | .kernel,   _     => .allow
  | .advisory, true  => .deny
  | .advisory, false => .allow

/-- The DECIDED rule: brush is the default WHERE a kernel fence enforces; else
    fall back to safe-subset's structural refusal. -/
def boundaryVerdict (f : Fence) (q : Request) : Effect :=
  match f with
  | .kernel   => brushHonest .kernel q
  | .advisory => safeSubset q

/-! ### The board decision is exactly the honest brush verdict -/

/-- **The safe-subset fallback is FORCED, not bolted on.** Under `advisory`, the
    honest brush verdict *is* safe-subset's — so "fall back to safe-subset when
    L3 is unavailable" is derived from the no-overclaim rule (I9), not an
    independent policy knob. -/
theorem fallback_is_forced (q : Request) :
    brushHonest .advisory q = safeSubset q := by
  rcases q with ⟨d⟩; cases d <;> rfl

/-- The DECIDED rule and the honest brush verdict are the same function; the
    "default + fallback" phrasing is one thing, not two. -/
theorem boundaryVerdict_eq_honest (f : Fence) (q : Request) :
    boundaryVerdict f q = brushHonest f q := by
  cases f
  · exact (fallback_is_forced q).symm   -- advisory: safeSubset = brushHonest advisory
  · rfl                                  -- kernel: definitional

/-! ### It is an attenuation in the FROZEN algebra — no new operation

The user's desired effect is `allow` (they want to run the command). `allow` is
the top of `Effect`, so meeting the desired effect with the fence's enforceable
ceiling recovers exactly the verdict: the decision is `Effect.meet`, nothing
new. -/

/-- the enforceable-effect ceiling the fence supplies for this request. -/
def enforceableCeiling (f : Fence) (q : Request) : Effect := boundaryVerdict f q

theorem allow_is_effect_top (e : Effect) : Effect.meet .allow e = e := by
  cases e <;> rfl

/-- **The boundary decision is a meet.** It attenuates the desired `allow` by
    the fence's enforceable ceiling — the frozen `Effect.meet`, no bespoke op. -/
theorem boundaryVerdict_is_attenuation (f : Fence) (q : Request) :
    boundaryVerdict f q = Effect.meet .allow (enforceableCeiling f q) := by
  simp only [enforceableCeiling, allow_is_effect_top]

/-! ### Lifted to `Authority`: the fence bounds ONLY `Effect`

The boundary ceiling is `⊤` on Assurance and Scope (the fence says nothing about
human presence or duration) and the enforceable effect on `Effect`. Minting a
grant is `attenuate request boundaryCeiling` — the frozen product meet. -/

/-- the fence ceiling as an `Authority`: enforceable on `Effect`, `⊤` elsewhere. -/
def boundaryCeiling (f : Fence) (q : Request) : Authority :=
  ⟨boundaryVerdict f q, .hardware, .durable⟩

/-- what the gate actually mints: the request attenuated by the fence ceiling. -/
def mintedGrant (req : Authority) (f : Fence) (q : Request) : Authority :=
  attenuate req (boundaryCeiling f q)

/-- **Never more than requested** — a direct corollary of `meet_le_left`. -/
theorem minted_le_request (req : Authority) (f : Fence) (q : Request) :
    mintedGrant req f q ≤ᴬ req :=
  meet_le_left req (boundaryCeiling f q)

/-- **Never above what the fence can enforce (I9, in the product).** The minted
    authority is ⊑ the boundary ceiling on every axis — a corollary of
    `meet_le_right`. An advisory boundary therefore cannot mint an
    effect its fence would only *advise*. -/
theorem minted_le_enforceable (req : Authority) (f : Fence) (q : Request) :
    mintedGrant req f q ≤ᴬ boundaryCeiling f q :=
  meet_le_right req (boundaryCeiling f q)

/-- **Fail-closed on the unenforceable case (L3/I5).** A containment-needing
    request under no kernel fence mints `deny` on the effect axis — the exact
    structural refusal safe-subset gives, reached here through the meet, for
    ANY request ceiling. This is the honesty guarantee the L3-gate rests on. -/
theorem advisory_dynamic_grant_is_deny (req : Authority) (q : Request)
    (h : q.dynamic = true) :
    (mintedGrant req .advisory q).effect = Effect.deny := by
  rcases req with ⟨e, a, s⟩
  simp only [mintedGrant, attenuate, boundaryCeiling, boundaryVerdict, safeSubset,
             h, Authority.meet, Effect.meet]
  cases e <;> rfl

/-! ### The two streams compose — projection is a meet-homomorphism (ADR 0020 D7)

Stream A enforces the effect carrier (`Caveats`, ADR 0002 — bridle *depends on*
it and MUST NOT reinvent it, I3). Stream B proves `Authority`. The projection
`Authority.effect` carries the product meet to the axis meet definitionally, so
whenever ceremony attenuates authority, the effect brush enforces attenuates in
lockstep. Layered-parallel converges: enforcement is the ⊓-image of the proof,
never a divergent second model. -/

/-- **The convergence theorem.** Projection to the enforced carrier commutes
    with the meet: `(a ⊓ b).effect = a.effect ⊓ b.effect`. Stream B's
    attenuation, projected onto what Stream A enforces, *is* Stream A's
    attenuation. -/
theorem proj_effect_meet (a b : Authority) :
    (a ⊓ b).effect = Effect.meet a.effect b.effect := rfl

/-- Same homomorphism on the other two axes — the product really is
    coordinatewise, so no axis can smuggle in amplification. -/
theorem proj_assurance_meet (a b : Authority) :
    (a ⊓ b).assurance = Assurance.meet a.assurance b.assurance := rfl
theorem proj_scope_meet (a b : Authority) :
    (a ⊓ b).scope = Scope.meet a.scope b.scope := rfl

/-! ### Summary the gate can quote

`boundaryVerdict = attenuate allow (fence ceiling)` (frozen meet), the fallback
is forced by I9, minting never exceeds request or enforceable ceiling, dynamic-
under-advisory fails closed, and enforcement is the meet-homomorphic image of
the proven authority. No new law; no fourth axis. The sequencing lives INSIDE
the v0.3.1 freeze. -/

end Ceremony.P0
