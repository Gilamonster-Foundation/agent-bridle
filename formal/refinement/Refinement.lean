-- Refinement proofs: the Authority.lean algebraic laws, discharged on the
-- EXTRACTED (Charon/Aeneas) implementation of `agent-bridle-ceremony`. Same
-- laws as formal/Ceremony/P0/Authority.lean, now on the actual Rust as
-- extracted — the Tier-3 refinement bridge, machine-checked.
--
-- The meet-order is stated as Authority.lean defines it: `a ≤ b  ↔  a ⊓ b = a`.
-- So attenuation is the absorption identity `(a⊓c) ⊓ a = a⊓c`, pure `meet`.
--
-- `resolve` is intentionally absent: its extraction goes through the opaque
-- axioms `core.slice.iter.Iter...fold` / `split_first` (Aeneas axiomatizes slice
-- iterators), so it does not reduce. Making it provable means rewriting `resolve`
-- as explicit recursion in the Rust kernel (tracked follow-up).
import AgentBridleCeremony.Funs
open Aeneas Aeneas.Std Result
open agent_bridle_ceremony

namespace CeremonyRefinement

-- ── axis meet: commutative, idempotent ──
theorem effect_meet_comm (a b : authority.Effect) :
    authority.Effect.meet a b = authority.Effect.meet b a := by cases a <;> cases b <;> rfl
theorem assurance_meet_comm (a b : authority.Assurance) :
    authority.Assurance.meet a b = authority.Assurance.meet b a := by cases a <;> cases b <;> rfl
theorem scope_meet_comm (a b : authority.Scope) :
    authority.Scope.meet a b = authority.Scope.meet b a := by cases a <;> cases b <;> rfl
theorem effect_meet_idem (a : authority.Effect) : authority.Effect.meet a a = ok a := by cases a <;> rfl
theorem assurance_meet_idem (a : authority.Assurance) : authority.Assurance.meet a a = ok a := by cases a <;> rfl
theorem scope_meet_idem (a : authority.Scope) : authority.Scope.meet a a = ok a := by cases a <;> rfl

-- ── product meet: commutative (L1 carrier), idempotent ──
theorem authority_meet_comm (a b : authority.Authority) :
    authority.Authority.meet a b = authority.Authority.meet b a := by
  obtain ⟨e1, a1, s1⟩ := a; obtain ⟨e2, a2, s2⟩ := b
  cases e1 <;> cases a1 <;> cases s1 <;> cases e2 <;> cases a2 <;> cases s2 <;> rfl
theorem authority_meet_idem (a : authority.Authority) : authority.Authority.meet a a = ok a := by
  obtain ⟨e, av, s⟩ := a; cases e <;> cases av <;> cases s <;> rfl

-- ── attenuation (L4 / PO-4): the meet is ≤ each input — never amplifies.
-- `x ≤ y  ↔  x ⊓ y = x`, so this is absorption: (a⊓c) ⊓ a = a⊓c, (a⊓c) ⊓ c = a⊓c. ──
theorem attenuate_le_input (a c : authority.Authority) :
    (do let m ← authority.Authority.meet a c; authority.Authority.meet m a)
      = authority.Authority.meet a c := by
  obtain ⟨e1, a1, s1⟩ := a; obtain ⟨e2, a2, s2⟩ := c
  cases e1 <;> cases a1 <;> cases s1 <;> cases e2 <;> cases a2 <;> cases s2 <;> rfl
theorem attenuate_le_ceiling (a c : authority.Authority) :
    (do let m ← authority.Authority.meet a c; authority.Authority.meet m c)
      = authority.Authority.meet a c := by
  obtain ⟨e1, a1, s1⟩ := a; obtain ⟨e2, a2, s2⟩ := c
  cases e1 <;> cases a1 <;> cases s1 <;> cases e2 <;> cases a2 <;> cases s2 <;> rfl

-- ── attenuate is exactly meet (the extracted definition) ──
theorem attenuate_is_meet (a c : authority.Authority) :
    authority.Authority.attenuate a c = authority.Authority.meet a c := by rfl

-- ── resolve: now PROVABLE. `resolve` was rewritten from `iter().fold` (which
-- extracts to Aeneas's opaque slice-iterator axioms) to explicit index
-- recursion, so it extracts to a real function and the laws below reduce. ──

/-- **No fail-open (OB-9 / OB-12).** An EMPTY candidate set resolves to
    `NeedsDecision`, never `Decided ⊤`. The safety-critical law — unprovable when
    `resolve` used `iter().fold`; now discharged on the extracted `resolve`. -/
theorem resolve_empty :
    authority.resolve (Slice.new authority.Authority)
      = ok authority.Resolution.NeedsDecision := by
  simp [authority.resolve, core.slice.Slice.is_empty, Slice.new, Slice.length]

/-- Bounded correctness: a single candidate resolves to itself (`meet_from`
    returns in one step, no recursion). -/
theorem resolve_singleton (a : authority.Authority) :
    authority.resolve ⟨[a], by scalar_tac⟩ = ok (authority.Resolution.Decided a) := by
  simp [authority.resolve, authority.meet_from, core.slice.Slice.is_empty,
        Slice.length, Slice.index_usize, Slice.len]

-- FOLLOW-UP (ROADMAP 1c): correctness through the *recursion* (length ≥ 2) and
-- the general order-independence (L1) over arbitrary-length inputs need
-- controlled unfolding of `meet_from` — its `partial_fixpoint` equation loops
-- the default `simp`. The general L1 result is already exhaustively covered by
-- the Rust unit tests (`resolve_is_order_independent`); porting it to Lean is a
-- meet_from-induction proof left as follow-up. The *safety* law (no fail-open)
-- is fully proven above.

end CeremonyRefinement
