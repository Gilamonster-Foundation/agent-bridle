/-
  Contract/counterexample tests for the POSIX authority machine.

  These pin the security-critical ORIENTATION of `⊑` and the amplification
  guards against accidental reversal, on concrete `Nat` capability vectors, so a
  future edit that flips the order or opens a guard breaks the build. Mirrors
  Tests/AuthorityLatticeContracts.lean.
-/
import Ceremony.Posix.Machine

namespace Ceremony.Posix

/-! ### Concrete authorities over `Nat` capabilities -/

/-- A grant permitting only capability 0. -/
def only0 : Authority Nat := fun c => c = 0
/-- A grant permitting capabilities 0 and 1. -/
def only01 : Authority Nat := fun c => c = 0 ∨ c = 1

/-! ### Orientation — the narrower grant is `⊑` the wider, never the reverse -/

theorem only0_within_only01 : only0 ⊑ only01 := fun _ h => Or.inl h

/-- If this ever proved, the order was reversed: `{0,1}` is NOT within `{0}`. -/
theorem only01_not_within_only0 : ¬ (only01 ⊑ only0) := by
  intro h
  have h1 : (1 : Nat) = 0 := h 1 (Or.inr rfl)
  exact absurd h1 (by decide)

/-! ### Complete mediation — an out-of-grant operation has NO transition -/

/-- The required authority of the sole operation is exactly capability `c`. -/
def reqConst (c : Nat) : Unit → Unit → Authority Nat := fun _ _ => (fun x => x = c)

/-- With effective grant `{0}`, an operation requiring capability `1` cannot form
    a transition at all — mediation is definitional, not a runtime reject. -/
theorem out_of_grant_op_has_no_transition :
    ¬ ∃ s', transitionOp (reqConst 1) { effective := only0, fds := Authority.bot } () () s' := by
  intro h
  obtain ⟨_, hguard, _⟩ := h
  have h1 : (1 : Nat) = 0 := hguard 1 rfl
  exact absurd h1 (by decide)

/-! ### Namespace non-amplification — even a maximally-permissive resolution -/

/-- Resolving a name that matches EVERY capability still cannot push `fds` past
    the grant: the faithful open intersects the resolution with `effective`. -/
theorem resolve_all_keeps_wf :
    (openName { effective := only01, fds := only0 } (fun _ => True)).wf :=
  namespace_non_amplification _ _ only0_within_only01

/-! ### Descriptor non-amplification — derive stays within the source fd -/

theorem derive_all_stays_within_source :
    (derive { effective := only01, fds := only0 } (fun _ => True)).fds ⊑ only0 :=
  descriptor_non_amplification _ _

/-! ### Descendant attenuation — child bounded by parent; wider child unconstructable -/

theorem spawn_child_attenuates :
    (spawnChild { effective := only01, fds := only01 } only0 only0_within_only01).effective ⊑ only01 :=
  spawnChild_attenuates _ _ _

/-- A child grant wider than the parent has no attenuation witness, so
    `spawnChild` cannot be constructed for it — the structural refusal of
    descendant escalation. -/
theorem no_wider_child_witness : ¬ (only01 ⊑ only0) := only01_not_within_only0

end Ceremony.Posix
