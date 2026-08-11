/-
  Contract/counterexample tests for the resolved-authority lattice.

  These pin the security-critical ORIENTATION of `within` against accidental
  reversal (Phase-1 requirement) and exercise the L4/L5/L6 refusal facts on
  concrete `Nat` vectors, so a future edit that flips the order or opens a
  fail-closed axis breaks the build.
-/
import Ceremony.Assurance.AuthorityLattice

namespace Ceremony.Assurance

/-! ### Orientation — the narrower side is `within` the wider, never the reverse -/

/-- The empty fence is within any bound (fully confined is admissible). -/
theorem orientation_empty_within_singleton :
    within (RScope.bounded ([] : List Nat)) (RScope.bounded [0]) := by
  intro x hx; simp at hx

/-- A non-empty fence is NOT within the empty bound (a widening is refused).
    If this ever proved, the order was reversed. -/
theorem orientation_singleton_not_within_empty :
    ¬ within (RScope.bounded [0]) (RScope.bounded ([] : List Nat)) := by
  intro h; have := h 0 (by simp); simp at this

/-- A bounded fence is within Unbounded (the ambient bound accepts anything). -/
theorem orientation_bounded_within_unbounded :
    within (RScope.bounded [0]) (RScope.unbounded : RScope Nat) := by trivial

/-- Unbounded fence is NOT within a bounded bound — permitting everything while
    the grant does not is the OCAP widening this layer exists to catch. -/
theorem orientation_unbounded_not_within_bounded :
    ¬ within (RScope.unbounded : RScope Nat) (RScope.bounded [0]) := by
  intro h; exact h

/-! ### Admit vs refuse, concrete -/

/-- `{0}` admissible against delegated `{0}` ∪ closure `{}`. -/
theorem admissible_within_grant :
    admissible (RScope.bounded [0]) (RScope.bounded [0]) (RScope.bounded ([] : List Nat)) := by
  intro x hx; simpa using hx

/-- `{1}` refused against delegated `{0}` — a resource never granted. -/
theorem refuses_out_of_grant :
    ¬ admissible (RScope.bounded [1]) (RScope.bounded [0]) (RScope.bounded ([] : List Nat)) :=
  widening_refused [1] [0] [] 1 (by simp) (by simp)

/-- L4 concrete: write path `1` ⊄ read `{0}` ⇒ resolved read `{0,1}` refused
    under the exact read bound. -/
theorem windows_write_read_refused_concrete :
    ¬ admissible (RScope.bounded [0, 1]) (RScope.bounded [0]) (RScope.bounded ([] : List Nat)) :=
  windows_unrepresentable_narrowing_rejected [0] [1] 1 (by simp) (by simp)

/-- L6 concrete: an Unknown axis is never admissible. -/
theorem unknown_refused_concrete :
    ¬ admissible (RScope.unknown : RScope Nat) (RScope.bounded [0]) (RScope.bounded [0]) :=
  unknown_never_admissible _ _

end Ceremony.Assurance
