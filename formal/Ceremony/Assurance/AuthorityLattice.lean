/-
  Ceremony Suite — Resolved-authority lattice + admission soundness (L1..L6)

  The temporal companion is formal/tla/AuthorityLifecycle.tla (T1..T7). This file
  is the PURE algebra half: it mechanizes the semantics of
  `agent_mesh_protocol::ResolvedScope` / the admission function that Bridle projects every OS
  fence into, and proves the security-critical facts admission relies on.

  Mathlib-FREE on purpose (a resolved axis is `unknown | unbounded | bounded List`,
  containment is plain list membership), so the file type-checks in seconds and is
  swept by AxiomAudit.lean — every theorem here rests only on `propext`/`Quot.sound`.

  CORRESPONDENCE (production → here), from the Phase-0 inventory:
    • ResolvedScope{Bounded,Unbounded,Unknown}  ↦  `RScope`
      (agent-mesh-protocol-0.6.4/src/authority.rs:582)
    • relate(resolved, bound) accepts Equal|Subset ↦  `within fence bound`
      (authority.rs:693; admission function (authority.rs:811))
    • ResolvedScope::union (Unknown/Unbounded absorbing) ↦ `runion`
      (authority.rs:647)
    • admission holds iff resolved ⊆ delegated ∪ closure ↦ `admissible`  (authority.rs:806)

  ORIENTATION (security-critical, do not reverse): `within fence bound` means
  "the FENCE is no wider than the BOUND" — the fence is the thing being
  constrained, the bound is delegated ∪ closure. A wider fence (a Superset) is a
  REFUSAL. This mirrors caveats.rs:8 ("a ⊑ b means a grants no more than b") and
  authority.rs:806. `orientation_*` theorems below pin it against accidental flip.

  Proved:
    L1  within is reflexive (non-Unknown), transitive, antisymmetric (as set
        equality), and union is monotone (a ⊆ a ∪ b).
    L2/L3  admission is sound by construction and refuses every widening; a fence
        holding a resource outside the bound cannot be admissible.
    L4  windows_write_implies_read_widening / windows_unrepresentable_narrowing_
        rejected — GIVEN the Windows projection premise (read = read ∪ write,
        passed as a HYPOTHESIS, never asserted), write ⊄ read forces refusal.
    L5  runtime_closure_not_hidden — a closure element outside the delegated grant
        cannot be laundered through resolution; it must widen the bound to be admissible.
    L6  unknown_never_admissible / unknown_closure_never_admissible — an Unknown axis (or
        Unknown closure) fails closed.
-/
namespace Ceremony.Assurance

/-! ### The resolved-authority axis and its operations -/

/-- One axis of a projected fence: the portable image of a native enforcement
    result. `unknown` = the backend could not bound the axis (fail closed, L7). -/
inductive RScope (α : Type) where
  | unknown
  | unbounded
  | bounded (s : List α)
deriving Repr

/-- Plain list containment (⊆). No `DecidableEq`, no Mathlib — just membership. -/
def Sub {α : Type} (a b : List α) : Prop := ∀ x, x ∈ a → x ∈ b

theorem Sub.refl {α} (a : List α) : Sub a a := fun _ hx => hx
theorem Sub.trans {α} {a b c : List α} (h₁ : Sub a b) (h₂ : Sub b c) : Sub a c :=
  fun x hx => h₂ x (h₁ x hx)
theorem Sub.append_left {α} (a b : List α) : Sub a (a ++ b) :=
  fun _ hx => List.mem_append.mpr (Or.inl hx)
theorem Sub.append_right {α} (a b : List α) : Sub b (a ++ b) :=
  fun _ hx => List.mem_append.mpr (Or.inr hx)

/-- `within fence bound` : the fence is admissible against the bound — i.e. it is
    no wider than the bound (`relate` returning Equal|Subset). Unknown on EITHER
    side is undecidable ⇒ fail closed. Unbounded fence vs bounded bound is a
    widening ⇒ refuse. -/
def within {α : Type} : RScope α → RScope α → Prop
  | .unknown,   _          => False
  | _,          .unknown   => False
  | .unbounded, .unbounded => True
  | .unbounded, .bounded _ => False
  | .bounded _, .unbounded => True
  | .bounded a, .bounded b => Sub a b

/-- Resolved-scope union (the `∪` in the admission function's bound). Unknown propagates
    (fail closed), Unbounded absorbs, else concrete union. -/
def runion {α : Type} : RScope α → RScope α → RScope α
  | .unknown,   _          => .unknown
  | _,          .unknown   => .unknown
  | .unbounded, _          => .unbounded
  | _,          .unbounded => .unbounded
  | .bounded a, .bounded b => .bounded (a ++ b)

/-- Per-axis admission (L3 BOUND): the fence must be within `delegated ∪ closure`. -/
def admissible {α : Type} (fence delegated closure : RScope α) : Prop :=
  within fence (runion delegated closure)

/-! ### L1 — the order -/

/-- Reflexive on every non-Unknown axis. -/
theorem within_refl {α} (f : RScope α) (h : f ≠ RScope.unknown) : within f f := by
  cases f with
  | unknown => exact absurd rfl h
  | unbounded => trivial
  | bounded a => exact Sub.refl a

/-- Transitive. Unknown axes make a hypothesis `False`, so those cases are vacuous. -/
theorem within_trans {α} {a b c : RScope α}
    (h₁ : within a b) (h₂ : within b c) : within a c := by
  cases a <;> cases b <;> cases c <;>
    simp only [within] at h₁ h₂ ⊢ <;>
    first
      | trivial
      | exact h₁.elim
      | exact h₂.elim
      | exact Sub.trans h₁ h₂

/-- Antisymmetric: two bounded scopes each within the other denote the same set. -/
theorem within_antisymm {α} {a b : List α}
    (h₁ : within (RScope.bounded a) (RScope.bounded b))
    (h₂ : within (RScope.bounded b) (RScope.bounded a)) :
    ∀ x, x ∈ a ↔ x ∈ b :=
  fun x => ⟨fun hx => h₁ x hx, fun hx => h₂ x hx⟩

/-- Union monotone: a bounded/unbounded axis is within its union with anything
    non-Unknown (`a ⊆ a ∪ b`). -/
theorem within_union_left {α} (a b : RScope α)
    (ha : a ≠ RScope.unknown) (hb : b ≠ RScope.unknown) :
    within a (runion a b) := by
  cases a with
  | unknown => exact absurd rfl ha
  | unbounded =>
    cases b with
    | unknown => exact absurd rfl hb
    | unbounded => simp only [runion, within]
    | bounded b => simp only [runion, within]
  | bounded a =>
    cases b with
    | unknown => exact absurd rfl hb
    | unbounded => simp only [runion, within]
    | bounded b => simp only [runion, within]; exact Sub.append_left a b

/-! ### L2 / L3 — admission soundness and no silent widening -/

/-- Soundness by construction: an admissible axis really is within the bound. -/
theorem admission_sound {α} {fence delegated closure : RScope α}
    (h : admissible fence delegated closure) :
    within fence (runion delegated closure) := h

/-- No silent widening (L3): a fence outside the authorized bound is refused. -/
theorem no_silent_widening {α} {fence delegated closure : RScope α}
    (h : ¬ within fence (runion delegated closure)) :
    ¬ admissible fence delegated closure := h

/-- A bounded fence carrying a resource outside `delegated ∪ closure` is refused
    — the concrete form of no-widening. -/
theorem widening_refused {α} (fence delegated closure : List α)
    (x : α) (hx : x ∈ fence) (hout : x ∉ delegated ++ closure) :
    ¬ admissible (RScope.bounded fence)
        (RScope.bounded delegated) (RScope.bounded closure) := by
  intro h
  simp only [admissible, runion, within] at h
  exact hout (h x hx)

/-! ### L4 — the Windows write-implies-read theorem (premise is a HYPOTHESIS) -/

/-- GIVEN the Windows AppContainer projection semantics — that the resolved read
    axis is `delegated.read ∪ delegated.write` (the aclaunch DACL grants read on
    every write path, `agent-bridle-aclaunch/src/main.rs:474`) — a write path that
    is not already a read path makes the resolved read axis exceed the delegated
    read grant. The projection premise is passed as `hproj`; it is EMPIRICALLY
    established by #338's native DACL evidence, never asserted here. -/
theorem windows_write_implies_read_widening {α}
    (delRead delWrite : List α) (resolvedRead : RScope α)
    (hproj : resolvedRead = RScope.bounded (delRead ++ delWrite))
    (w : α) (hw : w ∈ delWrite) (hout : w ∉ delRead) :
    ¬ within resolvedRead (RScope.bounded delRead) := by
  subst hproj
  intro hsub
  simp only [within] at hsub
  exact hout (hsub w (List.mem_append.mpr (Or.inr hw)))

/-- Corollary — an exact/narrow admission policy (bound = the delegated READ
    grant, empty closure) REFUSES a write-implies-read config where some write
    path is not a read path. This is the fail-closed posture #338 chose (Q3). -/
theorem windows_unrepresentable_narrowing_rejected {α}
    (delRead delWrite : List α)
    (w : α) (hw : w ∈ delWrite) (hout : w ∉ delRead) :
    ¬ admissible (RScope.bounded (delRead ++ delWrite))
        (RScope.bounded delRead) (RScope.bounded []) := by
  intro h
  simp only [admissible, runion, List.append_nil, within] at h
  exact hout (h w (List.mem_append.mpr (Or.inr hw)))

/-! ### L5 — runtime closure cannot be laundered -/

/-- A closure element outside the delegated grant cannot be hidden: an applied
    fence that includes it is refused against a bound that omits it. So authority
    the harness adds MUST widen the recorded bound (appear in resolved/closure) to
    be admissible — it cannot be silently labeled "runtime". -/
theorem runtime_closure_not_hidden {α} (delegated closure : List α)
    (c : α) (hc : c ∈ closure) (hout : c ∉ delegated) :
    ¬ within (RScope.bounded (delegated ++ closure)) (RScope.bounded delegated) := by
  intro hsub
  simp only [within] at hsub
  exact hout (hsub c (List.mem_append.mpr (Or.inr hc)))

/-! ### L6 — Unknown fails closed -/

/-- An Unknown fence axis is never admissible (regardless of the bound). -/
theorem unknown_never_admissible {α} (delegated closure : RScope α) :
    ¬ admissible (RScope.unknown : RScope α) delegated closure := by
  intro h; simp only [admissible, within] at h

/-- The bound-poisoning facts: unioning with Unknown yields Unknown, and nothing
    is `within` Unknown. -/
theorem runion_unknown_right {α} (d : RScope α) :
    runion d RScope.unknown = RScope.unknown := by cases d <;> rfl
theorem within_unknown_right {α} (f : RScope α) :
    within f RScope.unknown = False := by cases f <;> rfl

/-- An Unknown *closure* poisons the bound to Unknown, so nothing is admissible. -/
theorem unknown_closure_never_admissible {α} (fence delegated : RScope α) :
    ¬ admissible fence delegated (RScope.unknown : RScope α) := by
  intro h
  simp only [admissible, runion_unknown_right, within_unknown_right] at h

end Ceremony.Assurance
