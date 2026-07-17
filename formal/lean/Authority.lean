/-
  Ceremony Suite — Authority algebra (mechanized core of P0 §2.0 + laws L1/L4)

  Mathlib-FREE on purpose: each axis is a tiny finite chain, so the axis meet
  laws are `decide`-checked and the product laws follow componentwise. The
  file type-checks in seconds with `lean Authority.lean` — no Mathlib build.

  Proved (Tier-3, the algebra half of the v0.3.1 freeze):
    • each axis is a chain with a genuine meet (comm / assoc / idem);
    • Authority = Effect × Assurance × Scope; meet is componentwise;
    • attenuation: `a ⊓ c ≤ a` and `≤ c`   (L4 / PO-4 — never amplifies);
    • resolution is order-independent under adjacent transposition — the
      generating step of any permutation (L1 / PO-1);
    • no fail-open: `resolve [] = NeedsDecision`, never ⊤/approve (OB-9/OB-12).

  The append/rollback state machine (P2, PO-2*) is modeled separately in TLA+.
-/
namespace Ceremony

/-! ### Axes — finite chains; `deny/none/once` is ⊥ -/
inductive Effect | deny | allow deriving DecidableEq, Repr
inductive Assurance | none | presence | hardware deriving DecidableEq, Repr
inductive Scope | once | session | durable deriving DecidableEq, Repr

def Effect.rank : Effect → Nat | .deny => 0 | .allow => 1
def Assurance.rank : Assurance → Nat | .none => 0 | .presence => 1 | .hardware => 2
def Scope.rank : Scope → Nat | .once => 0 | .session => 1 | .durable => 2

def Effect.meet (a b : Effect) : Effect := if a.rank ≤ b.rank then a else b
def Assurance.meet (a b : Assurance) : Assurance := if a.rank ≤ b.rank then a else b
def Scope.meet (a b : Scope) : Scope := if a.rank ≤ b.rank then a else b

/-- axis laws — concrete after `cases`, closed by `decide`. -/
theorem Effect.meet_comm (a b : Effect) : a.meet b = b.meet a := by cases a <;> cases b <;> decide
theorem Effect.meet_assoc (a b c : Effect) : (a.meet b).meet c = a.meet (b.meet c) := by
  cases a <;> cases b <;> cases c <;> decide
theorem Effect.meet_idem (a : Effect) : a.meet a = a := by cases a <;> decide
theorem Effect.absorbL (a b : Effect) : (a.meet b).meet a = a.meet b := by cases a <;> cases b <;> decide
theorem Effect.absorbR (a b : Effect) : (a.meet b).meet b = a.meet b := by cases a <;> cases b <;> decide

theorem Assurance.meet_comm (a b : Assurance) : a.meet b = b.meet a := by cases a <;> cases b <;> decide
theorem Assurance.meet_assoc (a b c : Assurance) : (a.meet b).meet c = a.meet (b.meet c) := by
  cases a <;> cases b <;> cases c <;> decide
theorem Assurance.meet_idem (a : Assurance) : a.meet a = a := by cases a <;> decide
theorem Assurance.absorbL (a b : Assurance) : (a.meet b).meet a = a.meet b := by cases a <;> cases b <;> decide
theorem Assurance.absorbR (a b : Assurance) : (a.meet b).meet b = a.meet b := by cases a <;> cases b <;> decide

theorem Scope.meet_comm (a b : Scope) : a.meet b = b.meet a := by cases a <;> cases b <;> decide
theorem Scope.meet_assoc (a b c : Scope) : (a.meet b).meet c = a.meet (b.meet c) := by
  cases a <;> cases b <;> cases c <;> decide
theorem Scope.meet_idem (a : Scope) : a.meet a = a := by cases a <;> decide
theorem Scope.absorbL (a b : Scope) : (a.meet b).meet a = a.meet b := by cases a <;> cases b <;> decide
theorem Scope.absorbR (a b : Scope) : (a.meet b).meet b = a.meet b := by cases a <;> cases b <;> decide

/-! ### Authority = the product lattice -/
structure Authority where
  effect : Effect
  assurance : Assurance
  scope : Scope
deriving DecidableEq, Repr

/-- ⊥ = (deny, none, once): the single denied authority. -/
def Authority.bot : Authority := ⟨.deny, .none, .once⟩

def Authority.meet (a b : Authority) : Authority :=
  ⟨a.effect.meet b.effect, a.assurance.meet b.assurance, a.scope.meet b.scope⟩
infixl:70 " ⊓ " => Authority.meet

/-- the meet-induced order: `a ≤ b  ↔  a ⊓ b = a`. -/
def Authority.le (a b : Authority) : Prop := a ⊓ b = a
infix:50 " ≤ᴬ " => Authority.le

/-! ### Product meet laws — componentwise from the axis laws -/
theorem meet_comm (a b : Authority) : a ⊓ b = b ⊓ a := by
  obtain ⟨ae, aa, asc⟩ := a; obtain ⟨be, ba, bsc⟩ := b
  simp only [Authority.meet, Effect.meet_comm ae be, Assurance.meet_comm aa ba, Scope.meet_comm asc bsc]

theorem meet_assoc (a b c : Authority) : (a ⊓ b) ⊓ c = a ⊓ (b ⊓ c) := by
  obtain ⟨ae, aa, asc⟩ := a; obtain ⟨be, ba, bsc⟩ := b; obtain ⟨ce, ca, csc⟩ := c
  simp only [Authority.meet, Effect.meet_assoc, Assurance.meet_assoc, Scope.meet_assoc]

theorem meet_idem (a : Authority) : a ⊓ a = a := by
  obtain ⟨ae, aa, asc⟩ := a
  simp only [Authority.meet, Effect.meet_idem, Assurance.meet_idem, Scope.meet_idem]

/-! ### Attenuation (L4 / PO-4): meet is contractive on both inputs — never amplifies -/
theorem meet_le_left (a c : Authority) : (a ⊓ c) ≤ᴬ a := by
  obtain ⟨ae, aa, asc⟩ := a; obtain ⟨ce, ca, csc⟩ := c
  simp only [Authority.le, Authority.meet, Effect.absorbL, Assurance.absorbL, Scope.absorbL]

theorem meet_le_right (a c : Authority) : (a ⊓ c) ≤ᴬ c := by
  obtain ⟨ae, aa, asc⟩ := a; obtain ⟨ce, ca, csc⟩ := c
  simp only [Authority.le, Authority.meet, Effect.absorbR, Assurance.absorbR, Scope.absorbR]

/-- passing authority `a` through a ceiling `c` never exceeds either (L4). -/
def attenuate (a c : Authority) : Authority := a ⊓ c
theorem attenuate_le_input (a c : Authority) : attenuate a c ≤ᴬ a := meet_le_left a c
theorem attenuate_le_ceiling (a c : Authority) : attenuate a c ≤ᴬ c := meet_le_right a c
/-- sequential ceilings collapse to one meet — order of independent ceilings is irrelevant. -/
theorem attenuate_compose (a c d : Authority) : attenuate (attenuate a c) d = attenuate a (c ⊓ d) :=
  meet_assoc a c d

/-! ### Resolution (L1) — `ask` is NOT an authority level -/
inductive Resolution
  | NeedsDecision            -- was `ask`: control flow; headless ↦ deny
  | Decided (a : Authority)
deriving DecidableEq, Repr

/-- resolve matching rules by meet; empty match ⇒ NeedsDecision (NOT ⊤/approve;
    the no-fail-open clause, OB-9/OB-12). -/
def resolve : List Authority → Resolution
  | []      => .NeedsDecision
  | x :: xs => .Decided (xs.foldl Authority.meet x)

/-- **No fail-open.** An unmatched request never resolves to authority. -/
theorem resolve_empty : resolve [] = Resolution.NeedsDecision := rfl

/-- **Order-independence, generating step (PO-1).** Swapping two adjacent
    matched rules leaves the resolved authority unchanged; a full permutation is
    a composition of adjacent swaps, so resolution is independent of rule / file
    / load order. -/
theorem resolve_swap (x y : Authority) (xs : List Authority) :
    resolve (x :: y :: xs) = resolve (y :: x :: xs) := by
  simp only [resolve, List.foldl, meet_comm x y]

end Ceremony
