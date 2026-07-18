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

-- `native_decide` on the (computable) P1 allowlist needs `DecidableEq` for the
-- goal's `Result (Option Allowed…)`. Aeneas's `Error`/`Result` and the extracted
-- signed-object enums/witnesses only `deriving BEq`, so derive the `DecidableEq`
-- chain here (all are plain inductives / single-field structs).
deriving instance DecidableEq for Aeneas.Std.Error
deriving instance DecidableEq for Aeneas.Std.Result
deriving instance DecidableEq for signed_object.HashAlgorithm
deriving instance DecidableEq for signed_object.SignatureAlgorithm
deriving instance DecidableEq for signed_object.Codec
deriving instance DecidableEq for signed_object.AllowedHash
deriving instance DecidableEq for signed_object.AllowedSignature
deriving instance DecidableEq for signed_object.AllowedCodec

-- For the value-exhaustive resolve order-independence (L1): `native_decide` on a
-- `∀ x y z : Authority, …` needs `DecidableEq` + `Fintype` over the finite
-- Authority domain. Lean has no `Fintype` deriving handler, so build it by hand:
-- the axis enums enumerate directly, and the product via `Fintype.ofEquiv`.
deriving instance DecidableEq for authority.Effect
deriving instance DecidableEq for authority.Assurance
deriving instance DecidableEq for authority.Scope
deriving instance DecidableEq for authority.Authority
deriving instance DecidableEq for authority.Resolution

instance : Fintype authority.Effect :=
  ⟨{authority.Effect.Deny, authority.Effect.Allow}, fun x => by cases x <;> decide⟩
instance : Fintype authority.Assurance :=
  ⟨{authority.Assurance.None, authority.Assurance.Presence, authority.Assurance.Hardware},
   fun x => by cases x <;> decide⟩
instance : Fintype authority.Scope :=
  ⟨{authority.Scope.Once, authority.Scope.Session, authority.Scope.Durable},
   fun x => by cases x <;> decide⟩
instance : Fintype authority.Authority :=
  Fintype.ofEquiv (authority.Effect × authority.Assurance × authority.Scope)
    { toFun := fun p => ⟨p.1, p.2.1, p.2.2⟩
      invFun := fun a => (a.effect, a.assurance, a.scope)
      left_inv := fun _ => rfl
      right_inv := fun _ => rfl }

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

/-- **Order-independence (L1), value-exhaustive at length 3.** For EVERY triple
    of authorities, resolving a list and its adjacent-swap resolve identically,
    on the extracted `resolve` (which runs `meet_from` over the slice). Proven by
    `native_decide` over the whole finite `Authority³` domain — the extracted-code
    analogue of the Rust `resolve_is_order_independent` test. -/
theorem resolve_swap_len3_exhaustive :
    ∀ x y z : authority.Authority,
      authority.resolve ⟨[x, y, z], by scalar_tac⟩
        = authority.resolve ⟨[y, x, z], by scalar_tac⟩ := by
  native_decide

/-- The other adjacent transposition (positions 1,2). Together with the swap
    above, these generate all of `S₃`, so `resolve` is FULLY order-independent
    at length 3 — every permutation resolves identically, for every triple. -/
theorem resolve_swap_len3_last_two_exhaustive :
    ∀ x y z : authority.Authority,
      authority.resolve ⟨[x, y, z], by scalar_tac⟩
        = authority.resolve ⟨[x, z, y], by scalar_tac⟩ := by
  native_decide

-- ══ GENERAL order-independence (L1), arbitrary length ══
-- Strategy: characterize the extracted `meet_from` as a pure left-fold of a
-- pure `pmeet` (via `dspec_induction` over its `partial_fixpoint`), then get
-- permutation-invariance from `pmeet` being commutative + associative.

/-! A pure meet mirroring the extracted (monadic) `authority.Authority.meet`,
    with the bottom of each axis absorbing. -/
def pmeetE : authority.Effect → authority.Effect → authority.Effect
  | .Deny, _ => .Deny
  | .Allow, b => b
def pmeetA : authority.Assurance → authority.Assurance → authority.Assurance
  | .None, _ => .None
  | .Presence, .None => .None
  | .Presence, .Presence => .Presence
  | .Presence, .Hardware => .Presence
  | .Hardware, b => b
def pmeetS : authority.Scope → authority.Scope → authority.Scope
  | .Once, _ => .Once
  | .Session, .Once => .Once
  | .Session, .Session => .Session
  | .Session, .Durable => .Session
  | .Durable, b => b
def pmeet (a b : authority.Authority) : authority.Authority :=
  ⟨pmeetE a.effect b.effect, pmeetA a.assurance b.assurance, pmeetS a.scope b.scope⟩

theorem effmeet_eq (a b : authority.Effect) :
    authority.Effect.meet a b = ok (pmeetE a b) := by cases a <;> cases b <;> rfl
theorem assmeet_eq (a b : authority.Assurance) :
    authority.Assurance.meet a b = ok (pmeetA a b) := by cases a <;> cases b <;> rfl
theorem scomeet_eq (a b : authority.Scope) :
    authority.Scope.meet a b = ok (pmeetS a b) := by cases a <;> cases b <;> rfl

theorem meet_eq_pmeet (a b : authority.Authority) :
    authority.Authority.meet a b = ok (pmeet a b) := by
  obtain ⟨ae, aa, az⟩ := a; obtain ⟨be, ba, bz⟩ := b
  cases ae <;> cases aa <;> cases az <;> cases be <;> cases ba <;> cases bz <;> rfl

theorem pmeetE_comm (a b) : pmeetE a b = pmeetE b a := by cases a <;> cases b <;> rfl
theorem pmeetA_comm (a b) : pmeetA a b = pmeetA b a := by cases a <;> cases b <;> rfl
theorem pmeetS_comm (a b) : pmeetS a b = pmeetS b a := by cases a <;> cases b <;> rfl
theorem pmeetE_assoc (a b c) : pmeetE (pmeetE a b) c = pmeetE a (pmeetE b c) := by
  cases a <;> cases b <;> cases c <;> rfl
theorem pmeetA_assoc (a b c) : pmeetA (pmeetA a b) c = pmeetA a (pmeetA b c) := by
  cases a <;> cases b <;> cases c <;> rfl
theorem pmeetS_assoc (a b c) : pmeetS (pmeetS a b) c = pmeetS a (pmeetS b c) := by
  cases a <;> cases b <;> cases c <;> rfl

theorem pmeet_comm (a b : authority.Authority) : pmeet a b = pmeet b a := by
  simp only [pmeet, pmeetE_comm a.effect, pmeetA_comm a.assurance, pmeetS_comm a.scope]
theorem pmeet_assoc (a b c : authority.Authority) :
    pmeet (pmeet a b) c = pmeet a (pmeet b c) := by
  simp only [pmeet, pmeetE_assoc, pmeetA_assoc, pmeetS_assoc]
-- left-commutativity: the swap that, with assoc, gives full permutation-invariance.
theorem pmeet_left_comm (a b c : authority.Authority) :
    pmeet a (pmeet b c) = pmeet b (pmeet a c) := by
  rw [← pmeet_assoc, pmeet_comm a b, pmeet_assoc]

/-- **The load-bearing characterization.** The extracted `meet_from` (a
    `partial_fixpoint` tail-recursion) TOTALLY equals a pure left-fold of `pmeet`
    over the suffix `cs[start..]`. Proven by well-founded recursion on the
    measure `len - start` (Aeneas gives an unfolding equation but no termination;
    this supplies it). Gives the *value*, not just partial correctness. -/
theorem meet_from_eq_foldl (cs : Slice authority.Authority) (start : Std.Usize)
    (acc : authority.Authority) :
    authority.meet_from cs start acc
      = ok (List.foldl pmeet acc (cs.val.drop start.val)) := by
  rw [authority.meet_from]
  simp only [Slice.len]
  split
  · -- start ≥ len: the suffix is empty, fold returns acc.
    rename_i hge
    have : cs.val.length ≤ start.val := by scalar_tac
    simp [List.drop_eq_nil_of_le this]
  · -- start < len: read cs[start], meet, recurse (smaller measure).
    rename_i hlt
    have hlt' : start.val < cs.val.length := by scalar_tac
    have hidx : Slice.index_usize cs start = ok cs.val[start.val] := by
      simp [Slice.index_usize, hlt']
    -- (start+1) is in-bounds → ok i1 with i1.val = start.val+1 (raw form via
    -- add_equiv); index = hidx; meet = pmeet; tail call is the IH (smaller measure).
    have hadd := UScalar.add_equiv start (1#usize)
    cases hstep : (start + 1#usize) with
    | ok i1 =>
      rw [hstep] at hadd
      obtain ⟨_, hi1v, _⟩ := hadd
      simp only [hidx, meet_eq_pmeet, bind_tc_ok]
      rw [meet_from_eq_foldl cs i1 (pmeet acc cs.val[start.val])]
      congr 1
      rw [hi1v, List.drop_eq_getElem_cons hlt']
      rfl
    | fail e => rw [hstep] at hadd; simp only [UScalar.inBounds] at hadd; scalar_tac
    | div => rw [hstep] at hadd; exact hadd.elim
termination_by cs.val.length - start.val
decreasing_by
  rw [hstep] at hadd; obtain ⟨_, hi1v, _⟩ := hadd; scalar_tac

/-- `resolve` of a non-empty list is `Decided` of the pure left-fold of `pmeet`
    over the whole list (head as the seed) — the clean reduction of the extracted
    `resolve`, via `meet_from_eq_foldl`. -/
theorem resolve_cons (a : authority.Authority) (rest : List authority.Authority)
    (h : (a :: rest).length ≤ Std.Usize.max) :
    authority.resolve ⟨a :: rest, h⟩
      = ok (authority.Resolution.Decided (List.foldl pmeet a rest)) := by
  have hidx : Slice.index_usize (⟨a :: rest, h⟩ : Slice _) 0#usize = ok a := by
    simp [Slice.index_usize]
  simp only [authority.resolve, core.slice.Slice.is_empty, Slice.length, List.length_cons,
             Nat.add_one_ne_zero, decide_false, Bool.false_eq_true, if_false, hidx, bind_tc_ok]
  rw [meet_from_eq_foldl]
  simp only [bind_tc_ok]
  rfl

/-- **General order-independence (L1), arbitrary length.** For ANY two adjacent
    elements and ANY tail, a list and its adjacent-swap resolve identically — on
    the extracted `resolve`, for lists of UNBOUNDED length. Adjacent
    transpositions generate every permutation, so this is FULL order-independence
    (not just length 3). `foldl pmeet x (y::xs) = foldl pmeet (x⊓y) xs =
    foldl pmeet (y⊓x) xs` by `pmeet_comm`. -/
theorem resolve_adjacent_swap (x y : authority.Authority)
    (xs : List authority.Authority)
    (h1 : (x :: y :: xs).length ≤ Std.Usize.max)
    (h2 : (y :: x :: xs).length ≤ Std.Usize.max) :
    authority.resolve ⟨x :: y :: xs, h1⟩ = authority.resolve ⟨y :: x :: xs, h2⟩ := by
  rw [resolve_cons, resolve_cons]
  simp only [List.foldl_cons, pmeet_comm x y]

-- ══ P1 signed-object: the allowlist is a CLOSED gate (PO-8, law §4·4) ══
-- The extracted `admit` threads `allows_* = core.slice.Slice.contains(profile.axis,
-- algo) = List.anyM (eq …)` over the `v1` Vec — closed and computable. The v1
-- profile admits EXACTLY its member on each axis and rejects every other value,
-- the Rust image of SignedObject.lean's `allows_*` + `TrustedProfile` (v1-only).
-- Discharged on the extracted code by `native_decide` (via the DecidableEq chain
-- above), the Aeneas analogue of Lean's `by decide` over the finite domain.

open signed_object in
theorem admit_hash_v1_admits_blake3_rejects_sha1 :
    ((do let p ← Profile.v1; AllowedHash.admit p HashAlgorithm.Blake3_256)
      = ok (some { algorithm := HashAlgorithm.Blake3_256 }))
    ∧ ((do let p ← Profile.v1; AllowedHash.admit p HashAlgorithm.Sha1) = ok none) := by
  native_decide

open signed_object in
theorem admit_signature_v1_admits_ed25519_rejects_ecdsa :
    ((do let p ← Profile.v1; AllowedSignature.admit p SignatureAlgorithm.Ed25519)
      = ok (some { algorithm := SignatureAlgorithm.Ed25519 }))
    ∧ ((do let p ← Profile.v1; AllowedSignature.admit p SignatureAlgorithm.Ecdsa) = ok none) := by
  native_decide

open signed_object in
theorem admit_codec_v1_admits_dagcbor_rejects_json :
    ((do let p ← Profile.v1; AllowedCodec.admit p Codec.DagCbor)
      = ok (some { codec := Codec.DagCbor }))
    ∧ ((do let p ← Profile.v1; AllowedCodec.admit p Codec.Json) = ok none) := by
  native_decide

end CeremonyRefinement
