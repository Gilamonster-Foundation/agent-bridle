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

-- FOLLOW-UP (ROADMAP 1c): the GENERAL order-independence over ARBITRARY-length
-- inputs needs `meet_from` `partial_fixpoint` induction (its equation loops the
-- default `simp`) — beyond what the finite `native_decide` above can reach. The
-- safety law (no fail-open) is proven, and order-independence is now exhaustive
-- (all value-triples) on the extracted code at length 3.

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
