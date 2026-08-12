/-
  Ceremony Suite — Bridle POSIX authority machine (mechanized core of the
  design in docs/design/posix-authority-model.md §§4-8).

  Mathlib-FREE on purpose (like Ceremony/P0/Authority.lean): authority is a
  capability predicate `Cap → Prop`, the attenuation order is pointwise
  implication, and every proof is constructive — `intro`/`cases`/projection —
  so `lake exe formalGate` (no proof escapes) and `AxiomAudit` (postulates ⊆
  {propext, Quot.sound}) both pass with no extra command.

  Proved here (the MODEL half — platform-neutral, per docs/design §7):
    • the attenuation order is a preorder with a greatest-lower-bound meet and a
      fail-closed bottom (never amplifies);
    • complete mediation: a permitted operation's required authority is within
      the process's effective authority (the guard is definitional — an
      unauthorized transition does not exist);
    • namespace non-amplification: resolving a NAME preserves `fds ⊑ effective`
      (the namespace routes, it does not grant);
    • descriptor non-amplification: a capability DERIVED from a descriptor never
      exceeds the descriptor it derives from;
    • descendant attenuation: a spawned child's authority is bounded by the
      parent's, and the child is well-formed by construction;
    • capstone: from a well-formed start, EVERY reachable state keeps
      `fds ⊑ effective` — descriptors never amplify beyond the grant across any
      sequence of resolve / derive / operate steps.

  NOT proved here — stated as obligation `Prop`s (no proof term), discharged by
  native evidence per formal/assurance (ASM-POSIX-*), never by this model:
    • that a given OS actually enforces the projection (projection soundness);
    • that the analyzed authority is the applied authority (non-equivocation) —
      modeled temporally in formal/tla/AuthorityLifecycle.tla (T7), grounded by
      the ASM-CID runtime chain.
-/
namespace Ceremony.Posix

/-! ### Authority as a capability predicate; ⊑ is pointwise implication -/

/-- Authority is the set of capabilities a principal may exercise, as its
    Prop-valued characteristic function over an abstract capability universe. -/
def Authority (Cap : Type) : Type := Cap → Prop

/-- Attenuation order: `a ⊑ b` iff every capability `a` permits, `b` permits. -/
def Authority.le {Cap : Type} (a b : Authority Cap) : Prop := ∀ c, a c → b c
infix:50 " ⊑ " => Authority.le

/-- Componentwise meet = capability-set intersection. -/
def Authority.meet {Cap : Type} (a b : Authority Cap) : Authority Cap := fun c => a c ∧ b c
infixl:70 " ⊓ " => Authority.meet

/-- The fail-closed bottom: deny everything. -/
def Authority.bot {Cap : Type} : Authority Cap := fun _ => False

theorem le_refl {Cap : Type} (a : Authority Cap) : a ⊑ a := fun _ h => h

theorem le_trans {Cap : Type} {a b c : Authority Cap} (hab : a ⊑ b) (hbc : b ⊑ c) : a ⊑ c :=
  fun x hx => hbc x (hab x hx)

/-- Meet never amplifies: it lies below each input (L4 / PO-4, per axis). -/
theorem meet_le_left {Cap : Type} (a b : Authority Cap) : (a ⊓ b) ⊑ a := fun _ h => h.1
theorem meet_le_right {Cap : Type} (a b : Authority Cap) : (a ⊓ b) ⊑ b := fun _ h => h.2

/-- Meet is the greatest lower bound. -/
theorem meet_greatest {Cap : Type} {x a b : Authority Cap} (ha : x ⊑ a) (hb : x ⊑ b) :
    x ⊑ (a ⊓ b) := fun c hc => ⟨ha c hc, hb c hc⟩

/-- Nothing is below the fail-closed bottom except by permitting nothing. -/
theorem bot_le {Cap : Type} (a : Authority Cap) : Authority.bot ⊑ a := fun _ h => h.elim

/-! ### Process state and the descriptor invariant `fds ⊑ effective` -/

/-- A process holds a delegated grant (`effective`) and a set of capabilities
    reachable through its descriptor table (`fds`). -/
structure ProcessState (Cap : Type) where
  effective : Authority Cap
  fds : Authority Cap

/-- Well-formed: descriptors never carry authority beyond the grant. This is the
    descriptor-as-capability invariant every reachable state must keep. -/
def ProcessState.wf {Cap : Type} (s : ProcessState Cap) : Prop := s.fds ⊑ s.effective

/-! ### Operations and complete mediation -/

/-- A permitted operation transition. The guard `required ⊑ effective` is part of
    the definition: an unauthorized transition is not merely rejected, it does
    not exist. A pure operation leaves the state unchanged. -/
def transitionOp {Cap Op Obj : Type} (req : Op → Obj → Authority Cap)
    (s : ProcessState Cap) (op : Op) (obj : Obj) (s' : ProcessState Cap) : Prop :=
  req op obj ⊑ s.effective ∧ s' = s

/-- **Complete mediation.** Every permitted operation's required authority is
    within the process's effective authority. -/
theorem complete_mediation {Cap Op Obj : Type} (req : Op → Obj → Authority Cap)
    {s : ProcessState Cap} {op : Op} {obj : Obj} {s' : ProcessState Cap}
    (h : transitionOp req s op obj s') : req op obj ⊑ s.effective := h.1

/-! ### Namespace resolution routes; it does not grant -/

/-- Faithful open: resolving a name adds to `fds` only capabilities the grant
    already covers. Namespace resolution confers no authority. -/
def openName {Cap : Type} (s : ProcessState Cap) (resolved : Authority Cap) : ProcessState Cap :=
  { s with fds := fun c => s.fds c ∨ (resolved c ∧ s.effective c) }

/-- **Namespace non-amplification.** Resolving a name preserves `fds ⊑ effective`. -/
theorem namespace_non_amplification {Cap : Type} (s : ProcessState Cap)
    (resolved : Authority Cap) (h : s.wf) : (openName s resolved).wf := by
  intro c hc
  cases hc with
  | inl hfd => exact h c hfd
  | inr hres => exact hres.2

/-! ### Descriptor derivation never exceeds the source -/

/-- Faithful derive (dup / openat / reopen / O_PATH upgrade / SCM_RIGHTS): the
    derived descriptor's capabilities are contained in the source's. -/
def derive {Cap : Type} (s : ProcessState Cap) (d : Authority Cap) : ProcessState Cap :=
  { s with fds := fun c => s.fds c ∨ (d c ∧ s.fds c) }

/-- **Descriptor non-amplification.** A derived descriptor never exceeds `fds`. -/
theorem descriptor_non_amplification {Cap : Type} (s : ProcessState Cap) (d : Authority Cap) :
    (derive s d).fds ⊑ s.fds := by
  intro c hc
  cases hc with
  | inl hfd => exact hfd
  | inr hd => exact hd.2

theorem derive_wf {Cap : Type} (s : ProcessState Cap) (d : Authority Cap) (h : s.wf) :
    (derive s d).wf := le_trans (descriptor_non_amplification s d) h

/-! ### Spawn — descendant attenuation, well-formed by construction -/

/-- A spawned child gets a grant bounded by the parent (`hatt`) and inherits only
    the parent descriptors that fall within the child's own grant. -/
def spawnChild {Cap : Type} (parent : ProcessState Cap) (childGrant : Authority Cap)
    (_hatt : childGrant ⊑ parent.effective) : ProcessState Cap :=
  { effective := childGrant, fds := parent.fds ⊓ childGrant }

/-- **Descendant attenuation.** The child's grant is bounded by the parent's. -/
theorem spawnChild_attenuates {Cap : Type} (parent : ProcessState Cap)
    (childGrant : Authority Cap) (hatt : childGrant ⊑ parent.effective) :
    (spawnChild parent childGrant hatt).effective ⊑ parent.effective := hatt

/-- Delivered descriptors are bounded by the parent's. -/
theorem spawnChild_fds_attenuates {Cap : Type} (parent : ProcessState Cap)
    (childGrant : Authority Cap) (hatt : childGrant ⊑ parent.effective) :
    (spawnChild parent childGrant hatt).fds ⊑ parent.fds := meet_le_left parent.fds childGrant

/-- The child is well-formed by construction. -/
theorem spawnChild_wf {Cap : Type} (parent : ProcessState Cap)
    (childGrant : Authority Cap) (hatt : childGrant ⊑ parent.effective) :
    (spawnChild parent childGrant hatt).wf := meet_le_right parent.fds childGrant

/-! ### Capstone: every reachable state keeps `fds ⊑ effective` -/

/-- One step of single-process evolution: an authorized operation, a name
    resolution, or a descriptor derivation. -/
inductive Step {Cap Op Obj : Type} (req : Op → Obj → Authority Cap) :
    ProcessState Cap → ProcessState Cap → Prop
  | operate (s : ProcessState Cap) (op : Op) (obj : Obj) (_h : req op obj ⊑ s.effective) :
      Step req s s
  | resolve (s : ProcessState Cap) (resolved : Authority Cap) : Step req s (openName s resolved)
  | derive (s : ProcessState Cap) (d : Authority Cap) : Step req s (derive s d)

theorem step_preserves_wf {Cap Op Obj : Type} (req : Op → Obj → Authority Cap)
    {s s' : ProcessState Cap} (hs : s.wf) (hstep : Step req s s') : s'.wf := by
  cases hstep with
  | operate _op _obj _h => exact hs
  | resolve resolved => exact namespace_non_amplification s resolved hs
  | derive d => exact derive_wf s d hs

/-- Reachability under the step relation. -/
inductive Reach {Cap Op Obj : Type} (req : Op → Obj → Authority Cap) :
    ProcessState Cap → ProcessState Cap → Prop
  | refl (s : ProcessState Cap) : Reach req s s
  | tail {s s' s'' : ProcessState Cap} : Reach req s s' → Step req s' s'' → Reach req s s''

/-- **Model-level complete-mediation safety.** From a well-formed start, every
    reachable state keeps `fds ⊑ effective`: no sequence of resolve / derive /
    operate steps amplifies a process's authority beyond its grant. -/
theorem reach_preserves_wf {Cap Op Obj : Type} (req : Op → Obj → Authority Cap)
    {s s' : ProcessState Cap} (hs : s.wf) (hr : Reach req s s') : s'.wf := by
  induction hr with
  | refl => exact hs
  | tail _ hstep ih => exact step_preserves_wf req ih hstep

/-! ### Obligations discharged by native evidence, NOT by this model

    These are stated as `Prop`s with no proof term on purpose: the model cannot
    establish that a real OS refines it. They are the hand-off points to
    formal/assurance (ASM-POSIX-*) and the hostile-child Rust tests. -/

/-- Projection soundness (per platform): the capabilities a mechanism actually
    enforces are contained in the authority it was asked to enforce; where the
    platform cannot faithfully enforce an axis, the result is a refusal, never a
    silent widening. Discharged by native evidence, not proved here. -/
def ProjectionSoundnessObligation {Cap : Type}
    (enforced requested : Authority Cap) : Prop := enforced ⊑ requested

/-- Non-equivocation: the authority analyzed at admission equals the authority
    applied at the fence. Modeled temporally in AuthorityLifecycle.tla (T7) and
    grounded by the ASM-CID runtime chain; stated here as the hand-off. -/
def NonEquivocationObligation {Cap : Type}
    (analyzed applied : Authority Cap) : Prop := analyzed ⊑ applied ∧ applied ⊑ analyzed

end Ceremony.Posix
