----------------- MODULE EnforcementFence_NonEquivocation -----------------
(*
  #137 / laws L2 NON-EQUIVOCATION + L3 BOUND, tied together by CONTENT ADDRESSING.

  Temporal companion to EnforcementGate.tla, which discharges the *strength/time*
  non-equivocation (a fence can DROP between grant and exec; re-check at exec).
  The #317 bounded-authority audit found a *structural* non-equivocation the
  strength model cannot express: at a SINGLE instant, admission analyzes one
  fence (`effective`) while spawn applies a WIDER one (`mechanism_effective`,
  spawn.rs:550-555). Two distinct objects; the L3 bound proof was about the
  wrong one, so a widened scope (sh -> {sh,bash}) is admitted.

  Content addressing is the cure and this model makes it the AXIOM:

      Cid(a) = Cid(b)   <=>   a = b            (an injective content hash)

  so "the object admitted is the object applied" is exactly

      Cid(applied) = admittedCid

  and any widening is a DIFFERENT CID -- impossible to hide. `Design` toggles
  the two implementations:

     "OneFence"           -> spawn applies the admitted fence itself
                             (the fix: one AdmittedFence, no re-derivation).
     "SeparateDerivation" -> spawn re-derives the fence from policy
                             (the #317 bug: effective admitted, a possibly-wider
                             mechanism_effective applied).

  TLC:
     Design = "OneFence"           -> []Inv holds (L2 and L3 both safe).
     Design = "SeparateDerivation" -> counterexample: authorized={r1},
                                      resolved={r1} admitted, applied={r1,r2}
                                      widened -> L2 and L3 both fail (= sh->bash).
*)

CONSTANTS Resources,   \* a small finite set of resources, e.g. {r1, r2}
          Design       \* "OneFence" | "SeparateDerivation"

\* A CID is an INJECTIVE content hash. In this abstraction the object *is* its
\* resolved scope, so identity = value -- which is precisely Cid(a)=Cid(b) <=> a=b.
Cid(scope) == scope

VARIABLES
  authorized,     \* SUBSET Resources : the Caveat-delegated (authorized) scope
  admitted,       \* BOOLEAN : has admission accepted a fence yet?
  admittedScope,  \* SUBSET Resources : the resolved fence admission accepted
  admittedCid,    \* the CID admission recorded for that fence
  ran,            \* BOOLEAN : did the child execute?
  appliedScope    \* SUBSET Resources : the fence actually applied to the child

vars == << authorized, admitted, admittedScope, admittedCid, ran, appliedScope >>

TypeOK ==
  /\ authorized    \subseteq Resources
  /\ admitted      \in BOOLEAN
  /\ admittedScope \subseteq Resources
  /\ admittedCid   \subseteq Resources
  /\ ran           \in BOOLEAN
  /\ appliedScope  \subseteq Resources

Init ==
  /\ authorized \in SUBSET Resources
  /\ admitted = FALSE
  /\ admittedScope = {}
  /\ admittedCid = {}
  /\ ran = FALSE
  /\ appliedScope = {}

\* Admission (L3 at admit time): a backend proposes a resolved fence `resolved`;
\* admission ACCEPTS only if resolved \subseteq authorized, and records its CID.
Admit ==
  /\ ~admitted
  /\ \E resolved \in SUBSET Resources :
        /\ resolved \subseteq authorized
        /\ admittedScope' = resolved
        /\ admittedCid'   = Cid(resolved)
  /\ admitted' = TRUE
  /\ UNCHANGED << authorized, ran, appliedScope >>

\* Exec: apply a fence to the child and run it.
Exec ==
  /\ admitted
  /\ ~ran
  /\ \E applied \in SUBSET Resources :
        /\ \/ (Design = "OneFence"           /\ applied = admittedScope)
           \/ (Design = "SeparateDerivation" /\ admittedScope \subseteq applied)
        /\ appliedScope' = applied
  /\ ran' = TRUE
  /\ UNCHANGED << authorized, admitted, admittedScope, admittedCid >>

\* A terminal (post-exec) state stutters so the single-shot model does not
\* deadlock (there is no liveness obligation here).
Next == Admit \/ Exec \/ (ran /\ UNCHANGED vars)
Spec == Init /\ [][Next]_vars

---------------------------------------------------------------------------
\* L2: the fence applied to the child is the one admission analyzed (same CID).
L2_NonEquivocation == ran => (Cid(appliedScope) = admittedCid)
\* L3: the effective child authority is within what was authorized.
L3_EffectiveBound  == ran => (appliedScope \subseteq authorized)

Inv == TypeOK /\ L2_NonEquivocation /\ L3_EffectiveBound

THEOREM FixIsSafe == (Design = "OneFence") => (Spec => []Inv)
===========================================================================
