-------------------------- MODULE AuthorityLifecycle --------------------------
(*
  The authority/enforcement LIFECYCLE as a state machine (the temporal companion
  to the Lean authority algebra in formal/Ceremony/Assurance/AuthorityLattice.lean).

  This models the assurance chain the coordinator brief names:

      Requested -> Resolved -> Planned -> Compiled -> Applied -> Evidenced -> Executed

  and the invariants T1..T7 that no reachable transition may break. It is
  PLATFORM-NEUTRAL: it proves properties of Bridle's MODEL. It does not model
  Landlock, seccomp, Seatbelt, or AppContainer — native evidence (the Rust
  hostile-child tests) is what establishes that a given OS REFINES this model.

  CONTENT ADDRESSING, per the sibling spec EnforcementFence_NonEquivocation.tla,
  is the injective abstraction `Cid(x) == x` (identity = value). Provenance links
  (T7) carry the CID of the object they attest, so an evidence record that
  attests a DIFFERENT applied fence has a different CID and cannot hide.

  `Mode` toggles a faithful implementation against one deliberately-broken one
  per invariant, exactly as `Design` does in the non-equivocation spec:

     "Faithful"            -> []Inv holds (all of T1..T7).
     "ExecBeforeAdmit"     -> T1 counterexample (run before admission).
     "SilentWiden"         -> T2 counterexample (closure dropped from resolved).
     "AppliedExceedsClaim" -> T3 counterexample (applied wider than claimed).
     "UnknownAdmit"        -> T4 counterexample (Unknown axis admitted).
     "DescendantEscalate"  -> T5 counterexample (child gains authority).
     "AmbientEnv"          -> T6 counterexample (undelegated secret in child env).
     "SubstituteEvidence"  -> T7 counterexample (evidence attests another fence).
*)

CONSTANTS
  Resources,           \* small finite authority universe, e.g. {r1, r2}
  Secrets,             \* small finite secret-env universe, e.g. {s1}
  ExplicitDelegation,  \* SUBSET Secrets : env the caller explicitly delegated
  Mode                 \* one of the strings above

\* A CID is an injective content hash; here the object IS its value, so
\* Cid(a) = Cid(b) <=> a = b -- substitution resistance at the model level.
Cid(object) == object

Phases == { "Requested", "Resolved", "Planned", "Compiled",
            "Applied", "Evidenced", "Executed" }

\* The platform baseline env carries NO secret (e.g. Windows SystemRoot/PATHEXT).
PlatformBaseline == {}

VARIABLES
  phase,            \* current lifecycle phase
  requested,        \* SUBSET Resources : delegated / requested authority
  closure,          \* SUBSET Resources : runtime closure (harness-added authority)
  resolved,         \* SUBSET Resources : ResolvedAuthority (what admission analyzes)
  resolvedUnknown,  \* BOOLEAN : the backend projected the axis as Unknown
  admitted,         \* BOOLEAN : did admission accept?
  plan,             \* SUBSET Resources : EnforcementPlan
  compiled,         \* SUBSET Resources : CompiledFence
  applied,          \* SUBSET Resources : AppliedFence (what actually confined)
  appliedCid,       \* CID of the applied fence
  evidence,         \* SUBSET Resources : AppliedFenceEvidence (what native evidence observed)
  evidenceCid,      \* CID the evidence record claims to attest
  childAuth,        \* SUBSET Resources : gen-1 descendant authority
  grandchildAuth,   \* SUBSET Resources : gen-2 descendant authority
  childEnv          \* SUBSET Secrets : env actually delivered to the child

vars == << phase, requested, closure, resolved, resolvedUnknown, admitted,
           plan, compiled, applied, appliedCid, evidence, evidenceCid,
           childAuth, grandchildAuth, childEnv >>

\* The authorized bound (L3): what the delegated grant plus the declared runtime
\* closure permit. Admission accepts only resolved \subseteq Bound.
Bound == requested \cup closure

TypeOK ==
  /\ phase \in Phases
  /\ requested      \subseteq Resources
  /\ closure        \subseteq Resources
  /\ resolved       \subseteq Resources
  /\ resolvedUnknown \in BOOLEAN
  /\ admitted       \in BOOLEAN
  /\ plan           \subseteq Resources
  /\ compiled       \subseteq Resources
  /\ applied        \subseteq Resources
  /\ appliedCid     \subseteq Resources
  /\ evidence       \subseteq Resources
  /\ evidenceCid    \subseteq Resources
  /\ childAuth      \subseteq Resources
  /\ grandchildAuth \subseteq Resources
  /\ childEnv       \subseteq Secrets

Init ==
  /\ phase = "Requested"
  /\ requested \in SUBSET Resources
  /\ closure   \in SUBSET Resources
  /\ resolved = {}
  /\ resolvedUnknown = FALSE
  /\ admitted = FALSE
  /\ plan = {}
  /\ compiled = {}
  /\ applied = {}
  /\ appliedCid = {}
  /\ evidence = {}
  /\ evidenceCid = {}
  /\ childAuth = {}
  /\ grandchildAuth = {}
  /\ childEnv = {}

---------------------------------------------------------------------------
\* Resolve: the backend projects a ResolvedAuthority. Faithful projection folds
\* the runtime closure into `resolved` (visible, no silent widening) and reports
\* Unknown honestly. The bug modes break exactly one of those.
Resolve ==
  /\ phase = "Requested"
  /\ phase' = "Resolved"
  /\ IF Mode = "SilentWiden"
       \* BUG (L5/T2): closure is real (used downstream) but hidden from resolved.
       THEN /\ resolved' = requested
            /\ resolvedUnknown' = FALSE
       ELSE IF Mode = "UnknownAdmit"
       \* BUG (T4): the axis is Unknown yet resolution proceeds to admit it.
       THEN /\ resolved' = Bound
            /\ resolvedUnknown' = TRUE
       ELSE /\ resolved' = Bound
            /\ resolvedUnknown' = FALSE
  /\ UNCHANGED << requested, closure, admitted, plan, compiled, applied,
                  appliedCid, evidence, evidenceCid, childAuth, grandchildAuth,
                  childEnv >>

\* Admit: the enforcement gate. Faithful admission requires the resolved fence to
\* be within the authorized bound AND the axis to be decidable (not Unknown).
Admit ==
  /\ phase = "Resolved"
  /\ phase' = "Planned"
  /\ \/ Mode = "UnknownAdmit"                                  \* BUG (T4)
     \/ (resolved \subseteq Bound /\ ~resolvedUnknown)         \* faithful gate
  /\ admitted' = TRUE
  /\ plan' = resolved
  /\ UNCHANGED << requested, closure, resolved, resolvedUnknown, compiled,
                  applied, appliedCid, evidence, evidenceCid, childAuth,
                  grandchildAuth, childEnv >>

Compile ==
  /\ phase = "Planned"
  /\ phase' = "Compiled"
  /\ compiled' = plan
  /\ UNCHANGED << requested, closure, resolved, resolvedUnknown, admitted, plan,
                  applied, appliedCid, evidence, evidenceCid, childAuth,
                  grandchildAuth, childEnv >>

\* Apply: install the fence. Faithful applied = compiled. Two distinct bugs:
\*  - AppliedExceedsClaim widens beyond the authorized bound (T3);
\*  - SilentWiden installs the real closure the harness adds while `resolved`
\*    (what admission analyzed) omitted it, so the applied fence escapes the
\*    claim without any Unknown/Superset ever being visible (L5/T2).
Apply ==
  /\ phase = "Compiled"
  /\ phase' = "Applied"
  /\ IF Mode = "AppliedExceedsClaim"
       THEN applied' = Resources               \* BUG (T3): widen beyond the claim
       ELSE IF Mode = "SilentWiden"
       THEN applied' = compiled \cup closure    \* BUG (L5/T2): hidden closure installed
       ELSE applied' = compiled
  /\ appliedCid' = Cid(applied')
  /\ UNCHANGED << requested, closure, resolved, resolvedUnknown, admitted, plan,
                  compiled, evidence, evidenceCid, childAuth, grandchildAuth,
                  childEnv >>

\* Evidence: native evidence observes the applied fence. Faithful evidence
\* attests the SAME fence (matching CID). The bug attests a different one.
Evidence ==
  /\ phase = "Applied"
  /\ phase' = "Evidenced"
  /\ IF Mode = "SubstituteEvidence"
       THEN /\ evidence' = requested       \* attests some OTHER fence ...
            /\ evidenceCid' = Cid(requested)  \* ... with its (different) CID
       ELSE /\ evidence' = applied
            /\ evidenceCid' = appliedCid
  /\ UNCHANGED << requested, closure, resolved, resolvedUnknown, admitted, plan,
                  compiled, applied, appliedCid, childAuth, grandchildAuth,
                  childEnv >>

\* Execute: run the child (and its descendants). Faithful descendants inherit a
\* subset of the applied fence, and the child env is baseline + explicit
\* delegation only. The bugs escalate a descendant or leak an undelegated secret.
Execute ==
  /\ \/ phase = "Evidenced"
     \/ (Mode = "ExecBeforeAdmit" /\ phase = "Requested")   \* BUG (T1)
  /\ phase' = "Executed"
  /\ IF Mode = "DescendantEscalate"
       THEN /\ childAuth' = Resources                       \* BUG (T5)
            /\ grandchildAuth' = Resources
       ELSE /\ childAuth' = applied
            /\ grandchildAuth' = applied
  /\ IF Mode = "AmbientEnv"
       THEN childEnv' = Secrets                             \* BUG (T6)
       ELSE childEnv' = PlatformBaseline \cup ExplicitDelegation
  /\ UNCHANGED << requested, closure, resolved, resolvedUnknown, admitted, plan,
                  compiled, applied, appliedCid, evidence, evidenceCid >>

Next ==
  \/ Resolve \/ Admit \/ Compile \/ Apply \/ Evidence \/ Execute
  \/ (phase = "Executed" /\ UNCHANGED vars)   \* terminal stutter (no liveness here)

Spec == Init /\ [][Next]_vars

---------------------------------------------------------------------------
\* T1 — No execution before admission.
T1_NoExecBeforeAdmit == (phase = "Executed") => admitted

\* T2 — No silent authority widening: everything downstream of resolution is
\* contained in what resolution CLAIMED. A closure hidden from `resolved` shows
\* up here as plan/applied escaping `resolved`.
T2_NoSilentWiden ==
  /\ plan     \subseteq resolved
  /\ compiled \subseteq resolved
  /\ applied  \subseteq resolved

\* T3 — Applied authority is covered by the authorized claim (containment, NOT
\* equality: an exactness claim would be modeled separately).
T3_AppliedWithinClaim == applied \subseteq Bound

\* T4 — Unknown cannot become strong: admission never accepts an Unknown axis.
T4_UnknownNotStrong == admitted => ~resolvedUnknown

\* T5 — Descendant non-escalation: a confined child (and grandchild) cannot hold
\* authority beyond the applied fence.
T5_DescendantNonEscalation ==
  /\ childAuth      \subseteq applied
  /\ grandchildAuth \subseteq childAuth

\* T6 — Environment delegation: a secret NOT explicitly delegated never reaches
\* the child; a delegated one survives to an executed child.
T6_EnvDelegation ==
  /\ \A s \in Secrets : (s \notin ExplicitDelegation) => (s \notin childEnv)
  /\ \A s \in ExplicitDelegation : (phase = "Executed") => (s \in childEnv)

\* T7 — Provenance continuity: once evidence exists it attests the applied fence
\* (same CID) — no silent substitution of an unrelated object.
T7_ProvenanceContinuity ==
  (phase \in { "Evidenced", "Executed" }) => (evidenceCid = appliedCid)

Inv ==
  /\ TypeOK
  /\ T1_NoExecBeforeAdmit
  /\ T2_NoSilentWiden
  /\ T3_AppliedWithinClaim
  /\ T4_UnknownNotStrong
  /\ T5_DescendantNonEscalation
  /\ T6_EnvDelegation
  /\ T7_ProvenanceContinuity

THEOREM FaithfulIsSafe == (Mode = "Faithful") => (Spec => []Inv)
===============================================================================
