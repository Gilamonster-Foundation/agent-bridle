--------------------------- MODULE PosixAuthority ---------------------------
(*
  The Bridle POSIX authority PROJECTION as a state machine — the object /
  descriptor / namespace layer that AuthorityLifecycle.tla does not model.

  Where AuthorityLifecycle proves the *lifecycle* chain (Requested -> ... ->
  Executed, invariants T1..T7), this spec proves the four properties a POSIX
  projection must add on top, from docs/design/posix-authority-model.md §8:

      NoAuthorityAmplification   — a process exercises no capability beyond its
                                   delegated grant (complete mediation).
      NamespaceNonAmplification  — resolving a NAME confers no authority beyond
                                   the grant; the namespace routes, it does not
                                   grant (docs/design §5).
      DescriptorNonAmplification — a capability DERIVED from a descriptor (dup,
                                   openat, reopen via /proc/self/fd, O_PATH
                                   upgrade, SCM_RIGHTS) never exceeds the
                                   descriptor it derives from (docs/design §4).
      DescendantAttenuation      — a child's authority is a subset of its
                                   parent's; a spawn does not escalate.

  It is PLATFORM-NEUTRAL: it proves properties of Bridle's MODEL, not of
  Landlock/seccomp/Seatbelt/AppContainer. Native evidence (the hostile-child
  Rust tests) is what establishes that a given OS REFINES this model.

  Authority is modeled as a set of atomic capabilities `<<object, right>>`,
  mirroring the `Caveats` allowlist grain (agent-mesh-protocol) at the model
  level: a grant is a SUBSET of the finite capability universe, and every
  amplification is exactly a `\notin granted` membership fact.

  `Mode` toggles a faithful implementation against one deliberately-broken one
  per invariant, exactly as `Mode` does in AuthorityLifecycle.tla:

     "Faithful"          -> []Inv holds (all four properties).
     "Amplify"           -> NoAuthorityAmplification counterexample
                            (an operation bypasses the grant — the direct-syscall
                            / ambient-path bug).
     "NamespaceForge"    -> NamespaceNonAmplification counterexample
                            (name resolution manufactures rights the grant never
                            delegated — the ambient-root bug #319 targets).
     "DescriptorForge"   -> DescriptorNonAmplification counterexample
                            (a derived descriptor widens beyond its source —
                            the /proc/self/fd reopen / O_PATH upgrade bug).
     "DescendantEscalate"-> DescendantAttenuation counterexample
                            (a spawned child gains authority the parent lacked).
*)

CONSTANTS
  Objects,   \* small finite object universe, e.g. {o1, o2}
  Rights,    \* small finite rights set, e.g. {r, w}
  Mode       \* one of the strings above

\* The universe of atomic capabilities and the caps naming one object.
Caps       == Objects \X Rights
CapsOf(o)  == { c \in Caps : c[1] = o }

Phases == { "Start", "Opened", "Derived", "Spawned", "Operated" }

VARIABLES
  phase,        \* lifecycle position along the single Open->Derive->Spawn->Operate path
  granted,      \* SUBSET Caps : the delegated authority (the effective ceiling)
  fds,          \* SUBSET Caps : capabilities currently reachable through descriptors
  openAdded,    \* SUBSET Caps : caps the most recent name-resolution introduced
  deriveSource, \* SUBSET Caps : the descriptor authority a derive step drew from
  deriveAdded,  \* SUBSET Caps : caps the most recent derive step introduced
  childAuth,    \* SUBSET Caps : a spawned child's delegated authority
  childFds,     \* SUBSET Caps : capabilities delivered to the child's descriptors
  opened        \* SUBSET Caps : capabilities the process actually EXERCISED

vars == << phase, granted, fds, openAdded, deriveSource, deriveAdded,
           childAuth, childFds, opened >>

TypeOK ==
  /\ phase        \in Phases
  /\ granted      \subseteq Caps
  /\ fds          \subseteq Caps
  /\ openAdded    \subseteq Caps
  /\ deriveSource \subseteq Caps
  /\ deriveAdded  \subseteq Caps
  /\ childAuth    \subseteq Caps
  /\ childFds     \subseteq Caps
  /\ opened       \subseteq Caps

---------------------------------------------------------------------------
Init ==
  /\ phase = "Start"
  /\ granted \in SUBSET Caps        \* explore every delegated grant
  /\ fds = {}
  /\ openAdded = {}
  /\ deriveSource = {}
  /\ deriveAdded = {}
  /\ childAuth = {}
  /\ childFds = {}
  /\ opened = {}

\* Open: resolve a NAME to an object and obtain a descriptor for it. Faithful
\* resolution grants only the caps the delegated grant already covers for that
\* object — the namespace routes, it does not confer authority. The bug lets
\* resolution mint every right on the resolved object (ambient-root authority).
Open ==
  /\ phase = "Start"
  /\ phase' = "Opened"
  /\ \E o \in Objects :
       IF Mode = "NamespaceForge"
         THEN openAdded' = CapsOf(o)                 \* BUG: ambient rights on the object
         ELSE openAdded' = granted \cap CapsOf(o)    \* faithful: bounded by the grant
  /\ fds' = fds \cup openAdded'
  /\ UNCHANGED << granted, deriveSource, deriveAdded, childAuth, childFds, opened >>

\* Derive: manufacture another descriptor FROM an existing one (dup / openat /
\* reopen through /proc/self/fd / O_PATH upgrade / SCM_RIGHTS receipt). Faithful
\* derivation cannot exceed the source descriptor's authority. The bug reopens
\* the object with wider rights than the source fd held.
Derive ==
  /\ phase = "Opened"
  /\ phase' = "Derived"
  /\ deriveSource' = fds                              \* the authority actually held
  /\ IF Mode = "DescriptorForge"
       THEN deriveAdded' = Caps                       \* BUG: widen beyond the source fd
       ELSE deriveAdded' = fds                        \* faithful: no more than the source
  /\ fds' = fds \cup deriveAdded'
  /\ UNCHANGED << granted, openAdded, childAuth, childFds, opened >>

\* Spawn: create a child. Faithful attenuation gives the child a subset of the
\* parent's grant and delivers only descriptors the parent already holds. The
\* bug hands the child authority the parent never had.
Spawn ==
  /\ phase = "Derived"
  /\ phase' = "Spawned"
  /\ IF Mode = "DescendantEscalate"
       THEN /\ childAuth' = Caps                      \* BUG: child exceeds parent
            /\ childFds' = Caps
       ELSE /\ childAuth' = granted                   \* faithful: child <= parent grant
            /\ childFds' = fds
  /\ UNCHANGED << granted, fds, openAdded, deriveSource, deriveAdded, opened >>

\* Operate: exercise a capability through a held descriptor. Faithful operation
\* is doubly mediated — the cap must be reachable through a descriptor AND within
\* the grant (the enforcement floor re-checks the grant, never trusting the fd
\* alone). The bug exercises any capability directly (a raw syscall on an
\* un-delegated object), bypassing mediation entirely.
Operate ==
  /\ phase = "Spawned"
  /\ phase' = "Operated"
  /\ IF Mode = "Amplify"
       THEN \E c \in Caps : opened' = opened \cup {c}            \* BUG: unmediated raw op
       ELSE opened' = opened \cup (fds \cap granted)            \* faithful: doubly mediated
  /\ UNCHANGED << granted, fds, openAdded, deriveSource, deriveAdded, childAuth, childFds >>

Next ==
  \/ Open \/ Derive \/ Spawn \/ Operate
  \/ (phase = "Operated" /\ UNCHANGED vars)   \* terminal stutter (no liveness here)

Spec == Init /\ [][Next]_vars

---------------------------------------------------------------------------
\* P1 — Complete mediation / no authority amplification: every capability the
\* process actually exercised was within its delegated grant.
NoAuthorityAmplification == opened \subseteq granted

\* P2 — Namespace non-amplification: resolving a name introduced no capability
\* beyond the grant. The namespace is a router, not an authority source.
NamespaceNonAmplification == openAdded \subseteq granted

\* P3 — Descriptor non-amplification: a capability derived from a descriptor
\* never exceeds the authority of the descriptor it derived from.
DescriptorNonAmplification == deriveAdded \subseteq deriveSource

\* P4 — Descendant attenuation: a child's authority (grant and delivered
\* descriptors) is bounded by the parent's.
DescendantAttenuation ==
  /\ childAuth \subseteq granted
  /\ childFds  \subseteq fds

Inv ==
  /\ TypeOK
  /\ NoAuthorityAmplification
  /\ NamespaceNonAmplification
  /\ DescriptorNonAmplification
  /\ DescendantAttenuation

THEOREM FaithfulIsSafe == (Mode = "Faithful") => (Spec => []Inv)
===============================================================================
