------------------------- MODULE ProvenanceReplay -------------------------
EXTENDS Naturals
(*
  #137 / laws L5 PROVENANCE + L7 FAIL-CLOSED, under an EXPLICIT crash + restart
  (the buildfarm lesson: MODEL recovery as real actions, do not assume it).

  Evidence must bind the EXACT grant + fence admission analyzed AND the session
  (epoch) it was measured in. A crash wipes volatile admission state; a restart
  bumps the epoch to a new session. An adversary RETAINS a pre-crash evidence
  object and replays it after restart. Content addressing + session binding is a
  defense only if the Result acceptor RE-CHECKS that the evidence's
  (grant, fence, epoch) match the CURRENT admission and session -- fail-closed
  otherwise. A CID that is computed but never re-checked is decoration.

  `Design` toggles the acceptor:
     "FailClosed"          -> accept iff evGrant = admGrant /\ evFence = admFence
                              /\ evEpoch = epoch.  []Inv holds.
     "TrustStaleEvidence"  -> accept without the binding/session re-check (the bug).
                              Measure -> Crash -> Restart -> Accept replays a STALE
                              evidence into a NEW session -> L5 and L7 both fail.

  The two safety facts are LATCHED booleans set at the accept transition, so they
  stay stable across a later crash/restart (a legitimate accept is never retro-
  actively falsified by wiping volatile state).
*)

CONSTANTS Grants,     \* finite set of grant CIDs, e.g. {g1, g2}
          Fences,     \* finite set of fence CIDs, e.g. {f1, f2}
          MaxEpoch,   \* bound on session number, keeps the model finite
          Design      \* "FailClosed" | "TrustStaleEvidence"

None == "none"

VARIABLES
  epoch,          \* current session/run number (0..MaxEpoch)
  admGrant,       \* grant admission accepted THIS epoch (or None)
  admFence,       \* fence admission accepted THIS epoch (or None)
  crashed,        \* BOOLEAN : volatile state lost, awaiting restart
  ev,             \* the (retained) evidence record
  accepted,       \* BOOLEAN : has a Result accepted evidence?
  staleAccept,    \* BOOLEAN (latched): accepted evidence whose epoch != session
  mismatchAccept  \* BOOLEAN (latched): accepted evidence not binding the admission

vars == << epoch, admGrant, admFence, crashed, ev, accepted,
           staleAccept, mismatchAccept >>

NoneRec == [grant |-> None, fence |-> None, ep |-> 0]

TypeOK ==
  /\ epoch \in 0..MaxEpoch
  /\ admGrant \in Grants \cup {None}
  /\ admFence \in Fences \cup {None}
  /\ crashed \in BOOLEAN
  /\ ev \in [grant : Grants \cup {None}, fence : Fences \cup {None}, ep : 0..MaxEpoch]
  /\ accepted \in BOOLEAN
  /\ staleAccept \in BOOLEAN
  /\ mismatchAccept \in BOOLEAN

Init ==
  /\ epoch = 0
  /\ admGrant = None
  /\ admFence = None
  /\ crashed = FALSE
  /\ ev = NoneRec
  /\ accepted = FALSE
  /\ staleAccept = FALSE
  /\ mismatchAccept = FALSE

\* Admission binds a grant + fence in the CURRENT epoch.
Admit ==
  /\ ~crashed
  /\ admGrant = None
  /\ \E g \in Grants, f \in Fences :
        /\ admGrant' = g
        /\ admFence' = f
  /\ UNCHANGED << epoch, crashed, ev, accepted, staleAccept, mismatchAccept >>

\* Measurement produces evidence binding the EXACT admitted grant/fence + epoch.
Measure ==
  /\ ~crashed
  /\ admGrant # None
  /\ ev' = [grant |-> admGrant, fence |-> admFence, ep |-> epoch]
  /\ UNCHANGED << epoch, admGrant, admFence, crashed, accepted,
                  staleAccept, mismatchAccept >>

\* Fresh = the evidence binds the current admission AND the current session.
Fresh(e) == e.grant = admGrant /\ e.fence = admFence /\ e.ep = epoch

\* A Result accepts evidence. FailClosed re-checks Fresh; the buggy design does not.
\* The latched booleans record any acceptance that was NOT fresh.
Accept ==
  /\ ~crashed
  /\ ~accepted
  /\ ev # NoneRec
  /\ \/ (Design = "FailClosed" /\ Fresh(ev))
     \/ (Design = "TrustStaleEvidence")
  /\ accepted' = TRUE
  /\ staleAccept'    = (staleAccept    \/ ev.ep # epoch)
  /\ mismatchAccept' = (mismatchAccept \/ ev.grant # admGrant \/ ev.fence # admFence)
  /\ UNCHANGED << epoch, admGrant, admFence, crashed, ev >>

\* A crash wipes VOLATILE admission state; the evidence object survives (the
\* adversary kept a copy). accepted + latched facts persist (durable result store).
Crash ==
  /\ ~crashed
  /\ crashed' = TRUE
  /\ admGrant' = None
  /\ admFence' = None
  /\ UNCHANGED << epoch, ev, accepted, staleAccept, mismatchAccept >>

\* Restart bumps the epoch (new session) and clears the crash. The retained `ev`
\* now carries a STALE ep < epoch.
Restart ==
  /\ crashed
  /\ epoch < MaxEpoch
  /\ epoch' = epoch + 1
  /\ crashed' = FALSE
  /\ UNCHANGED << admGrant, admFence, ev, accepted, staleAccept, mismatchAccept >>

Next ==
  \/ Admit \/ Measure \/ Accept \/ Crash \/ Restart
  \/ UNCHANGED vars   \* stutter: bounded model, no deadlock, no liveness obligation

Spec == Init /\ [][Next]_vars

---------------------------------------------------------------------------
\* L5 PROVENANCE: no Result ever accepted evidence that did not bind the exact
\* grant + fence of the admission in force at accept time.
L5_ExactBinding == ~mismatchAccept
\* L7 FAIL-CLOSED: no Result ever accepted evidence from a stale session --
\* survives crash + restart precisely because acceptance re-checks the epoch.
L7_NoStaleReplay == ~staleAccept

Inv == TypeOK /\ L5_ExactBinding /\ L7_NoStaleReplay

THEOREM FailClosedIsSafe == (Design = "FailClosed") => (Spec => []Inv)
===========================================================================
