-------------------------- MODULE EnforcementGate --------------------------
(*
  Ceremony Suite — the L3-gate under a fence that CHANGES over time (P0).
  Temporal companion to formal/Ceremony/P0/Boundary.lean, which proves the
  *static* case (the L3-gated brush default is an attenuation in the frozen
  algebra, no new law/axis). This module discharges the one genuinely-new
  obligation the sequencing decision introduces:

    the "OCAP two-stream sequencing" board note makes brush the confined
    default WHERE a kernel fence is active. But a fence can DROP between the
    moment a dynamic op is authorized and the moment it executes (kernel
    module unload, container reconfig, policy change). Spec I4 requires the
    check "at the moment it executes" — NOT cached from grant time.

  The model makes that requirement falsifiable. `CheckAtExec` toggles the two
  designs:

    CheckAtExec = TRUE   -> re-check the CURRENT fence at exec (I4-faithful).
    CheckAtExec = FALSE  -> trust the fence observed at grant time (the bug).

  Invariant NoAdvisoryDynamicExec: no containment-needing op ever actually runs
  while the fence is advisory (I9 "never overclaim" / I5 fail-closed, over
  time). TLC result:

    CheckAtExec = TRUE   -> []Inv holds (the sequencing is safe).
    CheckAtExec = FALSE  -> TLC exhibits the fence-drop TOCTOU counterexample
                            (authorize under kernel -> FenceDown -> Exec runs
                            advisory). This is the design the gate must NOT use.

  So: the L3-gated brush default is spec-faithful IFF enforcement re-checks the
  fence at exec. That conditional IS the confirmation — and names the exact
  thing Stream A must implement.
*)
EXTENDS Naturals

CONSTANT CheckAtExec           \* TRUE = I4-faithful (re-check at exec); FALSE = cache grant-time fence

VARIABLES
  fence,                       \* "advisory" | "kernel" : the CURRENT enforcement strength
  grantFence,                  \* "none" | "advisory" | "kernel" : fence seen when the pending dynamic op was authorized
  advisoryDynamicRan           \* BOOLEAN : did a containment-needing op ever actually run under an advisory fence?

vars == << fence, grantFence, advisoryDynamicRan >>

Fences == { "advisory", "kernel" }

TypeOK ==
  /\ fence \in Fences
  /\ grantFence \in (Fences \cup { "none" })
  /\ advisoryDynamicRan \in BOOLEAN

Init ==
  /\ fence \in Fences
  /\ grantFence = "none"
  /\ advisoryDynamicRan = FALSE

\* The fence strength can change under our feet at any time.
FenceDown == fence = "kernel"   /\ fence' = "advisory" /\ UNCHANGED << grantFence, advisoryDynamicRan >>
FenceUp   == fence = "advisory" /\ fence' = "kernel"   /\ UNCHANGED << grantFence, advisoryDynamicRan >>

\* Authorize a containment-needing (dynamic) op. Per the L3-gate, a dynamic op
\* is authorized only where a kernel fence is currently active; we record the
\* fence observed at grant time.
AuthorizeDynamic ==
  /\ grantFence = "none"
  /\ fence = "kernel"
  /\ grantFence' = fence
  /\ UNCHANGED << fence, advisoryDynamicRan >>

\* Execute the pending dynamic op. The gate consults either the current fence
\* (I4-faithful) or the cached grant-time fence (the bug), per CheckAtExec. It
\* proceeds only if that fence reads "kernel". `advisoryDynamicRan` records what
\* ACTUALLY happened at the kernel — which depends on the CURRENT fence, not the
\* one the gate consulted.
ExecDynamic ==
  /\ grantFence # "none"
  /\ LET checked == IF CheckAtExec THEN fence ELSE grantFence
     IN  checked = "kernel"                               \* the gate lets it through
  /\ advisoryDynamicRan' = (advisoryDynamicRan \/ (fence = "advisory"))
  /\ grantFence' = "none"
  /\ UNCHANGED fence

Next == FenceDown \/ FenceUp \/ AuthorizeDynamic \/ ExecDynamic

Spec == Init /\ [][Next]_vars

------------------------------------------------------------------------------
\* Invariant: a containment-needing op never actually runs advisory (I9/I5 over
\* time). Holds under CheckAtExec = TRUE; TLC finds a counterexample under FALSE.
NoAdvisoryDynamicExec == advisoryDynamicRan = FALSE

Inv == TypeOK /\ NoAdvisoryDynamicExec

\* Config: to see it PASS, run with CheckAtExec <- TRUE and check Inv.
\* To see the TOCTOU bug, run with CheckAtExec <- FALSE (Inv will fail with a
\* trace: AuthorizeDynamic; FenceDown; ExecDynamic).
THEOREM SafeWhenCheckedAtExec == (CheckAtExec = TRUE) => (Spec => []Inv)
=============================================================================
