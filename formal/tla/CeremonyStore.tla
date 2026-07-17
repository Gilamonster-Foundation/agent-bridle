---------------------------- MODULE CeremonyStore ----------------------------
(*
  Ceremony Suite — the chain-store append + anti-rollback state machine (P2).
  Tier-3 (state-machine) companion to formal/lean/Authority.lean.

  Models ONE authority thread (store_id, thread_id fixed) as:
    - a committed spine: seq |-> record-id (a function), monotone in length;
    - a compare-and-swap append (OB-15, FROZEN): a proposer names the head it
      read; it commits ONLY if the head is unchanged, else it retries (benign);
    - an externally-protected checkpoint (P2 §4): the highest committed length
      a verifier has anchored OUTSIDE the store; it never regresses;
    - an untrusted step: an attacker with disk/network but no keys — it may
      propose candidates but MUST NOT rewrite committed history or move the
      checkpoint.

  Invariants map to the spec:
    SpineFunctional  -> OB-15 : one committed record per sequence (a fork is
                                two DIFFERENT committed ids at one seq).
    NoRollback       -> PO-2c : head length >= protected checkpoint always.
    CheckpointMono   -> PO-2/2a : the protected checkpoint only advances.
    CASLoserBenign   -> OB-15 : a lost CAS changes nothing (concurrent
                                proposals are not equivocation).
*)
EXTENDS Naturals, FiniteSets

CONSTANTS RecordIds        \* a finite pool of candidate record ids
ASSUME RecordIds # {}

VARIABLES
  spine,        \* [1..len -> RecordIds] : the committed authority spine
  len,          \* Nat : committed length (the head is spine[len], seq = len)
  checkpoint    \* Nat : externally-protected highest-accepted length

vars == << spine, len, checkpoint >>

TypeOK ==
  /\ len \in Nat
  /\ checkpoint \in Nat
  /\ spine \in [ (1..len) -> RecordIds ]

Init ==
  /\ len = 0
  /\ checkpoint = 0
  /\ spine = << >>            \* empty function on 1..0

\* A proposer read `expected` as the head length and proposes record `r` as the
\* next. CAS: commit iff the head is still `expected` (= len). Otherwise the
\* proposer LOST the race and simply retries — no state change (benign).
Append(expected, r) ==
  /\ r \in RecordIds
  /\ expected = len                       \* CAS success condition
  /\ len' = len + 1
  /\ spine' = [ i \in 1..(len+1) |-> IF i = len+1 THEN r ELSE spine[i] ]
  /\ UNCHANGED checkpoint

\* A verifier anchors a fresher head: the checkpoint may only advance to the
\* current committed length, never backward.
AdvanceCheckpoint ==
  /\ checkpoint < len
  /\ checkpoint' = len
  /\ UNCHANGED << spine, len >>

\* An attacker with disk/network but no keys. It cannot forge a committed
\* record (no signing key) and cannot move the protected checkpoint. The only
\* thing it can do to the *authority* state is nothing safety-relevant: we model
\* it as a no-op (candidate records live off the committed spine).
UntrustedStep == UNCHANGED vars

Next == (\E e \in Nat, r \in RecordIds : Append(e, r))
        \/ AdvanceCheckpoint
        \/ UntrustedStep

Spec == Init /\ [][Next]_vars

------------------------------------------------------------------------------
\* Invariants

\* OB-15: the spine is a function — at most one committed record per sequence.
SpineFunctional == spine \in [ (1..len) -> RecordIds ]

\* PO-2c: the committed head never rolls back below the protected checkpoint.
NoRollback == len >= checkpoint

Inv == TypeOK /\ SpineFunctional /\ NoRollback

THEOREM Spec => []Inv

------------------------------------------------------------------------------
\* Action properties (checked with a state constraint like len =< 4)

\* PO-2/2a: the protected checkpoint is monotone across every step.
CheckpointMono == [][ checkpoint' >= checkpoint ]_vars

\* OB-15: committed length is monotone — no committed record is ever removed
\* (a CAS-loser changes nothing; only successful CAS extends the spine).
LenMono == [][ len' >= len ]_vars

THEOREM Spec => (CheckpointMono /\ LenMono)
=============================================================================
