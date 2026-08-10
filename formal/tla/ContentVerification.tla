--------------------------- MODULE ContentVerification ---------------------------
(*
  #137 / the VERIFICATION surface — why a CID is only load-bearing when it is
  RE-CHECKED, not merely computed. (Shawn: "a CID that isn't utilized to validate
  the payload and verify the protocol is a major gap.")

  A security object crosses a boundary (deserialize off the wire / resolve a
  referenced parent / receive over the mesh) carrying a CLAIMED content id. An
  adversary can TAMPER: post a payload whose bytes do NOT match the claimed id
  (a narrow-looking claim over a wide-authority payload). Content addressing is
  only a defense if the receiver RECOMPUTES the id and rejects on mismatch:

      Cid(a) = Cid(b)  <=>  a = b            (injective content hash)
      accept  =>  Cid(payload) = claimedCid  (verify-on-receive)

  `Design` toggles the two receivers:

     "VerifyOnReceive" -> accept iff Cid(payload) = claimedCid
                          (content-addressable's ensure_content_id; envelope.rs:119
                          "payload_cid mismatch"). The tamper is REJECTED.
     "TrustClaimedId"  -> accept without recomputing (the gap: a CID that is
                          computed and stored but never checked). The adversary's
                          tampered payload is ACCEPTED under a false identity.

  Objects stand for authority payloads: `oNarrow` = a narrow authorized scope,
  `oWide` = a wider one. Accepting oWide under a claim of oNarrow is exactly the
  attack the whole content-addressed layer exists to make impossible.

  TLC:
     Design = "VerifyOnReceive" -> []Inv holds.
     Design = "TrustClaimedId"  -> counterexample: claimedCid=oNarrow, payload=oWide
                                   accepted -> NoForgedIdentity fails.
*)

CONSTANTS Objects,   \* payload value space, e.g. {oNarrow, oWide}
          Design     \* "VerifyOnReceive" | "TrustClaimedId"

\* An INJECTIVE content hash: identity = value, so Cid(a)=Cid(b) <=> a=b.
Cid(o) == o

VARIABLES
  claimedCid,   \* the content id the message CLAIMS (an element of Objects)
  payload,      \* the actual payload the message CARRIES (an element of Objects)
  received,     \* BOOLEAN : has the boundary processed the message?
  accepted      \* BOOLEAN : did the receiver accept it as authentic?

vars == << claimedCid, payload, received, accepted >>

TypeOK ==
  /\ claimedCid \in Objects
  /\ payload    \in Objects
  /\ received   \in BOOLEAN
  /\ accepted   \in BOOLEAN

\* An honest sender OR a tampering adversary posts a message: any claimed id over
\* any payload (a mismatch is a tamper). The boundary starts unprocessed.
Init ==
  /\ claimedCid \in Objects
  /\ payload    \in Objects
  /\ received = FALSE
  /\ accepted = FALSE

Receive ==
  /\ ~received
  /\ received' = TRUE
  /\ \/ (Design = "VerifyOnReceive" /\ accepted' = (Cid(payload) = claimedCid))
     \/ (Design = "TrustClaimedId"  /\ accepted' = TRUE)
  /\ UNCHANGED << claimedCid, payload >>

\* Terminal state stutters (no liveness obligation).
Next == Receive \/ (received /\ UNCHANGED vars)
Spec == Init /\ [][Next]_vars

-------------------------------------------------------------------------------
\* The verification law: nothing accepted under a content id it does not match.
\* A CID is only a defense when this holds -- and it holds ONLY if the receiver
\* recomputes and compares (Design = "VerifyOnReceive").
NoForgedIdentity == accepted => (Cid(payload) = claimedCid)

Inv == TypeOK /\ NoForgedIdentity

THEOREM VerifyOnReceiveIsSafe == (Design = "VerifyOnReceive") => (Spec => []Inv)
===============================================================================
