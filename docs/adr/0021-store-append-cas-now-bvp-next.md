# ADR 0021 — Store append: CAS now, Byzantine Vertical Paxos next

- Status: **Accepted** — the steady-state append is **FROZEN** as
  compare-and-swap on the expected head (v0.3.1 PROTOCOL FREEZE, 2026-07-16);
  the Byzantine-Vertical-Paxos evolution is an **adopted roadmap**, **NOT
  normative** until it lands its own ADR + a TLA+/Lean safety model.
- Date: 2026-07-16
- Context: closes **OB-15** (Review 7, the v0.3.1 protocol freeze). Records the
  chain-store append arbitration decision that P2 §1.1 states normatively, and
  the sequenced evolution the README "Store roadmap" block adopts. Extends P2
  (Chain-Store Profile) §1.1/§4 and depends on P0 §2.0 (the `Effect × Assurance
  × Scope` product lattice) and P1 §4·5 (the domain-separation tuple, which is
  what makes `store_id`/`thread_id` a value the signature covers rather than
  prose). Also touches P4 §2 (the quorum records) and P4 §3 (recovery), because
  *replication* membership and *key-custody* membership are deliberately kept as
  two separate thresholds.
- Origin: the adversarial review that flagged the **honest-race hole** — under
  a naive "highest chain wins" or "different head at the same length ⇒
  equivocation" rule, two honest devices that each read a head, propose a
  successor, and race to append would be indistinguishable from an attacker
  forking the log. That is both a false-positive halt (a benign race trips
  L2·H1's fork alarm) and a latent safety gap (no defined winner). The freeze
  had to pick an arbitration rule *and* fix the definition of equivocation so
  the two stop being confused.

## Question

How should the authority chain-store arbitrate **concurrent appends** — now,
for the single-writer steady state, and later, as a store is served by more
than one node — without any of:

1. **re-opening the `P1 → P2 → P0` waist proof.** The provable MVP is that
   triple; the append rule must be simple enough that the P2 trusted-state
   machine (`untrusted_step_safe`, checkpoint monotonicity under `Extends`)
   compiles and refines to Rust via Aeneas *today*;
2. **mislabeling honest races as attacks.** A CAS-loser is a device retrying,
   not a Byzantine actor. Halting authority-minting on a benign race is a
   self-inflicted denial of service, and "availability is a security property"
   (P0 L2);
3. **committing prematurely to a consensus protocol** whose safety we have not
   yet modeled. The chain-store is *deliberately not a blockchain* (P2 §1) —
   no mining, tokens, leader election, or global total order — so whatever
   replaces threshold-1 must be a **reconfigurable replication** protocol we
   can prove, not a coin.

## Decision

### D1 — Freeze CAS-on-expected-head as the v0.3.1 steady-state append

The append operation is **compare-and-swap on the thread's expected head**
(P2 §1.1, FROZEN):

```
Append(expected_head, next)  commits next  iff  head(store_id, thread_id) == expected_head
                             otherwise the caller is a CAS-loser and RETRIES.
```

Single-writer / optimistic-concurrency; the **simplest** model that closes the
honest-race hole. `next` extends `expected_head` on the same `(store_id,
thread_id)` spine with `sequence` strictly greater (never a sibling) — the
forward-only ratchet's "extends" from P2 §1.1. This is the append rule the P2
Lean trusted-state machine is written against; nothing here needs a quorum, a
leader, or a clock (validity keys on generation counters, P1 §2 — wall-clock is
provenance, never coordination).

CAS is **not a lesser stand-in** for the eventual protocol — it is the
**threshold-1 steady-state case** of it (D3). Freezing it lets the waist be
proven now without foreclosing the evolution.

### D2 — Refine equivocation: candidates and CAS-losers are NOT malicious

This refinement is **load-bearing regardless of the append model** and survives
verbatim into the reconfigurable world:

- a concurrent **candidate** record (an honest device proposing a successor to a
  head it just read) is **NORMAL**;
- a **CAS-loser** (a candidate that lost the race to commit a parent) is
  **BENIGN** — it retries; it is *never* evidence of misbehavior;
- **equivocation** is *two records both **committed** at the same `(store_id,
  thread_id, sequence)` with different CIDs* — a genuine double-commit / fork,
  not a race a writer lost.

This aligns the append rule with P2 §4's anti-rollback layering: "fork = proof
of misbehavior" (§4 layer 3) applies **only at the certified frontier** — a
quorum-certified head, or one voter's conflicting certification votes.
Concurrent candidates and CAS-losers can never equivocate because neither is
committed at the certified layer. Confusing the two is exactly the DAG error P2
§1 warns against (two heads at equal depth may be *legitimate* concurrent
descendants); the authority projection is a linear spine per causal thread, so
"one accepted successor at `n+1`" is a property of *commitment*, not of
*proposal*.

### D3 — Adopt the roadmap: CAS → vertically-reconfigurable replication

**Adopted sequencing (author's call):** prove the `P1 → P2 → P0` waist on CAS
first; **then** evolve P2 to separate a lean **steady-state** protocol from a
stronger **reconfiguration** mechanism. The separation is the core idea of
**Vertical Paxos** (Lamport-Malkhi-Zhou, PODC 2009) and its Byzantine
hardening, **Byzantine Vertical Paxos** (Abraham & Malkhi, IBM Zurich DCCL): an
auxiliary reconfiguration authority resolves *which configuration is active*, so
the ordinary read/write path can use **small quorums** while the expensive,
rare work is confined to reconfiguration.

The reconfiguration primitive is **the wedge**:

```
1. FENCE the active configuration      (stop it accepting new commands — "wedge")
2. CAPTURE a safe CLOSING STATE        (preserve every acknowledged-but-partial
                                        command decided in the old config)
3. CERTIFY the next configuration      (quorum-sign the config transition)
4. RESUME under the new configuration
```

CAS is the degenerate wedge: a threshold-1 configuration whose "reconfiguration"
is trivial. Everything the freeze proves about the CAS steady state is the
`f = 0`/threshold-1 slice of the reconfigurable machine, so the evolution is
**additive**, not a rewrite — the same `AuthorityCheckpoint (store_id,
thread_id, sequence, head)` anchor, the same `Extends` order, the same D2
definition of equivocation.

### D4 — The two-node story (`f+1` steady / `2f+1` reconfiguration + a state-light witness)

The target deployment shape mirrors P2/P3's solo-user **n = 2 device world**
(each enrolled device is the other's witness; the same k-of-n substrate as
revocation, reused):

- **Steady state runs on `f+1` full nodes.** With `f = 1` that is the **two
  enrolled devices** — both hold the full transcript and serve the ordinary
  append/read path with a small quorum. This is what VP buys: the common case
  does not pay majority-quorum cost.
- **Reconfiguration needs `2f+1` participants.** With `f = 1` that is three —
  the two full nodes plus a **state-light witness** that participates *only* in
  the wedge (fencing + certifying the next configuration) and does **not** carry
  the full log. A phone, a cheap always-on box, or a cloud attestation node can
  be the witness; it holds configuration/certification state, not history.
- **Safe failover.** If one full node is lost, the survivor plus the witness can
  reconfigure to a new pair without losing any acknowledged command (D3 step 2)
  and without a human racing to re-pin. This is the failover the frozen CAS
  store cannot do — under CAS a lost sole writer is a manual recovery event.

The exact fault-model quorum arithmetic (crash vs. Byzantine; whether the
Byzantine steady path is `f+1` with an honest reconfiguration authority or a
larger bound) is **pinned by the wedge ADR's TLA+ model, not asserted here**
(D7). The shape — *small steady quorum, larger quorum only at reconfiguration,
a witness that is heavy on trust and light on state* — is what is adopted.

### D5 — Key custody is a SEPARATE threshold (Shamir), not the replication quorum

**Do not conflate the replication configuration with the signing quorum.** They
answer different questions:

- the **replication configuration** answers *which nodes order and commit
  records* (the wedge quorum, D3/D4);
- **key custody** answers *who may sign authority* — the principal root and its
  loosening entries (P4 §1–2).

The signing key MAY be **Shamir-split** across a custody set that is
**independent** of the replication membership: a node can be in the active
configuration (it commits records) without holding a key share (it cannot mint
authority), and a Shamir share-holder can be offline and out of the
configuration entirely. Keeping the two thresholds orthogonal means a
compromise of the *replication* fabric cannot forge a signature, and a
reconfiguration cannot silently change *who can authorize* — that remains a
quorum-gated change to authority-generating structure under **P0 L2** (equality,
OB-16: sub-quorum actors can neither shrink **nor add** trusted structure). The
state-light witness (D4) is the clean example: it votes on configuration, holds
no key share, mints nothing.

### D6 — The partition-authority ceiling becomes operation-sensitive on the §2.0 lattice

Under the reconfigurable store, a node that can reach its steady-state quorum but
**not** a reconfiguration quorum (a partition) is not simply up-or-down. Its
authority **ceiling attenuates componentwise on the P0 §2.0 `Effect × Assurance
× Scope` lattice**: it may keep serving low-`Scope` operations within its fenced
configuration (e.g. `once`/`session`) while **`durable` scope and any structural
change** — anything that alters authority-generating structure — require a
certified reconfiguration and are therefore **denied** under partition
(fail-closed, L3). This is the honest, operation-sensitive version of "the store
is available": the ceiling degrades along the axes, `granted ⊑ ceiling` still
holds (L4), and the degradation is ⊑-monotone. CAS today is the flat case (a
sole writer's ceiling is its policy ceiling; a partition just stalls the
retry).

### D7 — The wedge / closing-state is NOT normative until its own ADR + TLA+/Lean

Explicitly out of the v0.3.1 freeze. Before any part of D3–D6 becomes normative
it must land:

- **its own ADR** (the "wedge / closing-state" decision — expected next in the
  ADR sequence), specifying the fault model, the exact quorum sizes, the
  fencing mechanism, the closing-state capture, and the configuration-transition
  record format;
- **a TLA+ model** of the wedge (fence → capture → certify → resume) proving
  the safety invariant — **no acknowledged command is lost across a
  reconfiguration, and no two configurations are simultaneously live** — under
  crash and then Byzantine faults;
- **a Lean extension** of the P2 trusted-state machine showing the reconfigurable
  transitions still satisfy `untrusted_step_safe` and checkpoint monotonicity
  under `Extends` (the CAS proof is the threshold-1 instance it must subsume).

Until those exist, implementations build to **D1 (CAS)** and **D2 (the refined
equivocation)** only. D2 is normative now *because it is append-model-independent*;
D3–D6 are the **adopted direction**, cited so implementers do not paint the CAS
store into a corner (e.g. by hard-coding "one writer forever" or by treating a
candidate as an attack).

## Consequences

- **The waist is provable today.** CAS is simple enough that the P2 Lean
  trusted-state machine and its Aeneas refinement do not wait on a consensus
  proof. The `P1 → P2 → P0` MVP proceeds on threshold-1.
- **Honest races never trip the fork alarm.** D2 makes L2·H1's
  proof-of-misbehavior escalation fire only at the certified frontier, so a
  two-device solo user racing two candidates gets a retry, not a `CHAIN HISTORY
  REGRESSION` halt. This is also what P0 §3's attest transaction relies on
  ("a fork is P2 proof-of-misbehavior, never a branch to silently adopt" —
  checked per causal thread so concurrent threads never false-trip).
- **The evolution is additive.** Because CAS is the threshold-1 slice of the
  reconfigurable machine and D2 is invariant across both, the BVP work extends
  P2 rather than replacing it — same anchor, same `Extends`, same equivocation
  definition.
- **Two full nodes get real failover — later.** The frozen store cannot fail
  over a lost sole writer without human recovery; the adopted roadmap gives the
  n=2 device world safe failover via a state-light witness, at the cost of the
  wedge machinery, once D7's proofs land.
- **Custody stays decoupled from replication.** Shamir key-custody as a separate
  threshold (D5) means neither growing the replication configuration nor losing
  a replica changes *who can sign* — authority structure remains quorum-gated
  under L2.
- **No blockchain.** The roadmap is reconfigurable *replication*, not consensus
  by mining or a global order (P2 §1). The reference points are BVP / VP, not a
  ledger coin.

## Alternatives considered

- **"Highest chain wins" / longest-log.** Rejected: this is the honest-race hole
  itself — a truncated-or-forked-but-internally-valid log can be *longer*, and
  two honest candidates at equal length are indistinguishable from a fork
  (P2 §1, §3 finding #1). Length is not authority.
- **"Different head at the same `sequence` ⇒ equivocation."** Rejected: false on
  a branching Conversation Graph and false for CAS races — it halts on benign
  concurrency (D2). Equivocation is *committed* double-spend at the certified
  layer, not divergent *proposals*.
- **Last-writer-wins (overwrite the head).** Rejected: silently drops an
  acknowledged commit — the exact safety loss the closing-state capture (D3
  step 2) exists to prevent. Unacceptable for an authority transcript.
- **Jump straight to full BVP now.** Rejected: its safety is unproven in our
  setting; adopting it before the TLA+/Lean model (D7) would block the waist
  proof on a much larger obligation and violate law-minimalism ("the algebra
  decides the count; ambition doesn't", P0 §7). CAS-first is the sequenced path.
- **Majority-quorum steady state (ordinary multi-Paxos / a BFT SMR in the hot
  path).** Rejected as the *steady-state* rule: the whole point of the Vertical
  Paxos separation is that the common path uses **small** quorums while a
  separate reconfiguration authority does the expensive work rarely. Paying
  majority cost on every append is the opposite of the n=2 solo-user ergonomics
  P2/P3 target.
- **Leader election / a coordinator service.** Rejected as a permanent primitive:
  it reintroduces the blockchain-shaped machinery P2 §1 explicitly excludes. The
  reconfiguration authority in VP/BVP is a *rare-path* config master, not a
  hot-path leader, and can itself be the state-light witness (D4).
- **One key threshold = the replication threshold.** Rejected (D5): conflating
  custody with replication lets a fabric compromise forge signatures and lets a
  reconfiguration silently move "who can authorize." Shamir custody stays a
  separate threshold.

## Tracking

- **Steady-state append (D1) + refined equivocation (D2):** normative in P2 §1.1
  (v0.3.1 freeze). No further work — proven with the `P1 → P2 → P0` waist.
- **The wedge / closing-state ADR (D7):** the *next* decision in this sequence —
  fault model, quorum sizes, fencing, closing-state capture, config-transition
  record. **Blocks** any normativity for D3–D6.
- **TLA+ model (D7):** wedge safety (no acknowledged command lost across
  reconfiguration; at most one live configuration) under crash then Byzantine
  faults. To live beside the profiles (no `.tla` in the tree yet — this ADR is
  the forcing function).
- **Lean extension (D7):** the reconfigurable P2 trusted-state machine subsuming
  the CAS threshold-1 proof (`untrusted_step_safe`, checkpoint monotonicity).
- **Deployment (D4):** the n=2 + state-light-witness topology reuses the P3/P4
  enrollment + k-of-n substrate; the witness is a P4 role that votes on
  configuration and holds no key share (D5).

## References

- **Byzantine Vertical Paxos — Ittai Abraham & Dahlia Malkhi (IBM Zurich DCCL).**
  The Byzantine hardening of the VP separation; the reference for the
  reconfigurable-replication target.
- **Vertical Paxos and Primary-Backup Replication — Leslie Lamport, Dahlia
  Malkhi, Lidong Zhou, PODC 2009.** The origin of separating small-quorum
  steady-state from a reconfiguration authority, and of the wedge/read-out on
  reconfiguration.
- Adi Shamir, *How to Share a Secret*, CACM 1979 — the separate key-custody
  threshold (D5).
- P2 (Chain-Store Profile) §1.1 (CAS + refined equivocation, FROZEN), §4 (the
  external anti-rollback anchor; fork = proof-of-misbehavior at the certified
  layer), §1 (linear authority spine; deliberately not a blockchain).
- P0 (Ceremony Contract) §2.0 (the `Effect × Assurance × Scope` product lattice
  the partition ceiling attenuates on), L2/L4 (structural equality; attenuation),
  §3 (the CAS attest transaction; per-thread fork check).
- P1 (Signed-Object) §2/§4·5 (`STORE_ID_SELF` genesis; the domain-separation
  tuple that makes `(store_id, thread_id)` signature-covered).
- P4 (Identity Lifecycle) §2 (quorum records) and §3 (recovery) — the k-of-n
  substrate the witness/reconfiguration quorum reuses.
- Schneier-Kelsey (1999); FssAgg (eprint 2008/185); RFC 6962 (CT Signed Tree
  Heads / monotonicity); TUF — the canon for what a hash-chained log does and
  does not buy (P2 §3).
- **OB-15** (Review 7, the v0.3.1 PROTOCOL FREEZE) — the finding this ADR
  discharges; README "Store roadmap (adopted): CAS → Byzantine Vertical Paxos".
