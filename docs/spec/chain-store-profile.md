# P2 — Chain-Store Profile

**Layer:** 1. **Depends on:** P1 (Signed-Object).
**Depended on by:** P0 (L2), P3, P4, P5.
**Status:** DRAFT. **Teeth:** a Lean trusted-state-machine
(`untrusted_step_safe`, checkpoint monotonicity) refined to Rust by Aeneas
(Tier 3) — this is the heart of GPT-5 #232's §8–9.
**Owns:** durable, tamper-evident, **rollback-resistant** history — and the
honest statement of what the hash chain does and does not buy.

## 1. Conversation is a jungle; authority is a railway (OB-2)

Records are `MerkleNode<T>` (P1). The wider **Conversation Graph**
(agent-mesh#67) is a genuine Merkle DAG — branches (parallel agents) and
merges (accepted synthesis) are first-class. But a branching DAG **cannot**
be checkpointed by a scalar `(length, head)`: two heads at equal depth can
be *legitimate* concurrent descendants, so "different heads at the same
length ⇒ equivocation" is false for a DAG.

The resolution: **the authority projection is a linear spine per causal
thread.** The conversation may branch and merge freely; branches must
**merge before producing the next authority record**, so the sequence of
authority records along one thread is totally ordered.

```rust
struct AuthorityCheckpoint {   // the protected anchor state (P2 §4)
    store_id:   StoreId,       // normative, cryptographically bound (OB-6)
    thread_id:  ThreadId,      // one causal authority thread
    sequence:   u64,           // dense per (store_id, thread_id)
    head:       LineCid,
}
```

Normative definitions:
- **`store_id`** — a content-addressed identifier of the store's genesis
  (its root record's CID); every signed record's domain tuple binds it
  (P1 §4·5), so a record cannot be replayed into a different store.
- **`thread_id`** — the identifier of one authority thread within a store; a
  causal thread is the totally-ordered sequence of authority records a
  single principal-scope advances. A thread MAY be forked (declared) and
  merged (a record naming multiple thread parents), but **within a thread,
  `sequence n` has exactly one accepted successor at `n+1`.**
- **`length`/`sequence`** — the dense per-thread record count, *not*
  longest-path depth.

**Equivocation, now well-defined:** two validly-signed records for the same
`(store_id, thread_id, sequence)` with different CIDs are incontestable
proof of misbehavior (§4). This is the branching-safe restatement of the CT
fork rule.

"Extends" for the ratchet means: the presented head's thread reaches the
protected `(thread_id, sequence, head)` as a strict-ancestor prefix — a
*forward extension of the same spine*, never a sibling. This chain-store is
the authority projection of the Conversation Graph — same `MerkleNode<T>`
structure, payload `T` = authority records here, conversation records there.
Deliberately *not* a blockchain: no mining, tokens, leader election, or
global total order.

*(Alternative considered and rejected as harder to reason about: a
frontier-based checkpoint `{store_id, frontier: Set<LineCid>}`. The linear
spine is chosen for provability; revisit only if genuine concurrent
authority within one thread becomes a requirement.)*

## 2. Two CIDs per record

```
c_i    = H(canon(record_i ∖ sig))     content-CID   (what is signed)
s_i    = Sign(k, c_i)                  the signature
line_i = record_i ∪ { sig: s_i }       the full at-rest line
ℓ_i    = H(canon(line_i))              line-CID      (what parents reference)
parents(record_{i+1}) ∋ ℓ_i           descendants commit to content AND sig
```

Parents reference the **line-CID** — the full predecessor *including its
signature* — so stripping or swapping a historical signature breaks the
chain as surely as editing content.

**At rest:** JSONL as a lossless line-oriented view of the canonical
DAG-CBOR records — one `line_i` per line, human-auditable, no comment
affordances to make canonicalization ambiguous. CIDs/sigs are always over
the canonical form, never the view.

## 3. What the chain buys — and what it does not

**Interior integrity (PO-2a).** Editing or removing an *interior* record
orphans every descendant's parent link — it verify-fails loudly **against a
head the verifier already trusts.** This extends detection to
{add, delete, reorder} of the interior and retires the flat-file
known-limit (policy.rs #226).

**What the chain alone does NOT do (finding #1).** Verification is always
*relative to a head*. An attacker who also controls the head can truncate
the tail, or present a wholly older / forked-but-internally-valid log; the
surviving prefix verifies and nothing is orphaned. This is the established
limit of every hash-chained log — Schneier-Kelsey (1999), FssAgg (eprint
2008/185), and the reason Certificate Transparency needs gossiped Signed
Tree Heads (RFC 6962). **Tail and fork integrity require §4's external
anchor, not the chain.** An anti-rollback claim resting on an in-chain
record is circular — it rolls back with the log it certifies.

## 4. The anti-rollback anchor (external, load-bearing for L2·H1)

Closing tail-and-fork requires state the attacker does not control. Three
canonical layers, ascending assurance:

1. **Independently-protected monotonic head (REQUIRED).** Each participant
   remembers — in storage *separate from the log* — the highest
   `AuthorityCheckpoint` `(store_id, thread_id, sequence, head)` it has
   accepted per thread (§1), and MUST reject any presented head that is not
   a forward extension of the *same spine* — never a lower `sequence`, a
   different store, or a sibling (TUF:
   *"clients MUST NOT replace metadata with a version less than the one
   currently trusted"*; RFC 6962 monotonicity). Defeats truncation and
   rollback for that participant. **Where it lives is normative** (§6):
   device keystore / hardware monotonic counter (TPM) / witness quorum /
   separately-protected checkpoint. *"On disk beside the log" does NOT
   qualify.*
2. **Witness cosigning (RECOMMENDED for shared stores).** The head is
   periodically countersigned by witnesses (the `AuditRecord`s of P4/P0,
   **exported off-chain**). A participant accepts a head only with a witness
   cosignature no older than its freshness policy (CT gossip / STH). Defeats
   *secret* equivocation: to fool a victim the attacker must fork the
   witnesses too.
3. **Fork = proof of misbehavior (REQUIRED).** Two validly-signed records
   for the same `(store_id, thread_id, sequence)` with different CIDs are
   incontestable evidence of equivocation (§1; the branching-safe restatement
   of RFC 6962). Implementations MUST halt authority minting from that store
   and escalate — never silently pick one. (Legitimate concurrent
   *conversation* branches are not equivocation; they merge before the next
   authority record, so they never collide on a `sequence`.)

For a solo user (P3's n=2 world) the monotonic head lives on each enrolled
device and each device is the other's witness — the same k-of-n substrate
as revocation, reused. A quorum/witness set is the enterprise instance of
the identical mechanism. **Nothing here trusts the storage medium**; the
anchor is trusted state a participant carries into each verification,
exactly as `pinned` is.

## 5. The trusted state machine (the Lean model)

The kernel over this store is a state machine with `trustedHead:
Checkpoint` outside the store. Transitions:

- **untrusted step** (anything an attacker with disk/network but no keys
  can do): MUST NOT widen authority, add/remove trusted identities, or
  rewrite the checkpoint — `untrusted_step_safe`.
- **sync/reload**: MAY advance the checkpoint only when the candidate
  `Extends` the current one; MUST reject a strict ancestor or unrelated
  fork.

Theorems (Tier 3): accepted checkpoints are monotonic under `Extends`; a
strict ancestor is rejected; rollback detection is conditional on the
checkpoint staying outside the attacker-controlled store.

## 6. Proof obligations

| PO | Statement | Tier |
|---|---|---|
| PO-2a | interior deletion/replay rejected vs. a trusted head | 3 |
| PO-2c | tail truncation + fork rejected vs. the external anchor (not merely detected later) | 3 |
| — | (`untrusted_step_safe`; checkpoint monotonicity under `Extends`) | 3 |

PO-2 (⊑-monotony under H1) and PO-2b (load-bearing set) live in P0/P4 but
*depend on* this profile discharging H1's rollback half.

## Relations
- P1 (Signed-Object) — CIDs, canonical form, deterministic sig
- agent-mesh#67 — the Conversation Graph this projects from
- GPT-5 PR #232 §8–9 — the Lean trusted-state-machine formulation
- RFC 6962, TUF, Schneier-Kelsey, FssAgg (eprint 2008/185) — the canon
