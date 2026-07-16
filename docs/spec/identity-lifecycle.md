# P4 — Identity Lifecycle

**Layer:** 2. **Depends on:** P1 (Signed-Object), P2 (chain-store), P0
(L2, L5). **Implements** P0's abstract contracts `AttestEvidence` and
`ValidAssociationProof` (OB-1) — the waist stays acyclic because *P4
depends on P0*, never the reverse.
**Status:** DRAFT. **Teeth:** Lean (quorum k-of-n soundness; non-regression
of the load-bearing set, PO-2b) + a **conditional liveness** obligation
(PO-R, §3). Tier 3.
**Owns:** roles and delegation, the durable identity records, quorum
revocation, and — required, not optional — break-glass and succession.

## 1. Roles (one identity model, four roles)

Every participant is a fingerprint; roles differ only in *what they sign*:

| Role | Holds | Signs |
|---|---|---|
| **Principal** | root keypair (vault/hardware) | issuance of agent/surface certs; durable loosening entries |
| **Agent** | keypair chained to a principal | envelopes, requests, delegations |
| **Surface** | keypair chained to a principal — possibly nothing else (a no-compute device is keypair + renderer) | its `Decision`s and `AttestationRecord`s |
| **Gate** | the enforcement identity (usually = its agent) | chain-store appends |

A monolith (newt carrying bridle + mesh in-process) is the **degenerate
case**: one fingerprint, all roles. Delegation is the roles splitting into
separate keypairs. In-process surfaces MAY omit signing decisions; **remote
surfaces MUST sign** (attributable provenance).

**Delegation** (agent → agent): both endpoints present chains to a **common
pinned principal** (L5). The root key is involved at **issuance, not
per-delegation** — headless fleets verify chains offline while the root
stays in hardware; revocation is a generation bump. Cross-principal
delegation is two principals pinning each other's roots (L5, one level up).
Shipped as mesh `CertChain::verify` + PoP-to-certify (#39/#40).

## 2. Durable records

### PinRecord / GrantRecord
```json
{ "parents": ["cid:…"],            // line-CIDs (P2); ⌀ only for genesis
  "payload": { "v": 1, "fingerprint": "b3:…", "pubkey": "ed25519:…",
    "channel": "qr", "caveats": [ … ],          // the granted meet
    "decision": { "grant": { "verb": "pin", "scope": "always" } },
    "presence": { "kind": "passkey", "discharge": "…" },   // §5
    "granted_at": "…" },                          // provenance, not validity
  "sig": "ed25519:…" }
```
A pin is created only by a bound-surface `grant` or a pre-pinned policy
entry (a signed loosening entry, L2).

### AuditRecord / AttestationRecord
An **AuditRecord** witnesses the chain head (`witnessed_head`, `fingerprint`,
`presence`); exported off-chain it becomes a P2 §4 anchor — in-chain alone
it anchors nothing. An **AttestationRecord** is the concrete implementation
of P0's `AttestEvidence` contract (OB-1) — its authorization-bearing
sibling: one presence signature, two distinct statements. **Authorization:**
`request_cid`, `decision_cid`. **History witness:** `previous_checkpoint`
and `observed_checkpoint`, each a P2 `AuthorityCheckpoint` `(store_id,
thread_id, sequence, head)` — not a bare CID, so the witness names *which
spine* it advanced (OB-2). Acceptance requires `observed_checkpoint` to be a
forward extension of `previous_checkpoint` on the same `(store_id,
thread_id)` spine, `sequence` strictly greater (else CHAIN HISTORY
REGRESSION). It binds the canonical challenge preimage of P0 §3 and is
committed by that section's CAS transaction. Attest and audit stay distinct
but co-signed — *no authorization floats free of the history that gave it
meaning.*

### RevocationRecord (quorum)
```json
{ "v": 1,
  "payload": { "revoke": "b3:…", "reason": "compromise|rotation|retirement",
               "succession": "b3:…", "policy": "cid:…" },   // CANONICAL UNSIGNED
  "signers": [ { "by": "b3:aa…", "sig": "…" },
               { "by": "b3:cc…", "sig": "…" } ] }           // sorted, deduped
```
**One payload, many detached signatures** — every signer signs
`content-CID(payload)`, so all cover identical bytes (a signature nested in
the object it signs is circular). `signers` is sorted by `by` and
deduplicated (one identity can't count twice toward `k`); the signature set
is *not* signed; the chain-append `sig` (WF-2) is separate and last.
Acceptance is **epoch-bound (OB-7):** `|distinct valid signers ∩ eligible|
≥ k` under `policy`, **and** `policy` MUST be the policy active at the
record's own checkpoint —
```
policy_cid == ActiveRevocationPolicy(revoke_target, observed_checkpoint, generation)
```
— else an attacker replays an older, weaker, validly-signed quorum policy.
Policy *transitions* are themselves authorized under the previously-active
policy (or a separately-defined root-transition rule). The quorum policy is
a principal-signed loosening entry (defining *who may revoke* is authority
structure, L2).

**Enrollment records the exact required revocation predicate, not a strength
tuple (OB-7).** The enrollment strength tuple `(SAS entropy × rounds,
witnesses, presence)` is **not totally ordered** — "2 rounds + 1 witness +
hardware" is incomparable to "1 round + 3 witnesses + no hardware" — so
"punting ≥ pinning" cannot be derived from it after the fact. Instead each
PinRecord names, at enrollment time, the *precise* `RevocationPolicy` CID
required to later punt this identity. Revocation compares against that
recorded predicate, never an informal ordering.

## 3. Break-glass & succession (REQUIRED)

A quorum strong enough to defeat a hostile revocation can also lock out a
legitimate owner who loses `k` keys — availability cuts both ways. So
enrollment MUST provision recovery:

- a **pre-enrolled recovery factor** (offline hardware key / printed share)
  counted in `n`;
- a **succession path** transferring a principal root to a new key under
  quorum, *or* **time-delayed unilateral recovery** — a self-revocation any
  single device can start that only takes effect after a published
  generation delay, giving co-signers a veto window ("social recovery with
  timelock").

Revoking the **last** root without a `succession` ends the mesh —
implementations MUST refuse unless the record carries `"tombstone": true`.

**PO-R is CONDITIONAL liveness (OB-8).** "Never permanently locked out"
cannot be proven unconditionally — all recovery factors can be destroyed,
all witnesses can vanish, an adversary can block progress forever. State the
theorem with its assumptions:
> **Given** at least one configured recovery threshold remains uncompromised,
> eventual communication among an authorized recovery quorum, fair
> advancement of recovery generations, and no permanent destruction of all
> recovery material — **then** a legitimate owner can eventually install a
> successor root.

The time-delayed unilateral path has a specific threat to answer: an attacker
who owns *one* device and **suppresses the veto messages** during the delay
window. Mitigations (each recorded, not assumed): require the veto window to
be acknowledged over ≥ 2 independent channels; make a *missing* expected
acknowledgement itself veto-the-recovery (fail-closed on silence); and cap
unilateral recovery to below the quorum needed for high-ceiling authority.
This subsystem is **required and specified conditionally**; the full
state-machine is P4's open work — the suite does not claim it closed.

## 4. Presence-attested pins
A pin MAY carry a `presence` discharge — a WebAuthn/passkey step-up bound to
the pin's `ContentId` (`DischargeVerifier`; PR #214). Upgrades first contact
from "someone clicked" to a hardware-attested human decision. Optional by
law, recommended for broad-ceiling pins.

## 5. Proof obligations

| PO | Statement | Tier |
|---|---|---|
| PO-2b | a sub-quorum coalition cannot shrink the load-bearing set | 3 |
| PO-5 | (shared with P0) delegation chain soundness; re-key ⇒ re-ceremony | 3 |
| PO-R | recovery is live — no permanent legitimate lock-out | 3 (liveness) |

## Relations
- P0 (L2/L5) · P2 (the store) · P3 (enrollment produces PinRecords) ·
  mesh #39/#40 (CertChain + PoP) · PR #214 (presence) · newt-agent#1209
