# P4 — Identity Lifecycle

**Layer:** 2. **Depends on:** P0 (L2, L5), P2 (chain-store).
**Status:** DRAFT. **Teeth:** Lean (quorum k-of-n soundness; non-regression
of the load-bearing set, PO-2b) + a **liveness** obligation (recovery is
never permanently denied to a legitimate owner, PO-R). Tier 3.
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
it anchors nothing. An **AttestationRecord** (P0 §3) is its authorization-
bearing sibling: one presence signature, two distinct fields —
**authorization** (`request_cid`, `decision_cid`) and **history witness**
(`observed_head`, `previous_witnessed_head`). Acceptance requires
`previous_witnessed_head` to be a reachable ancestor of `observed_head`
(else CHAIN HISTORY REGRESSION). Attest and audit stay distinct but
co-signed — *no authorization floats free of the history that gave it
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
Acceptance: `|distinct valid signers ∩ eligible| ≥ k` under `policy`. The
quorum policy is itself a principal-signed loosening entry (defining *who
may revoke* is authority structure, L2).

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
This subsystem is required and sketched here; full specification is P4's
open work. **PO-R (liveness):** a legitimate owner is never *permanently*
locked out.

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
