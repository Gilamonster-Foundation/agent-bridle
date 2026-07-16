# P3 — Enrollment Protocol

**Layer:** 2. **Depends on:** P0 (L5), P1, P2.
**Status:** DRAFT. **Teeth:** this profile is a **protocol**, not an
algebra — its correctness is *symbolic protocol analysis* (Tamarin /
ProVerif under Dolev-Yao), **Tier 2**, not Lean/Aeneas. A flawless lattice
can sit behind a leaky handshake; this is where that leak is proven absent.
**Owns:** how a key first joins — introductions, SAS pairing, and the
blessing of external corroboration surfaces.

## 1. Introduction — first contact is challenge-response

Freshness comes from the **recipient**, never the introducer: a self-chosen
nonce in a self-signed object is byte-for-byte replayable.

**Message 1 — the recipient issues a challenge it will remember:**
```json
{ "v": 1, "challenge": "…", "issued_by": "b3:…",
  "for_generation": 41, "expires_at_generation": 42 }
```
**Message 2 — the introducer answers, binding that challenge:**
```json
{ "v": 1, "fingerprint": "b3:…", "pubkey": "ed25519:…",
  "channel": "mdns | dial-back | relay | manual | qr",
  "proposed_caveats": [ … ], "observed": { "addr_candidates": [ … ] },
  "answers": "…", "transcript": "cid:…", "sig": "…" }
```
On receipt of message 2, **before any surface renders it**:
1. `answers` MUST be a challenge *this recipient issued, unconsumed,
   unexpired* — then mark it consumed. Replay-state lives with the
   challenger (unknown-key-share closure; station-to-station).
2. the fingerprint's hash algorithm MUST be in the P1 allowlist **before
   hashing**, then the fingerprint MUST equal that algorithm's multihash
   name of `pubkey` (self-certification, checked by the library not the
   human).
3. `sig` MUST verify under `pubkey` over message 2 incl. `answers` and
   `transcript` — **proof of possession**, transcript-bound.

## 2. SAS pairing (enrolling your own devices/surfaces)

How a new device — possibly no compute beyond key storage and a screen —
gets its keypair pinned under a principal. A naive "new device shows a
phrase, trusted device sends it back" is MITM-relayable. The sound
construction (Bluetooth numeric comparison / ZRTP):

1. both devices **commit** to nonces before revealing;
2. both **derive** the SAS from the *entire transcript* — commitments,
   reveals, **and the long-term public keys being enrolled**. This last is
   not optional: an SAS over only ephemeral material lets a MITM relay the
   handshake while substituting the long-term keys (key-substitution). The
   SAS must checksum *what is being pinned*, not the channel;
3. **a human compares the SAS on both screens** — a low-bandwidth
   *authenticated* channel the network MITM is not on. It is **not
   unspoofable**: it has a measurable error probability (the SAS entropy)
   and human-factors assumptions (humans skim). The phrase is a checksum,
   not a secret.

Commit-before-reveal forces the MITM to *guess* the SAS in advance;
`xxx-000` ≈ 1-in-46k per round. Paranoia is a parameter:
```
strength(enrollment) = (SAS entropy × rounds, distinct witnesses, presence)
```
Minima are set **by caveat ceiling**: a broad ceiling demands more rounds,
≥ 2 previously-secured witnessing surfaces, and a hardware presence
discharge (`attest`). Witnesses buy more than rounds — rounds shrink the
guess probability; independent witnesses multiply the channels an attacker
must own *simultaneously*. The completed enrollment is a `PinRecord` (P4)
whose payload carries the ceremony parameters.

**Punting ≥ pinning:** revocation (P4) is graded on the same scale —
removing an identity demands at least the strength that enrolled it.

## 3. External anchors (corroboration, never the root)

A principal root is **self-sovereign**. Externally published keys — GitHub
(`github.com/<user>.keys`), DNS, an org CA, a prior device — are **candidate
corroboration channels**: independent witnesses that the root you pin
belongs to the human you think it does. No anchor is load-bearing (floating-
identity law 1): GitHub corroborates the root, never *is* it. A user with no
GitHub enrolls by ceremony alone with zero degradation.

**Anchors are blessed, then participate.** Any public-key display surface
qualifies *once the key owner blesses it* — an `AnchorRecord` (principal-
signed binding of channel + location + displayed key) appended to the
chain-store. Unblessed anchors are ignored; a blessed one may *participate*
as a signing/corroboration surface (a GitHub-key signature counting as one
enrollment witness). Blessings revoke like any load-bearing identity (P4
quorum) — a captured anchor is cut loose and `n` just shrank by one.

## 4. Proof obligations (Tier 2 — symbolic)

| PO | Statement | Tool |
|---|---|---|
| PO-E | enrollment has no MITM / unknown-key-share under Dolev-Yao | Tamarin/ProVerif |
| PO-F | challenge freshness: no self-issued or replayed nonce is accepted | Tamarin/ProVerif |
| PO-S | SAS guess advantage ≤ (entropy, rounds, witnesses) bound | analysis + vectors |

The introduction/pin *outcome* records are P1/P4 objects and inherit their
Tier-3 obligations; the *handshake* is what this profile proves.

## Relations
- P0 L5 (the ceremony gate this satisfies) · P1 (allowlist, PoP sig) · P2
  (the store the PinRecord lands in) · P4 (PinRecord, RevocationRecord,
  AnchorRecord definitions) · agent-mesh#65/#66 (mesh-side structs)
