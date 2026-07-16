# P5 — Rendering Security Profile

**Layer:** 2. **Depends on:** P0 (the decision seam), P1, P4 (surface
identity). **Status:** DRAFT. **Teeth:** Lean effect-CID soundness (Tier 3)
for the cryptographic half; **surface-attestation protocol** obligations
(Tier 2) for binary + rendering attestation; a **stated, shrunk
human-factors residual** for the analog gap that is not cryptographic.
Naming the boundary honestly is the whole job.
**Owns:** binding *what the human saw* to *what executes*, surface
attestation (proving the renderer is faithful), and the obligations a
rendering surface carries.

## 1. Effect binding — what you see is what you sign

`action` carries both a human `display` and an `effect` — the content-CID of
the **canonical, fully-resolved call** (arguments *and* resolved resources —
the `CallRequest` the tool layer produces):

```json
"action": { "class": "exec", "display": "run_command: cd <path>",
            "effect": "cid:…" }
```

The gate MUST, **before minting authority, recompute the canonical effect
from the call it is about to run and check it equals `action.effect`** —
otherwise a stale or lossy `display`→effect mapping approves X and executes
Y while the CID still matches (confused-deputy / TOCTOU; WYSIWYS,
Landrock-Pedersen 1998). Display and effect are bound under the one
signature. **PO-W (soundness):** the gate executes the exact
`Sealed<CallRequest>` whose CID was approved.

**Effect binds a value; the value must freeze the mutable world (OB-10).**
`action.effect` is only as strong as what enters the sealed `CallRequest`.
"Resolved resources" is therefore given a **normative per-class boundary** —
each action class names which resource *identities* (not mutable handles)
are sealed:

| Class | Sealed identity — never a mutable handle |
|---|---|
| `file` | canonical path **+** inode/file-identity or content-CID |
| `container` | image **digest**, never a mutable tag |
| `repo` | repository identity **+** commit/tree CID |
| `network` | destination policy **+** an explicit DNS-resolution policy |
| `env`/`creds` | the resolved values, or a named residual (below) |

Anything left ambient at approval time — symlink targets, DNS answers,
mutable files, env vars, container tags, credentials resolved *after*
approval — is a **named residual**, never silently folded into PO-W. If a
class cannot freeze a resource, it says so; it does not pretend the
signature covered it.

## 2. Gate-signed requests (the phishing-canvas closure)

A **remote** surface MUST verify the request's signature and that `by`
chains to a pinned principal **before rendering** — an unauthenticated
prompt is a phishing canvas that trains the human on fake ceremonies, even
though its harvested decision is unredeemable (the `Decision.request` CID
binding, P0 §2.3). In-process, `by`/`sig` MAY be omitted.

## 3. The render-swap closure

`Decision.request` = the content-CID of the `PermissionRequest` as issued;
the gate accepts only a matching CID (P0 §2.3 step 1). This binds *what was
shown* to *what was granted* — an attacker cannot show request A and apply
the approval to request B.

## 4. Surface attestation — shrinking the faithfulness gap

Effect-binding proves the decision is bound to the data; it does not prove
the *surface* is a faithful renderer. Two complementary attestations raise
the bar so **an unfaithful surface has trouble passing** — the surface
becomes a participant that must prove *what it is* and *what it did*.

**4.1 Binary attestation — what the surface IS.** A surface's identity (P4:
a keypair) is bound to a **measured code identity** — a reproducible-build
hash, TPM/DICE quote, or platform attestation (Play Integrity / App
Attest). The principal blesses surface *measurements* onto a profile
allowlist (the same allowlist discipline as P1 §4·4, applied to code). A
decision from a surface whose measurement is not blessed is **refused for
actions above a policy-set ceiling** — degrading the residual from "any
surface on earth" to "a known-good build." A tampered renderer has a
different measurement and fails the check. This is remote attestation
(Parno et al.); its primitives are a Tier-1 assumption, its handshake a
Tier-2 (protocol) obligation.

**4.2 Rendering attestation — what the surface DID.** A **signed render
transcript**: the surface signs the exact bytes it presented, bound to
`request_cid` and the deterministic `display`-from-`effect` output (§1). The
faithfulness *ceremony* injects a challenge a faithful renderer passes and
an unfaithful one cannot: the gate derives a **witness token** from
`(effect, nonce)` that MUST appear verbatim in the canonical `display` the
human confirms. A surface that truncated, reformatted, localized-away, or
hid part of the effect cannot produce a `display` containing the correct
token — so the token is absent or wrong, the human sees the mismatch, and
the presence discharge (which covers the token) fails. "Did the surface show
the whole truth?" becomes checkable rather than assumed.

Both compose with the existing gate checklist: high-ceiling actions MAY
require a blessed measurement (4.1) **and** a token-bearing render transcript
(4.2) as part of the `attest` discharge (P0 §3).

## 5. The residual — faithfulness is *shrunk*, not eliminated

Even with §4, honesty is preserved (this is the discipline the reviews
praised): binary attestation proves the code is known-good, **not** that
known-good code has no rendering bug; the render transcript proves what bytes
were emitted, **not** what pixels a compromised display driver painted; the
witness-token ceremony assumes the human actually reads. The final analog
gap — human eyes on a possibly-hostile display — is irreducible. So P5:

- **requires** `display` to be a deterministic function of `effect` (§1), so
  it is checkable, and a surface that cannot render `effect` faithfully MUST
  refuse rather than show a prettier `display`;
- **offers** binary + rendering attestation (§4) to shrink the residual by
  policy ceiling;
- **names** the remainder as irreducible human factors — `attest` for high
  ceilings and distinct ceremony UI (newt#1209) mitigate, never eliminate.

Shrunk, bounded, named — not "solved." A rendering profile that *claimed*
cryptographic faithfulness would be exactly the "prose becomes
authority-bearing protocol" failure the security reviews caught.

## 6. Proof obligations

| PO | Statement | Tier |
|---|---|---|
| PO-W | the gate executes the exact `Sealed<CallRequest>` whose CID was approved | 3 |
| PO-RES | each action class seals resource *identities*, not mutable handles (OB-10) | 3 + vectors |
| — | render-swap / phishing-canvas closures | 3 (with P0 gate checklist) |
| PO-SB | binary attestation: a decision above ceiling C is honoured only from a blessed surface measurement | 2 (protocol) |
| PO-SR | rendering attestation: the witness token is present in `display` ⇒ the surface showed the whole effect | 2 (protocol) |
| residual | display-faithfulness on a hostile display | *shrunk by §4, not eliminated — stated* |

## Relations
- P0 §2.1/§2.3/§3 (request, decision, attest discharge) · P1 (canonical
  CIDs, allowlist) · P4 (surface identity the measurement binds to) ·
  newt-agent#1209 (ceremony UI consumer) · Landrock-Pedersen 1998 (WYSIWYS)
  · remote attestation (Parno et al.) for §4.1
