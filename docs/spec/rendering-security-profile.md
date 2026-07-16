# P5 — Rendering Security Profile

**Layer:** 2. **Depends on:** P0 (the decision seam), P1.
**Status:** DRAFT. **Teeth:** Lean effect-CID soundness (Tier 3) for the
cryptographic half; a **stated human-factors residual** for the half that
is *not* cryptographic. Naming the boundary honestly is the whole job.
**Owns:** binding *what the human saw* to *what executes*, and the
obligations a rendering surface carries.

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
signature. **PO-W (soundness):** an accepted decision's effect equals the
executed call.

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

## 4. The residual — rendering faithfulness is NOT cryptographic

Binding the signature to `effect` proves the decision is bound to the
*data*. It does **not** prove the UI faithfully showed that data to the
human. Truncation, locale, misleading formatting, hidden arguments, and path
abbreviation remain human-factors surfaces. This profile therefore:

- **requires** `display` to be derived from `effect` by a profile-defined,
  **deterministic rendering function** — so `display` is checkable against
  `effect`, and a surface that cannot faithfully render `effect`'s meaning
  MUST refuse rather than show a prettier `display`;
- treats a **signed render transcript** — the surface attesting the exact
  bytes it presented — as the strengthening path (its own future work);
- states plainly that the last gap is **irreducible human factors**:
  `attest` for high ceilings and distinct ceremony UI (consumer guidance,
  newt#1209) mitigate but do not eliminate it.

Named, not solved. This honesty is the point: a rendering profile that
*claimed* cryptographic faithfulness would be exactly the "prose becomes
authority-bearing protocol" failure the security reviews caught.

## 5. Proof obligations

| PO | Statement | Tier |
|---|---|---|
| PO-W | effect-CID soundness: accepted decision's effect = executed call | 3 |
| — | render-swap / phishing-canvas closures | 3 (with P0 gate checklist) |
| residual | display-faithfulness | *not cryptographic — stated, mitigated* |

## Relations
- P0 §2.1/§2.3 (PermissionRequest, Decision, gate acceptance) · P1
  (canonical CIDs) · newt-agent#1209 (ceremony UI consumer) ·
  Landrock-Pedersen 1998 (WYSIWYS)
