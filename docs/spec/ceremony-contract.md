# P0 — The Ceremony Contract (the narrow waist)

**Status:** DRAFT 0.2.1 (2026-07-16) — partitioned from the v0.1.x
monolith into the [Ceremony Suite](README.md), then repaired against review
round 6 (all eleven obligations closed in text — see README). This document
is the **waist**: the five laws, the authority algebra, and the decision
seam. Everything mechanical moved to a profile (P1–P5); this doc *references*
them and states the invariants they must satisfy.
**Depends on:** P1 (Signed-Object), P2 (Chain-Store); P4 only via the
abstract contracts it defines (`AttestEvidence`, `ValidAssociationProof`) —
no back-edge (OB-1).
**Depended on by:** P4, P3, P5.
**Teeth:** Lean proof of the lattice laws + resolution, refined to the pure
Rust kernel by Aeneas (Tier 3). See the review history and adjudications on
[#229](https://github.com/Gilamonster-Foundation/agent-bridle/pull/229);
positioning on [#225](https://github.com/Gilamonster-Foundation/agent-bridle/issues/225).

**Scope:** the contract between agent-* libraries (decision *semantics*) and
harnesses (*rendering*). A harness can comply without depending on any
bridle crate; `agent-bridle` is the reference implementation.

## 1. The seam

Libraries define the decision **space**; consumers define the **layout**. A
library crate MUST NOT contain rendering or interactive prompting. A
consumer binds a `DecisionSurface`; with none bound, the laws fail closed
(L3).

```
 agent-* libraries              consumer (harness)
┌─────────────────────┐        ┌──────────────────────────┐
│ decision kernel     │ struct │ DecisionSurface impl:    │
│ (pure; provable)    │──────► │  newt: matrix + audit    │
│ resolve · meet ·    │        │  hermes: flat list       │
│ gate · pin store    │ ◄──────│  daemon: policy files    │
└─────────────────────┘Decision│  phone: GUI sheet        │
                               └──────────────────────────┘
```

```rust
#[async_trait]
pub trait DecisionSurface {
    async fn decide(&self, req: PermissionRequest) -> Decision;
}
```

Policy files (#220) are the headless implementation of this trait.

## 2. Wire objects (the seam's vocabulary)

All are Memo-descendants (P1 §3). Full field-level definitions of the
identity/enrollment/store records live in their owning profiles; the three
objects the *seam* itself trades are here.

### 2.1 PermissionRequest

```json
{ "v": 1, "subject": "b3:…",
  "action": { "class": "exec", "display": "run_command: cd <path>",
              "effect": "cid:…" },       // canonical resolved call — P5
  "violation": "outside-granted-allowlist",
  "matrix": { … }, "context": { "session": "…", "generation": 41 },
  "by": "b3:…", "sig": "…" }             // gate signature — required remote (P5)
```

`action.effect` binds the signature to *what executes*, not what is shown
(P5 owns effect-binding and the rendering residual).

### 2.2 DecisionMatrix

```json
{ "verbs": ["allow", "attest", "deny"], "scopes": ["once", "session"],
  "default": ["allow", "once"], "escalations": ["audit"] }
```

The decision *space*; nothing encodes layout. `attest` is the
presence-required disposition (`attest × once` = ceremony every action;
`attest × session` = one discharge per generation). `default` is the
administrator/packager **opinion surface** (`rm -rf` ships `["deny",
"session"]`), never an auto-grant. Scope vocabulary is open; a durable
scope materializes as a signed loosening entry (L2, via P2).

**WF-1 (well-formedness, not a law):** every matrix MUST be decidable with
all escalations unrendered — `verbs × scopes` non-empty and sufficient (a
harness with no audit surface renders a complete chooser by omission).

### 2.3 Decision + gate acceptance

```json
{ "v": 1, "request": "cid:…", "grant": { "verb": "allow", "scope": "once" },
  "by": "b3:…", "sig": "…" }
```

`escalate` carries **zero authority** (L4); exactly one of `grant`/
`escalate`. **Gate acceptance is a checklist of MUSTs — the client is never
trusted:**

1. `request` = the content-CID of the request the gate itself issued;
2. `grant.verb ∈ matrix.verbs` and `grant.scope ∈ matrix.scopes`;
3. the result is `⊑` the request ceiling (L4) — never answer `once` with
   `always`;
4. the executable effect recomputes equal to `action.effect` (P5);
5. if `verb == attest`, the discharge verifies **and** its history witness
   passes the forward-only ratchet (§3).

A surface violating any is refused at the gate — the wire *enforces* L4, it
does not merely state it.

### 2.4 Vocabulary (one word, one job — OB-9)

Three registers were drifting; they are pinned here:

| Term | Register | Meaning |
|---|---|---|
| `allow` / `attest` / `deny` | **matrix verb** — what a surface *offers* the human | `allow` maps to verdict `approve`; `attest` to `attest`; `deny` to `deny` |
| `deny ⊏ attest ⊏ ask ⊏ approve` | **verdict** — resolution's codomain | the durable disposition `resolve` yields |
| `ask` | **verdict only** (never a matrix verb) | "no durable rule → interact"; the `resolve(∅)` default (L1); fail-closed via L3 |
| `escalate` | **Decision action** (never a verdict) | navigation to a richer surface; `authority(escalate) = ⊥` |

So `allow` (offer) and `approve` (verdict) are the same disposition seen
from the two sides of the seam; `ask` is a verdict, not an offer; `escalate`
is neither.

## 3. Attest discharge + the forward-only ratchet

An `attest` grant is **inert until a presence proof is verified**, and the
proof *also witnesses a non-regressing history*: the same finger-press
attests "I approved R" **and** "the world had not regressed when I did."

**Four roles, deliberately separate (OB-3).** The WebAuthn authenticator
does not understand a Merkle DAG — it signs over a client-data hash. So do
not say "the hardware witnessed the chain." The roles are:

| Role | Does |
|---|---|
| **Witness-verifier** | holds the P2 §4 protected checkpoint; verifies DAG extension; **constructs the challenge preimage** |
| **Authenticator** (WebAuthn/FIDO2) | proves user presence/verification over that challenge — nothing more |
| **Surface identity** | signs the resulting `AttestEvidence` record |
| **Gate** | appends, advances the anchor, then activates authority |

**One canonical challenge preimage** — every field the attestation binds,
domain-separated (P1 §), so nothing is left to prose:
```
challenge = H("agent-bridle/attest/v1",
              store_id, thread_id, request_cid, decision_cid,
              previous_checkpoint, observed_checkpoint, generation, nonce)
```

**The commit is transactional (compare-and-swap, OB-3).** A crash or
rollback must never leave "authority active but attestation not durable" or
"attestation appended but anchor not advanced":
```
1. witness-verifier: observed_checkpoint Extends protected_checkpoint  (else HALT)
2. authenticator: presence proof over the canonical challenge
3. surface: construct AttestEvidence
4. append it → post_attestation_head
5. CAS-advance the protected anchor: protected := post_attestation_head
6. only now mint/activate authority
```
Steps 4–6 are one atomic transition (CAS on the anchor); a recoverable
two-phase form is permitted. Rollback *or* fork at step 1 → `CHAIN HISTORY
REGRESSION` → halt + escalate (a fork is P2 proof-of-misbehavior, never a
branch to silently adopt). Checked **per causal thread** (P2 `thread_id`),
so concurrent threads never false-trip; generation (total order) and DAG
ancestry (partial order) must *both* advance.

**P0 depends only on an abstract evidence contract (OB-1)** — not on P4's
concrete record — so the waist has no back-edge into P4:
```rust
trait AttestEvidence {
    fn request(&self) -> ContentId;
    fn decision(&self) -> ContentId;
    fn previous_checkpoint(&self) -> Checkpoint;
    fn observed_checkpoint(&self) -> Checkpoint;
    fn presence_proof(&self) -> PresenceProof;
}
```
P4 supplies `AttestationRecord` as the concrete implementation. Payoff of
the whole ratchet: **every ordinary approval is a free freshness
checkpoint.** Not a new law — L2·H1's anchor applied at ceremony time.

## 4. The Laws (normative — the whole waist)

Five laws. Nothing enters this section without a proof obligation (§5);
everything else is mechanism (a profile) or well-formedness.

### L1 — Resolution is a meet
Verdicts are ordered by restrictiveness (`deny ⊏ attest ⊏ ask ⊏ approve`);
`deny` is ⊥, `approve` is ⊤. Resolution is the meet of the matching
verdicts, **with the no-match case defined explicitly** so it is total *and*
fail-closed (OB-9):
```
resolve(R, q) = ⨅ { verdict(r) | r ∈ R, r matches q }   if some rule matches q
              = ask                                       if none matches q
```
The explicit `ask` default is load-bearing: the empty meet's mathematical
identity is `⊤ = approve`, so *without this clause an unmatched request
would fail OPEN* — the defect L3 forbids. `ask` (→ prompt; headless → deny,
L3) is the deliberate "unknown ⇒ interactive, never granted" default. ⨅ is
associative, commutative, idempotent ⇒ resolution is independent of
rule/file/load order; no ordering attack exists. **PO-1** (now includes
`resolve(∅,q) = ask`, i.e. no fail-open). *(The `attest`-factorization fork
— one verb axis vs. `effect × assurance × scope` — is a lattice-shape
choice; L1 survives either, since a product of lattices is a lattice.
Author's call; see README.)*

### L2 — Tamper-boundedness
For any mutation `m` by a party holding **fewer than quorum(target)** keys:
```
resolve(m(R), q) ⊑ resolve(R, q)          (no widening)
LoadBearing(R) ⊆ LoadBearing(m(R))        (no structural narrowing)
```
Two directions, one law. **Downward:** sub-quorum actors only narrow
authority; forged loosening entries drop at load (fail-closed). **Upward:**
sub-quorum actors cannot shrink the load-bearing identity structure —
reversible narrowing (deny-spam) is a nuisance; **irreversible narrowing
(revoking an identity) requires quorum** (P4), because a fail-closed
system's failure mode is an adversary who can *force* closure. Availability
is a security property.
**H1 (append-only-verifiability + monotone freshness)** is discharged *by
mechanism*, split across P2: interior integrity by the chain (**PO-2a**),
tail/fork by the external anchor (**PO-2c**), revocation-quorum by P4
(**PO-2b**). **PO-2** proves ⊑-monotony under H1. (H1's chain-alone form was
over-claimed in v0.1.x and corrected — see README teeth Tier 3.)

### L3 — Fail-closed totality
`resolve` is total; no input reaches "undefined permission." Interactive
bottom is `ask`; absent a bound surface, `ask ↦ deny`, `attest ↦ deny`
(degradation is ⊑-monotone). **PO-3.**

### L4 — Attenuation
`effective = granted ⊓ required`; `granted = requested ⊓ ceiling`;
`authority(escalate) = ⊥`. Authority composes by meet, never amplifies
(property-tested upstream as `meet_never_amplifies`). **PO-4.**

### L5 — The ceremony gate
`association(peer) ⇒ pinned(fingerprint(peer))`. `fingerprint = H(pubkey)`
is self-certifying (P1) — re-key ⇒ new fingerprint ⇒ unpinned ⇒ full
re-ceremony; no silent identity swap is expressible. Pinned is **transitive
through certification** — but the waist states this over an **abstract
predicate** (OB-1), not P4's concrete cert-chain, so L5 has no back-edge:
```
pinned(fp) ⇔ fp ∈ PinSet ∨ ValidAssociationProof(fp, PinSet)
```
`ValidAssociationProof` is an abstract contract (there exists a
PoP-at-every-link chain `fp →* root ∈ PinSet`); **P4 proves its cert-chains
implement it** (shipped as mesh `CertChain::verify` + PoP, #39/#40). **PO-5**
(incl. chain soundness) is proved by P4 against this predicate.

## 5. Proof-obligation ledger (owned here; full suite in README)

| PO | Law | Statement | Tier |
|---|---|---|---|
| PO-1 | L1 | ⨅-resolution order-independent | 3 |
| PO-2 | L2 | sub-quorum mutation ⊑-monotone under H1 | 3 |
| PO-3 | L3 | totality + monotone headless degradation | 3 |
| PO-4 | L4 | meet never amplifies | 3 |
| PO-5 | L5 | no association without pin; re-key forces re-ceremony | 3 |

Pilot proofs: PO-1, PO-2. The kernel is pure `resolve` + precedence + the
gate checklist + the P2 trusted-state transition — no serde/IO/crypto/UI;
crypto enters as P1's abstract contracts. Conformance **vectors** bind the
four client languages to one observable behaviour.

## 6. Cross-cutting: the MITM ledger

"No MITM hole anywhere" is a claim to *enumerate*. Each row's closure lives
in the cited profile; the unifying rule is **the authenticated thing is
always the key, never the channel.**

| Channel | Attack | Closure (profile) |
|---|---|---|
| First contact | TOFU key swap | L5 ceremony / chain-to-pinned-principal (P3) |
| First contact | intro replay / unknown-key-share | recipient-issued challenge + PoP (P3) |
| Enrollment | relay + key substitution | commit-reveal SAS over long-term keys (P3) |
| Post-pin transport | path impersonation | dial-by-pubkey; paths are hints (mesh) |
| Delegation | rogue delegated agent | chains verify to a pinned principal (P4) |
| Remote surface | render-swap | `Decision.request` CID binding (P5) |
| Remote surface | phishing canvas | gate-signed requests, verified before render (P5) |
| Store sync | rollback / truncation / fork | external anti-rollback anchor (P2 §4) |
| Anchor channel | fake-root vouch | blessed anchors, k-of-n, never alone (P4) |
| The human | prompt fatigue | `attest` for high ceilings; UI guidance (residual) |

## 7. Governance — law minimalism

A good system has only the laws it absolutely needs. **Nothing enters §4
without a proof obligation; everything else is a profile or a
well-formedness predicate.** The count history: six → five (L6 → WF-1);
then held at five through the revocation-DoS absorption (L2 upward), the
Memo/multihash discipline (WF-2/P1), two adversarial security reviews
(rounds 4–5, eight findings closed as enforcement/mechanism/wire-discipline
— L2's H1 *corrected*, not multiplied), and the forward-only ratchet.
**Next candidate:** L1+L4 unify as one "authority composes by meet" law on
two carriers (verdict + caveat lattices) — five → four if the Lean
formulation collapses them cleanly.

The algebra decides the count; ambition doesn't.

## Relations
- Suite index: [README.md](README.md)
- Profiles: P1 [signed-object](signed-object-profile.md) · P2
  [chain-store](chain-store-profile.md) · P3
  [enrollment](enrollment-protocol.md) · P4
  [identity-lifecycle](identity-lifecycle.md) · P5
  [rendering](rendering-security-profile.md)
- #220 verdict/policy TOML · #231 `passkey`→`attest` rename · GPT-5 PR #232
  formal kernel · agent-mesh#67 Conversation Graph ·
  `docs/decisions/floating_identity.md` (law 5 = L5; law 4 = the graph)
