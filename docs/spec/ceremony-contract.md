# P0 — The Ceremony Contract (the narrow waist)

**Status:** DRAFT 0.2.0 (2026-07-16) — partitioned from the v0.1.x
monolith into the [Ceremony Suite](README.md). This document is now the
**waist**: the five laws, the authority algebra, and the decision seam.
Everything mechanical it used to contain moved to a profile (P1–P5); this
doc *references* them and states the invariants they must satisfy.
**Depends on:** P1 (Signed-Object), P2 (Chain-Store).
**Depended on by:** P3, P4, P5.
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

## 3. Attest discharge + the forward-only ratchet

An `attest` grant is **inert until a presence proof is verified** (WebAuthn/
FIDO2 challenge-response via the shipped `step_up::DischargeVerifier`): the
gate issues a domain-separated, single-use `Challenge` bound to the request
CID, subject, and generation; the authenticator returns a
`DischargeAttempt`; the gate verifies and consumes it **before** the grant
takes effect.

**A presence proof also witnesses a non-regressing history.** The challenge
commits to a **checkpoint**; the signer refuses unless the store it is
shown *extends* the store it last witnessed. This yields an
`AttestationRecord` (P4) carrying two distinct statements under one
signature — **authorization** ("I approved R") and **history witness** ("I
verified `observed_head` descends from `previous_witnessed_head`"). The
signer's `previous_witnessed_head` MUST live in its **P2 §4 anti-rollback
anchor**, not the store it validates. Rollback *or* fork → `CHAIN HISTORY
REGRESSION` → halt + escalate. Checked **per causal thread**, so concurrent
threads never false-trip. Generation (total order) and DAG ancestry
(partial order) must *both* advance. Payoff: **every ordinary approval is a
free freshness checkpoint.** Not a new law — L2·H1's anchor at ceremony
time.

## 4. The Laws (normative — the whole waist)

Five laws. Nothing enters this section without a proof obligation (§5);
everything else is mechanism (a profile) or well-formedness.

### L1 — Resolution is a meet
Verdicts are ordered by restrictiveness (`deny ⊏ attest ⊏ ask ⊏ approve`).
`resolve(R, q) = ⨅ { verdict(r) | r ∈ R, r matches q }`. ⨅ is associative,
commutative, idempotent ⇒ resolution is independent of rule/file/load order.
No ordering attack exists. **PO-1.** *(The `attest`-factorization fork —
one verb axis vs. `effect × assurance × scope` — is a lattice-shape choice;
L1 survives either, since a product of lattices is a lattice. Author's call;
see README.)*

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
through certification**:
```
pinned(fp) ⇔ fp ∈ PinSet ∨ ∃ chain: fp →* root ∈ PinSet, PoP at every link
```
so pinning a principal admits the agents/surfaces it issues (delegation, P4;
shipped as mesh `CertChain::verify` + PoP, #39/#40). **PO-5** (incl. chain
soundness).

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
