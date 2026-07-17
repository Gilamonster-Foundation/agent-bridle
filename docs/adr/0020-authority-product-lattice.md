# ADR 0020 — Authority as a product meet-lattice (Effect × Assurance × Scope)

- Status: Accepted (2026-07-16)
- Date: 2026-07-16
- Context: The Ceremony Suite's narrow waist, P0
  ([`ceremony-contract.md`](../spec/ceremony-contract.md)), reached its
  **v0.3.1 PROTOCOL FREEZE**. Review 7 (a protocol-freeze pass) filed
  **OB-12 (severity B)**: the single most divergence-prone thing left in the
  waist was the *type of an authority verdict*. Until this ADR it was carried
  as a **linear chain of dispositions** — `deny ⊏ attest ⊏ ask ⊏ approve` —
  one totally-ordered rung ladder. That shape had survived the split from the
  v0.1.x monolith unexamined, and it is the carrier on which **all five laws**
  (L1 meet-resolution, L2 tamper-boundedness, L3 fail-closed totality, L4
  attenuation, L5 ceremony gate) and the gate-acceptance checklist are stated.
  Getting the carrier wrong quietly corrupts every law that quantifies over
  it, so OB-12 was closed as a **type freeze**, not a wording tweak.
- Governed by / harmonizes with: **ADR 0002** (the `Caveats` meet-semilattice
  and the unforgeable `ToolContext`; `meet`/`leq`/constructors, **no
  `join`/`widen`**), **ADR 0012** (fence strength as a GLB over the report;
  "narrow-only in both directions"), **ADR 0007** (step-up `Presence` as a
  raise-only gesture axis), and the **#231** `passkey`→`attest` rename. This
  ADR ratifies, at the ceremony-suite level, the decision text already frozen
  in P0 §2.0/§2.4; the *proofs* that discharge it (PO-1, PO-3, PO-4) are the
  held implementation phase.
- Scope: the **Authority** type — what `resolve` returns, what a `grant`
  is, what a `ceiling` bounds. This is the *decision-semantics* carrier of the
  P0 waist. It is distinct from, but built on the same algebra as, the
  `Caveats` confinement lattice of ADR 0002 (see D7 and Notes).

## Decision

**Authority is a product meet-lattice of three independent axes**, with
componentwise attenuation. This is the frozen type (OB-12):

```
Authority = Effect × Assurance × Scope
  Effect    : deny ⊏ allow                        (deny = ⊥)
  Assurance : none ⊏ presence ⊏ hardware          (the old `attest` lives here)
  Scope     : once ⊏ session ⊏ durable            (profile-declared closed order)
  (e₁,a₁,s₁) ⊓ (e₂,a₂,s₂) = (e₁⊓e₂, a₁⊓a₂, s₁⊓s₂)
  ⊥ = (deny, none, once)     ⊤ = (allow, hardware, durable)
```

### D1 — Authority is the *product* of three lattices; meet is componentwise

A verdict is not a rung; it is a **point** `(effect, assurance, scope)`. The
product of lattices is a lattice, so `⊓` is defined coordinatewise and the
meet identities (associative, commutative, idempotent) hold **automatically**
per axis and therefore on the product. Resolution `⨅ { authority(r) | r
matches q }` (L1) is exactly this product meet — hence order-independent, no
rule/file/load-order attack (**PO-1**). The three axes answer three
*orthogonal* questions and must never be forced onto one line:

| Axis | Answers | Order |
|---|---|---|
| **Effect** | *what* is permitted | `deny ⊏ allow` |
| **Assurance** | *how strongly present* the human is | `none ⊏ presence ⊏ hardware` |
| **Scope** | *how long* the grant covers | `once ⊏ session ⊏ durable` (profile-declared) |

### D2 — `deny` is the bottom of Effect; there is exactly one ⊥

`deny` is `Effect`'s ⊥, so `⊥ = (deny, none, once)` is the single denied
authority. There are **not** several semantically-equal "denied authorities"
to distinguish or accidentally order among — a fail-closed system whose bottom
is not canonical invites bugs where one deny out-ranks another. One ⊥, reached
by any axis meeting down through Effect, is the fail-closed floor L3 degrades
to.

### D3 — `attest` is not a verb; assurance is its own axis

The former `attest` disposition is **`Assurance = presence`** (or, with a
bound hardware/measurement attestation, `hardware`; P5 §4.1). Because it is a
coordinate and not a rung, it **composes with any Effect and any Scope**:
"allow, once, presence-required" and "allow, durable, hardware-required" and
"deny, none" are all expressible points. This is the formalization of ADR
0007's raise-only step-up `Presence` and the #231 `passkey`→`attest` rename:
the *strength of proof-of-presence* is independent of *what* was decided and
*for how long*. A grant with `Assurance > none` is **inert until a presence
proof discharges it** (P0 §3, the forward-only ratchet); un-discharged, it
degrades to `deny` (L3), and this degradation is ⊑-monotone.

### D4 — `ask` is *not* an authority level; it is a control-flow result

There is no `ask` rung. Resolution is a sum type:

```
Resolution = NeedsDecision              (was `ask`: "no rule settled it — interact")
           | Decided(Authority)
```

`NeedsDecision` has **no place in the lattice**; the gate never *grants* it. It
routes to a bound `DecisionSurface`; **headless (no surface) it degrades to
`deny`** (`⊥`-Effect, L3). The empty-meet default is load-bearing: the empty
product meet is `⊤ = (allow, hardware, durable)`, so *if an unmatched request
resolved to the empty meet it would fail OPEN*. L1 therefore makes the no-match
case an explicit `NeedsDecision` (piecewise, never a seed that would also
downgrade a legitimate `allow`). `resolve` is total (**PO-3**).

### D5 — Scope is a profile-declared, *closed* order — not arbitrary strings

A profile MUST publish its Scope set and its total order + meet (v1:
`once ⊏ session ⊏ durable`); an implementation **rejects a scope outside its
profile**. "Open vocabulary" means *a profile may extend the set*, never *any
string compares somehow*. This keeps the third axis a genuine lattice with a
decidable meet rather than an ungoverned free-text field that would break
`⊓`'s totality.

### D6 — Attenuation is componentwise, under an explicit signed `ceiling`

`PermissionRequest` carries an **explicit, signed `ceiling`** — the maximum
Authority the request may resolve to (P0 §2.1). L4 becomes:

```
effective = granted ⊓ required
granted ⊑ ceiling            (componentwise: no axis exceeds the request ceiling)
authority(escalate) = ⊥
```

`⊑` is the product order (`e₁⊑e₂ ∧ a₁⊑a₂ ∧ s₁⊑s₂`). The gate re-derives the
ceiling from policy at issue time and **re-checks each axis** before minting
(never trusts a surface-supplied ceiling); a grant exceeding it on *any* axis
is refused by the acceptance checklist (P0 §2.3, item 3). Authority composes by
meet and **never amplifies on any axis** (**PO-4**, `meet_never_amplifies`
lifted to the product). This is the ADR 0002/0012 "narrow-only, no `join`"
discipline, now three-dimensional and with a per-axis ceiling the old scalar
chain could not express.

### D7 — The five laws lift componentwise; this is a carrier change, not a new law

Freezing the product type touches **no law count**. L1 (meet-resolution) and L4
(attenuation) are stated on the carrier and lift coordinatewise because a
product of lattices is a lattice; L2, L3, L5 are structurally unchanged. The
suite stays at **five laws**. This is the same algebra ADR 0002 established for
`Caveats` (a meet-semilattice with no widen), *generalized from one carrier to
a product of three* — the ceremony-suite `Authority` and the core `Caveats`
grant are siblings under one discipline, not two competing models.

## Consequences

**Positive**

- **Orthogonality is expressible.** "Allow durably but require hardware
  presence," "allow once with no presence," "deny" are distinct, composable
  points. The old chain could not name most of these.
- **One meet, proven once.** Because the product's meet is the coordinatewise
  meet of three trivially-correct small lattices, PO-1/PO-3/PO-4 reduce to
  per-axis facts and lift for free — a much smaller proof surface for Lean
  (Tier 3) than a bespoke order over fused dispositions.
- **`ask` can no longer be granted.** Lifting it to `NeedsDecision` removes an
  entire class of confusion where a "please interact" sentinel could be
  meet-ed, stored, or minted as if it were partial authority; headless
  degradation to `deny` is now a typed, total function (L3).
- **Fail-open closed at the empty meet.** Making the no-match case explicit
  (D4) removes the latent fail-open the empty product meet (`⊤`) would
  otherwise create.
- **Per-axis ceiling.** Attenuation and the signed ceiling now bound *each
  axis independently* (D6), so a policy can cap duration without capping effect
  and vice versa — impossible on a single ≤.
- **Vocabulary hygiene (OB-9/OB-12).** One word, one job: `Effect`,
  `Assurance`, `Scope` are authority axes; `NeedsDecision` and `escalate` are
  control-flow / navigation, `authority(escalate) = ⊥`. No `ask` verdict, no
  `attest` verb survives (P0 §2.4).

**Negative / residual**

- **Three axes to keep closed.** Each profile now owns publishing its Scope
  order (D5); an implementation that forgets to reject an out-of-profile scope
  reintroduces a non-lattice field. Guarded by conformance vectors, not by the
  type alone.
- **Assurance is inert without discharge.** `Assurance > none` is a *promise*
  until the presence proof + forward-only ratchet clears it (P0 §3); a caller
  that treats a `presence`-tagged grant as already-active before discharge is a
  bug the ratchet must catch, not the lattice.
- **Migration surface.** Any prose, schema, or test still speaking of `ask`/
  `attest` as verdicts must be rewritten; the DecisionMatrix and gate checklist
  now quantify over three axis sets, not one ordered list.

## Alternatives considered

- **The linear verdict lattice `deny ⊏ attest ⊏ ask ⊏ approve`** (the prior
  model). **REJECTED (OB-12)** on three independent grounds:
  1. **`ask` is not an authority level.** Placing it as a rung between `attest`
     and `approve` implied it carried "more authority than attest, less than
     approve" — meaningless. `ask` means *no rule decided; go interact*: a
     control-flow outcome, not a grant. On the chain it could be meet-ed,
     minted, or stored as partial authority, and the headless case had no
     principled value. Lifting it to `NeedsDecision` (D4) is the fix.
  2. **`attest` conflated outcome with assurance.** One rung fused *what was
     decided* (an allow) with *how strongly presence was proven* (a presence
     proof). You could not express "deny with hardware presence," or trade
     effect against assurance without also moving the other — because they
     shared an axis. Factoring assurance into its own `none ⊏ presence ⊏
     hardware` order (D3) lets it compose with any Effect and Scope.
  3. **Scope had no home at all.** Duration (once/session/durable) was tracked
     out-of-band, so a grant's lifetime could not attenuate under the same meet
     or be bounded by the same ceiling. The product adds it as a first-class,
     profile-declared axis (D5).
  The chain also forced attenuation (L4) to be a single scalar ≤, unable to cap
  one concern without the others, and gave the empty meet no safe default. The
  product meet-lattice resolves all four defects with strictly *less* bespoke
  algebra.
- **A four-axis product adding an explicit `Ask`/interaction axis.** REJECTED:
  interaction is *control flow around* resolution, not a dimension *of*
  authority. Modeling it as an axis re-imports exactly the category error of
  putting `ask` in the lattice. It stays the `Resolution` sum type (D4).
- **Multiple distinct "denied" bottoms (per-reason deny).** REJECTED (D2): a
  fail-closed system needs a single canonical ⊥. Deny *reasons* are audit
  metadata on the record, never orderable authority values.
- **Free-text `Scope` strings with a runtime comparator.** REJECTED (D5):
  "any string compares somehow" is not a lattice; the meet stops being total
  and decidable. Scope is a closed, profile-declared order that an
  implementation rejects outside of.

## Notes

- **Four independent reviewers converged** on `Effect × Assurance × Scope`.
  OB-12 was closed as *4-way converged* (README review 7): four separate
  adversarial passes, reasoning from different starting points (the `attest`
  factorization, the `ask`-in-the-lattice smell, the missing duration concern,
  and the empty-meet fail-open), each arrived at the same three-axis product.
  That convergence is why this is frozen as a *type*, not left as an author's
  call.
- **The five laws lift componentwise.** The frozen product carrier is a
  *carrier* change, not a new law: L1 and L4 are stated over `Authority` and
  lift coordinatewise (product of lattices is a lattice); L2/L3/L5 are
  untouched. Count stays five. (This freeze rode alongside **OB-16**, which
  corrected L2's *upward* direction to `TrustedStructure(m(R)) =
  TrustedStructure(R)` — **equality**, not `⊆` — over the authority-generating
  structure; that is a separate law correction, not part of this carrier
  decision, but shipped in the same v0.3.1 cut.)
- **Roadmap: five → four.** With the algebra on a clean product carrier, the
  next law-minimalism candidate is unifying **L1 + L4** into a single
  "authority composes by meet" law (P0 §7). The count is decided by whether the
  Lean formulation collapses them — *the algebra decides the count; ambition
  doesn't.* Nothing here presumes that collapse; it is noted as a consequence
  this freeze makes reachable.
- **Same discipline as the core lattice.** This `Authority` product is the
  ceremony-suite sibling of the ADR 0002 `Caveats` meet-semilattice: `meet`,
  `leq`, constructors — **no `join`/`widen`**. ADR 0012's "narrow-only in both
  directions" and "GLB, never a stored parallel enum" carry over directly; the
  only change is single-carrier → three-axis product.

## References

- P0 waist: [`docs/spec/ceremony-contract.md`](../spec/ceremony-contract.md)
  §2.0 (frozen type), §2.4 (vocabulary), §3 (presence discharge / ratchet),
  §4 (L1–L5), §7 (law minimalism).
- Suite index: [`docs/spec/README.md`](../spec/README.md) — OB-12 (type
  freeze), OB-9 (empty-meet default), OB-16 (L2 upward = equality), PO-1/PO-3/
  PO-4.
- ADR 0002 (Caveats meet-semilattice + unforgeable context), ADR 0012 (fence
  strength as GLB; narrow-only), ADR 0007 (step-up `Presence`, raise-only),
  #231 (`passkey`→`attest` rename). P1 signed-object (the `ceiling`/`grant`
  wire grammar), P5 rendering (`action.effect` binding, `hardware` attestation).