# The Ceremony Contract

**Status:** DRAFT 0.1.0 (2026-07-15) — for review. Normative once accepted.
**Scope:** the decision-surface and first-contact contract between agent-*
libraries (which own decision *semantics*) and harnesses (which own
*rendering*). Companion to the verdict/policy TOML contract (#220) — that
spec is the non-interactive half of this seam; this spec is the interactive
half plus the laws both halves obey.
**Audience:** implementers of client libraries (Rust, Python, Dart,
TypeScript) and of consuming harnesses (newt, hermes, gila, Claude Code /
Codex plugins). A harness can comply with this spec without depending on
any bridle crate; `agent-bridle` is the reference implementation.

Positioning, prior art, and the adoption strategy are recorded on
[#225](https://github.com/Gilamonster-Foundation/agent-bridle/issues/225);
this document deliberately restates none of it.

---

## 1. Terms

| Term | Definition | Already shipped as |
|---|---|---|
| **Fingerprint** | `blake3(pubkey)` — a self-certifying identity name | `agent_mesh_protocol::Fingerprint` |
| **Caveats** | attenuable authority; forms a meet-semilattice | `agent_mesh_protocol::Caveats` (`meet_never_amplifies` is property-tested) |
| **Verdict** | durable disposition: `deny ⊏ passkey ⊏ ask ⊏ approve`, ordered by restrictiveness | `agent_bridle_core::policy::Verdict` (`precedence()`) |
| **Gate** | the enforcement choke-point; mints `ToolContext` only inside `authorize()` | `agent-bridle-core` |
| **Surface** | a consumer-supplied renderer of decisions (TUI, GUI, policy file, API) | this spec, §3.6 |
| **Escalation** | a navigation affordance (e.g. `audit`) — never authority | this spec, §3.2 |
| **Pin** | a durable, provenance-carrying record that an identity's key was accepted | this spec, §3.5 |
| **Ceremony** | the interactive resolution of a decision the laws refuse to default | this spec, §4 L5 |
| **ContentId / MerkleNode** | BLAKE3 CID over canonical DAG-CBOR; parent-linked record | `content-addressable` crate |

Encodings: **one schema, three encodings.** JSON for interchange (client
libs), TOML at rest (#220 policy files), **canonical DAG-CBOR for anything
hashed or signed**. Signatures and `ContentId`s are computed over canonical
bytes only.

Time: per the workspace hard rule, **wall-clock is never a coordination
primitive**. Validity keys on generation counters
(`valid_for_generation`); RFC 3339 timestamps appear in records as
provenance *data* supplied by the boundary, never read by the kernel.

## 2. The seam

Libraries define the decision **space**; consumers define the **layout**.
A library crate MUST NOT contain rendering components or interactive
prompting. A consumer binds a `DecisionSurface` (§3.6); with none bound,
the laws fail closed (§4 L3).

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

## 3. Wire objects

Field names are normative; unknown fields MUST be ignored (forward
compatibility). All objects carry `"v": 1`.

### 3.1 PermissionRequest

What a gate hands a surface when a verdict resolves to interaction.

```json
{
  "v": 1,
  "subject": "b3:9f2c…",                 // Fingerprint — an identity, never a location
  "action":  { "class": "exec", "display": "run_command: cd <path>" },
  "violation": "outside-granted-allowlist",
  "matrix":  { … },                       // §3.2
  "context": { "session": "…", "rationale": "…", "generation": 41 }
}
```

### 3.2 DecisionMatrix

The decision *space*. Nothing here encodes layout — rows, columns, and
ordering are the consumer's.

```json
{
  "verbs":  ["allow", "deny"],
  "scopes": ["once", "session"],
  "default": ["allow", "once"],           // rendering hint only (the ⬅ cursor)
  "escalations": ["audit"]                 // affordances; MAY be rendered
}
```

The scope vocabulary is open: this spec fixes the laws over scopes, not the
set. A durable scope (e.g. `always`) materializes as a **signed loosening
entry** in the policy store and is therefore governed by L2.

### 3.3 Decision

```json
{ "v": 1, "grant": { "verb": "allow", "scope": "session" } }
{ "v": 1, "escalate": "audit" }
```

`escalate` carries **zero authority** (L4): it navigates the human to a
richer surface; the request remains undecided until a `grant` returns.

### 3.4 Introduction

First contact: an unpinned identity proposing itself.

```json
{
  "v": 1,
  "fingerprint": "b3:9f2c…",
  "pubkey": "ed25519:…",
  "channel": "mdns | dial-back | relay | manual | qr",
  "proposed_caveats": [ … ],               // Caveats; the requested ceiling
  "observed": { "addr_candidates": [ … ] } // candidates, never load-bearing
}
```

On receipt, an implementation MUST verify `fingerprint == blake3(pubkey)`
and reject on mismatch **before** any surface renders it (self-certification
is checked by the library, not delegated to the human).

### 3.5 PinRecord / GrantRecord (the chained store)

Durable outcomes are payloads of `MerkleNode<T>`:

```json
{
  "parents": ["cid:…"],                    // ⌀ only for genesis
  "payload": {
    "v": 1,
    "fingerprint": "b3:9f2c…",
    "pubkey": "ed25519:…",
    "channel": "qr",
    "caveats": [ … ],                      // the granted meet, not the request
    "decision": { "grant": { "verb": "pin", "scope": "always" } },
    "presence": { "kind": "passkey", "discharge": "…" },   // optional; §5.3
    "granted_at": "2026-07-15T21:04:00Z"   // provenance data, not validity
  },
  "sig": "ed25519:…"                       // over the node's ContentId
}
```

The signature covers the `ContentId`; the `ContentId` covers the parents.
Consequences in §5.1.

### 3.6 DecisionSurface (the seam)

Language-idiomatic equivalents of:

```rust
#[async_trait]
pub trait DecisionSurface {
    async fn decide(&self, req: PermissionRequest) -> Decision;
}
```

Policy files (#220) are the headless implementation of this trait. Client
libraries in Python/Dart/TypeScript expose the same shape over the JSON
wire objects.

## 4. The Laws (normative)

Six laws. Each carries a proof obligation (PO); §6.2 maps POs to the formal
track. Per the governance rule (§7), nothing joins this section without a
proof obligation demanding it.

### L1 — Resolution is a meet

Verdicts are totally ordered by restrictiveness
(`deny ⊏ passkey ⊏ ask ⊏ approve`). Resolution of request `q` against rule
set `R`:

```
resolve(R, q) = ⨅ { verdict(r) | r ∈ R, r matches q }
```

**Consequence:** ⨅ is associative, commutative, idempotent ⇒ resolution is
independent of rule order, file order, and load order. No ordering attack
exists. **PO-1.**

### L2 — Tamper-monotonicity

For any mutation `m` of the policy store made **without** the signing key:

```
resolve(m(R), q) ⊑ resolve(R, q)
```

A disk-write attacker can only narrow authority, never widen it. Forged
restrictive entries are a nuisance; forged loosening entries are dropped at
load (verification is fail-closed).

**Hypothesis H1 (no-replay):** `m` cannot undetectably reintroduce a
previously-signed loosening entry. H1 is discharged by the chained store
(§5.1), not assumed. **PO-2** (proved under H1; H1's discharge is PO-2a).

### L3 — Fail-closed totality

`resolve` is total: every request yields a verdict; no input reaches
"undefined permission." The interactive bottom is `ask`. Absent a bound
surface, interaction-requiring verdicts degrade restrictively:

```
headless: ask ↦ deny,  passkey ↦ deny        (degradation is ⊑-monotone)
```

**PO-3.**

### L4 — Attenuation

Authority composes by meet and never amplifies:

```
effective = granted ⊓ required        granted = requested ⊓ ceiling
```

Escalations carry no authority: `authority(escalate) = ⊥`.
Already property-tested upstream (`meet_never_amplifies`,
agent-mesh-protocol); this law names the obligation the formal track
re-proves over the kernel. **PO-4.**

### L5 — The ceremony gate

```
association(peer) ⇒ pinned(fingerprint(peer))
```

`fingerprint = blake3(pubkey)` is self-certifying, therefore **re-key ⇒ new
fingerprint ⇒ unpinned ⇒ full re-ceremony**. No silent identity swap is
expressible. A pin is created only by (a) a `Decision::grant` from a bound
surface, or (b) a pre-pinned policy entry — which is a signed loosening
entry and therefore governed by L2. **PO-5.**

### L6 — Completeness without escalation

Every `DecisionMatrix` MUST be decidable with all escalations unrendered:
`verbs × scopes` is non-empty and sufficient. (A harness with no audit
surface — hermes — renders a complete chooser by omission.) **PO-6**
(structural validation).

## 5. Mechanism (below the law line)

Mechanisms implement or discharge the laws; they add no new ones.

### 5.1 The chained store (discharges H1)

Pin/grant records are `MerkleNode<T>` in the `content-addressable` crate
(BLAKE3 `ContentId`, canonical DAG-CBOR, parent links). Because the
signature covers the `ContentId` and the `ContentId` covers the parents,
a replayed-after-deletion entry re-enters with a stale parent set: the head
no longer matches the store's, and verification rejects it loudly. This
retires the documented known-limit of flat signed files (policy.rs; #226).

### 5.2 Signed loosening verdicts (shipped)

The exposure is asymmetric — a forged `deny`/`ask` only narrows; a forged
`approve` widens — so signatures are required on loosening entries only.
Shipped in #226/#227 (`ExecEntry::signing_payload`,
`PolicyFile::verified_approves`, fail-closed drop). This spec inherits that
contract unchanged and extends it to pins (§3.5).

### 5.3 Presence-attested pins

A pin MAY carry a `presence` discharge: a WebAuthn/passkey step-up bound to
the pin's `ContentId` (the `DischargeVerifier` seam; PR #214 lineage). This
upgrades first contact from "someone at a keyboard clicked" to a
hardware-attested human decision. Optional by law, recommended for pins
whose caveat ceiling is broad.

## 6. Conformance

### 6.1 Shared vectors

`tests/vectors/*.json` (to be populated with the kernel): each vector is
`(policy set, request) → verdict` or `(matrix, decision) → outcome`. All
client libraries — Rust, Python, Dart, TypeScript — MUST produce identical
results. Property suites (proptest here; hypothesis/fast-check in bindings)
check L1, L3, L4 executably. This is the kyln round-trip-law pattern,
cross-language.

### 6.2 Formal obligations

The decision kernel (pure `resolve`, precedence, verified-load fold; no IO,
no serde, no wall-clock) is carved for extraction by Charon and proof in
Lean via Aeneas:

| PO | Law | Statement proved |
|---|---|---|
| PO-1 | L1 | ⨅-fold is order-independent (assoc ∘ comm ∘ idem) |
| PO-2 | L2 | keyless mutation is ⊑-monotone, under H1 |
| PO-2a | L2·H1 | chained store rejects replayed loosening entries |
| PO-3 | L3 | totality + monotone headless degradation |
| PO-4 | L4 | meet never amplifies (kernel restatement) |
| PO-5 | L5 | no association without pin; re-key forces re-ceremony |
| PO-6 | L6 | matrix validity is decidable sans escalations |

Pilot: PO-1 and PO-2.

### 6.3 Consumer checklist

A conforming harness:

- [ ] binds a `DecisionSurface` (interactive) or policy files (headless) —
      or accepts the L3 degradation to deny
- [ ] renders `verbs × scopes` completely; MAY render escalations (L6)
- [ ] treats `default` as a cursor hint, never an auto-grant
- [ ] never persists a loosening outcome without a signature (L2)
- [ ] relies on the library's self-certification check (§3.4) rather than
      asking the human to compare key bytes
- [ ] ships no rendering into any agent-* library crate

## 7. Governance — law minimalism

A good system has only the laws it absolutely needs. **Nothing enters §4
without a proof obligation demanding it; everything else is mechanism
(§5).** A standing audit hunts merges the algebra suggests — first
candidate: L1+L4 are one law ("authority composes by meet") on two carriers
(verdict lattice, caveat lattice); if the Lean formulation unifies them
cleanly, six becomes five.

## 8. Relations

- #220 — verdict/policy TOML contract (headless half of this seam)
- #225 — design directive, strategy, client-lib matrix (umbrella)
- #226 / #227 — signed loosening entries (shipped mechanism, §5.2)
- PR #214 — presence/WebAuthn lineage (§5.3)
- agent-mesh#65 — `Introduction` struct and mesh decision surfaces
- newt-agent#1209 — first consumer: pinning ceremony (HIGH)
- agent-mesh `docs/decisions/floating_identity.md` — identity doctrine
  (law 5 there = L5 here, seen from the transport)
- `content-addressable` crate — `ContentId`, canonical DAG-CBOR,
  `MerkleNode` (§5.1)
