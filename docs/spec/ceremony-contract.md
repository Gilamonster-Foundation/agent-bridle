# The Ceremony Contract

**Status:** DRAFT 0.1.5 (2026-07-16) — revised per review rounds 1–4 (#229);
round 4 = adversarial security review (GPT-5/Codex), findings adjudicated
against the security-engineering canon (RFC 6962, TUF, Schneier-Kelsey,
FssAgg, Landrock-Pedersen; see the PR thread). Normative once accepted.
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
| **Fingerprint** | `H(pubkey)` rendered as a **multihash** — a self-describing, self-certifying *name* for the key. The key is the identity; the fingerprint is its name. Algorithms are profile pins (§8), never law: *BLAKE3 is an implementation detail* | `agent_mesh_protocol::Fingerprint` (raw blake3 today; multihash wire format tracked on agent-mesh#66) |
| **Principal** | the root identity a human (or org) controls; agents and surfaces chain to it | `agent_mesh_protocol::UserKey` |
| **Memo** | the ancestor discipline (content-addressable-python `data.py`): every value carries its content-id and **reads verify it**. Its Rust heirs: `ContentId` (naming), `MerkleNode` (chaining+sigs), and `Sealed<T>` (§3 preamble — verify at construction, immutable after) | lineage; `Sealed<T>` to build |
| **Caveats** | attenuable authority; forms a meet-semilattice | `agent_mesh_protocol::Caveats` (`meet_never_amplifies` is property-tested) |
| **Verdict** | durable disposition: `deny ⊏ attest ⊏ ask ⊏ approve`, ordered by restrictiveness | `agent_bridle_core::policy::Verdict` (`precedence()`; code says `Passkey` until #231 lands) |
| **attest** | allowed only via a presence ceremony — the term follows the trusted-computing literature's *attestation* (Parno et al.); renamed from `passkey`, which remains correct for the *hardware mechanism* only | #231 (coordinated pre-1.0 rename) |
| **chain-store** | *term of art:* the append-only-verifiable record log — parent-linked full lines, signed content CIDs | `content-addressable` `MerkleNode` + the conventions of §5.1 |
| **Gate** | the enforcement choke-point; mints `ToolContext` only inside `authorize()` | `agent-bridle-core` |
| **Surface** | a consumer-supplied renderer of decisions (TUI, GUI, policy file, API) | this spec, §3.7 |
| **Escalation** | a navigation affordance (e.g. `audit`) — never authority | this spec, §3.2 |
| **Pin** | a durable, provenance-carrying record that an identity's key was accepted | this spec, §3.5 |
| **Ceremony** | the interactive resolution of a decision the laws refuse to default | this spec, §4 L5 |
| **ContentId / MerkleNode** | CID (multihash) over canonical DAG-CBOR; parent-linked record; v1 profile hashes with BLAKE3-256 (§8) | `content-addressable` crate |

Encodings: **one schema, three encodings.** JSON for interchange (client
libs), TOML at rest (#220 policy files), **canonical DAG-CBOR for anything
hashed or signed**. Signatures and `ContentId`s are computed over canonical
bytes only.

Identifiers are **self-describing**: fingerprints are multihash, keys and
signatures are multicodec-tagged, links are CIDv1 (multihash-native).
Comparison is over the opaque bytes *including* the code — two hash
algorithms never collide silently. The `b3:` / `ed25519:` / `cid:`
prefixes in this document's examples render the **v1 profile** (§8); the
formats themselves are algorithm-agnostic.

Time: per the workspace hard rule, **wall-clock is never a coordination
primitive**. Validity keys on generation counters
(`valid_for_generation`); RFC 3339 timestamps appear in records as
provenance *data* supplied by the boundary, never read by the kernel.

## 2. The seam

Libraries define the decision **space**; consumers define the **layout**.
A library crate MUST NOT contain rendering components or interactive
prompting. A consumer binds a `DecisionSurface` (§3.7); with none bound,
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

### 2.1 Who has an identity

**Every participant is a fingerprint.** Identity is universal; *roles*
differ in which wire objects a key signs:

| Role | Holds | Signs |
|---|---|---|
| **Principal** | the root keypair (vault/hardware-resident) | issuance of agent & surface certs; durable loosening entries |
| **Agent** | a keypair chained to a principal | envelopes, requests, delegations |
| **Surface** | a keypair chained to a principal — possibly *nothing else* (a no-compute device is a keypair + a renderer) | its `Decision`s and `AuditRecord`s |
| **Gate** | the enforcement identity (usually = its agent) | chain-store appends |

A monolith (newt-agent carrying bridle + mesh in-process) is the
**degenerate case**: one fingerprint wearing every role. Delegation is the
roles splitting into separate keypairs — nothing else changes. An
in-process surface MAY omit signing its `Decision`s (same trust domain as
the gate); a **remote** surface MUST sign them, so grant provenance in the
chain-store is attributable end to end.

**Delegation** (agent → agent, e.g. newt to a back-end worker): both
endpoints present chains to a **common pinned principal** (L5). The
principal's private key is involved at *issuance*, not per-delegation —
headless fleets verify chains offline while the root key stays in
hardware; revocation is a generation bump. Cross-principal delegation is
two principals pinning each other's roots — L5 again, one level up.

## 3. Wire objects

Field names are normative. All objects carry `"v": <profile-version>`, and
verification dispatches on it (**version dispatch**, not lenient parsing).

**Signature verification is over the received canonical bytes, never over
a re-serialization.** Typed deserialization drops unknown fields, so
reserializing a parsed object cannot reproduce the signed digest — verify
the bytes as received, then parse (RFC 8785 canonicalization pitfall;
JWS/COSE practice). **Unknown authority-bearing fields fail closed:** an
object carrying a field the profile version does not define is *rejected*,
not ignored — tolerating it is a silent downgrade / version-confusion
surface (finding #7). Non-authority annotations MAY be preserved verbatim
only when the profile marks them non-critical (COSE critical-header model).
Exactly **one** of `grant` / `escalate` is permitted on a Decision;
zero-or-both is rejected.

**The Memo discipline (WF-2).** Every wire object is a Memo-descendant,
with capabilities attached by *mechanical criteria* — a boundary test, not
a quota:

- **content-CID: unconditional.** Anything serializable and meaningful
  beyond this process has canonical bytes and therefore a name.
- **`by` + `sig`: at trust boundaries.** REQUIRED whenever the object
  crosses to a different fingerprint (remote surface, delegated agent,
  another host); MAY be omitted in-process — same trust domain, nothing to
  assert.
- **`parents`: for durability.** Anything appended to a chain-store links.
- **Sealed at load.** Implementations construct wire objects only through
  verification (CID recomputed; sig checked when present) — verify once at
  the boundary, immutable thereafter. Nothing enters a kernel unverified.

This is const-correctness for integrity: one unsigned hop breaks the chain
of custody the way one non-const cast breaks the guarantee. The discipline
applies to **all of the data layer and none of the resource layer** — the
same line the pure kernel already draws (§6.2).

### 3.1 PermissionRequest

What a gate hands a surface when a verdict resolves to interaction.

```json
{
  "v": 1,
  "subject": "b3:9f2c…",                 // Fingerprint — an identity, never a location
  "action": {
    "class":   "exec",
    "display": "run_command: cd <path>",  // human-facing presentation
    "effect":  "cid:…"                    // content-CID of the CANONICAL resolved call
  },
  "violation": "outside-granted-allowlist",
  "matrix":  { … },                       // §3.2
  "context": { "session": "…", "rationale": "…", "generation": 41 },
  "by": "b3:…", "sig": "…"                // the GATE's signature — required remote (Memo discipline)
}
```

**`effect` binds the signature to what executes, not to what is shown**
(finding #2 — *what you see is what you sign*, Landrock-Pedersen 1998).
`display` is a lossy human rendering; `effect` is the content-CID of the
canonical, fully-resolved call (arguments *and* resolved resources — the
`CallRequest` the tool layer already produces). The gate MUST, before
minting authority, **recompute the canonical effect from the call it is
about to run and check it equals `action.effect`** — otherwise a stale or
lossy `display`→effect mapping approves X and executes Y while the CID
still matches (confused-deputy / TOCTOU). Display and effect are bound
together under the one signature; a surface that cannot faithfully render
`effect`'s meaning MUST refuse rather than show a prettier `display`.

A **remote** surface MUST verify the request's signature and that `by`
chains to a pinned principal **before rendering** — an unauthenticated
prompt is a phishing canvas that trains the human on fake ceremonies
(§5.6), even though its harvested decision is unredeemable (the CID
binding, §3.3). In-process, `by`/`sig` MAY be omitted.

### 3.2 DecisionMatrix

The decision *space*. Nothing here encodes layout — rows, columns, and
ordering are the consumer's.

```json
{
  "verbs":  ["allow", "attest", "deny"],
  "scopes": ["once", "session"],
  "default": ["allow", "once"],           // rendering hint AND opinion surface
  "escalations": ["audit"]                 // affordances; MAY be rendered
}
```

**The third verb, `attest`,** is the disposition "allowed, but only via a
presence ceremony." It is not new structure — it surfaces the existing
`attest` verdict (né `passkey`, #231) in the matrix. Its meaning composes
with the ordinary scopes:

- `attest × once` — a fresh ceremony for **every** action;
- `attest × session` — **one** ceremony whose discharge covers the current
  generation; prompts weaken to plain confirmation until the generation
  ends. The pragmatic affordance for humans who tire of ceremony.

No `attest_deny` exists: deny is the bottom — there is nothing to
discharge. Discharge scopes order by coverage (`once ⊑ session`), so
broader coverage is a loosening; storing one durably is governed by L2.
The kernel never reads a clock: a discharge binds to a **generation**, and
the *boundary* bumps generations for any reason it likes — a timer, a
screen lock, a lid close. Wall-clock lives in consumer-land as one bump
trigger among several; authority math stays clock-free.

**`default` is an opinion surface.** It is a rendering hint (the ⬅ cursor)
— never an auto-grant — and it is exactly where an *administrator or
packager* expresses judgment: `rm -rf` ships as `["deny", "session"]`.
Pre-populated matrices plus durable **negative pins** (signed deny records
in the chain-store, §5.1, carrying provenance — *forbidden at Gate g, by
Fingerprint admin, during Ceremony c* — and transportable over agent-mesh
or configuration) are the enterprise-affordance / parental-control story.
Mechanism, not law: provenance and non-removability come from the
chain-store; the authority math is unchanged.

The scope vocabulary is open: this spec fixes the laws over scopes, not the
set. A durable scope (e.g. `always`) materializes as a **signed loosening
entry** in the policy store and is therefore governed by L2.

**Well-formedness (WF-1).** Every matrix MUST be decidable with all
escalations unrendered: `verbs × scopes` is non-empty and sufficient. (A
harness with no audit surface — hermes — renders a complete chooser by
omission.) This is a structural predicate on the wire object, checked in
conformance (§6.2) — deliberately *not* a law; see §7.

### 3.3 Decision

```json
{ "v": 1, "request": "cid:…",            // content-CID of the PermissionRequest AS ISSUED
  "grant": { "verb": "allow", "scope": "once" },
  "by": "b3:…", "sig": "…" }             // sig over this record's content-CID
{ "v": 1, "request": "cid:…",
  "grant": { "verb": "attest", "scope": "session",
             "discharge": { "challenge": "cid:…", "attempt": "…" } },  // §3.3.1
  "by": "b3:…", "sig": "…" }
{ "v": 1, "request": "cid:…", "escalate": "audit", "by": "b3:…", "sig": "…" }
```

`escalate` carries **zero authority** (L4): it navigates the human to a
richer surface; the request remains undecided until a `grant` returns. A
**remote** surface MUST sign its decisions; an in-process surface MAY omit
`by`/`sig` (§2.1), but the `request` binding is unconditional.

**Gate acceptance is a checklist of MUSTs — the client is never trusted**
(finding #3; never-trust-client authorization / capability monotonicity).
The gate mints authority only when *all* hold:

1. `request` equals the content-CID of the `PermissionRequest` the gate
   itself issued (render-swap closure, §5.6);
2. `grant.verb ∈ matrix.verbs` **and** `grant.scope ∈ matrix.scopes` —
   the answer is a member of the *offered* option-set;
3. the resulting authority is `⊑` the request's ceiling (L4) — a
   `once/session` request can never be answered `always`; a surface
   cannot return more than was asked;
4. the executable effect recomputes equal to `action.effect` (§3.1);
5. if `grant.verb == attest`, the discharge verifies (§3.3.1).

A buggy or compromised surface that violates any of these is refused at
the gate, not obeyed — the wire enforces L4, it does not merely state it.

#### 3.3.1 Attest discharge

An `attest` grant is **inert until a presence proof is verified**
(finding #4 — a verb meaning "prove presence" must carry the proof and a
normative verify step; WebAuthn/FIDO2 challenge-response). It reuses
bridle's shipped step-up contract:

- the gate issues a **domain-separated, single-use `Challenge`** (its
  content-CID is `discharge.challenge`), bound to this request's CID, the
  subject, and the current generation;
- the authenticator returns a `DischargeAttempt` (`discharge.attempt`) —
  a WebAuthn assertion over that challenge;
- the gate verifies it through `step_up::DischargeVerifier` and marks the
  challenge consumed **before** the grant takes effect. `attest × session`
  binds the verified discharge to the generation; a new generation voids
  it. An unverified or replayed discharge yields **no** authority.

### 3.4 Introduction

First contact is a **two-message challenge-response**, because freshness
comes from the *recipient*, never from the introducer (finding #5 — a
self-chosen nonce inside a self-signed object is byte-for-byte replayable;
the party seeking assurance must issue and consume the challenge).

**Message 1 — the recipient issues a challenge** it will remember:

```json
{ "v": 1, "challenge": "…",              // fresh random, recipient-generated
  "issued_by": "b3:…",                    // the recipient's fingerprint
  "for_generation": 41, "expires_at_generation": 42 }
```

**Message 2 — the introducer answers, binding that challenge:**

```json
{
  "v": 1,
  "fingerprint": "b3:9f2c…",
  "pubkey": "ed25519:…",
  "channel": "mdns | dial-back | relay | manual | qr",
  "proposed_caveats": [ … ],               // Caveats; the requested ceiling
  "observed": { "addr_candidates": [ … ] },// candidates, never load-bearing
  "answers": "…",                          // the recipient's challenge, echoed
  "transcript": "cid:…",                   // binds both fingerprints + msg 1
  "sig": "…"                               // by the INTRODUCED key over all of the above
}
```

On receipt of message 2, an implementation MUST, **before any surface
renders it**:

1. confirm `answers` is a challenge **this recipient issued, still
   unconsumed and unexpired**, then mark it consumed — replay-state lives
   with the challenger, so a captured introduction cannot be re-presented
   (Needham-Schroeder / station-to-station; unknown-key-share closure);
2. confirm the fingerprint's declared hash algorithm is a **member of the
   locally-trusted profile allowlist (§8) — checked *before* any hashing**
   (finding #8; the `alg:none`/algorithm-confusion class — never let the
   object choose its own verifier), then verify the fingerprint is that
   algorithm's multihash name of `pubkey` (self-certification checked by
   the library, never by the human);
3. verify `sig` under `pubkey` over message 2 including `answers` and
   `transcript` — **proof of possession**, transcript-bound so a bystander
   cannot relay someone else's introduction as their own.

### 3.5 PinRecord / GrantRecord (the chain-store)

Durable outcomes are payloads of `MerkleNode<T>`:

```json
{
  "parents": ["cid:…"],                    // line-CIDs of predecessors, sig INCLUDED (§5.1); ⌀ only for genesis
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
  "sig": "ed25519:…"                       // over the content-CID (presigned form; §5.1)
}
```

Two CIDs per record: the **content-CID** (canonical form *minus* `sig` —
what is signed) and the **line-CID** (canonical form *including* `sig` —
what descendants reference in `parents`). Consequences in §5.1.

### 3.6 AuditRecord & RevocationRecord (ceremonies over the store)

An audit is a ceremony whose subject is the chain head: a fingerprint
witnesses the store's state and signs what it saw.

```json
{
  "v": 1,
  "witnessed_head": "cid:…",               // line-CID of the head at review time
  "fingerprint": "b3:…",                   // the witness
  "presence": { "kind": "passkey", "discharge": "…" },  // literal finger on hardware
  "decision": { "grant": { "verb": "attest", "scope": "once" } }
}
```

It is appended to the chain-store like any record (its own content-CID,
sig, parents), so audits are themselves tamper-evident and auditable. No
new law — L5 composed with the log; one new record type. An audit's
`witnessed_head`, once **exported to independently-protected storage**
(§5.7), becomes an anti-rollback anchor — but an AuditRecord that lives
*only inside the chain* rolls back with it and anchors nothing (finding
#1). Anti-rollback is §5.7's job; the AuditRecord is its raw material.

**RevocationRecord** — punting a load-bearing identity is itself a
ceremony, and per L2 it demands **quorum**:

```json
{
  "v": 1,
  "payload": {                             // the CANONICAL UNSIGNED payload — every signer signs THIS
    "revoke": "b3:…",                      // the fingerprint being punted
    "reason": "compromise | rotation | retirement",
    "succession": "b3:…",                  // optional successor (root rotation)
    "policy": "cid:…"                      // the quorum policy in force
  },
  "signers": [                             // detached; each sig is over content-CID(payload)
    { "by": "b3:aa…", "sig": "…" },
    { "by": "b3:cc…", "sig": "…" }         // sorted by `by`, deduplicated
  ]
}
```

**One payload, many detached signatures** (finding #6 — a signature nested
in the object it signs is circular; each signer would otherwise sign a
different, progressively-grown record). Every signer signs
`content-CID(payload)` — the fixed unsigned inner object — so all
signatures cover *identical* bytes. `signers` is **sorted by `by` and
deduplicated** (one identity cannot count twice toward `k`), and the
signature set is *not* part of what is signed. The chain-append signature
(`sig` over the whole record's content-CID, WF-2) is separate from the
quorum signatures and added last.

Acceptance: `|distinct valid signers ∩ eligible| ≥ k` under the named
`policy`. The quorum policy (k, n, eligible signers) is itself a
principal-signed loosening entry established at setup — defining *who may
revoke* is authority structure, governed by L2 like any other loosening.
Revoking the **last** root without a `succession` ends the mesh;
implementations MUST refuse it unless the record carries an explicit
`"tombstone": true`.

### 3.7 DecisionSurface (the seam)

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

Five laws. Each carries a proof obligation (PO); §6.2 maps POs to the
formal track. Per the governance rule (§7), nothing joins this section
without a proof obligation demanding it.

### L1 — Resolution is a meet

Verdicts are totally ordered by restrictiveness
(`deny ⊏ attest ⊏ ask ⊏ approve`). Resolution of request `q` against rule
set `R`:

```
resolve(R, q) = ⨅ { verdict(r) | r ∈ R, r matches q }
```

**Consequence:** ⨅ is associative, commutative, idempotent ⇒ resolution is
independent of rule order, file order, and load order. No ordering attack
exists. **PO-1.**

### L2 — Tamper-boundedness

For any mutation `m` made by a party holding **fewer than quorum(target)**
of the designated keys:

```
resolve(m(R), q) ⊑ resolve(R, q)                    (no widening)
LoadBearing(R) ⊆ LoadBearing(m(R))                  (no structural narrowing)
```

Two directions, one law. **Downward:** a sub-quorum actor can only narrow
*authority*, never widen it — forged restrictive entries are a nuisance;
forged loosening entries are dropped at load (verification is
fail-closed). **Upward:** a sub-quorum actor cannot shrink the
**load-bearing identity structure** — pinned principals, enrolled devices,
blessed anchors. Narrowing splits into two species: *reversible* narrowing
(a spammed deny — the principal can prune it) is nuisance-bounded and
needs no key; **irreversible narrowing — revoking a load-bearing identity
— requires quorum**, because a fail-closed system's own failure mode is an
adversary who can *force* closure. "Reset mesh" must not be a
denial-of-service surface. Availability is a security property.

**Mechanism honesty (two layers).** Under flat policy files this law holds
for **additions only** — deleting a restrictive entry widens authority and
flat files cannot detect it. The chain-store (§5.1) extends detection to
{add, delete, reorder} of the log's *interior*. But the chain-store **by
itself does not detect rollback/truncation of the log's *tail*, nor a
split-view fork** (finding #1): an attacker who truncates a restrictive
suffix and its head, or presents an older valid fork, leaves a prefix that
still verifies — this is the established limit of every hash-chained log
(Schneier-Kelsey 1999; FssAgg / eprint 2008/185; and the reason
Certificate Transparency requires gossiped Signed Tree Heads, RFC 6962).
Closing it requires an **independently-protected monotonic anchor** (§5.7),
*not* the chain alone. An anti-rollback claim resting on an in-chain
AuditRecord is circular — it rolls back with the log it certifies.

**Hypothesis H1 (append-only-verifiability + monotone freshness):** `m`
cannot undetectably remove/reintroduce an *interior* record (chain-store),
**nor roll the log back past the last independently-anchored head** (§5.7).
H1 is *discharged by mechanism*, not assumed: interior integrity by the
chain (**PO-2a**), tail/fork integrity by the external anchor (**PO-2c**),
revocation-quorum soundness by §3.6 (**PO-2b**). **PO-2** proves ⊑-monotony
under H1.

### L3 — Fail-closed totality

`resolve` is total: every request yields a verdict; no input reaches
"undefined permission." The interactive bottom is `ask`. Absent a bound
surface, interaction-requiring verdicts degrade restrictively:

```
headless: ask ↦ deny,  attest ↦ deny         (degradation is ⊑-monotone)
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

`fingerprint = H(pubkey)`, a multihash name, is **self-certifying** for any
H the profile pins (§8) with two required properties: collision resistance,
and hardness of finding a key matching a given name. Therefore **re-key ⇒
new fingerprint ⇒ unpinned ⇒ full re-ceremony**. No silent identity swap is
expressible. (Rotating H is *re-naming*, not re-keying: the key signs a
linkage record binding its new name — quorum-free, the identity never
moved.) A pin is created only by (a) a `Decision::grant` from a bound
surface, or (b) a pre-pinned policy entry — which is a signed loosening
entry and therefore governed by L2.

The pinned predicate is **transitive through certification**:

```
pinned(fp) ⇔ fp ∈ PinSet
           ∨ ∃ chain: fp →* root,  root ∈ PinSet,
             proof-of-possession at every link
```

so pinning a principal admits the agents and surfaces it issues — this is
delegation (§2.1), and it is already shipped mechanism: mesh `CertChain::
verify` chains to the user root fail-closed (agent-mesh #39, §9.1) and
certification requires proof-of-possession (agent-mesh #40, §9.2).
**PO-5** (now including chain soundness).

## 5. Mechanism (below the law line)

Mechanisms implement or discharge the laws; they add no new ones.

### 5.1 The chain-store (load-bearing for L2)

Records are `MerkleNode<T>` in the `content-addressable` crate (multihash
CIDs — §8, canonical DAG-CBOR, parent links), with these conventions:

```
c_i = H(canon(record_i ∖ sig))          content-CID   (what is signed)
s_i = Sign(k, c_i)                       the signature (sig-trim convention)
line_i = record_i ∪ { sig: s_i }         the full at-rest line
ℓ_i = H(canon(line_i))                   line-CID      (what parents reference)
parents(record_{i+1}) ∋ ℓ_i              descendants commit to content AND sig
```

Parents reference the **line-CID** — the full predecessor *including its
signature* — so stripping or swapping a historical signature breaks the
chain just as surely as editing content. Editing or removing an *interior*
record orphans every descendant's parent link — it verify-fails loudly
**against a head the verifier already trusts**. This extends interior
integrity to deletions and retires the flat-file known-limit (policy.rs;
#226).

**What the chain alone does NOT do (finding #1):** verification is always
*relative to a head*. Against an attacker who also controls the head —
truncating the tail, or presenting a wholly older/forked-but-valid log —
the surviving prefix verifies fine and nothing is orphaned. The chain
gives interior integrity; **tail and fork integrity require the external
anchor of §5.7.** This spec does not claim otherwise.

Two stated assumptions, doing different jobs:

1. **Deterministic signatures.** `H(sig | content, key) = 0` — given the
   content and the key, the signature carries no fresh entropy. Ed25519
   provides exactly this (RFC 8032 derives the nonce from key and
   message), so the whole log is a **pure function** of (genesis, payload
   sequence, keys). A randomized scheme (ECDSA with random nonce) has
   `H(sig | content, key) > 0`: two honest signings of identical content
   yield different line-CIDs, and the chain forks on any re-sign. The
   entropy identity is the proof obligation that forces a deterministic
   scheme — it governs *reproducibility*.
2. **Collision resistance of `H`** governs *tamper-evidence*. The two are
   independent: determinism makes the log replayable; collision resistance
   makes it unforgeable.

**At rest:** the log's on-disk representation is **JSONL as a lossless
line-oriented view** of the canonical DAG-CBOR records — one `line_i` per
line, human-auditable, no comments or other affordances to make
canonicalization ambiguous. CIDs and signatures are always computed over
the canonical form, never over the view.

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

### 5.4 Enrollment ceremony (SAS pairing)

How a new device or surface — possibly with no compute beyond key storage
and a screen — gets its keypair admitted under a principal (L5, applied to
one's own devices).

The ritual is a **short-authentication-string comparison**, and its shape
matters: a naive "new device shows a phrase, trusted device sends it back
encrypted" is MITM-relayable — an attacker owning the channel relays the
phrase both ways and each side verifies *the attacker's* key. The sound
construction (per Bluetooth numeric comparison / ZRTP):

1. both devices **commit** to nonces before revealing anything;
2. both **derive** the SAS from the *entire key-exchange transcript* —
   commitments, reveals, **and the long-term public keys being enrolled**.
   This last inclusion is not optional: an SAS over only the ephemeral
   session material lets a MITM relay the handshake honestly while
   substituting the long-term keys — the classic key-substitution hole
   (§5.6). The SAS must checksum *what is being pinned*, not merely the
   channel;
3. **a human compares the SAS on both screens** — the out-of-band channel
   the MITM cannot sit on. The phrase is not a secret to transport; it is
   a checksum of the handshake two screens must agree on.

Commit-before-reveal forces a MITM to *guess* the SAS in advance; one
round of a `xxx-000`-style SAS ≈ 1-in-46k. Paranoia is then a parameter,
not a mood:

```
strength(enrollment) = (SAS entropy × rounds, distinct witnesses, presence)
```

Policy sets minima **by caveat ceiling**: a broad ceiling demands more
rounds, witnessing from ≥ 2 previously-secured surfaces, and a hardware
presence discharge (the `attest` verdict doing enrollment duty —
thumbprint on the device). Independent witnesses buy more than extra
rounds: rounds shrink the guess probability; witnesses multiply the
channels an attacker must own *simultaneously*. The completed enrollment
is a `PinRecord` in the chain-store whose payload carries the ceremony
parameters — auditable later (§3.6).

**Punting ≥ pinning.** Revocation (§3.6) is graded on the same scale:
removing an identity demands at least the ceremony strength that enrolled
it — quorum co-signers being the witness axis. Enrollment strength sets a
floor the revocation ceremony must meet, so the strongest identities are
exactly the ones an adversary finds hardest to destroy.

### 5.5 External anchors (corroboration, never the root)

A principal root is **self-sovereign**. Externally published keys —
GitHub-registered keys (`github.com/<user>.keys`), DNS, an org CA, a
previously-secured device — are **candidate corroboration channels** for
it: independent witnesses that the root you are pinning belongs to the
human you think it does. Per the floating-identity doctrine, no anchor is
load-bearing: GitHub corroborates the root; it never *is* the root. A
user with no GitHub enrolls by ceremony alone (§5.4) with zero degradation
in the algebra — anchors raise corroboration, never gate participation.

**Anchors are blessed, participating identities.** ANY public-key display
surface qualifies — *provided the key owner blesses it*: an `AnchorRecord`
(principal-signed binding of channel + location + displayed key) appended
to the chain-store. An unblessed anchor is ignored; a blessed one may
*participate* as a signing/corroboration surface in ceremonies (a
GitHub-key signature counting as one enrollment witness). Blessings are
revoked like any load-bearing identity — RevocationRecord, quorum (§3.6)
— so a captured anchor can be cut loose without ceremony-strength loss:
corroboration is k-of-n, and n just shrank by one.

### 5.6 The MITM ledger — every channel, every closure

"No MITM hole anywhere" is a claim to *enumerate*, not to feel:

| Channel | Attack | Closure | Residual |
|---|---|---|---|
| First contact (stranger) | TOFU key swap | L5 ceremony: SAS or out-of-band fingerprint check; or chain to a common pinned principal | the ceremony itself (below) |
| First contact | **introduction replay / unknown-key-share** | PoP: the introduced key signs the Introduction over a transcript-bound `fresh` (§3.4) | — |
| Enrollment handshake | relay + **key substitution** | commit-then-reveal; SAS covers the **long-term keys** (§5.4·2); human comparison is the authentic channel | SAS guess ≈ n⁻ᵏ per round; rounds × witnesses shrink it |
| Post-pin transport | impersonation on any raced path | dial-by-pubkey: QUIC/TLS authenticates the **node key** — a path that answers must hold the private key; paths are hints, never identity | key theft (out of scope: L2 quorum + revocation) |
| Delegation | rogue "delegated" agent inserted | chains verify to a pinned principal; proof-of-possession at issuance (mesh #39/#40) | principal-root compromise (quorum revocation + succession) |
| Remote surface | **render-swap**: human approves X, gate runs Y | `Decision.request` = content-CID of the request as rendered; sig covers it; gate matches CIDs (§3.3) | compromised surface *device* → its grants are attributable + revocable |
| Remote surface | **phishing canvas**: forged/unsolicited requests train the human | requests are gate-signed; surface verifies chain-to-pinned-principal *before rendering* (§3.1) | compromised gate key → quorum revocation |
| Chain-store sync | forgery in transit | records are self-authenticating (signed + chained); transport can corrupt nothing silently | — |
| Chain-store sync | **rollback / truncation / fork** (stale-but-valid head hides a revocation) | external anti-rollback anchor (§5.7): independently-stored monotonic head + witness cosigning + fork = proof-of-misbehavior. The chain alone does NOT close this. | withholding = visible staleness vs. a remembered anchor → fail closed |
| Anchor channel | compromised registry vouches a fake root | anchors are blessed, k-of-n, never sufficient alone (§5.5) | k−1 colluding anchors corroborate nothing |
| The human | prompt fatigue / phishing the ceremony | `attest` for high ceilings; distinct ceremony UI is consumer guidance (newt#1209) | irreducible; parameterized paranoia exists for exactly this |

The pattern behind every row: **the authenticated thing is always the
key, never the channel** — locations, relays, registries, and rendered
pixels are candidates and hints; signatures and CIDs are what the gate
trusts. One doctrine, applied across every row.

### 5.7 The anti-rollback anchor (external, load-bearing for L2·H1)

A hash-chained log is verified *relative to a head*. Every such log —
Schneier-Kelsey secure audit logs (1999), the FssAgg truncation analysis
(eprint 2008/185), Certificate Transparency (RFC 6962) — shares one limit:
**an attacker who controls the head can truncate the tail or present an
older/forked-but-internally-valid log, and it still verifies.** The chain
gives interior integrity only. Closing tail-and-fork requires state the
attacker does not control. This spec adopts the three canonical layers,
in ascending assurance:

1. **Independently-protected monotonic head (required).** Each participant
   remembers, in storage separate from the log, the highest
   `(generation, length, head-CID)` it has accepted, and **MUST reject any
   presented head that is not a consistent forward-extension** of it —
   never a shorter length or lower generation (the TUF rule: *"clients
   MUST NOT replace metadata with a version number less than the one
   currently trusted"*, RFC 6962 monotonicity). This alone defeats
   truncation and rollback *for that participant*.
2. **Witness cosigning (recommended for shared stores).** The head is
   periodically countersigned by one or more witnesses whose signatures
   are the `AuditRecord`s of §3.6 **exported off-chain**. A participant
   accepts a head only if it carries a witness cosignature no older than
   its freshness policy (CT gossip / STH; witness-cosigning). This defeats
   *secret* equivocation: to fool a victim the attacker must fork the
   witnesses too.
3. **Fork = proof of misbehavior (required).** Two validly-signed heads of
   the same store at the same length with different CIDs are incontestable
   evidence of equivocation (RFC 6962). Implementations MUST treat a
   detected fork as a security event, halt authority minting from that
   store, and escalate — never silently pick one.

For a solo user (§5.4's n=2 world) the monotonic head lives on each of
their own enrolled devices, and each device is the other's witness — the
same k-of-n substrate as revocation, reused. A quorum/witness set is the
enterprise instance of the identical mechanism. **Nothing here trusts the
storage medium**; the anchor is trusted state a participant carries into
each verification, exactly as `pinned` is.

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
| PO-2 | L2 | sub-quorum mutation is ⊑-monotone, under H1 |
| PO-2a | L2·H1 | chain-store rejects removed/replayed *interior* records (vs. a trusted head) |
| PO-2b | L2 | a sub-quorum coalition cannot shrink the load-bearing pin set |
| PO-2c | L2·H1 | against the §5.7 anchor, tail truncation and fork are rejected (not merely detected-later) |
| PO-3 | L3 | totality + monotone headless degradation |
| PO-4 | L4 | meet never amplifies (kernel restatement) |
| PO-5 | L5 | no association without pin; re-key forces re-ceremony |
| WF-1 | §3.2 | matrix decidable sans escalations (structural predicate, not a law) |
| WF-2 | §3 | Memo discipline: CID unconditional; sig at trust boundaries; parents for durability; Sealed at load |

Pilot: PO-1 and PO-2.

### 6.3 Consumer checklist

A conforming harness:

- [ ] binds a `DecisionSurface` (interactive) or policy files (headless) —
      or accepts the L3 degradation to deny
- [ ] renders `verbs × scopes` completely; MAY render escalations (WF-1, §3.2)
- [ ] treats `default` as a cursor hint, never an auto-grant
- [ ] never persists a loosening outcome without a signature (L2)
- [ ] relies on the library's self-certification + proof-of-possession
      checks (§3.4) rather than asking the human to compare key bytes
- [ ] (remote) verifies a request's gate signature before rendering (§3.1)
- [ ] constructs wire objects only through verified load (Sealed; WF-2),
      verifying signatures over received bytes and rejecting unknown
      authority-bearing fields fail-closed (§3)
- [ ] (gate) enforces the §3.3 acceptance checklist — request-CID match,
      matrix membership, ceiling, effect recomputation, attest discharge —
      never trusting the surface
- [ ] (gate) checks a fingerprint's algorithm against the trusted profile
      allowlist *before* dispatch (§3.4, §8)
- [ ] carries a §5.7 anti-rollback anchor for any shared/persisted store
- [ ] ships no rendering into any agent-* library crate

## 7. Governance — law minimalism

A good system has only the laws it absolutely needs. **Nothing enters §4
without a proof obligation demanding it; everything else is mechanism
(§5) or well-formedness (§3).** The count is audited ruthlessly:

- **Executed (review 1, 2026-07-15):** L6 demoted to WF-1 — completeness
  without escalation is a structural predicate on a wire object, not an
  algebraic invariant of authority. Six laws became five.
- **Executed (review 2, 2026-07-15):** the revocation-DoS invariant
  ("reset mesh" must not be an attack surface) was absorbed into L2 as its
  upward direction — tamper-*monotonicity* became tamper-*boundedness*.
  Zero count change; PO-2b added.
- **Executed (review 3, 2026-07-16):** the Memo discipline and the
  multihash directive landed as wire discipline (WF-2) and profile (§8) —
  laws name *properties*; algorithms are pins. L5 de-algorithm'd. Zero
  count change.
- **Executed (review 4, 2026-07-16 — adversarial security review,
  GPT-5/Codex):** eight true-positive findings, all adjudicated against
  the canon and closed as *enforcement* (gate MUSTs, §3.3), *mechanism*
  (external anti-rollback anchor §5.7; recipient-issued challenge §3.4;
  canonical quorum payload §3.6; effect-CID binding §3.1), and *wire
  discipline* (fail-closed unknown fields §3; algorithm allowlist §3.4,
  §8). The one law touched — L2 — was *corrected*, not multiplied: its
  H1 was over-claimed (chain alone ⇏ rollback resistance) and is now
  honestly split across chain + anchor. **Still five laws.** The review's
  meta-lesson — "prose becomes authority-bearing protocol" — is the case
  for the formal track, not against the design.
- **Next candidate:** L1+L4 are one law ("authority composes by meet") on
  two carriers (verdict lattice, caveat lattice); if the Lean formulation
  unifies them cleanly, five becomes four.

Additions from the same review — the `attest` verb, negative pins, the
`AuditRecord` — cost **zero** laws: each collapsed into existing structure
or landed below the line. The algebra decides the count; ambition doesn't.

## 8. Profile v1 (pins, not laws)

Algorithms are **implementation details**; each pin states the *property*
any replacement must carry. Identifiers are self-describing (multihash /
multicodec), so profile rotation happens under a running mesh.

**Agility needs an allowlist, or it is a downgrade attack** (finding #8).
Self-describing identifiers let the *object* declare its algorithm — so a
verifier that dispatches on the declared code alone lets the attacker pick
a broken hash (the `alg:none` / algorithm-confusion class). Therefore: a
verifier MUST check the declared code against **this locally-trusted
profile table before hashing or verifying**, and reject anything outside
it. Profile *rotation* is a negotiated, principal-signed change to the
allowlist (a loosening entry, L2), never a per-object choice. Agility
lives in the profile, not on the wire.

| Pin | v1 value | Required property (the law's interest) |
|---|---|---|
| Content hash `H` | BLAKE3-256 (multihash `0x1e`) | collision resistance; preimage hardness (L5 self-certification) |
| Signature | Ed25519 (RFC 8032) | **deterministic** — load-bearing for chain reproducibility (§5.1·1); existential unforgeability |
| Canonical encoding | DAG-CBOR (codec `0x71`) | injective, canonical serialization (one value ⇒ one byte string) |
| Links | CIDv1 | multihash-native, codec-tagged |

Rotating `H` is a **re-naming ceremony** (L5): keys sign linkage records
binding their new names; identity never moves. Rotating the signature
scheme is heavier — it is a **re-keying** (full L5 re-ceremony per
identity) because the key *is* the identity. The wire format
(`agent-mesh#66`) carries the codes either way.

## 9. Relations

- #220 — verdict/policy TOML contract (headless half of this seam)
- #225 — design directive, strategy, client-lib matrix (umbrella)
- #226 / #227 — signed loosening entries (shipped mechanism, §5.2)
- #231 — coordinated pre-1.0 rename `passkey` → `attest` (code catch-up
  for this spec's vocabulary)
- PR #214 — presence/WebAuthn lineage (§5.3)
- agent-mesh#65 — `Introduction` struct and mesh decision surfaces
- agent-mesh#66 — enrollment/delegation protocol; multihash wire format
  for `Fingerprint`
- newt-agent#1209 — first consumer: pinning ceremony (HIGH)
- agent-mesh `docs/decisions/floating_identity.md` — identity doctrine
  (law 5 there = L5 here, seen from the transport)
- `content-addressable` crate — `ContentId`, canonical DAG-CBOR,
  `MerkleNode` (§5.1)
