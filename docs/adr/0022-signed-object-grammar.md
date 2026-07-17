# ADR 0022 — Signed-object grammar: one constructor, protected tuple

- Status: **Accepted** — frozen in the v0.3.1 PROTOCOL FREEZE (2026-07-16, review 7); the *proof* that discharges it (PO-1c, a Lean canonicalization-injectivity contract, plus PO-8 allowlist-gating) is the still-held implementation phase.
- Date: 2026-07-16
- Layer: **P1 (Signed-Object Profile)** — the foundation the other five profiles write in. This ADR records the grammar decision behind [`signed-object-profile.md` §2](../spec/signed-object-profile.md) and the genesis sentinel that P2 [`chain-store-profile.md` §1](../spec/chain-store-profile.md) consumes.
- Closes: **OB-13** (bare-cid signature gap → one constructor over a protected tuple) and **OB-14** (`store_id = CID(genesis)` is a non-computable fixed point → `STORE_ID_SELF` sentinel), both from the round-7 protocol-freeze review (README "Review 7 — the v0.3.1 PROTOCOL FREEZE").

## Context

P1 makes objects **nameable, canonical, and verifiable** — it carries no authority semantics, but every authority-bearing profile above it (P0 requests/decisions, P2 store lines, P3 challenges, P4 identity records, P5 render transcripts) is a P1 signed object. So a gap in the signing grammar is a gap under the entire suite.

Two earlier-draft formulations were found to be unsound by the freeze review:

1. **The signature bound too little (OB-13).** A naive envelope signs only `cid = H(body)`:

   ```
   cid = H(body)
   sig = Sign(signer, cid)          ← the gap
   ```

   This authenticates the *body bytes* but leaves the **interpretation-bearing fields outside the signature**: `profile`, `codec`, and (depending on where the key id lives) `signer`. An attacker who cannot forge the signature can still, without breaking it:
   - **re-tag the codec** — present the same `cid`/`sig` under a different declared `codec`, steering the verifier into a different (possibly attacker-favourable) decoder;
   - **re-tag the profile** — replay a structurally-compatible body as a *different record type or profile version* (version-confusion / type-confusion), since the profile string that selects the schema was never signed;
   - **swap the claimed signer** — if the key id sits beside the sig rather than under it.

   All three are the classic "the header selects the algorithm/interpretation but is not in the signed image" family — `alg:none`, JWS header injection, COSE critical-header confusion. The digest is honest about *bytes* and silent about *what those bytes mean*.

2. **Genesis was a non-computable fixed point (OB-14).** P1 §4·5 makes *every* signed body begin with a domain-separation tuple that binds `store_id`. P2 defines `store_id = H(genesis record)`. The genesis record's body must therefore contain `store_id = H(genesis record)` — a value that depends on the very bytes being hashed. The first record of every store could not be canonically encoded at all.

A third, related hazard motivates the grammar being *singular*: the earlier text said both "JSON for interchange, TOML at rest, DAG-CBOR for signing" **and** "verify over received bytes, never reserialize." Those contradict — a recipient handed JSON did not receive the signed DAG-CBOR bytes, and JSON → DAG-CBOR *is* a reserialization that need not reproduce the signed digest (RFC 8785 pitfall).

## Question

What is the **one normative constructor** for a signed object such that (a) nothing that changes an object's *interpretation* can change without breaking the signature, (b) there is no split identity between the envelope and the body it wraps, (c) verification is total and allowlist-gated before any attacker-influenced bytes are touched, (d) JSON/TOML remain usable as views without ever becoming a second authority-bearing serialization, and (e) the genesis record is canonically encodable despite `store_id` depending on its own hash?

## Decision

### D1 — One constructor; the signature covers a canonical *protected tuple*, not the bare CID

There is exactly **one** signed-object grammar (no per-object choice). The signature covers a canonical **protected tuple** that pulls every interpretation-bearing field *inside* the signed image, domain-separated:

```json
{ "profile": "agent-bridle/permission-request/v1",   // protected
  "codec":   "dag-cbor",                              // protected
  "cid":     "cid:…",                                 // = H(body); protected
  "signer":  "b3:…",                                  // protected (fingerprint = H(pubkey))
  "body":    "<base64url canonical DAG-CBOR bytes>",  // carried, not reconstructed
  "sig":     "…" }
```
```
protected = canon( "agent-bridle/signed-object/v1",   // domain separation
                   profile, codec, cid, signer )
sig       = Sign(signer, protected)
```

Normative bindings (no implementer discretion):

- **`sig` covers `protected`.** `profile`, `codec`, `cid`, and `signer` are all authenticated; changing any one breaks the signature. The bare-cid gap is closed by construction — a re-tagged codec, a re-tagged profile, or a swapped signer yields a different `protected` and therefore a verification failure.
- **The domain-separation constant `"agent-bridle/signed-object/v1"` is the first element of `protected`**, so a signature minted for this grammar cannot be cross-protocol-replayed as anything else, and the envelope grammar itself is versioned.
- **`signer` is the single canonical location for the key id.** The `by` field seen in inner-record examples (P0/P4) is the *same* value surfaced logically inside a body — never a second authority. `signer` is the pinned fingerprint `H(pubkey)` (P1 §1), self-certifying under L5.
- **`cid = H(body)` binds the body to the envelope**; the body bytes are **carried** (`base64url` of the canonical DAG-CBOR), never reconstructed by the recipient. This resolves the "sign DAG-CBOR / verify received bytes" contradiction: the canonical bytes travel intact, so the verifier can verify over exactly what was signed.
- Determinism (Ed25519, P1 §5) guarantees `protected` maps to one signature encoding, so re-signing does not fork a chain built over these objects (P2).

### D2 — The body's domain tuple MUST equal the envelope (no split identity)

Pulling the fields into `protected` is necessary but not sufficient: the *body* also carries its own domain-separation tuple (P1 §4·5), and it must not disagree with the envelope wrapping it. Otherwise an object could be honestly signed at the envelope while its inner tuple claims a different profile/version/signer.

```
body domain tuple = ("agent-bridle/<profile>/<record-type>/<version>",
                     store_id, thread_id_or_principal_id, generation, <payload…>)
```

Normative equality check (an implementation **rejects any mismatch**):

- the body's domain-separation prefix MUST identify the **same** `profile` (and record-type/version) declared in the envelope;
- the body's declared `codec` MUST equal the envelope `codec`;
- the body's `signer`/`by` MUST equal the envelope `signer`.

There is **one identity across the boundary**, asserted twice and required to match — the envelope cannot claim one signer while the body attributes itself to another, and the profile cannot be re-labelled between the two layers.

### D3 — Verification order (allowlist before body; verify-over-received-bytes)

Verification is **identical in all four client languages** (Rust/Python/Dart/TS) and total (fail-closed). The order is load-bearing, not stylistic:

```
1. allowlist codec + algorithms (P1 §4·4)      — BEFORE touching body
2. recompute protected; verify sig over it under signer
3. verify cid == H(body)
4. decode body; check body domain tuple == (profile, codec, signer)   (D2)
5. schema + critical fields; reject unknown authority-bearing fields
6. construct Sealed<T>
```

Why the order matters:

- **Step 1 precedes any hashing or decoding (PO-8).** Self-describing identifiers let the *object* declare its algorithm; a verifier that dispatched on the declared code alone would let an attacker pick a broken hash or `alg:none`. The declared `codec`/algorithm codes are checked against the locally-trusted Profile v1 table **before** the body is hashed or the sig verified. Agility lives in the profile, never on the wire.
- **Step 2 verifies over the recomputed `protected`, and step 3 verifies `cid == H(body)` over the *received* canonical bytes** — never a re-serialization of a parsed object. Typed deserialization drops unknown fields; reserializing cannot reproduce the signed digest.
- **Step 4 enforces D2.** Only after the sig and CID check does the body get decoded and its inner domain tuple compared to the envelope.
- **Step 5 fails closed on unknown authority-bearing fields** (silent-downgrade / version-confusion surface). Non-authority annotations may be preserved verbatim only when the profile marks them non-critical (COSE critical-header model).
- **Step 6 is the only way an object enters a kernel.** `Sealed<T>` is the Rust heir of the content-addressable `Memo` read-time tamper check: objects are constructed *only* through this verification, immutable after. Nothing unverified crosses into P0's decision kernel.

### D4 — JSON and TOML are views/containers, never independent authority-bearing serializations

The **authority lives in `body` + `protected`.** Everything else is a rendering:

- A **JSON** rendering is for humans and non-authority interchange. It is never itself verified as the signed image — a recipient who is handed JSON must obtain the carried canonical `body` bytes to verify; a JSON reconstruction is not the signed object.
- **TOML policy files (#220)** *wrap* the signed object; the TOML is a container around `body`/`protected`, not a parallel signed form.
- Because there is one signed byte-string and it is carried (D1), "many views, one signed image" is consistent: views may be lossy or reformatted freely, and none of them is authoritative.
- **Wall-clock is never a coordination primitive.** Validity keys on generation counters (the domain tuple's `generation`); RFC 3339 timestamps are provenance *data* inside the body, not authority.

### D5 — Genesis `STORE_ID_SELF` sentinel breaks `store_id = CID(genesis)`

The fixed point (OB-14) is broken by a reserved sentinel, not by exempting genesis from domain separation:

- The **genesis body carries the reserved sentinel `store_id = 0x00` (`STORE_ID_SELF`)** in its domain tuple — a fixed, canonically-encodable value, so the genesis record can be encoded, hashed, and signed like any other object under D1.
- **The resulting `cid` of the genesis record *becomes* the store's `store_id`.**
- Every **subsequent** record binds that concrete `store_id` value in its own domain tuple (P1 §4·5), so no later record can be replayed into a different store.
- A **verifier resolves `STORE_ID_SELF` to "this record's own cid"** when checking the genesis record's domain tuple — the only record for which the sentinel is legal. `STORE_ID_SELF` appearing in any non-genesis record is rejected (fail-closed).

This makes P2's `store_id` a normative, cryptographically-bound identifier (consumed by P2 §1's `AuthorityCheckpoint`) without circularity: genesis names itself via the sentinel; the store's identity is genesis's CID; everyone after commits to that identity.

## Consequences

- **The interpretation of an object is now authenticated, not just its bytes.** Codec-confusion, profile/version-confusion, and signer-swap are all detected at step 2 — they are no longer "valid signature, wrong meaning."
- **No split identity.** D2's equality check means an object cannot be honestly signed at the envelope while lying in its body about profile, codec, or signer.
- **One constructor for the whole suite.** P0/P2/P3/P4/P5 records are all this one shape; a single Lean canonicalization-injectivity contract (PO-1c) plus the allowlist-gating proof (PO-8) covers signing for every profile above P1. The kernel consumes `H` and `Sign` as **abstract injective / one-way contracts**, which is what lets Aeneas run without modelling crypto.
- **Views are free.** JSON/TOML can be reformatted, pretty-printed, or lossily projected without touching authority, because authority is the carried `body` + `protected`, never the view.
- **Genesis is canonically encodable**, so P2's per-record `store_id` binding (the anti-replay-across-stores property under P1 §4·5) has no exception carved out for the first record.
- **Cost:** the body bytes are carried (base64url) in addition to the CID, so a signed object is larger than a bare `{cid, sig}` reference. This is deliberate — "verify over received canonical bytes, never reserialize" requires the bytes to be present. Reference-only forms (e.g. `parents` links in P2) still carry just a CID, because they point at an object that is itself carried elsewhere.

## Alternatives considered

- **Bare-cid signature (`sig = Sign(signer, H(body))`).** Rejected (OB-13): leaves `profile`/`codec`/`signer` outside the signed image — the codec-retag / profile-confusion / signer-swap attacks above.
- **Detached signature over the JSON view.** Rejected (D4): JSON is not injective/canonical for signing; verifying a reconstructed JSON is exactly the reserialization the RFC 8785 pitfall warns against, and it makes a human-facing view authority-bearing.
- **Per-object choice of "sign the CID" vs "sign the tuple."** Rejected: two constructors is two attack surfaces and two proofs; the freeze mandates **one** normative constructor.
- **Omit the domain-separation constant from `protected`.** Rejected: without `"agent-bridle/signed-object/v1"` inside the signed image, a signature is cross-protocol-replayable and the envelope grammar is itself unversioned.
- **Exempt the genesis body from the domain tuple** (so it need not bind `store_id`). Rejected (OB-14): a per-record exception is a permanent special case in every verifier and a version-confusion foothold; the `STORE_ID_SELF` sentinel keeps genesis a *normal* signed object with a resolvable placeholder instead.
- **Randomized signatures (ECDSA random-nonce).** Rejected (P1 §5): a fresh signature on every re-sign changes the content hash and forks any P2 chain built over the object; Profile v1 pins deterministic Ed25519.

## Proof obligations

| PO | Statement | Tier |
|---|---|---|
| PO-1c | canonicalization is injective; verify-over-received-bytes is sound (one value ⇒ one byte-string; a parsed-then-reserialized object cannot reproduce the signed digest) | 3 (Lean contract) |
| PO-8 | algorithm/codec dispatch is allowlist-gated — no code outside the Profile v1 table is honoured (step 1 before any hashing) | 3 |
| WF-2 | the Memo discipline holds structurally on every wire object (content-CID unconditional; `signer`/`sig` at trust boundaries; `parents` for durability; Sealed at load) | vector |

These are P1's obligations; the crypto primitives underneath (`H` collision-resistance, `Sign` unforgeability, deterministic-nonce) are **Tier 1** — assumed, cited to the literature, rotatable via the Profile-v1 allowlist. Positive + negative **conformance vectors** (shared JSON, kyln round-trip pattern) bind the four client languages to one observable verification behaviour — the teeth that keep implementations honest where proofs stop. They ship with the kernel (`suite.toml` `conformance_vectors`), the single implementation-phase item of the v0.3.1 exit gate.

## Tracking

- Grammar (D1–D4): `docs/spec/signed-object-profile.md` §2 / §4·4 / §4·5; closes **OB-13**.
- Genesis sentinel (D5): `docs/spec/signed-object-profile.md` §2 and `docs/spec/chain-store-profile.md` §1; closes **OB-14**; consumed by P2's `AuthorityCheckpoint.store_id`.
- Build/prove order: this is P1, the first profile proven — **P1 → P2 → P0 → P4 → P3** (README).

## Relations

- Suite index: [`README.md`](../spec/README.md) — Review 7 / v0.3.1 PROTOCOL FREEZE table (OB-13, OB-14).
- Owning profile: P1 [`signed-object-profile.md`](../spec/signed-object-profile.md).
- Consumers of `store_id`/`STORE_ID_SELF`: P2 [`chain-store-profile.md`](../spec/chain-store-profile.md) §1 (`AuthorityCheckpoint`, per-record store binding).
- Domain-tuple context binding (`store_id`, `thread_id`/`principal_id`, `generation`): P1 §4·5, discharging OB-6.
- `content-addressable` crate — `ContentId`, canonical DAG-CBOR, `MerkleNode<T>`, the `Sealed<T>` this grammar constructs; `Memo` read-time tamper check (WF-2).
- agent-mesh#66 — multihash wire format for `Fingerprint` (`signer`); #226/#227 — signed loosening entries as an existing P1 object.