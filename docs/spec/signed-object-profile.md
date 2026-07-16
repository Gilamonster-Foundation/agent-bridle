# P1 — Signed-Object Profile

**Layer:** foundation (no dependencies). **Depends on:** —.
**Depended on by:** P0, P2, P3, P4, P5 (everything).
**Status:** DRAFT. **Teeth:** proptest round-trip vectors + a Lean
canonicalization-injectivity contract (Tier 3); the crypto primitives are
Tier-1 assumptions.
**Owns:** how any object gets a name, a canonical form, and a signature —
and how a verifier decides which algorithms it will honour.

This profile is the alphabet the other five write in. It contains no
authority semantics; it makes objects *nameable, canonical, and
verifiable*.

## 1. Identifiers are self-describing

Fingerprints are **multihash**; keys and signatures are **multicodec**-
tagged; links are **CIDv1**. Comparison is over the opaque bytes *including
the algorithm code* — two hash algorithms never collide silently. The key
is the identity; the fingerprint `H(pubkey)` is its self-certifying *name*.
*BLAKE3 is an implementation detail, not a law.*

## 2. One schema, one signed byte-string, many views (OB-4)

An earlier draft said "JSON for interchange, TOML at rest, DAG-CBOR for
signing" *and* "verify over received bytes, never reserialize" — which is
contradictory, because a recipient handed JSON has not received the signed
DAG-CBOR bytes, and converting JSON → DAG-CBOR *is* a reserialization. The
resolution: **the canonical DAG-CBOR bytes are carried, not reconstructed.**

**The signed-object grammar is ONE normative constructor (OB-13/#2).** A
naive envelope that signs only `cid = H(body)` leaves the interpretation-
bearing fields (`profile`, `codec`, `signer`) *outside* the signature — an
attacker could re-tag the codec or profile without breaking the sig. So the
signature covers a canonical **protected tuple**, not the bare CID:

```json
{ "profile": "agent-bridle/permission-request/v1",   // protected
  "codec": "dag-cbor",                                // protected
  "cid": "cid:…",                                     // = H(body); protected
  "signer": "b3:…",                                   // protected
  "body": "<base64url canonical DAG-CBOR bytes>",
  "sig": "…" }
```
```
protected = canon( "agent-bridle/signed-object/v1",   // domain separation
                   profile, codec, cid, signer )
sig       = Sign(signer, protected)
```

Normative bindings (no implementer choice left):
- **`sig` covers `protected`** — profile, codec, cid, signer are all
  authenticated; changing any breaks the signature.
- **the body's own domain tuple** (§4·5) MUST equal `(profile, codec)` of the
  envelope, and its `signer`/`by` MUST equal the envelope `signer` — an
  implementation rejects any mismatch (no split identity across the boundary).
- `signer` is the one canonical location for the key id; `by` in inner-record
  examples (P0/P4) is the *same* value surfaced logically, never a second
  authority.
- verification (identical in all four languages):
  ```
  1. allowlist codec + algorithms (§4·4)         — before touching body
  2. recompute protected; verify sig over it under signer
  3. verify cid == H(body)
  4. decode body; check body domain tuple == (profile, codec, signer)
  5. schema + critical fields; reject unknown authority-bearing fields
  6. construct Sealed<T>
  ```

**Genesis is non-circular (OB-14/#3).** P2 defines `store_id = H(genesis
record)`, but every body must bind `store_id` (§4·5) — a fixed point at
genesis. Resolution (normative): **the genesis body carries the reserved
sentinel `store_id = 0x00` (`STORE_ID_SELF`); its resulting `cid` becomes the
store's `store_id`**, and every *subsequent* record binds that value. A
verifier resolves `STORE_ID_SELF` to "this record's own cid." The first
ordinary record can therefore be canonically encoded.

**JSON and TOML are views/containers, never independent authority-bearing
serializations.** A JSON rendering is for humans/non-authority interchange;
the *authority* lives in `body` + `protected`. TOML policy files (#220) wrap
the signed object. Wall-clock is never a coordination primitive — validity
keys on generation counters; RFC 3339 timestamps are provenance *data*.

## 3. The Memo discipline (WF-2)

Every wire object is a `Memo`-descendant (content-addressable-python
`data.py`: every value carries its content-id and *reads verify it*).
Capabilities attach by **mechanical criteria**, not by quota:

- **content-CID — unconditional.** Anything serializable and meaningful
  beyond this process has canonical bytes, hence a name.
- **`by` + `sig` — at trust boundaries.** REQUIRED when the object crosses
  to a different fingerprint (remote surface, delegated agent, another
  host); MAY be omitted in-process — same trust domain, nothing to assert.
- **`parents` — for durability.** Anything appended to a chain-store (P2)
  links.
- **Sealed at load.** Objects are constructed *only* through verification
  (CID recomputed; sig checked when present) — verified once at the
  boundary, immutable after. Nothing enters a kernel unverified. `Sealed<T>`
  is the Rust heir of Memo's read-time tamper check.

Const-correctness for integrity: one unsigned hop breaks the chain of
custody like one non-const cast breaks the guarantee. Applies to **all of
the data layer, none of the resource layer.**

## 4. Verification rules (the sharp edges)

1. **Verify over received canonical bytes, never a re-serialization.**
   Typed deserialization drops unknown fields; reserializing a parsed
   object cannot reproduce the signed digest. Verify the bytes as received,
   *then* parse (RFC 8785 pitfall; JWS/COSE practice).
2. **Unknown authority-bearing fields fail closed.** A field the profile
   version does not define is *rejected*, not ignored — tolerating it is a
   silent downgrade / version-confusion surface. Non-authority annotations
   MAY be preserved verbatim only when the profile marks them non-critical
   (COSE critical-header model).
3. **Version dispatch, not lenient parsing.** All objects carry
   `"v": <profile-version>`; verification dispatches on it.
4. **Algorithm allowlist before dispatch (PO-8).** Self-describing
   identifiers let the *object* declare its algorithm — so a verifier that
   dispatches on the declared code alone lets an attacker pick a broken
   hash (`alg:none` / algorithm-confusion). A verifier MUST check the
   declared code against the locally-trusted profile table (§6) **before
   hashing or verifying**, and reject anything outside it. Agility lives in
   the profile, never on the wire.
5. **Universal domain separation + context binding (OB-6).** *Every* signed
   `body` MUST begin with a domain-separation tuple, not just the WebAuthn
   challenge:
   ```
   ("agent-bridle/<profile>/<record-type>/<version>",
    store_id, thread_id_or_principal_id, generation, <payload…>)
   ```
   A signature is valid only for its exact `(record-type, store, thread/
   principal, version)` context. Without this, a validly-signed payload can
   be replayed **across stores, principals, causal threads, structurally-
   compatible record types, and profile versions.** `store_id` is a
   normative, cryptographically-bound identifier (P2 §) — "same store" is a
   value the signature covers, not prose. Verifiers reject a signature whose
   domain tuple does not match the context in which it is being used.

## 5. Deterministic signatures (why Ed25519 is pinned)

For Profile v1, signing MUST be **deterministic**: `Sign(sk, message)`
yields one canonical signature encoding for a fixed key and message.
Ed25519 provides this (RFC 8032 derives the nonce from key and message). A
randomized scheme (ECDSA with a random nonce) would produce a different
signature — hence a different content hash — on every re-sign, forking any
chain built over it (P2). Determinism governs **reproducibility**;
collision resistance of `H` governs **tamper-evidence**; they are
independent properties. (Information-theoretically: `H(sig|content,key)=0`.
The prose rule is normative; the identity is just why.)

## 6. Profile v1 (pins, not laws)

Each pin states the *property* a replacement must carry:

| Pin | v1 value | Required property |
|---|---|---|
| Content hash `H` | BLAKE3-256 (multihash `0x1e`) | collision resistance; preimage hardness (L5 self-certification) |
| Signature | Ed25519 (RFC 8032) | **deterministic**; existential unforgeability |
| Canonical encoding | DAG-CBOR (codec `0x71`) | injective canonical serialization (one value ⇒ one byte string) |
| Links | CIDv1 | multihash-native, codec-tagged |

Rotating `H` is a **re-naming ceremony** (P0·L5): keys sign linkage records
binding their new names; identity never moves. Rotating the signature
scheme is a **re-keying** (full L5 re-ceremony) because the key *is* the
identity. Profile rotation is a negotiated, principal-signed change to the
allowlist (a loosening entry, P0·L2), never a per-object choice.

## 7. Proof obligations

| PO | Statement | Tier |
|---|---|---|
| PO-1c | canonicalization is injective; verify-over-received-bytes is sound | 3 (Lean contract) |
| PO-8 | algorithm dispatch is allowlist-gated — no code outside the profile is honoured | 3 |
| WF-2 | the Memo discipline holds structurally on every wire object | vector |

The kernel (P0) consumes `H` and `Sign` as **abstract injective / one-way
contracts** — this profile's job is to satisfy them, the kernel's job to
assume them. That boundary is what lets Aeneas run without modelling crypto.

## Relations
- `content-addressable` crate — `ContentId`, canonical DAG-CBOR,
  `MerkleNode<T>`, the `Sealed<T>` to build
- agent-mesh#66 — multihash wire format for `Fingerprint`
- #226/#227 — signed loosening entries (shipped)
