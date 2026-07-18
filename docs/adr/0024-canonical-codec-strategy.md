# ADR 0024 — Canonical codec strategy: hand-rolled constrained encoder + golden-vector oracle

- Status: Proposed (2026-07-18)
- Date: 2026-07-18
- Context: Phase 1d must freeze the **byte-exact** canonical wire encoding of the
  signed-object format (P1, `signed-object-profile.md`) so that four independent
  implementations — Rust, Python, Dart, TypeScript — produce **identical bytes**
  for the same value. The *algorithms* are already pinned as property-stating,
  self-describing, replaceable pins (profile v1 §6: BLAKE3-256 / Ed25519 /
  DAG-CBOR / CIDv1). This ADR decides the **codec strategy and value space** —
  the byte-level rules the conformance vectors will freeze. It is grounded in two
  independent, converging lines of evidence: a cited deep-research review of the
  cross-language canonicalization landscape, and a four-language empirical
  prototype harness (`prototypes/phase1d-codec/`).
- Governed by / harmonizes with: **ADR 0022** (the signed-object grammar /
  protected tuple this codec serializes), the P1 profile §2/§4/§6 (the pins,
  the verify order, the value carriage), and the multihash law (§1: identifiers
  self-describe; the hash is an implementation detail, not a law).

## Decision

### D1 — Hand-roll a small constrained canonical encoder per language; do NOT depend on DAG-CBOR libraries

Every implementation encodes the restricted value space (D2) with a
purpose-built encoder (~120 lines), not an off-the-shelf DAG-CBOR/CBOR library.

Rationale (research + empirical):
- **Library support is sharply asymmetric and partly adversarial.** Rust
  (`serde_ipld_dagcbor`) and Python (`hashberg-io/dag-cbor`) have deterministic
  DAG-CBOR codecs; **Dart's leading CBOR library actively fights determinism**
  (default float16-shrinking, no length-first key sort, no tag-42 CID support),
  and **no canonical DAG-CBOR codec exists for TypeScript**. Depending on
  libraries would mean four heterogeneous implementations each making
  *underspecified* choices — the exact recipe for silent byte-divergence.
- **The prototypes prove the hand-rolled path works.** The four independent
  encoders produce **byte-identical** `body`/`cid`/`protected`/`sig` for a fixed
  input (Rust ≡ Python ≡ TS on the full vector; Dart identical on the
  library-independent parts — see D5). A tiny, self-contained encoder is
  trivially portable and auditable, and removes the entire "do four libraries
  agree on edge cases" risk class.

### D2 — The constrained value space (the injectivity subset)

Only these types may appear on the wire; each has exactly one canonical
encoding. An encoder **rejects** anything else (fail-closed):

| Type | Canonical encoding |
|---|---|
| unsigned int (`u64`) | major 0, **smallest** length form |
| text string (UTF-8) | major 3, definite length; bytes carried as-is |
| byte string | major 2, definite length |
| array | major 4, definite length; given order |
| map (string keys) | major 5, definite length; keys **sorted by their encoded-key bytes**; no duplicate keys |
| CID link | tag 42 wrapping `0x00` ++ CIDv1 bytes |

**Forbidden** (each is a documented cross-implementation divergence): floats /
NaN / ±Inf, indefinite-length items, non-string map keys, negative integers
(none needed in v1), nulls, bignums, other simple values.

Rationale: the specs (RFC 8949 §4.2, IPLD DAG-CBOR) do **not** by themselves
guarantee byte-identity — they assume every language first formed an *equivalent*
generic item (1 vs 1.0, double vs bignum, NFC vs raw UTF-8), which does not hold
across four languages. Removing each degree of freedom deletes a divergence
class. Bonus: this subset makes the JSON view a **lossless bijection**, so the
plain-text auditability the profile wants comes for free.

### D3 — Map-key ordering is length-first, achieved by sorting on the ENCODED key

DAG-CBOR mandates **length-first** map-key ordering (RFC 7049 §3.9 / RFC 8949
§4.2.3), *not* the RFC 8949 §4.2.1 bytewise-content default — the single biggest
interop hazard (Langley, "Several Canons of CBOR"). The correct, non-obvious
implementation: **sort by the full CBOR-encoded key** (the major-3 length head
++ UTF-8 bytes). Because the length lives in the head byte(s), this *coincides*
with length-first for text-string keys, while sorting by raw UTF-8 *content*
does not (`"z"` vs `"aa"`). The prototypes empirically confirm this: a 1-byte
key sorts **before** a 6-byte key across all four encoders.

### D4 — The golden test-vector corpus IS the contract

Byte-identity is delivered by **conformance testing against one golden corpus**,
not by trusting the specs or heterogeneous libraries. Every language cross-
validates against the same vectors (positive: input → exact `body`/`cid`/
`protected`/`sig`; negative: each tampered field → the specific rejection). The
four-language harness in `prototypes/phase1d-codec/` (`check.sh`) is the seed.

### D5 — Ed25519 and BLAKE3-256 both work across all four languages (empirically resolved)

- **Ed25519 (RFC 8032) is portable and deterministic** — four different
  libraries (dalek / cryptography / @noble / ed25519_edwards) produce the
  identical key and signature from the fixed seed.
- **BLAKE3-256 is viable in all four languages, including Dart.** The initial
  concern (no `blake3` on pub.dev; `hashlib` is blake2-only) was a naming red
  herring: **`blake3_dart` is a pure-Dart BLAKE3** (no FFI/native build) that
  produces the **byte-identical** CID to Rust (`blake3`), Python (`blake3`), and
  TypeScript (`@noble/hashes`) — confirmed on the full vector. So the v1
  content-hash pin **stays BLAKE3-256**; no hash reconsideration and no FFI is
  required to build the codec cross-language.
- **Residual (a maturity call, not a blocker):** `blake3_dart` is a
  community pure-Dart implementation. For a security-critical production hash,
  the choice is between (a) depending on a byte-verified pure-Dart package,
  vs. (b) an FFI binding to the official BLAKE3 reference for higher assurance —
  a library-assurance decision, independent of the codec (the multihash law
  keeps even the algorithm replaceable if needed). This does not affect D1–D4.

## Consequences

**Positive**
- The codec is a small, self-contained, dependency-free module per language —
  auditable, and immune to DAG-CBOR-library drift.
- Byte-identity is empirically demonstrated, not assumed, before the freeze.
- The constrained value space doubles as a lossless plain-text (JSON) view.
- The hash decision stays deferrable and cheap thanks to the self-describing
  substrate.

**Negative / residual**
- Four encoders to keep in lockstep — mitigated by the shared golden corpus
  (D4): drift fails a vector, loudly.
- The value-space constraints must be *enforced* by every encoder (reject floats
  etc.), not merely documented — a conformance-vector obligation.
- The Dart BLAKE3 path (FFI) adds a native build dependency to newt-mobile if
  BLAKE3 is kept (D5).

## Alternatives considered

- **Depend on DAG-CBOR libraries in each language.** REJECTED (D1): Dart's is
  adversarial to determinism, TypeScript has none, and heterogeneous libraries
  make underspecified choices — the dominant byte-divergence risk.
- **Rely on the RFC 8949 §4.2 / IPLD spec for byte-identity without a golden
  corpus.** REJECTED (D4): the specs are advisory / assume equivalent input
  items and do not prove independent implementations converge; conformance
  testing is what delivers the guarantee.
- **Bytewise (§4.2.1) map-key ordering.** REJECTED (D3): DAG-CBOR mandates
  length-first; encoded-key sort achieves it.

## References

- P1 signed-object profile §2 (one signed byte-string), §4 (verify rules), §6
  (the property-stating pins). ADR 0022 (the protected-tuple grammar).
- `prototypes/phase1d-codec/` — the four-language harness + `RESULTS.md` (the
  empirical byte-identity evidence) + `check.sh` (reproduce).
- Deep-research (2026-07-18): RFC 8949 §4.2 / §4.2.3, RFC 7049 §3.9, IPLD
  DAG-CBOR spec, Langley "Several Canons of CBOR", `serde_ipld_dagcbor`,
  `hashberg-io/dag-cbor`, `pub.dev/packages/cbor`, RFC 8032, the BLAKE3
  reference test vectors.
