# Phase-1d codec prototypes — cross-language byte-identity harness

**Status: EXPLORATORY / NON-NORMATIVE.** These prototypes exist to *empirically*
validate that four independent implementations (Rust, Python, Dart, TypeScript)
produce **byte-identical** canonical bytes for the signed-object wire format,
*before* anything is frozen in Phase 1d. Nothing here is a spec commitment; the
Rust prototype is the reference and the others must match its golden vectors.

## The value-space constraint (the decidable-from-principles part)

Every source of cross-implementation encoding divergence is *removed by
construction* — the wire value space is deliberately tiny, and every allowed
type has exactly one canonical byte encoding. This is what makes byte-identity
achievable and, as a bonus, makes the JSON view a lossless bijection.

Allowed value types (nothing else may appear on the wire):

| Type | Canonical CBOR encoding |
|---|---|
| **unsigned int** (`u64`) | major type 0, **smallest** length form (RFC 8949 §4.2.1) |
| **text string** (UTF-8) | major type 3, definite length, NFC not required (bytes carried as-is) |
| **byte string** | major type 2, definite length |
| **array** | major type 4, definite length; elements in given order |
| **map** (string keys) | major type 5, definite length; **keys sorted bytewise by their encoded-key bytes**; no duplicate keys |
| **CID link** | tag 42 (major type 6) wrapping a byte string: `0x00` multibase-identity prefix ++ CIDv1 bytes |

**Forbidden** (each is a known cross-lib divergence): floats/NaN/±Inf, negative
integers unless a field needs them (none in v1), indefinite-length items,
non-string map keys, `null`/`undefined`, bignums, simple values other than the
above. An encoder rejects anything outside this set (fail-closed).

## The signed-object construction (v1 pins)

```
body      = canonicalCBOR(domainTuple)                      # the signed payload
cid       = CIDv1(codec=dag-cbor 0x71, multihash=blake3-256 0x1e ++ BLAKE3-256(body))
protected = canonicalCBOR([ "agent-bridle/signed-object/v1", profile, codec, cidBytes, signer ])
sig       = Ed25519.sign(sk, protected)                     # RFC 8032, deterministic
```

- `domainTuple` (§4·5) = `[ "agent-bridle/<profile>/<record-type>/<version>",
  store_id, thread_id_or_principal, generation, <payload…> ]` — a typed CBOR
  array, never string concatenation (anti-boundary-confusion).
- `store_id` genesis sentinel `STORE_ID_SELF` = the byte string `0x00`.
- `signer` = **open decision** (see below); prototype carries the multicodec
  ed25519-pub tagged public key so the object verifies standalone.
- `codec`/`profile` are short text strings.

## Open decisions these prototypes are meant to inform

1. **Reuse dag-cbor libraries vs. this hand-rolled constrained encoder** — the
   prototypes ARE the constrained encoder; the research checks whether existing
   libraries agree with them byte-for-byte on this subset.
2. **`signer` = full pubkey (self-contained) vs. fingerprint** — prototype uses
   the tagged pubkey; revisit once P3 enrollment is designed.

## Golden vectors

Each language emits `vectors/<lang>.json`: for a **fixed** input value and a
**fixed** Ed25519 seed (all-zero 32 bytes), the hex of `body`, `cid`,
`protected`, `sig`, and `signer`. Byte-identity ⟺ the four files are identical
(modulo the `lang` field). `diff` them; any divergence is a codec bug or an
unpinned rule.
