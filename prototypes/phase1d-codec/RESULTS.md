# Phase-1d codec prototypes — empirical results (2026-07-18)

Four independent, hand-rolled implementations of the constrained canonical
DAG-CBOR encoder + the signed-object construction, from a fixed input and a
fixed all-zero Ed25519 seed. Run `./check.sh` to reproduce.

## Findings

| Language | Canonical CBOR (`body`) | Ed25519 (`signer`/`sig`) | BLAKE3 (`cid`) | Full vector |
|---|---|---|---|---|
| Rust (reference) | ✅ | ✅ | ✅ | ✅ |
| Python (`cryptography`, `blake3`) | ✅ | ✅ | ✅ | ✅ byte-identical to Rust |
| TypeScript/JS (`@noble`) | ✅ | ✅ | ✅ | ✅ byte-identical to Rust |
| Dart (`ed25519_edwards`, `blake3_dart`) | ✅ | ✅ | ✅ | ✅ byte-identical to Rust (full vector) |

## What this tells us

1. **The constrained-encoder strategy WORKS.** All four languages produce
   byte-identical canonical CBOR *without depending on any DAG-CBOR library* —
   the ~120-line hand-rolled encoder over the restricted value space is
   trivially portable and eliminates the cross-library canonicalization
   divergence that was the #1 risk. Strategy (b) validated for 4/4.

2. **Ed25519 determinism holds cross-language.** Four different libraries
   (dalek / cryptography / @noble / ed25519_edwards) produce the identical
   public key from the seed, and the identical deterministic signature where
   computed — RFC 8032 determinism is real and portable.

3. **BLAKE3 works in ALL FOUR languages — the Dart "gap" was a naming red
   herring.** The bare `blake3` package name doesn't exist on pub.dev, but
   `blake3_dart` (pure Dart, no FFI/native build) produces the **byte-identical**
   CID to Rust/Python/TS on the full vector. So the v1 hash pin stays BLAKE3-256;
   no FFI and no hash reconsideration is needed. (Residual: `blake3_dart` is a
   community pure-Dart impl — a production may prefer an FFI binding to the
   official reference for assurance; a library-maturity call, not a blocker.)

## Outcome

**All four languages produce byte-identical vectors on the entire construction**
(canonical CBOR + BLAKE3 CID + Ed25519 sig). The codec strategy (hand-rolled
constrained encoder + golden-vector oracle) and the BLAKE3-256/Ed25519 pins are
empirically validated cross-language. See ADR 0024. The only residual is a
Dart-BLAKE3 library-assurance preference (pure-Dart `blake3_dart` vs. FFI to the
reference) — independent of the codec.
