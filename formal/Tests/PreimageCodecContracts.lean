import Ceremony.P1.PreimageCodec

/-!
# Contracts for the F-233-02 preimage codec

Executable documentation + regression anchors for `Ceremony.P1.PreimageCodec`:
the atomic round-trips compute as claimed, and the whole-preimage encoder actually
distinguishes a one-field change end-to-end (a concrete witness of injectivity).
-/

open Ceremony.P1 Ceremony.P1.PreimageCodec

-- Atomic self-delimiting round-trips recover the value and the suffix verbatim.
example : readNat (uNat 3 ++ ([9] : List UInt8)) = some (3, [9]) := readNat_roundTrip 3 [9]

example : readBlob (blob ([7, 8] : List UInt8) ++ [99]) = some ([7, 8], [99]) :=
  readBlob_roundTrip [7, 8] [99]

-- The two headline results, named as contracts.
example : Function.Injective encodeSignaturePreimage :=
  encodeSignaturePreimage_injective

-- A concrete protected tuple and a variant differing in exactly one field.
def sampleDomain : SignatureDomain :=
  { recordType := "permission-request/v1"
    storeId := ByteArray.mk #[0]
    threadOrPrincipal := ByteArray.mk #[1, 2, 3] }

def samplePreimage : SignaturePreimage :=
  { canonicalUnsigned := ByteArray.mk #[9, 9]
    profileVersion := 1
    hashAlgorithm := .blake3_256
    signatureAlgorithm := .ed25519
    codec := .dagCbor
    domain := sampleDomain
    body := ByteArray.mk #[7]
    claimedCid := ByteArray.mk #[8]
    signer := ByteArray.mk #[5, 5]
    unknownCritical := [] }

/-- End-to-end witness: bumping only `profileVersion` changes the signed bytes.
    If the encoder ever dropped or aliased a field, this would fail. -/
example :
    encodeSignaturePreimage samplePreimage
      ≠ encodeSignaturePreimage { samplePreimage with profileVersion := 2 } := by
  intro h
  have heq := encodeSignaturePreimage_injective h
  simp [samplePreimage, sampleDomain] at heq
