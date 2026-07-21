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

-- ── F-233-01/04: real crypto inhabits the slimmed CryptoBoundary ────────────
-- A concrete byte-level signer whose Tier-1 properties (soundness, binding,
-- determinism) are all *satisfiable* — the honest counterpart to the old
-- identity-hash-only mock that the impossible `digest_binding` used to force.

def demoMsg : List UInt8 := [1, 2, 3]
def demoSig : ByteArray := ByteArray.mk #[9, 9]

def demoByteSigner : ByteSigner Profile.v1 where
  SignedBytes := fun allowed msg sig =>
    allowed.algorithm = .ed25519 ∧ msg = demoMsg ∧ sig = demoSig
  matchesBytes := fun allowed msg sig =>
    decide (allowed.algorithm = .ed25519 ∧ msg = demoMsg ∧ sig = demoSig)
  bytes_sound := by intro _ _ _ h; exact of_decide_eq_true h
  bytes_binding := by
    intro _ _ _ _ _ hl hr
    exact ⟨hl.1.trans hr.1.symm, hl.2.1.trans hr.2.1.symm⟩
  bytes_deterministic := by intro _ _ _ _ hl hr; exact hl.2.2.trans hr.2.2.symm

/-- The payoff, made concrete: a genuine `CryptoBoundary` built from the byte-level
    signer via `ofByteSigner`. That this type-checks is the inhabitance the
    impossible global-injectivity `digest_binding` denied to real crypto. -/
def demoBoundary : Ceremony.P1.CryptoBoundary Profile.v1 :=
  Ceremony.P1.CryptoBoundary.ofByteSigner demoByteSigner (fun _allowed body => body)

-- The structural guarantees hold for it as the DERIVED theorems (no postulate):
example {la ra : AllowedSignature Profile.v1} {lp rp : SignaturePreimage} {sig : ByteArray}
    (hl : demoByteSigner.SignedBytes la (encodeSignaturePreimage lp) sig)
    (hr : demoByteSigner.SignedBytes ra (encodeSignaturePreimage rp) sig) :
    la.algorithm = ra.algorithm ∧ lp = rp :=
  structural_binding_from_bytes demoByteSigner hl hr
