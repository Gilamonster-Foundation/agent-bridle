import Ceremony.P1.SignedObject

open Ceremony.P1

example : Profile.v1.allowsHash .blake3_256 := by decide

example : Not (Profile.v1.allowsHash .sha1) := by decide

example : Profile.v1.allowsSignature .ed25519 := by decide

example : Not (Profile.v1.allowsSignature .ecdsa) := by decide

example (allowed : AllowedSignature Profile.v1) :
    allowed.algorithm.isDeterministic :=
  v1_signature_is_deterministic allowed

example : Profile.v1.allowsCodec .dagCbor := by decide

example : Not (Profile.v1.allowsCodec .json) := by decide

def bytesEncoding : CanonicalEncoding ByteArray where
  encode := id
  injective := by
    intro left right h
    exact h

example (value : ByteArray) : (sealValue bytesEncoding value).value = value := rfl

example (left right : Sealed bytesEncoding)
    (h : left.canonical = right.canonical) : left = right :=
  sealed_eq_of_same_canonical h

def v1Envelope : RawEnvelope :=
  { version := 1
    hash := .blake3_256
    signature := .ed25519
    codec := .dagCbor
    receivedCanonical := ByteArray.mk #[1, 2, 3]
    unknownCritical := [] }

def unsupportedVersionEnvelope : RawEnvelope :=
  { v1Envelope with version := 2 }

def sha1Envelope : RawEnvelope :=
  { v1Envelope with hash := .sha1 }

def ecdsaEnvelope : RawEnvelope :=
  { v1Envelope with signature := .ecdsa }

def jsonEnvelope : RawEnvelope :=
  { v1Envelope with codec := .json }

def unknownCriticalEnvelope : RawEnvelope :=
  { v1Envelope with unknownCritical := ["future-authority"] }

example : (verifyEnvelope Profile.v1 v1Envelope).isSome := by decide

example : verifyEnvelope Profile.v1 unsupportedVersionEnvelope = none := by decide

example : verifyEnvelope Profile.v1 sha1Envelope = none := by decide

example : verifyEnvelope Profile.v1 ecdsaEnvelope = none := by decide

example : verifyEnvelope Profile.v1 jsonEnvelope = none := by decide

example : verifyEnvelope Profile.v1 unknownCriticalEnvelope = none := by decide

example (verified : VerifiedEnvelope Profile.v1 v1Envelope) :
    verified.receivedCanonical = v1Envelope.receivedCanonical :=
  verified_preserves_received verified
