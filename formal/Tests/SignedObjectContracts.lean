import Ceremony.P1.SignedObject

open Ceremony.P1

example : Profile.v1.allowsHash .blake3_256 := by decide

example : Not (Profile.v1.allowsHash .sha1) := by decide

example : Profile.v1.allowsSignature .ed25519 := by decide

example : Not (Profile.v1.allowsSignature .ecdsa) := by decide

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
