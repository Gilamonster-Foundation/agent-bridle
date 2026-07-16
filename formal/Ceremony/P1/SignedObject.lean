namespace Ceremony.P1

inductive HashAlgorithm
  | blake3_256
  | sha1
  deriving DecidableEq, Repr

inductive SignatureAlgorithm
  | ed25519
  | ecdsa
  deriving DecidableEq, Repr

inductive Codec
  | dagCbor
  | json
  deriving DecidableEq, Repr

structure Profile where
  version : Nat
  hashes : List HashAlgorithm
  signatures : List SignatureAlgorithm
  codecs : List Codec

namespace Profile

def v1 : Profile :=
  { version := 1
    hashes := [.blake3_256]
    signatures := [.ed25519]
    codecs := [.dagCbor] }

def allowsHash (profile : Profile) (algorithm : HashAlgorithm) : Prop :=
  algorithm ∈ profile.hashes

instance (profile : Profile) (algorithm : HashAlgorithm) :
    Decidable (allowsHash profile algorithm) := by
  unfold allowsHash
  infer_instance

def allowsSignature (profile : Profile) (algorithm : SignatureAlgorithm) : Prop :=
  algorithm ∈ profile.signatures

instance (profile : Profile) (algorithm : SignatureAlgorithm) :
    Decidable (allowsSignature profile algorithm) := by
  unfold allowsSignature
  infer_instance

def allowsCodec (profile : Profile) (codec : Codec) : Prop :=
  codec ∈ profile.codecs

instance (profile : Profile) (codec : Codec) :
    Decidable (allowsCodec profile codec) := by
  unfold allowsCodec
  infer_instance

end Profile

structure AllowedHash (profile : Profile) where
  algorithm : HashAlgorithm
  allowed : profile.allowsHash algorithm

structure AllowedSignature (profile : Profile) where
  algorithm : SignatureAlgorithm
  allowed : profile.allowsSignature algorithm

structure AllowedCodec (profile : Profile) where
  codec : Codec
  allowed : profile.allowsCodec codec

structure CanonicalEncoding (Value : Type) where
  encode : Value -> ByteArray
  injective : Function.Injective encode

structure Sealed {Value : Type} (encoding : CanonicalEncoding Value) where
  value : Value
  canonical : ByteArray
  canonical_eq : canonical = encoding.encode value

def sealValue (encoding : CanonicalEncoding Value) (value : Value) : Sealed encoding :=
  { value
    canonical := encoding.encode value
    canonical_eq := rfl }

theorem sealed_eq_of_same_canonical
    {encoding : CanonicalEncoding Value}
    {left right : Sealed encoding}
    (h : left.canonical = right.canonical) : left = right := by
  cases left with
  | mk leftValue leftCanonical leftCanonicalEq =>
      cases right with
      | mk rightValue rightCanonical rightCanonicalEq =>
          have valueEq : leftValue = rightValue := encoding.injective <|
            leftCanonicalEq.symm.trans (h.trans rightCanonicalEq)
          subst rightValue
          cases leftCanonicalEq
          cases rightCanonicalEq
          rfl

theorem blake3_allowed : Profile.v1.allowsHash .blake3_256 := by decide

theorem sha1_not_allowed : Not (Profile.v1.allowsHash .sha1) := by decide

theorem ed25519_allowed : Profile.v1.allowsSignature .ed25519 := by decide

theorem ecdsa_not_allowed : Not (Profile.v1.allowsSignature .ecdsa) := by decide

theorem dag_cbor_allowed : Profile.v1.allowsCodec .dagCbor := by decide

theorem json_not_allowed : Not (Profile.v1.allowsCodec .json) := by decide

end Ceremony.P1
