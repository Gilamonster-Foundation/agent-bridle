namespace Ceremony.P1

inductive HashAlgorithm
  | blake3_256
  | sha1
  deriving DecidableEq, Repr

inductive SignatureAlgorithm
  | ed25519
  | ecdsa
  deriving DecidableEq, Repr

def SignatureAlgorithm.isDeterministic : SignatureAlgorithm -> Prop
  | .ed25519 => True
  | .ecdsa => False

instance (algorithm : SignatureAlgorithm) :
    Decidable algorithm.isDeterministic := by
  cases algorithm <;> unfold SignatureAlgorithm.isDeterministic <;>
    exact inferInstance

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

theorem v1_signature_is_deterministic
    (allowed : AllowedSignature Profile.v1) :
    allowed.algorithm.isDeterministic := by
  rcases allowed with ⟨algorithm, algorithmAllowed⟩
  cases algorithm with
  | ed25519 => trivial
  | ecdsa => exact False.elim (ecdsa_not_allowed algorithmAllowed)

theorem dag_cbor_allowed : Profile.v1.allowsCodec .dagCbor := by decide

theorem json_not_allowed : Not (Profile.v1.allowsCodec .json) := by decide

structure RawEnvelope where
  version : Nat
  hash : HashAlgorithm
  signature : SignatureAlgorithm
  codec : Codec
  receivedCanonical : ByteArray
  unknownCritical : List String
  deriving DecidableEq

structure VerifiedEnvelope (profile : Profile) (raw : RawEnvelope) where
  version_eq : raw.version = profile.version
  critical_empty : raw.unknownCritical = []
  allowedHash : AllowedHash profile
  hash_eq : allowedHash.algorithm = raw.hash
  allowedSignature : AllowedSignature profile
  signature_eq : allowedSignature.algorithm = raw.signature
  allowedCodec : AllowedCodec profile
  codec_eq : allowedCodec.codec = raw.codec

def verifyEnvelope (profile : Profile) (raw : RawEnvelope) :
    Option (VerifiedEnvelope profile raw) :=
  if versionEq : raw.version = profile.version then
    if criticalEmpty : raw.unknownCritical = [] then
      if hashAllowed : profile.allowsHash raw.hash then
        if signatureAllowed : profile.allowsSignature raw.signature then
          if codecAllowed : profile.allowsCodec raw.codec then
            some
              { version_eq := versionEq
                critical_empty := criticalEmpty
                allowedHash :=
                  { algorithm := raw.hash
                    allowed := hashAllowed }
                hash_eq := rfl
                allowedSignature :=
                  { algorithm := raw.signature
                    allowed := signatureAllowed }
                signature_eq := rfl
                allowedCodec :=
                  { codec := raw.codec
                    allowed := codecAllowed }
                codec_eq := rfl }
          else none
        else none
      else none
    else none
  else none

theorem verified_hash_allowed
    {profile : Profile} {raw : RawEnvelope}
    {verified : VerifiedEnvelope profile raw}
    (_h : verifyEnvelope profile raw = some verified) :
    profile.allowsHash verified.allowedHash.algorithm :=
  verified.allowedHash.allowed

theorem verified_signature_allowed
    {profile : Profile} {raw : RawEnvelope}
    {verified : VerifiedEnvelope profile raw}
    (_h : verifyEnvelope profile raw = some verified) :
    profile.allowsSignature verified.allowedSignature.algorithm :=
  verified.allowedSignature.allowed

theorem verified_codec_allowed
    {profile : Profile} {raw : RawEnvelope}
    {verified : VerifiedEnvelope profile raw}
    (_h : verifyEnvelope profile raw = some verified) :
    profile.allowsCodec verified.allowedCodec.codec :=
  verified.allowedCodec.allowed

theorem unsupported_version_rejected
    {profile : Profile} {raw : RawEnvelope}
    (h : Not (raw.version = profile.version)) :
    verifyEnvelope profile raw = none := by
  simp [verifyEnvelope, h]

theorem unknown_critical_rejected
    {profile : Profile} {raw : RawEnvelope}
    (h : Not (raw.unknownCritical = [])) :
    verifyEnvelope profile raw = none := by
  simp [verifyEnvelope, h]

def VerifiedEnvelope.receivedCanonical
    {profile : Profile} {raw : RawEnvelope}
    (_verified : VerifiedEnvelope profile raw) : ByteArray :=
  raw.receivedCanonical

theorem verified_preserves_received
    {profile : Profile} {raw : RawEnvelope}
    (verified : VerifiedEnvelope profile raw) :
    verified.receivedCanonical = raw.receivedCanonical := rfl

inductive HashImplementation
  | blake3
  | legacySha1
  deriving DecidableEq, Repr

def dispatchHash (allowed : AllowedHash profile) : HashImplementation :=
  match allowed.algorithm with
  | .blake3_256 => .blake3
  | .sha1 => .legacySha1

theorem no_v1_sha1_witness (allowed : AllowedHash Profile.v1) :
    Not (allowed.algorithm = .sha1) := by
  intro h
  apply sha1_not_allowed
  simpa [h] using allowed.allowed

end Ceremony.P1
