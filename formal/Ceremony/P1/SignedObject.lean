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

inductive TrustedProfile : Profile -> Type
  | v1 : TrustedProfile Profile.v1

theorem trusted_profile_is_v1
    {profile : Profile} (_trusted : TrustedProfile profile) :
    profile = Profile.v1 := by
  cases _trusted
  rfl

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

structure CanonicalPayloadDecoder
    (Value : Type) (encoding : CanonicalEncoding Value) where
  parse : ByteArray -> Option Value
  parse_exact : forall bytes value, parse bytes = some value ->
    bytes = encoding.encode value

structure SignatureDomain where
  recordType : String
  storeId : ByteArray
  threadOrPrincipal : ByteArray
  deriving DecidableEq

structure SignaturePreimage where
  canonicalUnsigned : ByteArray
  profileVersion : Nat
  hashAlgorithm : HashAlgorithm
  signatureAlgorithm : SignatureAlgorithm
  codec : Codec
  domain : SignatureDomain
  body : ByteArray
  claimedCid : ByteArray
  signer : ByteArray
  unknownCritical : List String
  deriving DecidableEq

structure SignedEnvelopeCodec where
  Envelope : Type
  Unsigned : Type
  encode : Envelope -> ByteArray
  encode_injective : Function.Injective encode
  decode : ByteArray -> Option Envelope
  decode_exact : forall received envelope, decode received = some envelope ->
    encode envelope = received
  unsigned : Envelope -> Unsigned
  encodeUnsigned : Unsigned -> ByteArray
  unsigned_injective : Function.Injective encodeUnsigned
  version : Unsigned -> Nat
  hash : Unsigned -> HashAlgorithm
  signatureAlgorithm : Unsigned -> SignatureAlgorithm
  codec : Unsigned -> Codec
  domain : Unsigned -> SignatureDomain
  body : Unsigned -> ByteArray
  claimedCid : Unsigned -> ByteArray
  signer : Unsigned -> ByteArray
  signatureBytes : Envelope -> ByteArray
  unknownCritical : Unsigned -> List String

def SignedEnvelopeCodec.signaturePreimage
    (envelopeCodec : SignedEnvelopeCodec)
    (unsigned : envelopeCodec.Unsigned) : SignaturePreimage :=
  { canonicalUnsigned := envelopeCodec.encodeUnsigned unsigned
    profileVersion := envelopeCodec.version unsigned
    hashAlgorithm := envelopeCodec.hash unsigned
    signatureAlgorithm := envelopeCodec.signatureAlgorithm unsigned
    codec := envelopeCodec.codec unsigned
    domain := envelopeCodec.domain unsigned
    body := envelopeCodec.body unsigned
    claimedCid := envelopeCodec.claimedCid unsigned
    signer := envelopeCodec.signer unsigned
    unknownCritical := envelopeCodec.unknownCritical unsigned }

/-- The **operational** crypto interface a signature scheme must provide: a digest,
    an abstract signature relation, a concrete `Bool` verifier, and its soundness.
    This is deliberately inhabitable by *real* crypto (a real Ed25519 + BLAKE3
    boundary — see `PreimageCodec.CryptoBoundary.ofByteSigner`).

    The **security** properties are NOT postulated here (F-233-01/04). The former
    `digest_binding` asserted impossible *global* injectivity over arbitrary
    `ByteArray` — only a fake identity "hash" could satisfy it, so BLAKE3-256 could
    not inhabit this structure and every theorem over it was vacuous for real
    crypto. Digest collision-resistance is a Tier-1 *computational* assumption, not
    a total-function property, so it is intentionally absent. Likewise the former
    `signature_binding` / `signature_deterministic` were algebraic stand-ins, not
    EUF-CMA; they are now **derived theorems** about a byte-level signer
    (`PreimageCodec.structural_binding_from_bytes` /
    `structural_determinism_from_bytes`), resting on the Tier-1 `ByteSigner`
    assumptions composed with the Tier-3 `encodeSignaturePreimage_injective`. -/
structure CryptoBoundary (profile : Profile) where
  digest : AllowedHash profile -> ByteArray -> ByteArray
  SignedBy : AllowedSignature profile -> SignaturePreimage -> ByteArray -> Prop
  signatureMatches : AllowedSignature profile -> SignaturePreimage -> ByteArray -> Bool
  signature_sound : forall allowed preimage signature,
    signatureMatches allowed preimage signature = true ->
      SignedBy allowed preimage signature

structure VerifiedEnvelope
    (profile : Profile)
    (envelopeCodec : SignedEnvelopeCodec)
    (crypto : CryptoBoundary profile)
    (received : ByteArray) where
  private verified ::
  envelope : envelopeCodec.Envelope
  decoded_eq : envelopeCodec.decode received = some envelope
  received_exact : envelopeCodec.encode envelope = received
  trustedProfile : TrustedProfile profile
  version_eq :
    envelopeCodec.version (envelopeCodec.unsigned envelope) = profile.version
  critical_empty :
    envelopeCodec.unknownCritical (envelopeCodec.unsigned envelope) = []
  allowedHash : AllowedHash profile
  hash_eq :
    allowedHash.algorithm = envelopeCodec.hash (envelopeCodec.unsigned envelope)
  allowedSignature : AllowedSignature profile
  signature_eq : allowedSignature.algorithm =
    envelopeCodec.signatureAlgorithm (envelopeCodec.unsigned envelope)
  allowedCodec : AllowedCodec profile
  codec_eq :
    allowedCodec.codec = envelopeCodec.codec (envelopeCodec.unsigned envelope)
  digestEvidence :
    envelopeCodec.claimedCid (envelopeCodec.unsigned envelope) =
      crypto.digest allowedHash
        (envelopeCodec.body (envelopeCodec.unsigned envelope))
  signatureEvidence : crypto.SignedBy allowedSignature
    (envelopeCodec.signaturePreimage (envelopeCodec.unsigned envelope))
    (envelopeCodec.signatureBytes envelope)

def verifyEnvelope
    {profile : Profile}
    (trustedProfile : TrustedProfile profile)
    (envelopeCodec : SignedEnvelopeCodec)
    (crypto : CryptoBoundary profile)
    (received : ByteArray) :
    Option (VerifiedEnvelope profile envelopeCodec crypto received) :=
  match decodedEq : envelopeCodec.decode received with
  | none => none
  | some envelope =>
      let unsigned := envelopeCodec.unsigned envelope
      if versionEq : envelopeCodec.version unsigned = profile.version then
        if criticalEmpty : envelopeCodec.unknownCritical unsigned = [] then
          if hashAllowed : profile.allowsHash (envelopeCodec.hash unsigned) then
            let allowedHash : AllowedHash profile :=
              { algorithm := envelopeCodec.hash unsigned
                allowed := hashAllowed }
            if signatureAllowed :
                profile.allowsSignature (envelopeCodec.signatureAlgorithm unsigned) then
              let allowedSignature : AllowedSignature profile :=
                { algorithm := envelopeCodec.signatureAlgorithm unsigned
                  allowed := signatureAllowed }
              if codecAllowed : profile.allowsCodec (envelopeCodec.codec unsigned) then
                let allowedCodec : AllowedCodec profile :=
                  { codec := envelopeCodec.codec unsigned
                    allowed := codecAllowed }
                if digestValid : envelopeCodec.claimedCid unsigned =
                    crypto.digest allowedHash (envelopeCodec.body unsigned) then
                  if signatureValid : crypto.signatureMatches allowedSignature
                      (envelopeCodec.signaturePreimage unsigned)
                      (envelopeCodec.signatureBytes envelope) = true then
                    some
                      { envelope
                        decoded_eq := decodedEq
                        received_exact :=
                          envelopeCodec.decode_exact received envelope decodedEq
                        trustedProfile
                        version_eq := versionEq
                        critical_empty := criticalEmpty
                        allowedHash
                        hash_eq := rfl
                        allowedSignature
                        signature_eq := rfl
                        allowedCodec
                        codec_eq := rfl
                        digestEvidence := digestValid
                        signatureEvidence :=
                          crypto.signature_sound _ _ _ signatureValid }
                  else none
                else none
              else none
            else none
          else none
        else none
      else none

structure Sealed
    {Value : Type}
    (encoding : CanonicalEncoding Value)
    (profile : Profile)
    (envelopeCodec : SignedEnvelopeCodec)
    (crypto : CryptoBoundary profile)
    (received : ByteArray) where
  private sealed ::
  verified : VerifiedEnvelope profile envelopeCodec crypto received
  value : Value
  canonical_eq :
    envelopeCodec.body (envelopeCodec.unsigned verified.envelope) =
      encoding.encode value

def parseVerified
    {Value : Type}
    {encoding : CanonicalEncoding Value}
    (decoder : CanonicalPayloadDecoder Value encoding)
    {profile : Profile}
    {envelopeCodec : SignedEnvelopeCodec}
    {crypto : CryptoBoundary profile}
    {received : ByteArray}
    (verified : VerifiedEnvelope profile envelopeCodec crypto received) :
    Option (Sealed encoding profile envelopeCodec crypto received) :=
  let body := envelopeCodec.body (envelopeCodec.unsigned verified.envelope)
  match parsedEq : decoder.parse body with
  | none => none
  | some value =>
      some
        { verified
          value
          canonical_eq := decoder.parse_exact body value parsedEq }

def loadEnvelope
    {Value : Type}
    {encoding : CanonicalEncoding Value}
    (decoder : CanonicalPayloadDecoder Value encoding)
    {profile : Profile}
    (trustedProfile : TrustedProfile profile)
    (envelopeCodec : SignedEnvelopeCodec)
    (crypto : CryptoBoundary profile)
    (received : ByteArray) :
    Option (Sealed encoding profile envelopeCodec crypto received) :=
  match verifyEnvelope trustedProfile envelopeCodec crypto received with
  | none => none
  | some verified => parseVerified decoder verified

theorem sealed_value_unique
    {Value : Type}
    {encoding : CanonicalEncoding Value}
    {profile : Profile}
    {envelopeCodec : SignedEnvelopeCodec}
    {crypto : CryptoBoundary profile}
    {received : ByteArray}
    (left right : Sealed encoding profile envelopeCodec crypto received) :
    left.value = right.value := by
  have envelopeEq : left.verified.envelope = right.verified.envelope :=
    envelopeCodec.encode_injective <|
      left.verified.received_exact.trans right.verified.received_exact.symm
  have bodyEq :
      envelopeCodec.body (envelopeCodec.unsigned left.verified.envelope) =
        envelopeCodec.body (envelopeCodec.unsigned right.verified.envelope) :=
    congrArg (fun envelope =>
      envelopeCodec.body (envelopeCodec.unsigned envelope)) envelopeEq
  apply encoding.injective
  exact left.canonical_eq.symm.trans (bodyEq.trans right.canonical_eq)

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

inductive HashImplementation
  | blake3
  | legacySha1
  deriving DecidableEq, Repr

theorem trusted_hash_is_blake3
    {profile : Profile}
    (trusted : TrustedProfile profile)
    (allowed : AllowedHash profile) :
    allowed.algorithm = .blake3_256 := by
  have profileEq := trusted_profile_is_v1 trusted
  subst profile
  cases algorithmEq : allowed.algorithm with
  | blake3_256 => rfl
  | sha1 =>
      exfalso
      apply sha1_not_allowed
      simpa [algorithmEq] using allowed.allowed

theorem no_v1_sha1_witness (allowed : AllowedHash Profile.v1) :
    Not (allowed.algorithm = .sha1) := by
  intro algorithmEq
  have trustedEq := trusted_hash_is_blake3 TrustedProfile.v1 allowed
  simp [algorithmEq] at trustedEq

def dispatchHash
    {profile : Profile}
    (trusted : TrustedProfile profile)
    (allowed : AllowedHash profile) : HashImplementation :=
  match trusted_hash_is_blake3 trusted allowed with
  | _ => .blake3

end Ceremony.P1
