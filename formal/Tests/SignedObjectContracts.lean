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

def attackerProfile : Profile :=
  { Profile.v1 with hashes := [.sha1] }

example (trusted : TrustedProfile attackerProfile) : False := by
  cases trusted

def bytesEncoding : CanonicalEncoding ByteArray where
  encode := id
  injective := by
    intro left right h
    exact h

def bytesDecoder : CanonicalPayloadDecoder ByteArray bytesEncoding where
  parse := some
  parse_exact := by
    intro bytes value parsed
    cases parsed
    rfl

def goodReceived : ByteArray := ByteArray.mk #[1]

def alteredBodyReceived : ByteArray := ByteArray.mk #[2]

def alteredDomainReceived : ByteArray := ByteArray.mk #[3]

def alteredSignatureReceived : ByteArray := ByteArray.mk #[4]

def unsupportedVersionReceived : ByteArray := ByteArray.mk #[5]

def sha1Received : ByteArray := ByteArray.mk #[6]

def ecdsaReceived : ByteArray := ByteArray.mk #[7]

def jsonReceived : ByteArray := ByteArray.mk #[8]

def unknownCriticalReceived : ByteArray := ByteArray.mk #[9]

def unrelatedReceived : ByteArray := ByteArray.mk #[10]

def alteredCidReceived : ByteArray := ByteArray.mk #[11]

def alteredRecordTypeReceived : ByteArray := ByteArray.mk #[12]

def alteredStoreReceived : ByteArray := ByteArray.mk #[13]

def alteredSignerReceived : ByteArray := ByteArray.mk #[14]

def goodBody : ByteArray := ByteArray.mk #[20, 21]

def alteredBody : ByteArray := ByteArray.mk #[20, 22]

def goodCid : ByteArray := goodBody

def goodSigner : ByteArray := ByteArray.mk #[40, 41]

def alteredSigner : ByteArray := ByteArray.mk #[40, 42]

def goodSignature : ByteArray := ByteArray.mk #[50, 51]

def alteredSignature : ByteArray := ByteArray.mk #[50, 52]

def goodDomain : SignatureDomain :=
  { recordType := "grant-record"
    storeId := ByteArray.mk #[60]
    threadOrPrincipal := ByteArray.mk #[61] }

def alteredDomain : SignatureDomain :=
  { goodDomain with threadOrPrincipal := ByteArray.mk #[62] }

def alteredRecordTypeDomain : SignatureDomain :=
  { goodDomain with recordType := "decision-record" }

def alteredStoreDomain : SignatureDomain :=
  { goodDomain with storeId := ByteArray.mk #[63] }

def testUnsigned (envelope : ByteArray) : ByteArray :=
  if envelope = alteredSignatureReceived then goodReceived else envelope

def testEnvelopeCodec : SignedEnvelopeCodec where
  Envelope := ByteArray
  Unsigned := ByteArray
  encode := id
  encode_injective := by
    intro left right h
    exact h
  decode := some
  decode_exact := by
    intro received envelope decoded
    cases decoded
    rfl
  unsigned := testUnsigned
  encodeUnsigned := id
  unsigned_injective := by
    intro left right h
    exact h
  version := fun unsigned =>
    if unsigned = unsupportedVersionReceived then 2 else 1
  hash := fun unsigned =>
    if unsigned = sha1Received then .sha1 else .blake3_256
  signatureAlgorithm := fun unsigned =>
    if unsigned = ecdsaReceived then .ecdsa else .ed25519
  codec := fun unsigned =>
    if unsigned = jsonReceived then .json else .dagCbor
  domain := fun unsigned =>
    if unsigned = alteredDomainReceived then alteredDomain
    else if unsigned = alteredRecordTypeReceived then alteredRecordTypeDomain
    else if unsigned = alteredStoreReceived then alteredStoreDomain
    else goodDomain
  body := fun unsigned =>
    if unsigned = alteredBodyReceived then alteredBody else goodBody
  claimedCid := fun unsigned =>
    if unsigned = alteredCidReceived then alteredBody else goodCid
  signer := fun unsigned =>
    if unsigned = alteredSignerReceived then alteredSigner else goodSigner
  signatureBytes := fun envelope =>
    if envelope = alteredSignatureReceived then alteredSignature else goodSignature
  unknownCritical := fun unsigned =>
    if unsigned = unknownCriticalReceived then ["future-authority"] else []

def crossCodecReplay : SignedEnvelopeCodec :=
  { testEnvelopeCodec with
    domain := fun (unsigned : ByteArray) =>
      if unsigned = goodReceived then alteredRecordTypeDomain
      else testEnvelopeCodec.domain unsigned }

def goodPreimage : SignaturePreimage :=
  { canonicalUnsigned := goodReceived
    profileVersion := 1
    hashAlgorithm := .blake3_256
    signatureAlgorithm := .ed25519
    codec := .dagCbor
    domain := goodDomain
    body := goodBody
    claimedCid := goodCid
    signer := goodSigner
    unknownCritical := [] }

def exactCrypto : CryptoBoundary Profile.v1 where
  digest := fun _allowed body => body
  digest_binding := by
    intro leftAllowed rightAllowed left right sameDigest
    exact
      ⟨(trusted_hash_is_blake3 TrustedProfile.v1 leftAllowed).trans
          (trusted_hash_is_blake3 TrustedProfile.v1 rightAllowed).symm,
        sameDigest⟩
  SignedBy := fun allowed preimage signature =>
    allowed.algorithm = .ed25519 /\ preimage = goodPreimage /\
      signature = goodSignature
  signatureMatches := fun allowed preimage signature =>
    decide (allowed.algorithm = .ed25519 /\ preimage = goodPreimage /\
      signature = goodSignature)
  signature_sound := by
    intro allowed preimage signature valid
    exact of_decide_eq_true valid
  signature_binding := by
    intro leftAllowed rightAllowed left right _signature leftValid rightValid
    exact
      ⟨leftValid.1.trans rightValid.1.symm,
        leftValid.2.1.trans rightValid.2.1.symm⟩
  signature_deterministic := by
    intro _allowed _preimage left right leftValid rightValid
    exact leftValid.2.2.trans rightValid.2.2.symm

example {received envelope}
    (decoded : testEnvelopeCodec.decode received = some envelope) :
    testEnvelopeCodec.encode envelope = received :=
  testEnvelopeCodec.decode_exact received envelope decoded

example : testEnvelopeCodec.signaturePreimage goodReceived = goodPreimage := by
  decide

example :
    (verifyEnvelope TrustedProfile.v1 testEnvelopeCodec exactCrypto
      goodReceived).isSome := by
  decide

example :
    (verifyEnvelope TrustedProfile.v1 testEnvelopeCodec exactCrypto
      alteredBodyReceived).isNone := by
  decide

example :
    (verifyEnvelope TrustedProfile.v1 testEnvelopeCodec exactCrypto
      alteredDomainReceived).isNone := by
  decide

example :
    (verifyEnvelope TrustedProfile.v1 testEnvelopeCodec exactCrypto
      alteredRecordTypeReceived).isNone := by
  decide

example :
    (verifyEnvelope TrustedProfile.v1 testEnvelopeCodec exactCrypto
      alteredStoreReceived).isNone := by
  decide

example :
    (verifyEnvelope TrustedProfile.v1 testEnvelopeCodec exactCrypto
      alteredSignerReceived).isNone := by
  decide

example :
    (verifyEnvelope TrustedProfile.v1 testEnvelopeCodec exactCrypto
      alteredCidReceived).isNone := by
  decide

example :
    (verifyEnvelope TrustedProfile.v1 crossCodecReplay exactCrypto
      goodReceived).isNone := by
  decide

example :
    (verifyEnvelope TrustedProfile.v1 testEnvelopeCodec exactCrypto
      alteredSignatureReceived).isNone := by
  decide

example :
    (verifyEnvelope TrustedProfile.v1 testEnvelopeCodec exactCrypto
      unsupportedVersionReceived).isNone := by
  decide

example :
    (verifyEnvelope TrustedProfile.v1 testEnvelopeCodec exactCrypto
      sha1Received).isNone := by
  decide

example :
    (verifyEnvelope TrustedProfile.v1 testEnvelopeCodec exactCrypto
      ecdsaReceived).isNone := by
  decide

example :
    (verifyEnvelope TrustedProfile.v1 testEnvelopeCodec exactCrypto
      jsonReceived).isNone := by
  decide

example :
    (verifyEnvelope TrustedProfile.v1 testEnvelopeCodec exactCrypto
      unknownCriticalReceived).isNone := by
  decide

example :
    (verifyEnvelope TrustedProfile.v1 testEnvelopeCodec exactCrypto
      unrelatedReceived).isNone := by
  decide

example :
    (verifyEnvelope TrustedProfile.v1 testEnvelopeCodec exactCrypto goodReceived).map
      (fun verified => testEnvelopeCodec.encode verified.envelope) =
        some goodReceived := by
  decide

example :
    (loadEnvelope bytesDecoder TrustedProfile.v1 testEnvelopeCodec exactCrypto
      goodReceived).map (fun sealed => sealed.value) = some goodBody := by
  decide

example
    (left right :
      Sealed bytesEncoding Profile.v1 testEnvelopeCodec exactCrypto goodReceived) :
    left.value = right.value :=
  sealed_value_unique left right
