import Ceremony.P1.SignedObject

open Ceremony.P1

def unsafeDispatch : HashAlgorithm -> HashImplementation
  | .blake3_256 => .blake3
  | .sha1 => .legacySha1

example : unsafeDispatch .sha1 = .legacySha1 := rfl

example (allowed : AllowedHash Profile.v1) :
    Not (allowed.algorithm = .sha1) :=
  no_v1_sha1_witness allowed

example : dispatchHash
    TrustedProfile.v1
    ({ algorithm := .blake3_256, allowed := blake3_allowed } :
      AllowedHash Profile.v1) = .blake3 := rfl
