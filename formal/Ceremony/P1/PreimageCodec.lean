import Ceremony.P1.SignedObject

/-!
# F-233-02 — an injective, domain-separated, length-delimited preimage codec

The P1 model (`SignedObject.lean`) states `CryptoBoundary.signature_binding` over
`SignaturePreimage` *structures* (via `deriving DecidableEq`). For that structural
binding to correspond to what a signature scheme actually signs — a *byte string* —
the preimage needs a **concrete, injective canonical byte encoding**: distinct
preimages must produce distinct signed bytes. This file discharges that obligation
(epic #263, F-233-02): it exhibits such an encoding and proves it injective, via a
decoder round-trip.

**Freeze discipline (ADR 0024 §D0).** This encoding witnesses the *injectivity
property* — that a domain-separated, versioned, tagged, length-delimited canonical
encoding of `SignaturePreimage` exists. It is deliberately **not** the frozen wire
format: the exact bytes are pinned by ADR 0024 + the Phase-1d conformance vectors,
which stay deferred. The self-delimiting length prefix here is unary (proof-only,
trivially decodable); the wire codec uses a varint. Both are injective; only the
property is load-bearing at this tier.
-/

namespace Ceremony.P1.PreimageCodec

/-- A decoder consumes a prefix of the input and returns the value plus the
    untouched suffix. `none` on malformed input. -/
abbrev Reader (α : Type) := List UInt8 → Option (α × List UInt8)

/-- The round-trip law: `dec` recovers exactly what `enc` wrote and returns the
    suffix verbatim. This is precisely "the encoding is self-delimiting", which is
    what makes concatenating fields unambiguous. -/
def RoundTrip {α : Type} (enc : α → List UInt8) (dec : Reader α) : Prop :=
  ∀ (a : α) (rest : List UInt8), dec (enc a ++ rest) = some (a, rest)

/-- A self-delimiting encoder is a prefix code: a common encoded head forces the
    values *and* the tails to agree. The engine of the injectivity proof. -/
theorem RoundTrip.peel {α : Type} {enc : α → List UInt8} {dec : Reader α}
    (h : RoundTrip enc dec) {a b : α} {ta tb : List UInt8}
    (heq : enc a ++ ta = enc b ++ tb) : a = b ∧ ta = tb := by
  have ha := h a ta
  have hb := h b tb
  rw [heq] at ha
  rw [hb] at ha
  simpa using ha.symm

theorem RoundTrip.injective {α : Type} {enc : α → List UInt8} {dec : Reader α}
    (h : RoundTrip enc dec) : Function.Injective enc := by
  intro a b hab
  have := h.peel (ta := []) (tb := []) (by simpa using hab)
  exact this.1

/-! ## Atomic self-delimiting encoders -/

/-- Unary self-delimiting `Nat`: `n` zero bytes, then a `1` sentinel. Proof-only
    (the wire codec uses a varint); trivially injective and decodable. -/
def uNat : Nat → List UInt8
  | 0 => [1]
  | n + 1 => 0 :: uNat n

def readNat : Reader Nat
  | [] => none
  | b :: rest =>
    if b = 0 then (readNat rest).map (fun p => (p.1 + 1, p.2))
    else if b = 1 then some (0, rest)
    else none

theorem readNat_roundTrip : RoundTrip uNat readNat := by
  intro n
  induction n with
  | zero =>
    intro rest
    show readNat (1 :: rest) = some (0, rest)
    simp [readNat]
  | succ n ih =>
    intro rest
    show readNat (0 :: (uNat n ++ rest)) = some (n + 1, rest)
    have hstep : readNat (0 :: (uNat n ++ rest))
        = (readNat (uNat n ++ rest)).map (fun p => (p.1 + 1, p.2)) := by
      simp [readNat]
    rw [hstep, ih rest]
    rfl

/-- Length-prefixed byte blob: `uNat len ++ bytes`. Self-delimiting. -/
def blob (b : List UInt8) : List UInt8 := uNat b.length ++ b

def readBlob : Reader (List UInt8) := fun input =>
  match readNat input with
  | some (n, rest) => some (rest.take n, rest.drop n)
  | none => none

theorem readBlob_roundTrip : RoundTrip blob readBlob := by
  intro b rest
  show readBlob (uNat b.length ++ b ++ rest) = some (b, rest)
  simp only [readBlob, List.append_assoc]
  rw [readNat_roundTrip b.length (b ++ rest)]
  simp only [List.take_left, List.drop_left]

theorem uNat_length (n : Nat) : (uNat n).length = n + 1 := by
  induction n with
  | zero => rfl
  | succ m ih => simp [uNat, ih, Nat.add_comm]

theorem blob_ne_nil (b : List UInt8) : blob b ≠ [] := by
  intro h
  have hlen : (blob b).length = 0 := by rw [h]; rfl
  simp only [blob, List.length_append, uNat_length] at hlen
  omega

/-- Single-byte tag for each `HashAlgorithm`. -/
def encHash : HashAlgorithm → List UInt8
  | .blake3_256 => [10]
  | .sha1 => [11]

def readHash : Reader HashAlgorithm := fun input =>
  match input with
  | [] => none
  | b :: rest =>
    if b = 10 then some (.blake3_256, rest)
    else if b = 11 then some (.sha1, rest)
    else none

theorem readHash_roundTrip : RoundTrip encHash readHash := by
  intro a rest
  cases a with
  | blake3_256 => show readHash (10 :: rest) = _; simp [readHash]
  | sha1 => show readHash (11 :: rest) = _; simp [readHash]

def encSig : SignatureAlgorithm → List UInt8
  | .ed25519 => [20]
  | .ecdsa => [21]

def readSig : Reader SignatureAlgorithm := fun input =>
  match input with
  | [] => none
  | b :: rest =>
    if b = 20 then some (.ed25519, rest)
    else if b = 21 then some (.ecdsa, rest)
    else none

theorem readSig_roundTrip : RoundTrip encSig readSig := by
  intro a rest
  cases a with
  | ed25519 => show readSig (20 :: rest) = _; simp [readSig]
  | ecdsa => show readSig (21 :: rest) = _; simp [readSig]

def encCodec : Codec → List UInt8
  | .dagCbor => [30]
  | .json => [31]

def readCodec : Reader Codec := fun input =>
  match input with
  | [] => none
  | b :: rest =>
    if b = 30 then some (.dagCbor, rest)
    else if b = 31 then some (.json, rest)
    else none

theorem readCodec_roundTrip : RoundTrip encCodec readCodec := by
  intro a rest
  cases a with
  | dagCbor => show readCodec (30 :: rest) = _; simp [readCodec]
  | json => show readCodec (31 :: rest) = _; simp [readCodec]

/-! ## Injectivity of the domain-type field maps -/

theorem bytearray_data_toList_inj {a b : ByteArray}
    (h : a.data.toList = b.data.toList) : a = b :=
  ByteArray.ext (Array.ext' h)

theorem string_utf8_toList_inj {s t : String}
    (h : s.toUTF8.data.toList = t.toUTF8.data.toList) : s = t :=
  String.toByteArray_inj.mp (bytearray_data_toList_inj h)

/-! ## `List String` (the `unknownCritical` field) -/

def encStr (s : String) : List UInt8 := blob s.toUTF8.data.toList

/-- The critical-extensions list, each element a self-delimiting UTF-8 blob. -/
def encStrItems : List String → List UInt8
  | [] => []
  | s :: t => encStr s ++ encStrItems t

/-- Count-prefixed list of strings. Self-delimiting. -/
def encStrList (l : List String) : List UInt8 := uNat l.length ++ encStrItems l

theorem encStrItems_injective : Function.Injective encStrItems := by
  intro l
  induction l with
  | nil =>
    intro m hm
    cases m with
    | nil => rfl
    | cons b m' =>
      exfalso
      simp only [encStrItems, encStr] at hm
      have := congrArg List.length hm
      simp only [List.length_nil, List.length_append, blob, uNat_length] at this
      omega
  | cons a l' ih =>
    intro m hm
    cases m with
    | nil =>
      exfalso
      simp only [encStrItems, encStr] at hm
      have := congrArg List.length hm
      simp only [List.length_nil, List.length_append, blob, uNat_length] at this
      omega
    | cons b m' =>
      simp only [encStrItems, encStr] at hm
      obtain ⟨hhead, htail⟩ := readBlob_roundTrip.peel hm
      have hab := string_utf8_toList_inj hhead
      have hlm := ih htail
      rw [hab, hlm]

theorem encStrList_injective : Function.Injective encStrList := by
  intro l m hm
  simp only [encStrList] at hm
  obtain ⟨_, htail⟩ := readNat_roundTrip.peel hm
  exact encStrItems_injective htail

/-! ## The preimage encoding and its injectivity (F-233-02) -/

/-- Domain-separation label (OB-6): a fixed, versioned prefix binding the signing
    context to the signed-object profile. Constant, so it does not distinguish
    preimages — it separates this signing context from every other. -/
def domainLabelBytes : List UInt8 := "agent-bridle/signed-object/v1".toUTF8.toList

/-- The canonical, domain-separated, versioned, length-delimited encoding of the
    OB-13 protected tuple. Every one of the ten fields is written self-delimiting,
    behind the domain label, so the whole is a prefix code. -/
def encodeSignaturePreimage (p : SignaturePreimage) : List UInt8 :=
  blob domainLabelBytes
    ++ blob p.canonicalUnsigned.data.toList
    ++ uNat p.profileVersion
    ++ encHash p.hashAlgorithm
    ++ encSig p.signatureAlgorithm
    ++ encCodec p.codec
    ++ blob p.domain.recordType.toUTF8.data.toList
    ++ blob p.domain.storeId.data.toList
    ++ blob p.domain.threadOrPrincipal.data.toList
    ++ blob p.body.data.toList
    ++ blob p.claimedCid.data.toList
    ++ blob p.signer.data.toList
    ++ encStrList p.unknownCritical

/-- **F-233-02.** Distinct protected tuples produce distinct signed bytes. This is
    what lets the structural `CryptoBoundary.signature_binding` correspond to a
    byte-level EUF-CMA assumption: a signature over `encodeSignaturePreimage p`
    binds `p` uniquely. -/
theorem encodeSignaturePreimage_injective :
    Function.Injective encodeSignaturePreimage := by
  intro p q h
  obtain ⟨pcu, ppv, pha, psa, pco, ⟨prt, psi, ptp⟩, pbo, pci, psg, puc⟩ := p
  obtain ⟨qcu, qpv, qha, qsa, qco, ⟨qrt, qsi, qtp⟩, qbo, qci, qsg, quc⟩ := q
  simp only [encodeSignaturePreimage, List.append_assoc] at h
  obtain ⟨_, h⟩ := readBlob_roundTrip.peel h
  obtain ⟨hcu, h⟩ := readBlob_roundTrip.peel h
  obtain ⟨hpv, h⟩ := readNat_roundTrip.peel h
  obtain ⟨hha, h⟩ := readHash_roundTrip.peel h
  obtain ⟨hsa, h⟩ := readSig_roundTrip.peel h
  obtain ⟨hco, h⟩ := readCodec_roundTrip.peel h
  obtain ⟨hrt, h⟩ := readBlob_roundTrip.peel h
  obtain ⟨hsi, h⟩ := readBlob_roundTrip.peel h
  obtain ⟨htp, h⟩ := readBlob_roundTrip.peel h
  obtain ⟨hbo, h⟩ := readBlob_roundTrip.peel h
  obtain ⟨hci, h⟩ := readBlob_roundTrip.peel h
  obtain ⟨hsg, h⟩ := readBlob_roundTrip.peel h
  have huc := encStrList_injective h
  have ecu := bytearray_data_toList_inj hcu
  have ert := string_utf8_toList_inj hrt
  have esi := bytearray_data_toList_inj hsi
  have etp := bytearray_data_toList_inj htp
  have ebo := bytearray_data_toList_inj hbo
  have eci := bytearray_data_toList_inj hci
  have esg := bytearray_data_toList_inj hsg
  subst ecu; subst hpv; subst hha; subst hsa; subst hco
  subst ert; subst esi; subst etp; subst ebo; subst eci; subst esg; subst huc
  rfl

/-! ## The payoff: structural binding from a byte-level assumption

`SignedObject.lean`'s `CryptoBoundary.signature_binding` is stated over
`SignaturePreimage` *structures*. Today it is a bare postulate — the F-233-01/04
"algebraic equality stand-in" the audit flags. The honest form places the
cryptographic assumption where it belongs — on the **bytes** a signature scheme
actually signs (Tier-1 "assumed crypto", i.e. EUF-CMA) — and *derives* the
structural binding from that plus the injectivity proved above. This file shows the
derivation is sound; rewiring `SignedObject.lean` to adopt it is the F-233-01/04
follow-up. -/

/-- A byte-level signature relation carrying an EUF-CMA-style binding **assumption**
    (Tier-1): a signature that validates two byte messages forces the messages and
    the algorithm to agree. Stated over `List UInt8` — what is actually signed. -/
structure ByteSigner (profile : Profile) where
  SignedBytes : AllowedSignature profile → List UInt8 → ByteArray → Prop
  bytes_binding : ∀ leftAllowed rightAllowed leftMsg rightMsg signature,
    SignedBytes leftAllowed leftMsg signature ->
      SignedBytes rightAllowed rightMsg signature ->
        leftAllowed.algorithm = rightAllowed.algorithm /\ leftMsg = rightMsg

/-- **The bridge (F-233-02).** When the boundary signs `encodeSignaturePreimage p`,
    the *structural* binding that `SignedObject.lean` assumes outright is instead
    a **theorem**: byte-level EUF-CMA (Tier-1) composed with encoding injectivity
    (Tier-3, proved above). No structural `signature_binding` postulate is needed. -/
theorem structural_binding_from_bytes {profile : Profile} (signer : ByteSigner profile)
    {leftAllowed rightAllowed : AllowedSignature profile}
    {leftPreimage rightPreimage : SignaturePreimage} {signature : ByteArray}
    (hleft : signer.SignedBytes leftAllowed
      (encodeSignaturePreimage leftPreimage) signature)
    (hright : signer.SignedBytes rightAllowed
      (encodeSignaturePreimage rightPreimage) signature) :
    leftAllowed.algorithm = rightAllowed.algorithm /\ leftPreimage = rightPreimage := by
  obtain ⟨halg, hbytes⟩ :=
    signer.bytes_binding _ _ _ _ _ hleft hright
  exact ⟨halg, encodeSignaturePreimage_injective hbytes⟩

end Ceremony.P1.PreimageCodec
