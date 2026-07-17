# Ceremony Suite — Agent Onboarding Primer

**Read this first.** You have been brought online to work on the **Ceremony
Suite**: the specification (and eventually the proven implementation) of how
an agent system decides *who may do what*, binds those decisions to a
tamper-evident history, and proves it. This primer gets you from cold to
productive. It is opinionated on purpose — the design has survived multiple
adversarial reviews, and the conventions below are how it stays sound.

If you read nothing else, read: this file, then
[`README.md`](README.md) (the suite index), then the one profile you were
assigned. The five laws in [`ceremony-contract.md`](ceremony-contract.md) §4
are the spine of everything.

---

## 1. What this is, in one breath

Agent harnesses need to enforce authority: run this command? trust this
peer? pin this key? The **Ceremony Contract** is the library-side contract
for those decisions; the **Ceremony Suite** is that contract split into
seven documents, each provable in isolation, with the five laws as a *narrow
waist*.

The deliverable for end-users is a harness (newt, hermes, gila, a Claude
Code / Codex plugin) that prompts a human at the right moment and enforces
the answer. Everything here is the plumbing that makes those prompts
**honest** — cryptographically bound to what actually executes, and provably
unable to widen authority behind the user's back.

## 2. Why it matters — the contribution

A verified research pass established that the *ideas* here are ~30 years of
mainstream consensus (Saltzer's identifier/locator split, Host Identity
Protocol, NIST 800-207 Zero Trust, SPIFFE, iroh's "dial the key, not the
IP"). We are not inventing the loc/ID split.

**The unique contribution is the enforcement gate.** Nobody ships
*first-contact ceremony enforcement* — fail-closed, consumer-rendered,
presence-attested, caveat-attenuated — as a reusable, harness-agnostic,
formally-verified library. HIP admits the trust-on-first-use "leap of faith"
and ships nothing; SSH/Signal bake a prompt into one client; WebPKI/Tailscale
centralize; SPIRE automates the human away. WebAuthn is the closest precedent
(relying-party library enforces, platform renders) but is user→service, not
peer↔peer agent introduction.

So the moat is **the contract, not the crate**: publish the spec so any
harness can comply without taking a dependency; `agent-bridle` is the
reference implementation. Client libraries follow in Rust, Python, Dart, and
TypeScript (one Rust enforcement core; the other languages implement the
*consumer* side only — never fork the gate).

## 3. The doctrine (load-bearing beliefs — internalize these)

These are not style preferences; violating them has repeatedly produced real
bugs that adversarial reviewers found.

1. **The authenticated thing is always the key, never the channel.**
   Locations, relays, registries, and rendered pixels are candidates and
   hints; signatures and content-IDs are what a gate trusts. (This is the
   floating-identity doctrine — see agent-mesh `docs/decisions/
   floating_identity.md`. Identity floats; harnesses are fungible substrate.)
2. **No authorization or claim floats free of the exact history and
   artifacts that gave it meaning.** A decision binds the request; the
   request binds the executable effect; an attestation binds a non-regressing
   history checkpoint.
3. **Law minimalism.** A good system has only the laws it absolutely needs.
   *Nothing enters the law section without a proof obligation demanding it;*
   everything else is mechanism (a profile) or well-formedness. We have gone
   6 → 5 laws and absorbed four review rounds of additions at **zero** net
   law cost. The algebra decides the count; ambition does not.
4. **Libraries expose decision STRUCTS and seams; they contain NO TUI.**
   `agent-bridle` / `agent-mesh` / `agent-*` are libraries. They expose a
   `DecisionSurface` seam that *demands* a consumer-built UI; they never
   render. newt draws a matrix chooser, hermes a flat list, a daemon reads a
   policy file — one struct, many layouts. (Backlog: agent-bridle#225.)
5. **Algorithms are pins, not laws.** Laws name *properties* (collision
   resistance, determinism); a profile pins the algorithm; identifiers are
   self-describing (multihash/multicodec). *"BLAKE3 is an implementation
   detail."* Agility needs an allowlist checked before dispatch, or it is a
   downgrade attack.
6. **Honesty over completeness.** When a mechanism does not fully close a
   gap, name the residual (rendering faithfulness is not cryptographic; the
   chain alone does not stop rollback). A claim stronger than the machinery
   is the exact failure adversarial review punishes: *"prose becomes
   authority-bearing protocol."*
7. **Publish over patent.** Default to publishing defensively.

## 4. The architecture: the suite

Seven documents. Each is a **decision** with a lifecycle: *Proposed →
Accepted → Proven*. A downstream decision **cannot be Accepted until its
dependencies are Proven** — that is the "chain of decisions."

| # | Profile | Owns |
|---|---|---|
| **P0** | [`ceremony-contract.md`](ceremony-contract.md) | the five laws, the authority lattice, the `DecisionSurface` seam, gate acceptance — **the narrow waist** |
| **P1** | [`signed-object-profile.md`](signed-object-profile.md) | naming, canonicalization, signatures, the signed-bytes envelope, the algorithm allowlist |
| **P2** | [`chain-store-profile.md`](chain-store-profile.md) | the causal-transcript store, the linear authority spine, the external anti-rollback anchor |
| **P3** | [`enrollment-protocol.md`](enrollment-protocol.md) | introductions, SAS pairing, external anchors |
| **P4** | [`identity-lifecycle.md`](identity-lifecycle.md) | roles & delegation, records, quorum revocation, break-glass/succession |
| **P5** | [`rendering-security-profile.md`](rendering-security-profile.md) | effect binding, gate-signed requests, surface attestation |

**Dependency order:** `P1 → P2 → P0 → P4 → P3`, with P5 on {P0, P1, P4}.
(P0 depends on P4 only via *abstract contracts P0 itself defines* —
`AttestEvidence`, `ValidAssociationProof` — which P4 implements. That
dependency inversion is what keeps the graph acyclic; do not reintroduce a
concrete P4 type into P0.)

The provable MVP is **P1 + P2 + P0** — the waist. Ceremonies (P3–P5) graft
on once the waist is Proven. `suite.toml` pins which profile versions form
one compatible suite.

## 5. The three tiers of "teeth" (do not confuse them)

Correctness is enforced in layers, each verified by a *different* tool. A
proof that silently assumes the wrong tier is the classic failure mode.

- **Tier 3 — Lean + Aeneas (kernel refinement).** The authority *algebra*
  and the trusted *state machine* (P0/P1/P2/P4). A pure Rust kernel is
  extracted by Charon and proven in Lean via Aeneas to refine the model. CI
  gate: no Rust kernel merges unless the refinement proof passes.
- **Tier 2 — Tamarin / ProVerif (protocol safety).** The *ceremonies* (P3,
  parts of P5). A flawless lattice can sit behind a leaky handshake, so
  MITM / replay / unknown-key-share get *symbolic* proof, not algebraic.
- **Tier 1 — cryptographic primitives (assumed).** Ed25519 unforgeability,
  BLAKE3 collision resistance, deterministic nonces. Cited, not proven; the
  trust base; rotatable via P1's allowlist.
- **Cross-cutting — conformance vectors.** Shared JSON vectors bind the four
  client languages to one observable behaviour where proofs stop.

The pure kernel is `resolve` + precedence + the gate acceptance checklist +
the P2 trusted-state transition — **no serde, no IO, no crypto impl, no UI**.
Crypto enters the kernel as *abstract injective/one-way contracts* (P1's job
to satisfy). Keeping that boundary is what lets Aeneas run.

Toolchain setup (Lean/elan, Charon nightly, opam/OCaml for Aeneas, per OS):
[`../TOOLCHAIN.md`](../TOOLCHAIN.md).

## 6. The five laws (memorize these)

From P0 §4. Each has a proof obligation.

- **L1 — Resolution is a meet.** Verdicts are ordered `deny ⊏ attest ⊏ ask
  ⊏ approve`; `resolve` is the meet of matching verdicts, **with the no-match
  case defined explicitly as `ask`** (empty meet = ⊤ = approve would fail
  *open* — this is a subtle bug we fixed). Order-independent. (PO-1)
- **L2 — Tamper-boundedness.** A sub-quorum actor can neither *widen*
  authority nor *shrink* the load-bearing identity structure. Revoking an
  identity requires quorum ("reset mesh" must not be a DoS). Rollback
  resistance needs an *external* anchor, not the chain alone. (PO-2/2a/2b/2c)
- **L3 — Fail-closed totality.** `resolve` is total; headless degrades
  `ask/attest ↦ deny`. Nothing reaches "undefined permission." (PO-3)
- **L4 — Attenuation.** `effective = granted ⊓ required`; authority composes
  by meet, never amplifies; `escalate` carries ⊥ authority. (PO-4)
- **L5 — The ceremony gate.** `association ⇒ pinned`; `fingerprint =
  H(pubkey)` is self-certifying, so re-key ⇒ re-ceremony; pinned is
  transitive through certification (delegation). (PO-5)

## 7. Glossary (speak the same language)

- **Fingerprint** — `H(pubkey)` as a multihash; a self-describing *name* for
  a key. The key is the identity; the fingerprint is its name.
- **Verdict** vs **matrix verb** — `deny/attest/ask/approve` are *verdicts*
  (resolution's codomain); `allow/attest/deny` are *matrix verbs* (what a
  surface offers). `allow` = `approve` seen from the offer side. `ask` is a
  verdict, never an offer. `escalate` is a navigation action (⊥ authority),
  never a verdict.
- **attest** — the presence-required disposition (a fresh WebAuthn/passkey
  ceremony). Renamed from `passkey` (that word now names only the hardware
  mechanism; rename tracked in #231). Term follows the attestation
  literature (Parno et al.).
- **chain-store** — the append-only-verifiable record log; a Merkle DAG. The
  *authority projection* of the wider Conversation Graph (agent-mesh#67).
- **causal transcript / authority spine** — the store is a DAG for
  conversation but a **linear spine per causal thread** `(store_id,
  thread_id, sequence)` for authority. Conversation is a jungle; authority
  is a railway.
- **checkpoint / anchor** — the highest `AuthorityCheckpoint` a participant
  has accepted, kept *outside* the store it validates (device keystore /
  TPM / witness quorum). Rollback resistance lives here.
- **Sealed<T>** — a wire object constructed only through verification;
  immutable after. The Rust heir of the `Memo` discipline.
- **Gate** — the enforcement choke-point; mints authority only after its
  acceptance checklist passes. Never trusts the surface.
- **Caveats** — attenuable authority; a meet-semilattice (`meet_never_
  amplifies` is property-tested upstream in agent-mesh-protocol).

## 8. How we got here — the review discipline

This spec is the product of **heterogeneous adversarial review**: successive
passes by different model families (Claude, GPT-5/Codex, others), each trying
to break it. That is not incidental — it is the method. A cross-model
adversary finds what four same-model rounds miss.

- Findings are triaged into an **obligations ledger** (`README.md` → "Spec
  obligations"), tagged blocker/high/medium, each mapped to the owning
  profile.
- We fix by **naming and binding a mechanism**, not by adding a law.
- We record the *residual* honestly when a fix is partial.
- Every review round to date has *strengthened* the design and held the law
  count at five. The last full pass moved the criticism from "the
  architecture is confused" to "four interfaces need exact state-machine
  definitions" — which is victory, not defeat.

When you find a gap: add it to the obligations ledger with a resolution
direction before (or instead of) arguing it in prose.

## 9. Current state & what is HELD

- **PR #229** carries the whole suite on branch `docs/spec-ceremony-contract`.
- **PR #232** (GPT-5/Codex) is the stacked *formal kernel* design — adopted
  as the P0+P1+P2 provable MVP.
- **Status: design draft, actively reviewed.** Spec **revisions are open**;
  **merge and implementation are HELD** pending the author's sign-off. Do
  not merge to `main`; do not start the Lean/Rust/Aeneas implementation
  until told. (When in doubt, the hold is: *revise freely, land nothing.*)
- **Open author's-calls** (do not decide these yourself): (a) the OB-2
  *linear authority spine vs. frontier checkpoint* model — currently adopted
  as linear, pending veto; (b) the **`attest` factorization** — one verb
  axis vs. `effect × assurance × scope` (GPT-5 #232 leans product-lattice;
  L1 survives either).

## 10. How to contribute (the workflow)

Follow `AGENTS.md` and `../DESIGN.md` at the repo root; the essentials:

- **Branch → change → `just check` green → push → PR.** Never push to
  `main`. `just check` = fmt + clippy `-D warnings` (both feature configs) +
  tests. `just install-hooks` after clone; **never `--no-verify`** in this
  repo.
- **Concurrency hazard:** more than one agent writes the spec branch. Always
  `git fetch` first; work in a throwaway **worktree**; if a push is rejected,
  `git rebase` onto the moved branch (verify tree parity if the history was
  rewritten). Remove your worktree when done (disk discipline).
- **Commit hygiene:** author `hartsock@users.noreply.github.com`; trailer
  `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`.
  **Never** put a Claude session URL / `Claude-Session:` trailer in a commit
  or PR body — banned, enforced by hook where present.
- **Spec edits** cross-reference the owning profile and cite the obligation
  (`OB-n`) or law they serve. Keep the five-law waist sacred: a new law needs
  a proof obligation and an author decision.
- **When implementation opens** (not yet): build order `P1 → P2 → P0`; carve
  the pure kernel first; wire Charon→Aeneas→Lean; keep crypto behind abstract
  contracts.

## 11. Map — where everything lives

- **This suite:** `docs/spec/` (you are here). Index: `README.md`. Manifest:
  `suite.toml`. Toolchain: `../TOOLCHAIN.md`.
- **Reference implementation:** `agent-bridle` crates (`agent-bridle-core`
  owns the policy/verdict/gate; `step_up::DischargeVerifier` is the shipped
  presence seam; #226/#227 shipped signed loosening entries).
- **Mesh side:** `agent-mesh` — `Introduction`/decision surfaces (#65),
  enrollment + multihash `Fingerprint` (#66), the **Conversation Graph**
  (#67); `CertChain::verify` + proof-of-possession (#39/#40);
  `docs/decisions/floating_identity.md` (the doctrine).
- **First consumer:** newt-agent#1209 (the pinning ceremony, HIGH).
- **Umbrella / strategy:** agent-bridle#225 (the no-TUI directive, client-lib
  matrix, the contribution framing). Rename: #231 (`passkey`→`attest`).
- **Prior art (cite, don't reargue):** Saltzer RFC 1498; HIP RFC 7401/9063;
  NIST SP 800-207; SPIFFE; iroh; RFC 6962 (CT); TUF; Schneier-Kelsey; FssAgg
  (eprint 2008/185); Landrock-Pedersen 1998 (WYSIWYS); RFC 8785 (JCS).

---

*The rule underneath all of it: no authorization floats free of the history
and artifacts that gave it meaning. Everything else is how we make that
true and prove it.*
