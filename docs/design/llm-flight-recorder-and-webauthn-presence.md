# Design plan — the LLM flight recorder, WebAuthn human-presence capabilities, and remote discharge over agent-mesh

- Status: **Proposed** (design-only; plan of record for review — no implementation)
- Date: 2026-07-08
- Scope: `agent-bridle` (+ new crates), with wiring notes for `newt-agent`,
  `gilamonster-agent`, `hermes-thoon`, and the delivery fabric `agent-mesh`.
- Governed by ADR 0002 (OCAP design contract & hard invariants), ADR 0004
  (per-axis honesty), ADR 0007 (step-up consumability contract), ADR 0008
  (external-consumer / core-leanness), ADR 0016 (macOS egress proxy + audit
  seam), ADR 0017 (authority ≠ mechanism; enforcement ≠ disclosure), ADR 0018
  (first-class unbridle). Realizes the two invariants ADR 0002 still marks
  **Planned**: **I13** (policy amplification requires the human root, surfaced as
  an attest/WebAuthn gesture) and **I14** (irreversible effects need an off-box,
  effect-side verifier that recomputes the challenge).
- This document was adversarially reviewed against the code before publication;
  the "what exists vs. what is a prerequisite" split below is deliberately honest
  (the "never overclaim" rule, I9). Where the draft over-promised — a "real
  WebAuthn verifier," an "async provider," a self-verifying discharge — the review
  is folded in as a stated **prerequisite**, not hidden.

---

## 0. What the operator actually needs to see (the telescope)

Two instruments, one leash.

1. **A flight recorder for the model's own network life.** As an agent works,
   the operator wants an `iptraf`-style, live-and-historical view of *every LLM
   call the agent makes* — which endpoint (`api.anthropic.com`, `localhost:11434`,
   a vLLM node), how many bytes, how long, how many tokens, and — when the
   operator opts in — the prompt and completion themselves. This is the black
   box: what did my agent say to which model, and when. The tool is a recorder;
   the thing being observed is *the operator's own agent's behavior*, which they
   have every right to see and keep.

2. **A physical-presence gate on consequential authority.** Some actions should
   happen **only** while a human is verifiably at the keyboard — proven by a
   touch on a YubiKey, a platform fingerprint reader, or a passkey. And because
   the human is not always at *this* keyboard, the same proof must be collectable
   on a **phone or a web page** and carried back to the box doing the work, over
   the user's own agent-mesh. The tool is WebAuthn + a mesh; the thing being
   observed is *"is my human really here, right now, for this exact act?"*

Everything below serves those two sightings. The design reuses what agent-bridle
already is — the single-mint OCAP gate — rather than bolting on a parallel
authority channel. The recorder is observability that never changes an enforcement
decision (the ADR 0016 D5 rule; one scoped exception in §7.4); the presence gate
is a **third leash outcome** that adds no authority (the ADR 0007 D1 rule).

---

## 1. The five goals, and the one architecture that satisfies them

| # | Goal (operator's words) | This plan |
|---|---|---|
| 1 | *Capture + report ALL historical LLM traffic, like iptraf.* | A **two-tier capture model** (flow tier + body tier) writing to an append-only, tamper-evident **flight-recorder store** built on `agent-store`'s WriterLog. |
| 2 | *Gate some actions on a verified YubiKey/fingerprint being present.* | Ship real **`DischargeProvider`s** (CTAP-HID / platform authenticator) against the already-merged `step_up` gate, **plus the missing trust anchor** — credential enrollment + an ES256 verifier + facade feature plumbing (§7, §12 prerequisites). |
| 3 | *Provide these raw capabilities to newt / gilamonster / hermes.* | A **capability surface** exposed as operator-plane tools + in-proc Rust APIs; per-host adapters. |
| 4 | *Explore captured traffic in a TUI/GUI while the LLM works.* | A `Doorbell`-fed **live tail**: `bridle-netmon` extended for the standalone view; a `flow_lines` render-data seam in newt-core; a traffic-explorer sub-view on FleetView's per-agent Detail drill-in. |
| 5 | *A fingerprint/passkey from a phone or web app discharges presence remotely.* | A **`MeshDischargeProvider`** + a discharge wire schema over a reserved agent-mesh topic + phone enrollment via `delegate_external` PoP + a small **browser↔mesh gateway**. The gate re-verifies against an **enrolled** credential — the transport is never trusted for authority (though it *is* trusted for display; §8.3/§8.5). |

**One-paragraph thesis.** agent-bridle already owns the single choke point every
tool passes through (`Registry::dispatch` → `Gate::authorize`) and already owns
most of the step-up cryptographic surface (`step_up.rs`: `Presence`, WYSIWYS
`Challenge`, `Discharge`, `Attestation`, the `DischargeVerifier` trait with an
`Ed25519Verifier` and a `WebAuthnVerifier` — both behind off-by-default cargo
features and not yet reachable in any shipped binary — plus the causal-freshness
window; the single-use replay ledger lives on the `Gate` itself, `gate.rs`, not in
`step_up.rs`). What it is missing is (a) **eyes on LLM traffic** (it sees tool
traffic only), (b) a **ceremony** that actually talks to a hardware authenticator
*and a credential-enrollment anchor + an ES256 verifier so the gesture can't be
self-attested in software*, (c) a **transport** that can carry a gesture from a
phone, and (d) a **store + UI** for the recorded flows. This plan adds exactly
those pieces, each in a crate *outside* the lean core, and changes **no** existing
invariant — with one honest exception (§8.1) where goal 5's async transport forces
a decision about the currently-synchronous provider trait.

---

## 2. Ground truth — what exists today (honest inventory)

Recon (2026-07-08, read-only) across the six repos, then adversarially verified.
File paths are load-bearing; verify before editing since some are on dirty branches.

### 2.1 agent-bridle (workspace v0.7.1, main `f19ec0a`)

- **The gate is the single mint site.** `Gate::authorize` computes
  `effective = granted.meet(&tool.required())` and mints the unforgeable
  `ToolContext` (`agent-bridle-core/src/gate.rs`; `ToolContext::mint` is
  `pub(crate)`, `#![forbid(unsafe_code)]`, `compile_fail`-tested — I1/I2).
- **Step-up is substantially BUILT and merged, with three gaps.**
  `agent-bridle-core/src/step_up.rs` ships `Presence {None < Prompt < Passkey}`
  (total order load-bearing), content-addressed `Challenge::bind(action_id,
  generation, nonce)` (WYSIWYS, BLAKE3), `CallRequest`, `AttestRequirement
  {presence, record, freshness_generations}`, `Discharge` (carries WebAuthn
  `authenticator_data`/`client_data_json` fields), `Attestation`, the pure
  `DischargeVerifier` trait, the **synchronous** `DischargeProvider` trait
  (`fn obtain(...) -> Result<Discharge, String>`, `step_up.rs` — trait only, the
  sole impls are test `Mock`/`Failing`), `Decision {Allow, Deny, NeedsDischarge}`
  (`NeedsDischarge(AttestRequirement)` — **carries no challenge**), and
  `StepUpPolicy`. `Gate::evaluate` / `authorize_with_discharge` /
  `authorize_step_up` implement single-use, replay-proof, fail-closed admission
  (the replay ledger is `Gate.consumed: Mutex<HashSet<[u8;32]>>`, consumed *before*
  charging/minting). PR #24 merged; #61/#62/#63/#72 merged; ratified by **ADR 0007**;
  `StepUpPolicy` threaded into `Registry::dispatch` by #179.
  **The three gaps that block goal 2:**
  1. **No enrolled-credential anchor.** Both `Ed25519Verifier` and `WebAuthnVerifier`
     read the verifying key *out of the `Discharge` itself* (`discharge.credential_id`,
     `step_up.rs`), with no allowlist of the operator's enrolled credentials.
     Verification therefore proves only that *whoever saw the challenge* signed it
     with *some* key — anyone can mint a keypair, sign, and self-attest
     `Presence::Passkey` in software. Credential registration is explicitly out of
     scope of the verifier. Closing this is the central security prerequisite (§7.2).
  2. **`WebAuthnVerifier` is EdDSA-only (COSE alg `-8`).** `credential_id` must be a
     raw 32-byte Ed25519 key; the signature must be 64-byte EdDSA over
     `authenticatorData ‖ SHA-256(clientDataJSON)`, checked with
     `ed25519_dalek::verify_strict`; `Cargo.toml` pulls only `ed25519-dalek` + `sha2`.
     It **cannot** verify the ES256 (P-256 ECDSA) assertions that platform
     authenticators (Touch ID, Windows Hello) and synced passkeys mint — an ES256
     verifier is new work (§12 P-e). YubiKeys *can* be enrolled Ed25519 (COSE `-8`),
     so `CtapHidProvider` alone can run against today's verifier.
  3. **The verifiers are off-by-default features not exposed through the facade.**
     `verifier-ed25519`/`verifier-webauthn` are non-default; no crate in the
     facade→`agent-bridle-mcp` graph enables either, so both verifiers are compiled
     out of every shipped binary. Feature passthrough is needed (§7.3).
  Also: `agent-bridle-mcp` builds a plain `registry()` with **no** `.step_up(...)`,
  so there is no `NeedsDischarge` path over MCP; `Registry::dispatch` builds
  `CallRequest::unspecified(name)` (resource `""`) so resource-glob selectors never
  match (a resource-axis fail-open — §7.3); attestations are **discarded**
  (`registry.rs`: `let (cx, _attestation) = ...`).
- **Observation surface today is tool-only and thin.** (1) structured
  `Denial{kind, target, reason}` on the `ToolEnvelope`; (2) the **net egress audit**
  — `net_proxy.rs` emits `NetAuditEvent {ts_ms, host, port, kind, decision,
  bytes_up, bytes_down, dur_ms}` (no request-count, no `http_status`) through a
  pluggable `AuditSink` (`NullSink`/`JsonlSink`), gated by `BRIDLE_NET_AUDIT`, and
  fired **once per connection at close**; **`bridle-netmon`** is a std-only,
  iptraf-style live per-host table over that JSONL — *the direct precedent for
  goal 1's UI*; (3) `Attestation`s (discarded). No `tracing`/log crate usage, no
  per-dispatch event log.
- **agent-bridle sees TOOL traffic only — never LLM inference traffic.** No LLM
  client abstraction. The only routable seam is the per-shell-invocation loopback
  egress proxy (`net_proxy::start`) — torn down when the confined child is reaped
  (no daemon mode). For HTTPS `CONNECT` it is body-blind; for plaintext `http://`
  forwards it *can* read headers/bodies (relevant to local Ollama, §4.1). Its SSRF
  guard refuses any RFC1918/CGNAT/ULA origin, so a LAN LLM node (a dgx at
  `192.168.x`) is currently *unreachable* through it (§12 P-f).
- **agent-mesh is a types-only dependency** (`agent-mesh-protocol = "0.6"` for
  `Caveats` + `Fingerprint`). No mesh transport in agent-bridle. `integrations/pi-bridle/`
  (untracked) shows the host-wiring pattern: route a host's bash tool through
  `agent-bridle-mcp` over stdio JSON-RPC.
- Docs: `docs/DESIGN.md`, `docs/PRIVACY.md`, ADR 0001–0019. `docs/design/` is new
  with this file.

### 2.2 agent-mesh (target: **origin/main 0.6.2**, not the stale checkout)

A broker-free, **store-free**, LAN-first fabric. Crates: protocol / bus / discovery
/ transport / cli / py, published to crates.io (`v0.6.2`) + PyPI (`newt-agent-mesh`).
The pieces goal 5 needs are already on main:

- **Identity:** per-user ed25519 `UserKey` (PKCS#8, 0600 atomic), GitHub SSH
  cross-signing, ephemeral per-process `AgentKey` certified into a `CertChain`
  carrying a **property-tested `Caveats` meet-semilattice** (attenuation-only).
- **Phone enrollment already exists (§9.2, #40):** `AgentKey::possession_challenge()`
  + `delegate_external(challenge, proof, metadata)` certifies an externally-held
  pubkey (the phone) into a `CertChain` only against a signed proof-of-possession
  over a fresh nonce, attenuation-checked. Tests named
  `delegate_external_certifies_phone_and_roots_at_user`. **This enrolls the phone's
  *mesh AgentKey* — it does not enroll a *WebAuthn credential* (§8.2).**
- **Keystore signing seam (main):** `MeshSigner` — a platform keystore signs
  without exporting the seed.
- **Causal revocation (§9.1, #39):** `CertChain::verify_at(current_generation)`
  fails closed. No wall-clock (`expires_at` is a signed claim, never checked).
- **Bus:** user-scoped topics, `request(peer, topic, body, timeout)` with a
  `CorrelationId` + oneshot, **dial-back replies on the request's authenticated
  source address**. Crucially, `Bus::request` resolves the responder over **mDNS**
  and fails `Unreachable` for a never-announcing peer; the endpoint binds
  relay-free (`presets::N0DisableRelay`). So the *reply* leg needs no mDNS, but the
  *request* leg requires the responder to announce or be dialed via `request_direct`/
  `publish_to_direct` (#36, by `(pubkey, addr)`). `NonceCache` + per-peer monotonic
  `SequenceTracker` replay defense, 16 MiB envelope cap. **No persistence.**
- **Gaps for goal 5:** (a) **no browser-reachable gateway** — browsers cannot speak
  iroh QUIC with the pinned `agent-mesh/v1` ALPN; a WS/HTTP↔mesh bridge must be built
  (a native phone app speaks mesh directly via `MeshSigner`, but only LAN/VPN-reachable
  — §8.1). (b) No presence/discharge **payload schema** (envelope payloads are opaque
  bytes). (c) No WebAuthn verifier on the mesh side (agent-bridle has one, but it needs
  the §2.1 gaps closed). (d) `verify_at` is **not** wired into the transport handshake
  (`handshake.rs`/`stream.rs` still call context-free `verify()`), so a
  generation-scoped cert cannot complete a handshake yet (§12 P-d).

### 2.3 newt-agent (v0.7.1)

- **LLM traffic originates in TWO primary layers plus side channels.**
  (a) `InferenceBackend` trait (`newt-inference/src/backend.rs:86`;
  `LocalOllamaBackend`, `LocalVllmBackend`, `ProviderPluginBackend` subprocess
  JSON-RPC for cloud, `EmbeddedBackend` candle) serves the **headless** paths —
  wrappable with a recording decorator around `Arc<dyn InferenceBackend>`.
  (b) The **interactive** TUI loop `chat_complete` (`newt-core/src/agentic/mod.rs:1025`)
  bypasses the trait: it is a dispatcher over **three** independent reqwest loops —
  Ollama `/api/chat`, `openai_chat_complete` → `/v1/chat/completions`, and
  `openai_responses_complete` → `/v1/responses` — the final round **streaming**
  (`stream:true`). A tap must cover all three, or the loop must be refactored onto
  the trait. `ProviderPluginBackend` only sees the JSON-RPC boundary — the plugin's
  cloud HTTP is out of process. (c) **Side channels that bypass both seams:** the
  context-compression **summarizer** (`make_loop_summarizer`, invoked from *inside*
  `chat_complete`; live HTTP unless `kind = embedded`), the **embeddings client**
  (`semantic.rs`, always HTTP — the embedded backend can't serve embeddings), and
  **warm-up** (`warmup.rs`, `/api/generate` + `/api/ps`). Body-tier taps at the two
  primary layers alone do **not** cover "every LLM call" (I9) — a complete claim
  must enumerate the side channels.
- **History today is privacy-by-design and does NOT store raw bodies.**
  `ConversationStore` (`newt-core/src/store.rs`, `~/.newt/conversations.db`):
  per-writer Lamport ticks, BLAKE3 `prev_hash` turn chain, FTS5 — but keeps only
  final user/assistant text + digested `ToolEvent`s (`args_digest` = key names +
  `b3:` hash, **never raw args**, `conversation.rs`). `~/.newt/usage.jsonl` keeps
  `TurnMetrics`. So "iptraf for LLM" is a **new** flow store, and its body tier must
  reconcile with this deliberate never-store-raw posture (§5, §11).
- **TUI is a plain scroller by binding decision** (`docs/decisions/plain_scroller_tui.md`)
  — panes belong downstream. The render-data seam is `transcript_lines`
  (renderer-agnostic) and the sibling `ShellObservation` with `redact_secrets`
  (which is `pub(crate)` in `compress.rs` — §11.1). A `flow_lines` analogue follows.
- **agent-bridle 0.7 is wired** for `shell` + `web_fetch` under `[tui.permissions]`
  Caveats, `--disable-ocap`/`--yolo` an env-only escape hatch. The step-up
  primitives are **already imported** (`crew_attest.rs`) and gate crew/team dispatch
  **at `Presence::Prompt`**; a Passkey-required op surfaces `NeedsAttest` and stops,
  "awaiting BOOT's verifier (#472)".
- **Plan of record:** `docs/design/human-presence-capabilities.md` — **a MERGED
  docs PR (#472)**, not an open work item. Its §9 lists **five** blocking red-team
  fixes: (1) revocation no-op, (2) no PoP, (3) fail-open unsigned `$AGENT_BRIDLE_CAVEATS`
  grant, (4) `permits_key`/push-gate dead code, (5) online-root SPOF. Status: (1)+(2)
  **fixed on agent-mesh main** (#39/#40); (3)'s **fail-open half is fixed** — the
  bridle grant now fails **closed** to DENY-ALL (agent-bridle #25, `caveats_source.rs`),
  and `Caveats` has no serde defaults so a partial grant is a parse error; its
  **signed half remains** (the env grant is still unauthenticated — §12 P-c). (4)+(5)
  outstanding. `PresenceCaveats` in newt-core: **NOT FOUND** (design-only). No
  WebAuthn/CTAP crate in `Cargo.lock`.
- `newt doctor` (`newt-cli/src/doctor.rs`) is a monolithic section-printing
  `run()` — a "presence doctor" / "traffic doctor" section follows the shell-engine
  precedent.

### 2.4 gilamonster-agent (branch `fleetview/phase-2-navigation`)

- One crate, one binary (`gila`), the **rich-TUI home** (ratatui + crossterm),
  inheriting newt-agent as its airframe via git deps; `agent-bridle-core` used today
  **only** for Landlock-confined capability spawns (`capabilities.rs`). No agent-mesh
  dependency. All LLM calls go through newt's `TurnDriver` — no gila-side HTTP seam.
- **FleetView** (`gila matrix`) is a full-screen crew-monitor dashboard with a
  `Focus {Rail, Panel, Detail}` state machine; the **per-agent Detail drill-in**
  (`fleet.rs`, `detail_lines`) renders one agent's `Vec<MemMessage>` via
  `cowork::transcript_to_lines` — **the natural mount for a per-agent LLM-traffic
  explorer**. Data is 100% mock today (`FleetModel::mock`), and FleetView has **no
  live-ingestion seam yet**: `fleet.rs` never touches the `ObservationSource`/
  `ObservationChannel` seam in `follow.rs`, which is a *different* pipeline (shell
  observations → the model's context window, not a UI feed). Wiring live traffic into
  the Detail pane is FleetView's **first real data path** — new work (P2), a
  recorder-store → `FleetModel` feed. `AgentState::Blocked` already reserves a UI
  state: "Held by an OCAP attest gate (`crew_authz` needs a `Presence`)" — the gate
  is not built.

### 2.5 hermes-thoon (Gilamonster-Foundation speed fork of NousResearch/hermes-agent)

The richest integration surface, all-greenfield w.r.t. bridle/mesh/webauthn.

- **MCP is pure config:** `hermes mcp add bridle --command agent-bridle-mcp` wires
  confined tools with **zero code change**.
- **First-class plugin hooks around every LLM call:** `invoke_hook("pre_api_request", …)`
  / `("post_api_request", …)` (`run_agent.py`) pass full request messages + response —
  the bundled **langfuse** plugin is a working body-tier precedent. `pre_tool_call`
  hooks can return `{"action":"block"}` to **veto** a tool (`plugins.py`,
  `get_pre_tool_call_block_message`). Note the hook is **deny-only** and
  **synchronous**: there is no `NeedsDischarge → ceremony → retry` round-trip at this
  seam; a plugin could block inline while a ceremony runs, but the clean design is to
  let the bridle MCP tools own the ceremony (§6).
- **Provider config supports custom `base_url` and env proxies** (`HTTPS_PROXY`/
  `HTTP_PROXY`/`ALL_PROXY`, `NO_PROXY` bypass — honored in `_get_proxy_for_base_url`).
  A flow-tier recording proxy slots in; hermes ships a minimal OpenAI-compatible
  forward proxy (`hermes_cli/proxy/`) whose logging sibling the recorder would be.
- Existing stores to *coexist with*: `~/.hermes/state.db`, trajectory JSONL,
  `HERMES_DUMP_REQUESTS` dumps, `insights.py`.

### 2.6 agent-store (v0.1.2) — the store substrate

- **One crate, deliberately tiny.** `Backend` + `SqliteBackend` (bundled rusqlite,
  WAL); **`WriterLog`** — per-`(stream, writer)`, BLAKE3-chained, tamper-evident
  append log; **`Generation`**; **`Doorbell`** — in-process fan-out of
  `CommitEvent {stream, writer, seq, content_hash}` (a live-tail seam, **not
  auto-rung by `append`** — the consumer rings it); `StorePolicy`; `Fingerprint`
  (mesh-wire-compatible). `from_connection`/`connection()` let a consumer keep
  domain/index tables in the same DB.
- **Fits the flight recorder well:** per-writer causal order → per-agent/per-session
  streams; the BLAKE3 chain gives provenance/tamper-evidence; the Doorbell is a
  ready-made live-tail.
- **Missing for a recorder (this plan adds, upstream to agent-store):** no timestamps
  (design law — display-claim columns live in the consumer's domain table); no
  range/tail/`since-seq` query (only `head()` + full-scan `entries()`); no
  retention/compaction (naive pruning breaks `verify()`, which walks from seq 1 —
  needs verify-from-anchor / epoch rotation); no redaction (payloads opaque); **no
  cross-host ingest** (`append` computes seq/hash from the *local* head — a
  remotely-produced entry needs a new `ingest(Entry)` that validates linkage); and
  `append` is read-head-then-insert (per-`(stream, writer)` appends must be
  serialized).

---

## 3. Architecture

Two instruments, one leash. New pieces all live outside the lean core.

```
                                 ┌──────────────────────────────────────────────┐
   host agent (newt / gila /     │            agent-bridle                       │
   hermes) doing LLM work        │   Registry::dispatch ── Gate::authorize       │
        │                        │   (single mint site; effective=granted∧req)   │
        │ tool calls ────────────┼─▶       │            │                        │
        │                        │         │            └─▶ step_up: evaluate /   │
        │                        │         │                authorize_with_       │
        │ LLM calls (2 tiers)    │         ▼                discharge (BUILT;     │
        ├── FLOW (HTTPS_PROXY to  │   ┌────────────┐        needs enrolled-cred   │
        │   persistent recording │   │  RECORDER  │        anchor + ES256 — §7)   │
        │   proxy; endpoint/      │──▶│  tap →     │             ▲                │
        │   bytes/timing;         │   │ FlowRecord │             │ Discharge      │
        │   body-blind for HTTPS) │   │     │      │      ┌──────┴────────────┐   │
        │                         │   │     ▼      │      │ DischargeProvider  │   │
        ├── BODY (in-proc host    │──▶│ flight-    │      │ (SYNC ceremony)    │   │
        │   tap → FlowRecord w/   │   │ recorder   │      │ · CtapHid (YubiKey,│   │
        │   redacted prompts,     │   │ store      │      │   Ed25519)         │   │
        │   tokens; blob side-tbl)│   │(agent-store│      │ · Platform (entitled   │
        │                         │   │ WriterLog +│      │   helper; ES256 — P-e) │
        │                         │   │ blob CAS + │      │ · Mesh (remote;    │───┼─┐
        │                         │   │ redaction+ │      │   sync/async — §8.1)   │ │
        │                         │   │ retention) │      └────────────────────┘   │ │
        │                         │   │     │      │      verified vs ENROLLED      │ │
        │                         │   │ Doorbell───┼──▶ live tail (operator-plane): │ │
        │                         │   └────────────┘   · bridle-netmon (iptraf)     │ │
        │                         │                    · flow_lines (newt-core)      │ │
        │                         │                    · FleetView Detail (gila)     │ │
        └─────────────────────────┴───────────────────────────────────────────────┘ │
                                                                                      │
  phone / web ─ WebAuthn UV over ─▶ browser↔mesh gateway ─▶ agent-mesh bus ──────────┘
  ENROLLED credential (§8.2)        (untrusted for authority   presence/discharge topic;
                                     AND display — §8.3/8.5)    PoP-enrolled AgentKey
```

Three sub-architectures: **§4 Capture**, **§7 Presence**, **§8 Mesh discharge**.

---

## 4. Capture: the two-tier flight recorder

The honesty constraint (ADR 0004/0016 D2) forces two tiers, because their fidelity
is genuinely different. **Overclaiming body fidelity from a flow-blind capture is
exactly the "never overclaim" release blocker (I9).**

### 4.1 Tier A — flow (wire-level, iptraf fidelity, host-agnostic)

**What it is.** Generalize the existing per-invocation `net_proxy` (ADR 0016) into a
**persistent recording egress proxy** (`bridle-llmproxy`). A host points its LLM
client at it via `HTTPS_PROXY`/`base_url`. Per connection it emits an `LlmFlowRecord`
(§5) at **flow granularity**: resolved endpoint host/port, `bytes_up`/`bytes_down`,
`dur_ms`, and the SSRF/allow-list decision — re-shaping the fields `NetAuditEvent`
already produces (note: there is **no** request-count and **no** `http_status` today;
a CONNECT tunnel multiplexes many requests invisibly, so per-request counting is not
available from the wire — those fields are Body-tier or must be added on the plaintext
path only).

**Fidelity, stated honestly.** For HTTPS `CONNECT` this is **body-blind** — no TLS
termination exists and we will not MITM the operator's provider TLS. For plaintext
`http://` forwards (local Ollama `http://127.0.0.1:11434`, a typical vLLM node) the
proxy *can* read bodies — there body-blindness is a **design rule, not a physical
property**: the flow proxy parses plaintext HTTP only enough to route and count
bytes, and **discards bodies by design**; plaintext visibility never upgrades a
record past `fidelity = Flow`. Tier A answers "*which endpoints, how much, how often,
how long*" — the iptraf sighting — never "*what did it say.*"

**Granularity, stated honestly.** Flow records land **per connection, at close** —
`net_proxy` fires its audit only after the copy threads join. A long-lived streaming
HTTPS connection (an SSE completion, or a keep-alive connection reused across many
requests) produces **nothing** until it closes, so a flow-tier "live tail" shows
connection *open/close* events, not per-token progress. True token-by-token "while it
works" (goal 4) comes only from the Body tap (§4.2).

**Why it's the right default — and its coverage limit.** It needs **no host
cooperation** beyond a proxy env var and is uniform across every provider a client
routes through it. But proxy-env routing is **convention, not enforcement**: clients
commonly bypass proxies for loopback (`NO_PROXY`), so a local Ollama at `127.0.0.1`
may never traverse the proxy at all. It is the honest floor, not a guarantee of total
capture.

### 4.1.1 The persistent proxy's trust model (what generalizing ADR 0016 gives up)

ADR 0016 D3 deliberately ruled out a persistent listener: today the proxy binds an
OS-picked ephemeral loopback port known only to one fenced child, its allow-list comes
from that invocation's Caveats, and it dies when the child is reaped. `bridle-llmproxy`
trades that bracketing for always-on capture, so it must state its own trust model
(this needs its own ADR):

- **Loopback-only bind, authenticated + attributed clients.** The daemon binds
  `127.0.0.1` only. Because the per-invocation proxy was one-proxy-one-principal (so
  `NetAuditEvent` needs no identity fields), a shared daemon breaks attribution: a bare
  CONNECT carries no `session_id` and no writer `Fingerprint`. The design keeps
  one-listener-one-principal by **per-session ephemeral listeners**: a host registers a
  session with the recorder API — supplying `(session_id, writer_fingerprint)` — and the
  daemon binds a fresh loopback port for it, handing back the `HTTPS_PROXY` URL; every
  connection on that port is attributed to that principal; the port dies when the
  session closes. Connections on no session port are **refused**, never silently mixed.
- **The kernel fence stays honest.** A net-denied confined child must not be able to
  tunnel out via the daemon's stable port — the daemon must not become an ambient local
  egress relay for confined children (keep the per-invocation, caveat-scoped proxy for
  confined-child mode; the recorder daemon is a separate, opt-in, operator-owned service).

### 4.2 Tier B — body (semantic-level, prompts/tokens, opt-in, host-wired)

**What it is.** A **traffic-recorder capability** (`agent-bridle-recorder`, in-proc
Rust API + operator-plane MCP tool) that a host calls **from its own LLM client seam**
to emit a fully-populated `LlmFlowRecord`: model, provider, endpoint, request messages
(redacted — §11.1), token usage, latency, completion, tool calls. Stamped
`fidelity = Body`.

**Where each host taps it (goal 3):**

- **hermes-thoon** — a bundled plugin registering `post_api_request` (as langfuse
  does) → one `LlmFlowRecord` per call. Zero core-hermes change.
- **newt-agent** — a `RecordingBackend` decorator wrapping `Arc<dyn InferenceBackend>`
  (covers headless) **and** taps in the **three** `chat_complete` loop variants (Ollama
  `/api/chat`, `openai_chat_complete`, `openai_responses_complete`) accumulating the
  `stream:true` deltas, **plus** the three side channels (summarizer / embeddings /
  warm-up) if "every LLM call" is to hold. This is the one host needing code in several
  places; a follow-up may refactor the loop onto the trait.
- **gilamonster-agent** — inherits newt's capture (all its LLM calls are newt's
  `TurnDriver`); no gila-side tap needed.

**Streaming (goal 4's "while it works").** The body tap is the only place a live,
token-by-token view is possible — it emits an initial record on request and appends
deltas as the stream flows, ringing the Doorbell.

### 4.3 The flight-recorder store (`agent-bridle-recorder`, new crate)

Built **on `agent-store`**. Design:

- **Stream/writer keying:** `stream = "llm-traffic:<session_id>"`,
  `writer = <agent Fingerprint hex>`. Per-writer BLAKE3 chain gives provenance +
  tamper-evidence; multiple agents in one session hold independent chains, merged for
  display by the consumer (interleaving is a display claim, never a coordination
  primitive).
- **Payload split — the purge seam.** The chained payload carries only flow-tier fields
  + a BLAKE3 **CID**. **All Body-tier payloads** (request messages, completions — not
  just large ones) are content-addressed to a **deletable blob side-table**, never
  inlined into the chained bytes. This is load-bearing: redaction is best-effort (§11.1),
  and when it misses, the leaked secret is destroyed by **deleting the blob** — the chain
  still verifies (it covers the CID, not the blob). A missing blob renders `[purged]` and
  downgrades that record `Body → Flow`. Inline Body bytes in the chain would be a design
  violation because they are unpurgeable.
- **Domain index table** (via `from_connection`, same DB): the query columns the
  substrate refuses to own — a display-claim `captured_at_ms` (never an ordering key),
  `endpoint`, `model`, `provider`, `fidelity`, `direction`, `bytes`, `dur_ms`, `tokens`,
  indexed for range/tail.
- **New primitives contributed upstream to agent-store** (each a small PR there):
  `entries_since(stream, writer, seq)` + `LIMIT`/tail; stream/writer enumeration;
  per-`(stream, writer)` append serialization (the read-head-then-insert race);
  **`ingest(Entry)`** — insert a remotely-produced, already-chained entry after
  validating linkage (goal-5 / P6 cross-host merge); **verify-from-anchor** so retention
  can prune old prefixes without breaking `verify()`.
- **Retention:** epoch-rotation + verify-from-anchor; size/count caps; default
  local-only. A crude cap ships in P0 so the recorder is bounded from day one (§12).
- **Live tail:** subscribe to the `Doorbell` (the recorder rings it on append); on
  `CommitEvent` fetch the entry. In-process for a co-located TUI; over the mesh (a
  `CommitEvent` bridge) for a remote viewer.

Core-leanness (ADR 0008): the recorder depends on `agent-store` +
`agent-mesh-protocol` (Fingerprint) + serde. It is **not** in `agent-bridle-core`.

---

## 5. Data model — `LlmFlowRecord`

One record type, both tiers; a Body record is a strict superset of a Flow record.

```
LlmFlowRecord {
  session_id: String,               // groups a run
  writer: Fingerprint,              // which agent produced this (mesh-compatible)
  generation: u64,                  // causal tick
  captured_at_ms: u64,              // DISPLAY CLAIM — never an ordering key

  fidelity: Fidelity,               // Flow | Body  (honesty — never overclaim)
  direction: Direction,             // ConnOpen | ConnClose | Request | Response | Chunk
  provider: String,                 // "anthropic" | "openai" | "ollama" | ...
  endpoint: String,                 // host:port or URL authority
  model: Option<String>,

  bytes_up: u64, bytes_down: u64, dur_ms: u64,   // flow-tier facts

  // body-tier facts (present iff fidelity == Body); stored via blob CID (§4.3)
  request_messages: Option<RedactedMessages>,    // secrets scrubbed AND embedded
                                                 //   tool blocks digested (§11.1)
  completion: Option<RedactedText>,              // streamed as Chunk deltas
  tool_calls: Option<Vec<ToolCallRef>>,          // names + arg *digests*, not raw args
  usage: Option<TokenUsage>,                     // tokens, cost

  content_id: ContentId,            // BLAKE3 of the canonical record (chain link)
}
```

Design-law checks: **no raw secrets** (redaction is a construction-time invariant of
the redacted types); tool args in *both* channels are digested — `tool_calls` carries
names + arg digests, and `RedactedMessages` applies the same `b3:` digest to assistant
`tool_calls` args and `role:"tool"` bodies embedded in captured request messages, so
only user/assistant natural-language text is kept raw (mirroring `conversations.db`;
secret-scrubbing alone would *not* remove them). Ordering is `(writer, seq/generation)`;
`captured_at_ms` is a claim.

---

## 6. Capability surface (goal 3) — how hosts consume this

Three consumption modes, matching agent-bridle's "three frontends, one core":

1. **Operator-plane tools (NOT agent tools).** `traffic_query {session?, since_seq?,
   endpoint?, limit}` → `[LlmFlowRecord]` and `traffic_tail {session?, since_seq?}` →
   cursor-polling over `entries_since` (the live view; a stock MCP server has no server-
   push, so tail is client cursor-polling). **These are NOT registered in the facade
   `registry()` the agent dispatches through** — `agent-bridle-mcp` hands every registry
   tool to the model, and handing the model `traffic_query` would feed recorded history
   (including other sessions' Body-tier prompts) back into model context, to the provider,
   and to any prompt-injected instruction — defeating §11's black-box stance. They ship on
   a separate **operator-only** endpoint (the `bridle-netmon`/FleetView store readers and
   an operator MCP socket never added to an agent's `mcp_servers`). If ever made
   agent-callable they MUST be (a) hard-scoped to the calling session (identity, not a
   filter), (b) Flow-only, (c) Body access gated at `Presence::Passkey` — a new ADR first.
2. **The discharge round-trip (§7.3).** Topology matters: if the *server* holds the
   `DischargeProvider`, it runs the ceremony (CtapHid/Mesh) in-process and no client
   round-trip exists; if the *client* collects the gesture, a `NeedsDischarge → discharge`
   exchange is a **non-standard MCP extension** a stock client cannot answer. The plan is
   server-side ceremony (§7.3); the MCP extension is only for a bridle-aware client.
3. **In-proc Rust API** — newt and gila call the recorder + step-up APIs directly.
4. **Recording egress proxy** — Tier-A capture for any host that can set `HTTPS_PROXY`.

---

## 7. Presence: real ceremonies + the enrollment anchor (goal 2)

The gate, the policy, the replay ledger, and the freshness window are **already built
and merged**. Goal 2 is: (a) ship ceremonies that talk to hardware, (b) **close the
three §2.1 gaps** — an enrolled-credential anchor, an ES256 verifier, and facade feature
plumbing — without which the merged verifier can be self-attested in software, and
(c) wire the round-trip through the MCP frontend and resolve `CallRequest`.

### 7.1 `DischargeProvider` implementations (new, host-capability, IO, feature-gated)

The `DischargeProvider` trait is the host ceremony seam (never trusted to self-attest —
ADR 0007 D5). **It is synchronous** (`fn obtain(...) -> Result<Discharge, String>`),
called by the sync `Gate::authorize_step_up` from inside the async `Registry::dispatch`
— fine for local ceremonies that block on hardware, but consequential for the mesh
provider (§8.1). Ship three impls in a new `agent-bridle-presence` crate (decision Q3),
**never in core**:

- **`CtapHidProvider`** — drives a **YubiKey / FIDO2 key over USB-HID** (CTAP2
  `authenticatorGetAssertion`), asserting user-presence (touch) and, when required,
  user-verification (PIN/bio). Uses a Rust CTAP-HID crate (Q1). Enrolled **Ed25519**
  (COSE `-8`), it can run against today's verifier. `Presence::Passkey`.
- **`PlatformAuthenticatorProvider`** — Touch ID / Windows Hello / a fingerprint reader.
  **Caveat (known-hard, per the passkey-OCAP memo):** macOS Touch ID has *no clean CLI
  WebAuthn path* — `ASAuthorization` needs an **entitled, signed app context** (a plain
  CLI can't invoke it), and synced iCloud/Google passkeys are unreachable from
  CTAP2/libfido2. Windows Hello via `WebAuthn.dll` is more tractable. These authenticators
  mint **ES256**, so they also need the P-e verifier. This provider is **research-gated**,
  not a routine P3 deliverable.
- **`PromptProvider`** — a soft typed-yes / click, `Presence::Prompt` (the advisory
  no-authenticator fallback the *host* may choose per ADR 0007 D3 — the gate still denies
  it against a `Passkey` requirement).

**Verification is the invariant, but only once the two verifier gaps close.** The gate
re-derives the bound `Challenge` and verifies the assertion — but today both verifiers
read the key from `discharge.credential_id`, so verification currently proves possession
of *some* key by whoever saw the challenge. The gate must additionally check
`credential_id ∈` the operator's **enrolled credential set** (§7.2), and gain **ES256**
support (§12 P-e). Ceremonies are replaceable; **enrollment-anchored verification** is
the invariant.

### 7.2 Credential enrollment & pinning (the trust anchor — new)

A one-time **registration ceremony** (`navigator.credentials.create()` / CTAP2
`authenticatorMakeCredential`) captures each authenticator's `(rawId → COSE public key)`
and records it in a per-user **enrolled-credential registry** (a small signed local
store). Thereafter:

- The gate (or the provider, then re-checked by the gate) resolves an assertion's `rawId`
  against the registry to obtain the **registered** public key, and **rejects an unknown
  `rawId`**. This is the pin that turns "someone signed the challenge" into "the
  operator's enrolled authenticator signed the challenge."
- The registry is the shared anchor for both the local providers (§7.1) and the remote
  mesh path (§8.2). Enrolling is itself a `Presence::Passkey`-worthy act (bootstrapping
  the root of the presence chain) and should be an explicit operator ceremony, not
  implicit on first use.

### 7.3 MCP wiring + `CallRequest` resolution + feature plumbing

- **Feature plumbing (else nothing runs):** expose `verifier-ed25519`/`verifier-webauthn`
  through the facade `[features]` (a passthrough in `agent-bridle/Cargo.toml`) and enable
  one in `agent-bridle-mcp` — today neither is enabled anywhere in the shipped graph.
- Wire `RegistryBuilder::step_up(policy, provider, verifier)` in `agent-bridle-mcp`.
  **Topology note:** wiring `step_up` into `Registry::dispatch` runs the *whole* ceremony
  **in-process** (`evaluate → obtain → verify`), so `NeedsDischarge` never crosses the
  wire on that path — correct for a server-side ceremony (CtapHid/Mesh). A *client*-side
  gesture would instead need `evaluate`/`authorize_with_discharge` exposed as **separate**
  MCP calls (the non-standard extension of §6) — a distinct topology, chosen per client.
- Resolve `CallRequest {tool, args, resource}` in `Registry::dispatch` instead of
  `CallRequest::unspecified(name)`. **This is a security prerequisite, not a mechanical
  fix:** with `resource=""`, any `tool:resource-glob` rule (e.g.
  `git.push:github.com/org/prod-*`) never matches and silently falls through to the weaker
  default — a resource-axis fail-open for any host wiring resource-scoped step-up.

### 7.4 Persist the attestation (close the discard) — the one enforcement exception

Stop discarding the `Attestation` at `registry.rs`. Route it to the flight-recorder store
as a **Scar** — a content-addressed record that "this exact act was authorized by a human
gesture at generation N." **Failure semantics (fail-closed):** `AttestRequirement.record:
true` means a verified gesture *must* be durably recorded; once wired, a failed Scar write
for a `record: true` gate is a **denial** — the dispatch does not proceed un-recorded.
This is the **one** place where store availability gates enforcement (the durable record is
part of what the policy demanded). `record: false` step-ups and the flow/body recorder are
unaffected — their write failures never block a call.

### 7.5 Doctor sections

Add to `newt doctor` (and a bridle self-check) a **presence doctor** (is an authenticator
reachable? is one enrolled? which tier? ES256 or Ed25519?) and a **traffic doctor** (is the
store writable? is capture running? is it within retention caps?), each a new section
following the shell-engine precedent.

---

## 8. Remote presence over agent-mesh (goal 5)

The gesture is not always collectable at the box doing the work. The pieces line up onto
existing agent-mesh (0.6.2) primitives; the new work is a schema, a provider, a browser
gateway, one transport plumbing fix — and reuse of the §7.2 enrollment anchor.

### 8.1 The `MeshDischargeProvider` (the core of goal 5)

Because `DischargeProvider` is the ceremony seam, remote discharge is a provider
implementation. **The one thing the elegance hides:** the trait is *synchronous*
(`fn obtain`, `step_up.rs`) but is reached from the async `Registry::dispatch` on tokio,
while `MeshDischargeProvider` must `await Bus::request(...)`. Naive bridging inside a tokio
worker **deadlocks** (`futures::executor::block_on`) or **panics** (`Handle::block_on`).
This forces a decision (open question Q6 / the presence ADR): **(a)** make
`DischargeProvider::obtain` async — a **core-surface signature change** to `step_up.rs`
with its own I1 review (so "the gate and verifier are unchanged" does *not* hold for goal 5
under this option); or **(b)** a documented thread-bridge (a dedicated blocking thread +
channel) inside `MeshDischargeProvider`, keeping the trait sync. Either way it is a
deliberate, reviewed change, not a free consequence of the seam.

The flow:

1. `Gate::evaluate` returns `Decision::NeedsDischarge(requirement)` — **no challenge yet**
   (the merged `Decision` carries only the `AttestRequirement`). The **host** mints a
   single-use `nonce`, computes `action_id = ContentId(canonical(tool, args, resource))`,
   and derives `Challenge::bind(action_id, generation, nonce)` (WYSIWYS, already built).
   The gate recomputes and re-checks this same challenge across the freshness window at
   admission — so the challenge is authoritative on the gate side, not taken on trust.
2. `MeshDischargeProvider::obtain(...)` publishes a **discharge request** —
   `Bus::request(device_fp, "<user_fp>:presence/discharge/v1", body, timeout)` — to the
   user's registered presence device. **Reachability precondition:** `Bus::request`
   resolves `device_fp` over mDNS and fails `Unreachable` for a never-announcing peer, and
   the endpoint binds relay-free. So the presence device must either mDNS-announce on the
   operator's LAN or be enrolled with a stable dialable `(pubkey, addr)` for
   `request_direct` (a VPN/WireGuard address). **Native-phone remote discharge is LAN/VPN-
   only in this phase;** the off-LAN case rides the browser gateway (§8.3). The device holds
   an attenuated `AgentKey` enrolled via §8.2.
3. The phone/web collects a **WebAuthn UV assertion over the challenge** — the authenticator
   signs `authenticatorData ‖ SHA-256(clientDataJSON)`, whose `clientDataJSON` embeds the
   base64url `challenge`, with the UV flag set — and replies (dial-back on the request's
   authenticated source address, so the *reply* leg needs no mDNS).
4. A WebAuthn `get()` assertion carries `rawId + authenticatorData + clientDataJSON +
   signature` — **never the credential's public key**. So the provider **resolves `rawId`
   against the enrolled-credential registry (§8.2)** to obtain the registered key, populates
   `Discharge::credential_id` with it, and returns the `Discharge`; an unknown `rawId` is a
   refusal. The gate re-derives the bound `Challenge` and verifies the signature **against
   that enrolled key**. Transport-untrust for *authority* holds **only** once the credential
   is pinned (§7.2) and ES256 is supported (§12 P-e) — absent pinning, a relay could mint a
   software key, fabricate `authenticatorData` with UP|UV, and self-attest `Presence::Passkey`
   (the ADR 0007 D5 self-attestation this design forbids). With pinning this is **exactly
   ADR 0002 invariant I14**: an off-box, effect-side verifier recomputing the challenge
   against a known authenticator.
5. The discharged authority is scoped `valid_for_generation = Only({N})` so it is causally
   bounded and dies on the next generation bump — no wall-clock. (Requires P-d: `verify_at`
   plumbed into the transport handshake.)

### 8.2 Phone/web enrollment — two enrollments, not one

Goal 5 needs the phone to be (i) a trusted-but-attenuated **mesh peer** and (ii) the holder
of an **enrolled WebAuthn credential**. These are distinct:

- **Mesh AgentKey** — reuse `AgentKey::possession_challenge()` + `delegate_external(...)`
  (agent-mesh main, §9.2, #40): the phone's mesh key is certified into a `CertChain` against
  a signed PoP over a fresh nonce, attenuation-checked, its only authority being to answer
  presence challenges. Numeric-comparison pairing (the mesh-remote-control design's §4.5) is
  the MITM + human-presence defense. The phone signs via `MeshSigner` (Secure Enclave /
  Keystore — the seed never exports).
- **WebAuthn credential** — the *same* pairing ceremony must **also** run a WebAuthn
  registration (`navigator.credentials.create()` / CTAP2 `makeCredential`) and record
  `(rawId → COSE public key)` in the §7.2 enrolled-credential registry — the store §8.1 step
  4 resolves against. Mesh enrollment authenticates the *device*; it does **not** enroll the
  *credential*.

### 8.3 The browser↔mesh gateway (the one genuinely new service)

Browsers cannot speak iroh QUIC with the pinned ALPN, so the *web-app* case needs a bridge
(`agent-bridle-gateway`, new): a small WS/HTTP service, co-located with a mesh node, that (a)
serves the WebAuthn ceremony page, (b) relays the challenge to the browser, (c) runs
`navigator.credentials.get({publicKey: {challenge, userVerification:"required"}})`, and (d)
carries the assertion back onto the mesh. **The gateway is untrusted for authority** — it
never verifies, never holds authority; the assertion is bound to the challenge and
re-verified against the enrolled key at the gate. **But it is *not* untrusted for display:**
the page it serves is the human's screen (§8.5). (Q5: serving a WebAuthn page off-`localhost`
needs a TLS cert / trusted origin for `navigator.credentials.get`.) A **native phone app**
skips the gateway and speaks mesh directly via `MeshSigner` (LAN/VPN-reachable — §8.1).

### 8.4 Transport-generation plumbing (the one required mesh fix)

`verify_at(current_generation)` exists on agent-mesh main but is not wired into
`handshake.rs`/`stream.rs` (still context-free `verify()`), so a generation-scoped cert
cannot complete a handshake. Goal 5's causal-freshness scoping (§8.1 step 5) needs a
current-generation source plumbed into `Endpoint`/`Bus` — an **upstream agent-mesh PR**
(§12 P-d).

### 8.5 The discharge wire schema — and the WYSIWYS limit

A new application schema over the reserved topic: `DischargeRequest {challenge,
requirement, action_summary}` and `DischargeResponse {assertion {raw_id,
authenticator_data, client_data_json, signature} | refused}`.

**`action_summary` is advisory, not bound — a stated limit, not a property.** The challenge
commits only to `BLAKE3(domain ‖ action_id ‖ generation ‖ nonce)` (`Challenge::bind`), and
the signed `clientDataJSON` carries only `{type, challenge, origin}` — the human-readable
summary is **never part of what is signed**, and the gate cannot verify what was displayed.
So **what-you-sign-is-bound-to-the-action holds** (an assertion for a different action is
rejected when the gate re-derives the challenge), but **what-you-see is rendered by the
gateway (§8.3), which we declare untrusted for authority** — a malicious gateway (or a lying
provider composing the `DischargeRequest`) can show a benign summary beside a valid challenge
for a dangerous act. **Remote WYSIWYS is therefore an unmet prerequisite, not a property of
this schema.** Closing it requires (a) deriving `action_summary` deterministically from the
resolved `(tool, args, resource)` and **binding its hash into the signed material** (a
WebAuthn extension, or the challenge derivation), with the gate recomputing and rejecting
mismatches, and (b) a **trusted rendering surface** — a native app over `MeshSigner`, or an
authenticator with transaction-confirmation display — not a gateway-served page. (The local
path shares a milder form: a platform authenticator shows a generic OS prompt, and the
trusted display is the host's own terminal, at least inside the gate's trust domain.)

---

## 9. Host integration summary (goals 3 + 4)

| Host | Confined tools | Body capture | Live view | Presence gate |
|---|---|---|---|---|
| **hermes-thoon** | `hermes mcp add bridle` (zero code) | `post_api_request` plugin → `LlmFlowRecord` | pull via operator-plane `traffic_tail` (cursor-poll) | `pre_tool_call` plugin blocks on `presence_check` fail — **hermes-native tools only**, deny-only (see scope note) |
| **newt-agent** | already wired (0.7) | `RecordingBackend` decorator + three `chat_complete` taps + side channels | `flow_lines` render-data + slash-command viewer | wire a real `DischargeProvider` (needs §7.2 anchor + P-e) into the already-imported step-up; `newt doctor` sections |
| **gilamonster-agent** | inherited from newt | inherited (all calls are newt's `TurnDriver`) | **FleetView Detail** traffic-explorer via a new recorder-store → `FleetModel` feed (`Doorbell`/`entries_since`; new work — FleetView is mock-only today) rendered with `flow_lines`; wire the reserved `AgentState::Blocked` state | inherited |

> **Scope note — the hermes presence gate.** `pre_tool_call` gates hermes's *own* builtin
> tools (deny-only, no ceremony round-trip at this seam). Presence-gated *bridle* tools are
> gated inside the bridle MCP server itself (§7.3), where the ceremony lives. The two do not
> overlap: one guards hermes tools, the other guards bridle tools.

The load-bearing UI insight: newt stays a plain scroller (its binding decision); the **rich**
traffic explorer lives in gilamonster-agent's FleetView (its charter as the rich-TUI home) and
in the standalone `bridle-netmon`. newt-core only grows renderer-agnostic `flow_lines` — never
a ratatui dependency.

---

## 10. Design laws honored

- **Telescope, not sky.** Both instruments observe the operator's own agent / own presence —
  sightings the operator has a sovereign right to. Storage is local, plain, the operator's.
- **Provenance lands in the TARGET.** The flight recorder is the host's black box, not a mesh
  store. agent-mesh stays store-free; it carries capture *events* and discharge *challenges*,
  never history.
- **No wall-clock as coordination.** Ordering is `(writer, seq/generation)`; `captured_at_ms`
  and `expires_at` are display claims. Presence freshness is `valid_for_generation` + a
  single-use nonce, never a timer.
- **Secrets never move.** Redaction before append into a deletable blob table (so a miss is
  purgeable — §4.3/§11); the passkey never signs a CA and never exports its seed (`MeshSigner`);
  the gateway is untrusted for authority; body capture is opt-in and redacted.
- **Honesty / never overclaim (I9).** Every record is stamped `Flow` or `Body`; a CONNECT-tunnel
  record never claims body fidelity; plaintext visibility is discarded by rule; "every LLM call"
  is only true once the newt side channels are covered.
- **Attenuation-only; step-up adds no authority (ADR 0007 D1).** Discharge is the third leash
  outcome; `effective = granted.meet(required)` is unchanged on every path. The enrolled phone
  key is attenuated.
- **Core stays lean (ADR 0008).** Recorder, proxy, ceremonies, gateway, presence, and mesh
  provider all live outside `agent-bridle-core`. (One caveat: goal 5's async transport may force
  a core `DischargeProvider` signature change — §8.1 — an explicit, reviewed exception.)
- **Single mint site (I1).** No new `ToolContext` constructor. Capture reads what the gate
  decided; presence flows through `authorize_with_discharge`.
- **Observability never enforces — one scoped exception.** The flow/body recorder never changes
  a decision (ADR 0016 D5). The *only* exception is the §7.4 attestation Scar, where a
  `record: true` policy demands a durable record, so a failed Scar write is a fail-closed denial
  — there it is the *policy* gating, not the recorder.

---

## 11. Privacy & security stance (loud, because this is a serious surface)

Capturing *all* LLM traffic — including, at Body tier, the prompts — is a significant privacy
surface. To be codified in `docs/PRIVACY.md`:

- **Body capture is opt-in and off by default.** Flow tier is the default; prompts/completions
  only when the operator turns on Body tier for a host.
- **Redaction before persistence, with a remediation path.** Secrets are scrubbed by a
  construction-time invariant before the record's blob is written. Redaction is heuristic and
  will occasionally miss; because Body payloads live only in the deletable blob side-table
  (§4.3), a leaked secret is **purged** by deleting its blob while the tamper-evident chain stays
  intact (purge is itself recorded as a tombstone naming the CID); epoch rotation is the coarse
  fallback. Tool args are stored as digests, never raw.
- **Local-first, bounded, sovereign.** On the operator's disk, with size/count/epoch retention
  caps (a crude cap from P0). Never shipped anywhere by default. Cross-host merge over mesh (§4.3
  `ingest`) is opt-in and stays within the operator's own single-user mesh.
- **The recorder is not a leash.** It records what the gate decided; a compromised recorder leaks
  history (bounded by redaction + purge + retention), it cannot escalate authority. (Scoped
  exception: the §7.4 `record: true` Scar.)
- **The agent is not a reader.** Recorded history — even Flow tier — is for the operator's eyes;
  the query surface (§6) is operator-plane and never handed to the model, so recorded prompts
  cannot loop back into model context or to a prompt-injected instruction.
- **The presence gate fails closed.** No/weak/mismatched/replayed gesture → **denial** (ADR 0007
  D2). The gateway and transport are untrusted for authority; only the gate's re-verification
  against an **enrolled** credential counts (§7.2). Remote *display* trust is an unmet
  prerequisite, stated as such (§8.5).

### 11.1 Redaction — specification and enforcement

- **Pattern set.** Start from newt's `REDACTION_TABLE` (`compress.rs`: private-key blocks, `sk-`
  keys, GitHub tokens, `AKIA` ids, JWTs, `Bearer` values, closed-list credential assignments),
  extended for LLM shapes (`sk-ant-` keys, `x-api-key` headers, provider auth headers).
- **Reuse plan.** `redact_secrets` is `pub(crate)` in newt-core and the dependency direction is
  newt→bridle, so it cannot be imported. Extract the table + function into a small shared crate
  (e.g. `agent-redact`) that both `agent-bridle-recorder` and newt-core consume, or vendor a copy
  guarded by a cross-repo parity test.
- **Enforcement point.** Redaction runs at construction of the redacted types
  (`RedactedMessages`/`RedactedText`); the store's append path accepts only those types, so
  nothing unredacted enters a blob. For records arriving over MCP or mesh from non-Rust producers
  (the hermes Python plugin; §4.3 `ingest`), redaction **re-runs server-side at ingestion** — the
  wire is never trusted to have redacted.
- **On a miss.** Pattern redaction is best-effort; a novel secret shape can pass — a privacy
  failure bounded by Body-off-by-default, the blob purge path, retention caps, and an extensible
  table, never an authority failure. (Precedent, stated honestly: newt's `ShellObservation`
  stores raw content and redacts at *egress*; the recorder redacts at *ingress* because the chain
  freezes the CID — the blob is the purge seam that makes ingress-redaction's misses recoverable.)

---

## 12. Phased plan

Each phase is independently shippable and TDD-gated (red-on-today, green-after). Prerequisites
are **blocking** where marked.

**Prerequisites:**
- P-a. Causal revocation (`verify_at`) — **DONE on agent-mesh main (#39)**.
- P-b. Proof-of-possession for external keys (`delegate_external`) — **DONE on agent-mesh main
  (#40)**.
- P-c. **Authenticate/sign the grant source.** The fail-**open** default is already fixed —
  a missing `$AGENT_BRIDLE_CAVEATS` fails **closed** to DENY-ALL (agent-bridle #25,
  `caveats_source.rs`). The residual: the grant is trusted **unsigned**, so any process that can
  set the env var mints an arbitrary grant (the ADR 0002 I13 signed-artifact gap). Signing the
  grant **BLOCKS** trusting a presence gate against a hostile local environment (a tricked deputy
  that controls env could otherwise widen its own grant before the gate ever runs).
- P-d. Transport-generation plumbing (`verify_at` into handshake) — **upstream agent-mesh PR**.
  BLOCKS §8's generation-scoped discharge only.
- P-e. **ES256 support in `WebAuthnVerifier`.** The merged verifier is Ed25519-only (COSE `-8`);
  platform authenticators and synced passkeys mint **ES256** (P-256). Add COSE-key/ES256
  verification (`p256`). Without it every platform-authenticator/phone/browser assertion fails
  **closed**; only Ed25519-capable roaming keys (YubiKey enrolled `-8`) pass. BLOCKS the platform
  path of P3/P4 and all of P5's web/phone flows.
- P-f. **Internal-range egress opt-out for the recording proxy** (bridle #152). `net_proxy`'s
  SSRF guard is default-on and unconditional; as-coded the generalized proxy cannot reach a LAN
  LLM node (a dgx at `192.168.x`). A daemon-mode allow-list of explicitly configured internal LLM
  endpoints (keeping the unconditional guard for confined-child mode) + its own ADR. BLOCKS
  flow-tier capture of LAN backends.

**P0 — Flow-tier recorder (goal 1, floor).** Persistent recording egress proxy (generalize
`net_proxy`, per-session listeners, §4.1.1 trust model + ADR) + `agent-bridle-recorder` on
`agent-store` + `LlmFlowRecord` (flow fields) + the upstream agent-store `entries_since`/tail/
enumeration/append-serialization PRs. **Includes a crude retention cap** so P0 honors §11's
bounded stance and workspace disk discipline from day one. Extend `bridle-netmon` to read the
store. *Ships the honest iptraf floor with no host cooperation beyond a proxy env var. Needs P-f
for LAN backends.*

**P1 — Body-tier capture + hosts (goals 1, 3).** `agent-bridle-recorder` Body fields + blob
side-table + the shared `agent-redact` crate (§11.1) + verify-from-anchor retention. hermes
`post_api_request` plugin; newt `RecordingBackend` + three `chat_complete` taps + side channels;
operator-plane `traffic_query`/`traffic_tail`. *Depends on P0.*

**P2a — Flow-tier live views (goal 4, floor).** Doorbell live-tail; newt-core `flow_lines`
render-data; FleetView Detail flow view + the recorder-store → `FleetModel` feed; slash-command
viewer in newt. *Depends on P0 only.*
**P2b — Body-tier live exploration (goal 4).** Per-token streaming view fed by the Body tap.
*Depends on P1.*

**P3 — Local presence anchor + ceremonies (goal 2).** The §7.2 **enrolled-credential registry**
+ P-e **ES256 verifier** + §7.3 **facade feature plumbing** (else no verifier is compiled in) +
`agent-bridle-presence` (`CtapHidProvider` first — Ed25519, runs against today's verifier;
`PlatformAuthenticatorProvider` research-gated; `PromptProvider`). Wire `RegistryBuilder::step_up`
+ resolve `CallRequest`; persist the `Attestation` with `record: true` fail-closed (§7.4). `newt
doctor` sections. *Depends on P-c (sign the grant) + P-e.*

**P4 — Presence in hosts (goals 2, 3).** newt wires a real `DischargeProvider` into the imported
step-up (replaces `Presence::Prompt`-only crew gating, answers BOOT #472's client side); hermes
`pre_tool_call` presence-block plugin; gila wires `AgentState::Blocked`. *Depends on P3.*

**P5 — Remote discharge over mesh (goal 5).** The discharge wire schema + reserved topic; the
**async-vs-thread-bridge decision** for `DischargeProvider` (§8.1 Q6); `MeshDischargeProvider`;
dual enrollment (mesh PoP + WebAuthn credential, §8.2); the `agent-bridle-gateway` browser↔mesh
bridge (untrusted for authority; display gap stated). *Depends on P3 (ceremony + enrolled-cred
reuse) + P-d + P-e.*

**P6 — Cross-host flight-recorder merge (goal 1 at fleet scale).** agent-store `ingest(Entry)`
cross-host merge (with server-side re-redaction, §11.1) + a Doorbell→mesh `CommitEvent` bridge, so
a FleetView on one box can tail captured traffic from agents on another (within the operator's
single-user mesh). *Depends on P0 + P-d (generation-aware transport).*

**ADRs this plan spawns:** a two-tier-capture ADR (including the persistent-proxy trust model that
supersedes ADR 0016 D3's "no persistent listener"); a credential-enrollment + presence-ceremony ADR
(extending ADR 0007); a mesh-discharge ADR (realizing I14, including the sync-vs-async provider
decision); and a gateway-trust ADR (untrusted-for-authority, the display gap).

---

## 13. Risks & open questions

- **Q1 — CTAP-HID dependency.** Which Rust crate for USB-HID CTAP2? Must be cross-platform and not
  drag a heavy tree. *Owner: Shawn.*
- **Q2 — Streaming reconstruction fidelity.** newt's three `chat_complete` `stream:true` rounds
  must be tapped without perturbing the user-visible stream. Body-tier for interactive, or
  flow-tier-only there and body-tier for headless?
- **Q3 — Crate boundary for ceremonies.** New `agent-bridle-presence` vs. feature-gated in
  `agent-bridle-tool-shell`. Leaning new crate (dep isolation, ADR 0008). *Owner: Shawn.*
- **Q4 — Body capture default.** Confirm Body stays **off by default**, Flow is default (§11). A
  privacy call, not an engineering one.
- **Q5 — Gateway hosting + origin.** Where does the browser↔mesh gateway run, and does serving a
  WebAuthn page off-`localhost` need a TLS cert / trusted origin for `navigator.credentials.get`?
  *Owner: Shawn.*
- **Q6 — Sync vs. async `DischargeProvider`.** Goal 5 forces (a) an async trait (core-surface
  change + ADR) or (b) a thread-bridge in `MeshDischargeProvider`. *Owner: Shawn.*
- **Q7 — Platform authenticator reach.** Touch ID needs an entitled signed app context (no clean
  CLI path); synced passkeys are CTAP2-unreachable. Is a signed helper app in scope, or is P3/P4's
  platform tier deferred to YubiKey-only? *Owner: Shawn.*
- **Risk — scope.** Six phases across five repos. Ship as small, merge-on-green PRs (the ratchet
  discipline), one logical change per branch. P0 (flow floor) and P3 (local presence anchor) each
  deliver standalone operator value and should land first.
- **Risk — the enrolled-credential anchor (P3) is load-bearing.** Until the gate checks
  `credential_id ∈` enrolled set, the merged verifier proves only "someone signed" — a software
  self-attestation of `Presence::Passkey`. No presence-gated act should be trusted before P3's
  anchor + P-e land.

## 14. Explicitly NOT building

- **TLS interception / MITM of provider traffic.** Body fidelity comes from the in-proc host tap,
  never from decrypting the operator's provider TLS.
- **A mesh-side store.** agent-mesh stays store-free; history lives in the target.
- **Passkey-as-CA.** The passkey attests; it never signs the trust root. The mesh root stays the
  software ed25519 `UserKey`.
- **A second authority channel.** No new `ToolContext::mint`; presence flows through the existing
  `authorize_with_discharge`.
- **Wall-clock freshness or expiry enforcement.** Causal generation only.
- **Handing recorded traffic to the model.** The query surface is operator-plane; the agent is not
  a reader of its own black box (§6, §11).
- **A claim of remote WYSIWYS.** What-you-sign is bound; what-you-see over the gateway is not — an
  unmet prerequisite, not a shipped property (§8.5).
