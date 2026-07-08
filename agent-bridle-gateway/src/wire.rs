//! The wire schema spoken between the browser console, the gateway, and (in the
//! real system) the agent-mesh presence topic.
//!
//! These types mirror the schema in
//! `docs/design/llm-flight-recorder-and-webauthn-presence.md` (§8.5 for the
//! discharge round-trip, §5 for the flow record). They reuse the
//! `agent-bridle-core::step_up` primitives (`Presence`, `Challenge`) rather than
//! re-declaring the crypto surface. In the real system a `DischargeRequest`
//! arrives from the work-doing box over the mesh topic
//! `<user_fp>:presence/discharge/v1`; here the [`crate::mock`] provider stands in
//! for that leg.

use agent_bridle_core::Presence;
use serde::{Deserialize, Serialize};

/// Fidelity of a captured flow — the honesty axis (§4). A flow-tier record
/// (endpoint/bytes/timing) never claims to carry request/response bodies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Fidelity {
    /// Wire-level: endpoint, bytes, timing. Body-blind for HTTPS.
    Flow,
    /// Semantic-level: model, tokens, redacted prompts/completions.
    Body,
}

/// Direction/phase of a captured record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    /// A connection opened (flow tier).
    ConnOpen,
    /// A connection closed (flow tier; where `net_proxy` fires today).
    ConnClose,
    /// A model request (body tier).
    Request,
    /// A model response (body tier).
    Response,
}

/// Token accounting for a body-tier record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenUsage {
    /// Prompt tokens.
    pub prompt: u64,
    /// Completion tokens.
    pub completion: u64,
}

/// One captured LLM flow — the record the Traffic tab renders. A `Body` record
/// is a strict superset of a `Flow` record's fields (the body-only fields are
/// `None` at `Flow` fidelity). Mirrors §5's `LlmFlowRecord`.
///
/// `captured_at_ms` is a **display claim**, never an ordering key (the design's
/// no-wall-clock rule); ordering is `(writer, seq)`. In this MVP the records are
/// produced by [`crate::mock`]; the real recorder is P0/P1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LlmFlowRecord {
    /// Groups a run.
    pub session_id: String,
    /// Which agent produced this (a mesh-compatible fingerprint hex).
    pub writer: String,
    /// Causal tick.
    pub generation: u64,
    /// Per-writer monotonic sequence — the ordering key.
    pub seq: u64,
    /// Display claim only.
    pub captured_at_ms: u64,
    /// `Flow` or `Body` — never overclaim.
    pub fidelity: Fidelity,
    /// Request / response / connection phase.
    pub direction: Direction,
    /// e.g. `anthropic`, `openai`, `ollama`.
    pub provider: String,
    /// host:port or URL authority.
    pub endpoint: String,
    /// Model id, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// Bytes sent upstream.
    pub bytes_up: u64,
    /// Bytes received.
    pub bytes_down: u64,
    /// Duration in ms.
    pub dur_ms: u64,
    /// Token usage — body tier only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub usage: Option<TokenUsage>,
}

/// A request for a human presence gesture, as the human sees it. Mirrors §8.5's
/// `DischargeRequest`.
///
/// **WYSIWYS limit (§8.5):** `action_summary` is *advisory, not bound* — the
/// signed challenge commits only to `BLAKE3(domain ‖ action_id ‖ generation ‖
/// nonce)`, not to this text. The console renders it, but the gateway is untrusted
/// for display, so a real deployment must bind the summary hash into the signed
/// material for the human's reading to be trustworthy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DischargeRequest {
    /// A correlation id for this request/response pair.
    pub id: String,
    /// The 32-byte WYSIWYS challenge (`Challenge::bind`), hex-encoded for the wire.
    pub challenge_hex: String,
    /// The minimum gesture strength demanded.
    pub required_presence: Presence,
    /// The causal generation the discharge is bound to.
    pub generation: u64,
    /// Human-readable summary of the action awaiting approval (advisory).
    pub action_summary: String,
}

/// The browser's answer: a WebAuthn assertion, or a refusal. Mirrors §8.5's
/// `DischargeResponse`. All binary fields are base64url (no padding), as the
/// WebAuthn browser API produces them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DischargeResponse {
    /// A WebAuthn `get()` assertion over the challenge.
    Assertion {
        /// Correlates to the [`DischargeRequest::id`].
        id: String,
        /// The credential id (`rawId`), base64url.
        raw_id: String,
        /// `authenticatorData`, base64url.
        authenticator_data: String,
        /// `clientDataJSON`, base64url.
        client_data_json: String,
        /// The assertion signature, base64url.
        signature: String,
    },
    /// The human declined.
    Refused {
        /// Correlates to the [`DischargeRequest::id`].
        id: String,
    },
}

/// A WebAuthn registration, as the enroll view POSTs it. base64url fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrollmentRecord {
    /// The credential id (`rawId`), base64url — the key the enrolled-credential
    /// registry pins on (§7.2). In the real system the COSE public key is
    /// extracted from the attestation object; the MVP records the id only.
    pub raw_id: String,
    /// `clientDataJSON` from `create()`, base64url (kept for audit).
    pub client_data_json: String,
    /// A human label for the authenticator.
    #[serde(default)]
    pub label: String,
}

/// Messages the gateway pushes to the console over the WebSocket.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMsg {
    /// Sent on connect: identifies the gateway and its trust posture.
    Hello {
        /// The WebAuthn relying-party id the console must use.
        rp_id: String,
        /// A one-line honesty banner rendered in the UI.
        notice: String,
    },
    /// A presence gesture is being requested of the human.
    DischargeRequest(DischargeRequest),
    /// The outcome after the gateway relayed an assertion to the (mock) mesh.
    DischargeResult {
        /// Correlates to the [`DischargeRequest::id`].
        id: String,
        /// Whether the mock provider accepted the relay.
        relayed: bool,
        /// A human-readable explanation (states the untrusted-relay posture).
        detail: String,
    },
    /// A newly captured flow for the Traffic tab.
    Flow(LlmFlowRecord),
}

/// Messages the console sends to the gateway over the WebSocket.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientMsg {
    /// Ask the gateway to simulate an inbound presence request (stands in for the
    /// work-box calling `MeshDischargeProvider`).
    SimulateRequest {
        /// The presence tier to demand.
        presence: Presence,
        /// The action text to show the human.
        action_summary: String,
    },
    /// The human's answer to a discharge request.
    Discharge(DischargeResponse),
}
