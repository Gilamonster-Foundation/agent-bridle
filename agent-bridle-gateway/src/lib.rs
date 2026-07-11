//! `agent-bridle-gateway` — the browser↔agent-mesh presence gateway and operator
//! web console.
//!
//! This crate is the "one genuinely new service" of the LLM-flight-recorder +
//! WebAuthn-presence plan (`docs/design/llm-flight-recorder-and-webauthn-presence.md`,
//! §8.3). It serves a two-tab web console:
//!
//! - **Presence** — enroll a WebAuthn credential (`navigator.credentials.create`)
//!   and answer a presence request with a user-verified assertion
//!   (`navigator.credentials.get`). The gateway relays the assertion toward the
//!   mesh; it is **untrusted for authority** — the work-box gate re-verifies
//!   against the enrolled credential (§8.1 step 4).
//! - **Traffic** — a live `LlmFlowRecord` table (the iptraf-for-LLM view, §4).
//!
//! **This is the MVP vertical slice: the mesh leg is mocked** ([`mock`]). The
//! browser WebAuthn ceremony and the HTTP/WS transport are real; the agent-mesh
//! `Bus::request` round-trip and the gate's verification are stubbed so the whole
//! operator UX can be driven end-to-end before the mesh transport, the ES256
//! verifier, and the enrolled-credential pinning land (plan §12 P-d/P-e, §7.2).

pub mod mock;
pub mod wire;

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use agent_bridle_core::{CallRequest, Presence};
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use rand::RngCore;

use crate::mock::{MockFlows, MockMeshProvider, RelayError};
use crate::wire::{
    ClientMsg, DischargeRequest, DischargeResponse, EnrollmentRecord, LlmFlowRecord, ServerMsg,
};

/// The WebAuthn relying-party id the console binds credentials to. `localhost` is
/// a secure context by exemption; off-`localhost` this must match the served TLS
/// origin (plan Q5).
const DEFAULT_RP_ID: &str = "localhost";

const HELLO_NOTICE: &str = "MVP · mesh leg mocked · this gateway is UNTRUSTED for \
    authority — it relays; the work-box gate re-verifies against your enrolled \
    credential. The action summary shown is advisory (not yet bound into the \
    signature — §8.5).";

/// One outstanding presence request: the challenge bytes the console will sign,
/// kept so the gateway can assemble the [`agent_bridle_core::Discharge`] when the
/// assertion returns.
#[derive(Clone)]
struct Pending {
    challenge: [u8; 32],
    action_summary: String,
    generation: u64,
}

/// Shared gateway state. Everything here is in-memory and per-process — this is a
/// single-operator local service, not a multi-tenant server.
pub struct AppState {
    /// The relying-party id served to the console.
    rp_id: String,
    /// The mock enrolled-credential registry (§7.2 stand-in): raw_id → label.
    /// A real registry stores the COSE public key and is the pinning anchor.
    enrolled: Mutex<HashMap<String, EnrollmentRecord>>,
    /// Outstanding discharge requests, keyed by request id.
    pending: Mutex<HashMap<String, Pending>>,
    /// A monotonic generation counter (causal, never wall-clock).
    generation: AtomicU64,
    /// The demo flow generator for the Traffic tab.
    flows: Mutex<MockFlows>,
}

impl AppState {
    /// A fresh state with the given relying-party id.
    #[must_use]
    pub fn new(rp_id: impl Into<String>) -> Self {
        Self {
            rp_id: rp_id.into(),
            enrolled: Mutex::new(HashMap::new()),
            pending: Mutex::new(HashMap::new()),
            generation: AtomicU64::new(1),
            flows: Mutex::new(MockFlows::new()),
        }
    }

    /// Number of currently enrolled credentials (used by tests and the status
    /// endpoint).
    #[must_use]
    pub fn enrolled_count(&self) -> usize {
        self.enrolled.lock().expect("enrolled mutex").len()
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self::new(DEFAULT_RP_ID)
    }
}

/// Build the router over a shared [`AppState`]. Split out so tests can drive it
/// without binding a socket.
pub fn app(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/app.js", get(app_js))
        .route("/style.css", get(style_css))
        .route("/api/status", get(status))
        .route("/api/presence/enroll/options", get(enroll_options))
        .route("/api/presence/enroll", post(enroll))
        .route("/api/traffic", get(traffic_history))
        .route("/ws", get(ws_upgrade))
        .with_state(state)
}

// ── static assets (embedded, self-contained — no external CDN, no fs dep) ──────

async fn index() -> impl IntoResponse {
    html(include_str!("../web/index.html"))
}

async fn app_js() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
        include_str!("../web/app.js"),
    )
}

async fn style_css() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
        include_str!("../web/style.css"),
    )
}

fn html(body: &'static str) -> Response {
    ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], body).into_response()
}

// ── JSON HTTP endpoints ───────────────────────────────────────────────────────

async fn status(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "rp_id": state.rp_id,
        "enrolled": state.enrolled_count(),
        "generation": state.generation.load(Ordering::SeqCst),
        "mesh": "mocked",
    }))
}

/// WebAuthn `create()` options for the enroll view. The MVP offers both ES256
/// (COSE `-7`, what platform authenticators/synced passkeys mint) and EdDSA
/// (COSE `-8`, what today's core `WebAuthnVerifier` can check) so a real device
/// works even though the verifier is Ed25519-only for now (plan §12 P-e).
async fn enroll_options(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let mut challenge = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut challenge);
    Json(serde_json::json!({
        "challenge": b64url(&challenge),
        "rp": { "id": state.rp_id, "name": "agent-bridle presence" },
        "user": {
            "id": b64url(b"operator"),
            "name": "operator",
            "displayName": "Operator",
        },
        "pubKeyCredParams": [
            { "type": "public-key", "alg": -7 },
            { "type": "public-key", "alg": -8 },
        ],
        "authenticatorSelection": { "userVerification": "required" },
        "timeout": 60000,
    }))
}

async fn enroll(
    State(state): State<Arc<AppState>>,
    Json(record): Json<EnrollmentRecord>,
) -> Response {
    if record.raw_id.is_empty() {
        return (StatusCode::BAD_REQUEST, "missing raw_id").into_response();
    }
    state
        .enrolled
        .lock()
        .expect("enrolled mutex")
        .insert(record.raw_id.clone(), record);
    (
        StatusCode::OK,
        Json(serde_json::json!({ "enrolled": state.enrolled_count() })),
    )
        .into_response()
}

/// Operator-plane traffic query (the `traffic_query` analogue, §6): returns a
/// batch of demo flow records for the Traffic tab's initial load. In the real
/// system this reads the flight-recorder store, hard-scoped to the operator.
async fn traffic_history(State(state): State<Arc<AppState>>) -> Json<Vec<LlmFlowRecord>> {
    let now = now_ms();
    let mut flows = state.flows.lock().expect("flows mutex");
    Json((0..12).map(|_| flows.next(now)).collect())
}

// ── WebSocket: the live presence + traffic channel ────────────────────────────

async fn ws_upgrade(State(state): State<Arc<AppState>>, ws: WebSocketUpgrade) -> Response {
    ws.on_upgrade(move |socket| ws_loop(socket, state))
}

async fn ws_loop(mut socket: WebSocket, state: Arc<AppState>) {
    // Greet with the trust posture up front.
    let hello = ServerMsg::Hello {
        rp_id: state.rp_id.clone(),
        notice: HELLO_NOTICE.to_string(),
    };
    if send(&mut socket, &hello).await.is_err() {
        return;
    }

    // Push a few flows immediately so the Traffic tab is not empty on connect.
    // Generate them under the lock, then send them after the guard is dropped —
    // a `MutexGuard` must never be held across an `.await`.
    let initial: Vec<LlmFlowRecord> = {
        let now = now_ms();
        let mut flows = state.flows.lock().expect("flows mutex");
        (0..6).map(|_| flows.next(now)).collect()
    };
    for rec in initial {
        if send(&mut socket, &ServerMsg::Flow(rec)).await.is_err() {
            return;
        }
    }

    while let Some(Ok(msg)) = socket.recv().await {
        let text = match msg {
            Message::Text(t) => t,
            Message::Close(_) => break,
            // Ignore binary/ping/pong for the MVP.
            _ => continue,
        };
        let Ok(client_msg) = serde_json::from_str::<ClientMsg>(&text) else {
            continue;
        };
        match client_msg {
            ClientMsg::SimulateRequest {
                presence,
                action_summary,
            } => {
                let request = state.new_discharge_request(presence, action_summary);
                if send(&mut socket, &ServerMsg::DischargeRequest(request))
                    .await
                    .is_err()
                {
                    break;
                }
            }
            ClientMsg::Discharge(response) => {
                let result = state.relay_discharge(&response);
                if send(&mut socket, &result).await.is_err() {
                    break;
                }
            }
        }
    }
}

impl AppState {
    /// Mint a fresh presence request: bind the WYSIWYS challenge exactly as the
    /// real gate would (`Challenge::bind` over the action content-id, generation,
    /// and a single-use nonce) and remember it so the returning assertion can be
    /// assembled.
    fn new_discharge_request(
        &self,
        presence: Presence,
        action_summary: String,
    ) -> DischargeRequest {
        let generation = self.generation.load(Ordering::SeqCst);
        // The action id is content-addressed over the (tool, args, resource) the
        // human is approving — reused from core so the binding matches the gate.
        let action = CallRequest::new(
            "presence.demo",
            serde_json::json!({ "summary": action_summary }),
            "demo",
        );
        let mut nonce = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut nonce);
        let challenge = mock::bind_challenge(&action.content_id(), generation, &nonce);
        let challenge_bytes = *challenge.as_bytes();

        let id = hex(&nonce[..8]);
        self.pending.lock().expect("pending mutex").insert(
            id.clone(),
            Pending {
                challenge: challenge_bytes,
                action_summary: action_summary.clone(),
                generation,
            },
        );

        DischargeRequest {
            id,
            challenge_hex: hex(&challenge_bytes),
            required_presence: presence,
            generation,
            action_summary,
        }
    }

    /// Relay a browser discharge toward the (mock) mesh. Assembles the
    /// [`agent_bridle_core::Discharge`] and reports the untrusted-relay outcome —
    /// it performs no verification (that is the work-box gate's job).
    fn relay_discharge(&self, response: &DischargeResponse) -> ServerMsg {
        let id = match response {
            DischargeResponse::Assertion { id, .. } | DischargeResponse::Refused { id } => {
                id.clone()
            }
        };
        let pending = self.pending.lock().expect("pending mutex").remove(&id);
        let Some(pending) = pending else {
            return ServerMsg::DischargeResult {
                id,
                relayed: false,
                detail: "no matching outstanding request (already answered or expired)".into(),
            };
        };

        match MockMeshProvider::assemble(response, &pending.challenge) {
            Ok(discharge) => {
                // Advance the generation: one gesture, one act (single-use, §8.1 step 5).
                self.generation.fetch_add(1, Ordering::SeqCst);
                let known = self
                    .enrolled
                    .lock()
                    .expect("enrolled mutex")
                    .contains_key(&b64url(&discharge.credential_id));
                let enrolled_note = if known {
                    "credential is enrolled here"
                } else {
                    "credential NOT enrolled here — the real gate would REJECT it (§7.2 pinning)"
                };
                ServerMsg::DischargeResult {
                    id,
                    relayed: true,
                    detail: format!(
                        "assertion assembled for action “{}” at generation {}; \
                         would be carried onto the mesh and re-verified by the work-box \
                         gate ({}). Gateway performed NO verification.",
                        pending.action_summary, pending.generation, enrolled_note,
                    ),
                }
            }
            Err(RelayError::Refused) => ServerMsg::DischargeResult {
                id,
                relayed: false,
                detail: "human declined — nothing relayed".into(),
            },
            Err(RelayError::MalformedField(f)) => ServerMsg::DischargeResult {
                id,
                relayed: false,
                detail: format!("malformed assertion field: {f}"),
            },
            Err(RelayError::BadChallengeLength) => ServerMsg::DischargeResult {
                id,
                relayed: false,
                detail: "bound challenge was not 32 bytes".into(),
            },
        }
    }
}

async fn send(socket: &mut WebSocket, msg: &ServerMsg) -> Result<(), axum::Error> {
    let text = serde_json::to_string(msg).expect("ServerMsg is always serializable");
    socket.send(Message::Text(text)).await
}

fn b64url(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Wall-clock milliseconds — a **display claim only**, never an ordering key
/// (the design's no-wall-clock rule; ordering is `(writer, seq)`).
fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simulate_request_binds_and_remembers_a_challenge() {
        let state = AppState::new("localhost");
        let req = state.new_discharge_request(Presence::Passkey, "push to prod".into());
        assert_eq!(req.required_presence, Presence::Passkey);
        assert_eq!(req.challenge_hex.len(), 64, "32 bytes hex");
        assert_eq!(req.action_summary, "push to prod");
        assert_eq!(
            state.pending.lock().unwrap().len(),
            1,
            "the challenge is remembered for the returning assertion"
        );
    }

    #[test]
    fn relay_of_a_known_request_is_single_use_and_bumps_generation() {
        let state = AppState::new("localhost");
        let g0 = state.generation.load(Ordering::SeqCst);
        let req = state.new_discharge_request(Presence::Passkey, "delete repo".into());

        use base64::Engine;
        let b64u = |b: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b);
        let response = DischargeResponse::Assertion {
            id: req.id.clone(),
            raw_id: b64u(b"cred-1"),
            authenticator_data: b64u(&[0u8; 37]),
            client_data_json: b64u(br#"{"type":"webauthn.get"}"#),
            signature: b64u(&[1u8; 64]),
        };

        let ServerMsg::DischargeResult { relayed, .. } = state.relay_discharge(&response) else {
            panic!("expected a DischargeResult");
        };
        assert!(relayed, "a well-formed assertion is relayed");
        assert_eq!(
            state.generation.load(Ordering::SeqCst),
            g0 + 1,
            "one gesture advances the generation (single-use)"
        );

        // Re-presenting the same discharge finds no pending request → not relayed.
        let ServerMsg::DischargeResult { relayed: again, .. } = state.relay_discharge(&response)
        else {
            panic!("expected a DischargeResult");
        };
        assert!(!again, "the request was consumed — replay is refused");
    }

    #[test]
    fn refused_gesture_relays_nothing() {
        let state = AppState::new("localhost");
        let req = state.new_discharge_request(Presence::Passkey, "x".into());
        let ServerMsg::DischargeResult { relayed, .. } =
            state.relay_discharge(&DischargeResponse::Refused { id: req.id })
        else {
            panic!("expected a DischargeResult");
        };
        assert!(!relayed);
    }

    #[test]
    fn enroll_count_reflects_registered_credentials() {
        let state = AppState::new("localhost");
        assert_eq!(state.enrolled_count(), 0);
        state.enrolled.lock().unwrap().insert(
            "cred-x".into(),
            EnrollmentRecord {
                raw_id: "cred-x".into(),
                client_data_json: String::new(),
                label: "yubikey".into(),
            },
        );
        assert_eq!(state.enrolled_count(), 1);
    }
}
