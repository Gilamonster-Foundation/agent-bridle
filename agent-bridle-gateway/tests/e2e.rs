//! End-to-end test: bind the real server on an ephemeral loopback port and drive
//! the HTTP + WebSocket surface exactly as the browser console does, with a
//! stand-in "assertion" (the browser's WebAuthn call is the one thing a headless
//! test cannot make — everything else on the wire is exercised for real).

use std::sync::Arc;
use std::time::Duration;

use agent_bridle_gateway::{app, AppState};
use base64::Engine;
use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message as WsMessage;

fn b64u(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

async fn spawn_server() -> std::net::SocketAddr {
    let state = Arc::new(AppState::new("localhost"));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app(state)).await.unwrap();
    });
    // Give the accept loop a moment.
    tokio::time::sleep(Duration::from_millis(50)).await;
    addr
}

async fn http_get(addr: std::net::SocketAddr, path: &str) -> (String, String) {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let req = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    stream.write_all(req.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.unwrap();
    let raw = String::from_utf8_lossy(&buf).to_string();
    let (head, body) = raw.split_once("\r\n\r\n").unwrap_or((raw.as_str(), ""));
    (head.to_string(), body.to_string())
}

#[tokio::test]
async fn serves_the_console_and_assets() {
    let addr = spawn_server().await;

    let (head, body) = http_get(addr, "/").await;
    assert!(head.starts_with("HTTP/1.1 200"), "index 200: {head}");
    assert!(body.contains("agent-bridle"), "index has the app shell");
    assert!(
        body.contains("Presence") && body.contains("Traffic"),
        "both tabs present"
    );

    let (head, body) = http_get(addr, "/app.js").await;
    assert!(head.contains("200") && head.contains("javascript"));
    assert!(
        body.contains("navigator.credentials"),
        "app.js does real WebAuthn"
    );

    let (head, _) = http_get(addr, "/style.css").await;
    assert!(head.contains("200") && head.contains("text/css"));
}

#[tokio::test]
async fn status_and_enroll_options_are_well_formed() {
    let addr = spawn_server().await;

    let (_head, body) = http_get(addr, "/api/status").await;
    let status: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(status["mesh"], "mocked");
    assert_eq!(status["enrolled"], 0);

    let (_head, body) = http_get(addr, "/api/presence/enroll/options").await;
    let opts: serde_json::Value = serde_json::from_str(&body).unwrap();
    // The console must be offered both ES256 (-7) and EdDSA (-8) so a real
    // platform authenticator works even though the core verifier is Ed25519-only.
    let algs: Vec<i64> = opts["pubKeyCredParams"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["alg"].as_i64().unwrap())
        .collect();
    assert!(algs.contains(&-7), "ES256 offered");
    assert!(algs.contains(&-8), "EdDSA offered");
    assert_eq!(
        opts["authenticatorSelection"]["userVerification"],
        "required"
    );
}

#[tokio::test]
async fn traffic_history_returns_flow_records() {
    let addr = spawn_server().await;
    let (_head, body) = http_get(addr, "/api/traffic").await;
    let rows: Vec<serde_json::Value> = serde_json::from_str(&body).unwrap();
    assert!(!rows.is_empty(), "history is non-empty");
    // seq is the ordering key and strictly increases.
    let seqs: Vec<u64> = rows.iter().map(|r| r["seq"].as_u64().unwrap()).collect();
    assert!(
        seqs.windows(2).all(|w| w[1] > w[0]),
        "seq strictly increasing"
    );
}

/// Drive the WebSocket with a real client (tokio-tungstenite) to prove the
/// presence round-trip works over the real transport: hello + flows on connect,
/// then simulate_request → discharge_request → discharge (assertion) →
/// discharge_result. The one thing a headless test cannot do is the browser's
/// `navigator.credentials.get`; every byte on the wire around it is real.
#[tokio::test]
async fn websocket_presence_round_trip() {
    let addr = spawn_server().await;
    let url = format!("ws://{addr}/ws");
    let (mut ws, _resp) = tokio_tungstenite::connect_async(&url).await.unwrap();

    // Read the next server text frame, with a timeout.
    async fn next_text(
        ws: &mut (impl StreamExt<Item = Result<WsMessage, tokio_tungstenite::tungstenite::Error>>
                  + Unpin),
    ) -> Option<String> {
        loop {
            let msg = tokio::time::timeout(Duration::from_secs(2), ws.next())
                .await
                .ok()??
                .ok()?;
            match msg {
                WsMessage::Text(t) => return Some(t),
                WsMessage::Close(_) => return None,
                _ => continue,
            }
        }
    }

    // On connect: a hello banner and at least one flow record.
    let mut saw_hello = false;
    let mut saw_flow = false;
    for _ in 0..12 {
        let Some(text) = next_text(&mut ws).await else {
            break;
        };
        saw_hello |= text.contains("\"type\":\"hello\"");
        saw_flow |= text.contains("\"type\":\"flow\"");
        if saw_hello && saw_flow {
            break;
        }
    }
    assert!(saw_hello, "received the hello banner");
    assert!(saw_flow, "received at least one flow record");

    // simulate_request → discharge_request
    ws.send(WsMessage::Text(
        r#"{"type":"simulate_request","presence":"passkey","action_summary":"push to prod"}"#
            .to_string(),
    ))
    .await
    .unwrap();

    let mut id = None;
    let mut challenge_len = 0;
    for _ in 0..12 {
        let Some(text) = next_text(&mut ws).await else {
            break;
        };
        if text.contains("\"type\":\"discharge_request\"") {
            let v: serde_json::Value = serde_json::from_str(&text).unwrap();
            assert_eq!(v["required_presence"], "passkey");
            assert_eq!(v["action_summary"], "push to prod");
            challenge_len = v["challenge_hex"].as_str().unwrap().len();
            id = Some(v["id"].as_str().unwrap().to_string());
            break;
        }
    }
    let id = id.expect("got a discharge_request");
    assert_eq!(challenge_len, 64, "32-byte challenge in hex");

    // Answer with a stand-in assertion (the gateway relays without verifying).
    let discharge = format!(
        r#"{{"type":"discharge","kind":"assertion","id":"{id}","raw_id":"{}","authenticator_data":"{}","client_data_json":"{}","signature":"{}"}}"#,
        b64u(b"cred-e2e"),
        b64u(&[0u8; 37]),
        b64u(br#"{"type":"webauthn.get"}"#),
        b64u(&[1u8; 64]),
    );
    ws.send(WsMessage::Text(discharge)).await.unwrap();

    let mut relayed = false;
    for _ in 0..12 {
        let Some(text) = next_text(&mut ws).await else {
            break;
        };
        if text.contains("\"type\":\"discharge_result\"") {
            let v: serde_json::Value = serde_json::from_str(&text).unwrap();
            relayed = v["relayed"].as_bool().unwrap();
            assert!(
                v["detail"].as_str().unwrap().contains("NO verification"),
                "result states the untrusted-relay posture"
            );
            break;
        }
    }
    assert!(
        relayed,
        "the assertion was assembled and relayed to the mock mesh"
    );
}
