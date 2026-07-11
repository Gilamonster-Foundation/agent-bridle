//! The mocked mesh leg.
//!
//! In the real system (plan §8.1) a `MeshDischargeProvider` on the work-doing box
//! calls `Bus::request(device_fp, "<user_fp>:presence/discharge/v1", …)` and the
//! **gate** re-verifies the returned assertion against the operator's *enrolled*
//! credential (§7.2). This MVP stubs that leg: the gateway constructs the
//! [`Discharge`] and reports that it *would* be relayed onto the mesh and
//! re-verified on the work box — it performs **no** verification itself, because
//! the gateway is *untrusted for authority* (§8.3). That honesty is the whole
//! point of the mock: it demonstrates the relay without pretending to be the gate.

use agent_bridle_core::{Challenge, ContentId, Discharge, Presence};
use base64::Engine;

use crate::wire::{Direction, DischargeResponse, Fidelity, LlmFlowRecord, TokenUsage};

/// Decode a base64url-no-pad string (the WebAuthn wire form) into bytes.
///
/// Returns `None` on malformed input rather than panicking — the browser is
/// untrusted input.
#[must_use]
pub fn b64url_decode(s: &str) -> Option<Vec<u8>> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .ok()
}

/// Build the 32-byte WYSIWYS challenge for an action, exactly as the real gate
/// would (`Challenge::bind` over the action's content id, the generation, and a
/// single-use nonce). Reused, not re-implemented.
#[must_use]
pub fn bind_challenge(action_id: &ContentId, generation: u64, nonce: &[u8; 32]) -> Challenge {
    Challenge::bind(action_id, generation, nonce)
}

/// The mock mesh provider. Takes a browser [`DischargeResponse`] and, for an
/// assertion, assembles the `agent-bridle-core` [`Discharge`] that the real
/// `MeshDischargeProvider` would carry back over the mesh.
///
/// It returns `Ok(Discharge)` when the wire is well-formed. It does **not**
/// verify the signature, check user-verification flags, or resolve the credential
/// against an enrolled set — those are the work-box gate's job (§8.1 step 4). A
/// real deployment must not treat a value from here as authorized.
pub struct MockMeshProvider;

/// Why a browser discharge could not even be assembled into a [`Discharge`] to
/// relay (a wire/format problem, never an authorization decision).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayError {
    /// The human declined the gesture.
    Refused,
    /// A base64url field did not decode.
    MalformedField(&'static str),
    /// The bound challenge was not the 32 bytes the gate expects.
    BadChallengeLength,
}

impl MockMeshProvider {
    /// Assemble the [`Discharge`] a real provider would relay, from the browser's
    /// answer and the challenge the gateway had bound for this request.
    ///
    /// `challenge` is the 32-byte value the console signed (the gateway keeps it
    /// per outstanding request); the browser echoes it inside `clientDataJSON`.
    pub fn assemble(
        response: &DischargeResponse,
        challenge: &[u8; 32],
    ) -> Result<Discharge, RelayError> {
        let (raw_id, authenticator_data, client_data_json, signature) = match response {
            DischargeResponse::Refused { .. } => return Err(RelayError::Refused),
            DischargeResponse::Assertion {
                raw_id,
                authenticator_data,
                client_data_json,
                signature,
                ..
            } => (raw_id, authenticator_data, client_data_json, signature),
        };

        let credential_id = b64url_decode(raw_id).ok_or(RelayError::MalformedField("raw_id"))?;
        let auth_data = b64url_decode(authenticator_data)
            .ok_or(RelayError::MalformedField("authenticator_data"))?;
        let client_data = b64url_decode(client_data_json)
            .ok_or(RelayError::MalformedField("client_data_json"))?;
        let sig = b64url_decode(signature).ok_or(RelayError::MalformedField("signature"))?;

        Ok(Discharge {
            // The MVP reports the tier the ceremony targeted; the real gate
            // derives the *achieved* presence from the UV flag bit, never the
            // client's claim.
            presence: Presence::Passkey,
            credential_id,
            challenge: *challenge,
            signature: sig,
            authenticator_data: Some(auth_data),
            client_data_json: Some(client_data),
        })
    }
}

/// A tiny deterministic generator of demo `LlmFlowRecord`s for the Traffic tab,
/// so the console shows realistic-looking flows before the real recorder (P0/P1)
/// exists. Deterministic (a seeded counter) so tests can assert on it.
pub struct MockFlows {
    session_id: String,
    writer: String,
    seq: u64,
}

impl MockFlows {
    /// A generator for one demo session.
    #[must_use]
    pub fn new() -> Self {
        Self {
            session_id: "demo-session".to_string(),
            writer: "b3:demoagent00".to_string(),
            seq: 0,
        }
    }

    /// Produce the next demo flow record. `now_ms` is supplied by the caller (the
    /// record's timestamp is a display claim, never used for ordering).
    pub fn next(&mut self, now_ms: u64) -> LlmFlowRecord {
        // A small rotation of endpoints so the table looks alive; index by seq.
        const ENDPOINTS: &[(&str, &str, &str, Fidelity)] = &[
            (
                "anthropic",
                "api.anthropic.com:443",
                "claude-fable-5",
                Fidelity::Flow,
            ),
            ("ollama", "127.0.0.1:11434", "llama3.1:8b", Fidelity::Body),
            ("openai", "api.openai.com:443", "gpt-5", Fidelity::Flow),
            ("vllm", "gpu-node:8000", "qwen2.5-coder:32b", Fidelity::Body),
        ];
        let (provider, endpoint, model, fidelity) =
            ENDPOINTS[(self.seq as usize) % ENDPOINTS.len()];
        self.seq += 1;

        let bytes_up = 900 + (self.seq * 137) % 4096;
        let bytes_down = 1500 + (self.seq * 991) % 20_480;
        let usage = if matches!(fidelity, Fidelity::Body) {
            Some(TokenUsage {
                prompt: 200 + (self.seq * 13) % 3000,
                completion: 50 + (self.seq * 29) % 1500,
            })
        } else {
            None
        };

        LlmFlowRecord {
            session_id: self.session_id.clone(),
            writer: self.writer.clone(),
            generation: 1 + self.seq / 8,
            seq: self.seq,
            captured_at_ms: now_ms,
            fidelity,
            direction: Direction::ConnClose,
            provider: provider.to_string(),
            endpoint: endpoint.to_string(),
            model: Some(model.to_string()),
            bytes_up,
            bytes_down,
            dur_ms: 120 + (self.seq * 47) % 4000,
            usage,
        }
    }
}

impl Default for MockFlows {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::DischargeResponse;

    fn b64u(bytes: &[u8]) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    }

    #[test]
    fn assemble_builds_a_discharge_from_a_well_formed_assertion() {
        let challenge = [7u8; 32];
        let response = DischargeResponse::Assertion {
            id: "r1".into(),
            raw_id: b64u(b"cred-abc"),
            authenticator_data: b64u(&[0u8; 37]),
            client_data_json: b64u(br#"{"type":"webauthn.get","challenge":"x"}"#),
            signature: b64u(&[9u8; 64]),
        };
        let d = MockMeshProvider::assemble(&response, &challenge).expect("well-formed");
        assert_eq!(d.credential_id, b"cred-abc");
        assert_eq!(d.challenge, challenge);
        assert!(d.authenticator_data.is_some());
        assert!(d.client_data_json.is_some());
        assert_eq!(d.signature.len(), 64);
    }

    #[test]
    fn assemble_refuses_a_declined_gesture() {
        let response = DischargeResponse::Refused { id: "r1".into() };
        assert_eq!(
            MockMeshProvider::assemble(&response, &[0u8; 32]),
            Err(RelayError::Refused)
        );
    }

    #[test]
    fn assemble_rejects_malformed_base64() {
        let response = DischargeResponse::Assertion {
            id: "r1".into(),
            raw_id: "!!!not base64!!!".into(),
            authenticator_data: b64u(&[0u8; 37]),
            client_data_json: b64u(b"{}"),
            signature: b64u(&[9u8; 64]),
        };
        assert_eq!(
            MockMeshProvider::assemble(&response, &[0u8; 32]),
            Err(RelayError::MalformedField("raw_id"))
        );
    }

    #[test]
    fn mock_flows_are_deterministic_and_ordered() {
        let mut g = MockFlows::new();
        let a = g.next(1000);
        let b = g.next(1000);
        assert_eq!(a.seq, 1);
        assert_eq!(b.seq, 2);
        assert!(
            b.seq > a.seq,
            "seq is the ordering key, strictly increasing"
        );
        // Body-tier records carry token usage; flow-tier do not.
        for rec in [&a, &b] {
            match rec.fidelity {
                Fidelity::Body => assert!(rec.usage.is_some()),
                Fidelity::Flow => assert!(rec.usage.is_none()),
            }
        }
    }

    #[test]
    fn bind_challenge_reuses_core_and_is_stable() {
        let action = ContentId::of_bytes(b"git.push github.com/org/repo");
        let nonce = [3u8; 32];
        let c1 = bind_challenge(&action, 5, &nonce);
        let c2 = bind_challenge(&action, 5, &nonce);
        assert_eq!(c1.as_bytes(), c2.as_bytes(), "same inputs → same challenge");
        let c3 = bind_challenge(&action, 6, &nonce);
        assert_ne!(c1.as_bytes(), c3.as_bytes(), "generation is bound in");
    }
}
