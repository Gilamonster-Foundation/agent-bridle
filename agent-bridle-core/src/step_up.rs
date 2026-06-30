//! Human-presence step-up: a third leash outcome between *allow* and *deny*.
//!
//! The base leash decision is two-valued: a call is within the granted authority
//! or it is not (see [`crate::Gate::authorize`]). This module adds a third
//! outcome — **`attest`** — "authorized, but only with a fresh, non-repudiable
//! act of human presence" (a passkey / biometric gesture). It is **not a new
//! authority**: a discharge adds nothing to the grant (`effective` is still
//! `granted.meet(required)`); it sharpens the *liveness condition* under which
//! the same Writ is exercised. So it cannot break attenuation.
//!
//! The design (`newt-agent/docs/design/human-presence-capabilities.md`, paper
//! §7.5):
//!
//! - The [`Gate`](crate::Gate) stays pure and synchronous: it **verifies a
//!   proof** ([`Discharge`]) — it never performs the gesture. A host capability
//!   ([`DischargeProvider`], sibling of [`Sandbox`](crate::Sandbox)) runs the
//!   ceremony; [`Gate::authorize_step_up`](crate::Gate) orchestrates
//!   evaluate→obtain→authorize so the host needs a single call.
//! - The proof is bound to the *exact* action by a content-addressed
//!   [`Challenge`] — what-you-see-is-what-you-sign — so a gesture cannot be
//!   harvested and replayed for a different action.
//! - A verified, recorded gesture becomes a content-addressed [`Attestation`]:
//!   data that carries its own proof of integrity.
//!
//! Content-addressing reuses the mesh's BLAKE3 primitive
//! ([`agent_mesh_protocol::Fingerprint::of_bytes`]) so the whole stack speaks one
//! content-address.

use agent_mesh_protocol::Fingerprint;
use serde::{Deserialize, Serialize};

use crate::{ToolContext, ToolError};

/// Domain-separation tag mixed into every step-up [`Challenge`]. Bumping the
/// version invalidates every previously issued challenge.
const CHALLENGE_DOMAIN: &[u8] = b"agent-bridle/step-up/v1";

// ── Presence ────────────────────────────────────────────────────────────────

/// The strength of human gesture an action demands, weakest to strongest.
///
/// The ordering is **load-bearing**: a discharge satisfies a requirement iff its
/// presence is `>=` the required presence (a `Passkey` over-satisfies a
/// `Prompt`; a `Prompt` never satisfies a `Passkey`). Because attenuation may
/// only *raise* a required presence, this keeps "you can get more restrictive,
/// never less" true for the presence axis too.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Presence {
    /// No human gesture required.
    #[default]
    None,
    /// A soft prompt: any UI affirmation (a typed "yes", a click). Advisory —
    /// it proves a human *chose*, not *who*. (Charter: Tether.)
    Prompt,
    /// A hardware human gesture: a WebAuthn/FIDO2 user-presence (and optional
    /// user-verification) assertion from an authenticator the human controls.
    Passkey,
}

// ── Content-addressed action identity + challenge ────────────────────────────

/// The content address (BLAKE3) of a canonicalized [`CallRequest`] — a stable,
/// collision-resistant identity for "this exact action."
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContentId([u8; 32]);

impl ContentId {
    /// Content-address arbitrary bytes with the mesh's BLAKE3 primitive.
    #[must_use]
    pub fn of_bytes(data: &[u8]) -> Self {
        Self(Fingerprint::of_bytes(data).0)
    }

    /// The raw 32-byte digest.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Lower-hex rendering of the digest.
    #[must_use]
    pub fn to_hex(&self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }
}

/// A what-you-see-is-what-you-sign challenge: the content address of
/// `DOMAIN ‖ action_id ‖ generation ‖ nonce`. The authenticator signs *this*, so
/// a verified signature proves the human authorized that exact action, in that
/// causal generation, for that single-use nonce.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Challenge([u8; 32]);

impl Challenge {
    /// Bind a challenge to an action's [`ContentId`], a causal `generation`
    /// (never wall-clock), and a single-use `nonce`.
    #[must_use]
    pub fn bind(action: &ContentId, generation: u64, nonce: &[u8; 32]) -> Self {
        let mut buf = Vec::with_capacity(CHALLENGE_DOMAIN.len() + 32 + 8 + 32);
        buf.extend_from_slice(CHALLENGE_DOMAIN);
        buf.extend_from_slice(action.as_bytes());
        buf.extend_from_slice(&generation.to_le_bytes());
        buf.extend_from_slice(nonce);
        Self(Fingerprint::of_bytes(&buf).0)
    }

    /// The raw 32-byte challenge the authenticator signs.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// The action a leash decision is about: a tool name, its arguments, and the
/// resolved resource the policy keys on.
///
/// **Resolve before constructing.** A `resource` (and any path-bearing `args`)
/// must already be canonicalized (realpath, normalized refspec) so the human
/// approves the *resolved* effect, not a `..`-bearing alias.
#[derive(Debug, Clone)]
pub struct CallRequest {
    /// The dispatch name of the tool (e.g. `git.push`, `email.send`).
    pub tool: String,
    /// The tool arguments (the MCP `arguments` object).
    pub args: serde_json::Value,
    /// The resolved, policy-relevant resource (e.g. `github.com/org/repo`,
    /// a realpath, a recipient set).
    pub resource: String,
}

impl CallRequest {
    /// Construct a request.
    #[must_use]
    pub fn new(
        tool: impl Into<String>,
        args: serde_json::Value,
        resource: impl Into<String>,
    ) -> Self {
        Self {
            tool: tool.into(),
            args,
            resource: resource.into(),
        }
    }

    /// A request with no arguments and no resource — used by the back-compat
    /// no-step-up path.
    #[must_use]
    pub fn unspecified(tool: impl Into<String>) -> Self {
        Self {
            tool: tool.into(),
            args: serde_json::Value::Null,
            resource: String::new(),
        }
    }

    /// The content address of this action, computed over a canonical
    /// serialization of `(tool, canonical(args), resource)`.
    ///
    /// Canonicalization sorts object keys recursively (so argument order cannot
    /// change the identity) and is robust to whether `serde_json`'s
    /// `preserve_order` feature is enabled. Full RFC 8785 number/string
    /// normalization is a follow-up; for now the byte form is deterministic and
    /// order-independent, which is what the binding requires.
    #[must_use]
    pub fn content_id(&self) -> ContentId {
        let canonical = (
            self.tool.as_str(),
            canonical_json(&self.args),
            self.resource.as_str(),
        );
        let bytes = serde_json::to_vec(&canonical)
            .expect("a (str, Value, str) tuple is always JSON-serializable");
        ContentId::of_bytes(&bytes)
    }
}

/// Recursively rebuild a JSON value with object keys sorted, so the byte form is
/// deterministic regardless of insertion order or the `preserve_order` feature.
fn canonical_json(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let mut sorted = serde_json::Map::new();
            for k in keys {
                sorted.insert(k.clone(), canonical_json(&map[k]));
            }
            serde_json::Value::Object(sorted)
        }
        serde_json::Value::Array(items) => {
            serde_json::Value::Array(items.iter().map(canonical_json).collect())
        }
        other => other.clone(),
    }
}

// ── Requirement, discharge, attestation ──────────────────────────────────────

/// What step-up an action demands before the gate will mint a context for it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestRequirement {
    /// Minimum gesture strength this action demands.
    pub presence: Presence,
    /// Whether a verified gesture must be recorded as a provenance
    /// [`Attestation`] (the `passkey+record` policy decision).
    pub record: bool,
    /// Maximum age, in causal generations (never wall-clock), a discharge may
    /// have. `0` ⇒ it must be bound to the current generation. Enforced via the
    /// [`Challenge`] generation binding.
    pub freshness_generations: u64,
}

impl AttestRequirement {
    /// The empty requirement: no gesture, no record. The base-case for actions
    /// with no step-up policy.
    pub const NONE: Self = Self {
        presence: Presence::None,
        record: false,
        freshness_generations: 0,
    };

    /// A requirement for the given presence (no recording, current-generation
    /// freshness).
    #[must_use]
    pub fn presence(presence: Presence) -> Self {
        Self {
            presence,
            record: false,
            freshness_generations: 0,
        }
    }

    /// A requirement for a hardware gesture **and** a recorded attestation.
    #[must_use]
    pub fn passkey_recorded() -> Self {
        Self {
            presence: Presence::Passkey,
            record: true,
            freshness_generations: 0,
        }
    }

    /// Does this action demand any gesture at all?
    #[must_use]
    pub fn demands_gesture(&self) -> bool {
        self.presence > Presence::None
    }
}

/// A human-presence proof presented to the gate. Crypto-format-agnostic: the
/// `signature` and `credential_id` are opaque bytes a [`DischargeVerifier`]
/// interprets (the MVP software verifier reads them as ed25519).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Discharge {
    /// The gesture strength actually achieved (e.g. user-presence vs. verified).
    pub presence: Presence,
    /// Which authenticator/credential produced the proof (a public-key id).
    pub credential_id: Vec<u8>,
    /// The challenge bytes the authenticator signed.
    pub challenge: [u8; 32],
    /// The assertion signature over the challenge.
    pub signature: Vec<u8>,
}

/// A content-addressed, non-repudiable record that a human authorized a specific
/// action — Provenance that becomes a Scar in the causal log. It carries its own
/// proof: the credential id + signature prove *which* authenticator, the
/// challenge proves *which* action, the generation proves *which* flight.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attestation {
    /// Schema tag for forward-compatible parsing.
    pub schema: String,
    /// The tool whose invocation was authorized.
    pub tool: String,
    /// The resolved resource that was authorized.
    pub resource: String,
    /// The bound challenge the human signed.
    pub challenge: [u8; 32],
    /// The causal generation this authorization is valid for.
    pub generation: u64,
    /// The authenticator/credential id.
    pub credential_id: Vec<u8>,
    /// The assertion signature.
    pub signature: Vec<u8>,
    /// The gesture strength achieved.
    pub presence: Presence,
}

impl Attestation {
    /// Current attestation schema tag.
    pub const SCHEMA: &'static str = "agent-bridle/attestation/v1";

    /// Build a provenance record from a verified discharge for `(tool,
    /// resource)` in `generation`. Called by the gate only *after* a
    /// [`DischargeVerifier`] has accepted the discharge.
    #[must_use]
    pub fn from_verified(
        tool: &str,
        resource: &str,
        discharge: &Discharge,
        generation: u64,
    ) -> Self {
        Self {
            schema: Self::SCHEMA.to_string(),
            tool: tool.to_string(),
            resource: resource.to_string(),
            challenge: discharge.challenge,
            generation,
            credential_id: discharge.credential_id.clone(),
            signature: discharge.signature.clone(),
            presence: discharge.presence,
        }
    }

    /// The content address of this attestation record.
    #[must_use]
    pub fn content_id(&self) -> ContentId {
        let bytes = serde_json::to_vec(self).expect("Attestation is always JSON-serializable");
        ContentId::of_bytes(&bytes)
    }
}

/// Verifies a [`Discharge`] against the requirement and the gate-recomputed
/// [`Challenge`]. **Pure**: it performs no ceremony and no IO — that is a host
/// capability outside the gate. An `Err(reason)` is turned into a leash denial.
pub trait DischargeVerifier {
    /// Accept iff the discharge is a valid proof for `expected`, at or above
    /// `required.presence`. The reason string is safe to surface to the agent.
    fn verify(
        &self,
        discharge: &Discharge,
        required: &AttestRequirement,
        expected: &Challenge,
    ) -> Result<(), String>;
}

/// Runs the human-presence **ceremony** and returns a [`Discharge`] — the dual
/// of [`DischargeVerifier`] (a provider *produces* a proof; a verifier *checks*
/// one).
///
/// This is a **host capability**, a sibling of [`Sandbox`](crate::Sandbox): it
/// performs IO/UI (prompts a passkey, drives an authenticator) and lives in the
/// host, not the gate. The [`Gate`](crate::Gate) never calls it during
/// verification — only [`Gate::authorize_step_up`](crate::Gate) calls it, to
/// orchestrate the evaluate→obtain→authorize sequence on the host's behalf.
///
/// **It is not trusted to self-attest presence.** A provider returns whatever
/// [`Presence`] it claims to have achieved, but the gate (via the
/// [`DischargeVerifier`]) still re-checks `discharge.presence >= required.presence`
/// and that the discharge answers the gate-recomputed [`Challenge`]. A lying or
/// buggy provider can only get its discharge *rejected*, never over-admitted
/// (ADR 0007 D5).
pub trait DischargeProvider {
    /// Run the ceremony for `request` at `required` strength and return a
    /// [`Discharge`] whose `challenge` answers
    /// [`Challenge::bind`]`(&request.content_id(), generation, nonce)`.
    ///
    /// `generation` and the single-use `nonce` are supplied by the caller (the
    /// gate) so the produced proof binds to this exact action, generation, and
    /// nonce — what-you-see-is-what-you-sign. An `Err(reason)` (the human
    /// declined, no authenticator present, a transport failure) becomes a
    /// fail-closed leash denial; the reason is safe to surface to the agent.
    fn obtain(
        &self,
        request: &CallRequest,
        required: &AttestRequirement,
        generation: u64,
        nonce: &[u8; 32],
    ) -> Result<Discharge, String>;
}

/// A presented step-up proof, bundled: the single-use `nonce` the challenge was
/// bound with, the [`Discharge`] itself, and the [`DischargeVerifier`] that
/// checks it. Grouping the "proof" inputs keeps
/// [`Gate::authorize_with_discharge`](crate::Gate) to a small argument list and
/// distinct from the "what" (tool, grant, request, policy).
pub struct DischargeAttempt<'a> {
    /// The single-use nonce the challenge was bound with.
    pub nonce: [u8; 32],
    /// The proof produced by the host after running the ceremony.
    pub discharge: &'a Discharge,
    /// The verifier that checks the proof (pure; performs no ceremony).
    pub verifier: &'a dyn DischargeVerifier,
}

// ── Decision ─────────────────────────────────────────────────────────────────

/// The gate's verdict for one call under a step-up policy.
#[derive(Debug)]
pub enum Decision {
    /// Authorized with no step-up owed — the minted context, exactly as today.
    Allow(ToolContext),
    /// Refused. Fail-closed; this always wins.
    Deny(ToolError),
    /// Conditionally authorized: obtain a discharge satisfying the requirement
    /// and re-present it to [`Gate::authorize_with_discharge`](crate::Gate). No
    /// context is minted and no budget is charged here.
    NeedsDischarge(AttestRequirement),
}

// ── Policy ───────────────────────────────────────────────────────────────────

/// One policy rule mapping an action selector to a required step-up.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    /// `"<tool>"` or `"<tool>:<resource-glob>"`. The glob supports a single
    /// trailing `*` (or `**`) meaning prefix-match.
    pub selector: String,
    /// The step-up this rule demands when it matches.
    pub requirement: AttestRequirement,
}

impl Rule {
    fn matches(&self, request: &CallRequest) -> bool {
        let (tool, resource_glob) = match self.selector.split_once(':') {
            Some((tool, glob)) => (tool, Some(glob)),
            None => (self.selector.as_str(), None),
        };
        if tool != request.tool {
            return false;
        }
        match resource_glob {
            None => true,
            Some(glob) => glob_prefix_match(glob, &request.resource),
        }
    }
}

/// Exact match, or prefix-match when `pattern` ends in `*` / `**`.
fn glob_prefix_match(pattern: &str, text: &str) -> bool {
    if let Some(prefix) = pattern.strip_suffix('*') {
        let prefix = prefix.strip_suffix('*').unwrap_or(prefix);
        text.starts_with(prefix)
    } else {
        pattern == text
    }
}

/// The per-action step-up policy: a set of selector rules plus a fall-through
/// default. Most-specific (longest matching selector) wins. This is the
/// authoring surface behind the operator menu (*yes once / yes always / yes on
/// passkey / no*); it composes *on top of* the `Caveats` grant — `Caveats`
/// decides whether the authority exists, this decides what gesture admits its
/// use.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StepUpPolicy {
    /// Selector rules, evaluated most-specific-wins.
    pub rules: Vec<Rule>,
    /// The requirement for any action no rule matches.
    pub default: AttestRequirement,
}

impl StepUpPolicy {
    /// The empty policy: nothing ever needs a gesture. Used by the back-compat
    /// no-step-up path so existing behavior is unchanged.
    pub const EMPTY: Self = Self {
        rules: Vec::new(),
        default: AttestRequirement::NONE,
    };

    /// A policy with the given rules and default.
    #[must_use]
    pub fn new(rules: Vec<Rule>, default: AttestRequirement) -> Self {
        Self { rules, default }
    }

    /// The strongest requirement matching `request` (longest selector wins), or
    /// the policy default when none match.
    #[must_use]
    pub fn required_for(&self, request: &CallRequest) -> AttestRequirement {
        let mut best: Option<&Rule> = None;
        for rule in &self.rules {
            if rule.matches(request) && best.is_none_or(|b| rule.selector.len() > b.selector.len())
            {
                best = Some(rule);
            }
        }
        best.map_or_else(|| self.default.clone(), |r| r.requirement.clone())
    }
}

impl Default for StepUpPolicy {
    fn default() -> Self {
        Self::EMPTY
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Caveats, CountBound, Gate, Tool, ToolError, ToolResult};
    use ed25519_dalek::{Signer, SigningKey, VerifyingKey};

    /// A trivial tool, named so policy selectors can match it.
    struct NamedTool(&'static str);
    #[async_trait::async_trait]
    impl Tool for NamedTool {
        fn name(&self) -> &str {
            self.0
        }
        fn schema(&self) -> serde_json::Value {
            serde_json::json!({})
        }
        async fn invoke(
            &self,
            _args: serde_json::Value,
            _cx: &ToolContext,
        ) -> ToolResult<serde_json::Value> {
            Ok(serde_json::Value::Null)
        }
    }

    /// The MVP stub verifier: reads `credential_id`/`signature` as ed25519 and
    /// checks the assertion over the gate-recomputed challenge. A real
    /// WebAuthn/CTAP2 verifier (a host capability) lands in a later PR.
    struct SoftwareVerifier;
    impl DischargeVerifier for SoftwareVerifier {
        fn verify(
            &self,
            discharge: &Discharge,
            required: &AttestRequirement,
            expected: &Challenge,
        ) -> Result<(), String> {
            if discharge.presence < required.presence {
                return Err(format!(
                    "presence {:?} is below required {:?}",
                    discharge.presence, required.presence
                ));
            }
            if &discharge.challenge != expected.as_bytes() {
                return Err("discharge does not answer this action's challenge".into());
            }
            let vk_bytes: [u8; 32] = discharge
                .credential_id
                .as_slice()
                .try_into()
                .map_err(|_| "credential id is not a 32-byte ed25519 key".to_string())?;
            let vk = VerifyingKey::from_bytes(&vk_bytes).map_err(|e| e.to_string())?;
            let sig_bytes: [u8; 64] = discharge
                .signature
                .as_slice()
                .try_into()
                .map_err(|_| "signature is not 64 bytes".to_string())?;
            let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
            vk.verify_strict(expected.as_bytes(), &sig)
                .map_err(|e| e.to_string())
        }
    }

    /// Deterministic test key (a fixed seed — never a real secret).
    fn test_key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    /// Build a discharge by signing the challenge for `request` at `generation`.
    fn sign_discharge(
        key: &SigningKey,
        request: &CallRequest,
        generation: u64,
        nonce: &[u8; 32],
        presence: Presence,
    ) -> Discharge {
        let challenge = Challenge::bind(&request.content_id(), generation, nonce);
        let sig = key.sign(challenge.as_bytes());
        Discharge {
            presence,
            credential_id: key.verifying_key().to_bytes().to_vec(),
            challenge: *challenge.as_bytes(),
            signature: sig.to_bytes().to_vec(),
        }
    }

    fn push_policy() -> StepUpPolicy {
        StepUpPolicy::new(
            vec![Rule {
                selector: "git.push:github.com/org/*".to_string(),
                requirement: AttestRequirement::passkey_recorded(),
            }],
            AttestRequirement::NONE,
        )
    }

    fn push_request() -> CallRequest {
        CallRequest::new(
            "git.push",
            serde_json::json!({"ref": "refs/heads/main"}),
            "github.com/org/repo",
        )
    }

    #[test]
    fn presence_is_totally_ordered_none_prompt_passkey() {
        assert!(Presence::None < Presence::Prompt);
        assert!(Presence::Prompt < Presence::Passkey);
    }

    #[test]
    fn content_id_is_deterministic_and_argument_order_independent() {
        let a = CallRequest::new(
            "email.send",
            serde_json::json!({"to": "x", "subj": "y"}),
            "r",
        );
        let b = CallRequest::new(
            "email.send",
            serde_json::json!({"subj": "y", "to": "x"}),
            "r",
        );
        assert_eq!(
            a.content_id(),
            b.content_id(),
            "key order must not change identity"
        );
        let c = CallRequest::new(
            "email.send",
            serde_json::json!({"to": "z", "subj": "y"}),
            "r",
        );
        assert_ne!(a.content_id(), c.content_id(), "different args must differ");
    }

    /// Regression: a step-up requirement must NOT mint a context or charge a
    /// call — the gate withholds the leash until a proof is presented.
    #[test]
    fn needs_discharge_does_not_mint_or_charge() {
        let gate = Gate::with_budget(0, CountBound::AtMost(1));
        let granted = Caveats::top();
        let tool = NamedTool("git.push");
        // First, an action the policy gates: must return NeedsDischarge.
        match gate.evaluate(&tool, &granted, &push_request(), &push_policy()) {
            Decision::NeedsDischarge(req) => assert_eq!(req.presence, Presence::Passkey),
            other => panic!("expected NeedsDischarge, got {other:?}"),
        }
        // The single budgeted call must still be available — proving the
        // NeedsDischarge above charged nothing.
        let free = NamedTool("free.tool");
        match gate.evaluate(
            &free,
            &granted,
            &CallRequest::unspecified("free.tool"),
            &StepUpPolicy::EMPTY,
        ) {
            Decision::Allow(cx) => assert!(cx.caveats().leq(&granted)),
            other => panic!("expected Allow, got {other:?}"),
        }
    }

    /// A valid discharge over the bound challenge mints the context and records
    /// the attestation; the context still carries least authority.
    #[test]
    fn valid_discharge_mints_and_records() {
        let gate = Gate::new(0);
        let granted = Caveats::top();
        let tool = NamedTool("git.push");
        let req = push_request();
        let nonce = [9u8; 32];
        let discharge = sign_discharge(&test_key(), &req, 0, &nonce, Presence::Passkey);
        let attempt = DischargeAttempt {
            nonce,
            discharge: &discharge,
            verifier: &SoftwareVerifier,
        };

        let (cx, attestation) = gate
            .authorize_with_discharge(&tool, &granted, &req, &push_policy(), &attempt)
            .expect("valid discharge authorizes");
        assert!(cx.caveats().leq(&granted));
        let attestation = attestation.expect("passkey+record must produce an attestation");
        assert_eq!(attestation.tool, "git.push");
        assert_eq!(attestation.resource, "github.com/org/repo");
        // The record is content-addressed and stable.
        assert_eq!(attestation.content_id(), attestation.content_id());
    }

    /// A test [`DischargeProvider`] standing in for the host ceremony: it signs
    /// the bound challenge with a fixed key at a chosen presence (the gesture's
    /// effect, stubbed — no real authenticator).
    struct MockProvider {
        key: SigningKey,
        presence: Presence,
    }
    impl DischargeProvider for MockProvider {
        fn obtain(
            &self,
            request: &CallRequest,
            _required: &AttestRequirement,
            generation: u64,
            nonce: &[u8; 32],
        ) -> Result<Discharge, String> {
            Ok(sign_discharge(
                &self.key,
                request,
                generation,
                nonce,
                self.presence,
            ))
        }
    }

    /// A provider whose ceremony fails — the human declined, or no authenticator
    /// is present.
    struct FailingProvider;
    impl DischargeProvider for FailingProvider {
        fn obtain(
            &self,
            _request: &CallRequest,
            _required: &AttestRequirement,
            _generation: u64,
            _nonce: &[u8; 32],
        ) -> Result<Discharge, String> {
            Err("ceremony failed: human declined".into())
        }
    }

    /// The #61 orchestration helper: a provider that produces a valid passkey
    /// discharge drives `evaluate→obtain→authorize` to a minted context and a
    /// recorded attestation in a single call.
    #[test]
    fn provider_obtain_then_authorize_mints_and_records() {
        let gate = Gate::new(0);
        let granted = Caveats::top();
        let tool = NamedTool("git.push");
        let provider = MockProvider {
            key: test_key(),
            presence: Presence::Passkey,
        };
        let (cx, attestation) = gate
            .authorize_step_up(
                &tool,
                &granted,
                &push_request(),
                &push_policy(),
                &provider,
                &SoftwareVerifier,
                [11u8; 32],
            )
            .expect("a valid provider discharge authorizes");
        assert!(cx.caveats().leq(&granted));
        let attestation = attestation.expect("passkey+record must produce an attestation");
        assert_eq!(attestation.tool, "git.push");
    }

    /// Fail-closed: a provider whose ceremony errors makes the helper deny and
    /// mint/charge nothing — the single budgeted call survives (mirrors
    /// `needs_discharge_does_not_mint_or_charge`).
    #[test]
    fn provider_error_fails_closed() {
        let gate = Gate::with_budget(0, CountBound::AtMost(1));
        let granted = Caveats::top();
        let tool = NamedTool("git.push");
        let err = gate
            .authorize_step_up(
                &tool,
                &granted,
                &push_request(),
                &push_policy(),
                &FailingProvider,
                &SoftwareVerifier,
                [12u8; 32],
            )
            .expect_err("a failed ceremony is fail-closed");
        assert!(matches!(err, ToolError::Denied { .. }));
        // The single budgeted call is untouched — proving nothing was charged.
        let free = NamedTool("free.tool");
        match gate.evaluate(
            &free,
            &granted,
            &CallRequest::unspecified("free.tool"),
            &StepUpPolicy::EMPTY,
        ) {
            Decision::Allow(cx) => assert!(cx.caveats().leq(&granted)),
            other => panic!("expected Allow, got {other:?}"),
        }
    }

    /// The verifier — not the provider — decides: a provider that only achieves
    /// `Prompt` cannot satisfy the policy's `Passkey` requirement, even though it
    /// returned `Ok`. The gate re-checks presence regardless of what the
    /// provider claimed (ADR 0007 D5).
    #[test]
    fn provider_below_required_presence_is_denied() {
        let gate = Gate::new(0);
        let granted = Caveats::top();
        let tool = NamedTool("git.push");
        let provider = MockProvider {
            key: test_key(),
            presence: Presence::Prompt,
        };
        let err = gate
            .authorize_step_up(
                &tool,
                &granted,
                &push_request(),
                &push_policy(),
                &provider,
                &SoftwareVerifier,
                [13u8; 32],
            )
            .expect_err("a Prompt provider cannot satisfy a Passkey policy");
        assert!(matches!(err, ToolError::Denied { .. }));
    }

    /// When no step-up is owed, the helper degenerates to an ordinary authorize:
    /// it never runs the ceremony and returns no attestation.
    #[test]
    fn authorize_step_up_without_gesture_degenerates_to_authorize() {
        let gate = Gate::new(0);
        let granted = Caveats::top();
        let free = NamedTool("free.tool");
        let provider = MockProvider {
            key: test_key(),
            presence: Presence::Passkey,
        };
        let (cx, attestation) = gate
            .authorize_step_up(
                &free,
                &granted,
                &CallRequest::unspecified("free.tool"),
                &StepUpPolicy::EMPTY,
                &provider,
                &SoftwareVerifier,
                [14u8; 32],
            )
            .expect("no gesture owed → ordinary authorize");
        assert!(cx.caveats().leq(&granted));
        assert!(attestation.is_none(), "no step-up → no attestation");
    }

    /// Anti-theater: a discharge signed for a DIFFERENT action (different nonce)
    /// is rejected. This fails only because the challenge is bound to the exact
    /// action — a generic gesture would pass.
    #[test]
    fn wrong_challenge_is_denied() {
        let gate = Gate::new(0);
        let granted = Caveats::top();
        let tool = NamedTool("git.push");
        let req = push_request();
        // Sign over a different nonce than the one the gate will recompute with.
        let discharge = sign_discharge(&test_key(), &req, 0, &[1u8; 32], Presence::Passkey);
        let attempt = DischargeAttempt {
            nonce: [2u8; 32], // gate's nonce differs → expected challenge differs
            discharge: &discharge,
            verifier: &SoftwareVerifier,
        };
        let err = gate
            .authorize_with_discharge(&tool, &granted, &req, &push_policy(), &attempt)
            .expect_err("mismatched challenge must be denied");
        assert!(matches!(err, ToolError::Denied { .. }));
    }

    /// Fail-closed: a too-weak gesture (Prompt) cannot satisfy a Passkey
    /// requirement.
    #[test]
    fn presence_too_weak_fails_closed() {
        let gate = Gate::new(0);
        let granted = Caveats::top();
        let tool = NamedTool("git.push");
        let req = push_request();
        let nonce = [4u8; 32];
        // Correct challenge, but only Prompt strength.
        let discharge = sign_discharge(&test_key(), &req, 0, &nonce, Presence::Prompt);
        let attempt = DischargeAttempt {
            nonce,
            discharge: &discharge,
            verifier: &SoftwareVerifier,
        };
        let err = gate
            .authorize_with_discharge(&tool, &granted, &req, &push_policy(), &attempt)
            .expect_err("Prompt cannot satisfy Passkey");
        assert!(matches!(err, ToolError::Denied { .. }));
    }

    /// ADR 0007 D2/D3 (design §10 Q3): the **no-authenticator** case. A
    /// `Presence::None` discharge — "no hardware gesture was achievable" — over
    /// the *correctly bound* challenge still cannot satisfy a `Passkey`
    /// requirement. This isolates the presence floor (the challenge matches, so
    /// the only reason to deny is presence), and is distinct from
    /// `presence_too_weak_fails_closed` (which covers `Prompt`): it proves the
    /// gate fails closed and never silently downgrades when *no* presence is
    /// achievable, rather than only when a weaker-but-nonzero one is.
    #[test]
    fn no_authenticator_presence_none_cannot_satisfy_passkey() {
        let gate = Gate::new(0);
        let granted = Caveats::top();
        let tool = NamedTool("git.push");
        let req = push_request();
        let nonce = [5u8; 32];
        // Correctly bound challenge (same nonce the gate recomputes with), but
        // the achieved presence is None — the "no authenticator available" case.
        let discharge = sign_discharge(&test_key(), &req, 0, &nonce, Presence::None);
        let attempt = DischargeAttempt {
            nonce,
            discharge: &discharge,
            verifier: &SoftwareVerifier,
        };
        let err = gate
            .authorize_with_discharge(&tool, &granted, &req, &push_policy(), &attempt)
            .expect_err("Presence::None cannot satisfy Passkey");
        assert!(matches!(err, ToolError::Denied { .. }));
    }

    #[test]
    fn policy_most_specific_wins_and_default_applies() {
        let policy = StepUpPolicy::new(
            vec![
                Rule {
                    selector: "fs.delete:/tmp/*".to_string(),
                    requirement: AttestRequirement::presence(Presence::Prompt),
                },
                Rule {
                    selector: "fs.delete:/tmp/important/*".to_string(),
                    requirement: AttestRequirement::presence(Presence::Passkey),
                },
            ],
            AttestRequirement::NONE,
        );
        // Longer selector wins for the nested path.
        let nested = CallRequest::new("fs.delete", serde_json::Value::Null, "/tmp/important/x");
        assert_eq!(policy.required_for(&nested).presence, Presence::Passkey);
        // Broad path matches only the short rule.
        let broad = CallRequest::new("fs.delete", serde_json::Value::Null, "/tmp/scratch");
        assert_eq!(policy.required_for(&broad).presence, Presence::Prompt);
        // Unmatched tool falls through to the default.
        let other = CallRequest::new("email.read", serde_json::Value::Null, "inbox");
        assert_eq!(policy.required_for(&other).presence, Presence::None);
    }
}
