//! `provision-integration` over DIDComm — holder-side driver.
//!
//! Sends a VP-framed bootstrap request to the VTA over an authcrypt'd
//! DIDComm session and opens the sealed `TemplateBootstrap` bundle the
//! VTA returns. One round-trip, end-to-end: issues the mediator's
//! rolled-over admin DID, mints the mediator's own integration DID +
//! keys, and delivers the VTA's trust bundle and `did.jsonl` so the
//! mediator can boot even if the VTA is unreachable on first run.
//!
//! Supersedes the separate "authenticate + rotate + create DID" chain
//! the wizard runs today. The ACL registration (`pnm acl create`) step
//! stays — the VP's sender must already hold admin role in the target
//! context's ACL for the VTA to honour it. This module is only the
//! library layer; wiring into the wizard's phase machine is a separate
//! follow-up change.
//!
//! ## Flow
//!
//! 1. Open a [`vta_sdk::didcomm_session::DIDCommSession`] as the
//!    setup DID.
//! 2. Build + sign a
//!    [`vta_sdk::provision_integration::BootstrapRequest`] asking for
//!    the `didcomm-mediator` template render plus an admin-DID
//!    rollover via the `vta-admin` template.
//! 3. [`vta_sdk::provision_integration::didcomm::provision_integration_didcomm`]
//!    sends the VP, waits for the reply, returns the armored sealed
//!    bundle + digest.
//! 4. Open the bundle locally with the setup key's derived X25519
//!    secret. Pin against the VTA-reported digest to guard against a
//!    swapped bundle.
//! 5. Extract the [`TemplateBootstrapPayload`] and expose it through
//!    [`ProvisionResult`] accessors.
//!
//! ## Error shape
//!
//! Each failure mode maps to a typed [`ProvisionError`] variant with
//! a human-readable message. The wizard surfaces the message verbatim;
//! the operator-facing hint lives at the call site, not here.

use std::collections::BTreeMap;

use chrono::Duration;
use serde_json::Value;
use thiserror::Error;
use vta_sdk::did_key::decode_private_key_multibase;
use vta_sdk::didcomm_session::DIDCommSession;
use vta_sdk::error::VtaError;
use vta_sdk::provision_integration::{
    BootstrapAsk, BootstrapRequest, DidTemplateRef, ProvisionIntegrationError,
    TemplateBootstrapAsk,
    didcomm::provision_integration_didcomm,
    http::ProvisionSummary,
    payload::{DidKeyMaterial, TemplateBootstrapPayload, TemplateOutput},
};
use vta_sdk::sealed_transfer::{SealedPayloadV1, SealedTransferError, armor, open_bundle};

use crate::consts::{DEFAULT_MEDIATOR_TEMPLATE, DEFAULT_VTA_ADMIN_TEMPLATE};

/// Default validity on a wizard-issued VP — chosen to comfortably
/// cover human-paced bundle handoff latency with the verifier's ±5min
/// skew margin, without leaving a stale request valid long enough to
/// resurface.
pub const DEFAULT_VALIDITY: Duration = Duration::minutes(15);

/// Holder-side parameters for a mediator provisioning request.
///
/// Mirrors `TemplateBootstrapAsk` without requiring callers to reach
/// across crates for `DidTemplateRef`. The one-call-site convention
/// (builders + defaults on the wizard side) keeps SDK-shaped types off
/// the wizard's `app.rs` surface.
#[derive(Debug, Clone)]
pub struct ProvisionAsk {
    /// VTA context the mediator will live in. Becomes the ACL scope.
    pub context: String,
    /// Template name for the mediator's integration DID. Defaults to
    /// [`DEFAULT_MEDIATOR_TEMPLATE`].
    pub mediator_template: String,
    /// Variables supplied to the mediator template renderer. Must
    /// satisfy the template's `requiredVars` at the VTA.
    pub mediator_template_vars: BTreeMap<String, Value>,
    /// Template name for the VTA-minted long-term admin DID. When
    /// `None`, the authorization VC's subject stays the setup DID and
    /// no rollover happens — this is the legacy shape and not the
    /// default.
    pub admin_template: Option<String>,
    /// Variables supplied to the admin template renderer. Empty in the
    /// common case; the built-in `vta-admin` template takes none.
    pub admin_template_vars: BTreeMap<String, Value>,
    /// Operator-facing label for audit logs. Not covered by the VP
    /// proof cryptographically, but recorded in provisioning logs.
    pub label: Option<String>,
    /// VP freshness window. Defaults to [`DEFAULT_VALIDITY`].
    pub validity: Duration,
}

impl ProvisionAsk {
    /// Build an ask for a standard mediator provisioning with admin-DID
    /// rollover enabled. The mediator's public URL lands on the
    /// template's `URL` variable — the built-in `didcomm-mediator`
    /// template requires it.
    pub fn mediator(context: impl Into<String>, mediator_url: impl Into<String>) -> Self {
        let mut vars = BTreeMap::new();
        vars.insert("URL".to_string(), Value::String(mediator_url.into()));
        Self {
            context: context.into(),
            mediator_template: DEFAULT_MEDIATOR_TEMPLATE.to_string(),
            mediator_template_vars: vars,
            admin_template: Some(DEFAULT_VTA_ADMIN_TEMPLATE.to_string()),
            admin_template_vars: BTreeMap::new(),
            label: None,
            validity: DEFAULT_VALIDITY,
        }
    }

    /// Attach a human-readable audit label.
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    /// Disable admin-DID rollover — the VC subject stays the setup
    /// DID, and no second DID is minted. Rarely what the wizard
    /// wants; exposed for tests and recipe-driven flows that need the
    /// legacy shape.
    pub fn without_admin_rollover(mut self) -> Self {
        self.admin_template = None;
        self.admin_template_vars.clear();
        self
    }

    pub(crate) fn to_bootstrap_ask(&self) -> BootstrapAsk {
        BootstrapAsk::TemplateBootstrap(TemplateBootstrapAsk {
            context_hint: Some(self.context.clone()),
            template: DidTemplateRef {
                name: self.mediator_template.clone(),
                vars: self.mediator_template_vars.clone(),
            },
            admin_template: self.admin_template.as_ref().map(|n| DidTemplateRef {
                name: n.clone(),
                vars: self.admin_template_vars.clone(),
            }),
            note: self.label.clone(),
        })
    }
}

/// Local mirror of `vta_sdk::provision_integration::http::ProvisionSummary`.
///
/// The upstream type is `Debug + Serialize + Deserialize` but not
/// `Clone` (that'd be a cross-crate API change). We carry the same
/// fields and implement `From<ProvisionSummary>` so callers that
/// receive the SDK type can drop it into wizard state without care.
#[derive(Debug, Clone)]
pub struct ProvisionSummaryLocal {
    /// Ephemeral DID that signed the VP and opens the sealed bundle.
    pub client_did: String,
    /// Long-term admin DID — equals `client_did` when no rollover, or
    /// the VTA-minted DID when the VP carried an `adminTemplate`.
    pub admin_did: String,
    /// `true` when the VTA rolled the admin DID over during provisioning.
    pub admin_rolled_over: bool,
    /// The integration DID the template rendered.
    pub integration_did: String,
    pub template_name: String,
    pub template_kind: String,
    /// Template that rendered the rolled-over admin DID. `None` when no
    /// rollover happened.
    pub admin_template_name: Option<String>,
    /// Hex-encoded 16-byte bundle id (matches the VP nonce).
    pub bundle_id_hex: String,
    pub secret_count: usize,
    pub output_count: usize,
}

impl From<ProvisionSummary> for ProvisionSummaryLocal {
    fn from(s: ProvisionSummary) -> Self {
        Self {
            client_did: s.client_did,
            admin_did: s.admin_did,
            admin_rolled_over: s.admin_rolled_over,
            integration_did: s.integration_did,
            template_name: s.template_name,
            template_kind: s.template_kind,
            admin_template_name: s.admin_template_name,
            bundle_id_hex: s.bundle_id_hex,
            secret_count: s.secret_count,
            output_count: s.output_count,
        }
    }
}

/// Typed view of a successful `provision-integration` round-trip.
///
/// Wraps the opened [`TemplateBootstrapPayload`] alongside the wire-
/// level metadata (bundle id, digest) and the VTA's own summary so
/// callers can audit / persist without digging back into the raw
/// payload.
///
/// `Clone` is derived so the value can ride [`crate::vta_connect::runner::VtaEvent::Connected`]
/// from the background runner task back to the wizard's main loop
/// without wrapping the runner in additional indirection. The
/// underlying [`TemplateBootstrapPayload`] zeroizes on drop — clones
/// hold their own copies but carry the same contract.
#[derive(Debug, Clone)]
pub struct ProvisionResult {
    /// Hex-encoded `bundle_id` (16 bytes). Matches the nonce embedded
    /// in the original VP — useful for cross-checking audit logs.
    pub bundle_id_hex: String,
    /// SHA-256 digest of the armored ciphertext, as returned by the
    /// VTA. The local open already verified against this; downstream
    /// storage may record it for traceability.
    pub digest: String,
    /// Summary block the VTA includes on the response — `admin_did`,
    /// `integration_did`, `admin_rolled_over`, etc. Carried in the
    /// local `Clone`-friendly mirror shape.
    pub summary: ProvisionSummaryLocal,
    /// Full payload. Private key material is zeroized on drop
    /// (via the payload's own impl).
    pub payload: TemplateBootstrapPayload,
}

impl ProvisionResult {
    /// Build a `ProvisionResult` from a raw
    /// [`TemplateBootstrapPayload`] opened via sealed-transfer. The
    /// online DIDComm path has the VTA supply a
    /// [`ProvisionSummary`] alongside the payload; the offline path
    /// doesn't — we synthesise the summary from fields the payload
    /// itself carries so downstream code stays uniform.
    ///
    /// `bundle_id_hex` / `digest` are left empty: the offline path
    /// tracks both on [`crate::sealed_handoff::SealedHandoffState`]
    /// (nonce + SHA-256 of armored ciphertext) and downstream code
    /// has no current consumer for them.
    pub fn from_template_bootstrap_payload(payload: TemplateBootstrapPayload) -> Self {
        let integration_did = payload
            .config
            .did_document
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        // Admin DID = the one key in `secrets` that isn't the
        // integration DID. If neither (legacy no-rollover path) the
        // admin DID equals the integration DID and the mediator uses
        // its own setup key to authenticate — matches the online
        // path's no-rollover convention.
        let admin_did = payload
            .secrets
            .keys()
            .find(|k| **k != integration_did)
            .cloned()
            .unwrap_or_else(|| integration_did.clone());
        let admin_rolled_over = admin_did != integration_did;
        let summary = ProvisionSummaryLocal {
            client_did: admin_did.clone(),
            admin_did,
            admin_rolled_over,
            integration_did,
            template_name: payload.config.template_name.clone(),
            template_kind: payload.config.template_kind.clone(),
            admin_template_name: None,
            bundle_id_hex: String::new(),
            secret_count: payload.secrets.len(),
            output_count: payload.config.outputs.len(),
        };
        Self {
            bundle_id_hex: String::new(),
            digest: String::new(),
            summary,
            payload,
        }
    }

    /// Long-term admin DID the mediator should authenticate as.
    /// Equals [`ProvisionSummary::client_did`] when no rollover
    /// happened, or the freshly-minted admin DID when
    /// [`ProvisionSummary::admin_rolled_over`] is `true`.
    pub fn admin_did(&self) -> &str {
        &self.summary.admin_did
    }

    /// The mediator's own integration DID (rendered from the mediator
    /// template).
    pub fn integration_did(&self) -> &str {
        &self.summary.integration_did
    }

    /// Private key material the mediator needs to authenticate as its
    /// admin DID. Absent if the VTA didn't roll the admin over
    /// (legacy path) — in that case the mediator reuses the setup
    /// DID's own private key.
    pub fn admin_key(&self) -> Option<&DidKeyMaterial> {
        self.payload.secrets.get(self.admin_did())
    }

    /// Private key material for the integration DID (mediator's own
    /// service identity).
    pub fn integration_key(&self) -> Option<&DidKeyMaterial> {
        self.payload.secrets.get(self.integration_did())
    }

    /// `did.jsonl` content for the integration DID when the mediator
    /// template targets webvh. Mediator writes this to its
    /// `/.well-known/did.jsonl` at startup.
    pub fn webvh_log(&self) -> Option<&str> {
        self.payload
            .config
            .outputs
            .iter()
            .find_map(|out| match out {
                TemplateOutput::WebvhLog { did, log } if did == self.integration_did() => {
                    Some(log.as_str())
                }
                _ => None,
            })
    }

    /// REST URL for the VTA. `None` means the integration does not
    /// make outbound REST calls to this VTA (DIDComm-only deployment).
    pub fn vta_url(&self) -> Option<&str> {
        self.payload.config.vta_url.as_deref()
    }

    /// The authorization VC. Opaque JSON; archive for audit or feed to
    /// an `affinidi-vc` verifier if stronger checks are desired.
    pub fn authorization_vc(&self) -> &Value {
        &self.payload.authorization
    }
}

/// Errors from the provisioning driver. Each variant wraps the
/// underlying cause with enough context to render a useful operator
/// message without the caller having to inspect the chain.
#[derive(Debug, Error)]
pub enum ProvisionError {
    /// Setup key's multibase could not be decoded into a 32-byte seed.
    /// Indicates corruption of the on-disk setup-key file — the fix is
    /// to regenerate.
    #[error("setup key is malformed: {0}")]
    SetupKey(String),

    /// Could not build the `DIDCommSession` to the VTA through its
    /// mediator. Wrapped SDK error includes the exact failure (DID
    /// resolution, WebSocket handshake, secrets insertion).
    #[error("could not open DIDComm session to VTA: {0}")]
    SessionOpen(String),

    /// VP construction or signing failed. Callers hitting this
    /// indicate a library bug or a broken signing-key invariant.
    #[error("could not build VP: {0}")]
    VpSign(#[from] ProvisionIntegrationError),

    /// The VTA rejected the request or the DIDComm round-trip
    /// produced a transport-level error. `Forbidden` here usually
    /// means the ACL registration did not land for the setup DID
    /// (re-run `pnm acl create` and retry).
    #[error("provision-integration call failed: {0}")]
    Rpc(#[from] VtaError),

    /// The armored reply could not be parsed or did not contain
    /// exactly one bundle. Either a malformed VTA response or
    /// corruption in transit.
    #[error("sealed reply could not be decoded: {0}")]
    Armor(String),

    /// Opening the HPKE bundle failed. Most common cause: the setup
    /// key's X25519 derivation does not pair with the VTA's seal
    /// recipient (shouldn't happen because the VTA derived the
    /// recipient from the VP's `holder` — fire if it does).
    #[error("could not open sealed bundle: {0}")]
    Open(#[from] SealedTransferError),

    /// The payload was not a `TemplateBootstrap` variant — unexpected
    /// given we asked for that shape.
    #[error("sealed payload was the wrong variant (expected TemplateBootstrap)")]
    WrongPayload,
}

/// Drive a `provision-integration` round-trip end-to-end.
///
/// - `setup_did` / `setup_private_key_mb`: the ephemeral key the
///   operator enrolled on the VTA via `pnm acl create`. The VP is
///   signed with it; the bundle is sealed to it. Its authority at the
///   VTA is gone at the end of the round-trip if `ask.admin_template`
///   was set (default).
/// - `vta_did`: VTA identity.
/// - `mediator_did`: the DIDComm mediator advertised in the VTA's DID
///   doc — required, because this is a DIDComm-only driver.
///
/// Returns a [`ProvisionResult`] the caller can inspect / persist.
pub async fn provision_mediator_integration(
    setup_did: &str,
    setup_private_key_mb: &str,
    vta_did: &str,
    mediator_did: &str,
    ask: &ProvisionAsk,
) -> Result<ProvisionResult, ProvisionError> {
    let seed = decode_private_key_multibase(setup_private_key_mb)
        .map_err(|e| ProvisionError::SetupKey(e.to_string()))?;

    let session = DIDCommSession::connect(setup_did, setup_private_key_mb, vta_did, mediator_did)
        .await
        .map_err(|e| ProvisionError::SessionOpen(e.to_string()))?;

    let nonce: [u8; 16] = rand::random();
    let vp = BootstrapRequest::sign(
        &seed,
        setup_did,
        nonce,
        ask.validity,
        ask.label.clone(),
        ask.to_bootstrap_ask(),
    )
    .await?;

    let response =
        provision_integration_didcomm(&session, vp, ask.context.clone(), None, None).await?;

    let bundles =
        armor::decode(&response.bundle).map_err(|e| ProvisionError::Armor(e.to_string()))?;
    if bundles.len() != 1 {
        return Err(ProvisionError::Armor(format!(
            "expected exactly one armored bundle, found {}",
            bundles.len()
        )));
    }
    let bundle = &bundles[0];
    if bundle.bundle_id != nonce {
        return Err(ProvisionError::Armor(
            "returned bundle_id does not match the VP nonce".into(),
        ));
    }

    let x_secret = vta_sdk::sealed_transfer::ed25519_seed_to_x25519_secret(&seed);
    let opened = open_bundle(&x_secret, bundle, Some(&response.digest))?;

    let payload = match opened.payload {
        SealedPayloadV1::TemplateBootstrap(boxed) => *boxed,
        _ => return Err(ProvisionError::WrongPayload),
    };

    Ok(ProvisionResult {
        bundle_id_hex: hex_lower(&opened.bundle_id),
        digest: response.digest,
        summary: response.summary.into(),
        payload,
    })
}

fn hex_lower(bytes: &[u8]) -> String {
    const T: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(T[(b >> 4) as usize] as char);
        s.push(T[(b & 0xf) as usize] as char);
    }
    s
}

/// Build a synthetic [`ProvisionResult`] for tests that need a fully-
/// populated Connected event without standing up a VTA. `rolled_over`
/// picks between the admin-rollover path (admin DID != client DID)
/// and the legacy no-rollover path.
#[cfg(test)]
pub(crate) fn test_sample_result(rolled_over: bool) -> ProvisionResult {
    use serde_json::json;
    use vta_sdk::provision_integration::payload::{
        KeyPair, TemplateBootstrapConfig, VtaTrustBundle,
    };

    let admin_did = if rolled_over {
        "did:key:z6MkAdmin"
    } else {
        "did:key:z6MkSetup"
    };
    let mediator_did = "did:webvh:mediator.example.com";
    let mut secrets = BTreeMap::new();
    secrets.insert(
        mediator_did.to_string(),
        DidKeyMaterial {
            did: mediator_did.into(),
            signing_key: KeyPair {
                key_id: format!("{mediator_did}#key-1"),
                public_key_multibase: "z6MkSample".into(),
                private_key_multibase: "zPrivateSample".into(),
            },
            ka_key: KeyPair {
                key_id: format!("{mediator_did}#key-2"),
                public_key_multibase: "z6LSSample".into(),
                private_key_multibase: "zKaPrivate".into(),
            },
        },
    );
    if rolled_over {
        secrets.insert(
            admin_did.to_string(),
            DidKeyMaterial {
                did: admin_did.into(),
                signing_key: KeyPair {
                    key_id: format!("{admin_did}#key-1"),
                    public_key_multibase: "z6MkAdminSigning".into(),
                    private_key_multibase: "zAdminSigningPrivate".into(),
                },
                ka_key: KeyPair {
                    key_id: format!("{admin_did}#key-2"),
                    public_key_multibase: "z6LSAdminKa".into(),
                    private_key_multibase: "zAdminKaPrivate".into(),
                },
            },
        );
    }
    let payload = TemplateBootstrapPayload {
        authorization: json!({ "type": ["VerifiableCredential", "VtaAuthorizationCredential"] }),
        secrets,
        config: TemplateBootstrapConfig {
            template_name: DEFAULT_MEDIATOR_TEMPLATE.into(),
            template_kind: "mediator".into(),
            did_document: json!({ "id": mediator_did }),
            outputs: vec![TemplateOutput::WebvhLog {
                did: mediator_did.into(),
                log: "{\"versionId\":\"1-abc\"}\n".into(),
            }],
            vta_url: Some("https://vta.example.com".into()),
            vta_trust: VtaTrustBundle {
                vta_did: "did:webvh:vta.example.com".into(),
                vta_did_document: json!({ "id": "did:webvh:vta.example.com" }),
                vta_did_log: None,
            },
        },
    };
    ProvisionResult {
        bundle_id_hex: "00112233445566778899aabbccddeeff".into(),
        digest: "deadbeef".into(),
        summary: ProvisionSummaryLocal {
            client_did: "did:key:z6MkSetup".into(),
            admin_did: admin_did.into(),
            admin_rolled_over: rolled_over,
            integration_did: mediator_did.into(),
            template_name: DEFAULT_MEDIATOR_TEMPLATE.into(),
            template_kind: "mediator".into(),
            admin_template_name: if rolled_over {
                Some(DEFAULT_VTA_ADMIN_TEMPLATE.into())
            } else {
                None
            },
            bundle_id_hex: "00112233445566778899aabbccddeeff".into(),
            secret_count: if rolled_over { 2 } else { 1 },
            output_count: 1,
        },
        payload,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vta_sdk::provision_integration::payload::KeyPair;

    #[test]
    fn ask_mediator_defaults_include_admin_rollover_and_url_var() {
        let ask = ProvisionAsk::mediator("prod-mediator", "https://mediator.example.com");
        assert_eq!(ask.context, "prod-mediator");
        assert_eq!(ask.mediator_template, DEFAULT_MEDIATOR_TEMPLATE);
        assert_eq!(
            ask.mediator_template_vars["URL"],
            Value::String("https://mediator.example.com".into())
        );
        assert_eq!(
            ask.admin_template.as_deref(),
            Some(DEFAULT_VTA_ADMIN_TEMPLATE)
        );
        assert!(ask.admin_template_vars.is_empty());
        assert_eq!(ask.validity, DEFAULT_VALIDITY);
    }

    #[test]
    fn ask_without_admin_rollover_strips_admin_fields() {
        let ask = ProvisionAsk::mediator("ctx", "https://m").without_admin_rollover();
        assert!(ask.admin_template.is_none());
        assert!(ask.admin_template_vars.is_empty());
    }

    #[test]
    fn ask_to_bootstrap_ask_carries_admin_template() {
        let ask = ProvisionAsk::mediator("ctx", "https://m").with_label("wizard run");
        let BootstrapAsk::TemplateBootstrap(inner) = ask.to_bootstrap_ask();
        assert_eq!(inner.context_hint.as_deref(), Some("ctx"));
        assert_eq!(inner.template.name, DEFAULT_MEDIATOR_TEMPLATE);
        assert_eq!(
            inner.admin_template.as_ref().map(|t| t.name.as_str()),
            Some(DEFAULT_VTA_ADMIN_TEMPLATE)
        );
        assert_eq!(inner.note.as_deref(), Some("wizard run"));
    }

    fn sample_key(did: &str, fragment: &str) -> KeyPair {
        KeyPair {
            key_id: format!("{did}#{fragment}"),
            public_key_multibase: "z6MkSample".into(),
            private_key_multibase: "zPrivateSample".into(),
        }
    }

    fn sample_result(rolled_over: bool) -> ProvisionResult {
        super::test_sample_result(rolled_over)
    }

    #[test]
    fn result_accessors_with_admin_rollover() {
        let r = sample_result(true);
        assert_eq!(r.admin_did(), "did:key:z6MkAdmin");
        assert_eq!(r.integration_did(), "did:webvh:mediator.example.com");
        assert!(r.admin_key().is_some());
        assert!(r.integration_key().is_some());
        assert!(r.webvh_log().is_some());
        assert_eq!(r.vta_url(), Some("https://vta.example.com"));
    }

    #[test]
    fn result_accessors_without_admin_rollover_fall_back_to_client_did() {
        // When the VTA didn't roll over, the admin DID equals the
        // setup DID; the payload's `secrets` map carries the
        // integration DID only, so `admin_key()` returns `None` and
        // callers reuse the setup key as the admin key.
        let r = sample_result(false);
        assert_eq!(r.admin_did(), "did:key:z6MkSetup");
        assert!(r.admin_key().is_none());
        assert!(r.integration_key().is_some());
    }

    #[test]
    fn webvh_log_matches_integration_did_only() {
        // An output for a different DID in the same payload must not
        // satisfy `webvh_log()` — the accessor is DID-scoped.
        let mut r = sample_result(true);
        r.payload.config.outputs = vec![TemplateOutput::WebvhLog {
            did: "did:webvh:unrelated".into(),
            log: "noise".into(),
        }];
        assert!(r.webvh_log().is_none());
    }
}
