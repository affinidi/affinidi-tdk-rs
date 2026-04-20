//! Air-gapped sealed-handoff bootstrap consumer.
//!
//! Replaces the legacy "Cold-start" mode. Three logical phases live in
//! one place so the wizard can stay focused on UX:
//!
//! 1. **Generate request** — mint an ephemeral X25519 keypair and a
//!    16-byte nonce, render a [`vta_sdk::sealed_transfer::BootstrapRequest`]
//!    JSON for the operator to ship out-of-band to the VTA admin.
//! 2. **Receive bundle** — accept armored bytes from a paste buffer or
//!    a file, decode with [`vta_sdk::sealed_transfer::armor::decode`],
//!    surface bundle id + chunk count + computed digest.
//! 3. **Open** — verify the optional out-of-band digest, run
//!    [`vta_sdk::sealed_transfer::open_bundle`], project the
//!    [`SealedPayloadV1::AdminCredential`] variant onto a [`VtaSession`]
//!    so `generate_and_write` provisions the mediator backend.
//!
//! Zero network calls — the entire flow is local to the wizard host.
//! That property is what the mode is *for*; if you find yourself adding
//! a `reqwest` import here, stop and use the Online VTA flow instead.
//!
//! The UI rendering lives in `ui/sealed_handoff.rs`; this module is
//! deliberately UI-agnostic so it can be unit-tested without ratatui.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use rand::TryRngCore;
use tracing::info;
use vta_sdk::credentials::CredentialBundle;
use vta_sdk::sealed_transfer::{
    BootstrapRequest, SealedBundle, SealedPayloadV1, armor, bundle_digest, generate_keypair,
    open_bundle,
};

use crate::vta_connect::VtaSession;

/// Linear progress through the air-gapped flow. The wizard advances
/// strictly in order — each phase has a single well-defined exit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealedPhase {
    /// Bootstrap request rendered; waiting for the operator to dismiss
    /// (move to the paste step).
    RequestGenerated,
    /// Waiting for an armored bundle to be pasted in or loaded from a
    /// file. Anything that decodes cleanly advances; anything that
    /// doesn't keeps the operator on this phase with `last_error` set.
    AwaitingBundle,
    /// Bundle is parsed; optional out-of-band digest verification.
    /// Empty input means "skip the digest check" — that decision is
    /// surfaced explicitly in the prompt so the operator can't skip it
    /// by accident.
    DigestVerify,
    /// Bundle opened, payload extracted, [`VtaSession`] ready. The
    /// wizard transitions out of the sub-flow on Enter.
    Complete,
}

/// Ephemeral state for the sealed-handoff sub-flow.
///
/// Carries the consumer-side ephemeral X25519 secret in plaintext while
/// the wizard runs. Never serialised — same rule as `VtaConnectState`.
pub struct SealedHandoffState {
    pub phase: SealedPhase,
    /// Consumer's X25519 secret. Required to open the returned bundle;
    /// dropped when the sub-flow exits.
    pub recipient_secret: [u8; 32],
    /// Raw 16-byte nonce that anchors the bundle (must round-trip
    /// through the VTA admin's reply).
    pub nonce: [u8; 16],
    /// JSON-serialised [`BootstrapRequest`] the operator hands to the
    /// VTA admin. Persisted on state so the renderer can show it
    /// across re-renders without re-serialising.
    pub request_json: String,
    /// Parsed armored bundle, populated on transition into
    /// [`SealedPhase::DigestVerify`].
    pub bundle: Option<SealedBundle>,
    /// Computed SHA-256 of the parsed bundle, displayed alongside the
    /// digest-entry prompt as a courtesy "this is what the producer
    /// should have shown you".
    pub computed_digest: Option<String>,
    /// Successful open result projected onto a `VtaSession`. The
    /// wizard moves this onto `WizardApp.vta_session` when the
    /// sub-flow completes.
    pub session: Option<VtaSession>,
    /// Last error surfaced to the user — armor decode failures, digest
    /// mismatches, missing payload variants. Cleared on every
    /// successful transition.
    pub last_error: Option<String>,
}

impl SealedHandoffState {
    /// Mint a fresh keypair + nonce + bootstrap-request JSON. Called
    /// when the operator picks "VTA Sealed handoff" on the Vta step.
    /// Uses [`generate_keypair`], so the keypair is fresh per wizard
    /// run and the nonce binds the eventual reply to *this* request.
    pub fn new(label: Option<String>) -> Result<Self, SealedHandoffError> {
        // `generate_keypair` returns the secret wrapped in `Zeroizing`
        // for safe drop; the wizard already keeps the value in
        // process memory for the lifetime of the sub-flow, so unwrap
        // it eagerly into a plain array — the consuming `open_bundle`
        // takes `&[u8; 32]`.
        let (sk_zeroizing, pk) = generate_keypair();
        let sk: [u8; 32] = *sk_zeroizing;
        let mut nonce = [0u8; 16];
        rand::rng()
            .try_fill_bytes(&mut nonce)
            .map_err(|e| SealedHandoffError::Internal(format!("nonce generation failed: {e}")))?;
        let request = BootstrapRequest::new(pk, nonce, label);
        let request_json = serde_json::to_string_pretty(&request).map_err(|e| {
            SealedHandoffError::Internal(format!("BootstrapRequest serialise failed: {e}"))
        })?;
        Ok(Self {
            phase: SealedPhase::RequestGenerated,
            recipient_secret: sk,
            nonce,
            request_json,
            bundle: None,
            computed_digest: None,
            session: None,
            last_error: None,
        })
    }

    /// Bundle id (16 raw bytes → base64url) used in display text. Stable
    /// across re-renders since the nonce is constant for the run.
    pub fn nonce_display(&self) -> String {
        B64URL.encode(self.nonce)
    }
}

/// Failures the consumer can surface to the operator. Distinct from
/// `vta_sdk::sealed_transfer::SealedTransferError` because we want
/// human-friendly framing for paste-in / file-load failures rather than
/// the SDK's lower-level discriminants.
#[derive(Debug)]
pub enum SealedHandoffError {
    ArmorDecode(String),
    BundleCount(usize),
    DigestMismatch {
        expected: String,
        got: String,
    },
    WrongPayload,
    Open(String),
    FileRead {
        path: String,
        source: std::io::Error,
    },
    Internal(String),
}

impl std::fmt::Display for SealedHandoffError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ArmorDecode(e) => write!(f, "could not parse the armored bundle: {e}"),
            Self::BundleCount(n) => {
                write!(
                    f,
                    "expected exactly one bundle in the armored input, found {n}"
                )
            }
            Self::DigestMismatch { expected, got } => write!(
                f,
                "provided digest did not match the bundle: expected {expected}, got {got}"
            ),
            Self::WrongPayload => write!(f, "bundle did not contain a mediator admin credential"),
            Self::Open(e) => write!(f, "could not open the sealed bundle: {e}"),
            Self::FileRead { path, source } => {
                write!(f, "could not read bundle file '{path}': {source}")
            }
            Self::Internal(e) => write!(f, "internal error: {e}"),
        }
    }
}

impl std::error::Error for SealedHandoffError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::FileRead { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// Decode armored bytes (paste OR file) into a single sealed bundle and
/// stash it onto the state, advancing to the digest-verify phase. The
/// computed digest is recorded so the verify prompt can surface
/// "expected vs. computed" in one screen.
pub fn ingest_armored(
    state: &mut SealedHandoffState,
    armored: &str,
) -> Result<(), SealedHandoffError> {
    state.last_error = None;
    let bundles =
        armor::decode(armored).map_err(|e| SealedHandoffError::ArmorDecode(e.to_string()))?;
    if bundles.len() != 1 {
        return Err(SealedHandoffError::BundleCount(bundles.len()));
    }
    let bundle = bundles.into_iter().next().expect("len() == 1");
    state.computed_digest = Some(bundle_digest(&bundle));
    state.bundle = Some(bundle);
    state.phase = SealedPhase::DigestVerify;
    info!(
        bundle_id = %state.nonce_display(),
        "Sealed handoff: armored bundle parsed"
    );
    Ok(())
}

/// Read armored bytes from a file and feed them into [`ingest_armored`].
/// Path errors are wrapped as [`SealedHandoffError::FileRead`] so the UI
/// can present them alongside the paste-failure cases.
pub fn ingest_armored_file(
    state: &mut SealedHandoffState,
    path: &str,
) -> Result<(), SealedHandoffError> {
    let armored = std::fs::read_to_string(path).map_err(|e| SealedHandoffError::FileRead {
        path: path.to_string(),
        source: e,
    })?;
    ingest_armored(state, &armored)
}

/// Verify the (optional) operator-supplied digest matches the bundle's
/// canonical digest, then `open_bundle` the payload, project to a
/// [`VtaSession`], and advance to [`SealedPhase::Complete`].
///
/// `expected_digest` is the operator's input verbatim. Empty / whitespace
/// means "skip the OOB check" — the AEAD inside the bundle still
/// authenticates the payload, but the operator forgoes the producer-
/// declared digest binding.
pub fn open_with_digest(
    state: &mut SealedHandoffState,
    expected_digest: &str,
) -> Result<(), SealedHandoffError> {
    state.last_error = None;
    let bundle = state.bundle.as_ref().ok_or_else(|| {
        SealedHandoffError::Internal("open_with_digest called before ingest_armored".into())
    })?;
    let trimmed = expected_digest.trim();
    let expect = if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_lowercase())
    };
    let opened =
        open_bundle(&state.recipient_secret, bundle, expect.as_deref()).map_err(|e| match e {
            vta_sdk::sealed_transfer::SealedTransferError::DigestMismatch { expected, got } => {
                SealedHandoffError::DigestMismatch { expected, got }
            }
            other => SealedHandoffError::Open(other.to_string()),
        })?;

    let credential: CredentialBundle = match opened.payload {
        SealedPayloadV1::AdminCredential(boxed) => *boxed,
        _ => return Err(SealedHandoffError::WrongPayload),
    };

    state.session = Some(VtaSession {
        // Sealed handoff carries the credential, not a live REST URL.
        // The mediator's runtime VTA loader will pick the URL from the
        // credential's vta_did resolution, so an empty value here is
        // intentional rather than a placeholder.
        rest_url: String::new(),
        access_token: String::new(),
        // `context` lands on AdminCredential at provisioning time;
        // we keep the wizard's notion of "context_id" empty for the
        // sealed flow because the operator hasn't picked one — the
        // VTA admin chose it when they sealed the bundle.
        context_id: String::new(),
        vta_did: credential.vta_did.clone(),
        admin_did: credential.did.clone(),
        admin_private_key_mb: credential.private_key_multibase.clone(),
    });
    state.phase = SealedPhase::Complete;
    info!(
        admin_did = %credential.did,
        vta_did = %credential.vta_did,
        bundle_id = %state.nonce_display(),
        "Sealed handoff: bundle opened, admin credential extracted"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use vta_sdk::sealed_transfer::{
        AssertionProof, InMemoryNonceStore, ProducerAssertion, SealedPayloadV1, seal_payload,
    };

    fn assertion_for(pubkey: &[u8; 32]) -> ProducerAssertion {
        ProducerAssertion {
            producer_pubkey_b64: B64URL.encode(pubkey),
            proof: AssertionProof::PinnedOnly,
        }
    }

    #[test]
    fn new_state_renders_request_json() {
        let state = SealedHandoffState::new(Some("test".into())).unwrap();
        assert_eq!(state.phase, SealedPhase::RequestGenerated);
        assert!(state.request_json.contains("\"version\""));
        assert!(state.request_json.contains("\"client_pubkey\""));
        assert!(state.request_json.contains("\"nonce\""));
    }

    #[tokio::test]
    async fn round_trip_through_consumer_yields_session() {
        // Stand in for the VTA admin: produce a real sealed bundle
        // addressed to the consumer's pubkey, then drive the wizard
        // helpers to open it.
        let mut state = SealedHandoffState::new(None).unwrap();

        // Recover the consumer's pubkey from the request JSON so the
        // producer side seals to the right recipient.
        let parsed_request: BootstrapRequest = serde_json::from_str(&state.request_json).unwrap();
        let recipient_pk = parsed_request.decode_client_pubkey().unwrap();

        let (_prod_sk, prod_pk) = generate_keypair();
        let payload = SealedPayloadV1::AdminCredential(Box::new(CredentialBundle::new(
            "did:key:z6MkConsumer",
            "z3uADMIN",
            "did:webvh:vta.example.com",
        )));
        let store = InMemoryNonceStore::new();
        let bundle = seal_payload(
            &recipient_pk,
            state.nonce,
            assertion_for(&prod_pk),
            &payload,
            &store,
        )
        .await
        .unwrap();
        let armored = armor::encode(&bundle);

        ingest_armored(&mut state, &armored).unwrap();
        assert_eq!(state.phase, SealedPhase::DigestVerify);
        let digest = state
            .computed_digest
            .clone()
            .expect("digest computed on ingest");

        // Verify with the matching digest succeeds.
        open_with_digest(&mut state, &digest).unwrap();
        assert_eq!(state.phase, SealedPhase::Complete);
        let session = state.session.as_ref().expect("session populated on open");
        assert_eq!(session.admin_did, "did:key:z6MkConsumer");
        assert_eq!(session.vta_did, "did:webvh:vta.example.com");
        assert_eq!(session.admin_private_key_mb, "z3uADMIN");
    }

    #[test]
    fn ingest_rejects_garbage() {
        let mut state = SealedHandoffState::new(None).unwrap();
        let err = ingest_armored(&mut state, "not an armored bundle").unwrap_err();
        assert!(matches!(err, SealedHandoffError::ArmorDecode(_)));
        assert_eq!(state.phase, SealedPhase::RequestGenerated);
    }

    #[tokio::test]
    async fn open_rejects_digest_mismatch() {
        let mut state = SealedHandoffState::new(None).unwrap();
        let parsed_request: BootstrapRequest = serde_json::from_str(&state.request_json).unwrap();
        let recipient_pk = parsed_request.decode_client_pubkey().unwrap();
        let (_prod_sk, prod_pk) = generate_keypair();
        let payload = SealedPayloadV1::AdminCredential(Box::new(CredentialBundle::new(
            "did:key:z6MkX",
            "zKEY",
            "did:webvh:y",
        )));
        let store = InMemoryNonceStore::new();
        let bundle = seal_payload(
            &recipient_pk,
            state.nonce,
            assertion_for(&prod_pk),
            &payload,
            &store,
        )
        .await
        .unwrap();
        ingest_armored(&mut state, &armor::encode(&bundle)).unwrap();
        let err = open_with_digest(&mut state, "deadbeef").unwrap_err();
        assert!(matches!(err, SealedHandoffError::DigestMismatch { .. }));
        // Still on DigestVerify so the operator can correct or skip.
        assert_eq!(state.phase, SealedPhase::DigestVerify);
    }
}
