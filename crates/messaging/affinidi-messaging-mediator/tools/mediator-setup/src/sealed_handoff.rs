//! Air-gapped sealed-handoff bootstrap consumer.
//!
//! Replaces the legacy "Cold-start" mode. Three logical phases live in
//! one place so the wizard can stay focused on UX:
//!
//! 1. **Generate request** — mint an ephemeral Ed25519 keypair (wire
//!    format is `did:key`) and derive its paired X25519 secret for HPKE
//!    open, attach a 16-byte nonce, and render a
//!    [`vta_sdk::sealed_transfer::BootstrapRequest`] JSON for the
//!    operator to ship out-of-band to the VTA admin.
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
    BootstrapRequest, SealedBundle, SealedPayloadV1, armor, bundle_digest,
    ed25519_seed_to_x25519_secret, generate_ed25519_keypair, open_bundle,
};

use crate::consts::DEFAULT_VTA_CONTEXT;
use crate::vta_connect::provision::{ProvisionAsk, ProvisionResult};
use crate::vta_connect::{VtaIntent, VtaSession};

/// Linear progress through the air-gapped flow. The wizard advances
/// strictly in order — each phase has a single well-defined exit.
///
/// Two intents share this phase machine: `AdminOnly` walks the
/// `CollectContext → CollectAdminLabel → …` chain and produces a plain
/// `sealed_transfer::BootstrapRequest`; `FullSetup` walks
/// `CollectContext → CollectMediatorUrl → …` and produces a VP-framed
/// `provision_integration::BootstrapRequest`. The shared tail
/// (`RequestGenerated → AwaitingBundle → DigestVerify → Complete`) is
/// identical except for which `SealedPayloadV1` variant is accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealedPhase {
    /// Text input for the VTA context slug (e.g. `mediator`). Both
    /// intents start here.
    CollectContext,
    /// FullSetup-only: text input for the mediator's public URL. Fed
    /// to the VTA's `didcomm-mediator` template as the required `URL`
    /// variable. The built-in template accepts this plus two
    /// optional vars (`ROUTING_KEYS`, `ACCEPT`) — no other inputs
    /// are plumbed through today.
    CollectMediatorUrl,
    /// AdminOnly-only: text input for the admin ACL label. Optional —
    /// empty advances with the `--admin-label` flag omitted.
    CollectAdminLabel,
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
    /// Which intent drives the adapter — [`VtaIntent::AdminOnly`] for
    /// the lightweight admin-credential path, [`VtaIntent::FullSetup`]
    /// for the template-driven integration-DID path. Set at sub-flow
    /// entry; never changes after construction.
    pub intent: VtaIntent,
    /// VTA context slug the operator targets with the producer
    /// command. Pre-populated with [`DEFAULT_VTA_CONTEXT`]; the
    /// operator edits it on the `CollectContext` phase.
    pub context_id: String,
    /// AdminOnly-only: admin ACL label for the credential the VTA
    /// mints. Optional — empty string means "no label", the flag is
    /// omitted from the rendered producer command.
    pub admin_label: String,
    /// FullSetup-only: mediator public URL, fed to the VTA's
    /// `didcomm-mediator` template as the required `URL` variable.
    /// Required before the VP-framed request can be signed; empty
    /// until the operator fills it in on `CollectMediatorUrl`.
    pub mediator_url: String,
    /// Consumer's X25519 secret. Required to open the returned bundle;
    /// dropped when the sub-flow exits. Zeroed until the inputs phases
    /// complete and `finalize_request` runs.
    pub recipient_secret: [u8; 32],
    /// Raw 16-byte nonce that anchors the bundle (must round-trip
    /// through the VTA admin's reply). Zeroed until `finalize_request`.
    pub nonce: [u8; 16],
    /// JSON-serialised [`BootstrapRequest`] the operator hands to the
    /// VTA admin. Empty string until `finalize_request` populates it.
    pub request_json: String,
    /// On-disk path the wizard wrote `request_json` to, so the
    /// operator can copy it from a second terminal — selecting text
    /// directly in the TUI tends to wrap across the progress panel
    /// on the left. Best-effort: `None` if the write failed (we
    /// still display the JSON inline).
    pub request_path: Option<std::path::PathBuf>,
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
    /// Transient status line for the clipboard hotkey on
    /// `RequestGenerated`. Short message shown in the info box —
    /// "Copied!" on success, the arboard error on failure. Cleared
    /// when the phase changes so it doesn't leak into later screens.
    pub clipboard_status: Option<String>,
    /// Operator-facing label carried into the `BootstrapRequest` at
    /// finalisation. Captured at sub-flow entry so the wizard can
    /// stamp runs even across re-renders.
    pub run_label: Option<String>,
}

impl SealedHandoffState {
    /// Initialise empty sub-flow state landing on
    /// [`SealedPhase::CollectContext`]. The keypair + nonce + request
    /// JSON are produced later by [`Self::finalize_request`], once the
    /// operator has supplied the context slug + admin label — those
    /// inputs pin the producer command the operator eventually ships
    /// to the VTA admin.
    ///
    /// The `run_label` is carried through to the sealed
    /// `BootstrapRequest::label` field at finalisation for audit
    /// traceability.
    pub fn new(intent: VtaIntent, run_label: Option<String>) -> Self {
        Self {
            phase: SealedPhase::CollectContext,
            intent,
            context_id: DEFAULT_VTA_CONTEXT.to_string(),
            admin_label: String::new(),
            mediator_url: String::new(),
            recipient_secret: [0u8; 32],
            nonce: [0u8; 16],
            request_json: String::new(),
            request_path: None,
            bundle: None,
            computed_digest: None,
            session: None,
            last_error: None,
            clipboard_status: None,
            run_label,
        }
    }

    /// Seed a full-setup state with a mediator URL pre-populated from
    /// the wizard's earlier step (saves the operator from retyping it).
    pub fn with_mediator_url(mut self, url: impl Into<String>) -> Self {
        self.mediator_url = url.into();
        self
    }

    /// Mint the ephemeral Ed25519 keypair, derive the matching X25519
    /// HPKE secret, sample the bundle-binding nonce, build the
    /// appropriate request shape for the current intent, and
    /// best-effort-write the JSON to disk.
    ///
    /// For [`VtaIntent::AdminOnly`] this produces a plain
    /// `sealed_transfer::BootstrapRequest` (what `pnm contexts
    /// bootstrap` consumes). For [`VtaIntent::FullSetup`] this
    /// produces a VP-framed `provision_integration::BootstrapRequest`
    /// (what `vta bootstrap provision-integration` consumes) signed
    /// with the ephemeral key.
    ///
    /// Errors here mean the system RNG failed, serialisation broke,
    /// or VP signing failed — the wizard surfaces the failure and
    /// lets the operator either retry or back out. VP signing is
    /// async; invoked via `tokio::task::block_in_place` so the
    /// synchronous event-loop caller doesn't have to cascade
    /// `async`.
    pub fn finalize_request(&mut self) -> Result<(), SealedHandoffError> {
        // Bootstrap request wire format carries a `did:key` — i.e. the
        // consumer's Ed25519 pubkey encoded under multicodec `0xed`.
        // The producer decodes that and runs the standard Montgomery
        // derivation to get the HPKE recipient X25519 pubkey, so on
        // this side we must run the matching derivation on the *seed*
        // to get the X25519 secret that pairs with it.
        let (seed_zeroizing, ed_pub) = generate_ed25519_keypair();
        let seed_bytes: [u8; 32] = *seed_zeroizing;
        let sk: [u8; 32] = *ed25519_seed_to_x25519_secret(&seed_zeroizing);
        let mut nonce = [0u8; 16];
        rand::rng()
            .try_fill_bytes(&mut nonce)
            .map_err(|e| SealedHandoffError::Internal(format!("nonce generation failed: {e}")))?;

        let (request_json, filename) = match self.intent {
            VtaIntent::AdminOnly => {
                let request = BootstrapRequest::new(ed_pub, nonce, self.run_label.clone());
                let json = serde_json::to_string_pretty(&request).map_err(|e| {
                    SealedHandoffError::Internal(format!("BootstrapRequest serialise failed: {e}"))
                })?;
                (json, "bootstrap-request.json")
            }
            VtaIntent::FullSetup => {
                if self.mediator_url.trim().is_empty() {
                    return Err(SealedHandoffError::Internal(
                        "mediator URL must be set before finalising a full-setup request".into(),
                    ));
                }
                let client_did = affinidi_crypto::did_key::ed25519_pub_to_did_key(&ed_pub);
                let mut ask =
                    ProvisionAsk::mediator(self.context_id.clone(), self.mediator_url.clone());
                if let Some(ref label) = self.run_label {
                    ask = ask.clone().with_label(label.clone());
                }
                let bootstrap_ask = ask.to_bootstrap_ask();
                let validity = ask.validity;
                let label = self.run_label.clone();
                // VP signing is async; bridge back to sync via
                // `block_in_place`. The tokio::main runtime the
                // wizard runs on is multi-threaded, so this is safe.
                let vp = tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current().block_on(async {
                        vta_sdk::provision_integration::BootstrapRequest::sign(
                            &seed_bytes,
                            &client_did,
                            nonce,
                            validity,
                            label,
                            bootstrap_ask,
                        )
                        .await
                    })
                })
                .map_err(|e| SealedHandoffError::Internal(format!("VP signing failed: {e}")))?;
                let json = serde_json::to_string_pretty(&vp).map_err(|e| {
                    SealedHandoffError::Internal(format!("VP serialise failed: {e}"))
                })?;
                (json, "bootstrap-request-vp.json")
            }
        };

        // Best-effort write of the request JSON to the CWD so the
        // operator can `cat` it from a second terminal and copy it
        // cleanly. Distinct filenames per intent prevent a mid-run
        // mode switch from aliasing a stale file on disk.
        let request_path = std::path::PathBuf::from(filename);
        let persisted = match std::fs::write(&request_path, &request_json) {
            Ok(()) => Some(request_path),
            Err(_) => None,
        };

        self.recipient_secret = sk;
        self.nonce = nonce;
        self.request_json = request_json;
        self.request_path = persisted;
        self.phase = SealedPhase::RequestGenerated;
        Ok(())
    }

    /// Copy `request_json` onto the system clipboard via `arboard`.
    /// Mirrors the pattern used by openvtc-cli2's `DIDKeysShow`.
    /// Writes the result into `clipboard_status` so the renderer can
    /// surface "Copied!" or the specific error on the next frame.
    pub fn copy_request_to_clipboard(&mut self) {
        self.set_clipboard(self.request_json.clone(), "request JSON");
    }

    /// Copy the primary producer command to the clipboard — the one
    /// the operator would run first. The shape depends on intent:
    /// `pnm contexts bootstrap …` for AdminOnly, `vta bootstrap
    /// provision-integration …` for FullSetup.
    pub fn copy_primary_command_to_clipboard(&mut self) {
        let label = match self.intent {
            VtaIntent::AdminOnly => "pnm contexts bootstrap command",
            VtaIntent::FullSetup => "vta bootstrap provision-integration command",
        };
        self.set_clipboard(self.primary_command(), label);
    }

    /// Copy the fallback command to the clipboard. Only AdminOnly has
    /// a fallback today (`vta bootstrap seal` with a hand-authored
    /// payload JSON); FullSetup's only offline producer is
    /// `provision-integration`.
    pub fn copy_fallback_command_to_clipboard(&mut self) {
        if let Some(cmd) = self.fallback_command() {
            self.set_clipboard(cmd, "fallback producer command");
        } else {
            self.clipboard_status = Some("No fallback command for this intent".into());
        }
    }

    /// Primary producer command for the current intent.
    ///
    /// **AdminOnly** — `pnm contexts bootstrap --id <ctx> --name
    /// "<name>" --admin-label "<label>" --recipient <path>`. Mints an
    /// admin did:key locally, enrols via `POST /acl`, seals an
    /// [`vta_sdk::sealed_transfer::SealedPayloadV1::AdminCredential`]
    /// to the recipient.
    ///
    /// **FullSetup** — `vta bootstrap provision-integration --request
    /// <path> --context <ctx> --assertion pinned-only --out
    /// bundle.armor`. Runs on the VTA host; mints mediator integration
    /// DID via template render, rolls over admin DID, issues VC,
    /// seals a [`vta_sdk::sealed_transfer::SealedPayloadV1::TemplateBootstrap`]
    /// bundle.
    pub fn primary_command(&self) -> String {
        let file = self.request_file_display();
        match self.intent {
            VtaIntent::AdminOnly => {
                let mut cmd = format!(
                    "pnm contexts bootstrap --id {} --name \"{}\" --recipient {}",
                    self.context_id,
                    self.context_display_name(),
                    file,
                );
                if !self.admin_label.is_empty() {
                    cmd.push_str(&format!(" --admin-label \"{}\"", self.admin_label));
                }
                cmd
            }
            VtaIntent::FullSetup => format!(
                "vta bootstrap provision-integration \
                 --request {} \
                 --context {} \
                 --assertion pinned-only \
                 --out bundle.armor",
                file, self.context_id,
            ),
        }
    }

    /// Optional fallback command. AdminOnly returns a low-level `vta
    /// bootstrap seal …` invocation that requires the operator to
    /// hand-author a `SealedPayloadV1::AdminCredential` JSON file.
    /// FullSetup returns `None` — `provision-integration` is the only
    /// sanctioned offline producer.
    pub fn fallback_command(&self) -> Option<String> {
        match self.intent {
            VtaIntent::AdminOnly => Some(format!(
                "vta bootstrap seal --request {} --payload <ADMIN_CREDENTIAL_JSON> --out bundle.armor",
                self.request_file_display(),
            )),
            VtaIntent::FullSetup => None,
        }
    }

    fn request_file_display(&self) -> String {
        self.request_path
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| match self.intent {
                VtaIntent::AdminOnly => "bootstrap-request.json".into(),
                VtaIntent::FullSetup => "bootstrap-request-vp.json".into(),
            })
    }

    /// Human-readable display name passed to `pnm contexts bootstrap
    /// --name`. Deterministic from the context slug so operator
    /// re-runs produce identical commands.
    fn context_display_name(&self) -> String {
        format!("Mediator ({})", self.context_id)
    }

    fn set_clipboard(&mut self, text: String, label: &str) {
        match arboard::Clipboard::new().and_then(|mut c| c.set_text(text)) {
            Ok(()) => {
                self.clipboard_status = Some(format!("Copied {label}"));
            }
            Err(e) => {
                self.clipboard_status = Some(format!("Clipboard unavailable: {e}"));
            }
        }
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
    // Leaving RequestGenerated — drop the transient clipboard status
    // so it doesn't confusingly linger on later screens.
    state.clipboard_status = None;
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

    match (state.intent, opened.payload) {
        (VtaIntent::AdminOnly, SealedPayloadV1::AdminCredential(boxed)) => {
            let credential: CredentialBundle = *boxed;
            // AdminOnly: the mediator's runtime VTA loader picks URL
            // / transport from the credential's vta_did resolution.
            // The `context_id` the operator typed on `CollectContext`
            // is what the VTA admin used when running `pnm contexts
            // bootstrap --id <ctx>`, so it's safe to retain here for
            // the persisted AdminCredential.
            state.session = Some(VtaSession::admin_only(
                state.context_id.clone(),
                credential.vta_did.clone(),
                None,
                None,
                credential.did.clone(),
                credential.private_key_multibase.clone(),
            ));
            info!(
                admin_did = %credential.did,
                vta_did = %credential.vta_did,
                bundle_id = %state.nonce_display(),
                "Sealed handoff (AdminOnly): bundle opened, admin credential extracted"
            );
        }
        (VtaIntent::FullSetup, SealedPayloadV1::TemplateBootstrap(boxed)) => {
            let payload = *boxed;
            let vta_did = payload.config.vta_trust.vta_did.clone();
            let vta_url = payload.config.vta_url.clone();
            let provision = ProvisionResult::from_template_bootstrap_payload(payload);
            state.session = Some(VtaSession::full(
                state.context_id.clone(),
                vta_did,
                vta_url,
                None,
                provision,
            ));
            info!(
                context = %state.context_id,
                bundle_id = %state.nonce_display(),
                "Sealed handoff (FullSetup): bundle opened, template bootstrap applied"
            );
        }
        _ => return Err(SealedHandoffError::WrongPayload),
    }

    state.phase = SealedPhase::Complete;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use vta_sdk::sealed_transfer::{
        AssertionProof, InMemoryNonceStore, ProducerAssertion, SealedPayloadV1, seal_payload,
    };

    fn assertion_for(ed_pub: &[u8; 32]) -> ProducerAssertion {
        ProducerAssertion {
            producer_did: affinidi_crypto::did_key::ed25519_pub_to_did_key(ed_pub),
            proof: AssertionProof::PinnedOnly,
        }
    }

    #[test]
    fn new_lands_on_collect_context() {
        let state = SealedHandoffState::new(VtaIntent::AdminOnly, Some("test".into()));
        assert_eq!(state.phase, SealedPhase::CollectContext);
        assert_eq!(state.context_id, DEFAULT_VTA_CONTEXT);
        assert!(state.admin_label.is_empty());
        assert!(state.request_json.is_empty());
    }

    #[test]
    fn finalize_request_populates_request_json_and_advances() {
        let mut state = SealedHandoffState::new(VtaIntent::AdminOnly, Some("test".into()));
        state.finalize_request().expect("finalize succeeds");
        assert_eq!(state.phase, SealedPhase::RequestGenerated);
        assert!(state.request_json.contains("\"version\""));
        assert!(state.request_json.contains("\"client_did\""));
        assert!(state.request_json.contains("did:key:z6Mk"));
        assert!(state.request_json.contains("\"nonce\""));
    }

    #[test]
    fn admin_only_primary_command_uses_collected_context_and_label() {
        let mut state = SealedHandoffState::new(VtaIntent::AdminOnly, None);
        state.context_id = "prod-mediator".into();
        state.admin_label = "staff".into();
        state.finalize_request().unwrap();
        let cmd = state.primary_command();
        assert!(cmd.starts_with("pnm contexts bootstrap"));
        assert!(cmd.contains("--id prod-mediator"));
        assert!(cmd.contains("--name \"Mediator (prod-mediator)\""));
        assert!(cmd.contains("--admin-label \"staff\""));
        assert!(cmd.contains("--recipient bootstrap-request.json"));
        // No fabricated payload kind — regression check against the
        // broken pre-Slice-2 command.
        assert!(!cmd.contains("mediator-admin-credential"));
    }

    #[test]
    fn admin_only_primary_omits_admin_label_when_blank() {
        let mut state = SealedHandoffState::new(VtaIntent::AdminOnly, None);
        state.finalize_request().unwrap();
        let cmd = state.primary_command();
        assert!(!cmd.contains("--admin-label"));
    }

    #[test]
    fn admin_only_fallback_leaves_payload_placeholder_for_operator() {
        let mut state = SealedHandoffState::new(VtaIntent::AdminOnly, None);
        state.finalize_request().unwrap();
        let cmd = state
            .fallback_command()
            .expect("AdminOnly exposes a fallback");
        // Fallback command acknowledges the VTA admin has to supply
        // the AdminCredential JSON themselves — we mark the slot
        // rather than inventing a fake payload kind.
        assert!(cmd.contains("--payload <ADMIN_CREDENTIAL_JSON>"));
    }

    // FullSetup finalisation uses `tokio::task::block_in_place` to
    // bridge to `BootstrapRequest::sign` — only works on a
    // multi-threaded runtime, which is what the wizard's
    // `#[tokio::main]` produces. Tests must request the same.
    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn full_setup_primary_command_renders_provision_integration() {
        let mut state = SealedHandoffState::new(VtaIntent::FullSetup, None)
            .with_mediator_url("https://mediator.example.com");
        state.context_id = "prod-mediator".into();
        state.finalize_request().unwrap();
        let cmd = state.primary_command();
        assert!(cmd.starts_with("vta bootstrap provision-integration"));
        assert!(cmd.contains("--request bootstrap-request-vp.json"));
        assert!(cmd.contains("--context prod-mediator"));
        assert!(cmd.contains("--assertion pinned-only"));
        assert!(cmd.contains("--out bundle.armor"));
        // Sanity: FullSetup has no fallback.
        assert!(state.fallback_command().is_none());
    }

    #[test]
    fn full_setup_finalize_requires_mediator_url() {
        let mut state = SealedHandoffState::new(VtaIntent::FullSetup, None);
        // No URL set → finalise should fail early. No runtime needed
        // — we never reach the VP sign call.
        let err = state.finalize_request().unwrap_err();
        assert!(matches!(err, SealedHandoffError::Internal(_)));
        assert_eq!(state.phase, SealedPhase::CollectContext);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn full_setup_writes_vp_framed_request_file() {
        let mut state = SealedHandoffState::new(VtaIntent::FullSetup, None)
            .with_mediator_url("https://mediator.example.com");
        state.finalize_request().unwrap();
        // VP-framed requests go to a distinct filename so a mid-run
        // mode switch doesn't alias a stale plain request.
        let path = state.request_path.as_ref().expect("persisted file path");
        assert_eq!(
            path.file_name().and_then(|s| s.to_str()),
            Some("bootstrap-request-vp.json")
        );
        // VP shape includes Data Integrity proof fields.
        assert!(state.request_json.contains("\"proof\""));
        assert!(state.request_json.contains("VerifiablePresentation"));
    }

    #[tokio::test]
    async fn round_trip_through_consumer_yields_session() {
        // Stand in for the VTA admin: produce a real sealed bundle
        // addressed to the consumer's pubkey, then drive the wizard
        // helpers to open it.
        let mut state = SealedHandoffState::new(VtaIntent::AdminOnly, None);
        state.finalize_request().expect("finalize_request");

        // Recover the consumer's HPKE X25519 pubkey from the did:key in
        // the request so the producer seals to the right recipient.
        let parsed_request: BootstrapRequest = serde_json::from_str(&state.request_json).unwrap();
        let recipient_pk = parsed_request.decode_client_x25519_pub().unwrap();

        let (_prod_seed, prod_ed_pub) = generate_ed25519_keypair();
        let payload = SealedPayloadV1::AdminCredential(Box::new(CredentialBundle::new(
            "did:key:z6MkConsumer",
            "z3uADMIN",
            "did:webvh:vta.example.com",
        )));
        let store = InMemoryNonceStore::new();
        let bundle = seal_payload(
            &recipient_pk,
            state.nonce,
            assertion_for(&prod_ed_pub),
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
        assert_eq!(session.admin_did(), "did:key:z6MkConsumer");
        assert_eq!(session.vta_did, "did:webvh:vta.example.com");
        assert_eq!(session.admin_private_key_mb(), "z3uADMIN");
    }

    #[test]
    fn ingest_rejects_garbage() {
        let mut state = SealedHandoffState::new(VtaIntent::AdminOnly, None);
        state.finalize_request().unwrap();
        let err = ingest_armored(&mut state, "not an armored bundle").unwrap_err();
        assert!(matches!(err, SealedHandoffError::ArmorDecode(_)));
        assert_eq!(state.phase, SealedPhase::RequestGenerated);
    }

    #[tokio::test]
    async fn open_rejects_digest_mismatch() {
        let mut state = SealedHandoffState::new(VtaIntent::AdminOnly, None);
        state.finalize_request().unwrap();
        let parsed_request: BootstrapRequest = serde_json::from_str(&state.request_json).unwrap();
        let recipient_pk = parsed_request.decode_client_x25519_pub().unwrap();
        let (_prod_seed, prod_ed_pub) = generate_ed25519_keypair();
        let payload = SealedPayloadV1::AdminCredential(Box::new(CredentialBundle::new(
            "did:key:z6MkX",
            "zKEY",
            "did:webvh:y",
        )));
        let store = InMemoryNonceStore::new();
        let bundle = seal_payload(
            &recipient_pk,
            state.nonce,
            assertion_for(&prod_ed_pub),
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
