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

use std::collections::BTreeMap;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use chrono::Duration;
use rand::TryRng;
use serde_json::Value;
use tracing::{info, warn};
use vta_sdk::credentials::CredentialBundle;
use vta_sdk::provision_integration::{
    ProvisionRequestBuilder, http::ProvisionSummary, payload::TemplateBootstrapPayload,
};
use vta_sdk::sealed_transfer::{
    AssertionProof, BootstrapRequest, ProducerAssertion, SealedBundle, SealedPayloadV1, armor,
    bundle_digest, ed25519_seed_to_x25519_secret, generate_ed25519_keypair, open_bundle,
};

use crate::consts::{DEFAULT_MEDIATOR_TEMPLATE, DEFAULT_VTA_ADMIN_TEMPLATE, DEFAULT_VTA_CONTEXT};
use crate::vta::{ProvisionResult, VtaIntent, VtaSession};

/// Default validity on a wizard-issued VP for the **offline** path
/// (sealed handoff). The request file is shuttled between hosts by
/// hand — USB sticks, scp sessions, ticket attachments — so the
/// freshness window has to absorb realistic operator latency.
/// 7 days mirrors the VTA-team v1 CLI convention for `vta bootstrap
/// provision-integration` requests.
const DEFAULT_VALIDITY_OFFLINE: Duration = Duration::days(7);

/// Template variable the VTA's `didcomm-mediator` template reads to
/// pin the webvh hosting server for the minted DID's did.jsonl log.
/// Upstream contract: the value is a string matching
/// `WebvhServerRecord.id` in the VTA's server catalogue; leaving the
/// var absent keeps the serverless (self-hosted at `URL`) behaviour.
/// See `vta-sdk/templates/didcomm-mediator.json` +
/// `vta-service/src/operations/provision_integration.rs::resolve_webvh_server`.
const WEBVH_SERVER_TEMPLATE_VAR: &str = "WEBVH_SERVER";

/// Linear progress through the air-gapped flow. The wizard advances
/// strictly in order — each phase has a single well-defined exit.
///
/// Two intents share this phase machine: `AdminOnly` walks the
/// `CollectContext → CollectAdminLabel → …` chain and produces a plain
/// `sealed_transfer::BootstrapRequest`; `FullSetup` walks
/// `CollectContext → CollectMediatorUrl → CollectWebvhServer → …` and
/// produces a VP-framed `provision_integration::BootstrapRequest`.
/// The shared tail (`RequestGenerated → AwaitingBundle → DigestVerify
/// → Complete`) is identical except for which `SealedPayloadV1` variant
/// is accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealedPhase {
    /// Text input for the VTA context slug (e.g. `mediator`). Both
    /// intents start here.
    CollectContext,
    /// FullSetup-only: text input for the mediator's public URL. Fed
    /// to the VTA's `didcomm-mediator` template as the required `URL`
    /// variable.
    CollectMediatorUrl,
    /// FullSetup-only: optional text input for a webvh server id the
    /// VTA should host the minted DID's did.jsonl log on. Empty means
    /// "self-host at the URL" (the VTA's serverless path).
    CollectWebvhServer,
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
    /// FullSetup-only: optional webvh server id pinning the VTA to a
    /// specific hosting server for the minted DID's did.jsonl log.
    /// Empty means "self-host at the URL". See
    /// [`WEBVH_SERVER_TEMPLATE_VAR`].
    pub webvh_server: String,
    /// Consumer's X25519 secret. Required to open the returned bundle;
    /// dropped when the sub-flow exits. Zeroed until the inputs phases
    /// complete and `finalize_request` runs.
    pub recipient_secret: [u8; 32],
    /// Raw 32-byte Ed25519 seed the X25519 secret is derived from. The
    /// non-interactive driver persists this into the configured secret
    /// backend so phase 2 (a separate process invocation) can recover
    /// `recipient_secret` without the operator fishing it out by hand.
    /// Zeroed until `finalize_request` runs; unused by the TUI, which
    /// stays single-process and relies on the in-memory
    /// `recipient_secret` directly.
    pub seed_bytes: [u8; 32],
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
    /// Producer assertion extracted from the opened bundle. Captured
    /// so the renderer can surface "verified by digest only"
    /// (PinnedOnly) vs "DID-signed by …" (DidSigned) without
    /// reaching back into the SDK envelope. `None` until
    /// [`open_with_digest`] runs and succeeds.
    pub producer_assertion: Option<ProducerAssertion>,
    /// Single-line summary of the producer assertion's verification
    /// state, suitable for direct rendering in the wizard's info
    /// pane. Greenfield deployments commonly land in `PinnedOnly` —
    /// this string makes the trust posture explicit so the operator
    /// doesn't read silence as success.
    pub assertion_warning: Option<String>,
    /// Vertical scroll offset (in rendered rows) for the
    /// RequestGenerated panel. The panel's content — VP JSON +
    /// producer commands + hotkey cheatsheet — routinely exceeds
    /// the terminal viewport, especially on smaller windows. The
    /// main loop bumps this in response to Up/Down/PageUp/PageDown
    /// keys, and the renderer passes it to `Paragraph::scroll()`.
    /// Clamped to `>= 0` on the decrement side; the upper bound is
    /// left to ratatui, which renders empty rows past content
    /// rather than refusing. Reset to zero whenever the phase
    /// transitions so a later re-entry (e.g. operator backtracks)
    /// starts at the top.
    pub request_scroll: u16,
    /// Banner shown above the intro panel when the wizard
    /// transitioned into the sealed-handoff sub-flow from the
    /// recovery prompt rather than via the operator's primary
    /// `OfflineExport` choice. `None` for the direct entry path
    /// (intro screen renders without the banner). Populated by
    /// [`crate::app::WizardApp::transition_to_sealed_handoff`].
    pub offline_transition_banner: Option<String>,
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
            webvh_server: String::new(),
            recipient_secret: [0u8; 32],
            seed_bytes: [0u8; 32],
            nonce: [0u8; 16],
            request_json: String::new(),
            request_path: None,
            bundle: None,
            computed_digest: None,
            session: None,
            last_error: None,
            clipboard_status: None,
            run_label,
            producer_assertion: None,
            assertion_warning: None,
            request_scroll: 0,
            offline_transition_banner: None,
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
            VtaIntent::AdminOnly | VtaIntent::OfflineExport => {
                // Both intents emit the simpler v1
                // `sealed_transfer::BootstrapRequest` — pubkey + nonce
                // + label, no template ask. The VTA-side command
                // (`pnm contexts bootstrap` for AdminOnly,
                // `vta context reprovision` for OfflineExport) decides
                // what payload variant ends up in the sealed bundle.
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
                // SDK's `ProvisionAsk::to_builder` is `pub(crate)`, so we
                // construct the `ProvisionRequestBuilder` directly here.
                // The builder shape mirrors `ProvisionAsk::didcomm_mediator`
                // followed by `.with_validity(..).with_label(..)` and an
                // injected `WEBVH_SERVER` template var — kept in sync with
                // `vta-sdk/src/provision_client/ask.rs`.
                let mut vars = BTreeMap::new();
                vars.insert("URL".to_string(), Value::String(self.mediator_url.clone()));
                if !self.webvh_server.is_empty() {
                    vars.insert(
                        WEBVH_SERVER_TEMPLATE_VAR.to_string(),
                        Value::String(self.webvh_server.clone()),
                    );
                }
                let mut builder = ProvisionRequestBuilder::new(DEFAULT_MEDIATOR_TEMPLATE)
                    .vars(vars)
                    .context_hint(self.context_id.clone())
                    .validity(DEFAULT_VALIDITY_OFFLINE)
                    .admin_template(DEFAULT_VTA_ADMIN_TEMPLATE);
                if let Some(ref label) = self.run_label {
                    builder = builder.label(label.clone()).note(label.clone());
                }
                // VP signing is async; bridge back to sync via
                // `block_in_place`. The tokio::main runtime the
                // wizard runs on is multi-threaded, so this is safe.
                //
                // The builder's `sign_with` generates its own VP nonce
                // — we decode it back from the rendered VP and adopt
                // it as the bundle id (the producer will seal to the
                // matching `bundle_id`).
                let vp = tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current()
                        .block_on(async { builder.sign_with(&seed_bytes, &client_did).await })
                })
                .map_err(|e| SealedHandoffError::Internal(format!("VP signing failed: {e}")))?;
                nonce = decode_nonce_b64url(&vp.nonce)
                    .map_err(|e| SealedHandoffError::Internal(format!("VP nonce decode: {e}")))?;
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

        // The seed intentionally stays in-memory for the TUI — a
        // single-process session opens bundles directly via
        // `recipient_secret`. For the non-interactive two-phase flow,
        // `seed_bytes` is surfaced on this state so
        // `bootstrap_headless::phase1_emit_request` can persist it
        // into the configured secret backend. No disk copy is written
        // from either path.
        self.recipient_secret = sk;
        self.seed_bytes = seed_bytes;
        self.nonce = nonce;
        self.request_json = request_json;
        self.request_path = persisted;
        // Fresh content → fresh viewport. Without this, an operator
        // who scrolled earlier and backtracked would land on
        // RequestGenerated partway down the new JSON.
        self.request_scroll = 0;
        self.phase = SealedPhase::RequestGenerated;
        Ok(())
    }

    /// Scroll the RequestGenerated panel up by `rows`, saturating
    /// at the top. Row count is configurable so the same helper
    /// drives both single-line (Up/Down) and page-wise (PageUp/
    /// PageDown) keybindings.
    pub fn scroll_request_up(&mut self, rows: u16) {
        self.request_scroll = self.request_scroll.saturating_sub(rows);
    }

    /// Scroll the RequestGenerated panel down by `rows`. Upper
    /// bound is deliberately not clamped here — ratatui renders
    /// blank rows past content rather than erroring, and the
    /// content height depends on terminal width (line-wrap) which
    /// isn't known at this layer. Lets the operator scroll
    /// slightly past the bottom without us having to predict the
    /// wrap; they can scroll back up.
    pub fn scroll_request_down(&mut self, rows: u16) {
        self.request_scroll = self.request_scroll.saturating_add(rows);
    }

    /// Jump back to the top of the RequestGenerated panel. Used
    /// for Home key and as a phase-transition reset.
    pub fn scroll_request_home(&mut self) {
        self.request_scroll = 0;
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
            VtaIntent::OfflineExport => "vta context reprovision command",
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

    /// Copy the wizard-computed bundle digest to the clipboard.
    /// Hotkey `[F2]` on the `DigestVerify` panel — `F2` instead of
    /// a letter key because the panel has an active text input
    /// for the operator to type the OOB digest, and bare letters
    /// would land in the field instead of triggering a copy.
    pub fn copy_digest_to_clipboard(&mut self) {
        let Some(digest) = self.computed_digest.clone() else {
            self.clipboard_status = Some("No digest computed yet".into());
            return;
        };
        self.set_clipboard(digest, "computed digest");
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
    ///
    /// **OfflineExport** — `vta context reprovision --id <ctx>
    /// --recipient <path> --out bundle.armor`. Runs on the VTA host;
    /// retrieves *existing* mediator material (DID, operational keys,
    /// admin credential) for the named context and seals a
    /// [`vta_sdk::sealed_transfer::SealedPayloadV1::ContextProvision`]
    /// bundle. `--admin-key` is intentionally omitted — the VTA's
    /// auto-mint default ships a fresh admin identity in the bundle,
    /// which is what the wizard wants for self-sufficient mediator
    /// startup.
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
            VtaIntent::OfflineExport => format!(
                "vta context reprovision \
                 --id {} \
                 --recipient {} \
                 --out bundle.armor",
                self.context_id, file,
            ),
        }
    }

    /// Optional fallback command. AdminOnly returns a low-level `vta
    /// bootstrap seal …` invocation that requires the operator to
    /// hand-author a `SealedPayloadV1::AdminCredential` JSON file.
    /// FullSetup returns `None` — `provision-integration` is the only
    /// sanctioned offline producer.
    ///
    /// OfflineExport returns the `vta keys bundle` variant — narrower
    /// than `vta context reprovision`: ships only DID + operational
    /// keys, no admin credential. Use only when admin material is
    /// being managed out-of-band (key escrow, separate admin
    /// workstation, principle-of-least-privilege deployments).
    pub fn fallback_command(&self) -> Option<String> {
        match self.intent {
            VtaIntent::AdminOnly => Some(format!(
                "vta bootstrap seal --request {} --payload <ADMIN_CREDENTIAL_JSON> --out bundle.armor",
                self.request_file_display(),
            )),
            VtaIntent::FullSetup => None,
            VtaIntent::OfflineExport => Some(format!(
                "vta keys bundle --context {} --recipient {} --out bundle.armor",
                self.context_id,
                self.request_file_display(),
            )),
        }
    }

    fn request_file_display(&self) -> String {
        self.request_path
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| match self.intent {
                // AdminOnly + OfflineExport both write the v1
                // sealed_transfer::BootstrapRequest under the same
                // name — they're structurally identical requests.
                VtaIntent::AdminOnly | VtaIntent::OfflineExport => "bootstrap-request.json".into(),
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
        match crate::clipboard::copy_to_clipboard(&text) {
            Ok(method) => {
                self.clipboard_status = Some(format!("Copied {label} via {}", method.label()));
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

/// Classify the producer's trust-anchor proof and return an
/// operator-facing summary line for the wizard's info pane.
///
/// We deliberately *do not* perform DID resolution / signature
/// verification yet — greenfield deployments commonly run this flow
/// before the VTA's DID is published to its webvh log, in which case
/// resolution would fail on a live attempt. The honest position today
/// is: surface what the producer claimed, label `PinnedOnly` as
/// "verified by operator-supplied digest only", and flag `DidSigned`
/// / `Attested` as "claim recorded; cryptographic verification
/// pending future implementation". Returning `None` means "no
/// caveat worth surfacing" (reserved for the future verified case).
///
/// Logged via `tracing::warn` so even non-TUI runs leave an audit
/// trail. Renderer reads `SealedHandoffState::assertion_warning` for
/// the on-screen line.
fn classify_producer_assertion(assertion: &ProducerAssertion) -> Option<String> {
    match &assertion.proof {
        AssertionProof::PinnedOnly => {
            warn!(
                producer_did = %assertion.producer_did,
                proof = "pinned_only",
                "Sealed handoff: producer assertion is PinnedOnly — \
                 trust anchored by your supplied digest only, no DID-signature verification"
            );
            Some(format!(
                "Trust anchor: PinnedOnly. Verified by your supplied digest; \
                 the producer DID {} was not resolved.",
                assertion.producer_did
            ))
        }
        AssertionProof::DidSigned(sig) => {
            // Future work: resolve `assertion.producer_did`, walk to
            // `sig.verification_method`, verify `sig.signature_b64`
            // over the bundle digest. Today we only record the claim.
            warn!(
                producer_did = %assertion.producer_did,
                vm = %sig.verification_method,
                proof = "did_signed",
                "Sealed handoff: producer claims DidSigned proof — \
                 cryptographic verification is not yet implemented; \
                 trust still anchored by your supplied digest"
            );
            Some(format!(
                "Trust anchor: DidSigned by {} ({}). Signature is recorded but not \
                 yet verified — relying on your supplied digest until DID resolution \
                 lands.",
                assertion.producer_did, sig.verification_method
            ))
        }
        AssertionProof::Attested(quote) => {
            warn!(
                producer_did = %assertion.producer_did,
                format = %quote.format,
                proof = "attested",
                "Sealed handoff: producer claims Attested proof — \
                 attestation verification is not yet implemented"
            );
            Some(format!(
                "Trust anchor: Attested ({}) by {}. Attestation is recorded but \
                 not yet verified.",
                quote.format, assertion.producer_did
            ))
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

    // Capture the producer assertion for the renderer + audit log
    // before we move the payload. Trust-policy classification follows
    // (`PinnedOnly` → operator-supplied digest is the only anchor;
    // `DidSigned` / `Attested` → cryptographic verification is the
    // *intended* anchor but is currently a TODO — see
    // `classify_producer_assertion`).
    state.assertion_warning = classify_producer_assertion(&opened.producer);
    state.producer_assertion = Some(opened.producer);

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
            let provision = provision_from_template_payload(payload);
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
        (VtaIntent::OfflineExport, SealedPayloadV1::ContextProvision(boxed)) => {
            let bundle = *boxed;
            info!(
                context = %state.context_id,
                admin_did = %bundle.admin_did,
                integration_did = bundle.did.as_ref().map(|d| d.id.as_str()).unwrap_or("(none)"),
                bundle_id = %state.nonce_display(),
                "Sealed handoff (OfflineExport): ContextProvision bundle opened"
            );
            state.session = Some(VtaSession::context_export(state.context_id.clone(), bundle));
        }
        // Either an unexpected payload variant for the running intent,
        // or a wholly new variant the wizard doesn't know about yet
        // (e.g. `DidSecrets` from `vta keys bundle` — operator path
        // that isn't wired into the wizard). Surface as WrongPayload
        // so the operator can re-check which command the VTA admin
        // ran.
        _ => return Err(SealedHandoffError::WrongPayload),
    }

    state.phase = SealedPhase::Complete;
    Ok(())
}

/// Decode a base64url-no-pad VP nonce string back to the 16-byte
/// sealed-bundle id. Mirrors the SDK's `pub(crate)` helper
/// (`vta_sdk::provision_client::result::decode_nonce_b64url`) — kept
/// local so the offline FullSetup VP-signing path can recover the
/// nonce the builder generated for use as the bundle id.
fn decode_nonce_b64url(s: &str) -> Result<[u8; 16], String> {
    let raw = B64URL
        .decode(s)
        .map_err(|e| format!("VP nonce base64url: {e}"))?;
    raw.try_into()
        .map_err(|_| "VP nonce must be 16 bytes".to_string())
}

/// Build a [`ProvisionResult`] from a sealed-handoff
/// [`TemplateBootstrapPayload`]. The offline path opens the bundle
/// locally and has no VTA-supplied [`ProvisionSummary`] — synthesise
/// one from the payload itself so downstream code (which always
/// reads through [`ProvisionResult`] accessors) stays uniform with
/// the online path.
///
/// `bundle_id_hex` / `digest` are left empty: the offline path
/// tracks both on [`SealedHandoffState`] (nonce + SHA-256 of armored
/// ciphertext) and downstream code has no current consumer for them.
fn provision_from_template_payload(payload: TemplateBootstrapPayload) -> ProvisionResult {
    let integration_did = payload
        .config
        .did_document
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    // Admin DID = the one key in `secrets` that isn't the integration
    // DID. Falls back to the integration DID for the legacy no-rollover
    // path — matches the online runner's convention.
    let admin_did = payload
        .secrets
        .keys()
        .find(|k| **k != integration_did)
        .cloned()
        .unwrap_or_else(|| integration_did.clone());
    let admin_rolled_over = admin_did != integration_did;
    let summary = ProvisionSummary {
        client_did: admin_did.clone(),
        admin_did,
        admin_rolled_over,
        integration_did,
        template_name: payload.config.template_name.clone(),
        template_kind: payload.config.template_kind.clone(),
        admin_template_name: None,
        bundle_id_hex: String::new(),
        webvh_server_id: None,
        secret_count: payload.secrets.len(),
        output_count: payload.config.outputs.len(),
    };
    ProvisionResult {
        bundle_id_hex: String::new(),
        digest: String::new(),
        summary,
        payload,
    }
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
    fn scroll_saturates_at_zero_and_free_grows_on_down() {
        // RequestGenerated panel scroll — Up saturates at 0 so the
        // operator can't wedge the viewport past the top; Down is
        // unbounded because the rendered height depends on wrap
        // width we don't know at this layer. `Home` resets.
        let mut state = SealedHandoffState::new(VtaIntent::AdminOnly, None);
        assert_eq!(state.request_scroll, 0);
        state.scroll_request_up(5);
        assert_eq!(state.request_scroll, 0, "Up from 0 must saturate");
        state.scroll_request_down(3);
        assert_eq!(state.request_scroll, 3);
        state.scroll_request_down(10);
        assert_eq!(state.request_scroll, 13, "Down accumulates without clamp");
        state.scroll_request_up(4);
        assert_eq!(state.request_scroll, 9);
        state.scroll_request_home();
        assert_eq!(state.request_scroll, 0);
    }

    #[test]
    fn finalize_request_resets_scroll_to_top() {
        // Re-entering RequestGenerated (e.g. after a backtrack) must
        // land on row 0, otherwise the operator would see fresh JSON
        // rendered from partway down.
        let mut state = SealedHandoffState::new(VtaIntent::AdminOnly, None);
        state.scroll_request_down(20);
        state.finalize_request().expect("finalize succeeds");
        assert_eq!(state.phase, SealedPhase::RequestGenerated);
        assert_eq!(state.request_scroll, 0);
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn full_setup_webvh_server_appears_in_vp_template_vars() {
        // When the operator types a webvh server id on
        // `CollectWebvhServer`, the VP's ask must carry
        // `WEBVH_SERVER` as a template var so the VTA's
        // `resolve_webvh_server` picks it up. Empty input omits the
        // var entirely (serverless path).
        let mut state = SealedHandoffState::new(VtaIntent::FullSetup, None)
            .with_mediator_url("https://mediator.example.com");
        state.webvh_server = "prod-1".into();
        state.finalize_request().unwrap();
        // The VP JSON is signed, so field ordering is canonical.
        // Assert on substrings that are present regardless of
        // ordering — var name and value both appear verbatim.
        assert!(
            state.request_json.contains("\"WEBVH_SERVER\""),
            "WEBVH_SERVER template var missing from VP: {}",
            state.request_json
        );
        assert!(
            state.request_json.contains("\"prod-1\""),
            "resolved server id missing from VP: {}",
            state.request_json
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn full_setup_omits_webvh_server_var_when_blank() {
        let mut state = SealedHandoffState::new(VtaIntent::FullSetup, None)
            .with_mediator_url("https://mediator.example.com");
        state.finalize_request().unwrap();
        assert!(
            !state.request_json.contains("WEBVH_SERVER"),
            "blank webvh_server should omit the template var entirely"
        );
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
