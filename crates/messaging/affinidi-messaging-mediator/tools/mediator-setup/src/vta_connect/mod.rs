//! Online VTA connection flow.
//!
//! Scope (this iteration): establish an authenticated connection to a running
//! VTA. The operator supplies the VTA DID; the wizard resolves its service
//! endpoints, generates an ephemeral `did:key`, and displays a ready-to-paste
//! `pnm acl create` command. Once the operator has registered the ACL entry,
//! the wizard authenticates via DIDComm (primary) or REST (fallback).
//!
//! Out of scope here: mediator DID generation, admin DID provisioning, secret
//! persistence, context bootstrap. Those attach to the authenticated session
//! in later iterations.

pub mod cli;
pub mod diagnostics;
pub mod intent;
pub mod provision;
pub mod resolve;
pub mod runner;
pub mod setup_key;

pub use diagnostics::{
    ConnectedInfo, DiagCheck, DiagEntry, DiagStatus, apply_update, pending_list,
};
pub use intent::{AdminCredentialReply, VtaIntent, VtaReply, VtaTransport};
use vta_sdk::context_provision::ContextProvisionBundle;

use crate::vta_connect::provision::ProvisionResult;

/// A completed VTA interaction — retained on `WizardApp` after the
/// sub-flow exits so downstream steps (Did, Summary, secret-writing) can
/// use the resulting credential material.
///
/// The [`reply`](Self::reply) field carries the transport-agnostic payload.
/// Accessors below flatten the two variants into the shape downstream code
/// actually consumes (admin DID, admin private key, optional integration
/// DID).
#[derive(Clone, Debug)]
pub struct VtaSession {
    pub context_id: String,
    pub vta_did: String,
    /// REST URL advertised by the VTA DID doc. `None` for a
    /// DIDComm-only VTA or a sealed-handoff session. Persisted onto
    /// the mediator's admin credential so its runtime code has a URL
    /// fallback for VTA operations.
    pub rest_url: Option<String>,
    /// DIDComm mediator DID advertised by the VTA. Captured so a
    /// DIDComm-backed `VtaClient` can be reopened without
    /// re-resolving the VTA DID document.
    pub mediator_did: Option<String>,
    /// Unified reply — either a full template-bootstrap result or an
    /// admin-credential-only reply. See [`VtaReply`].
    pub reply: VtaReply,
}

impl VtaSession {
    /// Construct a session from a full template-bootstrap reply (both
    /// online and offline `FullSetup` adapters call this).
    pub fn full(
        context_id: String,
        vta_did: String,
        rest_url: Option<String>,
        mediator_did: Option<String>,
        provision: ProvisionResult,
    ) -> Self {
        Self {
            context_id,
            vta_did,
            rest_url,
            mediator_did,
            reply: VtaReply::Full(provision),
        }
    }

    /// Construct a session from an admin-credential-only reply (both
    /// online and offline `AdminOnly` adapters call this).
    pub fn admin_only(
        context_id: String,
        vta_did: String,
        rest_url: Option<String>,
        mediator_did: Option<String>,
        admin_did: String,
        admin_private_key_mb: String,
    ) -> Self {
        Self {
            context_id,
            vta_did,
            rest_url,
            mediator_did,
            reply: VtaReply::AdminOnly(AdminCredentialReply {
                admin_did,
                admin_private_key_mb,
            }),
        }
    }

    /// Construct a session from a `ContextProvision` sealed bundle —
    /// the OfflineExport adapter's reply shape. The bundle's `vta_did`
    /// / `vta_url` may be absent (older VTA-side flows) so we
    /// substitute empty strings to keep the session shape uniform;
    /// downstream code that needs them treats empty as "unknown".
    pub fn context_export(context_id: String, bundle: ContextProvisionBundle) -> Self {
        let vta_did = bundle.vta_did.clone().unwrap_or_default();
        let rest_url = bundle.vta_url.clone();
        Self {
            context_id,
            vta_did,
            rest_url,
            mediator_did: None,
            reply: VtaReply::ContextExport(Box::new(bundle)),
        }
    }

    /// Long-term admin DID the mediator authenticates as. For a
    /// [`VtaReply::Full`] reply this is the rolled-over DID from the
    /// `ProvisionResult`; for `AdminOnly` it's the DID the VTA supplied
    /// directly; for `ContextExport` it's the (auto-minted) admin DID
    /// the VTA shipped inside the [`ContextProvisionBundle`].
    pub fn admin_did(&self) -> &str {
        match &self.reply {
            VtaReply::Full(p) => p.admin_did(),
            VtaReply::AdminOnly(a) => &a.admin_did,
            VtaReply::ContextExport(b) => &b.admin_did,
        }
    }

    /// Private key (multibase) matching [`Self::admin_did`]. Returns an
    /// empty slice when a `Full` reply has no admin-key entry (the
    /// legacy no-rollover path); callers should treat empty as "reuse
    /// the setup key" exactly as before.
    pub fn admin_private_key_mb(&self) -> &str {
        match &self.reply {
            VtaReply::Full(p) => p
                .admin_key()
                .map(|k| k.signing_key.private_key_multibase.as_str())
                .unwrap_or(""),
            VtaReply::AdminOnly(a) => &a.admin_private_key_mb,
            VtaReply::ContextExport(b) => b.credential.private_key_multibase.as_str(),
        }
    }

    /// Integration (mediator-service) DID the VTA rendered or
    /// re-exported. `None` for `AdminOnly` (mediator brought its own
    /// DID) and for any `ContextExport` whose bundle didn't include a
    /// `did` slot (admin-only context — degenerate but possible).
    pub fn integration_did(&self) -> Option<&str> {
        match &self.reply {
            VtaReply::Full(p) => Some(p.integration_did()),
            VtaReply::AdminOnly(_) => None,
            VtaReply::ContextExport(b) => b.did.as_ref().map(|d| d.id.as_str()),
        }
    }

    /// Borrow the full [`ProvisionResult`] when the reply is
    /// [`VtaReply::Full`]. Returns `None` for `AdminOnly` and
    /// `ContextExport` — those carry their own shapes; see
    /// [`Self::as_context_export`] for the ContextExport accessor.
    pub fn as_full_provision(&self) -> Option<&ProvisionResult> {
        match &self.reply {
            VtaReply::Full(p) => Some(p),
            VtaReply::AdminOnly(_) | VtaReply::ContextExport(_) => None,
        }
    }

    /// Borrow the [`ContextProvisionBundle`] when the reply is
    /// [`VtaReply::ContextExport`]. Sibling to [`Self::as_full_provision`]
    /// — `main.rs::generate_and_write` walks both accessors when the
    /// `did_method` is `DID_VTA` and picks whichever is present.
    pub fn as_context_export(&self) -> Option<&ContextProvisionBundle> {
        match &self.reply {
            VtaReply::ContextExport(b) => Some(b),
            VtaReply::Full(_) | VtaReply::AdminOnly(_) => None,
        }
    }
}
// `Protocol` is only used by `diagnostics.rs` and the runner internally; the
// `ConnectedInfo` export above is enough for callers to read the active
// protocol without a direct import.
pub use runner::{VtaEvent, run_connection_test};
pub use setup_key::EphemeralSetupKey;

use crate::consts::{DEFAULT_VTA_CONTEXT, DEFAULT_VTA_SETUP_EXPIRY};

/// Ephemeral state for the Online-VTA sub-flow.
///
/// Never serialized — regenerated on every wizard run. Keeping this outside
/// `WizardConfig` is what guarantees the setup key and resolved endpoints
/// cannot leak into `mediator-build.toml`.
pub struct VtaConnectState {
    /// Which online path is running — `FullSetup` drives the full
    /// `provision-integration` round-trip; `AdminOnly` stops after
    /// verifying the setup DID's ACL enrollment via an authenticated
    /// DIDComm session. Set at sub-flow entry; never changes.
    pub intent: VtaIntent,
    pub vta_did: String,
    pub context_id: String,
    /// Mediator's public URL, captured during
    /// [`ConnectPhase::EnterMediatorUrl`]. Passed to the
    /// `didcomm-mediator` template as the `URL` variable when the
    /// runner calls
    /// [`crate::vta_connect::provision::provision_mediator_integration`].
    /// Empty until the operator fills it in. Unused when
    /// `intent == VtaIntent::AdminOnly`.
    pub mediator_url: String,
    pub setup_key: Option<EphemeralSetupKey>,
    pub phase: ConnectPhase,
    pub last_error: Option<String>,
    /// Webvh server catalogue returned from the preflight's
    /// `list_webvh_servers` call. Populated only on FullSetup when
    /// the preflight succeeds. Drives the `PickWebvhServer` phase:
    /// 0 entries → skip (serverless auto), 1 → auto-pick silently,
    /// 2+ → present a picker.
    pub webvh_servers: Vec<vta_sdk::webvh::WebvhServerRecord>,
    /// The operator's webvh-server pick (for 2+ catalogues) or the
    /// auto-selected id (for 1-entry catalogues). `None` means
    /// serverless — DID self-hosts at `URL`.
    pub webvh_server_choice: Option<String>,
    /// Optional path/mnemonic the operator typed in the
    /// [`ConnectPhase::EnterWebvhPath`] prompt. Forwarded to the VTA as
    /// the `WEBVH_PATH` template variable — the VTA passes it to the
    /// webvh server's `request_uri` call so the minted DID publishes
    /// under the chosen path. `None` means "server auto-assigns"
    /// (the empty-input case). Only meaningful when
    /// [`Self::webvh_server_choice`] is `Some` — the prompt is
    /// skipped on the serverless path.
    pub webvh_path: Option<String>,
    /// Mediator DID captured from the preflight, held across the
    /// picker dialog so the provision flight doesn't re-resolve.
    pub preflight_mediator_did: Option<String>,
    /// REST URL captured from the preflight, same rationale.
    pub preflight_rest_url: Option<String>,
    /// Checklist populated when Testing starts; updated as runner events
    /// arrive. Empty outside the Testing / Connected phases.
    pub diagnostics: Vec<DiagEntry>,
    /// Channel receiver for events from the spawned `run_connection_test`
    /// task. Drained on each wizard tick and then dropped when the test
    /// completes.
    pub event_rx: Option<tokio::sync::mpsc::UnboundedReceiver<VtaEvent>>,
    /// Populated once auth succeeds; future work wires this into downstream
    /// wizard steps.
    pub connection: Option<ConnectedInfo>,
    /// Transient status line for the clipboard hotkey on `AwaitingAcl`.
    /// Short message shown in the instructions block — "Copied!" on
    /// success, the arboard error on failure. Cleared on phase change
    /// so it doesn't leak onto the Testing / Connected screens.
    pub clipboard_status: Option<String>,
}

/// Linear progression through the online-VTA sub-flow. The UI layer reads this
/// to decide what to render; actions map onto transitions.
///
/// `EnterMediatorUrl` sits between `EnterContext` and `AwaitingAcl`
/// because the provision-integration runner needs the mediator's
/// public URL at run time — it's the `URL` template variable for the
/// `didcomm-mediator` template rendered by the VTA. Capturing it here
/// (rather than in the later Did step) keeps the Vta step
/// self-contained: everything the runner needs is collected before
/// the ACL command is displayed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConnectPhase {
    EnterDid,
    EnterContext,
    EnterMediatorUrl,
    AwaitingAcl,
    Testing,
    /// FullSetup-only. Preflight returned a catalogue of 2+ webvh
    /// servers and the operator needs to pick one (or opt out of
    /// hosting via the "serverless (self-host at URL)" option at
    /// the top of the list). For 0 or 1 servers the main loop
    /// auto-dispatches the provision flight without transitioning
    /// here.
    PickWebvhServer,
    /// FullSetup-only, server-hosted path only. After a webvh server
    /// has been chosen (auto-pick on single-entry catalogues, or
    /// operator-pick on 2+), prompt for an optional path/mnemonic.
    /// Blank input = server auto-assigns. Skipped on the serverless
    /// branch since there's no server to request a URI from.
    EnterWebvhPath,
    Connected,
}

impl Default for VtaConnectState {
    fn default() -> Self {
        Self::new(VtaIntent::FullSetup)
    }
}

impl VtaConnectState {
    pub fn new(intent: VtaIntent) -> Self {
        Self {
            intent,
            vta_did: String::new(),
            context_id: DEFAULT_VTA_CONTEXT.to_string(),
            mediator_url: String::new(),
            setup_key: None,
            phase: ConnectPhase::EnterDid,
            last_error: None,
            diagnostics: Vec::new(),
            event_rx: None,
            connection: None,
            clipboard_status: None,
            webvh_servers: Vec::new(),
            webvh_server_choice: None,
            webvh_path: None,
            preflight_mediator_did: None,
            preflight_rest_url: None,
        }
    }

    /// Copy the rendered `pnm acl create` command to the system clipboard
    /// via `arboard`. Result is recorded in `clipboard_status` so the
    /// renderer can surface "Copied!" or the specific error on the next
    /// frame. No-op if the setup key isn't generated yet.
    pub fn copy_acl_command_to_clipboard(&mut self) {
        let Some(cmd) = self.acl_command() else {
            self.clipboard_status = Some("Setup key not yet generated".into());
            return;
        };
        match arboard::Clipboard::new().and_then(|mut c| c.set_text(cmd)) {
            Ok(()) => {
                self.clipboard_status = Some("Copied pnm acl command".into());
            }
            Err(e) => {
                self.clipboard_status = Some(format!("Clipboard unavailable: {e}"));
            }
        }
    }

    /// Apply a single event from the runner task. Drives phase transitions
    /// on `Connected` / `Failed`.
    pub fn apply_event(&mut self, event: VtaEvent) {
        match event {
            VtaEvent::CheckStart(c) => {
                apply_update(&mut self.diagnostics, c, DiagStatus::Running);
            }
            VtaEvent::CheckDone(c, s) => {
                apply_update(&mut self.diagnostics, c, s);
            }
            VtaEvent::PreflightDone {
                rest_url,
                mediator_did,
                servers,
            } => {
                // Stash the preflight's transport details so the
                // provision flight doesn't re-resolve, and move to
                // the picker phase. The wizard's main loop
                // (`dispatch_webvh_choice`) inspects
                // `webvh_servers.len()` and either auto-selects
                // (0 / 1) or leaves the phase set for operator
                // input (2+).
                self.preflight_rest_url = rest_url;
                self.preflight_mediator_did = Some(mediator_did);
                self.webvh_servers = servers;
                self.webvh_server_choice = None;
                self.phase = ConnectPhase::PickWebvhServer;
                self.event_rx = None;
            }
            VtaEvent::Connected {
                protocol,
                rest_url,
                mediator_did,
                reply,
            } => {
                self.connection = Some(ConnectedInfo {
                    protocol,
                    rest_url,
                    mediator_did,
                    reply,
                });
                self.phase = ConnectPhase::Connected;
                self.event_rx = None;
                self.last_error = None;
            }
            VtaEvent::Failed(reason) => {
                self.last_error = Some(reason);
                self.event_rx = None;
                // Stay on Testing so the checklist remains visible. The UI
                // layer exposes Retry / Back options when
                // `last_error.is_some()`.
            }
        }
    }

    /// Render the single `pnm contexts create` command the operator runs on
    /// their Personal Network Manager to provision the mediator's context and
    /// grant admin access to the ephemeral setup DID in one shot.
    pub fn acl_command(&self) -> Option<String> {
        let setup_did = &self.setup_key.as_ref()?.did;
        Some(format!(
            "pnm contexts create --id {} --name \"Mediator\" \
             --admin-did {setup_did} --admin-expires {}",
            self.context_id, DEFAULT_VTA_SETUP_EXPIRY
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acl_command_renders_single_pnm_contexts_create() {
        let mut st = VtaConnectState::new(VtaIntent::FullSetup);
        st.context_id = "mediator-prod".into();
        st.setup_key = Some(EphemeralSetupKey::generate().unwrap());
        let cmd = st.acl_command().unwrap();
        assert!(cmd.starts_with("pnm contexts create"));
        assert!(cmd.contains("--id mediator-prod"));
        assert!(cmd.contains("--name \"Mediator\""));
        assert!(cmd.contains("--admin-did did:key:z6Mk"));
        assert!(cmd.contains("--admin-expires 1h"));
    }

    #[test]
    fn acl_command_none_without_setup_key() {
        let st = VtaConnectState::new(VtaIntent::FullSetup);
        assert!(st.acl_command().is_none());
    }

    #[test]
    fn default_context_is_mediator() {
        let st = VtaConnectState::new(VtaIntent::FullSetup);
        assert_eq!(st.context_id, DEFAULT_VTA_CONTEXT);
    }
}
