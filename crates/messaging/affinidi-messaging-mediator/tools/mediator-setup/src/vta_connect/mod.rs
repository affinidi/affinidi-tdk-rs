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
pub mod resolve;
pub mod runner;
pub mod setup_key;

pub use diagnostics::{
    ConnectedInfo, DiagCheck, DiagEntry, DiagStatus, apply_update, pending_list,
};

/// A completed VTA connection — retained on `WizardApp` after the sub-flow
/// exits so downstream steps (Did, Summary, secret-writing) can use the
/// authenticated session.
#[derive(Clone, Debug)]
pub struct VtaSession {
    pub rest_url: String,
    pub access_token: String,
    pub context_id: String,
    pub vta_did: String,
    /// Rotated admin did:key — not the setup DID the operator pasted into
    /// the ACL command. Persisted into the chosen secret backend so the
    /// mediator can authenticate to the VTA at runtime.
    pub admin_did: String,
    /// Private key (multibase) matching `admin_did`.
    pub admin_private_key_mb: String,
    /// webvh hosting services registered on the VTA, captured once
    /// at connect time. The Did step shows these as DID-publish
    /// options; empty list means "self-host only".
    pub webvh_servers: Vec<vta_sdk::webvh::WebvhServerRecord>,
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
    pub vta_did: String,
    pub context_id: String,
    pub setup_key: Option<EphemeralSetupKey>,
    pub phase: ConnectPhase,
    pub last_error: Option<String>,
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
}

/// Linear progression through the online-VTA sub-flow. The UI layer reads this
/// to decide what to render; actions map onto transitions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConnectPhase {
    EnterDid,
    EnterContext,
    AwaitingAcl,
    Testing,
    Connected,
}

impl Default for VtaConnectState {
    fn default() -> Self {
        Self::new()
    }
}

impl VtaConnectState {
    pub fn new() -> Self {
        Self {
            vta_did: String::new(),
            context_id: DEFAULT_VTA_CONTEXT.to_string(),
            setup_key: None,
            phase: ConnectPhase::EnterDid,
            last_error: None,
            diagnostics: Vec::new(),
            event_rx: None,
            connection: None,
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
            VtaEvent::Connected {
                protocol,
                access_token,
                rest_url,
                admin_did,
                admin_private_key_mb,
                webvh_servers,
            } => {
                self.connection = Some(ConnectedInfo {
                    protocol,
                    access_token,
                    rest_url,
                    admin_did,
                    admin_private_key_mb,
                    webvh_servers,
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
        let mut st = VtaConnectState::new();
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
        let st = VtaConnectState::new();
        assert!(st.acl_command().is_none());
    }

    #[test]
    fn default_context_is_mediator() {
        let st = VtaConnectState::new();
        assert_eq!(st.context_id, DEFAULT_VTA_CONTEXT);
    }
}
