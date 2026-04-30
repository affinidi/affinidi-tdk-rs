//! TUI state machine for the online VTA sub-flow.
//!
//! The wizard's online VTA flow walks through a small set of phases
//! ([`ConnectPhase`]) gathering operator input, dispatching the
//! [`vta_sdk::provision_client`] runner, and routing terminal outcomes
//! to a recovery / fallback prompt or the success screen.
//!
//! This module owns the phase machine + per-attempt history. The wire
//! protocol (events on a channel, sealed-bundle opening, transport
//! selection) lives in the SDK; consuming the events is the wizard's
//! job.

use std::time::Instant;

use vta_sdk::provision_client::{
    AttemptLog, AttemptResult, AttemptResultKind, ConnectedInfo, DiagEntry, DiagStatus,
    EphemeralSetupKey, Protocol, ResolvedVta, VtaEvent, VtaReply as SdkVtaReply, apply_update,
};
use vta_sdk::webvh::WebvhServerRecord;

use super::intent::VtaIntent;
use crate::consts::{DEFAULT_VTA_CONTEXT, DEFAULT_VTA_SETUP_EXPIRY};

/// Whether each retry / offline option is available on the recovery
/// prompt. The prompt dims unavailable options.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryOptions {
    pub retry_didcomm: bool,
    pub retry_rest: bool,
    pub offline_available: bool,
}

/// Whether each fallback action is available on the
/// `TransportFallbackPrompt` panel. Slice 3 fires this panel only
/// when an attempt failed pre-auth and the alternate transport is
/// advertised but not yet attempted — the prompt offers the
/// operator an interactive choice between falling back, retrying
/// the same wire, or switching to offline.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FallbackOptions {
    pub fall_back_to_rest: bool,
    pub retry_didcomm: bool,
    pub offline_available: bool,
}

/// Why the wizard transitioned from the online flow into the
/// offline sealed-handoff sub-flow. Carried into
/// [`crate::sealed_handoff::SealedHandoffState`] so the intro
/// screen can show the operator a one-line banner explaining
/// what happened and what to do next.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OfflineReason {
    /// Both transports failed (or only one was available and it
    /// failed). Pre- and post-auth alike — the operator chose to
    /// switch wires rather than keep trying online.
    BothFailed,
    /// The VTA's DID document advertised neither DIDComm nor REST.
    /// No online transport was ever attempted.
    NoTransportAvailable,
    /// Operator pressed `[O]` from the recovery prompt as a
    /// proactive choice — not because online attempts were
    /// exhausted. Reserved for a future "force offline" hotkey;
    /// the current recovery prompt always falls into one of the
    /// other two.
    #[allow(dead_code)]
    OperatorChoice,
}

impl OfflineReason {
    /// Operator-facing one-line banner. Stored on the sealed-handoff
    /// state and rendered above its intro to make the transition
    /// reason explicit.
    pub fn banner(&self) -> &'static str {
        match self {
            Self::BothFailed => "Online attempts failed — switching to offline sealed-handoff.",
            Self::NoTransportAvailable => {
                "VTA advertises no online transport — using offline sealed-handoff instead."
            }
            Self::OperatorChoice => "Switched to offline sealed-handoff at operator request.",
        }
    }
}

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
    /// [`ConnectPhase::EnterMediatorUrl`]. Becomes the `URL`
    /// template variable on the `ProvisionAsk::didcomm_mediator(..)`
    /// the runner builds. Empty until the operator fills it in.
    /// Unused when `intent == VtaIntent::AdminOnly`.
    pub mediator_url: String,
    pub setup_key: Option<EphemeralSetupKey>,
    pub phase: ConnectPhase,
    pub last_error: Option<String>,
    /// Webvh server catalogue returned from the preflight's
    /// `list_webvh_servers` call. Populated only on FullSetup when
    /// the preflight succeeds. Drives the `PickWebvhServer` phase:
    /// 0 entries → skip (serverless auto), 1 → auto-pick silently,
    /// 2+ → present a picker.
    pub webvh_servers: Vec<WebvhServerRecord>,
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
    /// VTA endpoints resolved from the DID document during the
    /// runner's resolve step. Populated via [`VtaEvent::Resolved`].
    /// Read by [`recovery_options`](Self::recovery_options) to know
    /// which transports the VTA actually advertises.
    pub resolved: Option<ResolvedVta>,
    /// Per-transport attempt history populated via
    /// [`VtaEvent::AttemptCompleted`]. Drives the recovery prompt's
    /// option-availability rules — a retry is only offered for a
    /// transport whose last attempt failed pre-auth.
    pub attempted: AttemptLog,
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
    /// All online attempts exhausted (or no transport advertised).
    /// The prompt offers retry of any pre-auth-failed transport,
    /// transition to the offline sealed-handoff sub-flow, or going
    /// back to a previous phase.
    RecoveryPrompt,
    /// Pre-auth failure with an unattempted alternate transport
    /// available. The prompt offers `[F]` to fall back, `[R]` to
    /// retry the same wire, `[O]` to go offline, or `[B]` to
    /// back out.
    TransportFallbackPrompt,
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
            resolved: None,
            attempted: AttemptLog::default(),
        }
    }

    /// Compute which actions the recovery prompt should offer.
    ///
    /// `retry_*` is true iff the transport is advertised in the
    /// resolved DID document AND its last attempt was a pre-auth
    /// failure. A post-auth failure means the VTA accepted us and
    /// rejected the request body; retrying the same wire reproduces
    /// the rejection. A transport never attempted on this run also
    /// has no retry offer — the operator's path back to it is
    /// "go back" + re-trigger, not the recovery prompt.
    ///
    /// `offline_available` is always true: sealed-handoff is the
    /// universal escape hatch.
    pub fn recovery_options(&self, resolved: &ResolvedVta) -> RecoveryOptions {
        RecoveryOptions {
            retry_didcomm: resolved.mediator_did.is_some()
                && matches!(
                    self.attempted.didcomm.as_ref().map(|r| &r.outcome),
                    Some(AttemptResultKind::PreAuthFailure(_))
                ),
            retry_rest: resolved.rest_url.is_some()
                && matches!(
                    self.attempted.rest.as_ref().map(|r| &r.outcome),
                    Some(AttemptResultKind::PreAuthFailure(_))
                ),
            offline_available: true,
        }
    }

    /// Compute the action availability for the
    /// `TransportFallbackPrompt` panel.
    ///
    /// `fall_back_to_rest` is true iff REST is advertised AND has
    /// not been attempted yet — falling back to a transport that
    /// already failed is not actually a fallback. `retry_didcomm`
    /// follows the same pre-auth rule as `recovery_options`.
    pub fn fallback_options(&self, resolved: &ResolvedVta) -> FallbackOptions {
        FallbackOptions {
            fall_back_to_rest: resolved.rest_url.is_some() && self.attempted.rest.is_none(),
            retry_didcomm: resolved.mediator_did.is_some()
                && matches!(
                    self.attempted.didcomm.as_ref().map(|r| &r.outcome),
                    Some(AttemptResultKind::PreAuthFailure(_))
                ),
            offline_available: true,
        }
    }

    /// Identify the most recently completed attempt and which
    /// transport ran it. Used by [`apply_event`] to decide between
    /// `TransportFallbackPrompt` (recent attempt was pre-auth) and
    /// `RecoveryPrompt` (post-auth, or no fallback target).
    pub fn last_attempt(&self) -> Option<(Protocol, &AttemptResult)> {
        match (&self.attempted.didcomm, &self.attempted.rest) {
            (Some(d), Some(r)) if d.at >= r.at => Some((Protocol::DidComm, d)),
            (Some(_), Some(r)) => Some((Protocol::Rest, r)),
            (Some(d), None) => Some((Protocol::DidComm, d)),
            (None, Some(r)) => Some((Protocol::Rest, r)),
            (None, None) => None,
        }
    }

    /// Decide whether a `Failed` event should land on the
    /// `TransportFallbackPrompt` rather than the broader
    /// `RecoveryPrompt`. The answer is yes iff:
    ///   1. We've recorded an attempt outcome (so we know which
    ///      transport just ran).
    ///   2. That attempt failed pre-auth — post-auth means the
    ///      VTA accepted us; a different wire would reproduce the
    ///      rejection.
    ///   3. The alternate transport is advertised in the resolved
    ///      DID document.
    ///   4. The alternate transport hasn't been tried yet on this
    ///      run — falling back to a wire that already failed isn't
    ///      a fallback.
    fn should_route_to_fallback(&self) -> bool {
        let resolved = match self.resolved.as_ref() {
            Some(r) => r,
            None => return false,
        };
        let (protocol, result) = match self.last_attempt() {
            Some(pair) => pair,
            None => return false,
        };
        if !matches!(result.outcome, AttemptResultKind::PreAuthFailure(_)) {
            return false;
        }
        match protocol {
            Protocol::DidComm => resolved.rest_url.is_some() && self.attempted.rest.is_none(),
            Protocol::Rest => resolved.mediator_did.is_some() && self.attempted.didcomm.is_none(),
        }
    }

    /// Copy the rendered `pnm acl create` command to the operator's
    /// clipboard. No-op if the setup key isn't generated yet.
    pub fn copy_acl_command_to_clipboard(&mut self) {
        let Some(cmd) = self.acl_command() else {
            self.clipboard_status = Some("Setup key not yet generated".into());
            return;
        };
        self.copy_text_to_clipboard(&cmd, "pnm acl command");
    }

    /// Copy the operator-supplied VTA DID to the clipboard. Hotkey
    /// `[v]` on the `Connected` phase. Status line surfaces the
    /// method (OSC 52 / system clipboard).
    pub fn copy_vta_did_to_clipboard(&mut self) {
        if self.vta_did.is_empty() {
            self.clipboard_status = Some("VTA DID not yet entered".into());
            return;
        }
        let did = self.vta_did.clone();
        self.copy_text_to_clipboard(&did, "VTA DID");
    }

    /// Copy the VTA-minted (or VTA-exported) mediator integration
    /// DID to the clipboard. Hotkey `[m]` on the `Connected` phase.
    /// AdminOnly runs have no VTA-minted mediator DID — the
    /// operator brought their own — so we surface a friendly
    /// status rather than silently doing nothing.
    pub fn copy_mediator_did_to_clipboard(&mut self) {
        let Some(conn) = self.connection.as_ref() else {
            self.clipboard_status = Some("No connection yet".into());
            return;
        };
        let did = match &conn.reply {
            SdkVtaReply::Full(p) => match p.integration_did() {
                Some(did) => did.to_string(),
                None => {
                    self.clipboard_status =
                        Some("AdminRotation flow — no VTA-minted mediator DID".into());
                    return;
                }
            },
            SdkVtaReply::AdminOnly(_) => {
                self.clipboard_status = Some("AdminOnly mode — no VTA-minted mediator DID".into());
                return;
            }
        };
        self.copy_text_to_clipboard(&did, "mediator DID");
    }

    /// Copy the long-term admin DID to the clipboard. Hotkey `[a]`
    /// on the `Connected` phase. Available for both online reply
    /// variants (every successful run has an admin credential).
    pub fn copy_admin_did_to_clipboard(&mut self) {
        let Some(conn) = self.connection.as_ref() else {
            self.clipboard_status = Some("No connection yet".into());
            return;
        };
        let did = match &conn.reply {
            SdkVtaReply::Full(p) => p.admin_did().to_string(),
            SdkVtaReply::AdminOnly(a) => a.admin_did.clone(),
        };
        self.copy_text_to_clipboard(&did, "admin DID");
    }

    /// Shared clipboard-write helper. Goes through
    /// [`crate::clipboard::copy_to_clipboard`] (SSH-aware OSC 52 +
    /// arboard fallback) and renders the operator-facing status
    /// line on `clipboard_status`.
    fn copy_text_to_clipboard(&mut self, text: &str, label: &str) {
        match crate::clipboard::copy_to_clipboard(text) {
            Ok(method) => {
                self.clipboard_status = Some(format!("Copied {label} via {}", method.label()));
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
                // A pre-auth failure with an unattempted alternate
                // transport routes to the FallbackPrompt; everything
                // else routes to the RecoveryPrompt. Post-auth
                // failures (VTA accepted us but rejected the request
                // body) always go to recovery — a different wire
                // reproduces the rejection.
                self.phase = if self.should_route_to_fallback() {
                    ConnectPhase::TransportFallbackPrompt
                } else {
                    ConnectPhase::RecoveryPrompt
                };
            }
            VtaEvent::Resolved(resolved) => {
                self.resolved = Some(resolved);
            }
            VtaEvent::AttemptCompleted { protocol, outcome } => {
                let result = AttemptResult {
                    outcome,
                    at: Instant::now(),
                };
                match protocol {
                    Protocol::DidComm => self.attempted.didcomm = Some(result),
                    Protocol::Rest => self.attempted.rest = Some(result),
                }
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

    fn resolved(mediator_did: Option<&str>, rest_url: Option<&str>) -> ResolvedVta {
        ResolvedVta {
            vta_did: "did:webvh:vta.test".into(),
            mediator_did: mediator_did.map(str::to_string),
            rest_url: rest_url.map(str::to_string),
        }
    }

    fn pre_auth() -> AttemptResult {
        AttemptResult {
            outcome: AttemptResultKind::PreAuthFailure("ACL not found".into()),
            at: Instant::now(),
        }
    }

    fn post_auth() -> AttemptResult {
        AttemptResult {
            outcome: AttemptResultKind::PostAuthFailure("template render rejected".into()),
            at: Instant::now(),
        }
    }

    fn connected() -> AttemptResult {
        AttemptResult {
            outcome: AttemptResultKind::Connected,
            at: Instant::now(),
        }
    }

    #[test]
    fn recovery_offers_retry_after_pre_auth_failure() {
        let mut st = VtaConnectState::new(VtaIntent::FullSetup);
        st.attempted.didcomm = Some(pre_auth());
        let opts = st.recovery_options(&resolved(Some("did:webvh:m"), None));
        assert!(opts.retry_didcomm, "pre-auth failure should be retryable");
        assert!(!opts.retry_rest);
        assert!(opts.offline_available);
    }

    #[test]
    fn recovery_does_not_offer_retry_after_post_auth_failure() {
        let mut st = VtaConnectState::new(VtaIntent::FullSetup);
        st.attempted.didcomm = Some(post_auth());
        let opts = st.recovery_options(&resolved(Some("did:webvh:m"), None));
        assert!(
            !opts.retry_didcomm,
            "post-auth failure means VTA accepted us — no retry"
        );
        assert!(opts.offline_available);
    }

    #[test]
    fn recovery_dims_retry_when_transport_not_advertised() {
        let mut st = VtaConnectState::new(VtaIntent::FullSetup);
        st.attempted.didcomm = Some(pre_auth());
        let opts = st.recovery_options(&resolved(None, Some("https://vta.test")));
        assert!(!opts.retry_didcomm);
    }

    #[test]
    fn recovery_dims_retry_when_never_attempted() {
        let st = VtaConnectState::new(VtaIntent::FullSetup);
        let opts = st.recovery_options(&resolved(Some("did:webvh:m"), Some("https://vta.test")));
        assert!(!opts.retry_didcomm, "no attempt → no retry offer");
        assert!(!opts.retry_rest);
        assert!(opts.offline_available);
    }

    #[test]
    fn recovery_does_not_offer_retry_after_successful_connection() {
        let mut st = VtaConnectState::new(VtaIntent::FullSetup);
        st.attempted.rest = Some(connected());
        let opts = st.recovery_options(&resolved(None, Some("https://vta.test")));
        assert!(
            !opts.retry_rest,
            "connected attempt is a final state, not retryable"
        );
    }

    // ─── fallback_options ──────────────────────────────────────────

    #[test]
    fn fallback_offers_rest_after_didcomm_pre_auth() {
        let mut st = VtaConnectState::new(VtaIntent::FullSetup);
        st.attempted.didcomm = Some(pre_auth());
        let opts = st.fallback_options(&resolved(Some("did:webvh:m"), Some("https://vta.test")));
        assert!(opts.fall_back_to_rest);
        assert!(opts.retry_didcomm);
        assert!(opts.offline_available);
    }

    #[test]
    fn fallback_disables_rest_when_not_advertised() {
        let mut st = VtaConnectState::new(VtaIntent::FullSetup);
        st.attempted.didcomm = Some(pre_auth());
        let opts = st.fallback_options(&resolved(Some("did:webvh:m"), None));
        assert!(!opts.fall_back_to_rest);
        assert!(opts.retry_didcomm);
    }

    #[test]
    fn fallback_disables_rest_when_already_attempted() {
        let mut st = VtaConnectState::new(VtaIntent::FullSetup);
        st.attempted.didcomm = Some(pre_auth());
        st.attempted.rest = Some(pre_auth());
        let opts = st.fallback_options(&resolved(Some("did:webvh:m"), Some("https://vta.test")));
        assert!(!opts.fall_back_to_rest);
    }

    #[test]
    fn fallback_disables_retry_after_post_auth_didcomm() {
        let mut st = VtaConnectState::new(VtaIntent::FullSetup);
        st.attempted.didcomm = Some(post_auth());
        let opts = st.fallback_options(&resolved(Some("did:webvh:m"), Some("https://vta.test")));
        assert!(!opts.retry_didcomm);
    }

    // ─── last_attempt ──────────────────────────────────────────────

    #[test]
    fn last_attempt_picks_most_recent() {
        let mut st = VtaConnectState::new(VtaIntent::FullSetup);
        let earlier = AttemptResult {
            outcome: AttemptResultKind::PreAuthFailure("first".into()),
            at: Instant::now(),
        };
        std::thread::sleep(std::time::Duration::from_millis(2));
        let later = AttemptResult {
            outcome: AttemptResultKind::PreAuthFailure("second".into()),
            at: Instant::now(),
        };
        st.attempted.didcomm = Some(earlier);
        st.attempted.rest = Some(later);
        let (protocol, _) = st.last_attempt().expect("two attempts recorded");
        assert_eq!(protocol, Protocol::Rest);
    }

    #[test]
    fn last_attempt_none_without_attempts() {
        let st = VtaConnectState::new(VtaIntent::FullSetup);
        assert!(st.last_attempt().is_none());
    }

    // ─── apply_event routing ───────────────────────────────────────

    #[test]
    fn pre_auth_didcomm_with_rest_advertised_routes_to_fallback_prompt() {
        let mut st = VtaConnectState::new(VtaIntent::FullSetup);
        st.resolved = Some(resolved(Some("did:webvh:m"), Some("https://vta.test")));
        st.apply_event(VtaEvent::AttemptCompleted {
            protocol: Protocol::DidComm,
            outcome: AttemptResultKind::PreAuthFailure("ACL not found".into()),
        });
        st.apply_event(VtaEvent::Failed("ACL not found".into()));
        assert_eq!(st.phase, ConnectPhase::TransportFallbackPrompt);
    }

    #[test]
    fn pre_auth_didcomm_without_rest_routes_to_recovery_prompt() {
        let mut st = VtaConnectState::new(VtaIntent::FullSetup);
        st.resolved = Some(resolved(Some("did:webvh:m"), None));
        st.apply_event(VtaEvent::AttemptCompleted {
            protocol: Protocol::DidComm,
            outcome: AttemptResultKind::PreAuthFailure("ACL not found".into()),
        });
        st.apply_event(VtaEvent::Failed("ACL not found".into()));
        assert_eq!(st.phase, ConnectPhase::RecoveryPrompt);
    }

    #[test]
    fn post_auth_failure_always_routes_to_recovery_prompt() {
        let mut st = VtaConnectState::new(VtaIntent::FullSetup);
        st.resolved = Some(resolved(Some("did:webvh:m"), Some("https://vta.test")));
        st.apply_event(VtaEvent::AttemptCompleted {
            protocol: Protocol::DidComm,
            outcome: AttemptResultKind::PostAuthFailure("template render rejected".into()),
        });
        st.apply_event(VtaEvent::Failed("template render rejected".into()));
        assert_eq!(st.phase, ConnectPhase::RecoveryPrompt);
    }

    #[test]
    fn rest_pre_auth_after_didcomm_failure_routes_to_recovery_prompt() {
        let mut st = VtaConnectState::new(VtaIntent::FullSetup);
        st.resolved = Some(resolved(Some("did:webvh:m"), Some("https://vta.test")));
        st.attempted.didcomm = Some(pre_auth());
        st.apply_event(VtaEvent::AttemptCompleted {
            protocol: Protocol::Rest,
            outcome: AttemptResultKind::PreAuthFailure("REST 401".into()),
        });
        st.apply_event(VtaEvent::Failed("REST 401".into()));
        assert_eq!(st.phase, ConnectPhase::RecoveryPrompt);
    }

    // ─── AttemptLog edge cases ─────────────────────────────────────

    #[test]
    fn attempt_log_overwrites_with_most_recent_outcome() {
        let mut st = VtaConnectState::new(VtaIntent::FullSetup);
        st.apply_event(VtaEvent::AttemptCompleted {
            protocol: Protocol::DidComm,
            outcome: AttemptResultKind::PreAuthFailure("first try".into()),
        });
        st.apply_event(VtaEvent::AttemptCompleted {
            protocol: Protocol::DidComm,
            outcome: AttemptResultKind::Connected,
        });
        let entry = st.attempted.didcomm.as_ref().unwrap();
        assert!(matches!(entry.outcome, AttemptResultKind::Connected));
    }

    #[test]
    fn attempt_log_independently_tracks_each_transport() {
        let mut st = VtaConnectState::new(VtaIntent::FullSetup);
        st.apply_event(VtaEvent::AttemptCompleted {
            protocol: Protocol::DidComm,
            outcome: AttemptResultKind::PreAuthFailure("didcomm reason".into()),
        });
        st.apply_event(VtaEvent::AttemptCompleted {
            protocol: Protocol::Rest,
            outcome: AttemptResultKind::PostAuthFailure("rest reason".into()),
        });
        assert!(matches!(
            st.attempted.didcomm.as_ref().unwrap().outcome,
            AttemptResultKind::PreAuthFailure(_)
        ));
        assert!(matches!(
            st.attempted.rest.as_ref().unwrap().outcome,
            AttemptResultKind::PostAuthFailure(_)
        ));
    }

    #[test]
    fn fallback_eligible_when_didcomm_pre_auth_then_didcomm_succeeds() {
        let mut st = VtaConnectState::new(VtaIntent::FullSetup);
        let r = resolved(Some("did:webvh:m"), Some("https://vta.test"));
        st.resolved = Some(r.clone());
        st.attempted.didcomm = Some(pre_auth());
        st.attempted.rest = Some(pre_auth());
        st.apply_event(VtaEvent::AttemptCompleted {
            protocol: Protocol::DidComm,
            outcome: AttemptResultKind::Connected,
        });
        let opts = st.recovery_options(&r);
        assert!(!opts.retry_didcomm, "Connected — no retry");
        assert!(opts.retry_rest, "REST is still pre-auth-failed");
    }
}
