use tokio::sync::mpsc::{UnboundedReceiver, unbounded_channel};
use tui_input::{Input, InputRequest};

use crate::consts::*;
use crate::discovery::{DiscoveryEvent, DiscoveryMode, DiscoveryRequest, DiscoveryState};
use crate::sealed_handoff::SealedHandoffState;
use crate::ui::selection::SelectionOption;
use crate::vta_connect::{
    ConnectPhase, EphemeralSetupKey, VtaConnectState, VtaIntent, VtaSession, VtaTransport,
    pending_list, run_connection_test,
};

/// All wizard steps in order.
///
/// Ordering note: `KeyStorage` runs before `Vta` deliberately. The secret
/// backend is the foundation everything else writes to — if it's
/// unreachable we want to know *before* spending time on VTA provisioning.
/// The VTA sub-flow also persists the rotated admin credential into this
/// backend on completion, so it needs to exist first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WizardStep {
    Deployment,
    KeyStorage,
    Vta,
    Protocol,
    Did,
    Security,
    Database,
    Admin,
    /// Where to write `mediator.toml`. Added as its own step so the
    /// question is asked inside the TUI (consistent nav + validation)
    /// rather than via a stdin prompt after the TUI exits.
    Output,
    Summary,
}

impl WizardStep {
    pub fn all() -> Vec<WizardStep> {
        vec![
            Self::Deployment,
            Self::KeyStorage,
            Self::Vta,
            Self::Protocol,
            Self::Did,
            Self::Security,
            Self::Database,
            Self::Admin,
            Self::Output,
            Self::Summary,
        ]
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Deployment => "Deployment Type",
            Self::Vta => "VTA Integration",
            Self::Protocol => "Protocol",
            Self::Did => "DID Configuration",
            Self::KeyStorage => "Key Storage",
            Self::Security => "SSL/TLS & JWT",
            Self::Database => "Database",
            Self::Admin => "Admin Account",
            Self::Output => "Output Location",
            Self::Summary => "Summary",
        }
    }

    pub fn index(&self) -> usize {
        Self::all().iter().position(|s| s == self).unwrap_or(0)
    }

    pub fn step_number(&self) -> usize {
        self.index() + 1
    }

    pub fn total() -> usize {
        Self::all().len()
    }

    pub fn next(&self) -> Option<WizardStep> {
        let steps = Self::all();
        let idx = self.index();
        steps.get(idx + 1).copied()
    }

    pub fn prev(&self) -> Option<WizardStep> {
        let steps = Self::all();
        let idx = self.index();
        if idx > 0 {
            steps.get(idx - 1).copied()
        } else {
            None
        }
    }

    /// True for steps whose selection list is multi-select (Space toggles,
    /// Enter advances). Exposed so the key handler and the global help bar
    /// can reflect the right key cues. Add any new multi-select step here.
    pub fn is_multi_select(&self) -> bool {
        matches!(self, Self::Protocol)
    }

    pub fn step_data(&self) -> StepData {
        let total = Self::total();
        let num = self.step_number();
        match self {
            Self::Deployment => StepData {
                title: format!("Step {num}/{total}: Deployment Type"),
                description: "What kind of deployment is this?".into(),
            },
            Self::Vta => StepData {
                title: format!("Step {num}/{total}: VTA Integration"),
                description: "Will this mediator use a Verifiable Trust Agent (VTA)?".into(),
            },
            Self::Protocol => StepData {
                title: format!("Step {num}/{total}: Messaging Protocol"),
                description:
                    "Toggle protocols with Enter. At least one required. Press Esc to continue."
                        .into(),
            },
            Self::Did => StepData {
                title: format!("Step {num}/{total}: DID Configuration"),
                description: "How should the mediator's DID be configured?".into(),
            },
            Self::KeyStorage => StepData {
                title: format!("Step {num}/{total}: Key Storage"),
                description: "Where should cryptographic keys be stored?".into(),
            },
            Self::Security => StepData {
                title: format!("Step {num}/{total}: SSL/TLS & JWT"),
                description: "Configure transport security and authentication tokens.".into(),
            },
            Self::Database => StepData {
                title: format!("Step {num}/{total}: Database"),
                description: "Enter the Redis connection URL.".into(),
            },
            Self::Admin => StepData {
                title: format!("Step {num}/{total}: Admin Account"),
                description: "Configure the admin DID for mediator management.".into(),
            },
            Self::Output => StepData {
                title: format!("Step {num}/{total}: Output Location"),
                description: "Where should the wizard write mediator.toml? (secrets.json, \
                     atm-functions.lua, did.jsonl all land in the same directory.)"
                    .into(),
            },
            Self::Summary => StepData {
                title: "Summary".into(),
                description: "Review and confirm your configuration.".into(),
            },
        }
    }
}

pub struct StepData {
    pub title: String,
    pub description: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputMode {
    /// Navigating a selection list in the right panel
    Selecting,
    /// Typing into a text field
    TextInput,
    /// Confirming an action (summary write)
    Confirming,
}

/// Which panel has keyboard focus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FocusPanel {
    /// Right panel — step content (options, text input)
    Content,
    /// Left panel — step progress list (click to jump to a step)
    Progress,
}

/// Sub-phases of the `KeyStorage` step that gather backend-specific config.
///
/// The operator picks a scheme on the selection list (implicit
/// `SelectScheme` phase, represented as `key_storage_phase: None`), and any
/// backend that needs extra info then walks through the relevant phases.
/// The placeholder cloud backends (gcp/azure/vault) have no config to
/// gather yet and skip straight to `advance()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyStoragePhase {
    /// `file://` — dev-only hard-gate. The operator must type the
    /// literal phrase `I understand` (case-insensitive) before the
    /// wizard advances to [`Self::FilePath`]. Anything else aborts the
    /// selection and rewinds to the scheme list.
    FileGate,
    /// `file://` — prompt for the path to write secrets.json.
    FilePath,
    /// `file://` — ask whether to encrypt with a passphrase
    /// (envelope-encryption via Argon2id + AES-GCM). Selecting "yes"
    /// advances to [`Self::FilePassphrase`]; "no" finishes the
    /// sub-flow with a plaintext file.
    FileEncryptChoice,
    /// `file://` — collect the passphrase via a masked prompt. The
    /// passphrase is exported as `MEDIATOR_FILE_BACKEND_PASSPHRASE`
    /// for the duration of the wizard process so the secret backend
    /// can derive its key when `MediatorSecrets::from_url` is called
    /// in `generate_and_write`.
    FilePassphrase,
    /// `keyring://` — prompt for the OS-keyring service name.
    KeyringService,
    /// `aws_secrets://` — first prompt: AWS region.
    AwsRegion,
    /// `aws_secrets://` — second prompt: secret name prefix.
    AwsPrefix,
    /// `gcp_secrets://` — first prompt: GCP project ID.
    GcpProject,
    /// `gcp_secrets://` — second prompt: secret name prefix.
    GcpPrefix,
    /// `azure_keyvault://` — vault name (commercial cloud), sovereign-
    /// cloud DNS name, or full URL. Single field — Azure Key Vault
    /// secrets share the vault namespace; the URL parser canonicalises.
    AzureVault,
    /// `vault://` — first prompt: server endpoint (`host[:port]`).
    VaultEndpoint,
    /// `vault://` — second prompt: KV v2 mount + optional per-key
    /// prefix glued (e.g. `secret/mediator`).
    VaultMount,
}

/// Literal phrase the operator must type to clear the `file://` hard-gate.
/// Stored as a constant so tests and the prompt rendering stay in sync.
pub const FILE_GATE_PHRASE: &str = "I understand";

/// Sub-phases of the `Did` step when `DID_VTA` is selected. After the
/// mediator URL is captured, the wizard asks the operator where the
/// VTA should publish the DID — pick a registered webvh hosting
/// service, self-host at the mediator URL, or self-host at a
/// different URL. Mirrors the `KeyStoragePhase` shape.
///
/// Skipped entirely for did:peer / did:webvh / import paths and for
/// sealed-handoff VTA sessions (those bring a fully-provisioned DID
/// already, no hosting choice to make).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DidPhase {
    /// Selection list: self-host-at-mediator / each VTA-hosted server
    /// / self-host-elsewhere.
    SelectWebvhHost,
    /// Text input for a different self-host base URL.
    EnterCustomUrl,
}

/// Sub-phases of the `Security` step. The SSL portion (selection list +
/// optional cert/key text inputs) runs as the implicit `None` phase; once
/// SSL is settled the wizard pivots to a small JWT-mode selection before
/// advancing to `Database`. Mirrors the `KeyStoragePhase` shape so that
/// the renderer can use the same "step has a sub-phase" pattern.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityPhase {
    /// Choose between generating a fresh JWT signing key or providing
    /// one out-of-band via env var / `--jwt-secret-file` at boot.
    JwtMode,
}

/// Sub-phases of the top-level `Vta` step picker (before any of the
/// transport-specific sub-flows take over).
///
/// Splits the single "VTA mode" question into two orthogonal
/// questions — intent (what do you want from the VTA?) and transport
/// (how does the request reach the VTA?). The four intent×transport
/// leaves each route into one of four adapters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VtaStepPhase {
    /// First question — FullSetup / AdminOnly / No VTA.
    SelectIntent,
    /// Second question — Online / Sealed handoff. Only reached after
    /// the operator picked a non-`None` intent on [`Self::SelectIntent`].
    SelectTransport,
}

impl KeyStoragePhase {
    /// First config phase for the given scheme. `None` means the scheme
    /// needs no extra config and can advance immediately.
    pub fn first_for(scheme: &str) -> Option<Self> {
        match scheme {
            // file:// always starts at the hard-gate, never directly at
            // FilePath. This is intentional: skipping the gate means
            // skipping the dev-only acknowledgement.
            STORAGE_FILE => Some(Self::FileGate),
            STORAGE_KEYRING => Some(Self::KeyringService),
            STORAGE_AWS => Some(Self::AwsRegion),
            STORAGE_GCP => Some(Self::GcpProject),
            STORAGE_AZURE => Some(Self::AzureVault),
            STORAGE_VAULT => Some(Self::VaultEndpoint),
            _ => None,
        }
    }
}

/// Accumulated configuration choices from the wizard.
#[derive(Debug, Clone)]
pub struct WizardConfig {
    pub config_path: String,
    pub deployment_type: String,
    /// Whether VTA integration is enabled
    pub use_vta: bool,
    /// VTA connectivity mode: `"online"`, `"sealed-mint"`, or
    /// `"sealed-export"`. See `consts::VTA_MODE_*`.
    pub vta_mode: String,
    /// VTA context id this mediator lives in. Populated from the
    /// recipe's `[vta] context` field or the TUI's sealed-handoff
    /// CollectContext phase. Defaults to
    /// [`crate::consts::DEFAULT_VTA_CONTEXT`] when unset.
    pub vta_context: String,
    /// DIDComm v2 protocol enabled (default: true)
    pub didcomm_enabled: bool,
    /// TSP protocol enabled (experimental, default: false)
    pub tsp_enabled: bool,
    pub did_method: String,
    pub public_url: String,
    pub secret_storage: String,
    // Per-backend config fields. Only the set relevant to `secret_storage`
    // is meaningful; others stay at defaults. Storing them as flat strings
    // keeps `WizardConfig` serialisable into the build-recipe TOML.
    pub secret_file_path: String,
    pub secret_keyring_service: String,
    pub secret_aws_region: String,
    pub secret_aws_prefix: String,
    /// GCP project ID hosting the mediator's secrets. Used together
    /// with [`Self::secret_gcp_prefix`] to build `gcp_secrets://`.
    pub secret_gcp_project: String,
    /// Per-secret name prefix on GCP. Empty is allowed — GCP secret
    /// names accept the bare well-known keys verbatim.
    pub secret_gcp_prefix: String,
    /// Bare vault name (`my-vault`), sovereign-cloud DNS name
    /// (`my-vault.vault.usgovcloudapi.net`), or full URL — the URL
    /// parser canonicalises all three shapes.
    pub secret_azure_vault: String,
    /// Vault server endpoint (`host[:port]`). May omit the scheme;
    /// the backend defaults to `https://` when none is given.
    pub secret_vault_endpoint: String,
    /// KV v2 mount + optional per-key prefix glued together
    /// (`secret/mediator`). The backend splits the first segment off
    /// as the mount and uses the rest as the prefix.
    pub secret_vault_mount: String,
    /// `true` when the operator chose `file://?encrypt=1`. Influences
    /// the backend URL written to `mediator.toml` and whether the
    /// wizard prompts for a passphrase.
    pub secret_file_encrypted: bool,
    pub ssl_mode: String,
    pub ssl_cert_path: String,
    pub ssl_key_path: String,
    /// When VTA-managed and a hosted server was picked, the server id.
    /// `None` means self-host. Set on the Did step's SelectWebvhHost
    /// phase; read by `generate_and_write` when it calls the VTA's
    /// `create_did_webvh`.
    pub vta_webvh_server_id: Option<String>,
    /// Optional mnemonic (URL path segment) when using a hosted
    /// server. `None` = VTA auto-assigns.
    pub vta_webvh_mnemonic: Option<String>,
    /// Self-host base URL — defaults to the stripped mediator URL.
    /// Only meaningful when `vta_webvh_server_id` is `None`.
    pub vta_webvh_self_host_url: String,
    /// `generate` (default) or `provide`. See [`crate::consts::JWT_MODE_GENERATE`].
    pub jwt_mode: String,
    pub database_url: String,
    pub admin_did_mode: String,
    pub listen_address: String,
}

impl WizardConfig {
    /// Return a display string for the selected protocols.
    pub fn protocol_display(&self) -> String {
        match (self.didcomm_enabled, self.tsp_enabled) {
            (true, true) => "DIDComm v2 + TSP".into(),
            (true, false) => "DIDComm v2".into(),
            (false, true) => "TSP".into(),
            (false, false) => "None (invalid)".into(),
        }
    }
}

impl Default for WizardConfig {
    fn default() -> Self {
        Self {
            config_path: DEFAULT_CONFIG_PATH.into(),
            deployment_type: String::new(),
            use_vta: false,
            vta_mode: String::new(),
            vta_context: DEFAULT_VTA_CONTEXT.into(),
            didcomm_enabled: true,
            tsp_enabled: false,
            did_method: String::new(),
            public_url: String::new(),
            secret_storage: String::new(),
            secret_file_path: DEFAULT_SECRET_FILE_PATH.into(),
            secret_keyring_service: DEFAULT_KEYRING_SERVICE.into(),
            secret_aws_region: DEFAULT_AWS_REGION.into(),
            secret_aws_prefix: DEFAULT_AWS_SECRET_PREFIX.into(),
            secret_gcp_project: DEFAULT_GCP_PROJECT.into(),
            secret_gcp_prefix: DEFAULT_GCP_SECRET_PREFIX.into(),
            secret_azure_vault: DEFAULT_AZURE_VAULT.into(),
            secret_vault_endpoint: DEFAULT_VAULT_ENDPOINT.into(),
            secret_vault_mount: DEFAULT_VAULT_MOUNT.into(),
            secret_file_encrypted: false,
            ssl_mode: String::new(),
            ssl_cert_path: String::new(),
            ssl_key_path: String::new(),
            vta_webvh_server_id: None,
            vta_webvh_mnemonic: None,
            vta_webvh_self_host_url: String::new(),
            jwt_mode: JWT_MODE_GENERATE.into(),
            database_url: DEFAULT_REDIS_URL.into(),
            admin_did_mode: String::new(),
            listen_address: DEFAULT_LISTEN_ADDR.into(),
        }
    }
}

/// The main wizard application state.
pub struct WizardApp {
    pub current_step: WizardStep,
    pub config: WizardConfig,
    pub selection_index: usize,
    pub text_input: Input,
    pub mode: InputMode,
    pub focus: FocusPanel,
    /// Index of highlighted step in the progress panel (left panel)
    pub progress_index: usize,
    pub should_quit: bool,
    pub write_config: bool,
    completed: Vec<WizardStep>,
    /// Which field within the chosen secret backend we're currently
    /// collecting. `None` means we're still on the scheme-selection list
    /// (the default KeyStorage view). Transient — not persisted.
    pub key_storage_phase: Option<KeyStoragePhase>,
    /// Sub-phase tracker for the `Security` step. `None` means the SSL
    /// portion is still active (selection list or cert/key text inputs);
    /// `Some(JwtMode)` means the JWT-mode selection is on screen.
    pub security_phase: Option<SecurityPhase>,
    /// Sub-phase tracker for the `Did` step. Only ever populated when
    /// the operator picked `DID_VTA` and we have an online VTA
    /// session — the wizard then walks the webvh-host selection
    /// screens before advancing to Security.
    pub did_phase: Option<DidPhase>,
    /// Ephemeral state for the online-VTA connection sub-flow. Present only
    /// while the operator is stepping through the sub-phases of the Vta step.
    pub vta_connect: Option<VtaConnectState>,
    /// Optional CLI-provided VTA DID that pre-fills the first sub-flow
    /// text field. Kept on the app (not on `VtaConnectState`) so repeated
    /// enter/exit cycles within the same wizard session all see the prefill.
    pub vta_did_prefill: Option<String>,
    /// Optional CLI-provided context id override for the sub-flow.
    pub vta_context_prefill: Option<String>,
    /// Captured VTA session — set when the Connected phase advances, read
    /// by the config-writing step to provision the mediator's DID.
    pub vta_session: Option<VtaSession>,
    /// Ephemeral state for the air-gapped sealed-handoff sub-flow.
    /// Present only while the operator is on that sub-flow's screens;
    /// extracted into `vta_session` and dropped on completion.
    pub sealed_handoff: Option<SealedHandoffState>,
    /// Snapshot of on-disk artefact paths captured at the moment the
    /// sealed-handoff sub-flow transitions out of `Complete`. Used
    /// post-setup to clean up the ephemeral seed + request file
    /// after the mediator has written its config — same cleanup the
    /// non-interactive `--from` path does via
    /// [`crate::bootstrap_headless::cleanup_artifacts`]. `None`
    /// when the setup didn't go through the sealed-handoff flow.
    pub tui_bootstrap_artifacts: Option<crate::bootstrap_headless::BootstrapArtifacts>,
    /// Which of the two top-level picker questions is on screen. Reset
    /// to [`VtaStepPhase::SelectIntent`] whenever the operator enters
    /// or re-enters the Vta step.
    pub vta_step_phase: VtaStepPhase,
    /// Intent the operator picked on the first question. `None` until
    /// they pick, then `Some(FullSetup)` or `Some(AdminOnly)` while
    /// they answer the second question. Cleared when the Vta step is
    /// left (advance or go-back).
    pub vta_intent_choice: Option<VtaIntent>,
    /// Transient notice shown under the transport picker when the
    /// operator selects a (intent, transport) combination whose
    /// adapter isn't implemented yet. Cleared on the next
    /// transition.
    pub vta_stub_notice: Option<String>,
    /// Active discovery overlay — `Some` while the operator triggered F5
    /// on a cloud-backend prefix screen and either the background
    /// `list_namespace` task is in flight (`Loading`), the result is
    /// being browsed (`Loaded`), or the failure is being read (`Failed`).
    /// Cleared on Enter (apply pick) or Esc (dismiss).
    pub discovery: Option<DiscoveryState>,
    /// Receiver side of the discovery channel. Set when a discovery is
    /// kicked off; drained on each tick by [`Self::drain_discovery_events`]
    /// and dropped when the result lands or the operator dismisses.
    pub discovery_rx: Option<UnboundedReceiver<DiscoveryEvent>>,
}

impl WizardApp {
    pub fn new(config_path: String) -> Self {
        let mut config = WizardConfig::default();
        config.config_path = config_path;
        Self {
            current_step: WizardStep::Deployment,
            config,
            selection_index: 0,
            text_input: Input::default(),
            mode: InputMode::Selecting,
            focus: FocusPanel::Content,
            progress_index: 0,
            should_quit: false,
            write_config: false,
            completed: Vec::new(),
            key_storage_phase: None,
            security_phase: None,
            did_phase: None,
            vta_connect: None,
            vta_did_prefill: None,
            vta_context_prefill: None,
            vta_session: None,
            sealed_handoff: None,
            tui_bootstrap_artifacts: None,
            vta_step_phase: VtaStepPhase::SelectIntent,
            vta_intent_choice: None,
            vta_stub_notice: None,
            discovery: None,
            discovery_rx: None,
        }
    }

    /// Enter the sealed-handoff sub-flow. Mints the consumer keypair +
    /// nonce + bootstrap-request JSON immediately so the first
    /// rendered screen has something to display. Errors here mean the
    /// system RNG failed — bubble them up rather than silently using a
    /// degraded value.
    fn enter_sealed_handoff_subflow(&mut self, intent: VtaIntent) {
        // The sub-flow opens on `CollectContext` — a text-input prompt
        // for the VTA context slug. Seed the input widget with the
        // state's default so the operator can accept with Enter or
        // edit. Keypair + request JSON are produced later by
        // `SealedHandoffState::finalize_request`.
        //
        // For `FullSetup` we pre-seed the mediator URL from
        // `config.public_url` when it's already been set elsewhere in
        // the wizard — saves the operator from retyping.
        let mut state = crate::sealed_handoff::SealedHandoffState::new(
            intent,
            Some(format!("mediator/{}", self.config.config_path)),
        );
        if intent == VtaIntent::FullSetup && !self.config.public_url.is_empty() {
            state = state.with_mediator_url(self.config.public_url.clone());
        }
        self.text_input = Input::new(state.context_id.clone());
        self.mode = InputMode::TextInput;
        self.sealed_handoff = Some(state);
    }

    /// Predicate used by the renderer/key-handler to keep the sealed
    /// sub-flow's screens in scope while the operator is mid-flow.
    pub fn in_sealed_handoff_subflow(&self) -> bool {
        self.current_step == WizardStep::Vta && self.sealed_handoff.is_some()
    }

    /// Drive the sealed sub-flow forward. The phases are linear and
    /// each "select" advances by one — the actual ingest/open work
    /// happens on the text-input confirmation path.
    fn sealed_handoff_select(&mut self) {
        use crate::sealed_handoff::SealedPhase;
        let Some(state) = self.sealed_handoff.as_mut() else {
            return;
        };
        match state.phase {
            SealedPhase::CollectContext
            | SealedPhase::CollectAdminLabel
            | SealedPhase::CollectMediatorUrl
            | SealedPhase::CollectWebvhServer => {
                // These phases drive text-input; Enter goes through
                // `sealed_handoff_confirm_text`, not here. The renderer
                // only lands in `sealed_handoff_select` for these
                // phases if the mode is out of sync (e.g. the user
                // toggled focus). Safest to no-op.
            }
            SealedPhase::RequestGenerated => {
                // Enter the paste prompt for the armored bundle.
                state.phase = SealedPhase::AwaitingBundle;
                self.text_input = Input::default();
                self.mode = InputMode::TextInput;
            }
            SealedPhase::AwaitingBundle | SealedPhase::DigestVerify => {
                // While in TextInput mode the renderer routes Enter
                // through `confirm_text_input`; this branch only
                // matters if the user is somehow in Selecting mode at
                // this phase (e.g. after an error). Stay put.
            }
            SealedPhase::Complete => {
                // Project the captured session onto the wizard and
                // exit the sub-flow. From here the wizard advances to
                // Protocol like the Online VTA path.
                //
                // Before dropping the sealed_handoff state, snapshot
                // the on-disk artefact paths so main.rs can clean
                // them up after the TUI finishes and writes the
                // mediator config. Matches the non-interactive
                // path's cleanup contract — "only what the mediator
                // needs to start should be kept".
                self.tui_bootstrap_artifacts =
                    Some(crate::bootstrap_headless::BootstrapArtifacts {
                        request_path: state.request_path.take(),
                    });
                self.vta_session = state.session.take();
                self.sealed_handoff = None;
                self.mode = InputMode::Selecting;
                self.advance();
            }
        }
    }

    /// Handle Enter on a text-input prompt belonging to the sealed
    /// sub-flow. Returns `true` if the input was consumed so the
    /// outer dispatcher knows not to fall through.
    fn sealed_handoff_confirm_text(&mut self) -> bool {
        use crate::sealed_handoff::{
            SealedPhase, ingest_armored, ingest_armored_file, open_with_digest,
        };
        let Some(state) = self.sealed_handoff.as_mut() else {
            return false;
        };
        let value = self.text_input.value().to_string();
        match state.phase {
            SealedPhase::CollectContext => {
                // Accept the typed context slug (empty means "use the
                // pre-filled default"). Branch to the next collect
                // phase based on intent: AdminOnly → CollectAdminLabel,
                // FullSetup → CollectMediatorUrl.
                let trimmed = value.trim();
                if !trimmed.is_empty() {
                    state.context_id = trimmed.to_string();
                }
                match state.intent {
                    VtaIntent::AdminOnly => {
                        state.phase = SealedPhase::CollectAdminLabel;
                        self.text_input = Input::new(state.admin_label.clone());
                    }
                    VtaIntent::FullSetup => {
                        state.phase = SealedPhase::CollectMediatorUrl;
                        self.text_input = Input::new(state.mediator_url.clone());
                    }
                    VtaIntent::OfflineExport => {
                        // No further inputs — context_id alone drives
                        // `vta context reprovision`. Finalise the
                        // request right here so the operator lands on
                        // RequestGenerated in one keystroke.
                        if let Err(e) = state.finalize_request() {
                            state.last_error = Some(e.to_string());
                        } else {
                            self.text_input = Input::default();
                            self.mode = InputMode::Selecting;
                        }
                    }
                }
                true
            }
            SealedPhase::CollectMediatorUrl => {
                // Required field for FullSetup — an empty value keeps
                // the operator on this phase with `last_error` set
                // rather than silently finalising a VP the VTA will
                // reject. Advance to the optional webvh-server pick.
                let trimmed = value.trim();
                if trimmed.is_empty() {
                    state.last_error = Some(
                        "Mediator public URL is required for full-setup provisioning \
                         (fed to the VTA's didcomm-mediator template as the `URL` \
                         variable)."
                            .into(),
                    );
                    return true;
                }
                state.mediator_url = trimmed.to_string();
                state.last_error = None;
                state.phase = SealedPhase::CollectWebvhServer;
                self.text_input = Input::new(state.webvh_server.clone());
                true
            }
            SealedPhase::CollectWebvhServer => {
                // Optional — blank means "serverless, self-host at the
                // URL". Non-blank is passed to the VTA as the
                // `WEBVH_SERVER` template var; the VTA validates
                // against its server catalogue (unknown id → NotFound
                // before any minting runs).
                state.webvh_server = value.trim().to_string();
                if let Err(e) = state.finalize_request() {
                    state.last_error = Some(e.to_string());
                } else {
                    self.text_input = Input::default();
                    self.mode = InputMode::Selecting;
                }
                true
            }
            SealedPhase::CollectAdminLabel => {
                // Optional field — empty string means "skip the
                // --admin-label flag in the rendered command".
                state.admin_label = value.trim().to_string();
                if let Err(e) = state.finalize_request() {
                    state.last_error = Some(e.to_string());
                    // Stay on CollectAdminLabel so the operator can
                    // retry / back out. `finalize_request` only fails
                    // on unrecoverable RNG / serialisation errors, so
                    // in practice this branch is for dev-time
                    // sanity.
                } else {
                    self.text_input = Input::default();
                    self.mode = InputMode::Selecting;
                }
                true
            }
            SealedPhase::AwaitingBundle => {
                // Accept either a file path or an inline armored paste.
                // File-path is the reliable primary route — TUI paste
                // of multi-line armor doesn't survive `tui_input`'s
                // single-line widget on most terminals (newlines get
                // stripped before reaching `ingest_armored`, so the
                // armor decoder can't find its BEGIN/END markers).
                //
                // Detection order:
                // 1. If the input starts with `-----BEGIN ` and has
                //    newlines intact, treat as inline armor. Handles
                //    operators who pipe the contents through a
                //    terminal paste that genuinely preserved newlines.
                // 2. Otherwise trim whitespace and check whether the
                //    input names a path that exists — load the file
                //    and decode.
                // 3. If the path doesn't exist but the input is a
                //    long single-line starting with `-----BEGIN `,
                //    hint that paste likely stripped newlines.
                // 4. Fall through to raw-armor decode which will
                //    error with `"no BEGIN blocks found"` — the
                //    surfaced message lets the operator see the
                //    exact mismatch.
                let trimmed = value.trim();
                let result = if trimmed.starts_with("-----BEGIN ") && value.contains('\n') {
                    ingest_armored(state, &value)
                } else {
                    let path_candidate = trimmed;
                    let path_exists = !path_candidate.is_empty()
                        && std::path::Path::new(path_candidate).is_file();
                    if path_exists {
                        ingest_armored_file(state, path_candidate)
                    } else if trimmed.starts_with("-----BEGIN ") {
                        // Paste looked like armor but has no newlines
                        // — most common failure mode (terminal /
                        // tui_input stripped them). Give a specific
                        // hint instead of a generic armor error.
                        Err(crate::sealed_handoff::SealedHandoffError::ArmorDecode(
                            "paste appears to be armored but contains no line breaks — \
                             terminals often strip newlines on paste. Try entering the \
                             path to `bundle.armor` instead."
                                .into(),
                        ))
                    } else {
                        ingest_armored(state, &value)
                    }
                };
                if let Err(e) = result {
                    state.last_error = Some(e.to_string());
                } else {
                    self.text_input = Input::default();
                }
                true
            }
            SealedPhase::DigestVerify => {
                if let Err(e) = open_with_digest(state, value.trim()) {
                    state.last_error = Some(e.to_string());
                } else {
                    self.text_input = Input::default();
                    self.mode = InputMode::Selecting;
                }
                true
            }
            SealedPhase::RequestGenerated | SealedPhase::Complete => false,
        }
    }

    /// Esc/back from inside the sealed sub-flow. Drops the ephemeral
    /// keypair (zeroed on Drop by `Zeroizing` upstream — but we copied
    /// the secret out, so explicit `take()` clears the visible copy)
    /// and returns to the Vta scheme list.
    fn sealed_handoff_back(&mut self) {
        if let Some(mut state) = self.sealed_handoff.take() {
            state.recipient_secret.fill(0);
        }
        self.config.use_vta = false;
        self.config.vta_mode = String::new();
        self.mode = InputMode::Selecting;
        self.text_input = Input::default();
    }

    /// True while the operator is inside the online-VTA connection sub-flow.
    pub fn in_vta_subflow(&self) -> bool {
        self.current_step == WizardStep::Vta && self.vta_connect.is_some()
    }

    pub fn vta_phase(&self) -> Option<&ConnectPhase> {
        self.vta_connect.as_ref().map(|s| &s.phase)
    }

    /// Begin the online-VTA sub-flow: initialise ephemeral state and prompt
    /// for the VTA DID.
    fn enter_vta_subflow(&mut self, intent: VtaIntent) {
        let mut st = VtaConnectState::new(intent);
        if let Some(did) = self.vta_did_prefill.as_ref() {
            st.vta_did = did.clone();
        }
        if let Some(ctx) = self.vta_context_prefill.as_ref() {
            st.context_id = ctx.clone();
        }
        self.text_input = Input::new(st.vta_did.clone());
        self.mode = InputMode::TextInput;
        self.vta_connect = Some(st);
    }

    /// Exit the sub-flow, discarding ephemeral state. Used when the operator
    /// backs out of the Vta step entirely.
    fn exit_vta_subflow(&mut self) {
        self.vta_connect = None;
        self.mode = InputMode::Selecting;
        self.text_input = Input::default();
    }

    /// Handle Enter for non-text-input sub-phases.
    fn vta_subflow_select(&mut self) {
        let Some(st) = self.vta_connect.as_ref() else {
            return;
        };
        match st.phase {
            ConnectPhase::AwaitingAcl => {
                self.start_vta_test();
            }
            ConnectPhase::Testing => {
                // Only meaningful after the runner has finished with a
                // failure — let the operator retry. If the runner is still
                // in flight `event_rx` is still `Some` and we ignore Enter.
                let st = self.vta_connect.as_ref().expect("subflow");
                if st.event_rx.is_none() && st.last_error.is_some() {
                    self.start_vta_test();
                }
            }
            ConnectPhase::PickWebvhServer => {
                // Index 0 is "serverless"; indices 1..=N map to
                // `st.webvh_servers[i-1]`. Commit the pick. Serverless
                // jumps straight to the provision flight — there's no
                // server to request a URI from, so no path prompt.
                // Server picks route through `EnterWebvhPath` so the
                // operator can supply an optional path.
                let choice: Option<String> = if self.selection_index == 0 {
                    None
                } else {
                    st.webvh_servers
                        .get(self.selection_index - 1)
                        .map(|s| s.id.clone())
                };
                let rest_url = st.preflight_rest_url.clone();
                let mediator_did = match st.preflight_mediator_did.clone() {
                    Some(m) => m,
                    None => return, // defensive — shouldn't happen after PreflightDone
                };
                // Record the choice on state (read by
                // `start_vta_provision` after the path prompt resolves,
                // and by the UI if the runner later fails). Serverless
                // also wipes any stale `webvh_path` from a back-nav.
                let is_serverless = {
                    let Some(st_mut) = self.vta_connect.as_mut() else {
                        return;
                    };
                    st_mut.webvh_server_choice = choice.clone();
                    if choice.is_none() {
                        st_mut.webvh_path = None;
                        true
                    } else {
                        st_mut.phase = ConnectPhase::EnterWebvhPath;
                        false
                    }
                };
                if is_serverless {
                    self.start_vta_provision(rest_url, mediator_did);
                } else {
                    // Server-hosted — prompt for an optional path.
                    // Pre-fill with any value captured on a prior
                    // attempt (back-nav round-trip) so the operator
                    // can accept with Enter.
                    let prefill = self
                        .vta_connect
                        .as_ref()
                        .and_then(|s| s.webvh_path.clone())
                        .unwrap_or_default();
                    self.mode = InputMode::TextInput;
                    self.text_input = Input::new(prefill);
                }
            }
            ConnectPhase::Connected => {
                // Persist the authenticated session so later steps can
                // use the credential material. `conn.reply` already
                // carries the right variant — FullSetup → Full,
                // AdminOnly → AdminOnly — we just wrap the transport
                // context around it.
                if let Some(state) = self.vta_connect.as_ref()
                    && let Some(conn) = state.connection.as_ref()
                {
                    self.vta_session = Some(VtaSession {
                        context_id: state.context_id.clone(),
                        vta_did: state.vta_did.clone(),
                        rest_url: conn.rest_url.clone(),
                        mediator_did: conn.mediator_did.clone(),
                        reply: conn.reply.clone(),
                    });
                }
                self.vta_connect = None;
                self.mode = InputMode::Selecting;
                self.advance();
            }
            _ => {}
        }
    }

    /// Kick off (or re-kick) the diagnostic + auth run. Resets the checklist,
    /// creates a fresh channel, and spawns the runner.
    fn start_vta_test(&mut self) {
        let Some(st) = self.vta_connect.as_mut() else {
            return;
        };
        let Some(key) = st.setup_key.as_ref() else {
            st.last_error = Some("setup key missing — regenerate via Esc".into());
            return;
        };
        let intent = st.intent;
        let vta_did = st.vta_did.clone();
        let setup_did = key.did.clone();
        let setup_privkey_mb = key.private_key_multibase().to_string();

        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        st.diagnostics = pending_list();
        st.event_rx = Some(rx);
        st.last_error = None;
        st.clipboard_status = None;
        st.phase = ConnectPhase::Testing;
        self.selection_index = 0;

        tokio::spawn(async move {
            run_connection_test(intent, vta_did, setup_did, setup_privkey_mb, tx).await;
        });
    }

    /// Kick off the FullSetup provision flight once the preflight has
    /// delivered a webvh-server choice (auto or operator-picked) and —
    /// for the server-hosted branch — the operator has typed an
    /// optional path via [`ConnectPhase::EnterWebvhPath`]. The
    /// resolved `mediator_did` + `rest_url` captured on preflight
    /// become inputs so we don't re-resolve; the webvh server pick
    /// and path are read from state.
    fn start_vta_provision(&mut self, rest_url: Option<String>, mediator_did: String) {
        let Some(st) = self.vta_connect.as_mut() else {
            return;
        };
        let Some(key) = st.setup_key.as_ref() else {
            st.last_error = Some("setup key missing — regenerate via Esc".into());
            return;
        };
        let vta_did = st.vta_did.clone();
        let setup_did = key.did.clone();
        let setup_privkey_mb = key.private_key_multibase().to_string();
        let context = st.context_id.clone();
        let mediator_url = st.mediator_url.clone();
        let label = Some(format!("mediator setup — {context}"));
        let webvh_server_id = st.webvh_server_choice.clone();
        let webvh_path = st.webvh_path.clone();

        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        st.event_rx = Some(rx);
        st.last_error = None;
        st.clipboard_status = None;
        st.phase = ConnectPhase::Testing;
        self.selection_index = 0;
        // Callers reach here from either a selection (PickWebvhServer)
        // or a text-input confirmation (EnterWebvhPath). Force
        // `Selecting` so the renderer drops the prompt widget while
        // the runner works, and so `Connected`'s "Continue" Enter
        // routes to `select_current`, not `confirm_text_input`.
        self.mode = InputMode::Selecting;

        tokio::spawn(async move {
            crate::vta_connect::runner::run_provision_flight(
                vta_did,
                setup_did,
                setup_privkey_mb,
                mediator_did,
                rest_url,
                context,
                mediator_url,
                label,
                webvh_server_id,
                webvh_path,
                tx,
            )
            .await;
        });
    }

    /// Drain any pending events from the runner and apply them to the
    /// sub-flow state. Called from the main event loop on every tick.
    pub fn drain_vta_events(&mut self) {
        // Drain any pending runner events. Both the early-exit
        // (no sub-flow / no channel) and the normal drain path fall
        // through to the webvh auto-dispatch below, which also runs
        // after a synthesised `PreflightDone` (tests) or after the
        // channel was already closed by a previous drain tick.
        if let Some(st) = self.vta_connect.as_mut() {
            if st.event_rx.is_some() {
                // Collect events first to release the mutable borrow
                // on `event_rx` before calling `apply_event` (which
                // also borrows `st` mutably).
                let mut batch = Vec::new();
                let mut disconnected = false;
                {
                    let rx = st.event_rx.as_mut().unwrap();
                    loop {
                        match rx.try_recv() {
                            Ok(event) => batch.push(event),
                            Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                            Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                                disconnected = true;
                                break;
                            }
                        }
                    }
                }
                for event in batch {
                    st.apply_event(event);
                }
                if disconnected {
                    st.event_rx = None;
                }
            }
        } else {
            return;
        }

        // Post-drain dispatch: if we just landed on PickWebvhServer
        // with 0 or 1 servers, auto-select and kick the provision
        // flight straight away — no operator interaction needed.
        // Structured as two borrows (read → write → spawn) so the
        // `&mut self` call out to `start_vta_provision` doesn't
        // overlap the `&self` read of `vta_connect`.
        enum AutoPick {
            ServerlessOnly,
            SinglePick(String),
        }
        let auto = self.vta_connect.as_ref().and_then(|s| {
            if s.phase != ConnectPhase::PickWebvhServer || s.event_rx.is_some() {
                return None;
            }
            match s.webvh_servers.len() {
                0 => Some((
                    AutoPick::ServerlessOnly,
                    s.preflight_rest_url.clone(),
                    s.preflight_mediator_did.clone()?,
                )),
                1 => Some((
                    AutoPick::SinglePick(s.webvh_servers[0].id.clone()),
                    s.preflight_rest_url.clone(),
                    s.preflight_mediator_did.clone()?,
                )),
                _ => None,
            }
        });
        if let Some((pick, rest_url, mediator_did)) = auto {
            let choice = match pick {
                AutoPick::ServerlessOnly => None,
                AutoPick::SinglePick(id) => Some(id),
            };
            let is_serverless = {
                let Some(st) = self.vta_connect.as_mut() else {
                    return;
                };
                st.webvh_server_choice = choice.clone();
                if choice.is_none() {
                    st.webvh_path = None;
                    true
                } else {
                    // Auto-picked a server — still prompt for the
                    // optional path so the operator can supply one.
                    st.phase = ConnectPhase::EnterWebvhPath;
                    false
                }
            };
            if is_serverless {
                self.start_vta_provision(rest_url, mediator_did);
            } else {
                let prefill = self
                    .vta_connect
                    .as_ref()
                    .and_then(|s| s.webvh_path.clone())
                    .unwrap_or_default();
                self.mode = InputMode::TextInput;
                self.text_input = Input::new(prefill);
            }
        }
    }

    /// Advance the sub-flow from a text-input phase into the next phase.
    fn vta_subflow_confirm_text(&mut self) -> anyhow::Result<()> {
        let Some(st) = self.vta_connect.as_mut() else {
            return Ok(());
        };
        let mut webvh_path_dispatch = false;
        match st.phase {
            ConnectPhase::EnterDid => {
                let val = self.text_input.value().trim().to_string();
                if val.is_empty() {
                    return Ok(());
                }
                st.vta_did = val;
                st.phase = ConnectPhase::EnterContext;
                let ctx = st.context_id.clone();
                self.text_input = Input::new(ctx);
                // Stay in TextInput mode for the next field.
            }
            ConnectPhase::EnterContext => {
                let val = self.text_input.value().trim().to_string();
                if !val.is_empty() {
                    st.context_id = val;
                }
                // FullSetup needs the mediator's public URL (goes into
                // the template's `URL` var); AdminOnly doesn't — skip
                // straight to the ACL instructions screen.
                match st.intent {
                    VtaIntent::FullSetup => {
                        let prefill = if st.mediator_url.is_empty() {
                            self.config.public_url.clone()
                        } else {
                            st.mediator_url.clone()
                        };
                        st.phase = ConnectPhase::EnterMediatorUrl;
                        self.text_input = Input::new(prefill);
                        // Stay in TextInput mode.
                    }
                    VtaIntent::AdminOnly => {
                        st.setup_key = Some(EphemeralSetupKey::generate()?);
                        st.phase = ConnectPhase::AwaitingAcl;
                        self.mode = InputMode::Selecting;
                        self.selection_index = 0;
                        self.text_input = Input::default();
                    }
                    VtaIntent::OfflineExport => {
                        // Online sub-flow is never entered for
                        // OfflineExport — `enter_vta_subflow` rejects
                        // this intent and the transport selector
                        // routes straight to `enter_sealed_handoff_subflow`.
                        // Pattern is exhaustive because the enum
                        // demands it; reaching here would be a wiring
                        // bug.
                        unreachable!("OfflineExport never enters the online VTA sub-flow");
                    }
                }
            }
            ConnectPhase::EnterMediatorUrl => {
                let val = self.text_input.value().trim().to_string();
                if val.is_empty() {
                    // Block advance until the operator provides a URL —
                    // the VTA template requires it.
                    return Ok(());
                }
                st.mediator_url = val.clone();
                // Mirror onto WizardConfig so the Did step doesn't
                // prompt again and later generators have the value.
                self.config.public_url = val;
                st.setup_key = Some(EphemeralSetupKey::generate()?);
                st.phase = ConnectPhase::AwaitingAcl;
                self.mode = InputMode::Selecting;
                self.selection_index = 0;
                self.text_input = Input::default();
            }
            ConnectPhase::EnterWebvhPath => {
                // Blank is a valid answer — server auto-assigns the
                // path. Non-blank is forwarded to the VTA as
                // `WEBVH_PATH`. The provision flight itself is
                // dispatched after this match closes so the
                // `&mut VtaConnectState` borrow on `st` is released.
                let val = self.text_input.value().trim().to_string();
                st.webvh_path = if val.is_empty() { None } else { Some(val) };
                self.text_input = Input::default();
                webvh_path_dispatch = true;
            }
            _ => {}
        }
        if webvh_path_dispatch {
            let (rest_url, mediator_did) = {
                let Some(st) = self.vta_connect.as_ref() else {
                    return Ok(());
                };
                match st.preflight_mediator_did.clone() {
                    Some(m) => (st.preflight_rest_url.clone(), m),
                    // Defensive — shouldn't happen past PickWebvhServer.
                    None => return Ok(()),
                }
            };
            self.start_vta_provision(rest_url, mediator_did);
        }
        Ok(())
    }

    /// Handle Esc within the sub-flow — step back one phase, or exit to the
    /// outer Vta selection list.
    fn vta_subflow_back(&mut self) {
        let Some(st) = self.vta_connect.as_mut() else {
            return;
        };
        match st.phase {
            ConnectPhase::EnterDid => {
                self.exit_vta_subflow();
            }
            ConnectPhase::EnterContext => {
                st.phase = ConnectPhase::EnterDid;
                let did = st.vta_did.clone();
                self.text_input = Input::new(did);
                self.mode = InputMode::TextInput;
            }
            ConnectPhase::EnterMediatorUrl => {
                st.phase = ConnectPhase::EnterContext;
                let ctx = st.context_id.clone();
                self.text_input = Input::new(ctx);
                self.mode = InputMode::TextInput;
            }
            ConnectPhase::AwaitingAcl => {
                // Step back to the most recent text-input phase —
                // EnterMediatorUrl for FullSetup (which collected
                // that), EnterContext for AdminOnly (which skipped
                // the URL prompt entirely).
                st.setup_key = None;
                match st.intent {
                    VtaIntent::FullSetup => {
                        st.phase = ConnectPhase::EnterMediatorUrl;
                        let url = st.mediator_url.clone();
                        self.text_input = Input::new(url);
                    }
                    VtaIntent::AdminOnly => {
                        st.phase = ConnectPhase::EnterContext;
                        let ctx = st.context_id.clone();
                        self.text_input = Input::new(ctx);
                    }
                    VtaIntent::OfflineExport => {
                        // Online sub-flow is never entered for
                        // OfflineExport. See note in
                        // `vta_subflow_confirm_text` above.
                        unreachable!("OfflineExport never enters the online VTA sub-flow");
                    }
                }
                self.mode = InputMode::TextInput;
            }
            ConnectPhase::PickWebvhServer => {
                // Stepping back from the webvh picker rewinds to
                // `AwaitingAcl` so the operator can re-run
                // `pnm acl create` or re-kick the preflight. The
                // captured server catalogue is cleared so we don't
                // render a stale list on the next attempt.
                st.phase = ConnectPhase::AwaitingAcl;
                st.webvh_servers.clear();
                st.webvh_server_choice = None;
                st.webvh_path = None;
                st.preflight_mediator_did = None;
                st.preflight_rest_url = None;
                self.mode = InputMode::Selecting;
                self.selection_index = 0;
            }
            ConnectPhase::EnterWebvhPath => {
                // Back to the server picker — the operator may want a
                // different server or to drop to serverless. The
                // typed path is kept on state so it re-pre-fills if
                // they land here again.
                st.phase = ConnectPhase::PickWebvhServer;
                self.mode = InputMode::Selecting;
                // Seed the picker highlight on the previously-chosen
                // server (offset by 1 for the "serverless" row at 0).
                self.selection_index = st
                    .webvh_server_choice
                    .as_ref()
                    .and_then(|id| {
                        st.webvh_servers
                            .iter()
                            .position(|s| &s.id == id)
                            .map(|idx| idx + 1)
                    })
                    .unwrap_or(0);
            }
            ConnectPhase::Testing | ConnectPhase::Connected => {
                // Abort the runner (receiver drop closes the channel on its
                // side) and return to the instructions screen so the
                // operator can re-check the ACL and try again.
                st.event_rx = None;
                st.diagnostics.clear();
                st.last_error = None;
                st.connection = None;
                st.phase = ConnectPhase::AwaitingAcl;
                self.mode = InputMode::Selecting;
                self.selection_index = 0;
            }
            #[allow(unreachable_patterns)]
            _ => {
                // No other transient phases currently exist; guard for
                // future additions.
                st.phase = ConnectPhase::AwaitingAcl;
                self.mode = InputMode::Selecting;
                self.selection_index = 0;
            }
        }
    }

    /// Switch focus to the progress panel (left)
    pub fn focus_progress(&mut self) {
        if self.mode == InputMode::TextInput {
            return; // Don't switch away from text input
        }
        self.focus = FocusPanel::Progress;
        self.progress_index = self.current_step.index();
    }

    /// Switch focus to the content panel (right)
    pub fn focus_content(&mut self) {
        self.focus = FocusPanel::Content;
    }

    /// Move progress highlight up
    pub fn progress_up(&mut self) {
        if self.progress_index > 0 {
            self.progress_index -= 1;
        }
    }

    /// Move progress highlight down
    pub fn progress_down(&mut self) {
        let max = WizardStep::all().len().saturating_sub(1);
        if self.progress_index < max {
            self.progress_index += 1;
        }
    }

    /// Jump to the step highlighted in the progress panel.
    /// All state is preserved — we just change the current step.
    pub fn jump_to_progress_step(&mut self) {
        let steps = WizardStep::all();
        if let Some(&step) = steps.get(self.progress_index) {
            // Can only jump to completed steps or the current step
            if self.completed.contains(&step) || step == self.current_step {
                self.current_step = step;
                self.on_enter_step();
                self.selection_index = self.default_selection_index();
                // Set mode based on step type
                if step == WizardStep::Database {
                    self.mode = InputMode::TextInput;
                    self.text_input = Input::new(self.config.database_url.clone());
                } else {
                    self.mode = InputMode::Selecting;
                }
                self.focus = FocusPanel::Content;
            }
        }
    }

    pub fn completed_steps(&self) -> Vec<WizardStep> {
        self.completed.clone()
    }

    /// Step title/description to display in the right-panel header.
    /// Overrides the static `WizardStep::step_data` when the wizard is inside
    /// a sub-flow that has its own narrative (e.g. online-VTA).
    pub fn current_step_data(&self) -> StepData {
        let default = self.current_step.step_data();
        if let Some(phase) = self.vta_phase() {
            let num = self.current_step.step_number();
            let total = WizardStep::total();
            let (suffix, desc): (&str, &str) = match phase {
                ConnectPhase::EnterDid => (
                    "Enter VTA DID",
                    "Type the VTA's DID; the wizard resolves its endpoints.",
                ),
                ConnectPhase::EnterContext => (
                    "Enter context id",
                    "VTA context name the mediator will live in (default: mediator).",
                ),
                ConnectPhase::EnterMediatorUrl => (
                    "Enter mediator URL",
                    "Public URL this mediator will serve at — passed to the VTA's DID template.",
                ),
                ConnectPhase::AwaitingAcl => (
                    "Register ACL",
                    "Run the displayed command on the VTA host, then press Enter to provision.",
                ),
                ConnectPhase::Testing => (
                    "Provisioning",
                    "Authenticating over DIDComm and requesting a VTA-minted mediator DID…",
                ),
                ConnectPhase::PickWebvhServer => (
                    "Pick webvh server",
                    "The VTA has more than one registered webvh hosting server — pick one \
                     to host the minted DID's did.jsonl log, or self-host at the URL above.",
                ),
                ConnectPhase::EnterWebvhPath => (
                    "Enter webvh path",
                    "Optional path/mnemonic for the minted DID on the chosen webvh server. \
                     Press Enter with the field blank to let the server auto-assign.",
                ),
                ConnectPhase::Connected => (
                    "Connected",
                    "Mediator DID minted by the VTA — advancing to the next step.",
                ),
            };
            return StepData {
                title: format!("Step {num}/{total}: VTA Integration — {suffix}"),
                description: desc.into(),
            };
        }
        // Top-level Vta picker — reflect which of the two questions the
        // operator is currently answering so the header stays useful
        // alongside the option list.
        if self.current_step == WizardStep::Vta
            && self.vta_connect.is_none()
            && self.sealed_handoff.is_none()
        {
            let num = self.current_step.step_number();
            let total = WizardStep::total();
            let (suffix, desc): (&str, &str) = match self.vta_step_phase {
                VtaStepPhase::SelectIntent => (
                    "What from VTA?",
                    "Decide whether the VTA should mint your mediator's DID (Full setup), \
                     only provide an admin credential, or stay out of the wizard entirely.",
                ),
                VtaStepPhase::SelectTransport => (
                    "How is the request delivered?",
                    "Pick online for a direct network call or sealed handoff for an \
                     air-gapped armored-bundle exchange.",
                ),
            };
            return StepData {
                title: format!("Step {num}/{total}: VTA Integration — {suffix}"),
                description: desc.into(),
            };
        }
        default
    }

    /// Get the options for the current step.
    pub fn current_options(&self) -> Vec<SelectionOption> {
        match self.current_step {
            WizardStep::Deployment => vec![
                SelectionOption::new(
                    "Local development",
                    "Desktop, quick start — ideal for testing",
                ),
                SelectionOption::new(
                    "Headless server",
                    "Production deployment on cloud or bare metal",
                ),
                SelectionOption::new("Container", "Docker image for container orchestration"),
            ],
            WizardStep::Vta => {
                if let Some(phase) = self.vta_phase() {
                    let st = self.vta_connect.as_ref().expect("phase implies state");
                    return match phase {
                        ConnectPhase::AwaitingAcl => vec![SelectionOption::new(
                            "Test VTA connection",
                            "Run the `pnm acl create` command below, then press Enter to verify",
                        )],
                        ConnectPhase::Testing => {
                            if st.event_rx.is_some() {
                                // Runner still in flight — no actionable
                                // option yet; the UI renders a spinner.
                                vec![]
                            } else if st.last_error.is_some() {
                                vec![SelectionOption::new(
                                    "Retry",
                                    "Re-run the diagnostic + auth sequence",
                                )]
                            } else {
                                vec![]
                            }
                        }
                        ConnectPhase::Connected => vec![SelectionOption::new(
                            "Continue",
                            "Advance to the next wizard step",
                        )],
                        ConnectPhase::PickWebvhServer => {
                            // First option is always "serverless" (self-host at URL); the
                            // remaining entries mirror `st.webvh_servers` so the
                            // selection index maps to `idx - 1`.
                            let mut opts = Vec::with_capacity(st.webvh_servers.len() + 1);
                            opts.push(SelectionOption::new(
                                "Serverless — self-host at mediator URL",
                                "Don't pin a webvh hosting server; the minted DID resolves \
                                 directly at the mediator's public URL.",
                            ));
                            for srv in &st.webvh_servers {
                                let label = srv.label.as_deref().unwrap_or("(no label)");
                                opts.push(SelectionOption::new(
                                    format!("{} — {}", srv.id, label),
                                    srv.did.clone(),
                                ));
                            }
                            opts
                        }
                        _ => vec![],
                    };
                }
                match self.vta_step_phase {
                    VtaStepPhase::SelectIntent => vec![
                        SelectionOption::new(
                            "Full setup — VTA mints my mediator DID",
                            "VTA renders a DID template, mints integration + admin keys, issues an authorisation VC. The wizard will skip the DID step when this path is chosen.",
                        ),
                        SelectionOption::new(
                            "Admin credential only — I'll bring my own DID",
                            "Mediator keeps the DID from the DID step; the VTA only supplies an admin credential used for VTA admin APIs.",
                        ),
                        SelectionOption::new(
                            "Pick up pre-provisioned mediator (offline export)",
                            "VTA already provisioned the context + mediator DID + keys (e.g. during VTA bootstrap). Wizard writes a request; VTA admin runs `vta context reprovision --id <ctx> --recipient <file>` and returns the existing material in a ContextProvision bundle. Always offline.",
                        ),
                        SelectionOption::new(
                            "No VTA",
                            "Manage keys and DIDs independently (local dev, cloud secret stores).",
                        ),
                    ],
                    VtaStepPhase::SelectTransport => {
                        let intent = self
                            .vta_intent_choice
                            .expect("transport phase implies an intent was picked");
                        let (online_sub, offline_sub) = match intent {
                            VtaIntent::FullSetup => (
                                "Direct DIDComm session to a running VTA. Requires: `pnm acl create` run out-of-band first to enrol the wizard's ephemeral setup DID in the target context.",
                                "No live network from this host. Wizard writes a VP-framed request; VTA admin runs `vta bootstrap provision-integration` on the VTA host and returns an armored bundle.",
                            ),
                            VtaIntent::AdminOnly => (
                                "Direct REST/DIDComm check against the VTA. Requires: `pnm acl create` run out-of-band first to enrol the mediator's own DID as admin of the target context.",
                                "No live network from this host. Wizard writes a request; VTA admin runs `pnm contexts bootstrap --recipient <file>` on their CLI and returns an armored bundle carrying the admin credential.",
                            ),
                            VtaIntent::OfflineExport => {
                                // Defensive: SelectIntent routes
                                // OfflineExport directly to sealed
                                // handoff without ever entering this
                                // phase. If it somehow lands here we
                                // render a single-row stub explaining
                                // the situation rather than panicking
                                // in the renderer (which would tear
                                // the TUI down mid-frame).
                                return vec![SelectionOption::new(
                                    "(no transport choice for OfflineExport)",
                                    "OfflineExport is always offline — sealed handoff via `vta context reprovision` is the only producer.",
                                )];
                            }
                        };
                        vec![
                            SelectionOption::new("Online", online_sub),
                            SelectionOption::new("Sealed handoff (air-gapped)", offline_sub),
                        ]
                    }
                }
            }
            WizardStep::Protocol => {
                let didcomm_check = if self.config.didcomm_enabled {
                    "[x]"
                } else {
                    "[ ]"
                };
                let tsp_check = if self.config.tsp_enabled {
                    "[x]"
                } else {
                    "[ ]"
                };
                vec![
                    SelectionOption::new(
                        format!("{didcomm_check} DIDComm v2 (recommended)"),
                        "Industry-standard DID-based messaging",
                    ),
                    SelectionOption::new(
                        format!("{tsp_check} TSP (Trust Spanning Protocol) [experimental]"),
                        "Lightweight trust protocol — experimental support",
                    ),
                ]
            }
            WizardStep::Did => {
                // When the webvh-host sub-flow is active, render its
                // options (self-host / each server / self-host
                // elsewhere) instead of the DID-method picker.
                if self.did_phase == Some(DidPhase::SelectWebvhHost) {
                    let mut opts = Vec::new();
                    let stripped = if self.config.vta_webvh_self_host_url.is_empty() {
                        Self::strip_url_path(&self.config.public_url)
                    } else {
                        self.config.vta_webvh_self_host_url.clone()
                    };
                    opts.push(SelectionOption::new(
                        format!("Self-host at {stripped}"),
                        "Derived from the mediator URL (path stripped — webvh publishes at /.well-known/did.jsonl).",
                    ));
                    // Note: VTA-hosted webvh servers used to appear here
                    // as individual picks, populated from the VTA's
                    // `list_webvh_servers` RPC. With provision-integration
                    // the mediator DID is rendered by a VTA-side template
                    // that decides publishing itself — so the operator
                    // chooses templates (via context overrides on the
                    // VTA), not servers here. Legacy self-host options
                    // remain for non-VTA flows.
                    let _ = self.vta_session.as_ref();
                    opts.push(SelectionOption::new(
                        "Self-host elsewhere",
                        "Type a different base URL (e.g. a webvh server you operate separately).",
                    ));
                    return opts;
                }
                let mut opts = vec![];
                // "Configure via VTA" is only meaningful when the
                // operator picked `FullSetup` on the Vta step — that's
                // the intent that has the VTA mint the integration
                // DID. `AdminOnly` keeps the operator's own DID and
                // hides this option; `No VTA` never shows it.
                if self.config.use_vta && self.shows_vta_did_option() {
                    opts.push(SelectionOption::new(
                        "Configure via VTA (recommended)",
                        "Centralized key management — VTA creates and hosts your DID",
                    ));
                }
                opts.push(SelectionOption::new(
                    "Generate did:webvh",
                    "Production — generates random keys you must manage yourself",
                ));
                opts.push(SelectionOption::new(
                    "Generate did:peer",
                    "Quick start — generates random keys, no hosting required",
                ));
                opts.push(SelectionOption::new(
                    "Import existing DID",
                    "Paste an existing DID string and secrets",
                ));
                opts
            }
            WizardStep::KeyStorage => {
                // The file:// encrypt/no-encrypt choice rides on top
                // of the same selection-list UI as the scheme picker.
                // Branch *before* we render the scheme list so the
                // operator sees the right question.
                if self.key_storage_phase == Some(KeyStoragePhase::FileEncryptChoice) {
                    return vec![
                        SelectionOption::new(
                            "Encrypt with a passphrase (recommended)",
                            "Argon2id-derived AES-256-GCM. The wizard prompts for a passphrase you must also provide to the mediator at boot.",
                        ),
                        SelectionOption::new(
                            "No encryption (plaintext on disk)",
                            "Same secrets.json shape as before. Anyone with read access to the file gets the keys.",
                        ),
                    ];
                }
                // Unified secret-storage backends. `vta://` is no longer a
                // backend (the VTA is a *source* of keys, not a store) and
                // `string://` has been removed (inline secrets in TOML are
                // unsafe even for CI — use `file://` with env-var overrides
                // instead).
                vec![
                    SelectionOption::new(
                        "OS Keyring (keyring://) [recommended for desktop]",
                        "macOS Keychain, Linux Secret Service, Windows Credential Manager",
                    ),
                    SelectionOption::new(
                        "AWS Secrets Manager (aws_secrets://)",
                        "AWS cloud production",
                    ),
                    SelectionOption::new(
                        "Google Cloud Secret Manager (gcp_secrets://)",
                        "GCP cloud production",
                    ),
                    SelectionOption::new(
                        "Azure Key Vault (azure_keyvault://)",
                        "Azure cloud production",
                    ),
                    SelectionOption::new(
                        "HashiCorp Vault (vault://)",
                        "Enterprise / multi-cloud (KV v2 only)",
                    ),
                    SelectionOption::new(
                        "Local file (file://)",
                        "Stored in secrets.json — DEV ONLY, requires explicit confirmation",
                    ),
                ]
            }
            WizardStep::Security => {
                if self.security_phase == Some(SecurityPhase::JwtMode) {
                    vec![
                        SelectionOption::new(
                            "Generate a fresh JWT signing key (recommended)",
                            "Wizard creates an Ed25519 PKCS8 key and stores it under the well-known secret name.",
                        ),
                        SelectionOption::new(
                            "Provide my own JWT secret",
                            "Mediator reads MEDIATOR_JWT_SECRET / --jwt-secret-file at boot. Wizard does not prompt for the key.",
                        ),
                    ]
                } else {
                    vec![
                        SelectionOption::new(
                            "No SSL (use TLS-terminating proxy)",
                            "Recommended: nginx, Caddy, AWS ALB handle TLS",
                        ),
                        SelectionOption::new(
                            "Provide existing certificates",
                            "Use your own SSL certificate and key files",
                        ),
                        SelectionOption::new(
                            "Generate self-signed certificates",
                            "Local development only — not for production",
                        ),
                    ]
                }
            }
            WizardStep::Database => {
                // Database uses text input, but we return empty for the selection fallback
                vec![]
            }
            WizardStep::Admin => {
                let mut opts = vec![
                    SelectionOption::new(
                        "Generate a new admin did:key",
                        "Creates a new Ed25519 key pair",
                    ),
                    SelectionOption::new("Paste an existing admin DID", "Use any DID method"),
                ];
                if self.admin_options_include_vta() {
                    opts.push(SelectionOption::new(
                        "Generate admin DID from VTA",
                        "Retrieve from VTA context",
                    ));
                }
                opts.push(SelectionOption::new(
                    "Skip for now",
                    "Configure admin later",
                ));
                opts
            }
            // Output step is text-input (the renderer branches on
            // `current_step == Output` and draws a compact prompt),
            // so no selection list is needed here.
            WizardStep::Output => vec![],
            WizardStep::Summary => vec![],
        }
    }

    /// Get the info text for the currently highlighted option.
    pub fn current_info_text(&self) -> String {
        match self.current_step {
            WizardStep::Deployment => match self.selection_index {
                0 => "Sets sensible defaults for local development: did:peer, inline secrets, no SSL, localhost Redis.".into(),
                1 => "Sets defaults for production: did:webvh, external secret storage, TLS proxy, local or remote Redis.".into(),
                2 => "Same as server, plus generates a Dockerfile and docker-compose.yml with correct feature flags.".into(),
                _ => String::new(),
            },
            WizardStep::Vta => {
                if let Some(phase) = self.vta_phase() {
                    return match phase {
                        ConnectPhase::EnterDid => {
                            "Enter the VTA's DID (e.g. did:webvh:vta.example.com). The wizard resolves the DID document to discover its DIDComm service endpoint — you do not need to supply URLs separately.".into()
                        }
                        ConnectPhase::EnterContext => {
                            "The VTA context this mediator will live in. Defaults to 'mediator'; override if you use a different naming convention or run multiple mediators against the same VTA.".into()
                        }
                        ConnectPhase::EnterMediatorUrl => {
                            "Public URL this mediator will serve at (e.g. https://mediator.example.com). Passed to the VTA's DID template as the `URL` variable so the rendered mediator DID advertises the right service endpoints.".into()
                        }
                        ConnectPhase::AwaitingAcl => {
                            "The wizard has generated an ephemeral did:key to authenticate to the VTA. Run the displayed `pnm acl create` command on your VTA admin host, then press Enter to provision the mediator's DID and admin credential in one round-trip.".into()
                        }
                        ConnectPhase::Testing => {
                            "Opening a DIDComm session to the VTA, sending the signed provisioning request, and opening the sealed bundle the VTA returns…".into()
                        }
                        ConnectPhase::PickWebvhServer => {
                            let st = self.vta_connect.as_ref().expect("phase implies state");
                            match self.selection_index {
                                0 => "Self-host the minted DID at the mediator URL (no webvh hosting server). Pick this if the mediator owns the public endpoint for its did.jsonl log.".into(),
                                i => {
                                    // Servers are offset by one (index 0 = serverless).
                                    let idx = i - 1;
                                    match st.webvh_servers.get(idx) {
                                        Some(srv) => {
                                            let label = srv.label.as_deref().unwrap_or("(no label)");
                                            format!("Host the minted DID's did.jsonl on '{}' ({label}). Sent to the VTA as WEBVH_SERVER = {}.", srv.id, srv.id)
                                        }
                                        None => String::new(),
                                    }
                                }
                            }
                        }
                        ConnectPhase::EnterWebvhPath => {
                            "Optional path or mnemonic the webvh server should publish the minted DID under (forwarded to the VTA as the `WEBVH_PATH` template variable, then on to the server's `request_uri` call). Leave blank to let the server auto-assign.".into()
                        }
                        ConnectPhase::Connected => {
                            "VTA-minted mediator DID received. Advancing to the next step.".into()
                        }
                    };
                }
                // A stub notice — surfaced when the operator picked an
                // (intent, transport) leaf that's not yet wired — takes
                // precedence over the per-option hint so the operator
                // sees why nothing moved.
                if let Some(ref notice) = self.vta_stub_notice {
                    return notice.clone();
                }
                match (self.vta_step_phase, self.selection_index) {
                    (VtaStepPhase::SelectIntent, 0) => "The mediator's integration DID, admin DID, and VTA trust bundle are all issued by the VTA via a template render. The wizard skips the DID step when this path is chosen.".into(),
                    (VtaStepPhase::SelectIntent, 1) => "The mediator keeps the DID you configure in the next step. The VTA only supplies an admin credential used to authenticate against VTA admin APIs.".into(),
                    (VtaStepPhase::SelectIntent, 2) => "Keys and DIDs are generated locally or stored in cloud secret managers. You are responsible for backup and rotation.".into(),
                    (VtaStepPhase::SelectTransport, 0) => "Direct network interaction with a running VTA. Lower friction but requires network reachability and an out-of-band `pnm acl create` step to pre-authorise the wizard against the VTA's ACL.".into(),
                    (VtaStepPhase::SelectTransport, 1) => "Armored sealed-bundle exchange — no network from this host. Suitable for air-gapped or offline deployments, or when the VTA isn't directly reachable.".into(),
                    _ => String::new(),
                }
            }
            WizardStep::Protocol => match self.selection_index {
                0 => "DIDComm v2 is the industry standard for DID-based secure messaging. Recommended for most deployments. Space toggles; Enter continues.".into(),
                1 => "TSP is a lightweight alternative to DIDComm. EXPERIMENTAL: not all mediator features are supported yet. Can be enabled alongside DIDComm. Space toggles; Enter continues.".into(),
                _ => String::new(),
            },
            WizardStep::Did => {
                if self.did_phase == Some(DidPhase::SelectWebvhHost) {
                    return "Pick where the VTA should publish this DID's did.jsonl log. \
                            Self-host = the mediator (or another server you operate) serves \
                            the document at `/.well-known/did.jsonl`. VTA-hosted = the VTA \
                            manages publication for you on a registered webvh server."
                        .into();
                }
                if self.config.use_vta {
                    match self.selection_index {
                        0 => "VTA creates and manages the mediator's DID and keys centrally. Uses the built-in `didcomm-mediator` template. To customise: `pnm did-templates init didcomm-mediator > custom.json`, edit, then upload under the same name — context/global scope shadows the built-in automatically.".into(),
                        1 => "did:webvh requires a webvh server to host the DID document. Uses the same `didcomm-mediator` template shape as the VTA-managed path, rendered locally — you back up and manage the keys yourself.".into(),
                        2 => "did:peer is self-contained — no hosting required. Generates random keys that you must back up and manage yourself. Best for local dev and testing.".into(),
                        3 => "Import a DID you've already created. You'll need to provide the DID string and private key secrets.".into(),
                        _ => String::new(),
                    }
                } else {
                    match self.selection_index {
                        0 => "did:webvh requires a webvh server to host the DID document. Uses the `didcomm-mediator` template shape, rendered locally — you back up and manage the keys yourself.".into(),
                        1 => "did:peer is self-contained — no hosting required. Generates random keys that you must back up and manage yourself. Best for local dev and testing.".into(),
                        2 => "Import a DID you've already created. You'll need to provide the DID string and private key secrets.".into(),
                        _ => String::new(),
                    }
                }
            }
            WizardStep::KeyStorage => match self.selection_index {
                0 => "Uses the OS keyring (macOS Keychain, Linux Secret Service, Windows Credential Manager). Good for desktop development and single-host servers.".into(),
                1 => "Store secrets in AWS Secrets Manager. Requires AWS credentials configured. Suitable for AWS production.".into(),
                2 => "Store secrets in Google Cloud Secret Manager. Auth via Application Default Credentials (GOOGLE_APPLICATION_CREDENTIALS / `gcloud auth application-default login` / GKE workload identity).".into(),
                3 => "Store secrets in Azure Key Vault. Auth via Azure CLI / azd developer credentials (`az login`). Sovereign clouds supported via full DNS in the vault field.".into(),
                4 => "Store secrets in HashiCorp Vault (KV v2). Token auth via VAULT_TOKEN env var. The mount point must already exist on the server.".into(),
                5 => "Secrets written to conf/secrets.json as plaintext. DEV ONLY — anyone with file access can read the private keys. The wizard will require an explicit confirmation before accepting this choice.".into(),
                _ => String::new(),
            },
            WizardStep::Security => {
                if self.security_phase == Some(SecurityPhase::JwtMode) {
                    match self.selection_index {
                        0 => "The wizard generates a 32-byte Ed25519 PKCS8 keypair and writes it into the unified secret backend at the well-known key `mediator/jwt/secret`. The mediator picks it up at startup with no further config.".into(),
                        1 => "The wizard records your choice but does NOT generate or prompt for a key. Before starting the mediator, set MEDIATOR_JWT_SECRET (raw PKCS8 bytes, base64-encoded) or pass --jwt-secret-file <path>. Choose this when CI/CD already issues JWT keys or when an HSM holds them.".into(),
                        _ => String::new(),
                    }
                } else {
                    match self.selection_index {
                        0 => "Run the mediator behind a reverse proxy (nginx, Caddy, AWS ALB) that terminates TLS. The mediator runs plain HTTP. This is the recommended approach.".into(),
                        1 => "Provide paths to existing SSL certificate and key files.".into(),
                        2 => "Generate self-signed certificates for local development. Browsers will show security warnings.".into(),
                        _ => String::new(),
                    }
                }
            }
            WizardStep::Database => {
                "Redis is used for message queues, session storage, and forwarding. Use database partitions (e.g. redis://127.0.0.1/1) to isolate data when sharing a Redis instance.".into()
            }
            WizardStep::Admin => {
                if self.config.use_vta {
                    match self.selection_index {
                        0 => "Generates a new Ed25519 did:key. The private key will be displayed — save it securely!".into(),
                        1 => "Paste any DID (did:key, did:peer, did:webvh, etc.) to use as admin.".into(),
                        2 => "Copy the admin DID from your VTA context.".into(),
                        3 => "You can configure the admin DID later by editing mediator.toml or via the admin API.".into(),
                        _ => String::new(),
                    }
                } else {
                    match self.selection_index {
                        0 => "Generates a new Ed25519 did:key. The private key will be displayed — save it securely!".into(),
                        1 => "Paste any DID (did:key, did:peer, did:webvh, etc.) to use as admin.".into(),
                        2 => "You can configure the admin DID later by editing mediator.toml or via the admin API.".into(),
                        _ => String::new(),
                    }
                }
            }
            WizardStep::Output => {
                "Defaults to `conf/mediator.toml` (relative to the mediator's working \
                 directory). Sibling files — `secrets.json` when file:// is the chosen \
                 backend, `atm-functions.lua`, `did.jsonl` — land in the same folder."
                    .into()
            }
            WizardStep::Summary => String::new(),
        }
    }

    /// Handle Enter key — select current option and advance.
    pub fn select_current(&mut self) {
        match self.current_step {
            WizardStep::Deployment => {
                self.config.deployment_type = match self.selection_index {
                    0 => DEPLOYMENT_LOCAL.into(),
                    1 => DEPLOYMENT_SERVER.into(),
                    2 => DEPLOYMENT_CONTAINER.into(),
                    _ => return,
                };
                self.apply_deployment_defaults();
                self.advance();
            }
            WizardStep::Vta => {
                if self.in_vta_subflow() {
                    self.vta_subflow_select();
                    return;
                }
                if self.in_sealed_handoff_subflow() {
                    self.sealed_handoff_select();
                    return;
                }
                match self.vta_step_phase {
                    VtaStepPhase::SelectIntent => match self.selection_index {
                        0 => {
                            self.vta_intent_choice = Some(VtaIntent::FullSetup);
                            self.vta_step_phase = VtaStepPhase::SelectTransport;
                            self.vta_stub_notice = None;
                            self.selection_index = 0;
                        }
                        1 => {
                            self.vta_intent_choice = Some(VtaIntent::AdminOnly);
                            self.vta_step_phase = VtaStepPhase::SelectTransport;
                            self.vta_stub_notice = None;
                            self.selection_index = 0;
                        }
                        2 => {
                            // OfflineExport — pick up state the VTA
                            // already provisioned. Always offline (the
                            // v1 sealed_transfer::BootstrapRequest has
                            // no online transport equivalent), so we
                            // skip the SelectTransport phase entirely
                            // and route straight into sealed_handoff.
                            self.vta_intent_choice = Some(VtaIntent::OfflineExport);
                            self.vta_stub_notice = None;
                            self.config.use_vta = true;
                            self.config.vta_mode = VTA_MODE_EXPORT.into();
                            self.apply_vta_defaults();
                            self.enter_sealed_handoff_subflow(VtaIntent::OfflineExport);
                        }
                        3 => {
                            self.vta_intent_choice = None;
                            self.config.use_vta = false;
                            self.config.vta_mode = String::new();
                            self.apply_vta_defaults();
                            self.advance();
                        }
                        _ => {}
                    },
                    VtaStepPhase::SelectTransport => {
                        let intent = self
                            .vta_intent_choice
                            .expect("transport phase implies an intent was picked");
                        let transport = match self.selection_index {
                            0 => VtaTransport::Online,
                            1 => VtaTransport::Offline,
                            _ => return,
                        };
                        self.vta_stub_notice = None;
                        match (intent, transport) {
                            (VtaIntent::FullSetup, VtaTransport::Online) => {
                                // Online DIDComm flow with full
                                // provision-integration — wizard
                                // authenticates then runs the VP
                                // round-trip.
                                self.config.use_vta = true;
                                self.config.vta_mode = VTA_MODE_ONLINE.into();
                                self.apply_vta_defaults();
                                self.enter_vta_subflow(VtaIntent::FullSetup);
                            }
                            (VtaIntent::AdminOnly, VtaTransport::Offline) => {
                                // AdminOnly offline: `pnm contexts bootstrap`
                                // produces an `AdminCredential` sealed
                                // bundle; wizard extracts fallback admin
                                // fields.
                                self.config.use_vta = true;
                                self.config.vta_mode = VTA_MODE_SEALED.into();
                                self.apply_vta_defaults();
                                self.enter_sealed_handoff_subflow(VtaIntent::AdminOnly);
                            }
                            (VtaIntent::FullSetup, VtaTransport::Offline) => {
                                // FullSetup offline: wizard emits a VP-framed
                                // BootstrapRequest; VTA admin runs
                                // `vta bootstrap provision-integration` and
                                // returns a TemplateBootstrap sealed bundle
                                // that the wizard projects onto a full
                                // `ProvisionResult`.
                                self.config.use_vta = true;
                                self.config.vta_mode = VTA_MODE_SEALED.into();
                                self.apply_vta_defaults();
                                self.enter_sealed_handoff_subflow(VtaIntent::FullSetup);
                            }
                            (VtaIntent::AdminOnly, VtaTransport::Online) => {
                                // Online AdminOnly: wizard generates a
                                // fresh did:key, operator runs `pnm
                                // acl create` out-of-band, wizard
                                // opens an authenticated DIDComm
                                // session to verify enrollment. The
                                // setup did:key becomes the long-term
                                // admin credential (no rotation, no
                                // provision-integration).
                                self.config.use_vta = true;
                                self.config.vta_mode = VTA_MODE_ONLINE.into();
                                self.apply_vta_defaults();
                                self.enter_vta_subflow(VtaIntent::AdminOnly);
                            }
                            (VtaIntent::OfflineExport, _) => {
                                // OfflineExport bypasses the
                                // SelectTransport phase entirely (see
                                // SelectIntent index 2 above) — it has
                                // no online transport. Reaching here
                                // means the operator's selection_index
                                // landed on the wrong intent variant;
                                // treat as a wiring bug.
                                unreachable!(
                                    "OfflineExport should never reach SelectTransport — \
                                     SelectIntent routes it directly to sealed_handoff"
                                );
                            }
                        }
                    }
                }
            }
            WizardStep::Protocol => {
                // Enter always advances on a multi-select step. Toggling is
                // handled by `toggle_current_multi_select` (Space key).
                if !self.config.didcomm_enabled && !self.config.tsp_enabled {
                    return; // Can't continue with no protocol
                }
                self.advance();
            }
            WizardStep::Did => {
                // The webvh-host selection rides on top of the Did
                // step's selection list UI. Route Enter to the
                // sub-flow handler when that phase is active.
                if self.did_phase == Some(DidPhase::SelectWebvhHost) {
                    self.confirm_webvh_host_choice();
                    return;
                }
                if self.config.use_vta {
                    self.config.did_method = match self.selection_index {
                        0 => DID_VTA.into(),
                        1 => DID_WEBVH.into(),
                        2 => DID_PEER.into(),
                        3 => DID_IMPORT.into(),
                        _ => return,
                    };
                    // DID_VTA and DID_WEBVH both need the mediator URL so
                    // the resulting DID document can publish correct
                    // service endpoints. Skip the prompt when an upstream
                    // VTA subflow (online ConnectPhase::EnterMediatorUrl
                    // or sealed SealedPhase::CollectMediatorUrl) already
                    // captured it — the mediator DID has been minted
                    // from that value, so re-prompting is redundant.
                    let url_already_captured =
                        self.vta_session.is_some() && !self.config.public_url.is_empty();
                    if (self.selection_index == 0 || self.selection_index == 1)
                        && !url_already_captured
                    {
                        self.mode = InputMode::TextInput;
                        self.text_input = Input::new(self.config.public_url.clone());
                        return;
                    }
                } else {
                    self.config.did_method = match self.selection_index {
                        0 => DID_WEBVH.into(),
                        1 => DID_PEER.into(),
                        2 => DID_IMPORT.into(),
                        _ => return,
                    };
                    // For did:webvh, collect the public URL
                    if self.selection_index == 0 {
                        self.mode = InputMode::TextInput;
                        self.text_input = Input::new(self.config.public_url.clone());
                        return;
                    }
                }
                self.advance();
            }
            WizardStep::KeyStorage => {
                // FileEncryptChoice is the only phase that uses
                // selection mode (rather than text input) — handle it
                // here so Enter advances the encrypt/no-encrypt pick.
                if self.key_storage_phase == Some(KeyStoragePhase::FileEncryptChoice) {
                    if self.selection_index == 0 {
                        // Yes, encrypt — collect the passphrase.
                        self.enter_key_storage_phase(KeyStoragePhase::FilePassphrase);
                    } else {
                        // No, plaintext — finish the file:// sub-flow.
                        self.config.secret_file_encrypted = false;
                        self.exit_key_storage_subflow();
                        self.advance();
                    }
                    return;
                }
                // Ignore a stray Enter while a text-input sub-phase is
                // active — `confirm_text_input` drives those.
                if self.key_storage_phase.is_some() {
                    return;
                }
                self.config.secret_storage = match self.selection_index {
                    0 => STORAGE_KEYRING.into(),
                    1 => STORAGE_AWS.into(),
                    2 => STORAGE_GCP.into(),
                    3 => STORAGE_AZURE.into(),
                    4 => STORAGE_VAULT.into(),
                    5 => STORAGE_FILE.into(),
                    _ => return,
                };
                // Backend with extra config → enter sub-flow. No extra
                // config → advance straight away.
                if let Some(phase) = KeyStoragePhase::first_for(&self.config.secret_storage) {
                    self.enter_key_storage_phase(phase);
                } else {
                    self.advance();
                }
            }
            WizardStep::Security => {
                // Two-phase step: SSL first, then JWT mode. The JWT
                // sub-phase reuses `selection_index` for its own
                // 2-option pick.
                if self.security_phase == Some(SecurityPhase::JwtMode) {
                    self.config.jwt_mode = match self.selection_index {
                        0 => JWT_MODE_GENERATE.into(),
                        1 => JWT_MODE_PROVIDE.into(),
                        _ => return,
                    };
                    self.security_phase = None;
                    self.advance();
                    return;
                }
                self.config.ssl_mode = match self.selection_index {
                    0 => SSL_NONE.into(),
                    1 => SSL_EXISTING.into(),
                    2 => SSL_SELF_SIGNED.into(),
                    _ => return,
                };
                // For existing certs, collect file paths first; the JWT
                // phase then runs once both paths are saved.
                if self.selection_index == 1 {
                    self.mode = InputMode::TextInput;
                    self.text_input = Input::new(self.config.ssl_cert_path.clone());
                    return;
                }
                self.enter_jwt_mode_phase();
            }
            WizardStep::Database => {
                // Database step: confirm text input
                self.config.database_url = self.text_input.value().to_string();
                self.advance();
            }
            WizardStep::Admin => {
                // Options list is [generate, paste, (vta,) skip] with
                // the `vta` entry at index 2 only when
                // `admin_options_include_vta()` agrees. Use that same
                // predicate to map the selection back to the enum so
                // a layout change doesn't need two-place updates.
                let with_vta = self.admin_options_include_vta();
                self.config.admin_did_mode = match (with_vta, self.selection_index) {
                    (_, 0) => ADMIN_GENERATE.into(),
                    (_, 1) => ADMIN_PASTE.into(),
                    (true, 2) => ADMIN_VTA.into(),
                    (true, 3) => ADMIN_SKIP.into(),
                    (false, 2) => ADMIN_SKIP.into(),
                    _ => return,
                };
                self.advance();
            }
            WizardStep::Output => {
                // Enter on the Output step is a no-op when the text
                // input is active — `confirm_text_input` handles the
                // actual save. Keep the branch exhaustive.
            }
            WizardStep::Summary => {
                if self.mode == InputMode::Confirming {
                    self.write_config = true;
                    self.should_quit = true;
                } else {
                    self.mode = InputMode::Confirming;
                }
            }
        }
    }

    /// Enter a specific KeyStorage config sub-phase with the input
    /// pre-filled from the field's current value.
    fn enter_key_storage_phase(&mut self, phase: KeyStoragePhase) {
        let value = match phase {
            // FileGate / FilePassphrase / FileEncryptChoice all start
            // with an empty input — the operator must type the
            // dev-only acknowledgement / passphrase from scratch every
            // time, and the encrypt-choice screen uses a selection
            // list rather than text input.
            KeyStoragePhase::FileGate => String::new(),
            KeyStoragePhase::FilePassphrase => String::new(),
            KeyStoragePhase::FilePath => self.config.secret_file_path.clone(),
            KeyStoragePhase::KeyringService => self.config.secret_keyring_service.clone(),
            KeyStoragePhase::AwsRegion => self.config.secret_aws_region.clone(),
            KeyStoragePhase::AwsPrefix => self.config.secret_aws_prefix.clone(),
            KeyStoragePhase::GcpProject => self.config.secret_gcp_project.clone(),
            KeyStoragePhase::GcpPrefix => self.config.secret_gcp_prefix.clone(),
            KeyStoragePhase::AzureVault => self.config.secret_azure_vault.clone(),
            KeyStoragePhase::VaultEndpoint => self.config.secret_vault_endpoint.clone(),
            KeyStoragePhase::VaultMount => self.config.secret_vault_mount.clone(),
            // Encrypt choice doesn't take text input — render uses
            // selection mode. Short-circuit before touching the input
            // widget so we don't flip mode unexpectedly.
            KeyStoragePhase::FileEncryptChoice => {
                self.key_storage_phase = Some(phase);
                self.mode = InputMode::Selecting;
                self.selection_index = if self.config.secret_file_encrypted {
                    0
                } else {
                    1
                };
                return;
            }
        };
        self.key_storage_phase = Some(phase);
        self.text_input = Input::new(value);
        self.mode = InputMode::TextInput;
    }

    /// Confirm the current KeyStorage text-input phase: save the value,
    /// transition to the next phase for this backend, or advance out of
    /// the step if we're on the last field.
    fn confirm_key_storage_phase(&mut self) {
        let Some(phase) = self.key_storage_phase else {
            return;
        };
        let value = self.text_input.value().trim().to_string();
        match phase {
            KeyStoragePhase::FileGate => {
                // Case-insensitive match on the literal phrase. Anything
                // else aborts the file:// selection: clear the choice,
                // exit the sub-flow back to the scheme list so the
                // operator can pick a real backend.
                if value.eq_ignore_ascii_case(FILE_GATE_PHRASE) {
                    self.enter_key_storage_phase(KeyStoragePhase::FilePath);
                } else {
                    self.config.secret_storage = String::new();
                    self.exit_key_storage_subflow();
                }
            }
            KeyStoragePhase::FilePath => {
                if !value.is_empty() {
                    self.config.secret_file_path = value;
                }
                // After the file path lands the encrypt/no-encrypt
                // question. file:// is dev-only; we want the operator
                // to make the security trade-off explicitly rather
                // than silently shipping plaintext.
                self.enter_key_storage_phase(KeyStoragePhase::FileEncryptChoice);
            }
            KeyStoragePhase::FileEncryptChoice => {
                // Driven via select_current; the text-input branch
                // shouldn't be reached. If it is (stray Enter while
                // mode briefly mismatched), treat as no-op.
            }
            KeyStoragePhase::FilePassphrase => {
                if value.is_empty() {
                    // Reject empty — Argon2id with an empty passphrase
                    // is trivially brute-forceable.
                    return;
                }
                // Export to the env var the encrypted backend reads.
                // The wizard process is short-lived; the env var dies
                // with it. Operators who want persistence beyond the
                // wizard run set the var themselves before starting
                // the mediator.
                unsafe {
                    std::env::set_var(affinidi_messaging_mediator_common::PASSPHRASE_ENV, &value);
                }
                self.config.secret_file_encrypted = true;
                self.exit_key_storage_subflow();
                self.advance();
            }
            KeyStoragePhase::KeyringService => {
                if !value.is_empty() {
                    self.config.secret_keyring_service = value;
                }
                self.exit_key_storage_subflow();
                self.advance();
            }
            KeyStoragePhase::AwsRegion => {
                if !value.is_empty() {
                    self.config.secret_aws_region = value;
                }
                self.enter_key_storage_phase(KeyStoragePhase::AwsPrefix);
            }
            KeyStoragePhase::AwsPrefix => {
                if !value.is_empty() {
                    self.config.secret_aws_prefix = value;
                }
                self.exit_key_storage_subflow();
                self.advance();
            }
            KeyStoragePhase::GcpProject => {
                if value.is_empty() {
                    // GCP project IDs aren't optional — there's no
                    // sensible default. Reject and keep the operator on
                    // the prompt rather than write `gcp_secrets:///…`
                    // and explode at backend-open time.
                    return;
                }
                self.config.secret_gcp_project = value;
                self.enter_key_storage_phase(KeyStoragePhase::GcpPrefix);
            }
            KeyStoragePhase::GcpPrefix => {
                // Empty prefix is allowed — GCP secret names accept the
                // bare well-known keys verbatim.
                self.config.secret_gcp_prefix = value;
                self.exit_key_storage_subflow();
                self.advance();
            }
            KeyStoragePhase::AzureVault => {
                if value.is_empty() {
                    // No default — sovereign-cloud + commercial-cloud
                    // share no host pattern. Force a typed answer
                    // rather than silently writing `azure_keyvault://`.
                    return;
                }
                self.config.secret_azure_vault = value;
                self.exit_key_storage_subflow();
                self.advance();
            }
            KeyStoragePhase::VaultEndpoint => {
                if value.is_empty() {
                    // Vault endpoints are deployment-specific (the
                    // `vault server` listen address is environment-
                    // dependent). No sensible default — force a typed
                    // answer.
                    return;
                }
                self.config.secret_vault_endpoint = value;
                self.enter_key_storage_phase(KeyStoragePhase::VaultMount);
            }
            KeyStoragePhase::VaultMount => {
                if !value.is_empty() {
                    self.config.secret_vault_mount = value;
                }
                self.exit_key_storage_subflow();
                self.advance();
            }
        }
    }

    /// Back-nav within the KeyStorage sub-flow. AWS / GCP / Vault each
    /// chain two phases; back from the second returns to the first.
    /// Single-phase backends (keyring, file gate, Azure vault) drop
    /// straight back to the scheme selection list.
    fn key_storage_back(&mut self) {
        let Some(phase) = self.key_storage_phase else {
            return;
        };
        match phase {
            KeyStoragePhase::AwsPrefix => {
                self.enter_key_storage_phase(KeyStoragePhase::AwsRegion);
            }
            KeyStoragePhase::GcpPrefix => {
                self.enter_key_storage_phase(KeyStoragePhase::GcpProject);
            }
            KeyStoragePhase::VaultMount => {
                self.enter_key_storage_phase(KeyStoragePhase::VaultEndpoint);
            }
            _ => {
                self.exit_key_storage_subflow();
            }
        }
    }

    fn exit_key_storage_subflow(&mut self) {
        self.key_storage_phase = None;
        self.mode = InputMode::Selecting;
        self.text_input = Input::default();
    }

    /// `true` while the discovery overlay (loading spinner, results
    /// list, or error banner) is on screen. The main input handler
    /// short-circuits to [`Self::handle_discovery_key`] in this state
    /// so normal text-input keys don't leak through.
    pub fn in_discovery_overlay(&self) -> bool {
        self.discovery.is_some()
    }

    /// Build a [`DiscoveryRequest`] for the current key-storage phase
    /// and the wizard's accumulated config, or return `None` when the
    /// phase isn't discoverable (or required upstream config is
    /// missing — e.g. F5 on `AwsPrefix` before `AwsRegion` was filled).
    fn discovery_request_for_phase(&self) -> Option<DiscoveryRequest> {
        let phase = self.key_storage_phase?;
        match phase {
            KeyStoragePhase::AwsPrefix => {
                let region = self.config.secret_aws_region.trim();
                if region.is_empty() {
                    return None;
                }
                Some(DiscoveryRequest::Aws {
                    region: region.to_string(),
                })
            }
            KeyStoragePhase::GcpPrefix => {
                let project = self.config.secret_gcp_project.trim();
                if project.is_empty() {
                    return None;
                }
                Some(DiscoveryRequest::Gcp {
                    project: project.to_string(),
                })
            }
            KeyStoragePhase::AzureVault => {
                // The vault name is the *current* text input — the
                // operator hasn't confirmed it yet. Treat F5 as a
                // sanity check on what they've typed so far.
                let vault = self.text_input.value().trim();
                if vault.is_empty() {
                    return None;
                }
                Some(DiscoveryRequest::Azure {
                    vault: vault.to_string(),
                })
            }
            KeyStoragePhase::VaultMount => {
                let endpoint = self.config.secret_vault_endpoint.trim();
                if endpoint.is_empty() {
                    return None;
                }
                // Use the operator's currently-typed mount value as the
                // discovery target. Empty / unset → fall back to the
                // wizard default so F5 still works on a fresh entry.
                let raw_mount = self.text_input.value().trim();
                let mount = if raw_mount.is_empty() {
                    DEFAULT_VAULT_MOUNT.to_string()
                } else {
                    raw_mount.to_string()
                };
                Some(DiscoveryRequest::Vault {
                    endpoint: endpoint.to_string(),
                    mount,
                })
            }
            // Other key-storage phases are local-only (file path,
            // keyring service, AWS region, GCP project, Vault
            // endpoint, file gate, encrypt choice, file passphrase) —
            // no remote namespace to enumerate.
            _ => None,
        }
    }

    /// Kick off discovery for the current key-storage phase. Sets the
    /// overlay to `Loading` and spawns a background task that resolves
    /// to a `DiscoveryEvent` on the channel. No-op (silent) when the
    /// current phase isn't discoverable or upstream config is missing —
    /// the F5 hint footer makes the requirements visible.
    pub fn kick_off_discovery(&mut self) {
        if self.discovery.is_some() {
            // Already in flight or being browsed — F5 is idempotent.
            return;
        }
        let Some(req) = self.discovery_request_for_phase() else {
            return;
        };
        let (tx, rx) = unbounded_channel();
        self.discovery = Some(DiscoveryState::Loading);
        self.discovery_rx = Some(rx);
        crate::discovery::spawn(req, tx);
    }

    /// Drain any discovery events queued since the last tick into the
    /// overlay state. Called from the main loop's ticker so the UI
    /// reflects the result without waiting for a keypress.
    pub fn drain_discovery_events(&mut self) {
        let Some(rx) = self.discovery_rx.as_mut() else {
            return;
        };
        // Best-effort drain — `try_recv` doesn't block. We only handle
        // one event per tick because the channel only ever carries one
        // (Loaded or Failed) before we drop the receiver.
        if let Ok(event) = rx.try_recv() {
            self.discovery = Some(match event {
                DiscoveryEvent::Loaded { mode, items, total } => DiscoveryState::Loaded {
                    mode,
                    items,
                    total,
                    cursor: 0,
                    scroll: 0,
                },
                DiscoveryEvent::Failed(message) => DiscoveryState::Failed { message },
            });
            self.discovery_rx = None;
        }
    }

    /// Handle keypresses while the discovery overlay is on screen.
    /// Returns `true` when the key was consumed by the overlay so the
    /// caller skips the usual text-input dispatch.
    pub fn handle_discovery_key(&mut self, code: crossterm::event::KeyCode) -> bool {
        use crossterm::event::KeyCode;
        let Some(state) = self.discovery.as_mut() else {
            return false;
        };
        match state {
            DiscoveryState::Loading => {
                // Esc cancels (drops the channel — the spawned task
                // can finish; its send goes to a dropped receiver).
                // Any other key is swallowed silently.
                if matches!(code, KeyCode::Esc) {
                    self.discovery = None;
                    self.discovery_rx = None;
                }
            }
            DiscoveryState::Failed { .. } => {
                // Any key dismisses the error banner.
                self.discovery = None;
                self.discovery_rx = None;
            }
            DiscoveryState::Loaded {
                mode,
                items,
                cursor,
                scroll,
                ..
            } => {
                if items.is_empty() {
                    // Empty list — only Esc / Enter dismiss.
                    if matches!(code, KeyCode::Esc | KeyCode::Enter) {
                        self.discovery = None;
                    }
                    return true;
                }
                let max = items.len() - 1;
                match code {
                    KeyCode::Up | KeyCode::Char('k') => {
                        if *cursor > 0 {
                            *cursor -= 1;
                            // Keep cursor visible — scroll up if we
                            // walked past the top of the viewport.
                            if *cursor < *scroll {
                                *scroll = *cursor;
                            }
                        }
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        if *cursor < max {
                            *cursor += 1;
                            // Viewport height is rendered-side knowledge;
                            // we approximate with a generous 10-row
                            // window. Worst case the renderer clips a
                            // row — better than constraining input
                            // logic to a magic-number height.
                            if *cursor >= *scroll + 10 {
                                *scroll = cursor.saturating_sub(9);
                            }
                        }
                    }
                    KeyCode::PageUp => {
                        *cursor = cursor.saturating_sub(10);
                        *scroll = scroll.saturating_sub(10);
                    }
                    KeyCode::PageDown => {
                        *cursor = (*cursor + 10).min(max);
                        if *cursor >= *scroll + 10 {
                            *scroll = cursor.saturating_sub(9);
                        }
                    }
                    KeyCode::Home => {
                        *cursor = 0;
                        *scroll = 0;
                    }
                    KeyCode::End => {
                        *cursor = max;
                        *scroll = max.saturating_sub(9);
                    }
                    KeyCode::Enter => {
                        // Pick mode applies the selection; Confirm
                        // mode just dismisses (the list was an info
                        // display, not a chooser).
                        if matches!(mode, DiscoveryMode::Pick) {
                            let picked = items[*cursor].clone();
                            self.text_input = Input::new(picked);
                        }
                        self.discovery = None;
                    }
                    KeyCode::Esc => {
                        self.discovery = None;
                    }
                    _ => {}
                }
            }
        }
        true
    }

    /// Enter the JWT-mode sub-phase of the Security step. Called once SSL
    /// has been settled (either selection-only path or after the cert/key
    /// inputs). Pre-selects the operator's last choice so re-entry is
    /// idempotent; defaults to "generate" on a fresh run.
    fn enter_jwt_mode_phase(&mut self) {
        self.security_phase = Some(SecurityPhase::JwtMode);
        self.mode = InputMode::Selecting;
        self.selection_index = if self.config.jwt_mode == JWT_MODE_PROVIDE {
            1
        } else {
            0
        };
    }

    /// Strip any URL path so the stripped `<scheme>://<host>[:port]`
    /// lands on the VTA's `CreateDidWebvhRequest.url`. webvh resolves
    /// to `<url>/.well-known/did.jsonl`, so a trailing `/mediator/v1`
    /// on the operator-typed URL would point the resolver somewhere
    /// that doesn't serve the DID document.
    fn strip_url_path(raw: &str) -> String {
        match url::Url::parse(raw) {
            Ok(mut u) => {
                u.set_path("");
                u.to_string().trim_end_matches('/').to_string()
            }
            Err(_) => raw.to_string(),
        }
    }

    /// Number of entries in the webvh-host selection list — kept as
    /// a helper for future navigation code (e.g. up/down clamping)
    /// though the renderer derives the count from `current_options()`
    /// today.
    #[allow(dead_code)]
    fn webvh_host_option_count(&self) -> usize {
        // Pre provision-integration there was a list of VTA-registered
        // webvh servers here. That list is gone — the VTA's template
        // decides publishing — so only the two static self-host options
        // remain.
        2
    }

    pub fn in_did_subflow(&self) -> bool {
        self.current_step == WizardStep::Did && self.did_phase.is_some()
    }

    /// Confirm the SelectWebvhHost selection. `selection_index` maps
    /// to 0 = self-host at mediator URL, 1..=servers.len() = VTA-hosted
    /// server, servers.len()+1 = self-host elsewhere.
    fn confirm_webvh_host_choice(&mut self) {
        // Only two static options remain after provision-integration:
        // idx 0 = self-host at mediator URL, idx 1 = self-host elsewhere.
        // The VTA-registered server list is gone; the VTA's template
        // handles publishing for use_vta flows.
        match self.selection_index {
            0 => {
                self.config.vta_webvh_server_id = None;
                self.config.vta_webvh_mnemonic = None;
                self.did_phase = None;
                self.advance();
            }
            _ => {
                self.did_phase = Some(DidPhase::EnterCustomUrl);
                self.mode = InputMode::TextInput;
                self.text_input = Input::new(self.config.vta_webvh_self_host_url.clone());
            }
        }
    }

    /// Defensive helper kept symmetric with [`Self::in_key_storage_subflow`].
    /// Currently unused at call sites — the renderer reads
    /// `security_phase` directly — but exposed so future help-bar /
    /// back-nav code can branch on the same predicate.
    #[allow(dead_code)]
    pub fn in_security_subflow(&self) -> bool {
        self.current_step == WizardStep::Security && self.security_phase.is_some()
    }

    pub fn in_key_storage_subflow(&self) -> bool {
        self.current_step == WizardStep::KeyStorage && self.key_storage_phase.is_some()
    }

    /// Handle text input confirmation (Enter in TextInput mode).
    pub fn confirm_text_input(&mut self) {
        if self.in_key_storage_subflow() {
            self.confirm_key_storage_phase();
            return;
        }
        if self.in_vta_subflow() {
            // Errors here mean the ephemeral key generator failed — surface
            // as a transient error on the sub-flow state, not a panic.
            if let Err(e) = self.vta_subflow_confirm_text()
                && let Some(st) = self.vta_connect.as_mut()
            {
                st.last_error = Some(e.to_string());
            }
            return;
        }
        if self.in_sealed_handoff_subflow() && self.sealed_handoff_confirm_text() {
            return;
        }
        match self.current_step {
            WizardStep::Did => {
                // Handle Did sub-phases (VTA webvh host choice) before
                // the "just saved the mediator URL" fall-through below.
                match self.did_phase {
                    Some(DidPhase::EnterCustomUrl) => {
                        let v = self.text_input.value().trim().to_string();
                        if !v.is_empty() {
                            self.config.vta_webvh_self_host_url = Self::strip_url_path(&v);
                        }
                        self.config.vta_webvh_server_id = None;
                        self.config.vta_webvh_mnemonic = None;
                        self.did_phase = None;
                        self.mode = InputMode::Selecting;
                        self.advance();
                        return;
                    }
                    // SelectWebvhHost is Selecting mode, not TextInput —
                    // falls through to the default Did branch below.
                    _ => {}
                }

                self.config.public_url = self.text_input.value().to_string();
                // For the VTA-managed path the mediator DID is already
                // rendered by the VTA's template (provision-integration
                // happened in the Vta step), so we skip the webvh-host
                // picker entirely — there's no choice left for the
                // operator to make. did:webvh / import / sealed-handoff
                // fall through to the straight advance below.
                if self.config.did_method == DID_VTA && self.vta_session.is_some() {
                    self.mode = InputMode::Selecting;
                    self.advance();
                    return;
                }
                self.mode = InputMode::Selecting;
                self.advance();
            }
            WizardStep::Security => {
                // First text input: cert path, then key path. After the
                // key path is saved, drop into the JWT-mode selection
                // rather than advancing straight to Database.
                if self.config.ssl_cert_path.is_empty()
                    || self.config.ssl_cert_path == self.text_input.value()
                {
                    self.config.ssl_cert_path = self.text_input.value().to_string();
                    self.text_input = Input::new(self.config.ssl_key_path.clone());
                } else {
                    self.config.ssl_key_path = self.text_input.value().to_string();
                    self.mode = InputMode::Selecting;
                    self.enter_jwt_mode_phase();
                }
            }
            WizardStep::Database => {
                self.config.database_url = self.text_input.value().to_string();
                self.mode = InputMode::Selecting;
                self.advance();
            }
            WizardStep::Output => {
                let value = self.text_input.value().trim().to_string();
                if !value.is_empty() {
                    self.config.config_path = value;
                }
                self.mode = InputMode::Selecting;
                self.advance();
            }
            _ => {
                self.mode = InputMode::Selecting;
                self.advance();
            }
        }
    }

    /// Apply sensible defaults based on deployment type selection.
    fn apply_deployment_defaults(&mut self) {
        match self.config.deployment_type.as_str() {
            DEPLOYMENT_LOCAL | DEPLOYMENT_SERVER | DEPLOYMENT_CONTAINER => {
                self.config.use_vta = true;
                self.config.vta_mode = VTA_MODE_ONLINE.into();
                self.config.didcomm_enabled = true;
                self.config.tsp_enabled = false;
                self.config.did_method = DID_VTA.into();
                // The unified secret backend is independent of VTA mode —
                // pick a sensible default per platform; the operator
                // refines it on the KeyStorage step.
                self.config.secret_storage = STORAGE_KEYRING.into();
                self.config.ssl_mode = SSL_NONE.into();
                self.config.database_url = DEFAULT_REDIS_URL.into();
                self.config.admin_did_mode = ADMIN_GENERATE.into();
            }
            _ => {}
        }
    }

    /// Apply or clear VTA-dependent defaults when toggling VTA integration.
    ///
    /// `secret_storage` is deliberately *not* overridden here — the operator
    /// configures it in the earlier `KeyStorage` step and the VTA step
    /// should respect that choice. The Did + Admin defaults still shift
    /// because those steps come after Vta.
    fn apply_vta_defaults(&mut self) {
        if self.config.use_vta {
            // Intent decides whether the VTA supplies the mediator
            // DID too, or only the admin credential.
            match self.vta_intent_choice {
                Some(VtaIntent::FullSetup) | None => {
                    // FullSetup deliberately mints a fresh admin DID
                    // as part of `provision_integration`'s admin-DID
                    // rollover — that DID is the intended mediator
                    // admin handoff, so `ADMIN_VTA` is the correct
                    // default.
                    //
                    // `None` shouldn't happen while `use_vta` is
                    // `true` under the two-question picker, but
                    // fall through to the legacy "VTA supplies
                    // everything" defaults for safety.
                    self.config.did_method = DID_VTA.into();
                    self.config.admin_did_mode = ADMIN_VTA.into();
                }
                Some(VtaIntent::OfflineExport) => {
                    // OfflineExport mints an admin credential as a
                    // side effect of `vta context reprovision` (for
                    // the mediator to authenticate back to the VTA),
                    // NOT as an intentional mediator-admin-API
                    // handoff. Reusing that same DID for both the
                    // mediator→VTA trust boundary and the
                    // clients→mediator-admin trust boundary
                    // overloads one key across two scopes.
                    //
                    // Default the mediator's admin-API identity to
                    // `ADMIN_GENERATE` (fresh did:key) so the two
                    // roles stay separate by default. Operator can
                    // still override at the Admin step if their
                    // deployment warrants reusing the VTA credential.
                    self.config.did_method = DID_VTA.into();
                    self.config.admin_did_mode = ADMIN_GENERATE.into();
                }
                Some(VtaIntent::AdminOnly) => {
                    // Mediator's integration DID is chosen locally
                    // in the Did step; the VTA only supplies an
                    // admin credential. Drop any stale DID_VTA
                    // carry-over from an earlier FullSetup attempt
                    // so the Did step surfaces the real picker.
                    //
                    // AdminOnly keeps `ADMIN_VTA` because that IS
                    // the point of the intent — the VTA is explicitly
                    // asked to supply the mediator's admin identity.
                    if self.config.did_method == DID_VTA {
                        self.config.did_method = DID_PEER.into();
                    }
                    self.config.admin_did_mode = ADMIN_VTA.into();
                }
            }
        } else {
            if self.config.did_method == DID_VTA {
                self.config.did_method = DID_PEER.into();
            }
            if self.config.admin_did_mode == ADMIN_VTA {
                self.config.admin_did_mode = ADMIN_GENERATE.into();
            }
            self.config.vta_mode = String::new();
        }
    }

    /// Whether the Admin step's option list should include the
    /// "Generate admin DID from VTA" entry.
    ///
    /// Returns `true` for deployments where the VTA intentionally mints
    /// an admin DID meant for the mediator (FullSetup's admin-DID
    /// rollover, AdminOnly's whole-flow purpose). Returns `false` for
    /// OfflineExport — the bundle's admin credential there is an
    /// auto-mint for mediator↔VTA authentication, and reusing it as
    /// the mediator's own admin-API identity conflates two trust
    /// scopes behind one key.
    fn admin_options_include_vta(&self) -> bool {
        if !self.config.use_vta {
            return false;
        }
        !matches!(self.vta_intent_choice, Some(VtaIntent::OfflineExport))
    }

    /// Whether the Did step should offer the "Configure via VTA"
    /// option. Only meaningful after the Vta step has completed; read
    /// from the persisted `did_method` (set by `apply_vta_defaults`
    /// for FullSetup) plus the session state when present.
    fn shows_vta_did_option(&self) -> bool {
        // `did_method == DID_VTA` is the FullSetup signal — AdminOnly
        // clears it in `apply_vta_defaults`. `No VTA` also clears it.
        self.config.did_method == DID_VTA
    }

    /// Per-step entry reset. Called from every point that mutates
    /// `current_step` so that landing on a step (forward or backward)
    /// always starts from a clean sub-phase. Keeping this in one place
    /// avoids the "which sub-phase leaked from the last visit" class
    /// of bug.
    fn on_enter_step(&mut self) {
        if self.current_step == WizardStep::Vta {
            self.vta_step_phase = VtaStepPhase::SelectIntent;
            self.vta_intent_choice = None;
            self.vta_stub_notice = None;
        }
    }

    fn advance(&mut self) {
        // Step through the wizard, auto-skipping any step whose inputs
        // have already been settled upstream (see
        // `should_auto_skip_step`). The loop lets us chain skips —
        // e.g. a future step that's also FullSetup-noop — without
        // reworking callers. Bounded by `WizardStep::total()` to
        // guarantee termination even if the predicate pathologically
        // fires on every remaining step.
        let mut guard = WizardStep::total();
        loop {
            self.completed.push(self.current_step);
            let Some(next) = self.current_step.next() else {
                return;
            };
            self.current_step = next;
            self.on_enter_step();
            self.selection_index = self.default_selection_index();
            // Database + Output both open in text-input mode; Summary
            // goes straight to the confirmation screen. Everything
            // else uses the selection-list default.
            if self.current_step == WizardStep::Database {
                self.mode = InputMode::TextInput;
                self.text_input = Input::new(self.config.database_url.clone());
            } else if self.current_step == WizardStep::Output {
                self.mode = InputMode::TextInput;
                self.text_input = Input::new(self.config.config_path.clone());
            } else if self.current_step == WizardStep::Summary {
                self.mode = InputMode::Confirming;
            } else {
                self.mode = InputMode::Selecting;
            }
            if !self.should_auto_skip_step() {
                return;
            }
            guard = guard.saturating_sub(1);
            if guard == 0 {
                return;
            }
        }
    }

    /// Per-step predicate: true when the step has no operator-actionable
    /// decision left because upstream work already settled it. The
    /// wizard's `advance` / `go_back` loops consult this to jump over
    /// such steps silently rather than presenting a single-option
    /// confirmation screen.
    ///
    /// Today only the `Did` step qualifies, and only under online
    /// FullSetup / OfflineExport: the VTA either minted the integration
    /// DID during provision-integration (FullSetup — TemplateBootstrap
    /// reply) or exported a pre-provisioned one via `vta context
    /// reprovision` (OfflineExport — ContextProvision reply). Either
    /// way `apply_vta_defaults` already pinned `did_method = DID_VTA`
    /// and the mediator DID + doc + keys + did.jsonl ride on
    /// `vta_session`. Operators can still reach this step via the
    /// progress-panel jump if they want to inspect it.
    fn should_auto_skip_step(&self) -> bool {
        match self.current_step {
            WizardStep::Did => {
                self.config.use_vta
                    && self.config.did_method == DID_VTA
                    && self.vta_session.as_ref().is_some_and(|s| {
                        // Either provisioning shape carries a minted
                        // integration DID. AdminOnly has neither
                        // accessor populated — the mediator brought
                        // its own DID, so the Did step still runs.
                        s.as_full_provision().is_some() || s.as_context_export().is_some()
                    })
            }
            _ => false,
        }
    }

    pub fn go_back(&mut self) {
        if self.in_key_storage_subflow() {
            self.key_storage_back();
            return;
        }
        if self.in_vta_subflow() {
            self.vta_subflow_back();
            return;
        }
        if self.in_sealed_handoff_subflow() {
            self.sealed_handoff_back();
            return;
        }
        // Top-level Vta picker: Esc from SelectTransport rewinds to
        // SelectIntent rather than leaving the step entirely. The
        // intent choice is cleared so SelectIntent's selection_index
        // can be re-defaulted without a stale pick.
        if self.current_step == WizardStep::Vta
            && self.vta_step_phase == VtaStepPhase::SelectTransport
            && self.vta_connect.is_none()
            && self.sealed_handoff.is_none()
        {
            self.vta_step_phase = VtaStepPhase::SelectIntent;
            self.vta_intent_choice = None;
            self.vta_stub_notice = None;
            self.selection_index = 0;
            self.mode = InputMode::Selecting;
            return;
        }
        if self.in_did_subflow() {
            // EnterCustomUrl and EnterMnemonic → back to SelectWebvhHost.
            // SelectWebvhHost → exit the sub-flow entirely and fall
            // back to the mediator URL prompt.
            match self.did_phase {
                Some(DidPhase::EnterCustomUrl) => {
                    self.did_phase = Some(DidPhase::SelectWebvhHost);
                    self.mode = InputMode::Selecting;
                    self.selection_index = 0;
                }
                Some(DidPhase::SelectWebvhHost) => {
                    self.did_phase = None;
                    self.mode = InputMode::TextInput;
                    self.text_input = Input::new(self.config.public_url.clone());
                }
                None => {}
            }
            return;
        }
        match self.mode {
            InputMode::TextInput => {
                self.mode = InputMode::Selecting;
            }
            InputMode::Confirming => {
                // On Summary, Esc goes back to the previous step
                if self.current_step == WizardStep::Summary {
                    self.step_back_auto_skipping();
                    self.mode = InputMode::Selecting;
                    self.refresh_text_input_mode();
                } else {
                    self.mode = InputMode::Selecting;
                }
            }
            InputMode::Selecting => {
                if !self.step_back_auto_skipping() {
                    // Already at the first step — Esc quits the wizard.
                    self.should_quit = true;
                    return;
                }
                self.refresh_text_input_mode();
            }
        }
    }

    /// Walk `current_step` backwards one step, skipping any step that
    /// [`Self::should_auto_skip_step`] reports as non-actionable. The
    /// forward path uses the same predicate inside `advance`, so
    /// back-nav lands on the same step the operator saw on the way in.
    /// Returns `true` when a previous step was found (current_step
    /// mutated), `false` when we're already at the first step.
    fn step_back_auto_skipping(&mut self) -> bool {
        let mut guard = WizardStep::total();
        loop {
            let Some(prev) = self.current_step.prev() else {
                return false;
            };
            self.completed.retain(|s| *s != prev);
            self.current_step = prev;
            self.on_enter_step();
            self.selection_index = self.default_selection_index();
            if !self.should_auto_skip_step() {
                return true;
            }
            guard = guard.saturating_sub(1);
            if guard == 0 {
                return true;
            }
        }
    }

    /// Shared helper for `go_back`: when landing on a text-input step
    /// (Database, Output) re-seed the input widget with the current
    /// config value so the operator can edit rather than retype.
    fn refresh_text_input_mode(&mut self) {
        match self.current_step {
            WizardStep::Database => {
                self.mode = InputMode::TextInput;
                self.text_input = Input::new(self.config.database_url.clone());
            }
            WizardStep::Output => {
                self.mode = InputMode::TextInput;
                self.text_input = Input::new(self.config.config_path.clone());
            }
            _ => {}
        }
    }

    pub fn move_up(&mut self) {
        if self.selection_index > 0 {
            self.selection_index -= 1;
        }
    }

    pub fn move_down(&mut self) {
        let max = self.current_options().len().saturating_sub(1);
        if self.selection_index < max {
            self.selection_index += 1;
        }
    }

    pub fn handle_text_input(&mut self, req: InputRequest) {
        self.text_input.handle(req);
    }

    /// Toggle the currently highlighted option on a multi-select step.
    /// No-op on single-select steps. Enforces "at least one selection"
    /// invariants where the step has them (e.g. Protocol needs at least one
    /// protocol enabled).
    pub fn toggle_current_multi_select(&mut self) {
        if !self.current_step.is_multi_select() {
            return;
        }
        match self.current_step {
            WizardStep::Protocol => {
                let was_didcomm = self.config.didcomm_enabled;
                let was_tsp = self.config.tsp_enabled;
                match self.selection_index {
                    0 => self.config.didcomm_enabled = !self.config.didcomm_enabled,
                    1 => self.config.tsp_enabled = !self.config.tsp_enabled,
                    _ => {}
                }
                // Never let the operator deselect everything — revert the
                // toggle if the result would leave zero protocols enabled.
                if !self.config.didcomm_enabled && !self.config.tsp_enabled {
                    self.config.didcomm_enabled = was_didcomm;
                    self.config.tsp_enabled = was_tsp;
                }
            }
            _ => {}
        }
    }

    /// Splice a pasted string into the current text input at the cursor
    /// position. No-op outside of `InputMode::TextInput`. Newlines and other
    /// control characters are dropped so a multi-line paste collapses to a
    /// single line (our fields — DID, context id, URLs — are single-line by
    /// design).
    ///
    /// **Exception**: the sealed-handoff `AwaitingBundle` phase accepts
    /// armored bytes whose format is fundamentally multi-line (`-----BEGIN
    /// VTA SEALED BUNDLE-----` / `-----END ...-----` with newlines between
    /// them). We preserve `\n` and `\r` on that phase so a genuine
    /// bracketed-paste of the armor content survives through to
    /// `armor::decode`. In practice most terminals still collapse large
    /// pastes, which is why the confirm handler also accepts a file path —
    /// see `sealed_handoff_confirm_text::AwaitingBundle`.
    pub fn paste_text(&mut self, raw: &str) {
        if self.mode != InputMode::TextInput {
            return;
        }
        let preserve_newlines = matches!(
            self.sealed_handoff.as_ref().map(|s| s.phase),
            Some(crate::sealed_handoff::SealedPhase::AwaitingBundle)
        );
        let cleaned: String = raw
            .chars()
            .filter(|c| {
                if preserve_newlines && (*c == '\n' || *c == '\r') {
                    return true;
                }
                !c.is_control() && *c != '\n' && *c != '\r' && *c != '\t'
            })
            .collect();
        if cleaned.is_empty() {
            return;
        }
        let current = self.text_input.value();
        let cursor = self.text_input.cursor();
        let mut chars = current.chars();
        let mut new_value = String::with_capacity(current.len() + cleaned.len());
        for _ in 0..cursor {
            if let Some(c) = chars.next() {
                new_value.push(c);
            }
        }
        new_value.push_str(&cleaned);
        for c in chars {
            new_value.push(c);
        }
        let new_cursor = cursor + cleaned.chars().count();
        self.text_input = Input::new(new_value).with_cursor(new_cursor);
    }

    /// Get the default selection index based on deployment defaults.
    fn default_selection_index(&self) -> usize {
        match self.current_step {
            WizardStep::Vta => match self.config.vta_mode.as_str() {
                VTA_MODE_ONLINE => 0,
                VTA_MODE_SEALED => 1,
                _ if self.config.use_vta => 0, // VTA enabled but no mode yet
                _ => 2,                        // No VTA
            },
            WizardStep::Protocol => 0, // Start at DIDComm toggle
            WizardStep::Did => {
                if self.config.use_vta {
                    match self.config.did_method.as_str() {
                        DID_VTA => 0,
                        DID_WEBVH => 1,
                        DID_PEER => 2,
                        DID_IMPORT => 3,
                        _ => 0,
                    }
                } else {
                    match self.config.did_method.as_str() {
                        DID_WEBVH => 0,
                        DID_PEER => 1,
                        DID_IMPORT => 2,
                        _ => 0,
                    }
                }
            }
            WizardStep::KeyStorage => match self.config.secret_storage.as_str() {
                STORAGE_KEYRING => 0,
                STORAGE_AWS => 1,
                STORAGE_GCP => 2,
                STORAGE_AZURE => 3,
                STORAGE_VAULT => 4,
                STORAGE_FILE => 5,
                _ => 0,
            },
            WizardStep::Security => match self.config.ssl_mode.as_str() {
                SSL_EXISTING => 1,
                SSL_SELF_SIGNED => 2,
                _ => 0,
            },
            WizardStep::Admin => {
                // Mirror the layout logic in `current_options` /
                // `select_current`: VTA entry at index 2 only when
                // `admin_options_include_vta()`. When absent (e.g.
                // OfflineExport), `ADMIN_VTA` is no longer a valid
                // stored mode for this flow — fall back to the
                // generate-new-did:key default rather than pointing
                // at an option that isn't rendered.
                let with_vta = self.admin_options_include_vta();
                match (with_vta, self.config.admin_did_mode.as_str()) {
                    (_, ADMIN_PASTE) => 1,
                    (true, ADMIN_VTA) => 2,
                    (true, ADMIN_SKIP) => 3,
                    (false, ADMIN_SKIP) => 2,
                    _ => 0,
                }
            }
            _ => 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── WizardStep navigation ──────────────────────────────────────────

    #[test]
    fn step_all_returns_10_steps_in_order() {
        // Output was inserted before Summary in the "move config-path
        // into the TUI" refactor, bumping the step count from 9 → 10.
        let steps = WizardStep::all();
        assert_eq!(steps.len(), 10);
        assert_eq!(steps[0], WizardStep::Deployment);
        assert_eq!(steps[1], WizardStep::KeyStorage);
        assert_eq!(steps[2], WizardStep::Vta);
        assert_eq!(steps[8], WizardStep::Output);
        assert_eq!(steps[9], WizardStep::Summary);
    }

    #[test]
    fn step_index_matches_position() {
        for (i, step) in WizardStep::all().iter().enumerate() {
            assert_eq!(step.index(), i);
            assert_eq!(step.step_number(), i + 1);
        }
    }

    #[test]
    fn step_total_matches_all_len() {
        assert_eq!(WizardStep::total(), WizardStep::all().len());
    }

    #[test]
    fn first_step_has_no_prev() {
        assert_eq!(WizardStep::Deployment.prev(), None);
    }

    #[test]
    fn last_step_has_no_next() {
        assert_eq!(WizardStep::Summary.next(), None);
    }

    #[test]
    fn next_prev_are_inverses() {
        let steps = WizardStep::all();
        for i in 0..steps.len() - 1 {
            let next = steps[i].next().unwrap();
            assert_eq!(next, steps[i + 1]);
            assert_eq!(next.prev().unwrap(), steps[i]);
        }
    }

    // ── WizardConfig ───────────────────────────────────────────────────

    #[test]
    fn protocol_display_combinations() {
        let mut cfg = WizardConfig::default();
        cfg.didcomm_enabled = true;
        cfg.tsp_enabled = false;
        assert_eq!(cfg.protocol_display(), "DIDComm v2");

        cfg.tsp_enabled = true;
        assert_eq!(cfg.protocol_display(), "DIDComm v2 + TSP");

        cfg.didcomm_enabled = false;
        assert_eq!(cfg.protocol_display(), "TSP");

        cfg.tsp_enabled = false;
        assert_eq!(cfg.protocol_display(), "None (invalid)");
    }

    #[test]
    fn default_config_has_sensible_values() {
        let cfg = WizardConfig::default();
        assert!(cfg.didcomm_enabled);
        assert!(!cfg.tsp_enabled);
        assert_eq!(cfg.config_path, DEFAULT_CONFIG_PATH);
        assert_eq!(cfg.database_url, DEFAULT_REDIS_URL);
        assert_eq!(cfg.listen_address, DEFAULT_LISTEN_ADDR);
    }

    // ── WizardApp state machine ────────────────────────────────────────

    #[test]
    fn new_app_starts_at_deployment() {
        let app = WizardApp::new(DEFAULT_CONFIG_PATH.into());
        assert_eq!(app.current_step, WizardStep::Deployment);
        assert_eq!(app.mode, InputMode::Selecting);
        assert_eq!(app.focus, FocusPanel::Content);
        assert!(!app.should_quit);
        assert!(!app.write_config);
    }

    #[test]
    fn advance_moves_to_next_step() {
        let mut app = WizardApp::new("test.toml".into());
        assert_eq!(app.current_step, WizardStep::Deployment);
        app.advance();
        assert_eq!(app.current_step, WizardStep::KeyStorage);
        assert!(app.completed_steps().contains(&WizardStep::Deployment));
    }

    #[test]
    fn advance_sets_text_input_for_database_and_output() {
        let mut app = WizardApp::new("test.toml".into());
        while app.current_step != WizardStep::Admin {
            app.advance();
        }
        // Admin → Output (new text-input step for config path)
        app.advance();
        assert_eq!(app.current_step, WizardStep::Output);
        assert_eq!(app.mode, InputMode::TextInput);
        // Output → Summary (confirmation screen)
        app.advance();
        assert_eq!(app.current_step, WizardStep::Summary);
        assert_eq!(app.mode, InputMode::Confirming);
    }

    #[test]
    fn go_back_from_first_step_quits() {
        let mut app = WizardApp::new("test.toml".into());
        app.go_back();
        assert!(app.should_quit);
    }

    #[test]
    fn go_back_returns_to_previous_step() {
        let mut app = WizardApp::new("test.toml".into());
        app.advance(); // Deployment → KeyStorage
        app.advance(); // KeyStorage → Vta
        app.advance(); // Vta → Protocol
        assert_eq!(app.current_step, WizardStep::Protocol);
        app.go_back();
        assert_eq!(app.current_step, WizardStep::Vta);
    }

    #[test]
    fn go_back_from_summary_confirming_returns_to_output() {
        // Output now sits between Admin and Summary (config-path
        // prompt moved into the TUI), so Esc on the confirmation
        // screen lands there rather than at Admin.
        let mut app = WizardApp::new("test.toml".into());
        while app.current_step != WizardStep::Summary {
            app.advance();
        }
        assert_eq!(app.mode, InputMode::Confirming);
        app.go_back();
        assert_eq!(app.current_step, WizardStep::Output);
        assert_eq!(app.mode, InputMode::TextInput);
    }

    #[test]
    fn paste_text_inserts_at_cursor_in_text_input_mode() {
        let mut app = WizardApp::new("test.toml".into());
        app.mode = InputMode::TextInput;
        app.text_input = tui_input::Input::new("did:webvh:".into());
        // Place cursor at end.
        app.text_input = tui_input::Input::new("did:webvh:".into()).with_cursor(10);
        app.paste_text("vta.example.com");
        assert_eq!(app.text_input.value(), "did:webvh:vta.example.com");
        assert_eq!(app.text_input.cursor(), 25);
    }

    #[test]
    fn paste_text_strips_newlines_and_tabs() {
        let mut app = WizardApp::new("test.toml".into());
        app.mode = InputMode::TextInput;
        app.text_input = tui_input::Input::new(String::new());
        app.paste_text("did:webvh:vta.example.com\n");
        assert_eq!(app.text_input.value(), "did:webvh:vta.example.com");

        app.text_input = tui_input::Input::new(String::new());
        app.paste_text("did:web\tvh:\r\nexample.com");
        assert_eq!(app.text_input.value(), "did:webvh:example.com");
    }

    #[test]
    fn paste_text_preserves_newlines_on_awaiting_bundle() {
        // Sealed-handoff armor requires newlines between its BEGIN/END
        // markers; the default single-line-collapse behaviour would
        // break `armor::decode`. Must preserve \n and \r when the
        // sealed-handoff state is on AwaitingBundle.
        use crate::sealed_handoff::{SealedHandoffState, SealedPhase};
        use crate::vta_connect::VtaIntent;
        let mut app = WizardApp::new("test.toml".into());
        app.mode = InputMode::TextInput;
        let mut state = SealedHandoffState::new(VtaIntent::FullSetup, None);
        state.phase = SealedPhase::AwaitingBundle;
        app.sealed_handoff = Some(state);
        app.text_input = tui_input::Input::new(String::new());
        app.paste_text(
            "-----BEGIN VTA SEALED BUNDLE-----\nBundle-Id: abc\n-----END VTA SEALED BUNDLE-----\n",
        );
        assert!(app.text_input.value().contains('\n'));
        assert!(app.text_input.value().contains("-----BEGIN"));
        assert!(app.text_input.value().contains("-----END"));
    }

    #[test]
    fn paste_text_still_strips_newlines_outside_awaiting_bundle() {
        // Other sealed-handoff phases (CollectContext, CollectMediatorUrl,
        // etc.) are single-line prompts — paste must still collapse.
        use crate::sealed_handoff::{SealedHandoffState, SealedPhase};
        use crate::vta_connect::VtaIntent;
        let mut app = WizardApp::new("test.toml".into());
        app.mode = InputMode::TextInput;
        let mut state = SealedHandoffState::new(VtaIntent::FullSetup, None);
        state.phase = SealedPhase::CollectContext;
        app.sealed_handoff = Some(state);
        app.text_input = tui_input::Input::new(String::new());
        app.paste_text("mediator-local\nextra");
        assert_eq!(app.text_input.value(), "mediator-localextra");
    }

    #[test]
    fn paste_text_ignored_outside_text_input_mode() {
        let mut app = WizardApp::new("test.toml".into());
        app.mode = InputMode::Selecting;
        app.paste_text("did:webvh:vta.example.com");
        assert_eq!(app.text_input.value(), "");
    }

    #[test]
    fn move_up_down_bounds() {
        let mut app = WizardApp::new("test.toml".into());
        app.selection_index = 0;
        app.move_up();
        assert_eq!(app.selection_index, 0); // stays at 0

        let max = app.current_options().len() - 1;
        app.selection_index = max;
        app.move_down();
        assert_eq!(app.selection_index, max); // stays at max
    }

    #[test]
    fn protocol_toggle_prevents_deselecting_both() {
        let mut app = WizardApp::new("test.toml".into());
        app.config.deployment_type = DEPLOYMENT_LOCAL.into();
        advance_to(&mut app, WizardStep::Protocol);
        assert!(app.current_step.is_multi_select());

        // DIDComm is selected by default
        assert!(app.config.didcomm_enabled);
        assert!(!app.config.tsp_enabled);

        // Space toggles the highlighted option — try to turn DIDComm off when
        // it's the only one enabled. The state machine must revert so at
        // least one protocol stays selected.
        app.selection_index = 0;
        app.toggle_current_multi_select();
        assert!(
            app.config.didcomm_enabled,
            "DIDComm must stay on when it's the only protocol enabled"
        );
    }

    #[test]
    fn protocol_multi_select_space_toggle_plus_enter_advance() {
        let mut app = WizardApp::new("test.toml".into());
        app.config.deployment_type = DEPLOYMENT_LOCAL.into();
        advance_to(&mut app, WizardStep::Protocol);

        // Turn on TSP alongside DIDComm via Space.
        app.selection_index = 1;
        app.toggle_current_multi_select();
        assert!(app.config.didcomm_enabled);
        assert!(app.config.tsp_enabled);

        // Enter advances — no more "Continue >" pseudo-row.
        app.select_current();
        assert_eq!(app.current_step, WizardStep::Did);
    }

    #[test]
    fn protocol_options_are_two_checkboxes_no_continue_row() {
        let mut app = WizardApp::new("test.toml".into());
        app.current_step = WizardStep::Protocol;
        let opts = app.current_options();
        assert_eq!(
            opts.len(),
            2,
            "Protocol step should only list the two protocol toggles"
        );
    }

    #[test]
    fn deployment_defaults_set_correctly() {
        let mut app = WizardApp::new("test.toml".into());

        // Select "Local development"
        app.selection_index = 0;
        app.select_current();

        assert_eq!(app.config.deployment_type, DEPLOYMENT_LOCAL);
        assert!(app.config.use_vta);
        assert!(app.config.didcomm_enabled);
        assert_eq!(app.config.ssl_mode, SSL_NONE);
        assert_eq!(app.config.database_url, DEFAULT_REDIS_URL);
    }

    #[test]
    fn summary_enter_sets_write_config() {
        let mut app = WizardApp::new("test.toml".into());
        while app.current_step != WizardStep::Summary {
            app.advance();
        }
        assert_eq!(app.mode, InputMode::Confirming);
        app.select_current();
        assert!(app.write_config);
        assert!(app.should_quit);
    }

    #[test]
    fn focus_progress_syncs_index() {
        let mut app = WizardApp::new("test.toml".into());
        app.advance(); // → KeyStorage
        app.advance(); // → Vta
        app.advance(); // → Protocol
        app.advance(); // → Did
        app.focus_progress();
        assert_eq!(app.focus, FocusPanel::Progress);
        assert_eq!(app.progress_index, WizardStep::Did.index());
    }

    #[test]
    fn focus_progress_blocked_during_text_input() {
        let mut app = WizardApp::new("test.toml".into());
        app.mode = InputMode::TextInput;
        app.focus_progress();
        assert_eq!(app.focus, FocusPanel::Content); // didn't switch
    }

    #[test]
    fn jump_to_completed_step() {
        let mut app = WizardApp::new("test.toml".into());
        app.advance(); // → KeyStorage
        app.advance(); // → Vta
        app.advance(); // → Protocol
        app.advance(); // → Did
        app.focus_progress();
        app.progress_index = 0; // Deployment
        app.jump_to_progress_step();
        assert_eq!(app.current_step, WizardStep::Deployment);
    }

    #[test]
    fn jump_to_incomplete_step_does_nothing() {
        let mut app = WizardApp::new("test.toml".into());
        app.advance(); // → KeyStorage
        app.focus_progress();
        app.progress_index = WizardStep::Database.index();
        let before = app.current_step;
        app.jump_to_progress_step();
        assert_eq!(app.current_step, before); // unchanged
    }

    // ── KeyStorage sub-flow tests ─────────────────────────────────────

    #[test]
    fn keystorage_file_backend_walks_gate_then_path_then_encrypt_choice() {
        // Phase H added an encrypt/no-encrypt step after the path
        // prompt. The wizard no longer auto-advances to Vta after
        // confirming the path — the operator must answer the
        // encryption question first.
        let mut app = WizardApp::new("test.toml".into());
        app.current_step = WizardStep::KeyStorage;
        // "Local file (file://)" lives at index 5 after vta:// and
        // string:// were dropped from the selection list.
        app.selection_index = 5;
        app.select_current();
        assert_eq!(app.config.secret_storage, STORAGE_FILE);
        assert_eq!(app.key_storage_phase, Some(KeyStoragePhase::FileGate));
        assert_eq!(app.mode, InputMode::TextInput);

        // Type the gate phrase (case-insensitive) — advances to FilePath.
        app.text_input = Input::new(FILE_GATE_PHRASE.to_lowercase());
        app.confirm_text_input();
        assert_eq!(app.key_storage_phase, Some(KeyStoragePhase::FilePath));

        // Accept the default path — moves into the encrypt choice.
        app.confirm_text_input();
        assert_eq!(app.config.secret_file_path, DEFAULT_SECRET_FILE_PATH);
        assert_eq!(
            app.key_storage_phase,
            Some(KeyStoragePhase::FileEncryptChoice)
        );
        assert_eq!(app.mode, InputMode::Selecting);

        // Pick "no encryption" (index 1) — finishes the sub-flow.
        app.selection_index = 1;
        app.select_current();
        assert!(!app.in_key_storage_subflow());
        assert!(!app.config.secret_file_encrypted);
        assert_eq!(app.current_step, WizardStep::Vta);
    }

    #[test]
    fn keystorage_file_backend_encrypt_yes_collects_passphrase() {
        // Picking "encrypt" advances to the passphrase prompt, which
        // rejects empty input and exports the value via env on confirm.
        let mut app = WizardApp::new("test.toml".into());
        app.current_step = WizardStep::KeyStorage;
        app.selection_index = 5; // file://
        app.select_current();
        // Walk through the gate + path with defaults.
        app.text_input = Input::new(FILE_GATE_PHRASE.into());
        app.confirm_text_input();
        app.confirm_text_input(); // accept default path
        assert_eq!(
            app.key_storage_phase,
            Some(KeyStoragePhase::FileEncryptChoice)
        );

        // Encrypt = yes (index 0).
        app.selection_index = 0;
        app.select_current();
        assert_eq!(app.key_storage_phase, Some(KeyStoragePhase::FilePassphrase));
        assert_eq!(app.mode, InputMode::TextInput);

        // Empty passphrase is rejected — phase doesn't change.
        app.text_input = Input::new(String::new());
        app.confirm_text_input();
        assert_eq!(
            app.key_storage_phase,
            Some(KeyStoragePhase::FilePassphrase),
            "empty passphrase must be rejected (Argon2id with no input is trivial)"
        );

        // Real passphrase exits the sub-flow + flips secret_file_encrypted.
        app.text_input = Input::new("correct horse battery staple".into());
        app.confirm_text_input();
        assert!(!app.in_key_storage_subflow());
        assert!(app.config.secret_file_encrypted);
        assert_eq!(app.current_step, WizardStep::Vta);

        // The wizard exports the env var so generate_and_write can open
        // the encrypted backend on first put. Read it back to confirm,
        // then clean up so we don't pollute neighbour tests.
        let key = affinidi_messaging_mediator_common::PASSPHRASE_ENV;
        assert_eq!(
            std::env::var(key).ok().as_deref(),
            Some("correct horse battery staple"),
        );
        unsafe {
            std::env::remove_var(key);
        }
    }

    #[test]
    fn keystorage_file_backend_gate_rejection_clears_choice() {
        // Anything other than the gate phrase aborts the file:// choice
        // entirely — the operator is dropped back on the scheme list
        // with `secret_storage` cleared so they have to re-pick.
        let mut app = WizardApp::new("test.toml".into());
        app.current_step = WizardStep::KeyStorage;
        app.selection_index = 5; // file://
        app.select_current();
        assert_eq!(app.key_storage_phase, Some(KeyStoragePhase::FileGate));

        app.text_input = Input::new("yes".into());
        app.confirm_text_input();

        assert!(app.config.secret_storage.is_empty());
        assert!(!app.in_key_storage_subflow());
        assert_eq!(app.current_step, WizardStep::KeyStorage);
    }

    #[test]
    fn keystorage_file_backend_gate_back_returns_to_scheme_list() {
        // Esc on the gate must rewind to the scheme list rather than
        // the (skipped) FilePath phase, otherwise the operator can't
        // back out without typing the phrase.
        let mut app = WizardApp::new("test.toml".into());
        app.current_step = WizardStep::KeyStorage;
        app.selection_index = 5; // file://
        app.select_current();
        assert_eq!(app.key_storage_phase, Some(KeyStoragePhase::FileGate));

        app.go_back();
        assert!(!app.in_key_storage_subflow());
        assert_eq!(app.current_step, WizardStep::KeyStorage);
    }

    #[test]
    fn keystorage_keyring_backend_prompts_for_service() {
        let mut app = WizardApp::new("test.toml".into());
        app.current_step = WizardStep::KeyStorage;
        app.selection_index = 0; // Keyring (now first in the list)
        app.select_current();
        assert_eq!(app.key_storage_phase, Some(KeyStoragePhase::KeyringService));

        app.text_input = Input::new("affinidi-prod-mediator".into());
        app.confirm_text_input();
        assert_eq!(app.config.secret_keyring_service, "affinidi-prod-mediator");
        assert_eq!(app.current_step, WizardStep::Vta);
    }

    #[test]
    fn keystorage_aws_backend_walks_region_then_prefix() {
        let mut app = WizardApp::new("test.toml".into());
        app.current_step = WizardStep::KeyStorage;
        app.selection_index = 1; // AWS (renumbered: vta:// removed)
        app.select_current();
        assert_eq!(app.key_storage_phase, Some(KeyStoragePhase::AwsRegion));

        app.text_input = Input::new("eu-west-2".into());
        app.confirm_text_input();
        assert_eq!(app.config.secret_aws_region, "eu-west-2");
        assert_eq!(app.key_storage_phase, Some(KeyStoragePhase::AwsPrefix));

        app.text_input = Input::new("prod/mediator/".into());
        app.confirm_text_input();
        assert_eq!(app.config.secret_aws_prefix, "prod/mediator/");
        assert!(!app.in_key_storage_subflow());
        assert_eq!(app.current_step, WizardStep::Vta);
    }

    #[test]
    fn keystorage_gcp_enters_project_then_prefix_subflow() {
        // GCP backend has two text-input phases: project then prefix.
        // The project field is required (no sensible default — GCP
        // project IDs are tenant-scoped); empty input on that screen
        // is rejected and the operator stays on the prompt.
        let mut app = WizardApp::new("test.toml".into());
        app.current_step = WizardStep::KeyStorage;
        app.selection_index = 2; // GCP
        app.select_current();
        assert_eq!(app.config.secret_storage, STORAGE_GCP);
        assert_eq!(app.key_storage_phase, Some(KeyStoragePhase::GcpProject));

        app.text_input = Input::new("my-prod-project".into());
        app.confirm_text_input();
        assert_eq!(app.config.secret_gcp_project, "my-prod-project");
        assert_eq!(app.key_storage_phase, Some(KeyStoragePhase::GcpPrefix));

        app.text_input = Input::new("mediator-".into());
        app.confirm_text_input();
        assert_eq!(app.config.secret_gcp_prefix, "mediator-");
        assert!(!app.in_key_storage_subflow());
        assert_eq!(app.current_step, WizardStep::Vta);
    }

    #[test]
    fn keystorage_azure_enters_single_vault_subflow() {
        // Azure has one text-input phase: the vault name (or full URL).
        // Empty input is rejected — there's no sensible default that
        // covers both commercial and sovereign clouds.
        let mut app = WizardApp::new("test.toml".into());
        app.current_step = WizardStep::KeyStorage;
        app.selection_index = 3; // Azure
        app.select_current();
        assert_eq!(app.config.secret_storage, STORAGE_AZURE);
        assert_eq!(app.key_storage_phase, Some(KeyStoragePhase::AzureVault));

        app.text_input = Input::new("my-vault".into());
        app.confirm_text_input();
        assert_eq!(app.config.secret_azure_vault, "my-vault");
        assert!(!app.in_key_storage_subflow());
        assert_eq!(app.current_step, WizardStep::Vta);
    }

    #[test]
    fn keystorage_vault_enters_endpoint_then_mount_subflow() {
        // HashiCorp Vault has two phases: endpoint then mount + prefix.
        // The endpoint field is required (deployment-specific); the
        // mount has a default (`secret/mediator`) so empty input on
        // the mount screen keeps the default.
        let mut app = WizardApp::new("test.toml".into());
        app.current_step = WizardStep::KeyStorage;
        app.selection_index = 4; // Vault
        app.select_current();
        assert_eq!(app.config.secret_storage, STORAGE_VAULT);
        assert_eq!(app.key_storage_phase, Some(KeyStoragePhase::VaultEndpoint));

        app.text_input = Input::new("vault.internal:8200".into());
        app.confirm_text_input();
        assert_eq!(app.config.secret_vault_endpoint, "vault.internal:8200");
        assert_eq!(app.key_storage_phase, Some(KeyStoragePhase::VaultMount));

        app.text_input = Input::new("kv/prod-mediator".into());
        app.confirm_text_input();
        assert_eq!(app.config.secret_vault_mount, "kv/prod-mediator");
        assert!(!app.in_key_storage_subflow());
        assert_eq!(app.current_step, WizardStep::Vta);
    }

    // ── Discovery overlay (F5) state-machine tests ───────────────────

    #[test]
    fn discovery_request_for_aws_prefix_requires_region() {
        // F5 on AwsPrefix without a region is a no-op (returns None);
        // once the region is set, the request carries it through.
        let mut app = WizardApp::new("test.toml".into());
        app.key_storage_phase = Some(KeyStoragePhase::AwsPrefix);
        app.config.secret_aws_region = String::new();
        assert!(app.discovery_request_for_phase().is_none());
        app.config.secret_aws_region = "eu-west-2".into();
        match app.discovery_request_for_phase() {
            Some(crate::discovery::DiscoveryRequest::Aws { region }) => {
                assert_eq!(region, "eu-west-2");
            }
            other => panic!("expected Aws request, got {other:?}"),
        }
    }

    #[test]
    fn discovery_request_for_azure_uses_current_text_input() {
        // Azure's vault is the field the operator is editing — the
        // request reads from `text_input`, not from the saved config
        // field, so F5 verifies what's typed *now* rather than the
        // last confirmed value.
        let mut app = WizardApp::new("test.toml".into());
        app.key_storage_phase = Some(KeyStoragePhase::AzureVault);
        app.text_input = Input::new("partial-vault-name".into());
        match app.discovery_request_for_phase() {
            Some(crate::discovery::DiscoveryRequest::Azure { vault }) => {
                assert_eq!(vault, "partial-vault-name");
            }
            other => panic!("expected Azure request, got {other:?}"),
        }
    }

    #[test]
    fn discovery_request_for_vault_mount_falls_back_to_default() {
        // F5 with empty mount input falls back to the wizard default
        // so the operator can hit it on a fresh entry to see what's
        // already at `secret/mediator`.
        let mut app = WizardApp::new("test.toml".into());
        app.key_storage_phase = Some(KeyStoragePhase::VaultMount);
        app.config.secret_vault_endpoint = "vault.internal:8200".into();
        app.text_input = Input::new(String::new());
        match app.discovery_request_for_phase() {
            Some(crate::discovery::DiscoveryRequest::Vault { endpoint, mount }) => {
                assert_eq!(endpoint, "vault.internal:8200");
                assert_eq!(mount, DEFAULT_VAULT_MOUNT);
            }
            other => panic!("expected Vault request, got {other:?}"),
        }
    }

    #[test]
    fn discovery_request_none_for_non_discoverable_phases() {
        // Region / project / endpoint screens are upstream of the
        // discoverable namespace — F5 is a no-op there. Same for the
        // file:// / keyring sub-flow.
        let mut app = WizardApp::new("test.toml".into());
        for phase in [
            KeyStoragePhase::AwsRegion,
            KeyStoragePhase::GcpProject,
            KeyStoragePhase::VaultEndpoint,
            KeyStoragePhase::FilePath,
            KeyStoragePhase::KeyringService,
        ] {
            app.key_storage_phase = Some(phase);
            assert!(
                app.discovery_request_for_phase().is_none(),
                "expected no discovery request for {phase:?}"
            );
        }
    }

    #[test]
    fn handle_discovery_key_navigates_loaded_list() {
        use crate::discovery::{DiscoveryMode, DiscoveryState};
        use crossterm::event::KeyCode;
        let mut app = WizardApp::new("test.toml".into());
        app.discovery = Some(DiscoveryState::Loaded {
            mode: DiscoveryMode::Pick,
            items: vec!["a/".into(), "b/".into(), "c/".into()],
            total: 6,
            cursor: 0,
            scroll: 0,
        });
        // Down moves cursor to 1, then End jumps to last.
        assert!(app.handle_discovery_key(KeyCode::Down));
        match &app.discovery {
            Some(DiscoveryState::Loaded { cursor, .. }) => assert_eq!(*cursor, 1),
            _ => panic!("expected Loaded state with cursor=1"),
        }
        assert!(app.handle_discovery_key(KeyCode::End));
        match &app.discovery {
            Some(DiscoveryState::Loaded { cursor, .. }) => assert_eq!(*cursor, 2),
            _ => panic!("expected Loaded state with cursor=2"),
        }
        // Home returns to top.
        assert!(app.handle_discovery_key(KeyCode::Home));
        match &app.discovery {
            Some(DiscoveryState::Loaded { cursor, .. }) => assert_eq!(*cursor, 0),
            _ => panic!("expected Loaded state with cursor=0"),
        }
    }

    #[test]
    fn handle_discovery_key_pick_applies_selection_and_dismisses() {
        use crate::discovery::{DiscoveryMode, DiscoveryState};
        use crossterm::event::KeyCode;
        let mut app = WizardApp::new("test.toml".into());
        app.discovery = Some(DiscoveryState::Loaded {
            mode: DiscoveryMode::Pick,
            items: vec!["alpha/".into(), "beta/".into()],
            total: 4,
            cursor: 1,
            scroll: 0,
        });
        assert!(app.handle_discovery_key(KeyCode::Enter));
        // Pick mode wrote the selection into the text input.
        assert_eq!(app.text_input.value(), "beta/");
        // …and dismissed the overlay.
        assert!(app.discovery.is_none());
    }

    #[test]
    fn handle_discovery_key_confirm_dismisses_without_pick() {
        use crate::discovery::{DiscoveryMode, DiscoveryState};
        use crossterm::event::KeyCode;
        let mut app = WizardApp::new("test.toml".into());
        // Operator was editing the AzureVault field — that's the
        // current text_input value. Confirm mode must NOT overwrite it
        // with a discovered secret name.
        app.text_input = Input::new("operator-typed-vault".into());
        app.discovery = Some(DiscoveryState::Loaded {
            mode: DiscoveryMode::Confirm,
            items: vec!["existing-secret".into()],
            total: 1,
            cursor: 0,
            scroll: 0,
        });
        assert!(app.handle_discovery_key(KeyCode::Enter));
        assert_eq!(app.text_input.value(), "operator-typed-vault");
        assert!(app.discovery.is_none());
    }

    #[test]
    fn handle_discovery_key_failed_dismisses_on_any_key() {
        use crate::discovery::DiscoveryState;
        use crossterm::event::KeyCode;
        let mut app = WizardApp::new("test.toml".into());
        app.discovery = Some(DiscoveryState::Failed {
            message: "credentials missing".into(),
        });
        // Any key dismisses — pick something arbitrary.
        assert!(app.handle_discovery_key(KeyCode::Char('x')));
        assert!(app.discovery.is_none());
    }

    #[test]
    fn handle_discovery_key_loading_only_dismisses_on_esc() {
        use crate::discovery::DiscoveryState;
        use crossterm::event::KeyCode;
        let mut app = WizardApp::new("test.toml".into());
        app.discovery = Some(DiscoveryState::Loading);
        // Random key swallowed — wizard stays in Loading.
        assert!(app.handle_discovery_key(KeyCode::Char('x')));
        assert!(matches!(app.discovery, Some(DiscoveryState::Loading)));
        // Esc cancels.
        assert!(app.handle_discovery_key(KeyCode::Esc));
        assert!(app.discovery.is_none());
    }

    // ── Security JWT sub-phase tests ─────────────────────────────────

    #[test]
    fn security_ssl_none_then_jwt_generate_advances() {
        // SSL "None" + JWT "generate" — the common dev path. Should
        // walk through both phases and land on Database.
        let mut app = WizardApp::new("test.toml".into());
        app.current_step = WizardStep::Security;
        app.selection_index = 0; // No SSL
        app.select_current();
        // SSL is now settled; we're in the JWT sub-phase.
        assert_eq!(app.security_phase, Some(SecurityPhase::JwtMode));
        assert_eq!(app.current_step, WizardStep::Security);

        // Default selection is "generate" (index 0).
        app.select_current();
        assert_eq!(app.config.jwt_mode, JWT_MODE_GENERATE);
        assert!(app.security_phase.is_none());
        assert_eq!(app.current_step, WizardStep::Database);
    }

    #[test]
    fn security_ssl_none_then_jwt_provide_records_choice() {
        let mut app = WizardApp::new("test.toml".into());
        app.current_step = WizardStep::Security;
        app.selection_index = 0; // No SSL
        app.select_current();
        assert_eq!(app.security_phase, Some(SecurityPhase::JwtMode));

        app.selection_index = 1; // Provide
        app.select_current();
        assert_eq!(app.config.jwt_mode, JWT_MODE_PROVIDE);
        assert_eq!(app.current_step, WizardStep::Database);
    }

    #[test]
    fn security_ssl_existing_collects_paths_then_jwt_phase() {
        // Existing-cert path runs two text-input prompts before the JWT
        // selection appears.
        let mut app = WizardApp::new("test.toml".into());
        app.current_step = WizardStep::Security;
        app.selection_index = 1; // Existing certs
        app.select_current();
        // Now in TextInput mode collecting the cert path.
        assert_eq!(app.mode, InputMode::TextInput);
        app.text_input = Input::new("/etc/ssl/cert.pem".into());
        app.confirm_text_input();
        // Still TextInput, now collecting key path.
        assert_eq!(app.mode, InputMode::TextInput);
        app.text_input = Input::new("/etc/ssl/key.pem".into());
        app.confirm_text_input();
        // Both paths saved; JWT phase active.
        assert_eq!(app.config.ssl_cert_path, "/etc/ssl/cert.pem");
        assert_eq!(app.config.ssl_key_path, "/etc/ssl/key.pem");
        assert_eq!(app.security_phase, Some(SecurityPhase::JwtMode));
        assert_eq!(app.current_step, WizardStep::Security);
    }

    #[test]
    fn keystorage_back_rewinds_aws_second_phase() {
        let mut app = WizardApp::new("test.toml".into());
        app.current_step = WizardStep::KeyStorage;
        app.selection_index = 1; // AWS
        app.select_current();
        app.confirm_text_input(); // AwsRegion → AwsPrefix
        assert_eq!(app.key_storage_phase, Some(KeyStoragePhase::AwsPrefix));

        app.go_back();
        assert_eq!(app.key_storage_phase, Some(KeyStoragePhase::AwsRegion));

        app.go_back();
        assert!(!app.in_key_storage_subflow());
    }

    // ── VTA integration tests ─────────────────────────────────────────

    /// Advance the wizard to a specific step. Used by the VTA tests so the
    /// intermediate step ordering (KeyStorage now sits between Deployment
    /// and Vta) doesn't require every test to hardcode a fresh count.
    fn advance_to(app: &mut WizardApp, target: WizardStep) {
        let mut guard = 0;
        while app.current_step != target {
            assert!(guard < 20, "advance_to did not reach {target:?}");
            app.advance();
            guard += 1;
        }
    }

    /// Walk the two-question Vta picker: pick "Full setup" (intent) then
    /// "Online" (transport). After this call the wizard is inside the
    /// online-VTA sub-flow at `ConnectPhase::EnterDid`.
    fn pick_full_setup_online(app: &mut WizardApp) {
        app.selection_index = 0;
        app.select_current(); // SelectIntent → FullSetup
        app.selection_index = 0;
        app.select_current(); // SelectTransport → Online (enters sub-flow)
    }

    /// Walk the two-question Vta picker: pick "Admin credential only"
    /// (intent) then "Sealed handoff" (transport). After this call the
    /// wizard is inside the sealed-handoff sub-flow.
    fn pick_admin_only_sealed(app: &mut WizardApp) {
        app.selection_index = 1;
        app.select_current(); // SelectIntent → AdminOnly
        app.selection_index = 1;
        app.select_current(); // SelectTransport → Offline (enters sub-flow)
    }

    #[test]
    fn vta_yes_then_online_enters_subflow() {
        let mut app = WizardApp::new("test.toml".into());
        advance_to(&mut app, WizardStep::Vta);
        assert_eq!(app.current_step, WizardStep::Vta);

        // Two-question picker: "Full setup" then "Online".
        pick_full_setup_online(&mut app);

        // Online picks the DID/context-entry sub-flow — the wizard stays on
        // the Vta step until the connection is tested in a later phase.
        assert_eq!(app.current_step, WizardStep::Vta);
        assert!(app.in_vta_subflow(), "should have entered VTA sub-flow");
        assert_eq!(app.vta_phase(), Some(&ConnectPhase::EnterDid));
        assert_eq!(app.mode, InputMode::TextInput);
        assert!(app.config.use_vta);
        assert_eq!(app.config.vta_mode, VTA_MODE_ONLINE);
        assert_eq!(app.config.did_method, DID_VTA);
        // `secret_storage` is owned by the earlier KeyStorage step — the Vta
        // step deliberately doesn't override whatever was chosen there.
        assert_eq!(app.config.admin_did_mode, ADMIN_VTA);
    }

    #[test]
    fn vta_subflow_collects_did_then_context_then_instructions() {
        let mut app = WizardApp::new("test.toml".into());
        advance_to(&mut app, WizardStep::Vta);
        pick_full_setup_online(&mut app); // enter sub-flow at EnterDid

        // Enter the VTA DID.
        app.text_input = tui_input::Input::new("did:webvh:vta.example.com".into());
        app.confirm_text_input();
        assert_eq!(app.vta_phase(), Some(&ConnectPhase::EnterContext));
        assert_eq!(
            app.vta_connect.as_ref().unwrap().vta_did,
            "did:webvh:vta.example.com"
        );

        // Accept the default context id ("mediator" is pre-filled).
        app.confirm_text_input();
        assert_eq!(app.vta_phase(), Some(&ConnectPhase::EnterMediatorUrl));

        // Enter the mediator URL — the new phase added for
        // provision-integration (template `URL` variable).
        app.text_input = tui_input::Input::new("https://mediator.example.com".into());
        app.confirm_text_input();
        assert_eq!(app.vta_phase(), Some(&ConnectPhase::AwaitingAcl));
        assert_eq!(app.mode, InputMode::Selecting);
        let st = app.vta_connect.as_ref().unwrap();
        assert!(st.setup_key.is_some(), "ephemeral setup key generated");
        assert_eq!(st.mediator_url, "https://mediator.example.com");
        let acl = st.acl_command().unwrap();
        assert!(acl.starts_with("pnm contexts create"));
        assert!(acl.contains("--id mediator"));
        assert!(acl.contains("--admin-did did:key:z6Mk"));
        assert!(acl.contains("--admin-expires 1h"));
    }

    #[test]
    fn vta_subflow_back_rewinds_phases() {
        let mut app = WizardApp::new("test.toml".into());
        advance_to(&mut app, WizardStep::Vta);
        pick_full_setup_online(&mut app); // EnterDid

        app.text_input = tui_input::Input::new("did:webvh:vta.example.com".into());
        app.confirm_text_input(); // → EnterContext
        app.confirm_text_input(); // → EnterMediatorUrl
        app.text_input = tui_input::Input::new("https://mediator.example.com".into());
        app.confirm_text_input(); // → AwaitingAcl
        assert_eq!(app.vta_phase(), Some(&ConnectPhase::AwaitingAcl));

        app.go_back(); // → EnterMediatorUrl
        assert_eq!(app.vta_phase(), Some(&ConnectPhase::EnterMediatorUrl));

        app.go_back(); // → EnterContext
        assert_eq!(app.vta_phase(), Some(&ConnectPhase::EnterContext));

        app.go_back(); // → EnterDid
        assert_eq!(app.vta_phase(), Some(&ConnectPhase::EnterDid));

        app.go_back(); // → exits sub-flow back to selection
        assert!(!app.in_vta_subflow());
        assert_eq!(app.current_step, WizardStep::Vta);
    }

    #[tokio::test]
    async fn vta_subflow_awaiting_acl_enter_starts_testing() {
        // Pressing Enter on the AwaitingAcl instructions kicks off the
        // provision-integration runner. The test exits before the runner
        // actually contacts any network — we only verify the phase
        // transition and that the channel + diagnostics list are seeded.
        let mut app = WizardApp::new("test.toml".into());
        advance_to(&mut app, WizardStep::Vta);
        pick_full_setup_online(&mut app);
        app.text_input = tui_input::Input::new("did:webvh:vta.example.com".into());
        app.confirm_text_input();
        app.confirm_text_input();
        app.text_input = tui_input::Input::new("https://mediator.example.com".into());
        app.confirm_text_input();
        assert_eq!(app.vta_phase(), Some(&ConnectPhase::AwaitingAcl));

        app.select_current();
        assert_eq!(app.vta_phase(), Some(&ConnectPhase::Testing));
        let st = app.vta_connect.as_ref().unwrap();
        assert!(st.event_rx.is_some(), "runner channel should be open");
        assert_eq!(
            st.diagnostics.len(),
            crate::vta_connect::DiagCheck::all().len()
        );
    }

    #[tokio::test]
    async fn vta_subflow_connected_enter_advances_past_vta_step() {
        use crate::vta_connect::{DiagStatus, VtaEvent, diagnostics::Protocol};

        let mut app = WizardApp::new("test.toml".into());
        advance_to(&mut app, WizardStep::Vta);
        pick_full_setup_online(&mut app);
        app.text_input = tui_input::Input::new("did:webvh:vta.example.com".into());
        app.confirm_text_input();
        app.confirm_text_input();
        app.text_input = tui_input::Input::new("https://mediator.example.com".into());
        app.confirm_text_input();
        app.select_current(); // → Testing

        // Inject a synthetic success event (bypass the real network runner).
        let st = app.vta_connect.as_mut().unwrap();
        st.event_rx = None; // pretend the runner completed
        st.apply_event(VtaEvent::CheckDone(
            crate::vta_connect::DiagCheck::Authenticate,
            DiagStatus::Ok("ok".into()),
        ));
        st.apply_event(VtaEvent::Connected {
            protocol: Protocol::DidComm,
            rest_url: Some("https://vta.example.com".into()),
            mediator_did: Some("did:webvh:mediator.vta.example.com".into()),
            reply: crate::vta_connect::VtaReply::Full(
                crate::vta_connect::provision::test_sample_result(true),
            ),
        });
        assert_eq!(app.vta_phase(), Some(&ConnectPhase::Connected));

        app.select_current();
        assert_eq!(app.current_step, WizardStep::Protocol);
        assert!(!app.in_vta_subflow());
    }

    #[tokio::test]
    async fn vta_subflow_testing_failure_allows_retry() {
        use crate::vta_connect::VtaEvent;

        let mut app = WizardApp::new("test.toml".into());
        advance_to(&mut app, WizardStep::Vta);
        pick_full_setup_online(&mut app);
        app.text_input = tui_input::Input::new("did:webvh:vta.example.com".into());
        app.confirm_text_input();
        app.confirm_text_input();
        app.text_input = tui_input::Input::new("https://mediator.example.com".into());
        app.confirm_text_input();
        app.select_current(); // → Testing

        // Simulate runner failure.
        let st = app.vta_connect.as_mut().unwrap();
        st.event_rx = None;
        st.apply_event(VtaEvent::Failed("ACL not found".into()));
        assert_eq!(app.vta_phase(), Some(&ConnectPhase::Testing));
        assert!(app.vta_connect.as_ref().unwrap().last_error.is_some());

        // The Retry option should now be offered.
        let opts = app.current_options();
        assert_eq!(opts.len(), 1);
        assert_eq!(opts[0].label, "Retry");

        // Enter re-kicks the runner.
        app.select_current();
        let st = app.vta_connect.as_ref().unwrap();
        assert_eq!(st.phase, ConnectPhase::Testing);
        assert!(st.event_rx.is_some());
        assert!(st.last_error.is_none());
    }

    #[test]
    fn vta_sealed_handoff_sets_defaults_and_enters_subflow() {
        let mut app = WizardApp::new("test.toml".into());
        app.selection_index = 0;
        app.select_current(); // Deployment → KeyStorage
        advance_to(&mut app, WizardStep::Vta);

        // Two-question picker: "Admin credential only" then "Sealed
        // handoff". Selection captures the mode + enters the dedicated
        // sealed sub-flow rather than advancing the wizard. AdminOnly
        // does NOT force `did_method = VTA` — the operator picks their
        // own DID in the Did step; the VTA only issues an admin
        // credential.
        pick_admin_only_sealed(&mut app);
        assert_eq!(app.current_step, WizardStep::Vta);
        assert!(app.config.use_vta);
        assert_eq!(app.config.vta_mode, VTA_MODE_SEALED);
        assert_ne!(
            app.config.did_method, DID_VTA,
            "AdminOnly keeps operator's own DID choice (not forced to VTA)",
        );
        assert_eq!(app.config.admin_did_mode, ADMIN_VTA);
        assert!(app.in_sealed_handoff_subflow());
    }

    #[test]
    fn vta_no_clears_vta_options() {
        let mut app = WizardApp::new("test.toml".into());
        app.selection_index = 0;
        app.select_current(); // Deployment → KeyStorage (sets VTA defaults)
        advance_to(&mut app, WizardStep::Vta);
        assert_eq!(app.config.did_method, DID_VTA);

        // Select "No VTA" (index 3 — order: FullSetup, AdminOnly,
        // OfflineExport, No VTA).
        app.selection_index = 3;
        app.select_current();
        assert_eq!(app.current_step, WizardStep::Protocol);
        assert!(!app.config.use_vta);
        // apply_vta_defaults should have switched the DID method + admin
        // mode to non-VTA; `secret_storage` is now chosen in the earlier
        // KeyStorage step and intentionally not touched by Vta.
        assert_eq!(app.config.did_method, DID_PEER);
        assert!(app.config.vta_mode.is_empty());
    }

    #[test]
    fn did_options_exclude_vta_when_disabled() {
        let mut app = WizardApp::new("test.toml".into());
        app.config.use_vta = false;
        app.current_step = WizardStep::Did;
        let opts = app.current_options();
        assert_eq!(opts.len(), 3); // webvh, peer, import
    }

    #[test]
    fn did_options_include_vta_when_full_setup_intent_chosen() {
        // The "Configure via VTA" option only appears for the
        // FullSetup intent, signalled by `did_method == DID_VTA`
        // after `apply_vta_defaults` ran. AdminOnly keeps
        // `use_vta == true` but clears `did_method` so the operator
        // picks a local DID method.
        let mut app = WizardApp::new("test.toml".into());
        app.config.use_vta = true;
        app.config.did_method = DID_VTA.into();
        app.current_step = WizardStep::Did;
        let opts = app.current_options();
        assert_eq!(opts.len(), 4); // VTA, webvh, peer, import
    }

    #[test]
    fn did_options_hide_vta_when_admin_only_intent_chosen() {
        let mut app = WizardApp::new("test.toml".into());
        app.config.use_vta = true;
        app.config.did_method = DID_PEER.into();
        app.current_step = WizardStep::Did;
        let opts = app.current_options();
        // AdminOnly — operator picks their own DID method; the
        // "Configure via VTA" option is suppressed.
        assert_eq!(opts.len(), 3); // webvh, peer, import
    }

    #[test]
    fn vta_step_select_intent_has_four_options() {
        let mut app = WizardApp::new("test.toml".into());
        app.current_step = WizardStep::Vta;
        app.on_enter_step();
        assert_eq!(app.vta_step_phase, VtaStepPhase::SelectIntent);
        let opts = app.current_options();
        assert_eq!(opts.len(), 4); // FullSetup, AdminOnly, OfflineExport, No VTA
    }

    #[test]
    fn vta_intent_offline_export_skips_transport_phase() {
        // OfflineExport is always offline (no online transport for the
        // v1 sealed_transfer::BootstrapRequest shape) so picking it
        // routes straight into the sealed-handoff sub-flow without
        // ever entering SelectTransport.
        let mut app = WizardApp::new("test.toml".into());
        advance_to(&mut app, WizardStep::Vta);
        app.selection_index = 2; // OfflineExport
        app.select_current();
        assert_eq!(app.vta_intent_choice, Some(VtaIntent::OfflineExport));
        assert_eq!(app.config.vta_mode, VTA_MODE_EXPORT);
        assert!(app.config.use_vta);
        // SelectTransport is bypassed.
        assert_eq!(app.vta_step_phase, VtaStepPhase::SelectIntent);
        // Sealed-handoff sub-flow is now active with OfflineExport
        // intent — context_id is the only further input the operator
        // needs to provide.
        assert!(app.in_sealed_handoff_subflow());
        let st = app.sealed_handoff.as_ref().unwrap();
        assert_eq!(st.intent, VtaIntent::OfflineExport);
    }

    #[test]
    fn vta_step_select_transport_has_two_options_after_intent_pick() {
        let mut app = WizardApp::new("test.toml".into());
        advance_to(&mut app, WizardStep::Vta);
        // Pick "Full setup" — advances to transport sub-phase.
        app.selection_index = 0;
        app.select_current();
        assert_eq!(app.vta_step_phase, VtaStepPhase::SelectTransport);
        assert_eq!(app.vta_intent_choice, Some(VtaIntent::FullSetup));
        let opts = app.current_options();
        assert_eq!(opts.len(), 2); // Online, Sealed handoff
        assert!(opts[0].label.starts_with("Online"));
    }

    #[test]
    fn vta_step_go_back_from_transport_rewinds_to_intent() {
        let mut app = WizardApp::new("test.toml".into());
        advance_to(&mut app, WizardStep::Vta);
        app.selection_index = 0;
        app.select_current(); // FullSetup → SelectTransport
        assert_eq!(app.vta_step_phase, VtaStepPhase::SelectTransport);

        app.go_back();
        assert_eq!(app.vta_step_phase, VtaStepPhase::SelectIntent);
        assert!(app.vta_intent_choice.is_none());
        assert_eq!(app.current_step, WizardStep::Vta);
    }

    #[test]
    fn vta_full_setup_offline_enters_sealed_subflow_with_correct_intent() {
        // Slice 3: FullSetup + Offline is no longer a stub — it enters
        // the sealed sub-flow with `VtaIntent::FullSetup`, which
        // drives the VP-framed request + template-bootstrap reply
        // path. Operator lands on `CollectContext`.
        let mut app = WizardApp::new("test.toml".into());
        advance_to(&mut app, WizardStep::Vta);
        app.selection_index = 0;
        app.select_current(); // FullSetup
        app.selection_index = 1;
        app.select_current(); // Offline
        assert!(app.in_sealed_handoff_subflow());
        let state = app.sealed_handoff.as_ref().unwrap();
        assert_eq!(state.intent, VtaIntent::FullSetup);
        assert_eq!(
            state.phase,
            crate::sealed_handoff::SealedPhase::CollectContext
        );
        assert!(app.vta_stub_notice.is_none());
        assert_eq!(app.config.vta_mode, VTA_MODE_SEALED);
    }

    #[test]
    fn vta_admin_only_online_enters_vta_subflow_with_correct_intent() {
        // Slice 4: AdminOnly + Online is no longer a stub — it
        // enters the online VTA sub-flow with
        // `VtaIntent::AdminOnly`, which skips provision-integration
        // and keeps the setup DID as the long-term admin credential.
        let mut app = WizardApp::new("test.toml".into());
        advance_to(&mut app, WizardStep::Vta);
        app.selection_index = 1;
        app.select_current(); // AdminOnly
        app.selection_index = 0;
        app.select_current(); // Online
        assert!(app.in_vta_subflow());
        assert!(!app.in_sealed_handoff_subflow());
        assert!(app.vta_stub_notice.is_none());
        let st = app.vta_connect.as_ref().unwrap();
        assert_eq!(st.intent, VtaIntent::AdminOnly);
        assert_eq!(st.phase, ConnectPhase::EnterDid);
        assert_eq!(app.config.vta_mode, VTA_MODE_ONLINE);
    }

    #[test]
    fn vta_step_re_entry_resets_picker_phase() {
        let mut app = WizardApp::new("test.toml".into());
        advance_to(&mut app, WizardStep::Vta);
        app.selection_index = 0;
        app.select_current(); // FullSetup — now on SelectTransport

        // Jump back to Vta from somewhere else via go_back; the picker
        // should reset to SelectIntent so the operator can re-answer
        // cleanly instead of continuing with a stale intent pick.
        app.vta_step_phase = VtaStepPhase::SelectIntent; // belt-and-braces
        app.on_enter_step();
        assert_eq!(app.vta_step_phase, VtaStepPhase::SelectIntent);
        assert!(app.vta_intent_choice.is_none());
        assert!(app.vta_stub_notice.is_none());
    }

    // Helpers for the webvh-picker tests below.
    fn sample_webvh_server(id: &str, label: Option<&str>) -> vta_sdk::webvh::WebvhServerRecord {
        use chrono::Utc;
        vta_sdk::webvh::WebvhServerRecord {
            id: id.into(),
            did: format!("did:webvh:{id}.example.com"),
            label: label.map(str::to_string),
            access_token: None,
            access_expires_at: None,
            refresh_token: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    /// Drive the wizard far enough to have a `vta_connect` sub-flow
    /// with a setup key + context id in place, then fake a preflight
    /// with the supplied server catalogue. Returns the wizard ready
    /// to exercise picker dispatch.
    fn prime_full_setup_picker(servers: Vec<vta_sdk::webvh::WebvhServerRecord>) -> WizardApp {
        use crate::vta_connect::EphemeralSetupKey;
        use crate::vta_connect::runner::VtaEvent;
        let mut app = WizardApp::new("test.toml".into());
        advance_to(&mut app, WizardStep::Vta);
        pick_full_setup_online(&mut app); // EnterDid
        app.text_input = tui_input::Input::new("did:webvh:vta.example.com".into());
        app.confirm_text_input(); // → EnterContext
        app.confirm_text_input(); // → EnterMediatorUrl
        app.text_input = tui_input::Input::new("https://mediator.example.com".into());
        app.confirm_text_input(); // → AwaitingAcl (generates setup key)
        // Synthesise a preflight completion without actually running
        // a DIDComm session.
        let st = app.vta_connect.as_mut().unwrap();
        // Make sure the setup key field is populated (ConnectPhase
        // machinery does this during `confirm_text_input`).
        if st.setup_key.is_none() {
            st.setup_key = Some(EphemeralSetupKey::generate().unwrap());
        }
        st.phase = ConnectPhase::Testing;
        st.event_rx = None;
        st.apply_event(VtaEvent::PreflightDone {
            rest_url: Some("https://vta.example.com".into()),
            mediator_did: "did:webvh:mediator.vta.example.com".into(),
            servers,
        });
        app
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn webvh_picker_auto_dispatches_serverless_when_catalogue_empty() {
        // 0 registered servers → wizard skips the picker entirely and
        // kicks the provision flight with `webvh_server_choice = None`
        // (serverless). Phase transitions back to `Testing` while the
        // runner is in flight.
        let mut app = prime_full_setup_picker(vec![]);
        app.drain_vta_events();
        let st = app.vta_connect.as_ref().unwrap();
        assert_eq!(st.phase, ConnectPhase::Testing);
        assert!(st.webvh_server_choice.is_none());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn webvh_picker_auto_picks_single_entry() {
        // 1 registered server → wizard auto-selects it, commits the
        // choice, and transitions to `EnterWebvhPath` so the operator
        // can supply an optional path before the provision flight
        // starts. The text-input mode is activated for that prompt.
        let only = sample_webvh_server("prod-1", Some("Primary"));
        let mut app = prime_full_setup_picker(vec![only]);
        app.drain_vta_events();
        let st = app.vta_connect.as_ref().unwrap();
        assert_eq!(st.phase, ConnectPhase::EnterWebvhPath);
        assert_eq!(st.webvh_server_choice.as_deref(), Some("prod-1"));
        assert!(st.webvh_path.is_none());
        assert!(matches!(app.mode, InputMode::TextInput));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn webvh_picker_waits_when_catalogue_has_multiple_entries() {
        // 2+ registered servers → stay on `PickWebvhServer`; no
        // provision flight starts until the operator picks.
        let servers = vec![
            sample_webvh_server("prod-1", Some("Primary")),
            sample_webvh_server("backup-1", Some("DR")),
        ];
        let mut app = prime_full_setup_picker(servers);
        app.drain_vta_events();
        let st = app.vta_connect.as_ref().unwrap();
        assert_eq!(st.phase, ConnectPhase::PickWebvhServer);
        assert!(st.webvh_server_choice.is_none());
        // Options list: serverless + 2 servers = 3 entries.
        let opts = app.current_options();
        assert_eq!(opts.len(), 3);
        assert!(opts[0].label.starts_with("Serverless"));
        assert!(opts[1].label.contains("prod-1"));
        assert!(opts[2].label.contains("backup-1"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn webvh_picker_serverless_selection_commits_none_choice() {
        let servers = vec![
            sample_webvh_server("prod-1", Some("Primary")),
            sample_webvh_server("backup-1", Some("DR")),
        ];
        let mut app = prime_full_setup_picker(servers);
        app.drain_vta_events();
        assert_eq!(
            app.vta_connect.as_ref().unwrap().phase,
            ConnectPhase::PickWebvhServer
        );
        app.selection_index = 0; // Serverless
        app.select_current();
        let st = app.vta_connect.as_ref().unwrap();
        assert!(
            st.webvh_server_choice.is_none(),
            "index 0 should commit serverless (None)"
        );
        // Provision flight started.
        assert_eq!(st.phase, ConnectPhase::Testing);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn webvh_picker_server_selection_routes_through_path_prompt() {
        // Picking a real server commits the choice, but the provision
        // flight doesn't start yet — we stop on `EnterWebvhPath` so
        // the operator can supply an optional path. Only serverless
        // dispatches immediately.
        let servers = vec![
            sample_webvh_server("prod-1", Some("Primary")),
            sample_webvh_server("backup-1", Some("DR")),
        ];
        let mut app = prime_full_setup_picker(servers);
        app.drain_vta_events();
        app.selection_index = 2; // second server ("backup-1")
        app.select_current();
        let st = app.vta_connect.as_ref().unwrap();
        assert_eq!(st.webvh_server_choice.as_deref(), Some("backup-1"));
        assert_eq!(st.phase, ConnectPhase::EnterWebvhPath);
        assert!(st.webvh_path.is_none());
        assert!(matches!(app.mode, InputMode::TextInput));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn webvh_path_prompt_blank_dispatches_with_none() {
        // Blank input on `EnterWebvhPath` means "server auto-assigns".
        // The flight kicks off (phase → Testing), `webvh_path` stays
        // `None` so no `WEBVH_PATH` var is injected downstream, and
        // mode drops back to `Selecting` so the eventual `Connected`
        // "Continue" Enter routes correctly.
        let only = sample_webvh_server("prod-1", Some("Primary"));
        let mut app = prime_full_setup_picker(vec![only]);
        app.drain_vta_events();
        assert_eq!(
            app.vta_connect.as_ref().unwrap().phase,
            ConnectPhase::EnterWebvhPath
        );
        app.text_input = tui_input::Input::default();
        app.confirm_text_input();
        let st = app.vta_connect.as_ref().unwrap();
        assert_eq!(st.phase, ConnectPhase::Testing);
        assert!(st.webvh_path.is_none());
        assert!(matches!(app.mode, InputMode::Selecting));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn webvh_path_prompt_captures_trimmed_value() {
        // Non-blank input lands on state verbatim (trimmed) and then
        // the provision flight starts. Downstream the runner relays
        // it as the `WEBVH_PATH` template var. Mode drops back to
        // `Selecting` so the `Connected` continue-Enter works.
        let only = sample_webvh_server("prod-1", Some("Primary"));
        let mut app = prime_full_setup_picker(vec![only]);
        app.drain_vta_events();
        app.text_input = tui_input::Input::new("  my-mediator  ".into());
        app.confirm_text_input();
        let st = app.vta_connect.as_ref().unwrap();
        assert_eq!(st.phase, ConnectPhase::Testing);
        assert_eq!(st.webvh_path.as_deref(), Some("my-mediator"));
        assert!(matches!(app.mode, InputMode::Selecting));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn webvh_path_back_nav_returns_to_picker_without_losing_path() {
        // Typing a path and then backing out lands on the picker with
        // the typed value preserved on state, so re-entering the
        // prompt (e.g. to switch servers) pre-fills the field.
        let servers = vec![
            sample_webvh_server("prod-1", Some("Primary")),
            sample_webvh_server("backup-1", Some("DR")),
        ];
        let mut app = prime_full_setup_picker(servers);
        app.drain_vta_events();
        app.selection_index = 1;
        app.select_current();
        assert_eq!(
            app.vta_connect.as_ref().unwrap().phase,
            ConnectPhase::EnterWebvhPath
        );
        // Operator types a path, then Esc — the back-nav should
        // retain the state field and rewind to the picker.
        app.vta_connect.as_mut().unwrap().webvh_path = Some("typed".into());
        app.vta_subflow_back();
        let st = app.vta_connect.as_ref().unwrap();
        assert_eq!(st.phase, ConnectPhase::PickWebvhServer);
        assert_eq!(st.webvh_path.as_deref(), Some("typed"));
        assert_eq!(st.webvh_server_choice.as_deref(), Some("prod-1"));
    }

    /// Drive the wizard to the point where online FullSetup has
    /// received a synthetic `Connected` event with a full provision
    /// reply. Leaves `current_step == Vta`, phase `Connected`,
    /// `vta_session` populated, `did_method = DID_VTA`. Callers
    /// typically immediately `select_current()` to advance past the
    /// Vta step.
    fn prime_full_setup_connected() -> WizardApp {
        use crate::vta_connect::{DiagStatus, VtaEvent, diagnostics::Protocol};
        let mut app = WizardApp::new("test.toml".into());
        advance_to(&mut app, WizardStep::Vta);
        pick_full_setup_online(&mut app);
        app.text_input = tui_input::Input::new("did:webvh:vta.example.com".into());
        app.confirm_text_input();
        app.confirm_text_input();
        app.text_input = tui_input::Input::new("https://mediator.example.com".into());
        app.confirm_text_input();
        app.select_current(); // → Testing (runner spawned, we'll detach)
        let st = app.vta_connect.as_mut().unwrap();
        st.event_rx = None;
        st.apply_event(VtaEvent::CheckDone(
            crate::vta_connect::DiagCheck::Authenticate,
            DiagStatus::Ok("ok".into()),
        ));
        st.apply_event(VtaEvent::Connected {
            protocol: Protocol::DidComm,
            rest_url: Some("https://vta.example.com".into()),
            mediator_did: Some("did:webvh:mediator.vta.example.com".into()),
            reply: crate::vta_connect::VtaReply::Full(
                crate::vta_connect::provision::test_sample_result(true),
            ),
        });
        app
    }

    #[tokio::test]
    async fn did_step_auto_skipped_on_full_setup_online() {
        // After VTA FullSetup provisions the DID, the Did step has
        // nothing left for the operator to decide — apply_vta_defaults
        // already pinned did_method = DID_VTA and vta_session carries
        // the rendered DID doc + keys. `advance` should jump straight
        // from Protocol to Security (the step after Did).
        let mut app = prime_full_setup_connected();
        app.select_current(); // Vta → Protocol
        assert_eq!(app.current_step, WizardStep::Protocol);
        app.select_current(); // Protocol → (auto-skip Did) → Security
        assert_eq!(app.current_step, WizardStep::Security);
        // Did still marked completed so the progress bar reflects the
        // full walk, not a gap.
        assert!(app.completed_steps().contains(&WizardStep::Did));
    }

    #[test]
    fn admin_options_exclude_vta_on_offline_export() {
        // OfflineExport's bundle carries an auto-minted admin
        // credential meant for mediator↔VTA auth only. Reusing it
        // as the mediator's own admin-API identity overloads one
        // key across two trust scopes, so the "Generate admin DID
        // from VTA" option must NOT appear in the Admin step
        // picker for this intent — and the default mode must be
        // ADMIN_GENERATE, not ADMIN_VTA.
        let mut app = WizardApp::new("test.toml".into());
        app.config.use_vta = true;
        app.vta_intent_choice = Some(VtaIntent::OfflineExport);
        app.apply_vta_defaults();
        assert_eq!(app.config.admin_did_mode, ADMIN_GENERATE);

        assert!(!app.admin_options_include_vta());

        app.current_step = WizardStep::Admin;
        let opts = app.current_options();
        assert_eq!(opts.len(), 3, "generate / paste / skip — no VTA entry");
        assert!(!opts.iter().any(|o| o.label.contains("VTA")));
    }

    #[test]
    fn admin_options_include_vta_on_full_setup() {
        // FullSetup's admin-DID rollover is a deliberate handoff
        // of a fresh mediator-admin DID — keep the "Generate admin
        // DID from VTA" option available and default to it.
        let mut app = WizardApp::new("test.toml".into());
        app.config.use_vta = true;
        app.vta_intent_choice = Some(VtaIntent::FullSetup);
        app.apply_vta_defaults();
        assert_eq!(app.config.admin_did_mode, ADMIN_VTA);
        assert!(app.admin_options_include_vta());

        app.current_step = WizardStep::Admin;
        let opts = app.current_options();
        assert_eq!(opts.len(), 4, "generate / paste / VTA / skip");
        assert!(opts.iter().any(|o| o.label.contains("VTA")));
    }

    #[test]
    fn did_step_auto_skipped_on_offline_export() {
        // OfflineExport's ContextProvision reply carries the
        // mediator DID + keys the same way FullSetup's
        // TemplateBootstrap reply does — both should trigger the
        // Did-step auto-skip. Drive the predicate directly with a
        // synthetic VtaSession since the sealed-handoff entry flow
        // is interactive.
        use crate::vta_connect::VtaSession;
        use vta_sdk::context_provision::{ContextProvisionBundle, ProvisionedDid};
        use vta_sdk::credentials::CredentialBundle;
        use vta_sdk::did_secrets::SecretEntry;
        use vta_sdk::keys::KeyType;

        let bundle = ContextProvisionBundle {
            context_id: "mediator-local".into(),
            context_name: "Mediator local".into(),
            vta_url: Some("https://vta.example.com".into()),
            vta_did: Some("did:webvh:vta.example.com".into()),
            credential: CredentialBundle::new(
                "did:key:z6MkAdmin",
                "zAdminPrivate",
                "did:webvh:vta.example.com",
            ),
            admin_did: "did:key:z6MkAdmin".into(),
            did: Some(ProvisionedDid {
                id: "did:webvh:mediator.example.com".into(),
                did_document: None,
                log_entry: None,
                secrets: vec![SecretEntry {
                    key_id: "did:webvh:mediator.example.com#key-0".into(),
                    key_type: KeyType::Ed25519,
                    private_key_multibase: "zSigning".into(),
                }],
            }),
        };

        let mut app = WizardApp::new("test.toml".into());
        app.config.use_vta = true;
        app.config.did_method = DID_VTA.into();
        app.vta_session = Some(VtaSession::context_export("mediator-local".into(), bundle));

        // Predicate must fire with the ContextExport shape too —
        // this is the regression the earlier `as_full_provision`-only
        // check caused.
        app.current_step = WizardStep::Did;
        assert!(
            app.should_auto_skip_step(),
            "OfflineExport session with did_method=DID_VTA must auto-skip the Did step"
        );
    }

    #[tokio::test]
    async fn did_step_back_nav_skips_past_on_full_setup_online() {
        // Coming back the other way should land on Protocol, not on
        // the auto-skipped Did step — same predicate, same behaviour.
        let mut app = prime_full_setup_connected();
        app.select_current(); // Vta → Protocol
        app.select_current(); // Protocol → Security (Did skipped)
        assert_eq!(app.current_step, WizardStep::Security);
        app.go_back(); // Security → (skip Did) → Protocol
        assert_eq!(app.current_step, WizardStep::Protocol);
    }

    #[test]
    fn did_step_not_skipped_without_vta_session() {
        // Sanity: the skip predicate requires all three of
        // `use_vta`, `did_method == DID_VTA`, and a Full provision
        // reply on `vta_session`. Without a VTA session (e.g. No-VTA
        // path, or mid-flow before provisioning succeeds) the Did
        // step must still appear.
        let mut app = WizardApp::new("test.toml".into());
        advance_to(&mut app, WizardStep::Did);
        assert_eq!(app.current_step, WizardStep::Did);
    }
}
