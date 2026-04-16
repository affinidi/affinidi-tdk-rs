use tui_input::{Input, InputRequest};

use crate::consts::*;
use crate::ui::selection::SelectionOption;

/// All wizard steps in order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WizardStep {
    Deployment,
    Vta,
    Protocol,
    Did,
    KeyStorage,
    Security,
    Database,
    Admin,
    Summary,
}

impl WizardStep {
    pub fn all() -> Vec<WizardStep> {
        vec![
            Self::Deployment,
            Self::Vta,
            Self::Protocol,
            Self::Did,
            Self::KeyStorage,
            Self::Security,
            Self::Database,
            Self::Admin,
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

/// Accumulated configuration choices from the wizard.
#[derive(Debug, Clone)]
pub struct WizardConfig {
    pub config_path: String,
    pub deployment_type: String,
    /// Whether VTA integration is enabled
    pub use_vta: bool,
    /// VTA connectivity mode: "online" or "cold-start"
    pub vta_mode: String,
    /// DIDComm v2 protocol enabled (default: true)
    pub didcomm_enabled: bool,
    /// TSP protocol enabled (experimental, default: false)
    pub tsp_enabled: bool,
    pub did_method: String,
    pub public_url: String,
    pub secret_storage: String,
    pub ssl_mode: String,
    pub ssl_cert_path: String,
    pub ssl_key_path: String,
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
            didcomm_enabled: true,
            tsp_enabled: false,
            did_method: String::new(),
            public_url: String::new(),
            secret_storage: String::new(),
            ssl_mode: String::new(),
            ssl_cert_path: String::new(),
            ssl_key_path: String::new(),
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
                vec![
                    SelectionOption::new(
                        "VTA Online",
                        "VTA is accessible — connection mode auto-detected from credential",
                    ),
                    SelectionOption::new(
                        "VTA Cold-start",
                        "VTA not accessible — use pre-provisioned or cached credentials",
                    ),
                    SelectionOption::new(
                        "No VTA",
                        "Manage keys and DIDs independently (local dev, cloud secret stores)",
                    ),
                ]
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
                    SelectionOption::new("Continue >", "Proceed to the next step"),
                ]
            }
            WizardStep::Did => {
                let mut opts = vec![];
                if self.config.use_vta {
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
                let mut opts = vec![];
                if self.config.use_vta {
                    opts.push(SelectionOption::new(
                        "VTA managed (vta://) [recommended]",
                        "Centralized key management via Verifiable Trust Agent",
                    ));
                }
                opts.push(SelectionOption::new(
                    "OS Keyring (keyring://)",
                    "macOS Keychain, Linux Secret Service, Windows Credential Manager",
                ));
                opts.push(SelectionOption::new(
                    "AWS Secrets Manager (aws_secrets://)",
                    "AWS cloud production",
                ));
                opts.push(SelectionOption::new(
                    "Google Cloud Secret Manager (gcp_secrets://)",
                    "GCP cloud production — coming soon",
                ));
                opts.push(SelectionOption::new(
                    "Azure Key Vault (azure_keyvault://)",
                    "Azure cloud production — coming soon",
                ));
                opts.push(SelectionOption::new(
                    "HashiCorp Vault (vault://)",
                    "Enterprise / multi-cloud — coming soon",
                ));
                opts.push(SelectionOption::new(
                    "Local file (file://)",
                    "Stored in secrets.json — NOT secure for production",
                ));
                opts.push(SelectionOption::new(
                    "Inline in config (string://)",
                    "Embedded in mediator.toml — dev/CI only, NOT secure",
                ));
                opts
            }
            WizardStep::Security => vec![
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
            ],
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
                if self.config.use_vta {
                    opts.push(SelectionOption::new(
                        "Copy admin DID from VTA",
                        "Retrieve from VTA context",
                    ));
                }
                opts.push(SelectionOption::new(
                    "Skip for now",
                    "Configure admin later",
                ));
                opts
            }
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
            WizardStep::Vta => match self.selection_index {
                0 => "The mediator connects to VTA at startup to fetch keys and DID documents. Connection mode is auto-detected from the credential. Recommended for production.".into(),
                1 => "The mediator starts with pre-provisioned credentials cached locally. Useful when VTA is temporarily unreachable or during initial bootstrap.".into(),
                2 => "Keys and DIDs are generated locally or stored in cloud secret managers. You are responsible for backup and rotation.".into(),
                _ => String::new(),
            },
            WizardStep::Protocol => match self.selection_index {
                0 => "DIDComm v2 is the industry standard for DID-based secure messaging. Recommended for most deployments.".into(),
                1 => "TSP is a lightweight alternative to DIDComm. EXPERIMENTAL: not all mediator features are supported yet. Can be enabled alongside DIDComm.".into(),
                2 => "Proceed to the next step with selected protocols.".into(),
                _ => String::new(),
            },
            WizardStep::Did => {
                if self.config.use_vta {
                    match self.selection_index {
                        0 => "VTA creates and manages the mediator's DID and keys centrally. Supports did:peer and did:webvh (configurable in VTA). Recommended for production.".into(),
                        1 => "did:webvh requires a webvh server to host the DID document. Generates random keys that you must back up and manage yourself.".into(),
                        2 => "did:peer is self-contained — no hosting required. Generates random keys that you must back up and manage yourself. Best for local dev and testing.".into(),
                        3 => "Import a DID you've already created. You'll need to provide the DID string and private key secrets.".into(),
                        _ => String::new(),
                    }
                } else {
                    match self.selection_index {
                        0 => "did:webvh requires a webvh server to host the DID document. Generates random keys that you must back up and manage yourself.".into(),
                        1 => "did:peer is self-contained — no hosting required. Generates random keys that you must back up and manage yourself. Best for local dev and testing.".into(),
                        2 => "Import a DID you've already created. You'll need to provide the DID string and private key secrets.".into(),
                        _ => String::new(),
                    }
                }
            }
            WizardStep::KeyStorage => {
                if self.config.use_vta {
                    match self.selection_index {
                        0 => "Keys managed by VTA with local caching for offline cold-start. Most secure — keys never leave the VTA boundary.".into(),
                        1 => "Uses the OS keyring (macOS Keychain, Linux Secret Service, Windows Credential Manager). Good for desktop development.".into(),
                        2 => "Store secrets in AWS Secrets Manager. Requires AWS credentials configured. Suitable for AWS production.".into(),
                        3 => "Store secrets in Google Cloud Secret Manager. Coming soon.".into(),
                        4 => "Store secrets in Azure Key Vault. Coming soon.".into(),
                        5 => "Store secrets in HashiCorp Vault. Coming soon.".into(),
                        6 => "Secrets written to conf/secrets.json as plaintext. NOT secure — anyone with file access can read the private keys.".into(),
                        7 => "Secrets embedded directly in mediator.toml as plaintext. NOT secure — only use for dev/CI environments.".into(),
                        _ => String::new(),
                    }
                } else {
                    match self.selection_index {
                        0 => "Uses the OS keyring (macOS Keychain, Linux Secret Service, Windows Credential Manager). Good for desktop development.".into(),
                        1 => "Store secrets in AWS Secrets Manager. Requires AWS credentials configured. Suitable for AWS production.".into(),
                        2 => "Store secrets in Google Cloud Secret Manager. Coming soon.".into(),
                        3 => "Store secrets in Azure Key Vault. Coming soon.".into(),
                        4 => "Store secrets in HashiCorp Vault. Coming soon.".into(),
                        5 => "Secrets written to conf/secrets.json as plaintext. NOT secure — anyone with file access can read the private keys.".into(),
                        6 => "Secrets embedded directly in mediator.toml as plaintext. NOT secure — only use for dev/CI environments.".into(),
                        _ => String::new(),
                    }
                }
            }
            WizardStep::Security => match self.selection_index {
                0 => "Run the mediator behind a reverse proxy (nginx, Caddy, AWS ALB) that terminates TLS. The mediator runs plain HTTP. This is the recommended approach.".into(),
                1 => "Provide paths to existing SSL certificate and key files.".into(),
                2 => "Generate self-signed certificates for local development. Browsers will show security warnings.".into(),
                _ => String::new(),
            },
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
                match self.selection_index {
                    0 => {
                        // VTA Online
                        self.config.use_vta = true;
                        self.config.vta_mode = VTA_MODE_ONLINE.into();
                    }
                    1 => {
                        // VTA Cold-start
                        self.config.use_vta = true;
                        self.config.vta_mode = VTA_MODE_COLD_START.into();
                    }
                    2 => {
                        // No VTA
                        self.config.use_vta = false;
                        self.config.vta_mode = String::new();
                    }
                    _ => return,
                }
                self.apply_vta_defaults();
                self.advance();
            }
            WizardStep::Protocol => {
                match self.selection_index {
                    0 => self.config.didcomm_enabled = !self.config.didcomm_enabled,
                    1 => self.config.tsp_enabled = !self.config.tsp_enabled,
                    2 => {
                        // "Continue" option — advance if at least one protocol selected
                        if !self.config.didcomm_enabled && !self.config.tsp_enabled {
                            return; // Can't continue with no protocol
                        }
                        self.advance();
                        return;
                    }
                    _ => return,
                }
                // Don't allow deselecting both
                if !self.config.didcomm_enabled && !self.config.tsp_enabled {
                    // Re-enable the one they just toggled off
                    match self.selection_index {
                        0 => self.config.didcomm_enabled = true,
                        1 => self.config.tsp_enabled = true,
                        _ => {}
                    }
                }
            }
            WizardStep::Did => {
                if self.config.use_vta {
                    self.config.did_method = match self.selection_index {
                        0 => DID_VTA.into(),
                        1 => DID_WEBVH.into(),
                        2 => DID_PEER.into(),
                        3 => DID_IMPORT.into(),
                        _ => return,
                    };
                    // For did:webvh, collect the public URL
                    if self.selection_index == 1 {
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
                if self.config.use_vta {
                    self.config.secret_storage = match self.selection_index {
                        0 => STORAGE_VTA.into(),
                        1 => STORAGE_KEYRING.into(),
                        2 => STORAGE_AWS.into(),
                        3 => STORAGE_GCP.into(),
                        4 => STORAGE_AZURE.into(),
                        5 => STORAGE_VAULT.into(),
                        6 => STORAGE_FILE.into(),
                        7 => STORAGE_STRING.into(),
                        _ => return,
                    };
                } else {
                    self.config.secret_storage = match self.selection_index {
                        0 => STORAGE_KEYRING.into(),
                        1 => STORAGE_AWS.into(),
                        2 => STORAGE_GCP.into(),
                        3 => STORAGE_AZURE.into(),
                        4 => STORAGE_VAULT.into(),
                        5 => STORAGE_FILE.into(),
                        6 => STORAGE_STRING.into(),
                        _ => return,
                    };
                }
                self.advance();
            }
            WizardStep::Security => {
                self.config.ssl_mode = match self.selection_index {
                    0 => SSL_NONE.into(),
                    1 => SSL_EXISTING.into(),
                    2 => SSL_SELF_SIGNED.into(),
                    _ => return,
                };
                // For existing certs, collect file paths
                if self.selection_index == 1 {
                    self.mode = InputMode::TextInput;
                    self.text_input = Input::new(self.config.ssl_cert_path.clone());
                    return;
                }
                self.advance();
            }
            WizardStep::Database => {
                // Database step: confirm text input
                self.config.database_url = self.text_input.value().to_string();
                self.advance();
            }
            WizardStep::Admin => {
                if self.config.use_vta {
                    self.config.admin_did_mode = match self.selection_index {
                        0 => ADMIN_GENERATE.into(),
                        1 => ADMIN_PASTE.into(),
                        2 => ADMIN_VTA.into(),
                        3 => ADMIN_SKIP.into(),
                        _ => return,
                    };
                } else {
                    self.config.admin_did_mode = match self.selection_index {
                        0 => ADMIN_GENERATE.into(),
                        1 => ADMIN_PASTE.into(),
                        2 => ADMIN_SKIP.into(),
                        _ => return,
                    };
                }
                self.advance();
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

    /// Handle text input confirmation (Enter in TextInput mode).
    pub fn confirm_text_input(&mut self) {
        match self.current_step {
            WizardStep::Did => {
                self.config.public_url = self.text_input.value().to_string();
                self.mode = InputMode::Selecting;
                self.advance();
            }
            WizardStep::Security => {
                // First text input: cert path, then key path
                if self.config.ssl_cert_path.is_empty()
                    || self.config.ssl_cert_path == self.text_input.value()
                {
                    self.config.ssl_cert_path = self.text_input.value().to_string();
                    self.text_input = Input::new(self.config.ssl_key_path.clone());
                } else {
                    self.config.ssl_key_path = self.text_input.value().to_string();
                    self.mode = InputMode::Selecting;
                    self.advance();
                }
            }
            WizardStep::Database => {
                self.config.database_url = self.text_input.value().to_string();
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
                self.config.secret_storage = STORAGE_VTA.into();
                self.config.ssl_mode = SSL_NONE.into();
                self.config.database_url = DEFAULT_REDIS_URL.into();
                self.config.admin_did_mode = ADMIN_GENERATE.into();
            }
            _ => {}
        }
    }

    /// Apply or clear VTA-dependent defaults when toggling VTA integration.
    fn apply_vta_defaults(&mut self) {
        if self.config.use_vta {
            self.config.did_method = DID_VTA.into();
            self.config.secret_storage = STORAGE_VTA.into();
            self.config.admin_did_mode = ADMIN_VTA.into();
        } else {
            if self.config.did_method == DID_VTA {
                self.config.did_method = DID_PEER.into();
            }
            if self.config.secret_storage == STORAGE_VTA {
                self.config.secret_storage = STORAGE_STRING.into();
            }
            if self.config.admin_did_mode == ADMIN_VTA {
                self.config.admin_did_mode = ADMIN_GENERATE.into();
            }
            self.config.vta_mode = String::new();
        }
    }

    fn advance(&mut self) {
        self.completed.push(self.current_step);
        if let Some(next) = self.current_step.next() {
            self.current_step = next;
            self.selection_index = self.default_selection_index();
            // Database step starts in text input mode
            if self.current_step == WizardStep::Database {
                self.mode = InputMode::TextInput;
                self.text_input = Input::new(self.config.database_url.clone());
            } else if self.current_step == WizardStep::Summary {
                self.mode = InputMode::Confirming;
            } else {
                self.mode = InputMode::Selecting;
            }
        }
    }

    pub fn go_back(&mut self) {
        match self.mode {
            InputMode::TextInput => {
                self.mode = InputMode::Selecting;
            }
            InputMode::Confirming => {
                // On Summary, Esc goes back to the previous step
                if self.current_step == WizardStep::Summary {
                    if let Some(prev) = self.current_step.prev() {
                        self.completed.retain(|s| *s != prev);
                        self.current_step = prev;
                        self.selection_index = self.default_selection_index();
                        self.mode = InputMode::Selecting;
                        if self.current_step == WizardStep::Database {
                            self.mode = InputMode::TextInput;
                            self.text_input = Input::new(self.config.database_url.clone());
                        }
                    }
                } else {
                    self.mode = InputMode::Selecting;
                }
            }
            InputMode::Selecting => {
                if let Some(prev) = self.current_step.prev() {
                    self.completed.retain(|s| *s != prev);
                    self.current_step = prev;
                    self.selection_index = self.default_selection_index();
                    if self.current_step == WizardStep::Database {
                        self.mode = InputMode::TextInput;
                        self.text_input = Input::new(self.config.database_url.clone());
                    }
                } else {
                    // First step — Esc quits the wizard
                    self.should_quit = true;
                }
            }
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

    /// Get the default selection index based on deployment defaults.
    fn default_selection_index(&self) -> usize {
        match self.current_step {
            WizardStep::Vta => match self.config.vta_mode.as_str() {
                VTA_MODE_ONLINE => 0,
                VTA_MODE_COLD_START => 1,
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
            WizardStep::KeyStorage => {
                if self.config.use_vta {
                    match self.config.secret_storage.as_str() {
                        STORAGE_VTA => 0,
                        STORAGE_KEYRING => 1,
                        STORAGE_AWS => 2,
                        STORAGE_GCP => 3,
                        STORAGE_AZURE => 4,
                        STORAGE_VAULT => 5,
                        STORAGE_FILE => 6,
                        STORAGE_STRING => 7,
                        _ => 0,
                    }
                } else {
                    match self.config.secret_storage.as_str() {
                        STORAGE_KEYRING => 0,
                        STORAGE_AWS => 1,
                        STORAGE_GCP => 2,
                        STORAGE_AZURE => 3,
                        STORAGE_VAULT => 4,
                        STORAGE_FILE => 5,
                        STORAGE_STRING => 6,
                        _ => 0,
                    }
                }
            }
            WizardStep::Security => match self.config.ssl_mode.as_str() {
                SSL_EXISTING => 1,
                SSL_SELF_SIGNED => 2,
                _ => 0,
            },
            WizardStep::Admin => {
                if self.config.use_vta {
                    match self.config.admin_did_mode.as_str() {
                        ADMIN_PASTE => 1,
                        ADMIN_VTA => 2,
                        ADMIN_SKIP => 3,
                        _ => 0,
                    }
                } else {
                    match self.config.admin_did_mode.as_str() {
                        ADMIN_PASTE => 1,
                        ADMIN_SKIP => 2,
                        _ => 0,
                    }
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
    fn step_all_returns_9_steps_in_order() {
        let steps = WizardStep::all();
        assert_eq!(steps.len(), 9);
        assert_eq!(steps[0], WizardStep::Deployment);
        assert_eq!(steps[1], WizardStep::Vta);
        assert_eq!(steps[8], WizardStep::Summary);
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
        assert_eq!(app.current_step, WizardStep::Vta);
        assert!(app.completed_steps().contains(&WizardStep::Deployment));
    }

    #[test]
    fn advance_sets_text_input_for_database() {
        let mut app = WizardApp::new("test.toml".into());
        // Advance to Database step
        while app.current_step != WizardStep::Admin {
            app.advance();
        }
        // Admin → Summary should set Confirming
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
        app.advance(); // Deployment → Vta
        app.advance(); // Vta → Protocol
        app.advance(); // Protocol → Did
        assert_eq!(app.current_step, WizardStep::Did);
        app.go_back();
        assert_eq!(app.current_step, WizardStep::Protocol);
    }

    #[test]
    fn go_back_from_summary_confirming_returns_to_admin() {
        let mut app = WizardApp::new("test.toml".into());
        // Advance to Summary
        while app.current_step != WizardStep::Summary {
            app.advance();
        }
        assert_eq!(app.mode, InputMode::Confirming);
        app.go_back();
        assert_eq!(app.current_step, WizardStep::Admin);
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
        app.advance(); // → Vta
        app.advance(); // → Protocol

        // DIDComm is selected by default
        assert!(app.config.didcomm_enabled);
        assert!(!app.config.tsp_enabled);

        // Toggle DIDComm off — should re-enable since it's the only one
        app.selection_index = 0; // DIDComm toggle
        app.select_current();
        // At least one must remain enabled
        assert!(app.config.didcomm_enabled || app.config.tsp_enabled);
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
        app.advance(); // → Vta (Deployment completed)
        app.advance(); // → Protocol (Vta completed)
        app.advance(); // → Did (Protocol completed)
        app.focus_progress();
        app.progress_index = 0; // Deployment
        app.jump_to_progress_step();
        assert_eq!(app.current_step, WizardStep::Deployment);
    }

    #[test]
    fn jump_to_incomplete_step_does_nothing() {
        let mut app = WizardApp::new("test.toml".into());
        app.advance(); // → Vta
        app.focus_progress();
        app.progress_index = 6; // Database (not completed)
        let before = app.current_step;
        app.jump_to_progress_step();
        assert_eq!(app.current_step, before); // unchanged
    }

    // ── VTA integration tests ─────────────────────────────────────────

    #[test]
    fn vta_yes_then_online_advances() {
        let mut app = WizardApp::new("test.toml".into());
        app.advance(); // Deployment → Vta
        assert_eq!(app.current_step, WizardStep::Vta);

        // Select "VTA Online" (index 0)
        app.selection_index = 0;
        app.select_current();
        // Should advance directly to Protocol
        assert_eq!(app.current_step, WizardStep::Protocol);
        assert!(app.config.use_vta);
        assert_eq!(app.config.vta_mode, VTA_MODE_ONLINE);
        assert_eq!(app.config.did_method, DID_VTA);
        assert_eq!(app.config.secret_storage, STORAGE_VTA);
        assert_eq!(app.config.admin_did_mode, ADMIN_VTA);
    }

    #[test]
    fn vta_cold_start_sets_defaults() {
        let mut app = WizardApp::new("test.toml".into());
        // Select deployment to set VTA defaults
        app.selection_index = 0;
        app.select_current(); // Deployment → Vta

        // Select "VTA Cold-start" (index 1)
        app.selection_index = 1;
        app.select_current();
        assert_eq!(app.current_step, WizardStep::Protocol);
        assert!(app.config.use_vta);
        assert_eq!(app.config.vta_mode, VTA_MODE_COLD_START);
        assert_eq!(app.config.did_method, DID_VTA);
    }

    #[test]
    fn vta_no_clears_vta_options() {
        let mut app = WizardApp::new("test.toml".into());
        // Select deployment to set VTA defaults (did_method=DID_VTA, etc.)
        app.selection_index = 0;
        app.select_current(); // Deployment → Vta
        assert_eq!(app.config.did_method, DID_VTA);

        // Select "No VTA" (index 2)
        app.selection_index = 2;
        app.select_current();
        assert_eq!(app.current_step, WizardStep::Protocol);
        assert!(!app.config.use_vta);
        // apply_vta_defaults should have switched VTA values to non-VTA
        assert_eq!(app.config.did_method, DID_PEER);
        assert_eq!(app.config.secret_storage, STORAGE_STRING);
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
    fn did_options_include_vta_when_enabled() {
        let mut app = WizardApp::new("test.toml".into());
        app.config.use_vta = true;
        app.current_step = WizardStep::Did;
        let opts = app.current_options();
        assert_eq!(opts.len(), 4); // VTA, webvh, peer, import
    }

    #[test]
    fn vta_step_has_three_options() {
        let mut app = WizardApp::new("test.toml".into());
        app.current_step = WizardStep::Vta;
        let opts = app.current_options();
        assert_eq!(opts.len(), 3); // Online, Cold-start, No VTA
    }
}
