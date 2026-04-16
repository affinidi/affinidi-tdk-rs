use tui_input::{Input, InputRequest};

use crate::ui::selection::SelectionOption;

/// All wizard steps in order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WizardStep {
    Deployment,
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
            Self::Protocol => StepData {
                title: format!("Step {num}/{total}: Messaging Protocol"),
                description: "Which messaging protocol should the mediator use?".into(),
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
    /// Navigating a selection list
    Selecting,
    /// Typing into a text field
    TextInput,
    /// Confirming an action (summary write)
    Confirming,
}

/// Accumulated configuration choices from the wizard.
#[derive(Debug, Clone)]
pub struct WizardConfig {
    pub config_path: String,
    pub deployment_type: String,
    pub protocol: String,
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

impl Default for WizardConfig {
    fn default() -> Self {
        Self {
            config_path: "conf/mediator.toml".into(),
            deployment_type: String::new(),
            protocol: String::new(),
            did_method: String::new(),
            public_url: String::new(),
            secret_storage: String::new(),
            ssl_mode: String::new(),
            ssl_cert_path: String::new(),
            ssl_key_path: String::new(),
            database_url: "redis://127.0.0.1/".into(),
            admin_did_mode: String::new(),
            listen_address: "0.0.0.0:7037".into(),
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
    pub should_quit: bool,
    pub quit_confirm: bool,
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
            should_quit: false,
            quit_confirm: false,
            write_config: false,
            completed: Vec::new(),
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
            WizardStep::Protocol => vec![
                SelectionOption::new(
                    "DIDComm v2 (recommended)",
                    "Industry-standard DID-based messaging",
                ),
                SelectionOption::new(
                    "TSP (Trust Spanning Protocol) [experimental]",
                    "Lightweight trust protocol — experimental support",
                ),
            ],
            WizardStep::Did => vec![
                SelectionOption::new("Generate did:peer", "Simplest option — no hosting required"),
                SelectionOption::new("Generate did:webvh", "Production — requires a webvh server"),
                SelectionOption::new("Import existing DID", "Paste an existing DID string"),
                SelectionOption::new("Configure via VTA", "Centralized key management via VTA"),
            ],
            WizardStep::KeyStorage => vec![
                SelectionOption::new(
                    "Inline in config (string://)",
                    "Embedded in mediator.toml — dev/CI only",
                ),
                SelectionOption::new(
                    "Local file (file://)",
                    "Stored in secrets.json — simple deployments",
                ),
                SelectionOption::new(
                    "OS Keyring (keyring://)",
                    "macOS Keychain, Linux Secret Service",
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
                SelectionOption::new("HashiCorp Vault (vault://)", "Enterprise / multi-cloud"),
                SelectionOption::new(
                    "VTA managed (vta://)",
                    "Centralized via Verifiable Trust Agent",
                ),
            ],
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
            WizardStep::Admin => vec![
                SelectionOption::new(
                    "Generate a new admin did:key",
                    "Creates a new Ed25519 key pair",
                ),
                SelectionOption::new("Paste an existing admin DID", "Use any DID method"),
                SelectionOption::new("Copy admin DID from VTA", "Retrieve from VTA context"),
                SelectionOption::new("Skip for now", "Configure admin later"),
            ],
            WizardStep::Summary => vec![],
        }
    }

    /// Get the info text for the currently highlighted option.
    pub fn current_info_text(&self) -> String {
        match self.current_step {
            WizardStep::Deployment => match self.selection_index {
                0 => "Sets sensible defaults for local development: did:peer, inline secrets, no SSL, localhost Redis.".into(),
                1 => "Sets defaults for production: did:webvh, external secret storage, TLS proxy, remote Redis.".into(),
                2 => "Same as server, plus generates a Dockerfile and docker-compose.yml with correct feature flags.".into(),
                _ => String::new(),
            },
            WizardStep::Protocol => match self.selection_index {
                0 => "DIDComm v2 is the industry standard for DID-based secure messaging. Recommended for most deployments.".into(),
                1 => "TSP is a lightweight alternative to DIDComm. EXPERIMENTAL: not all mediator features are supported with TSP yet.".into(),
                _ => String::new(),
            },
            WizardStep::Did => match self.selection_index {
                0 => "did:peer is self-contained — no hosting required. Best for local dev and testing.".into(),
                1 => "did:webvh requires a webvh server to host the DID document. Best for production deployments.".into(),
                2 => "Import a DID you've already created. You'll need to provide the DID string and secrets.".into(),
                3 => "Use your Verifiable Trust Agent (VTA) to create and manage the mediator's DID.".into(),
                _ => String::new(),
            },
            WizardStep::KeyStorage => match self.selection_index {
                0 => "Secrets are embedded directly in mediator.toml. Simple but not secure for production.".into(),
                1 => "Secrets written to conf/secrets.json. Easy to manage, no external dependencies.".into(),
                2 => "Uses the OS keyring (macOS Keychain, Linux Secret Service, Windows Credential Manager).".into(),
                3 => "Store secrets in AWS Secrets Manager. Requires AWS credentials configured.".into(),
                4 => "Store secrets in Google Cloud Secret Manager. Coming soon.".into(),
                5 => "Store secrets in Azure Key Vault. Coming soon.".into(),
                6 => "Store secrets in HashiCorp Vault. Coming soon.".into(),
                7 => "Secrets managed by VTA with local caching for offline cold-start.".into(),
                _ => String::new(),
            },
            WizardStep::Security => match self.selection_index {
                0 => "Run the mediator behind a reverse proxy (nginx, Caddy, AWS ALB) that terminates TLS. The mediator runs plain HTTP. This is the recommended approach.".into(),
                1 => "Provide paths to existing SSL certificate and key files.".into(),
                2 => "Generate self-signed certificates for local development. Browsers will show security warnings.".into(),
                _ => String::new(),
            },
            WizardStep::Database => {
                "Redis is used for message queues, session storage, and forwarding. Use database partitions (e.g. redis://127.0.0.1/1) to isolate data when sharing a Redis instance.".into()
            }
            WizardStep::Admin => match self.selection_index {
                0 => "Generates a new Ed25519 did:key. The private key will be displayed — save it securely!".into(),
                1 => "Paste any DID (did:key, did:peer, did:webvh, etc.) to use as admin.".into(),
                2 => "Copy the admin DID from your VTA context.".into(),
                3 => "You can configure the admin DID later by editing mediator.toml or via the admin API.".into(),
                _ => String::new(),
            },
            WizardStep::Summary => String::new(),
        }
    }

    /// Handle Enter key — select current option and advance.
    pub fn select_current(&mut self) {
        match self.current_step {
            WizardStep::Deployment => {
                self.config.deployment_type = match self.selection_index {
                    0 => "Local development".into(),
                    1 => "Headless server".into(),
                    2 => "Container".into(),
                    _ => return,
                };
                self.apply_deployment_defaults();
                self.advance();
            }
            WizardStep::Protocol => {
                self.config.protocol = match self.selection_index {
                    0 => "DIDComm v2".into(),
                    1 => "TSP".into(),
                    _ => return,
                };
                self.advance();
            }
            WizardStep::Did => {
                self.config.did_method = match self.selection_index {
                    0 => "did:peer".into(),
                    1 => "did:webvh".into(),
                    2 => "Import existing".into(),
                    3 => "VTA managed".into(),
                    _ => return,
                };
                // For did:webvh, we'll need to collect the public URL
                if self.selection_index == 1 {
                    self.mode = InputMode::TextInput;
                    self.text_input = Input::new(self.config.public_url.clone());
                    return;
                }
                self.advance();
            }
            WizardStep::KeyStorage => {
                self.config.secret_storage = match self.selection_index {
                    0 => "string://".into(),
                    1 => "file://".into(),
                    2 => "keyring://".into(),
                    3 => "aws_secrets://".into(),
                    4 => "gcp_secrets://".into(),
                    5 => "azure_keyvault://".into(),
                    6 => "vault://".into(),
                    7 => "vta://".into(),
                    _ => return,
                };
                self.advance();
            }
            WizardStep::Security => {
                self.config.ssl_mode = match self.selection_index {
                    0 => "No SSL (TLS proxy)".into(),
                    1 => "Existing certificates".into(),
                    2 => "Self-signed".into(),
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
                self.config.admin_did_mode = match self.selection_index {
                    0 => "Generate did:key".into(),
                    1 => "Paste existing".into(),
                    2 => "Copy from VTA".into(),
                    3 => "Skip".into(),
                    _ => return,
                };
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
            "Local development" => {
                self.config.protocol = "DIDComm v2".into();
                self.config.did_method = "did:peer".into();
                self.config.secret_storage = "string://".into();
                self.config.ssl_mode = "No SSL (TLS proxy)".into();
                self.config.database_url = "redis://127.0.0.1/".into();
                self.config.admin_did_mode = "Generate did:key".into();
            }
            "Headless server" => {
                self.config.protocol = "DIDComm v2".into();
                self.config.did_method = "did:webvh".into();
                self.config.secret_storage = "aws_secrets://".into();
                self.config.ssl_mode = "No SSL (TLS proxy)".into();
                self.config.database_url = "redis://127.0.0.1/".into();
                self.config.admin_did_mode = "Generate did:key".into();
            }
            "Container" => {
                self.config.protocol = "DIDComm v2".into();
                self.config.did_method = "did:webvh".into();
                self.config.secret_storage = "aws_secrets://".into();
                self.config.ssl_mode = "No SSL (TLS proxy)".into();
                self.config.database_url = "redis://127.0.0.1/".into();
                self.config.admin_did_mode = "Generate did:key".into();
            }
            _ => {}
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
                self.mode = InputMode::Selecting;
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
                self.mode = InputMode::Selecting;
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

    pub fn request_quit(&mut self) {
        if self.quit_confirm {
            self.should_quit = true;
        } else {
            self.quit_confirm = true;
        }
    }

    pub fn cancel_quit(&mut self) {
        self.quit_confirm = false;
    }

    /// Get the default selection index based on deployment defaults.
    fn default_selection_index(&self) -> usize {
        match self.current_step {
            WizardStep::Protocol => match self.config.protocol.as_str() {
                "TSP" => 1,
                _ => 0,
            },
            WizardStep::Did => match self.config.did_method.as_str() {
                "did:webvh" => 1,
                "Import existing" => 2,
                "VTA managed" => 3,
                _ => 0,
            },
            WizardStep::KeyStorage => match self.config.secret_storage.as_str() {
                "file://" => 1,
                "keyring://" => 2,
                "aws_secrets://" => 3,
                "gcp_secrets://" => 4,
                "azure_keyvault://" => 5,
                "vault://" => 6,
                "vta://" => 7,
                _ => 0,
            },
            WizardStep::Security => match self.config.ssl_mode.as_str() {
                "Existing certificates" => 1,
                "Self-signed" => 2,
                _ => 0,
            },
            WizardStep::Admin => match self.config.admin_did_mode.as_str() {
                "Paste existing" => 1,
                "Copy from VTA" => 2,
                "Skip" => 3,
                _ => 0,
            },
            _ => 0,
        }
    }
}
