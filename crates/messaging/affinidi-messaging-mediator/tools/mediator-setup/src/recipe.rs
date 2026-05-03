//! Build recipe — a declarative TOML file that drives the setup wizard
//! non-interactively. See `examples/mediator-build.toml` for the full schema.
//!
//! **Security:** build recipes never contain secrets. Credentials embedded in
//! URLs (e.g. Redis passwords) are stripped when saving. When replaying a
//! recipe that needs credentials, the user is prompted at runtime or can
//! supply them via environment variables.

use serde::Deserialize;
use url::Url;

use crate::app::WizardConfig;
use crate::consts::*;

/// Top-level build recipe.
#[derive(Debug, Deserialize)]
pub struct BuildRecipe {
    pub deployment: DeploymentSection,
    #[serde(default)]
    pub identity: IdentitySection,
    #[serde(default)]
    pub secrets: SecretsSection,
    #[serde(default)]
    pub security: SecuritySection,
    #[serde(default)]
    pub database: DatabaseSection,
    /// Optional storage backend selector. When `[storage].backend =
    /// "fjall"`, the mediator opens an embedded Fjall database at
    /// `data_dir`; the `[database]` section is ignored. Defaults to
    /// `"redis"`, so existing recipes without `[storage]` continue
    /// to use the legacy Redis path.
    #[serde(default)]
    pub storage: StorageSection,
    #[serde(default)]
    pub output: OutputSection,
    #[serde(default)]
    pub install: InstallSection,
    /// VTA-specific inputs previously collected interactively on the
    /// Vta step. Only meaningful when `deployment.use_vta = true`;
    /// individual fields are mode-gated at validation time (e.g.
    /// `context` is required for every sealed mode, `webvh_server`
    /// only for `sealed-mint`).
    #[serde(default)]
    pub vta: VtaSection,
}

/// `[vta]` section — operator inputs for the VTA integration. Split out
/// of `DeploymentSection` because a growing recipe with VTA-specific
/// fields reads more naturally as its own table than a widening
/// `[deployment]`.
#[derive(Debug, Default, Deserialize)]
pub struct VtaSection {
    /// VTA context ID this mediator lives in. Defaults to `"mediator"`
    /// via `apply_vta_defaults` when absent; operators with multiple
    /// mediators against one VTA should set this explicitly.
    #[serde(default)]
    pub context: Option<String>,
    /// Optional webvh server id the VTA should pin the minted DID's
    /// `did.jsonl` log to. Only honoured for `vta_mode =
    /// "sealed-mint"`; ignored for `sealed-export` (nothing is being
    /// minted) and for `online` (the TUI collects it interactively).
    #[serde(default)]
    pub webvh_server: Option<String>,
    /// Optional webvh path / mnemonic the VTA forwards to the chosen
    /// webvh server's `request_uri` call. Pairs with `webvh_server`;
    /// both are sealed-mint-only.
    #[serde(default)]
    pub webvh_path: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct DeploymentSection {
    /// `local`, `server`, or `container`
    #[serde(rename = "type")]
    pub deployment_type: String,
    /// `["didcomm"]`, `["tsp"]`, or `["didcomm", "tsp"]`
    #[serde(default = "default_protocols")]
    pub protocols: Vec<String>,
    /// Whether VTA integration is enabled
    #[serde(default)]
    pub use_vta: bool,
    /// VTA connectivity mode:
    ///
    /// - `"online"` — live REST/DIDComm round-trip from the mediator
    ///   to a running VTA. Only supported via the interactive TUI
    ///   today because the `pnm acl create` step is inherently
    ///   operator-gated; recipe-driven `--from` for `online` is
    ///   rejected with a pointer at the TUI.
    /// - `"sealed-mint"` — air-gapped sealed handoff where the VTA
    ///   mints a *fresh* mediator DID + keys on the VTA side and
    ///   returns a `TemplateBootstrap` bundle. Use for greenfield
    ///   deployments.
    /// - `"sealed-export"` — air-gapped export of state the VTA has
    ///   already provisioned (ran a prior `sealed-mint` or online
    ///   setup). VTA admin runs `vta contexts reprovision` and
    ///   returns a `ContextProvision` bundle. Use for migrations
    ///   and restores.
    /// - `"sealed"` — **deprecated** alias for `"sealed-mint"`,
    ///   accepted for backward compatibility with recipes written
    ///   before the split. Emits a warning on load.
    #[serde(default)]
    pub vta_mode: Option<String>,
}

fn default_protocols() -> Vec<String> {
    vec!["didcomm".into()]
}

#[derive(Debug, Deserialize)]
pub struct IdentitySection {
    /// `vta`, `did:peer`, `did:webvh`, or `import`
    #[serde(default = "default_did_method")]
    pub did_method: String,
    /// Required when `did_method = "did:webvh"`
    pub public_url: Option<String>,
}

fn default_did_method() -> String {
    "vta".into()
}

impl Default for IdentitySection {
    fn default() -> Self {
        Self {
            did_method: default_did_method(),
            public_url: None,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct SecretsSection {
    /// One of: `file://`, `keyring://`, `aws_secrets://`,
    /// `gcp_secrets://`, `azure_keyvault://`, `vault://`. Note:
    /// `string://` (inline) and `vta://` are no longer accepted —
    /// `vta://` was never a backend (the VTA is a key *source*) and
    /// `string://` is unsafe even for CI.
    #[serde(default = "default_storage")]
    pub storage: String,
}

fn default_storage() -> String {
    "keyring://".into()
}

impl Default for SecretsSection {
    fn default() -> Self {
        Self {
            storage: default_storage(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct SecuritySection {
    /// `none`, `self-signed`, or `existing`
    #[serde(default = "default_ssl")]
    pub ssl: String,
    /// Path to existing SSL certificate (when `ssl = "existing"`)
    pub ssl_cert: Option<String>,
    /// Path to existing SSL key (when `ssl = "existing"`)
    pub ssl_key: Option<String>,
    /// `generate`, `skip`, or `import`
    #[serde(default = "default_admin")]
    pub admin: String,
    /// Pre-existing admin DID (when `admin = "import"`)
    #[allow(dead_code)] // will be used when admin DID import is implemented
    pub admin_did: Option<String>,
    /// JWT signing-secret provisioning mode: `generate` (default) or
    /// `provide`. With `provide`, the wizard records the choice but does
    /// not mint or prompt for a key — the mediator reads it from
    /// `MEDIATOR_JWT_SECRET` / `--jwt-secret-file` at startup.
    #[serde(default = "default_jwt_mode")]
    pub jwt_mode: String,
}

fn default_ssl() -> String {
    "none".into()
}

fn default_admin() -> String {
    "generate".into()
}

fn default_jwt_mode() -> String {
    "generate".into()
}

impl Default for SecuritySection {
    fn default() -> Self {
        Self {
            ssl: default_ssl(),
            ssl_cert: None,
            ssl_key: None,
            admin: default_admin(),
            admin_did: None,
            jwt_mode: default_jwt_mode(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct DatabaseSection {
    #[serde(default = "default_database_url")]
    pub url: String,
}

fn default_database_url() -> String {
    "redis://127.0.0.1/".into()
}

impl Default for DatabaseSection {
    fn default() -> Self {
        Self {
            url: default_database_url(),
        }
    }
}

/// Optional `[storage]` section in the recipe — selects the mediator's
/// storage backend. When omitted, falls back to the legacy `[database]`
/// section (Redis). The wizard-generated `mediator.toml` mirrors the
/// shape: a `[storage]` section with `backend = "redis" | "fjall"`,
/// plus a backend-specific configuration.
///
/// Memory backend is intentionally absent — it's a tests-only backend
/// and shouldn't appear in operator-facing config.
#[derive(Debug, Deserialize)]
pub struct StorageSection {
    /// `"redis"` or `"fjall"`. Defaults to `"redis"` so existing
    /// recipes without a `[storage]` section continue to work.
    #[serde(default = "default_storage_backend")]
    pub backend: String,
    /// On-disk path for the Fjall data directory. Used only when
    /// `backend = "fjall"`. The mediator creates this directory if it
    /// doesn't exist.
    #[serde(default = "default_fjall_data_dir")]
    pub data_dir: String,
}

fn default_storage_backend() -> String {
    "redis".into()
}

fn default_fjall_data_dir() -> String {
    "./data/mediator".into()
}

impl Default for StorageSection {
    fn default() -> Self {
        Self {
            backend: default_storage_backend(),
            data_dir: default_fjall_data_dir(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct OutputSection {
    /// Path for the generated mediator.toml
    #[serde(default = "default_config_path")]
    pub config_path: String,
    /// Listen address for the mediator (ip:port)
    #[serde(default = "default_listen_address")]
    pub listen_address: String,
    /// HTTP prefix all mediator routes nest under (`/mediator/v1/` by
    /// default). Combined with `identity.public_url` when rendering the
    /// did:webvh service endpoints. Empty / `/` means "serve at host
    /// root" — useful when fronting the mediator with a path-rewriting
    /// reverse proxy.
    #[serde(default = "default_api_prefix")]
    pub api_prefix: String,
}

fn default_config_path() -> String {
    "conf/mediator.toml".into()
}

fn default_listen_address() -> String {
    "0.0.0.0:7037".into()
}

fn default_api_prefix() -> String {
    crate::consts::DEFAULT_API_PREFIX.into()
}

impl Default for OutputSection {
    fn default() -> Self {
        Self {
            config_path: default_config_path(),
            listen_address: default_listen_address(),
            api_prefix: default_api_prefix(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct InstallSection {
    /// Whether to run `cargo install` after generating config
    #[serde(default)]
    pub enabled: bool,
    /// Custom install root (passed as `cargo install --root <path>`)
    pub path: Option<String>,
}

impl Default for InstallSection {
    fn default() -> Self {
        Self {
            enabled: false,
            path: None,
        }
    }
}

/// Normalise a raw `vta_mode` string from a recipe into the canonical
/// values the wizard code uses ([`VTA_MODE_ONLINE`] /
/// [`VTA_MODE_SEALED_MINT`] / [`VTA_MODE_SEALED_EXPORT`]).
///
/// `None` and empty strings return `""` — `to_wizard_config` then runs
/// its legacy auto-detect path (did_method=vta → ONLINE). A deprecated
/// `"sealed"` is silently rewritten to `sealed-mint` because every
/// pre-split recipe used the single value for the mint case.
fn normalise_vta_mode(raw: Option<&str>) -> anyhow::Result<String> {
    let trimmed = raw.unwrap_or("").trim();
    Ok(match trimmed {
        "" => String::new(),
        VTA_MODE_ONLINE => VTA_MODE_ONLINE.into(),
        VTA_MODE_SEALED_MINT => VTA_MODE_SEALED_MINT.into(),
        VTA_MODE_SEALED_EXPORT => VTA_MODE_SEALED_EXPORT.into(),
        // Backward compat: pre-split recipes wrote `"sealed"` to
        // mean what's now `"sealed-mint"`. Accept silently —
        // nobody's written `"sealed"` to mean anything else.
        VTA_MODE_SEALED_LEGACY => VTA_MODE_SEALED_MINT.into(),
        other => anyhow::bail!(
            "Invalid deployment.vta_mode '{}': expected one of '{}', '{}', '{}' \
             (or legacy '{}' which maps to '{}')",
            other,
            VTA_MODE_ONLINE,
            VTA_MODE_SEALED_MINT,
            VTA_MODE_SEALED_EXPORT,
            VTA_MODE_SEALED_LEGACY,
            VTA_MODE_SEALED_MINT,
        ),
    })
}

/// Load a build recipe from a TOML file.
pub fn load(path: &str) -> anyhow::Result<BuildRecipe> {
    let contents = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("Cannot read build recipe '{}': {}", path, e))?;
    let recipe: BuildRecipe = toml::from_str(&contents)
        .map_err(|e| anyhow::anyhow!("Invalid build recipe '{}': {}", path, e))?;
    Ok(recipe)
}

/// Convert a build recipe into a WizardConfig.
pub fn to_wizard_config(recipe: &BuildRecipe) -> anyhow::Result<WizardConfig> {
    let mut config = WizardConfig::default();

    // Deployment type
    config.deployment_type = match recipe.deployment.deployment_type.as_str() {
        "local" => DEPLOYMENT_LOCAL.into(),
        "server" => DEPLOYMENT_SERVER.into(),
        "container" => DEPLOYMENT_CONTAINER.into(),
        other => anyhow::bail!(
            "Invalid deployment.type '{}': expected 'local', 'server', or 'container'",
            other
        ),
    };

    // VTA integration
    config.use_vta = recipe.deployment.use_vta;
    config.vta_mode = normalise_vta_mode(recipe.deployment.vta_mode.as_deref())?;

    // Auto-detect: if recipe uses VTA-managed DID but use_vta is missing
    // (backward compat). Note: `secrets.storage = "vta://"` is no longer
    // recognised — VTA is a *source* of keys, not a storage backend.
    if !config.use_vta && recipe.identity.did_method == "vta" {
        config.use_vta = true;
        if config.vta_mode.is_empty() {
            config.vta_mode = VTA_MODE_ONLINE.into();
        }
    }

    // [vta] section — operator inputs previously collected
    // interactively. `context` defaults to `DEFAULT_VTA_CONTEXT`
    // (`"mediator"`) when absent; webvh_server / webvh_path stay
    // `None` when absent (meaningful only for sealed-mint and
    // auto-routed by `apply_vta_defaults` equivalents in the
    // non-interactive path).
    config.vta_context = recipe
        .vta
        .context
        .clone()
        .unwrap_or_else(|| DEFAULT_VTA_CONTEXT.into());
    // Reuse the existing `vta_webvh_server_id` / `vta_webvh_mnemonic`
    // fields on `WizardConfig` — they were originally populated by
    // the TUI's online-VTA webvh picker and have the right shape for
    // the recipe-driven sealed-mint flow too. `WEBVH_PATH` on the
    // VTA template maps to `vta_webvh_mnemonic`.
    config.vta_webvh_server_id = recipe.vta.webvh_server.clone();
    config.vta_webvh_mnemonic = recipe.vta.webvh_path.clone();

    // Mode-specific validation: `sealed-mint` mints a new DID on the
    // VTA whose template requires a `URL` — identity.public_url must
    // therefore be present. `sealed-export` pulls back an existing
    // DID (URL already baked in), so `public_url` is informational.
    // `online` uses the live DIDComm round-trip; the TUI collects
    // the URL interactively when missing — recipe-driven `online` is
    // rejected separately in `run_from_recipe`.
    if config.use_vta
        && config.vta_mode == VTA_MODE_SEALED_MINT
        && recipe
            .identity
            .public_url
            .as_deref()
            .is_none_or(str::is_empty)
    {
        anyhow::bail!(
            "vta_mode = \"sealed-mint\" requires identity.public_url — \
             the VTA's didcomm-mediator template renders the mediator DID \
             using this URL."
        );
    }

    // Protocols
    config.didcomm_enabled = false;
    config.tsp_enabled = false;
    for proto in &recipe.deployment.protocols {
        match proto.as_str() {
            "didcomm" => config.didcomm_enabled = true,
            "tsp" => config.tsp_enabled = true,
            other => anyhow::bail!("Invalid protocol '{}': expected 'didcomm' or 'tsp'", other),
        }
    }
    if !config.didcomm_enabled && !config.tsp_enabled {
        anyhow::bail!("At least one protocol must be enabled (didcomm or tsp)");
    }

    // DID method
    config.did_method = match recipe.identity.did_method.as_str() {
        "vta" => DID_VTA.into(),
        "did:peer" | "peer" => DID_PEER.into(),
        "did:webvh" | "webvh" => DID_WEBVH.into(),
        "import" => DID_IMPORT.into(),
        other => anyhow::bail!(
            "Invalid identity.did_method '{}': expected 'vta', 'did:peer', 'did:webvh', or 'import'",
            other
        ),
    };

    if config.did_method == DID_WEBVH {
        config.public_url = recipe.identity.public_url.clone().ok_or_else(|| {
            anyhow::anyhow!("identity.public_url is required when did_method = 'did:webvh'")
        })?;
    } else if let Some(ref url) = recipe.identity.public_url {
        config.public_url = url.clone();
    }

    // Secrets — accept either the bare scheme (backward compat with
    // pre-cloud-config recipes) or a fully-formed URL. A full URL gets
    // parsed into per-backend fields so re-running the wizard from a
    // recipe restores region / project / vault / endpoint without the
    // operator re-typing them. `string://` and `vta://` are rejected.
    apply_secrets_storage(&recipe.secrets.storage, &mut config)?;

    // Security
    config.ssl_mode = match recipe.security.ssl.as_str() {
        "none" => SSL_NONE.into(),
        "self-signed" | "self_signed" => SSL_SELF_SIGNED.into(),
        "existing" => {
            config.ssl_cert_path = recipe.security.ssl_cert.clone().ok_or_else(|| {
                anyhow::anyhow!("security.ssl_cert is required when ssl = 'existing'")
            })?;
            config.ssl_key_path = recipe.security.ssl_key.clone().ok_or_else(|| {
                anyhow::anyhow!("security.ssl_key is required when ssl = 'existing'")
            })?;
            SSL_EXISTING.into()
        }
        other => anyhow::bail!(
            "Invalid security.ssl '{}': expected 'none', 'self-signed', or 'existing'",
            other
        ),
    };

    config.admin_did_mode = match recipe.security.admin.as_str() {
        "generate" => ADMIN_GENERATE.into(),
        "skip" => ADMIN_SKIP.into(),
        "import" => {
            // TODO: handle imported admin DID
            ADMIN_PASTE.into()
        }
        other => anyhow::bail!(
            "Invalid security.admin '{}': expected 'generate', 'skip', or 'import'",
            other
        ),
    };

    config.jwt_mode = match recipe.security.jwt_mode.as_str() {
        "generate" | "" => JWT_MODE_GENERATE.into(),
        "provide" => JWT_MODE_PROVIDE.into(),
        other => anyhow::bail!(
            "Invalid security.jwt_mode '{}': expected 'generate' or 'provide'",
            other
        ),
    };

    // Database
    config.database_url = recipe.database.url.clone();

    // Storage backend selector. Validate the choice up-front so a
    // typo in the recipe surfaces here rather than at mediator
    // startup. `memory` is intentionally rejected — it's a tests-
    // only backend.
    match recipe.storage.backend.as_str() {
        "redis" => config.storage_backend = "redis".into(),
        "fjall" => {
            config.storage_backend = "fjall".into();
            config.fjall_data_dir = recipe.storage.data_dir.clone();
        }
        other => {
            return Err(anyhow::anyhow!(
                "Invalid storage.backend '{}': expected 'redis' or 'fjall'",
                other
            ));
        }
    }

    // Output
    config.config_path = recipe.output.config_path.clone();
    config.listen_address = recipe.output.listen_address.clone();
    config.api_prefix = recipe.output.api_prefix.clone();

    Ok(config)
}

/// Strip credentials from a URL, replacing them with a placeholder.
/// Returns the redacted URL and whether any credentials were found.
///
/// Examples:
///   `redis://:password@host/` → `redis://host/` (credentials stripped)
///   `redis://user:pass@host/` → `redis://host/` (credentials stripped)
///   `redis://127.0.0.1/`      → `redis://127.0.0.1/` (unchanged)
fn redact_url(raw: &str) -> (String, bool) {
    match Url::parse(raw) {
        Ok(mut url) => {
            let had_credentials = !url.username().is_empty() || url.password().is_some();
            if had_credentials {
                let _ = url.set_username("");
                let _ = url.set_password(None);
            }
            (url.to_string(), had_credentials)
        }
        Err(_) => (raw.to_string(), false),
    }
}

/// Check if a database URL needs credentials to be supplied at runtime.
/// Returns true if the URL has a placeholder or if the recipe was saved
/// with credentials stripped.
pub fn needs_database_credentials(url: &str) -> bool {
    url.contains("<") || url.contains("${") || url.contains("$DATABASE")
}

/// Generate a build recipe TOML string from the wizard config.
/// This allows reproducing the same build by running `mediator-setup --from <file>`.
///
/// **Security:** credentials are stripped from URLs. The recipe is safe to
/// commit to version control.
pub fn from_wizard_config(config: &WizardConfig) -> String {
    let mut out = String::new();
    out.push_str("# Mediator Build Recipe\n");
    out.push_str("# Generated by mediator-setup — rerun with: mediator-setup --from <this-file>\n");
    out.push_str("#\n");
    out.push_str("# This file is safe to commit to version control.\n");
    out.push_str("# No secrets, passwords, or private keys are stored here.\n\n");

    // Deployment
    out.push_str("[deployment]\n");
    let deployment_type = match config.deployment_type.as_str() {
        DEPLOYMENT_LOCAL => "local",
        DEPLOYMENT_SERVER => "server",
        DEPLOYMENT_CONTAINER => "container",
        _ => "local",
    };
    out.push_str(&format!("type = \"{deployment_type}\"\n"));

    let mut protocols = Vec::new();
    if config.didcomm_enabled {
        protocols.push("\"didcomm\"");
    }
    if config.tsp_enabled {
        protocols.push("\"tsp\"");
    }
    out.push_str(&format!("protocols = [{}]\n", protocols.join(", ")));
    out.push_str(&format!("use_vta = {}\n", config.use_vta));
    if config.use_vta && !config.vta_mode.is_empty() {
        out.push_str(&format!("vta_mode = \"{}\"\n", config.vta_mode));
    }
    out.push('\n');

    // [vta] — only emit when VTA is enabled and at least one field
    // has a non-default value. Keeping an empty section out of the
    // written recipe means the rendered TOML stays small for the
    // common case where the operator didn't customise webvh
    // hosting.
    if config.use_vta {
        let has_nondefault_context =
            !config.vta_context.is_empty() && config.vta_context != DEFAULT_VTA_CONTEXT;
        let has_webvh_server = config.vta_webvh_server_id.is_some();
        let has_webvh_path = config.vta_webvh_mnemonic.is_some();
        if has_nondefault_context || has_webvh_server || has_webvh_path {
            out.push_str("[vta]\n");
            if has_nondefault_context {
                out.push_str(&format!("context = \"{}\"\n", config.vta_context));
            }
            if let Some(ref s) = config.vta_webvh_server_id {
                out.push_str(&format!("webvh_server = \"{s}\"\n"));
            }
            if let Some(ref p) = config.vta_webvh_mnemonic {
                out.push_str(&format!("webvh_path = \"{p}\"\n"));
            }
            out.push('\n');
        }
    }

    // Identity
    out.push_str("[identity]\n");
    let did_method = match config.did_method.as_str() {
        DID_VTA => "vta",
        DID_PEER => "did:peer",
        DID_WEBVH => "did:webvh",
        DID_IMPORT => "import",
        _ => "vta",
    };
    out.push_str(&format!("did_method = \"{did_method}\"\n"));
    if !config.public_url.is_empty() {
        out.push_str(&format!("public_url = \"{}\"\n", config.public_url));
    }
    out.push('\n');

    // Secrets — emit the fully-assembled backend URL so a recipe replay
    // restores per-backend config (region / project / vault / endpoint)
    // without the operator re-typing them. The URL is constructed by
    // `build_backend_url`, the same routine the wizard writes into the
    // mediator's `[secrets].backend` field.
    out.push_str("[secrets]\n");
    let storage_url = crate::config_writer::build_backend_url(config);
    out.push_str(&format!("storage = \"{storage_url}\"\n\n"));

    // Security
    out.push_str("[security]\n");
    let ssl = match config.ssl_mode.as_str() {
        SSL_NONE => "none",
        SSL_SELF_SIGNED => "self-signed",
        SSL_EXISTING => "existing",
        _ => "none",
    };
    out.push_str(&format!("ssl = \"{ssl}\"\n"));
    if ssl == "existing" {
        out.push_str(&format!("ssl_cert = \"{}\"\n", config.ssl_cert_path));
        out.push_str(&format!("ssl_key = \"{}\"\n", config.ssl_key_path));
    }
    let admin = match config.admin_did_mode.as_str() {
        ADMIN_GENERATE => "generate",
        ADMIN_SKIP => "skip",
        ADMIN_PASTE => "import",
        _ => "generate",
    };
    out.push_str(&format!("admin = \"{admin}\"\n"));
    let jwt_mode = match config.jwt_mode.as_str() {
        JWT_MODE_PROVIDE => "provide",
        _ => "generate",
    };
    out.push_str(&format!("jwt_mode = \"{jwt_mode}\"\n\n"));

    // Database — strip any embedded credentials
    out.push_str("[database]\n");
    let (redacted_url, had_credentials) = redact_url(&config.database_url);
    if had_credentials {
        out.push_str("# NOTE: Credentials were stripped from this URL for security.\n");
        out.push_str("# Set DATABASE_URL env var or update this value before running.\n");
    }
    out.push_str(&format!("url = \"{redacted_url}\"\n\n"));

    // Output
    out.push_str("[output]\n");
    out.push_str(&format!("config_path = \"{}\"\n", config.config_path));
    out.push_str(&format!("listen_address = \"{}\"\n", config.listen_address));
    out.push_str(&format!("api_prefix = \"{}\"\n\n", config.api_prefix));

    // Install (default: not enabled in recipe — user can enable manually)
    out.push_str("[install]\n");
    out.push_str("enabled = false\n");

    out
}

/// Apply a recipe's `secrets.storage` value to a [`WizardConfig`].
///
/// Accepts both the bare scheme (backward compat with pre-cloud-config
/// recipes — e.g. `aws_secrets://` with no body) and a fully-formed URL
/// (`aws_secrets://us-east-1/mediator/`). Full URLs are parsed via
/// `mediator-common`'s [`affinidi_messaging_mediator_common::parse_url`]
/// and the per-backend fields (region / project / vault / endpoint /
/// mount) are populated so a recipe replay restores the operator's full
/// choice without re-prompting.
///
/// Deprecated schemes (`string://`, `vta://`) error with a pointer to
/// the supported alternative.
fn apply_secrets_storage(raw: &str, config: &mut WizardConfig) -> anyhow::Result<()> {
    // Bare scheme (no body) — preserve the pre-cloud-config behaviour:
    // set `secret_storage` to the scheme, leave per-backend fields at
    // their wizard defaults. Operators upgrading from older recipes
    // see no surprise change.
    let bare_schemes = [
        STORAGE_FILE,
        STORAGE_KEYRING,
        STORAGE_AWS,
        STORAGE_GCP,
        STORAGE_AZURE,
        STORAGE_VAULT,
    ];
    if let Some(&scheme) = bare_schemes.iter().find(|&&s| raw == s) {
        config.secret_storage = scheme.into();
        return Ok(());
    }

    // Deprecated schemes — match before parse_url so the operator-facing
    // message points at the right replacement rather than a generic
    // parse error.
    if raw.starts_with(STORAGE_STRING) {
        anyhow::bail!(
            "secrets.storage '{}' is no longer supported — use '{}' (with optional encryption) instead",
            raw,
            STORAGE_FILE
        );
    }
    if raw.starts_with(STORAGE_VTA) {
        anyhow::bail!(
            "secrets.storage '{}' is no longer supported — VTA is a key source, not a backend; choose a real store ({}, {}, …)",
            raw,
            STORAGE_KEYRING,
            STORAGE_AWS
        );
    }

    // Full URL — let the shared parser handle each scheme's body and
    // surface its diagnostics verbatim. Splitting per-backend fields
    // here mirrors the wizard's own `enter_key_storage_phase` chain.
    use affinidi_messaging_mediator_common::secrets::{BackendUrl, parse_url};
    let parsed = parse_url(raw).map_err(|e| {
        anyhow::anyhow!(
            "Invalid secrets.storage '{}': {} (expected one of {}, {}, {}, {}, {}, {})",
            raw,
            e,
            STORAGE_FILE,
            STORAGE_KEYRING,
            STORAGE_AWS,
            STORAGE_GCP,
            STORAGE_AZURE,
            STORAGE_VAULT,
        )
    })?;
    match parsed {
        BackendUrl::File { path, encrypted } => {
            config.secret_storage = STORAGE_FILE.into();
            config.secret_file_path = path;
            config.secret_file_encrypted = encrypted;
        }
        BackendUrl::Keyring { service } => {
            config.secret_storage = STORAGE_KEYRING.into();
            config.secret_keyring_service = service;
        }
        BackendUrl::Aws { region, namespace } => {
            config.secret_storage = STORAGE_AWS.into();
            config.secret_aws_region = region;
            config.secret_aws_namespace = namespace;
        }
        BackendUrl::Gcp { project, namespace } => {
            config.secret_storage = STORAGE_GCP.into();
            config.secret_gcp_project = project;
            config.secret_gcp_namespace = namespace;
        }
        BackendUrl::Azure { vault } => {
            config.secret_storage = STORAGE_AZURE.into();
            // The mediator-common parser canonicalises bare names to
            // `https://<name>.vault.azure.net`. Round-tripping the full
            // URL is fine — it stays canonical when re-parsed.
            config.secret_azure_vault = vault;
        }
        BackendUrl::Vault { endpoint, path } => {
            config.secret_storage = STORAGE_VAULT.into();
            config.secret_vault_endpoint = endpoint;
            config.secret_vault_mount = path;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_redact_url_no_credentials() {
        let (url, had) = redact_url("redis://127.0.0.1/");
        assert_eq!(url, "redis://127.0.0.1/");
        assert!(!had);
    }

    #[test]
    fn test_redact_url_password_only() {
        let (url, had) = redact_url("redis://:secret@host:6379/");
        assert!(!url.contains("secret"));
        assert!(url.contains("host:6379"));
        assert!(had);
    }

    #[test]
    fn test_redact_url_user_and_password() {
        let (url, had) = redact_url("redis://admin:s3cret@db.example.com:6379/2");
        assert!(!url.contains("admin"));
        assert!(!url.contains("s3cret"));
        assert!(url.contains("db.example.com"));
        assert!(url.contains("/2"));
        assert!(had);
    }

    #[test]
    fn test_recipe_strips_credentials() {
        let config = WizardConfig {
            database_url: "redis://user:p4ssw0rd@prod-redis.example.com:6379/1".into(),
            ..WizardConfig::default()
        };
        let recipe = from_wizard_config(&config);
        assert!(!recipe.contains("p4ssw0rd"), "password leaked into recipe");
        assert!(!recipe.contains("user:"), "username leaked into recipe");
        assert!(recipe.contains("prod-redis.example.com"));
        assert!(recipe.contains("Credentials were stripped"));
    }

    // ── needs_database_credentials ─────────────────────────────────────

    #[test]
    fn test_needs_credentials_placeholders() {
        assert!(needs_database_credentials("redis://<host>:6379/"));
        assert!(needs_database_credentials("redis://${DB_HOST}/"));
        assert!(needs_database_credentials("$DATABASE_URL"));
    }

    #[test]
    fn test_needs_credentials_normal_url() {
        assert!(!needs_database_credentials("redis://127.0.0.1/"));
        assert!(!needs_database_credentials("redis://prod-host:6379/2"));
    }

    // ── to_wizard_config validation ────────────────────────────────────

    fn minimal_recipe() -> BuildRecipe {
        BuildRecipe {
            deployment: DeploymentSection {
                deployment_type: "local".into(),
                protocols: vec!["didcomm".into()],
                use_vta: false,
                vta_mode: None,
            },
            identity: IdentitySection::default(),
            secrets: SecretsSection::default(),
            security: SecuritySection::default(),
            database: DatabaseSection::default(),
            storage: StorageSection::default(),
            output: OutputSection::default(),
            install: InstallSection::default(),
            vta: VtaSection::default(),
        }
    }

    #[test]
    fn test_valid_recipe_converts() {
        let config = to_wizard_config(&minimal_recipe()).unwrap();
        assert_eq!(config.deployment_type, DEPLOYMENT_LOCAL);
        assert!(config.didcomm_enabled);
        assert!(!config.tsp_enabled);
        assert_eq!(config.did_method, DID_VTA);
        // Default backend is now keyring:// (vta:// rejected as a store).
        assert_eq!(config.secret_storage, STORAGE_KEYRING);
    }

    #[test]
    fn test_all_deployment_types() {
        for (input, expected) in [
            ("local", DEPLOYMENT_LOCAL),
            ("server", DEPLOYMENT_SERVER),
            ("container", DEPLOYMENT_CONTAINER),
        ] {
            let mut recipe = minimal_recipe();
            recipe.deployment.deployment_type = input.into();
            let config = to_wizard_config(&recipe).unwrap();
            assert_eq!(config.deployment_type, expected);
        }
    }

    #[test]
    fn test_invalid_deployment_type_errors() {
        let mut recipe = minimal_recipe();
        recipe.deployment.deployment_type = "cloud".into();
        assert!(to_wizard_config(&recipe).is_err());
    }

    #[test]
    fn test_both_protocols() {
        let mut recipe = minimal_recipe();
        recipe.deployment.protocols = vec!["didcomm".into(), "tsp".into()];
        let config = to_wizard_config(&recipe).unwrap();
        assert!(config.didcomm_enabled);
        assert!(config.tsp_enabled);
    }

    #[test]
    fn test_no_protocols_errors() {
        let mut recipe = minimal_recipe();
        recipe.deployment.protocols = vec![];
        assert!(to_wizard_config(&recipe).is_err());
    }

    #[test]
    fn test_invalid_protocol_errors() {
        let mut recipe = minimal_recipe();
        recipe.deployment.protocols = vec!["grpc".into()];
        assert!(to_wizard_config(&recipe).is_err());
    }

    #[test]
    fn test_all_did_methods() {
        for (input, expected) in [
            ("vta", DID_VTA),
            ("did:peer", DID_PEER),
            ("peer", DID_PEER),
            ("did:webvh", DID_WEBVH),
            ("webvh", DID_WEBVH),
            ("import", DID_IMPORT),
        ] {
            let mut recipe = minimal_recipe();
            recipe.identity.did_method = input.into();
            if expected == DID_WEBVH {
                recipe.identity.public_url = Some("https://example.com".into());
            }
            let config = to_wizard_config(&recipe).unwrap();
            assert_eq!(config.did_method, expected, "input: {input}");
        }
    }

    #[test]
    fn test_webvh_requires_public_url() {
        let mut recipe = minimal_recipe();
        recipe.identity.did_method = "did:webvh".into();
        recipe.identity.public_url = None;
        assert!(to_wizard_config(&recipe).is_err());
    }

    #[test]
    fn test_all_secret_storage_schemes() {
        // Accepted schemes only — `string://` and `vta://` are rejected
        // by the recipe loader (covered separately in
        // `test_legacy_secret_storage_schemes_rejected`).
        for scheme in [
            STORAGE_FILE,
            STORAGE_KEYRING,
            STORAGE_AWS,
            STORAGE_GCP,
            STORAGE_AZURE,
            STORAGE_VAULT,
        ] {
            let mut recipe = minimal_recipe();
            recipe.secrets.storage = scheme.into();
            let config = to_wizard_config(&recipe).unwrap();
            assert_eq!(config.secret_storage, scheme);
        }
    }

    #[test]
    fn test_legacy_secret_storage_schemes_rejected() {
        for scheme in [STORAGE_STRING, STORAGE_VTA] {
            let mut recipe = minimal_recipe();
            recipe.secrets.storage = scheme.into();
            let err = to_wizard_config(&recipe)
                .err()
                .unwrap_or_else(|| panic!("scheme {scheme} should have been rejected"))
                .to_string();
            assert!(
                err.contains("no longer supported"),
                "expected rejection for {scheme}, got: {err}"
            );
        }
    }

    #[test]
    fn test_invalid_secret_storage_errors() {
        let mut recipe = minimal_recipe();
        recipe.secrets.storage = "dropbox://".into();
        assert!(to_wizard_config(&recipe).is_err());
    }

    #[test]
    fn test_full_url_round_trip_for_each_cloud_backend() {
        // A full URL in `secrets.storage` populates the per-backend
        // fields so a recipe replay restores region / project / vault /
        // endpoint without re-prompting the operator. Mirrors the
        // wizard's own `enter_key_storage_phase` chain.
        let mut recipe = minimal_recipe();
        recipe.secrets.storage = "aws_secrets://eu-west-2/prod/mediator/".into();
        let config = to_wizard_config(&recipe).unwrap();
        assert_eq!(config.secret_storage, STORAGE_AWS);
        assert_eq!(config.secret_aws_region, "eu-west-2");
        assert_eq!(config.secret_aws_namespace, "prod/mediator/");

        recipe.secrets.storage = "gcp_secrets://my-prod-proj/svc-".into();
        let config = to_wizard_config(&recipe).unwrap();
        assert_eq!(config.secret_storage, STORAGE_GCP);
        assert_eq!(config.secret_gcp_project, "my-prod-proj");
        assert_eq!(config.secret_gcp_namespace, "svc-");

        recipe.secrets.storage = "azure_keyvault://my-prod-vault".into();
        let config = to_wizard_config(&recipe).unwrap();
        assert_eq!(config.secret_storage, STORAGE_AZURE);
        // Bare names canonicalise to the full URL via mediator-common's
        // parser — round-tripping through the recipe preserves the
        // canonical form.
        assert_eq!(
            config.secret_azure_vault,
            "https://my-prod-vault.vault.azure.net"
        );

        recipe.secrets.storage = "vault://vault.internal:8200/secret/prod-mediator".into();
        let config = to_wizard_config(&recipe).unwrap();
        assert_eq!(config.secret_storage, STORAGE_VAULT);
        assert_eq!(config.secret_vault_endpoint, "vault.internal:8200");
        assert_eq!(config.secret_vault_mount, "secret/prod-mediator");
    }

    #[test]
    fn test_bare_scheme_keeps_defaults_for_backward_compat() {
        // Pre-cloud-config recipes wrote just the bare scheme. Loading
        // those still works — the per-backend fields keep their
        // wizard defaults rather than failing the parse.
        let mut recipe = minimal_recipe();
        recipe.secrets.storage = STORAGE_GCP.into();
        let config = to_wizard_config(&recipe).unwrap();
        assert_eq!(config.secret_storage, STORAGE_GCP);
        assert_eq!(config.secret_gcp_project, DEFAULT_GCP_PROJECT);
        assert_eq!(config.secret_gcp_namespace, DEFAULT_GCP_SECRET_NAMESPACE);
    }

    #[test]
    fn test_ssl_existing_requires_paths() {
        let mut recipe = minimal_recipe();
        recipe.security.ssl = "existing".into();
        recipe.security.ssl_cert = None;
        recipe.security.ssl_key = None;
        assert!(to_wizard_config(&recipe).is_err());

        recipe.security.ssl_cert = Some("/path/cert.pem".into());
        assert!(to_wizard_config(&recipe).is_err()); // still missing key

        recipe.security.ssl_key = Some("/path/key.pem".into());
        let config = to_wizard_config(&recipe).unwrap();
        assert_eq!(config.ssl_cert_path, "/path/cert.pem");
        assert_eq!(config.ssl_key_path, "/path/key.pem");
    }

    // ── from_wizard_config round-trip ──────────────────────────────────

    #[test]
    fn test_recipe_round_trip() {
        let original = WizardConfig {
            config_path: "conf/mediator.toml".into(),
            deployment_type: DEPLOYMENT_SERVER.into(),
            use_vta: false,
            vta_mode: String::new(),
            didcomm_enabled: true,
            tsp_enabled: true,
            did_method: DID_PEER.into(),
            public_url: String::new(),
            secret_storage: STORAGE_KEYRING.into(),
            ssl_mode: SSL_NONE.into(),
            ssl_cert_path: String::new(),
            ssl_key_path: String::new(),
            database_url: "redis://127.0.0.1/3".into(),
            admin_did_mode: ADMIN_SKIP.into(),
            listen_address: "0.0.0.0:8080".into(),
            ..WizardConfig::default()
        };

        let recipe_toml = from_wizard_config(&original);
        let parsed: BuildRecipe = toml::from_str(&recipe_toml).unwrap();
        let restored = to_wizard_config(&parsed).unwrap();

        assert_eq!(restored.deployment_type, original.deployment_type);
        assert_eq!(restored.didcomm_enabled, original.didcomm_enabled);
        assert_eq!(restored.tsp_enabled, original.tsp_enabled);
        assert_eq!(restored.did_method, original.did_method);
        assert_eq!(restored.secret_storage, original.secret_storage);
        assert_eq!(restored.ssl_mode, original.ssl_mode);
        assert_eq!(restored.database_url, original.database_url);
        assert_eq!(restored.config_path, original.config_path);
        assert_eq!(restored.listen_address, original.listen_address);
        assert_eq!(restored.use_vta, original.use_vta);
    }

    #[test]
    fn test_vta_mode_values_and_legacy_alias() {
        // Canonical split: `sealed-mint` / `sealed-export` / `online`.
        // Legacy `"sealed"` (pre-split) normalises silently to
        // `sealed-mint` because that was the only interpretation
        // before the split landed.
        let mut recipe = minimal_recipe();
        recipe.deployment.use_vta = true;
        recipe.identity.public_url = Some("https://mediator.example.com".into());

        for raw in ["sealed-mint", "sealed-export", "online"] {
            recipe.deployment.vta_mode = Some(raw.into());
            let cfg = to_wizard_config(&recipe).unwrap();
            assert_eq!(cfg.vta_mode, raw);
        }

        recipe.deployment.vta_mode = Some("sealed".into());
        let cfg = to_wizard_config(&recipe).unwrap();
        assert_eq!(
            cfg.vta_mode, VTA_MODE_SEALED_MINT,
            "legacy `sealed` normalises to `sealed-mint`"
        );

        recipe.deployment.vta_mode = Some("cold-start".into());
        let err = to_wizard_config(&recipe).unwrap_err().to_string();
        assert!(
            err.contains("Invalid deployment.vta_mode"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_sealed_mint_requires_public_url() {
        let mut recipe = minimal_recipe();
        recipe.deployment.use_vta = true;
        recipe.deployment.vta_mode = Some(VTA_MODE_SEALED_MINT.into());
        // public_url omitted → rejected
        let err = to_wizard_config(&recipe).unwrap_err().to_string();
        assert!(
            err.contains("requires identity.public_url"),
            "unexpected error: {err}"
        );
        // public_url present → accepted
        recipe.identity.public_url = Some("https://mediator.example.com".into());
        let cfg = to_wizard_config(&recipe).unwrap();
        assert_eq!(cfg.vta_mode, VTA_MODE_SEALED_MINT);
    }

    #[test]
    fn test_vta_section_round_trips_through_recipe() {
        // Non-default context + webvh fields must be written to the
        // recipe text AND parsed back into the matching wizard
        // config fields. Defaults are elided so the recipe text
        // stays lean.
        let original = WizardConfig {
            use_vta: true,
            vta_mode: VTA_MODE_SEALED_MINT.into(),
            vta_context: "prod-mediator".into(),
            did_method: DID_VTA.into(),
            public_url: "https://mediator.example.com".into(),
            secret_storage: STORAGE_KEYRING.into(),
            admin_did_mode: ADMIN_VTA.into(),
            vta_webvh_server_id: Some("prod-1".into()),
            vta_webvh_mnemonic: Some("mediator/v1".into()),
            ..WizardConfig::default()
        };

        let recipe_toml = from_wizard_config(&original);
        assert!(recipe_toml.contains("[vta]"));
        assert!(recipe_toml.contains("context = \"prod-mediator\""));
        assert!(recipe_toml.contains("webvh_server = \"prod-1\""));
        assert!(recipe_toml.contains("webvh_path = \"mediator/v1\""));

        let parsed: BuildRecipe = toml::from_str(&recipe_toml).unwrap();
        let restored = to_wizard_config(&parsed).unwrap();
        assert_eq!(restored.vta_context, "prod-mediator");
        assert_eq!(restored.vta_webvh_server_id.as_deref(), Some("prod-1"));
        assert_eq!(restored.vta_webvh_mnemonic.as_deref(), Some("mediator/v1"));
    }

    #[test]
    fn test_vta_section_omitted_on_defaults() {
        // Default context + no webvh pins → no `[vta]` in recipe
        // output, keeping the TOML small for the common case.
        let original = WizardConfig {
            use_vta: true,
            vta_mode: VTA_MODE_ONLINE.into(),
            did_method: DID_VTA.into(),
            ..WizardConfig::default()
        };
        let recipe_toml = from_wizard_config(&original);
        assert!(!recipe_toml.contains("[vta]"));
    }

    #[test]
    fn test_recipe_round_trip_with_vta() {
        // VTA-managed DID with a real secret backend (keyring) — vta:// is
        // no longer a valid storage scheme, so the round-trip exercises
        // the new shape: VTA for *identity*, unified backend for *keys*.
        let original = WizardConfig {
            use_vta: true,
            vta_mode: VTA_MODE_ONLINE.into(),
            did_method: DID_VTA.into(),
            secret_storage: STORAGE_KEYRING.into(),
            admin_did_mode: ADMIN_VTA.into(),
            ..WizardConfig::default()
        };

        let recipe_toml = from_wizard_config(&original);
        assert!(recipe_toml.contains("use_vta = true"));
        assert!(recipe_toml.contains("vta_mode = \"online\""));

        let parsed: BuildRecipe = toml::from_str(&recipe_toml).unwrap();
        let restored = to_wizard_config(&parsed).unwrap();

        assert!(restored.use_vta);
        assert_eq!(restored.vta_mode, VTA_MODE_ONLINE);
        assert_eq!(restored.did_method, DID_VTA);
        assert_eq!(restored.secret_storage, STORAGE_KEYRING);
    }

    #[test]
    fn test_backward_compat_infers_vta() {
        // Old recipe without use_vta but with VTA-managed DID — the
        // loader still infers `use_vta = true`. (The old `secrets.storage
        // = "vta://"` trigger is gone — that scheme is now rejected.)
        let mut recipe = minimal_recipe();
        recipe.identity.did_method = "vta".into();
        let config = to_wizard_config(&recipe).unwrap();
        assert!(config.use_vta, "should auto-detect VTA from did_method");
        assert_eq!(config.vta_mode, VTA_MODE_ONLINE);
    }
}
