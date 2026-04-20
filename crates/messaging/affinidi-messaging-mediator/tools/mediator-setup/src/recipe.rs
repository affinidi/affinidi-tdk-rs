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
    #[serde(default)]
    pub output: OutputSection,
    #[serde(default)]
    pub install: InstallSection,
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
    /// VTA connectivity mode: `"online"` or `"cold-start"`
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

#[derive(Debug, Deserialize)]
pub struct OutputSection {
    /// Path for the generated mediator.toml
    #[serde(default = "default_config_path")]
    pub config_path: String,
    /// Listen address for the mediator (ip:port)
    #[serde(default = "default_listen_address")]
    pub listen_address: String,
}

fn default_config_path() -> String {
    "conf/mediator.toml".into()
}

fn default_listen_address() -> String {
    "0.0.0.0:7037".into()
}

impl Default for OutputSection {
    fn default() -> Self {
        Self {
            config_path: default_config_path(),
            listen_address: default_listen_address(),
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
    config.vta_mode = recipe.deployment.vta_mode.clone().unwrap_or_default();

    // Auto-detect: if recipe uses VTA-managed DID but use_vta is missing
    // (backward compat). Note: `secrets.storage = "vta://"` is no longer
    // recognised — VTA is a *source* of keys, not a storage backend.
    if !config.use_vta && recipe.identity.did_method == "vta" {
        config.use_vta = true;
        if config.vta_mode.is_empty() {
            config.vta_mode = VTA_MODE_ONLINE.into();
        }
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

    // Secrets — `string://` and `vta://` are rejected. `string://` was
    // dropped (inline secrets in TOML are unsafe even for CI; use `file://`
    // with `MEDIATOR_SECRETS_BACKEND` env override). `vta://` was never a
    // store — the VTA is a key *source*; pick a real backend (keyring,
    // file, AWS, …) for the unified secret store.
    config.secret_storage = match recipe.secrets.storage.as_str() {
        s @ (STORAGE_FILE | STORAGE_KEYRING | STORAGE_AWS | STORAGE_GCP | STORAGE_AZURE
        | STORAGE_VAULT) => s.to_string(),
        STORAGE_STRING => anyhow::bail!(
            "secrets.storage '{}' is no longer supported — use '{}' (with optional encryption) instead",
            STORAGE_STRING,
            STORAGE_FILE
        ),
        STORAGE_VTA => anyhow::bail!(
            "secrets.storage '{}' is no longer supported — VTA is a key source, not a backend; choose a real store ({}, {}, …)",
            STORAGE_VTA,
            STORAGE_KEYRING,
            STORAGE_AWS
        ),
        other => anyhow::bail!(
            "Invalid secrets.storage '{}': expected one of {}, {}, {}, {}, {}, {}",
            other,
            STORAGE_FILE,
            STORAGE_KEYRING,
            STORAGE_AWS,
            STORAGE_GCP,
            STORAGE_AZURE,
            STORAGE_VAULT
        ),
    };

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

    // Output
    config.config_path = recipe.output.config_path.clone();
    config.listen_address = recipe.output.listen_address.clone();

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

    // Secrets
    out.push_str("[secrets]\n");
    out.push_str(&format!("storage = \"{}\"\n\n", config.secret_storage));

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
    out.push_str(&format!(
        "listen_address = \"{}\"\n\n",
        config.listen_address
    ));

    // Install (default: not enabled in recipe — user can enable manually)
    out.push_str("[install]\n");
    out.push_str("enabled = false\n");

    out
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
            output: OutputSection::default(),
            install: InstallSection::default(),
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
