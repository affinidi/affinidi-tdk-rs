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
}

fn default_protocols() -> Vec<String> {
    vec!["didcomm".into()]
}

#[derive(Debug, Default, Deserialize)]
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

#[derive(Debug, Default, Deserialize)]
pub struct SecretsSection {
    /// `string://`, `file://`, `keyring://`, `aws_secrets://`,
    /// `gcp_secrets://`, `azure_keyvault://`, `vault://`, or `vta://`
    #[serde(default = "default_storage")]
    pub storage: String,
}

fn default_storage() -> String {
    "vta://".into()
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
}

fn default_ssl() -> String {
    "none".into()
}

fn default_admin() -> String {
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
        "local" => "Local development".into(),
        "server" => "Headless server".into(),
        "container" => "Container".into(),
        other => anyhow::bail!(
            "Invalid deployment.type '{}': expected 'local', 'server', or 'container'",
            other
        ),
    };

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
        "vta" => "VTA managed".into(),
        "did:peer" | "peer" => "did:peer".into(),
        "did:webvh" | "webvh" => "did:webvh".into(),
        "import" => "Import existing".into(),
        other => anyhow::bail!(
            "Invalid identity.did_method '{}': expected 'vta', 'did:peer', 'did:webvh', or 'import'",
            other
        ),
    };

    if config.did_method == "did:webvh" {
        config.public_url = recipe.identity.public_url.clone().ok_or_else(|| {
            anyhow::anyhow!("identity.public_url is required when did_method = 'did:webvh'")
        })?;
    } else if let Some(ref url) = recipe.identity.public_url {
        config.public_url = url.clone();
    }

    // Secrets
    config.secret_storage = match recipe.secrets.storage.as_str() {
        s @ ("string://" | "file://" | "keyring://" | "aws_secrets://" | "gcp_secrets://"
        | "azure_keyvault://" | "vault://" | "vta://") => s.to_string(),
        other => anyhow::bail!(
            "Invalid secrets.storage '{}': expected a valid scheme (string://, file://, keyring://, aws_secrets://, gcp_secrets://, azure_keyvault://, vault://, vta://)",
            other
        ),
    };

    // Security
    config.ssl_mode = match recipe.security.ssl.as_str() {
        "none" => "No SSL (TLS proxy)".into(),
        "self-signed" | "self_signed" => "Self-signed".into(),
        "existing" => {
            config.ssl_cert_path = recipe.security.ssl_cert.clone().ok_or_else(|| {
                anyhow::anyhow!("security.ssl_cert is required when ssl = 'existing'")
            })?;
            config.ssl_key_path = recipe.security.ssl_key.clone().ok_or_else(|| {
                anyhow::anyhow!("security.ssl_key is required when ssl = 'existing'")
            })?;
            "Existing certificates".into()
        }
        other => anyhow::bail!(
            "Invalid security.ssl '{}': expected 'none', 'self-signed', or 'existing'",
            other
        ),
    };

    config.admin_did_mode = match recipe.security.admin.as_str() {
        "generate" => "Generate did:key".into(),
        "skip" => "Skip".into(),
        "import" => {
            // TODO: handle imported admin DID
            "Paste existing".into()
        }
        other => anyhow::bail!(
            "Invalid security.admin '{}': expected 'generate', 'skip', or 'import'",
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
        "Local development" => "local",
        "Headless server" => "server",
        "Container" => "container",
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
    out.push_str(&format!("protocols = [{}]\n\n", protocols.join(", ")));

    // Identity
    out.push_str("[identity]\n");
    let did_method = match config.did_method.as_str() {
        "VTA managed" => "vta",
        "did:peer" => "did:peer",
        "did:webvh" => "did:webvh",
        "Import existing" => "import",
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
        "No SSL (TLS proxy)" => "none",
        "Self-signed" => "self-signed",
        "Existing certificates" => "existing",
        _ => "none",
    };
    out.push_str(&format!("ssl = \"{ssl}\"\n"));
    if ssl == "existing" {
        out.push_str(&format!("ssl_cert = \"{}\"\n", config.ssl_cert_path));
        out.push_str(&format!("ssl_key = \"{}\"\n", config.ssl_key_path));
    }
    let admin = match config.admin_did_mode.as_str() {
        "Generate did:key" => "generate",
        "Skip" => "skip",
        "Paste existing" => "import",
        _ => "generate",
    };
    out.push_str(&format!("admin = \"{admin}\"\n\n"));

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
}
