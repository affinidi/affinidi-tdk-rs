use std::{fs, path::Path};

use affinidi_secrets_resolver::secrets::Secret;
use toml_edit::DocumentMut;

use crate::app::WizardConfig;

/// Generated cryptographic material from the wizard generators.
pub struct GeneratedValues {
    /// The mediator's DID string (did:peer:..., vta://..., etc.)
    pub mediator_did: String,
    /// Secrets for the mediator DID
    pub mediator_secrets: Vec<Secret>,
    /// JWT signing secret (base64url-encoded)
    pub jwt_secret: String,
    /// Admin DID (if generated)
    pub admin_did: Option<String>,
    /// Admin secret (if generated — displayed to user, not stored in config)
    #[allow(dead_code)] // read in main.rs, not by config_writer
    pub admin_secret: Option<Secret>,
    /// SSL cert path (if self-signed was generated)
    pub ssl_cert_path: Option<String>,
    /// SSL key path (if self-signed was generated)
    pub ssl_key_path: Option<String>,
}

/// The default mediator.toml template, embedded at compile time.
/// This is the authoritative source of all config fields and their defaults.
const DEFAULT_TEMPLATE: &str = include_str!("../../../conf/mediator.toml");

/// Write the mediator configuration file and any associated secret files.
pub fn write_config(config: &WizardConfig, generated: &GeneratedValues) -> anyhow::Result<()> {
    let toml_content = generate_toml(config, generated)?;

    // Ensure parent directory exists
    let path = Path::new(&config.config_path);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    fs::write(path, &toml_content)?;

    // Write secrets file if using file:// storage
    if config.secret_storage == "file://" {
        let secrets_path = config_dir(config).join("secrets.json");
        crate::generators::secrets::write_secrets_file(
            &generated.mediator_secrets,
            &secrets_path.to_string_lossy(),
        )?;
    }

    Ok(())
}

/// Get the config directory from the config path.
fn config_dir(config: &WizardConfig) -> std::path::PathBuf {
    Path::new(&config.config_path)
        .parent()
        .unwrap_or(Path::new("."))
        .to_path_buf()
}

/// Parse the default template and patch in wizard-generated values.
fn generate_toml(config: &WizardConfig, generated: &GeneratedValues) -> anyhow::Result<String> {
    let mut doc: DocumentMut = DEFAULT_TEMPLATE
        .parse()
        .map_err(|e| anyhow::anyhow!("Failed to parse default config template: {e}"))?;

    // ── Top-level fields ───────────────────────────────────────────────
    doc["mediator_did"] = toml_edit::value(format!("did://{}", generated.mediator_did));

    // VTA section — update or remove based on config
    if config.did_method == "VTA managed" || config.secret_storage == "vta://" {
        // Keep [vta] section, update context
        if let Some(vta) = doc.get_mut("vta") {
            vta["credential"] = toml_edit::value("keyring://affinidi-mediator/vta-credential");
            vta["context"] = toml_edit::value("mediator");
        }
    } else {
        // Remove [vta] section entirely
        doc.remove("vta");
    }

    // ── [server] ───────────────────────────────────────────────────────
    if let Some(server) = doc.get_mut("server") {
        server["listen_address"] = toml_edit::value(&config.listen_address);

        if let Some(ref admin_did) = generated.admin_did {
            server["admin_did"] = toml_edit::value(format!("did://{admin_did}"));
        } else {
            // Comment out admin_did
            server.as_table_like_mut().map(|t| t.remove("admin_did"));
        }

        // Self-hosted DID document
        if config.did_method == "did:webvh" {
            server["did_web_self_hosted"] = toml_edit::value("file://./conf/mediator_did.json");
        } else {
            server
                .as_table_like_mut()
                .map(|t| t.remove("did_web_self_hosted"));
        }
    }

    // ── [database] ─────────────────────────────────────────────────────
    if let Some(db) = doc.get_mut("database") {
        db["database_url"] = toml_edit::value(&config.database_url);
    }

    // ── [security] ─────────────────────────────────────────────────────
    if let Some(sec) = doc.get_mut("security") {
        // Mediator secrets reference
        let secrets_ref = match config.secret_storage.as_str() {
            "string://" => {
                let b64 =
                    crate::generators::secrets::secrets_to_base64(&generated.mediator_secrets)?;
                format!("string://{b64}")
            }
            "file://" => "file://./conf/secrets.json".into(),
            "keyring://" => "keyring://affinidi-mediator/secrets".into(),
            "aws_secrets://" => "aws_secrets://mediator/secrets".into(),
            "gcp_secrets://" => "gcp_secrets://mediator/secrets".into(),
            "azure_keyvault://" => "azure_keyvault://mediator-secrets".into(),
            "vault://" => "vault://secret/mediator/secrets".into(),
            "vta://" => "vta://mediator".into(),
            other => other.to_string(),
        };
        sec["mediator_secrets"] = toml_edit::value(&secrets_ref);

        // SSL
        match config.ssl_mode.as_str() {
            "No SSL (TLS proxy)" => {
                sec["use_ssl"] = toml_edit::value("false");
            }
            "Existing certificates" => {
                sec["use_ssl"] = toml_edit::value("true");
                sec["ssl_certificate_file"] = toml_edit::value(&config.ssl_cert_path);
                sec["ssl_key_file"] = toml_edit::value(&config.ssl_key_path);
            }
            "Self-signed" => {
                sec["use_ssl"] = toml_edit::value("true");
                let cert = generated
                    .ssl_cert_path
                    .as_deref()
                    .unwrap_or("conf/keys/end.cert");
                let key = generated
                    .ssl_key_path
                    .as_deref()
                    .unwrap_or("conf/keys/end.key");
                sec["ssl_certificate_file"] = toml_edit::value(cert);
                sec["ssl_key_file"] = toml_edit::value(key);
            }
            _ => {
                sec["use_ssl"] = toml_edit::value("false");
            }
        }

        // JWT
        sec["jwt_authorization_secret"] =
            toml_edit::value(format!("string://{}", generated.jwt_secret));
    }

    Ok(doc.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_generated() -> GeneratedValues {
        GeneratedValues {
            mediator_did: "did:peer:2.Vtest.Etest".into(),
            mediator_secrets: vec![],
            jwt_secret: "test_jwt_secret_base64url".into(),
            admin_did: Some("did:key:z6MkTest".into()),
            admin_secret: None,
            ssl_cert_path: None,
            ssl_key_path: None,
        }
    }

    #[test]
    fn test_generate_toml_preserves_all_fields() {
        let config = WizardConfig {
            config_path: "conf/mediator.toml".into(),
            deployment_type: "Local development".into(),
            didcomm_enabled: true,
            tsp_enabled: false,
            did_method: "did:peer".into(),
            public_url: String::new(),
            secret_storage: "string://".into(),
            ssl_mode: "No SSL (TLS proxy)".into(),
            ssl_cert_path: String::new(),
            ssl_key_path: String::new(),
            database_url: "redis://127.0.0.1/".into(),
            admin_did_mode: "Generate did:key".into(),
            listen_address: "0.0.0.0:7037".into(),
        };

        let toml = generate_toml(&config, &test_generated()).unwrap();

        // Verify wizard-set values
        assert!(toml.contains("mediator_did = \"did://did:peer:2.Vtest.Etest\""));
        assert!(toml.contains("use_ssl = \"false\""));
        assert!(toml.contains("database_url = \"redis://127.0.0.1/\""));
        assert!(toml.contains("admin_did = \"did://did:key:z6MkTest\""));
        assert!(toml.contains("jwt_authorization_secret = \"string://test_jwt_secret_base64url\""));

        // Verify fields from template that wizard doesn't touch are preserved
        assert!(toml.contains("database_pool_size"));
        assert!(toml.contains("database_timeout"));
        assert!(toml.contains("[streaming]"));
        assert!(toml.contains("[did_resolver]"));
        assert!(toml.contains("[limits]"));
        assert!(toml.contains("[processors.forwarding]"));
        assert!(toml.contains("[processors.message_expiry_cleanup]"));
        assert!(toml.contains("block_anonymous_outer_envelope"));
        assert!(toml.contains("force_session_did_match"));

        // VTA section should be removed for did:peer —
        // check that the section header line is gone (credential/context fields removed)
        assert!(!toml.contains("credential = "));
        assert!(!toml.contains("context = "));
    }

    #[test]
    fn test_generate_toml_vta() {
        let config = WizardConfig {
            config_path: "conf/mediator.toml".into(),
            deployment_type: "Headless server".into(),
            didcomm_enabled: true,
            tsp_enabled: false,
            did_method: "VTA managed".into(),
            public_url: String::new(),
            secret_storage: "vta://".into(),
            ssl_mode: "No SSL (TLS proxy)".into(),
            ssl_cert_path: String::new(),
            ssl_key_path: String::new(),
            database_url: "redis://redis.example.com/".into(),
            admin_did_mode: "Generate did:key".into(),
            listen_address: "0.0.0.0:7037".into(),
        };

        let generated = GeneratedValues {
            mediator_did: "vta://mediator".into(),
            mediator_secrets: vec![],
            jwt_secret: "test_jwt".into(),
            admin_did: Some("did:key:z6MkTest".into()),
            admin_secret: None,
            ssl_cert_path: None,
            ssl_key_path: None,
        };

        let toml = generate_toml(&config, &generated).unwrap();
        assert!(toml.contains("[vta]"));
        assert!(toml.contains("mediator_secrets = \"vta://mediator\""));
        assert!(toml.contains("database_url = \"redis://redis.example.com/\""));
    }

    #[test]
    fn test_ssl_self_signed() {
        let config = WizardConfig {
            ssl_mode: "Self-signed".into(),
            did_method: "did:peer".into(),
            secret_storage: "string://".into(),
            ..WizardConfig::default()
        };
        let generated = GeneratedValues {
            ssl_cert_path: Some("conf/keys/end.cert".into()),
            ssl_key_path: Some("conf/keys/end.key".into()),
            ..test_generated()
        };
        let toml = generate_toml(&config, &generated).unwrap();
        assert!(toml.contains("use_ssl = \"true\""));
        assert!(toml.contains("ssl_certificate_file = \"conf/keys/end.cert\""));
        assert!(toml.contains("ssl_key_file = \"conf/keys/end.key\""));
    }

    #[test]
    fn test_ssl_existing_certificates() {
        let config = WizardConfig {
            ssl_mode: "Existing certificates".into(),
            ssl_cert_path: "/etc/ssl/cert.pem".into(),
            ssl_key_path: "/etc/ssl/key.pem".into(),
            did_method: "did:peer".into(),
            secret_storage: "string://".into(),
            ..WizardConfig::default()
        };
        let toml = generate_toml(&config, &test_generated()).unwrap();
        assert!(toml.contains("use_ssl = \"true\""));
        assert!(toml.contains("ssl_certificate_file = \"/etc/ssl/cert.pem\""));
        assert!(toml.contains("ssl_key_file = \"/etc/ssl/key.pem\""));
    }

    #[test]
    fn test_no_admin_did_removes_field() {
        let config = WizardConfig {
            admin_did_mode: "Skip".into(),
            did_method: "did:peer".into(),
            secret_storage: "string://".into(),
            ..WizardConfig::default()
        };
        let generated = GeneratedValues {
            admin_did: None,
            admin_secret: None,
            ..test_generated()
        };
        let toml = generate_toml(&config, &generated).unwrap();
        // admin_did should not appear as a key=value (may appear in comments)
        assert!(!toml.contains("admin_did = \"did://"));
    }

    #[test]
    fn test_webvh_includes_self_hosted() {
        let config = WizardConfig {
            did_method: "did:webvh".into(),
            secret_storage: "string://".into(),
            ..WizardConfig::default()
        };
        let toml = generate_toml(&config, &test_generated()).unwrap();
        assert!(toml.contains("did_web_self_hosted = \"file://./conf/mediator_did.json\""));
    }

    #[test]
    fn test_non_webvh_removes_self_hosted() {
        let config = WizardConfig {
            did_method: "did:peer".into(),
            secret_storage: "string://".into(),
            ..WizardConfig::default()
        };
        let toml = generate_toml(&config, &test_generated()).unwrap();
        // should not have did_web_self_hosted as a key=value
        assert!(!toml.contains("did_web_self_hosted = \"file://"));
    }

    #[test]
    fn test_all_secret_storage_refs() {
        let cases = [
            ("file://", "file://./conf/secrets.json"),
            ("keyring://", "keyring://affinidi-mediator/secrets"),
            ("aws_secrets://", "aws_secrets://mediator/secrets"),
            ("gcp_secrets://", "gcp_secrets://mediator/secrets"),
            ("azure_keyvault://", "azure_keyvault://mediator-secrets"),
            ("vault://", "vault://secret/mediator/secrets"),
            ("vta://", "vta://mediator"),
        ];
        for (storage, expected_ref) in cases {
            let config = WizardConfig {
                did_method: "did:peer".into(),
                secret_storage: storage.into(),
                ..WizardConfig::default()
            };
            let toml = generate_toml(&config, &test_generated()).unwrap();
            assert!(
                toml.contains(&format!("mediator_secrets = \"{expected_ref}\"")),
                "storage={storage}: expected {expected_ref} in output"
            );
        }
    }

    #[test]
    fn test_listen_address_set() {
        let config = WizardConfig {
            listen_address: "127.0.0.1:9090".into(),
            did_method: "did:peer".into(),
            secret_storage: "string://".into(),
            ..WizardConfig::default()
        };
        let toml = generate_toml(&config, &test_generated()).unwrap();
        assert!(toml.contains("listen_address = \"127.0.0.1:9090\""));
    }
}
