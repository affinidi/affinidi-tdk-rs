use std::{fs, path::Path};

use affinidi_secrets_resolver::secrets::Secret;
use toml_edit::DocumentMut;

use crate::app::WizardConfig;
use crate::consts::*;

/// Generated cryptographic material from the wizard generators.
///
/// The TOML writer only consumes the fields that affect `mediator.toml`
/// itself (DID, admin DID, SSL paths). Operating keys, the JWT secret,
/// and the admin credential are pushed into the unified secret backend
/// by `main.rs::generate_and_write` and intentionally aren't surfaced
/// through `mediator.toml` at all.
pub struct GeneratedValues {
    /// The mediator's DID string (did:peer:..., did:webvh:..., or vta-minted)
    pub mediator_did: String,
    /// Secrets for the mediator DID — pushed into the unified backend
    /// under `mediator/operating/secrets`. Kept on this struct because
    /// the wizard's banner/finish summary reports the count.
    #[allow(dead_code)] // surfaced by main.rs, not config_writer
    pub mediator_secrets: Vec<Secret>,
    /// Raw PKCS8 bytes of the JWT signing key. `None` when the operator
    /// chose `provide` mode — the mediator then loads the key from
    /// `MEDIATOR_JWT_SECRET` / `--jwt-secret-file` at boot. Pushed into
    /// the unified backend by main.rs when present; never written to
    /// the config file.
    #[allow(dead_code)] // surfaced by main.rs, not config_writer
    pub jwt_secret: Option<Vec<u8>>,
    /// Admin DID (if generated). Written to `[server].admin_did`.
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

/// Redis Lua functions required by the mediator at runtime.
const ATM_FUNCTIONS_LUA: &str = include_str!("../../../conf/atm-functions.lua");

/// Write the mediator configuration file and any associated secret files.
pub fn write_config(config: &WizardConfig, generated: &GeneratedValues) -> anyhow::Result<()> {
    let toml_content = generate_toml(config, generated)?;

    // Ensure parent directory exists
    let path = Path::new(&config.config_path);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    fs::write(path, &toml_content)?;

    // Write the Redis Lua functions file alongside the config
    let lua_path = config_dir(config).join("atm-functions.lua");
    fs::write(&lua_path, ATM_FUNCTIONS_LUA)?;

    // Write secrets file if using file:// storage
    if config.secret_storage == STORAGE_FILE {
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

    // ── [secrets] ──────────────────────────────────────────────────────
    // Write the unified backend URL. The VTA session (if any) landed keys
    // under well-known names inside this backend via `generate_and_write`;
    // the mediator reads them at startup via `MediatorSecrets`.
    let backend_url = build_backend_url(config);
    if let Some(secrets_section) = doc.get_mut("secrets") {
        secrets_section["backend"] = toml_edit::value(&backend_url);
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
        if config.did_method == DID_WEBVH {
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
        // SSL
        match config.ssl_mode.as_str() {
            SSL_NONE => {
                sec["use_ssl"] = toml_edit::value("false");
            }
            SSL_EXISTING => {
                sec["use_ssl"] = toml_edit::value("true");
                sec["ssl_certificate_file"] = toml_edit::value(&config.ssl_cert_path);
                sec["ssl_key_file"] = toml_edit::value(&config.ssl_key_path);
            }
            SSL_SELF_SIGNED => {
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

        // JWT signing secret is no longer a config field — it lives in the
        // unified `[secrets]` backend under `mediator/jwt/secret`.
    }

    Ok(doc.to_string())
}

/// Construct the `[secrets].backend` URL from the wizard's per-backend
/// config choices. Mirrors the URL shape the mediator's `SecretStore`
/// parser accepts. `vta://` is no longer supported as a storage scheme —
/// when the operator has a VTA session, the admin credential goes into
/// whichever real backend they chose, not into the VTA itself.
///
/// Public so `generate_and_write` (in `main.rs`) can open the *same*
/// backend the mediator will read at startup before writing the config
/// file — that way provisioning failures surface to the operator rather
/// than only being discovered when the mediator next boots.
pub fn build_backend_url(config: &WizardConfig) -> String {
    match config.secret_storage.as_str() {
        STORAGE_FILE => {
            // Template default is `conf/secrets.json`; callers in
            // `generate_and_write` may extend this later via absolute
            // paths. Append `?encrypt=1` when the operator opted into
            // envelope encryption — the mediator's `open_store` parser
            // routes that flag to the AEAD-backed file store.
            if config.secret_file_encrypted {
                format!("file://{}?encrypt=1", config.secret_file_path)
            } else {
                format!("file://{}", config.secret_file_path)
            }
        }
        STORAGE_KEYRING => format!("keyring://{}", config.secret_keyring_service),
        STORAGE_AWS => format!(
            "aws_secrets://{}/{}",
            config.secret_aws_region, config.secret_aws_prefix
        ),
        STORAGE_GCP => "gcp_secrets://PROJECT/PREFIX".into(),
        STORAGE_AZURE => "azure_keyvault://VAULT".into(),
        STORAGE_VAULT => "vault://HOST/PATH".into(),
        // string:// is no longer supported by the mediator's SecretStore
        // URL parser; fall back to a keyring default and warn in stdout
        // during `generate_and_write`.
        STORAGE_STRING | STORAGE_VTA | _ => "keyring://affinidi-mediator".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_generated() -> GeneratedValues {
        GeneratedValues {
            mediator_did: "did:peer:2.Vtest.Etest".into(),
            mediator_secrets: vec![],
            jwt_secret: Some(b"test_jwt_secret_pkcs8".to_vec()),
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
            use_vta: false,
            vta_mode: String::new(),
            didcomm_enabled: true,
            tsp_enabled: false,
            did_method: DID_PEER.into(),
            public_url: String::new(),
            secret_storage: STORAGE_STRING.into(),
            ssl_mode: SSL_NONE.into(),
            ssl_cert_path: String::new(),
            ssl_key_path: String::new(),
            database_url: DEFAULT_REDIS_URL.into(),
            admin_did_mode: ADMIN_GENERATE.into(),
            listen_address: DEFAULT_LISTEN_ADDR.into(),
            ..WizardConfig::default()
        };

        let toml = generate_toml(&config, &test_generated()).unwrap();

        // Verify wizard-set values
        assert!(toml.contains("mediator_did = \"did://did:peer:2.Vtest.Etest\""));
        assert!(toml.contains("use_ssl = \"false\""));
        assert!(toml.contains("database_url = \"redis://127.0.0.1/\""));
        assert!(toml.contains("admin_did = \"did://did:key:z6MkTest\""));
        // JWT signing secret is now a well-known key in the backend, not a
        // config field.
        assert!(!toml.contains("jwt_authorization_secret"));
        assert!(toml.contains("[secrets]"));
        assert!(toml.contains("backend ="));

        // Verify fields from template that wizard doesn't touch are preserved
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
            use_vta: true,
            vta_mode: VTA_MODE_ONLINE.into(),
            didcomm_enabled: true,
            tsp_enabled: false,
            did_method: DID_VTA.into(),
            public_url: String::new(),
            secret_storage: STORAGE_VTA.into(),
            ssl_mode: SSL_NONE.into(),
            ssl_cert_path: String::new(),
            ssl_key_path: String::new(),
            database_url: "redis://redis.example.com/".into(),
            admin_did_mode: ADMIN_GENERATE.into(),
            listen_address: DEFAULT_LISTEN_ADDR.into(),
            ..WizardConfig::default()
        };

        let generated = GeneratedValues {
            mediator_did: "vta://mediator".into(),
            mediator_secrets: vec![],
            jwt_secret: Some(b"test_jwt".to_vec()),
            admin_did: Some("did:key:z6MkTest".into()),
            admin_secret: None,
            ssl_cert_path: None,
            ssl_key_path: None,
        };

        let toml = generate_toml(&config, &generated).unwrap();
        // `[secrets]` replaces the old `[vta]` + `mediator_secrets`
        // plumbing — the VTA session is recorded in the unified secret
        // backend via the admin credential, not as a config-file section.
        assert!(toml.contains("[secrets]"));
        assert!(toml.contains("backend ="));
        assert!(toml.contains("database_url = \"redis://redis.example.com/\""));
    }

    #[test]
    fn test_ssl_self_signed() {
        let config = WizardConfig {
            ssl_mode: SSL_SELF_SIGNED.into(),
            did_method: DID_PEER.into(),
            secret_storage: STORAGE_STRING.into(),
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
            ssl_mode: SSL_EXISTING.into(),
            ssl_cert_path: "/etc/ssl/cert.pem".into(),
            ssl_key_path: "/etc/ssl/key.pem".into(),
            did_method: DID_PEER.into(),
            secret_storage: STORAGE_STRING.into(),
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
            admin_did_mode: ADMIN_SKIP.into(),
            did_method: DID_PEER.into(),
            secret_storage: STORAGE_STRING.into(),
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
            did_method: DID_WEBVH.into(),
            secret_storage: STORAGE_STRING.into(),
            ..WizardConfig::default()
        };
        let toml = generate_toml(&config, &test_generated()).unwrap();
        assert!(toml.contains("did_web_self_hosted = \"file://./conf/mediator_did.json\""));
    }

    #[test]
    fn test_non_webvh_removes_self_hosted() {
        let config = WizardConfig {
            did_method: DID_PEER.into(),
            secret_storage: STORAGE_STRING.into(),
            ..WizardConfig::default()
        };
        let toml = generate_toml(&config, &test_generated()).unwrap();
        // should not have did_web_self_hosted as a key=value
        assert!(!toml.contains("did_web_self_hosted = \"file://"));
    }

    #[test]
    fn test_all_secret_storage_refs() {
        // Unified model: every backend choice becomes a single
        // `[secrets].backend = "<url>"` in mediator.toml. `string://` and
        // `vta://` are no longer storage backends (string:// dropped;
        // vta:// is a key *source*, not a store).
        let cases = [
            (STORAGE_FILE, "file://conf/secrets.json"),
            (STORAGE_KEYRING, "keyring://affinidi-mediator"),
            (STORAGE_AWS, "aws_secrets://us-east-1/mediator/"),
        ];
        for (storage, expected_backend) in cases {
            let config = WizardConfig {
                did_method: DID_PEER.into(),
                secret_storage: storage.into(),
                ..WizardConfig::default()
            };
            let toml = generate_toml(&config, &test_generated()).unwrap();
            assert!(
                toml.contains(&format!("backend = \"{expected_backend}\"")),
                "storage={storage}: expected backend=\"{expected_backend}\" in output"
            );
        }
    }

    #[test]
    fn test_listen_address_set() {
        let config = WizardConfig {
            listen_address: "127.0.0.1:9090".into(),
            did_method: DID_PEER.into(),
            secret_storage: STORAGE_STRING.into(),
            ..WizardConfig::default()
        };
        let toml = generate_toml(&config, &test_generated()).unwrap();
        assert!(toml.contains("listen_address = \"127.0.0.1:9090\""));
    }
}
