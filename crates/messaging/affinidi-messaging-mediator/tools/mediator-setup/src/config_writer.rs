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
    /// `true` when the wizard wrote a `did.jsonl` next to the config —
    /// either because `did_method = "did:webvh"` (self-hosted webvh) or
    /// because `did_method = "vta"` returned a serverless mediator DID
    /// whose log entry the mediator now serves itself. Drives whether
    /// `[server].did_web_self_hosted` is written into `mediator.toml`.
    pub did_log_jsonl_written: bool,
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

    // mediator.toml carries the `[secrets].backend` URL — vault
    // endpoint, AWS region/namespace, etc. Not key material, but
    // enough to mount a targeted attack on the secret backend, so
    // restrict to owner-only on Unix.
    crate::secure_fs::write_sensitive(path, &toml_content)?;

    // Redis Lua functions are public Redis script content — leave
    // at default (world-readable) permissions.
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
        server["api_prefix"] = toml_edit::value(&config.api_prefix);

        if let Some(ref admin_did) = generated.admin_did {
            server["admin_did"] = toml_edit::value(format!("did://{admin_did}"));
        } else {
            // Comment out admin_did
            server.as_table_like_mut().map(|t| t.remove("admin_did"));
        }

        // Self-hosted DID log. Two conditions must both hold before the
        // wizard activates the line:
        //   1. A `did.jsonl` was written next to the config (either the
        //      did:webvh self-host generator or the VTA-managed
        //      serverless path).
        //   2. The DID's host matches the public URL host — i.e. this
        //      mediator can plausibly serve `/.well-known/did.json`
        //      for that DID. When the VTA delegates webvh hosting to a
        //      different domain, the mediator must not advertise itself
        //      as the authority.
        // Otherwise the line stays commented (template default), which
        // is also the safe outcome when public_url isn't set or the DID
        // shape doesn't expose a host.
        let should_self_host = generated.did_log_jsonl_written
            && self_host_domain_match(&generated.mediator_did, &config.public_url);
        if should_self_host {
            server["did_web_self_hosted"] = toml_edit::value("file://./conf/did.jsonl");
        } else {
            server
                .as_table_like_mut()
                .map(|t| t.remove("did_web_self_hosted"));
        }
    }

    // ── [database] ─────────────────────────────────────────────────────
    // The legacy `[database]` section is always written so a wizard
    // run that picks Fjall today and switches to Redis later doesn't
    // need the operator to fill in a URL from scratch.
    if let Some(db) = doc.get_mut("database") {
        db["database_url"] = toml_edit::value(&config.database_url);
    }

    // ── [storage] ──────────────────────────────────────────────────────
    // Storage backend selector — added after the legacy `[database]`
    // section so the rendered TOML reads top-down: identity, secrets,
    // (optional) bundled-redis URL, then the actual backend choice.
    //
    // - `backend = "redis"` (default): mediator uses `[database]`.
    // - `backend = "fjall"`: mediator opens an embedded LSM at
    //   `data_dir`; `[database]` is ignored entirely.
    {
        // Find or insert the [storage] table.
        if doc.get("storage").is_none() {
            doc["storage"] = toml_edit::Item::Table(toml_edit::Table::new());
        }
        let storage = doc.get_mut("storage").expect("just inserted");
        storage["backend"] = toml_edit::value(&config.storage_backend);
        if config.storage_backend == crate::consts::STORAGE_BACKEND_FJALL {
            storage["data_dir"] = toml_edit::value(&config.fjall_data_dir);
        } else {
            // Strip a stale data_dir if the operator switched back to
            // Redis on a re-run.
            if let Some(table) = storage.as_table_like_mut() {
                table.remove("data_dir");
            }
        }
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

        // Network posture — Open by default. Always overwrite the
        // template's hard-coded trio so the wizard's choice (or the
        // recipe's `[security].network_mode`) is what lands in the
        // generated config; otherwise the template's historical
        // closed-mode defaults would silently shadow Open.
        match config.network_mode.as_str() {
            crate::consts::NETWORK_MODE_CLOSED => {
                sec["mediator_acl_mode"] = toml_edit::value("explicit_allow");
                sec["global_acl_default"] =
                    toml_edit::value("DENY_ALL,LOCAL,SEND_MESSAGES,RECEIVE_MESSAGES");
                sec["local_direct_delivery_allowed"] = toml_edit::value("true");
            }
            // Open is the default — applied for `NETWORK_MODE_OPEN`
            // and any unrecognised value (defensive: a typo'd recipe
            // value falls back to the new default rather than the
            // historical posture).
            _ => {
                sec["mediator_acl_mode"] = toml_edit::value("explicit_deny");
                sec["global_acl_default"] = toml_edit::value("ALLOW_ALL");
                sec["local_direct_delivery_allowed"] = toml_edit::value("true");
            }
        }
    }

    Ok(doc.to_string())
}

/// True when the mediator's DID and the public URL resolve to the same
/// host. Drives whether the wizard activates `did_web_self_hosted` —
/// when both sides agree on the host, this mediator can serve
/// `/.well-known/did.json[l]` for that DID; otherwise some other server
/// is the authority and the field stays commented.
///
/// Comparison is case-insensitive (DNS hosts are case-insensitive) and
/// strips ports, so `https://mediator.example.com:7037` matches
/// `did:webvh:SCID:mediator.example.com`. Returns `false` whenever
/// either input fails to parse or yields no host.
fn self_host_domain_match(mediator_did: &str, public_url: &str) -> bool {
    match (webvh_did_host(mediator_did), url_host(public_url.trim())) {
        (Some(d), Some(u)) => d.eq_ignore_ascii_case(&u),
        _ => false,
    }
}

/// Extract the host segment from a `did:webvh:SCID:host[:port][:path…]`
/// DID. The webvh spec puts the SCID at position 2 and the host at
/// position 3; everything after that is path. Returns `None` for
/// non-webvh DIDs or malformed inputs.
fn webvh_did_host(did: &str) -> Option<String> {
    let stripped = did.strip_prefix("did:webvh:")?;
    let mut parts = stripped.splitn(3, ':');
    let _scid = parts.next()?;
    let host_with_port = parts.next()?;
    // `host[%3Aport]` — webvh percent-encodes the port separator. Only
    // the host portion is meaningful for the domain match.
    let host = host_with_port
        .split_once("%3A")
        .or_else(|| host_with_port.split_once("%3a"))
        .map(|(h, _)| h)
        .unwrap_or(host_with_port);
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

/// Parse the host out of a public URL. Accepts bare hosts (`example.com`)
/// and full URLs (`https://example.com:7037/path`). Returns `None` when
/// the input is empty or has no parseable host.
fn url_host(url: &str) -> Option<String> {
    if url.is_empty() {
        return None;
    }
    // Try as-is first; if there's no scheme, retry with `https://`
    // so callers don't need to normalise. `url::Url::parse` requires a
    // scheme; without one a bare host like `mediator.example.com` would
    // be rejected, even though it's the form a recipe author may write.
    let parsed = url::Url::parse(url)
        .or_else(|_| url::Url::parse(&format!("https://{url}")))
        .ok()?;
    parsed.host_str().map(|h| h.to_string())
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
            config.secret_aws_region, config.secret_aws_namespace
        ),
        STORAGE_GCP => format!(
            "gcp_secrets://{}/{}",
            config.secret_gcp_project, config.secret_gcp_namespace
        ),
        STORAGE_AZURE => format!("azure_keyvault://{}", config.secret_azure_vault),
        STORAGE_VAULT => format!(
            "vault://{}/{}",
            config.secret_vault_endpoint, config.secret_vault_mount
        ),
        // string:// is no longer supported by the mediator's SecretStore
        // URL parser; fall back to a keyring default and warn in stdout
        // during `generate_and_write`. The wildcard catches any future
        // legacy variant that lands here without a dedicated arm —
        // STORAGE_STRING / STORAGE_VTA are listed explicitly because
        // they have callers today.
        _ => "keyring://affinidi-mediator".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── build_backend_url parametric coverage ─────────────────────────
    //
    // Six backend variants × two `?encrypt=1` modes for file://. Three
    // downstream call sites trust this output verbatim
    // (`generate_and_write`, `phase1_emit_request`, `phase2_apply`),
    // so a typo in any branch silently misroutes secret storage.

    #[test]
    fn build_backend_url_file_plain() {
        let cfg = WizardConfig {
            secret_storage: STORAGE_FILE.into(),
            secret_file_path: "conf/secrets.json".into(),
            secret_file_encrypted: false,
            ..WizardConfig::default()
        };
        assert_eq!(build_backend_url(&cfg), "file://conf/secrets.json");
    }

    #[test]
    fn build_backend_url_file_encrypted_appends_query() {
        let cfg = WizardConfig {
            secret_storage: STORAGE_FILE.into(),
            secret_file_path: "conf/secrets.json".into(),
            secret_file_encrypted: true,
            ..WizardConfig::default()
        };
        assert_eq!(
            build_backend_url(&cfg),
            "file://conf/secrets.json?encrypt=1"
        );
    }

    #[test]
    fn build_backend_url_keyring() {
        let cfg = WizardConfig {
            secret_storage: STORAGE_KEYRING.into(),
            secret_keyring_service: "affinidi-mediator-prod".into(),
            ..WizardConfig::default()
        };
        assert_eq!(build_backend_url(&cfg), "keyring://affinidi-mediator-prod");
    }

    #[test]
    fn build_backend_url_aws_concatenates_region_and_namespace() {
        let cfg = WizardConfig {
            secret_storage: STORAGE_AWS.into(),
            secret_aws_region: "us-east-1".into(),
            secret_aws_namespace: "mediator/prod".into(),
            ..WizardConfig::default()
        };
        assert_eq!(
            build_backend_url(&cfg),
            "aws_secrets://us-east-1/mediator/prod"
        );
    }

    #[test]
    fn build_backend_url_gcp_concatenates_project_and_namespace() {
        let cfg = WizardConfig {
            secret_storage: STORAGE_GCP.into(),
            secret_gcp_project: "affinidi-prod".into(),
            secret_gcp_namespace: "mediator-keys".into(),
            ..WizardConfig::default()
        };
        assert_eq!(
            build_backend_url(&cfg),
            "gcp_secrets://affinidi-prod/mediator-keys"
        );
    }

    #[test]
    fn build_backend_url_azure_uses_vault_field() {
        let cfg = WizardConfig {
            secret_storage: STORAGE_AZURE.into(),
            secret_azure_vault: "mediator.vault.azure.net".into(),
            ..WizardConfig::default()
        };
        assert_eq!(
            build_backend_url(&cfg),
            "azure_keyvault://mediator.vault.azure.net"
        );
    }

    #[test]
    fn build_backend_url_vault_concatenates_endpoint_and_mount() {
        let cfg = WizardConfig {
            secret_storage: STORAGE_VAULT.into(),
            secret_vault_endpoint: "vault.example.com:8200".into(),
            secret_vault_mount: "secret/mediator".into(),
            ..WizardConfig::default()
        };
        assert_eq!(
            build_backend_url(&cfg),
            "vault://vault.example.com:8200/secret/mediator"
        );
    }

    #[test]
    fn build_backend_url_rejects_unsafe_string_scheme_with_keyring_fallback() {
        // `string://` was the legacy "inline plaintext" backend —
        // dropped because the mediator runtime no longer accepts it.
        // The wizard could in theory still see a stale recipe with
        // it, so the writer falls back to a sane keyring URL rather
        // than emitting the unsafe one.
        let cfg = WizardConfig {
            secret_storage: STORAGE_STRING.into(),
            ..WizardConfig::default()
        };
        assert_eq!(build_backend_url(&cfg), "keyring://affinidi-mediator");
    }

    #[test]
    fn build_backend_url_rejects_vta_scheme_with_keyring_fallback() {
        // `vta://` was never a backend (the VTA is a key *source*,
        // not a store). Same fallback as `string://`.
        let cfg = WizardConfig {
            secret_storage: STORAGE_VTA.into(),
            ..WizardConfig::default()
        };
        assert_eq!(build_backend_url(&cfg), "keyring://affinidi-mediator");
    }

    #[test]
    fn build_backend_url_unknown_scheme_falls_back_to_keyring() {
        // Defensive: a typo'd scheme (e.g. `key-ring:`) lands on
        // the same safe default rather than emitting a malformed URL.
        let cfg = WizardConfig {
            secret_storage: "totally-not-a-real-scheme://".into(),
            ..WizardConfig::default()
        };
        assert_eq!(build_backend_url(&cfg), "keyring://affinidi-mediator");
    }

    fn test_generated() -> GeneratedValues {
        GeneratedValues {
            mediator_did: "did:peer:2.Vtest.Etest".into(),
            mediator_secrets: vec![],
            jwt_secret: Some(b"test_jwt_secret_pkcs8".to_vec()),
            admin_did: Some("did:key:z6MkTest".into()),
            admin_secret: None,
            ssl_cert_path: None,
            ssl_key_path: None,
            did_log_jsonl_written: false,
        }
    }

    #[test]
    fn open_network_mode_emits_explicit_deny_trio() {
        // Open is the wizard default — the trio is `explicit_deny` /
        // `ALLOW_ALL` / `local_direct_delivery_allowed = "true"`. Asserts
        // that the writer overwrites the template's hard-coded closed
        // trio, not just appends.
        let config = WizardConfig {
            network_mode: crate::consts::NETWORK_MODE_OPEN.into(),
            ..WizardConfig::default()
        };
        let toml = generate_toml(&config, &test_generated()).unwrap();
        assert!(toml.contains("mediator_acl_mode = \"explicit_deny\""));
        assert!(toml.contains("global_acl_default = \"ALLOW_ALL\""));
        assert!(toml.contains("local_direct_delivery_allowed = \"true\""));
        // Closed trio must NOT survive — match the assignment value,
        // not the bare token (which appears in the template's `### ACL
        // logic mode: explicit_deny | explicit_allow` doc comment).
        assert!(!toml.contains("mediator_acl_mode = \"explicit_allow\""));
        assert!(!toml.contains("\"DENY_ALL,LOCAL,SEND_MESSAGES,RECEIVE_MESSAGES\""));
    }

    #[test]
    fn closed_network_mode_emits_explicit_allow_trio() {
        let config = WizardConfig {
            network_mode: crate::consts::NETWORK_MODE_CLOSED.into(),
            ..WizardConfig::default()
        };
        let toml = generate_toml(&config, &test_generated()).unwrap();
        assert!(toml.contains("mediator_acl_mode = \"explicit_allow\""));
        assert!(
            toml.contains("global_acl_default = \"DENY_ALL,LOCAL,SEND_MESSAGES,RECEIVE_MESSAGES\"")
        );
        assert!(toml.contains("local_direct_delivery_allowed = \"true\""));
        // Open trio must NOT survive.
        assert!(!toml.contains("global_acl_default = \"ALLOW_ALL\""));
        assert!(!toml.contains("mediator_acl_mode = \"explicit_deny\""));
    }

    #[test]
    fn unknown_network_mode_falls_back_to_open() {
        // Defensive: a typo'd recipe value must land on the new default
        // rather than silently keeping the historical posture.
        let config = WizardConfig {
            network_mode: "totally-not-a-real-mode".into(),
            ..WizardConfig::default()
        };
        let toml = generate_toml(&config, &test_generated()).unwrap();
        assert!(toml.contains("mediator_acl_mode = \"explicit_deny\""));
        assert!(toml.contains("global_acl_default = \"ALLOW_ALL\""));
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
            did_log_jsonl_written: false,
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

    /// True when the rendered TOML contains an *active* (uncommented)
    /// `did_web_self_hosted = ...` line. The template's commented
    /// fallback (`# did_web_self_hosted = ...`) is intentionally
    /// ignored — assertions about wizard behaviour care about the
    /// active key, not the documentation comment.
    fn has_active_did_web_self_hosted(toml: &str) -> bool {
        toml.lines()
            .any(|line| line.trim_start().starts_with("did_web_self_hosted"))
    }

    #[test]
    fn test_webvh_self_host_with_matching_domain_activates_line() {
        // did:webvh self-host generator always produces a DID whose
        // host segment is the public URL host (the SCID is computed
        // from the very same domain). The wizard must activate
        // `did_web_self_hosted` so the mediator serves
        // `/.well-known/did.jsonl` for its own DID.
        let config = WizardConfig {
            did_method: DID_WEBVH.into(),
            secret_storage: STORAGE_STRING.into(),
            public_url: "https://mediator.example.com".into(),
            ..WizardConfig::default()
        };
        let generated = GeneratedValues {
            mediator_did: "did:webvh:QmScid:mediator.example.com".into(),
            did_log_jsonl_written: true,
            ..test_generated()
        };
        let toml = generate_toml(&config, &generated).unwrap();
        assert!(has_active_did_web_self_hosted(&toml));
        assert!(toml.contains("did_web_self_hosted = \"file://./conf/did.jsonl\""));
    }

    #[test]
    fn test_webvh_with_mismatched_domain_leaves_commented() {
        // VTA-managed path: VTA mints a DID hosted on a different
        // webvh server. Even though a `did.jsonl` lands next to the
        // config, the mediator must NOT advertise itself as the
        // authority — leaving the line commented protects against
        // serving stale content for someone else's DID.
        let config = WizardConfig {
            did_method: DID_VTA.into(),
            secret_storage: STORAGE_STRING.into(),
            public_url: "https://mediator.example.com".into(),
            ..WizardConfig::default()
        };
        let generated = GeneratedValues {
            mediator_did: "did:webvh:QmScid:webvh.vta-host.com".into(),
            did_log_jsonl_written: true,
            ..test_generated()
        };
        let toml = generate_toml(&config, &generated).unwrap();
        assert!(!has_active_did_web_self_hosted(&toml));
        // Comment line from the template should still be present so the
        // operator can flip it later if they take over hosting.
        assert!(toml.contains("# did_web_self_hosted"));
    }

    #[test]
    fn test_webvh_with_matching_domain_but_no_jsonl_stays_commented() {
        // Defensive: domain-match alone isn't enough — there has to
        // be a did.jsonl on disk for the line to point at.
        let config = WizardConfig {
            did_method: DID_VTA.into(),
            secret_storage: STORAGE_STRING.into(),
            public_url: "https://mediator.example.com".into(),
            ..WizardConfig::default()
        };
        let generated = GeneratedValues {
            mediator_did: "did:webvh:QmScid:mediator.example.com".into(),
            did_log_jsonl_written: false,
            ..test_generated()
        };
        let toml = generate_toml(&config, &generated).unwrap();
        assert!(!has_active_did_web_self_hosted(&toml));
    }

    #[test]
    fn test_webvh_with_empty_public_url_stays_commented() {
        // `public_url` may be unset (e.g. minimal recipe). Without
        // both sides we fail closed and leave the line commented.
        let config = WizardConfig {
            did_method: DID_WEBVH.into(),
            secret_storage: STORAGE_STRING.into(),
            public_url: String::new(),
            ..WizardConfig::default()
        };
        let generated = GeneratedValues {
            mediator_did: "did:webvh:QmScid:mediator.example.com".into(),
            did_log_jsonl_written: true,
            ..test_generated()
        };
        let toml = generate_toml(&config, &generated).unwrap();
        assert!(!has_active_did_web_self_hosted(&toml));
    }

    #[test]
    fn test_webvh_domain_match_is_case_insensitive_and_strips_port() {
        // DNS hosts are case-insensitive; bind ports on the public URL
        // shouldn't break the equality check.
        let config = WizardConfig {
            did_method: DID_WEBVH.into(),
            secret_storage: STORAGE_STRING.into(),
            public_url: "https://Mediator.Example.com:7037".into(),
            ..WizardConfig::default()
        };
        let generated = GeneratedValues {
            mediator_did: "did:webvh:QmScid:mediator.example.com".into(),
            did_log_jsonl_written: true,
            ..test_generated()
        };
        let toml = generate_toml(&config, &generated).unwrap();
        assert!(has_active_did_web_self_hosted(&toml));
    }

    #[test]
    fn test_non_webvh_removes_self_hosted() {
        let config = WizardConfig {
            did_method: DID_PEER.into(),
            secret_storage: STORAGE_STRING.into(),
            ..WizardConfig::default()
        };
        let toml = generate_toml(&config, &test_generated()).unwrap();
        // should not appear as an active key=value (commented form may
        // still survive from the template)
        assert!(!has_active_did_web_self_hosted(&toml));
    }

    // ── self_host_domain_match unit tests ─────────────────────────────

    #[test]
    fn self_host_domain_match_basic_match() {
        assert!(self_host_domain_match(
            "did:webvh:QmScid:mediator.example.com",
            "https://mediator.example.com",
        ));
    }

    #[test]
    fn self_host_domain_match_bare_host_in_url() {
        // Recipe authors may write a bare host without scheme.
        assert!(self_host_domain_match(
            "did:webvh:QmScid:mediator.example.com",
            "mediator.example.com",
        ));
    }

    #[test]
    fn self_host_domain_match_strips_port_and_path() {
        assert!(self_host_domain_match(
            "did:webvh:QmScid:mediator.example.com",
            "https://mediator.example.com:7037/mediator/v1/",
        ));
    }

    #[test]
    fn self_host_domain_match_case_insensitive() {
        assert!(self_host_domain_match(
            "did:webvh:QmScid:Mediator.Example.com",
            "https://mediator.example.COM",
        ));
    }

    #[test]
    fn self_host_domain_match_rejects_different_hosts() {
        assert!(!self_host_domain_match(
            "did:webvh:QmScid:webvh.vta-host.com",
            "https://mediator.example.com",
        ));
    }

    #[test]
    fn self_host_domain_match_rejects_non_webvh_did() {
        // did:peer / did:key DIDs have no host — fail closed.
        assert!(!self_host_domain_match(
            "did:peer:2.Vtest.Etest",
            "https://mediator.example.com",
        ));
        assert!(!self_host_domain_match(
            "did:key:z6MkTest",
            "https://mediator.example.com",
        ));
    }

    #[test]
    fn self_host_domain_match_rejects_empty_inputs() {
        assert!(!self_host_domain_match("", "https://mediator.example.com"));
        assert!(!self_host_domain_match(
            "did:webvh:QmScid:mediator.example.com",
            "",
        ));
        assert!(!self_host_domain_match("", ""));
    }

    #[test]
    fn webvh_did_host_handles_percent_encoded_port() {
        // Per webvh spec the port separator is percent-encoded as
        // `%3A`. The host-only comparison should drop the port.
        assert_eq!(
            webvh_did_host("did:webvh:QmScid:localhost%3A8000"),
            Some("localhost".to_string())
        );
        assert_eq!(
            webvh_did_host("did:webvh:QmScid:localhost%3a8000"),
            Some("localhost".to_string())
        );
    }

    #[test]
    fn webvh_did_host_handles_path_segments() {
        // webvh DIDs may carry path segments after the host — e.g.
        // `did:webvh:SCID:host:tenant:subpath`. The first segment
        // after the SCID is the host (port may be percent-encoded).
        assert_eq!(
            webvh_did_host("did:webvh:QmScid:mediator.example.com:tenant:abc"),
            Some("mediator.example.com".to_string())
        );
    }

    #[test]
    fn webvh_did_host_returns_none_for_malformed() {
        assert_eq!(webvh_did_host("did:peer:2.Vtest"), None);
        assert_eq!(webvh_did_host("did:webvh:onlyone"), None);
        assert_eq!(webvh_did_host(""), None);
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
