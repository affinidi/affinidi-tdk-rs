pub mod helpers;
pub mod limits;
pub mod processors;
pub mod security;

pub use limits::*;
pub use processors::*;
pub use security::*;

use affinidi_did_common::Document;
use affinidi_did_resolver_cache_sdk::{
    DIDCacheClient,
    config::{DIDCacheConfig, DIDCacheConfigBuilder},
};
use affinidi_messaging_mediator_common::{
    database::config::{DatabaseConfig, DatabaseConfigRaw},
    errors::MediatorError,
};
use affinidi_messaging_mediator_processors::message_expiry_cleanup::config::MessageExpiryCleanupConfig;
use affinidi_secrets_resolver::ThreadedSecretsResolver;
use vta_sdk::{client::VtaClient, credentials::CredentialBundle};
use async_convert::{TryFrom, async_trait};
use aws_config::{self, BehaviorVersion, Region};
use didwebvh_rs::log_entry::{LogEntry, LogEntryMethods};
use serde::{Deserialize, Serialize};
use sha256::digest;
use std::{collections::HashMap, env, fmt, sync::Arc};
use tracing::{error, info, warn};
use tracing_subscriber::{EnvFilter, filter::LevelFilter};

use helpers::{
    get_hostname, load_forwarding_protection_blocks, load_vta_credential, read_config_file,
    read_did_config, read_document,
};

#[derive(Debug, Serialize, Deserialize)]
pub struct ServerConfig {
    pub listen_address: String,
    pub api_prefix: String,
    pub admin_did: String,
    pub did_web_self_hosted: Option<String>,
}

/// Live streaming configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StreamingConfig {
    pub enabled: String,
    pub uuid: String,
}

/// DID resolver configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DIDResolverConfig {
    pub address: Option<String>,
    pub cache_capacity: String,
    pub cache_ttl: String,
    pub network_timeout: String,
    pub network_limit: String,
}

impl DIDResolverConfig {
    pub fn convert(&self) -> DIDCacheConfig {
        let mut config = DIDCacheConfigBuilder::default()
            .with_cache_capacity(self.cache_capacity.parse().unwrap_or(1000))
            .with_cache_ttl(self.cache_ttl.parse().unwrap_or(300))
            .with_network_timeout(self.network_timeout.parse().unwrap_or(5))
            .with_network_cache_limit_count(self.network_limit.parse().unwrap_or(100));

        if let Some(address) = &self.address {
            config = config.with_network_mode(address);
        }

        config.build()
    }
}

/// VTA (Verifiable Trust Agent) configuration for centralized key management.
/// When present, enables `vta://` scheme for `mediator_did` and `mediator_secrets`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VtaConfigRaw {
    /// Base64url-encoded credential from VTA admin (cnm-cli auth credentials generate)
    pub credential: String,
    /// VTA context name for the mediator's keys and DID (default: "mediator")
    pub context: Option<String>,
    /// Override the VTA URL from the credential (useful for dev/testing)
    pub url: Option<String>,
}

/// Raw configuration deserialized from the TOML file, converted to [`Config`]
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct ConfigRaw {
    pub log_level: String,
    pub log_json: String,
    pub mediator_did: String,
    pub server: ServerConfig,
    pub database: DatabaseConfigRaw,
    pub security: SecurityConfigRaw,
    pub streaming: StreamingConfig,
    pub did_resolver: DIDResolverConfig,
    pub limits: LimitsConfigRaw,
    pub processors: ProcessorsConfigRaw,
    pub vta: Option<VtaConfigRaw>,
}

#[derive(Clone, Serialize)]
pub struct Config {
    #[serde(skip_serializing)]
    pub log_level: LevelFilter,
    #[serde(skip_serializing)]
    pub log_json: bool,
    pub listen_address: String,
    pub mediator_did: String,
    pub mediator_did_hash: String,
    pub mediator_did_doc: Option<String>,
    pub admin_did: String,
    pub api_prefix: String,
    pub streaming_enabled: bool,
    pub streaming_uuid: String,
    pub database: DatabaseConfig,
    pub security: SecurityConfig,
    #[serde(skip_serializing)]
    pub did_resolver_config: DIDCacheConfig,
    pub processors: ProcessorsConfig,
    pub limits: LimitsConfig,
    pub tags: HashMap<String, String>,
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("log_level", &self.log_level)
            .field("log_json", &self.log_json)
            .field("listen_address", &self.listen_address)
            .field("mediator_did", &self.mediator_did)
            .field("mediator_did_hash", &self.mediator_did_hash)
            .field("admin_did", &self.admin_did)
            .field("mediator_did_doc", &"Hidden")
            .field("database", &self.database)
            .field("streaming_enabled?", &self.streaming_enabled)
            .field("streaming_uuid", &self.streaming_uuid)
            .field("DID Resolver config", &self.did_resolver_config)
            .field("api_prefix", &self.api_prefix)
            .field("security", &self.security)
            .field("processors", &self.processors)
            .field("Limits", &self.limits)
            .field("tags", &self.tags)
            .finish()
    }
}

impl Config {
    fn default(secrets_resolver: Arc<ThreadedSecretsResolver>) -> Self {
        let did_resolver_config = DIDCacheConfigBuilder::default()
            .with_cache_capacity(1000)
            .with_cache_ttl(300)
            .with_network_timeout(5)
            .with_network_cache_limit_count(100)
            .build();

        Config {
            log_level: LevelFilter::INFO,
            log_json: true,
            listen_address: "".into(),
            mediator_did: "".into(),
            mediator_did_hash: "".into(),
            mediator_did_doc: None,
            admin_did: "".into(),
            database: DatabaseConfig::default(),
            streaming_enabled: true,
            streaming_uuid: "".into(),
            did_resolver_config,
            api_prefix: "/mediator/v1/".into(),
            security: SecurityConfig::default(secrets_resolver),
            processors: ProcessorsConfig {
                forwarding: ForwardingConfig::default(),
                message_expiry_cleanup: MessageExpiryCleanupConfig::default(),
            },
            limits: LimitsConfig::default(),
            tags: HashMap::from([("app".to_string(), "mediator".to_string())]),
        }
    }
}

#[async_trait]
impl TryFrom<ConfigRaw> for Config {
    type Error = MediatorError;

    async fn try_from(raw: ConfigRaw) -> Result<Self, Self::Error> {
        // Set up AWS Configuration
        // Region is resolved in order: AWS_REGION env var → EC2 instance metadata →
        // ~/.aws/config. Only override if explicitly set via env var.
        let mut aws_builder = aws_config::defaults(BehaviorVersion::latest());
        if let Ok(region) = env::var("AWS_REGION") {
            aws_builder = aws_builder.region(Region::new(region));
        }
        let aws_config = aws_builder.load().await;
        let mut tags = HashMap::from([("app".to_string(), "mediator".to_string())]);
        for (key, value) in env::vars() {
            if key.get(..13) == Some("MEDIATOR_TAG_") {
                if let Some(tag_key) = key.get(13..) {
                    tags.insert(tag_key.to_lowercase(), value);
                }
            }
        }

        // Set up a common secrets resolver
        // Do this here and pass into the defaults so that they don't create multiple instances of the same
        // When you instantiate config, the ..Config::default() will run the full default() function again
        // If SecretsResolver was instantiated in default(), it would create two copies of it (though only use one)
        let secrets_resolver = Arc::new(ThreadedSecretsResolver::new(None).await.0);

        // Initialize VTA client if vta:// scheme is used for DID or secrets
        // IMPORTANT: The mediator MUST use REST (not DIDComm) to communicate with VTA during
        // startup. If the VTA only supports DIDComm transport via this mediator, neither service
        // can bootstrap — a deadlock. The `client` feature (not `session`) ensures REST transport.
        let needs_vta = raw.mediator_did.starts_with("vta://")
            || raw.security.mediator_secrets.starts_with("vta://");

        // VTA health info for circular dependency detection (populated below if VTA is used)
        let mut vta_mediator_did: Option<String> = None;
        let mut vta_mediator_url: Option<String> = None;

        let vta_client = if needs_vta {
            let vta_config = raw.vta.as_ref().ok_or_else(|| {
                MediatorError::ConfigError(
                    12,
                    "NA".into(),
                    "[vta] config section is required when using vta:// scheme for mediator_did or mediator_secrets".into(),
                )
            })?;

            // Resolve the credential from its storage backend (string://, aws_secrets://, keyring://)
            let credential_raw = load_vta_credential(&vta_config.credential, &aws_config).await?;
            let url_override = vta_config.url.as_deref().filter(|u| !u.is_empty());

            info!("Authenticating to VTA via REST...");

            // Try lightweight auth first (works when VTA DID is did:key).
            // Falls back to session-based auth with full DID resolution for
            // VTAs using did:web, did:webvh, or other non-did:key methods.
            let client = match VtaClient::from_credential(&credential_raw, url_override).await {
                Ok(client) => {
                    info!(
                        "Successfully authenticated to VTA at '{}' (REST, auto-refresh enabled)",
                        client.base_url()
                    );
                    client
                }
                Err(e) => {
                    let err_msg = format!("{e}");
                    if e.is_network() {
                        return Err(MediatorError::ConfigError(12, "NA".into(), format!(
                            "Cannot reach VTA via REST: {e}. \
                             The mediator requires REST access to the VTA during startup. \
                             If the VTA relies on this mediator for DIDComm transport and has no \
                             independent REST endpoint, this is a deadlock — neither service can start. \
                             Ensure the VTA exposes a REST API that is reachable without this mediator."
                        )));
                    }

                    // Lightweight auth failed (e.g., VTA DID is not did:key).
                    // Fall back to session-based challenge-response with full DID resolution.
                    warn!("Lightweight VTA auth failed ({err_msg}), trying session auth with DID resolution...");

                    let credential = CredentialBundle::decode(&credential_raw).map_err(|e| {
                        MediatorError::ConfigError(12, "NA".into(), format!("Invalid VTA credential: {e}"))
                    })?;

                    let vta_url = url_override
                        .or(credential.vta_url.as_deref())
                        .ok_or_else(|| {
                            MediatorError::ConfigError(
                                12, "NA".into(),
                                "VTA URL not found in credential or config".into(),
                            )
                        })?;

                    let token_result = vta_sdk::session::challenge_response(
                        vta_url,
                        &credential.did,
                        &credential.private_key_multibase,
                        &credential.vta_did,
                    )
                    .await
                    .map_err(|e| {
                        error!("VTA session auth also failed: {e}");
                        MediatorError::ConfigError(
                            12, "NA".into(),
                            format!("VTA authentication failed: {e}"),
                        )
                    })?;

                    let client = VtaClient::new(vta_url);
                    client.set_token(token_result.access_token);
                    info!("Successfully authenticated to VTA at '{vta_url}' (REST, session auth)");
                    client
                }
            };

            // Probe VTA health to detect circular dependency with this mediator.
            // The health endpoint reports the VTA's own mediator configuration, so we can
            // check whether the VTA routes DIDComm through this same mediator.
            match client.health().await {
                Ok(health) => {
                    if health.mediator_did.is_some() || health.mediator_url.is_some() {
                        info!(
                            "VTA reports mediator dependency — mediator_did: {:?}, mediator_url: {:?}",
                            health.mediator_did.as_deref().unwrap_or("none"),
                            health.mediator_url.as_deref().unwrap_or("none"),
                        );
                    }
                    vta_mediator_did = health.mediator_did;
                    vta_mediator_url = health.mediator_url;
                }
                Err(e) => {
                    warn!("Could not check VTA health for circular dependency detection (non-fatal): {e}");
                }
            }

            Some(client)
        } else {
            None
        };

        // Resolve mediator DID before building config so we can check for circular dependency
        let mediator_did = read_did_config(&raw.mediator_did, &aws_config, "mediator_did", vta_client.as_ref()).await?;

        // Circular dependency check: does the VTA route DIDComm through THIS mediator?
        if let Some(vta_med_did) = &vta_mediator_did {
            if vta_med_did == &mediator_did {
                warn!(
                    "CIRCULAR DEPENDENCY: This mediator's DID ({mediator_did}) matches the VTA's \
                     configured mediator DID. The VTA routes DIDComm through this mediator. \
                     REST bootstrapping prevents startup deadlock, but both services are \
                     interdependent — if this mediator is unavailable, the VTA's DIDComm \
                     transport will be disrupted until the mediator restarts and re-bootstraps \
                     from VTA via REST. Simultaneous restarts of both services may require \
                     manual intervention (start VTA first with REST enabled, then start mediator)."
                );
            }
        } else if let Some(vta_med_url) = &vta_mediator_url {
            // Fallback: if we couldn't match by DID, warn if VTA has any mediator configured
            warn!(
                "VTA is configured with mediator_url '{}'. If this is the same mediator, \
                 a circular dependency exists. Ensure the VTA's REST endpoint is accessible \
                 independently of this mediator for bootstrap.",
                vta_med_url
            );
        }

        let mut config = Config {
            log_level: match raw.log_level.as_str() {
                "trace" => LevelFilter::TRACE,
                "debug" => LevelFilter::DEBUG,
                "info" => LevelFilter::INFO,
                "warn" => LevelFilter::WARN,
                "error" => LevelFilter::ERROR,
                _ => LevelFilter::INFO,
            },
            log_json: raw.log_json.parse().unwrap_or_else(|_| {
                warn!(
                    "Could not parse log_json value '{}', using default: true",
                    raw.log_json
                );
                true
            }),
            listen_address: raw.server.listen_address,
            mediator_did,
            admin_did: read_did_config(&raw.server.admin_did, &aws_config, "admin_did", None).await?,
            database: raw.database.try_into()?,
            streaming_enabled: raw.streaming.enabled.parse().unwrap_or_else(|_| {
                warn!(
                    "Could not parse streaming.enabled value '{}', using default: true",
                    raw.streaming.enabled
                );
                true
            }),
            did_resolver_config: raw.did_resolver.convert(),
            api_prefix: raw.server.api_prefix,
            security: raw
                .security
                .convert(secrets_resolver.clone(), &aws_config, vta_client.as_ref())
                .await?,
            processors: ProcessorsConfig {
                forwarding: raw.processors.forwarding.clone().try_into()?,
                message_expiry_cleanup: raw.processors.message_expiry_cleanup.clone().try_into()?,
            },
            limits: raw.limits.try_into()?,
            tags,
            ..Config::default(secrets_resolver)
        };

        config.mediator_did_hash = digest(&config.mediator_did);

        // Initialise a mutable did document for later use on validation and resolver loading
        let mut did_document: Option<Document> = None;

        // Are we self-hosting our own did:web Document?
        if let Some(path) = raw.server.did_web_self_hosted {
            let document_json = read_document(&path, &aws_config).await?;

            // Validate and parse as LogEntry (webvh format) first, then fall back to direct Document
            let parsed_document = match LogEntry::deserialize_string(&document_json, None) {
                Ok(log_entry) => {
                    // Extract the did_document from the log_entry
                    let did_doc = log_entry.get_did_document().map_err(|err| {
                        error!("Couldn't extract DID Document from LogEntry: {err}");
                        MediatorError::ConfigError(
                            12,
                            "NA".into(),
                            format!("Couldn't extract DID Document from LogEntry: {err}"),
                        )
                    })?;

                    // Convert Value to Document
                    serde_json::from_value(did_doc).map_err(|err| {
                        error!("Couldn't convert DID Document value to Document struct. Reason: {err}");
                        MediatorError::ConfigError(
                            12,
                            "NA".into(),
                            format!("Couldn't convert DID Document value to Document struct. Reason: {err}"),
                        )
                    })?
                }
                Err(_log_entry_err) => {
                    // Try parsing as a direct Document struct
                    serde_json::from_str::<Document>(&document_json).map_err(|err| {
                        error!("Couldn't parse content as LogEntry or Document. Reason: {err}");
                        MediatorError::ConfigError(
                            12,
                            "NA".into(),
                            format!(
                                "Couldn't parse content as LogEntry or Document. Reason: {err}"
                            ),
                        )
                    })?
                }
            };

            // Store the raw document string (JSON or JSONL format)
            config.mediator_did_doc = Some(document_json);
            // Store the parsed Document for later use
            did_document = Some(parsed_document);
        }

        // Ensure that the security JWT expiry times are valid
        if config.security.jwt_access_expiry >= config.security.jwt_refresh_expiry {
            error!(
                "JWT Access expiry ({}) must be less than JWT Refresh expiry ({})",
                config.security.jwt_access_expiry, config.security.jwt_refresh_expiry
            );
            return Err(MediatorError::ConfigError(
                12,
                "NA".into(),
                "JWT Access expiry must be less than JWT Refresh expiry".into(),
            ));
        }

        // Get Subscriber unique hostname
        if config.streaming_enabled {
            config.streaming_uuid = get_hostname(&raw.streaming.uuid)?;
        }

        // Fill out the forwarding protection for DIDs and associated service endpoints
        // This protects against the mediator forwarding messages to itself.
        let mut did_resolver = DIDCacheClient::new(config.did_resolver_config.clone())
            .await
            .map_err(|err| {
                MediatorError::DIDError(
                    12,
                    "NA".into(),
                    "NA".into(),
                    format!("Couldn't start DID Resolver: {err}"),
                )
            })?;

        // Load the Local DID Document if self hosted
        if let Some(mediator_doc) = did_document {
            did_resolver
                .add_did_document(&config.mediator_did, mediator_doc)
                .await;
        }

        load_forwarding_protection_blocks(
            &did_resolver,
            &mut config.processors.forwarding,
            &config.mediator_did,
            &raw.processors.forwarding.blocked_forwarding_dids,
        )
        .await?;

        Ok(config)
    }
}

pub async fn init(config_file: &str, with_ansi: bool) -> Result<Config, MediatorError> {
    // Read configuration file parameters
    let config = read_config_file(config_file)?;

    // setup logging/tracing framework
    let filter = if env::var("RUST_LOG").is_ok() {
        EnvFilter::from_default_env()
    } else {
        EnvFilter::new(config.log_level.as_str())
    };

    let subscriber = tracing_subscriber::fmt()
        // Use a more compact, abbreviated log format
        .compact()
        // Display source code file paths
        .with_file(false)
        // Display source code line numbers
        .with_line_number(false)
        // Display the thread ID an event was recorded on
        .with_thread_ids(false)
        // Don't display the event's target (module path)
        .with_target(true)
        .with_ansi(with_ansi)
        .with_env_filter(filter);

    println!("Switching to tracing subscriber for all logging...");
    if config
        .log_json
        .parse()
        .unwrap_or_else(|_: std::str::ParseBoolError| {
            eprintln!(
                "WARN: Could not parse log_json value '{}', using default: true",
                config.log_json
            );
            true
        })
    {
        let subscriber = subscriber
            .json()
            // Build the subscriber
            .finish();
        tracing::subscriber::set_global_default(subscriber).map_err(|e| {
            MediatorError::ConfigError(12, "NA".into(), format!("Couldn't setup logging: {e}"))
        })?;
    } else {
        let subscriber = subscriber.finish();
        tracing::subscriber::set_global_default(subscriber).map_err(|e| {
            MediatorError::ConfigError(12, "NA".into(), format!("Couldn't setup logging: {e}"))
        })?;
    }

    match <Config as async_convert::TryFrom<ConfigRaw>>::try_from(config).await {
        Ok(config) => {
            info!("Configuration settings parsed successfully.\n{:#?}", config);
            Ok(config)
        }
        Err(err) => Err(err),
    }
}
