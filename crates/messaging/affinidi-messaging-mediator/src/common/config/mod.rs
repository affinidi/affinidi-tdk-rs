pub mod helpers;
pub mod limits;
pub mod processors;
pub mod security;
pub mod vta_cache;

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
use async_convert::{TryFrom, async_trait};
use aws_config::{self, BehaviorVersion, Region};
use didwebvh_rs::log_entry::{LogEntry, LogEntryMethods};
use serde::{Deserialize, Serialize};
use sha256::digest;
use std::{collections::HashMap, env, fmt, sync::Arc};
use tracing::{error, info, warn};
use tracing_subscriber::{EnvFilter, filter::LevelFilter};
use vta_sdk::integration::{self, VtaServiceConfig};

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
///
/// When present, enables `vta://` scheme for `mediator_did` and `mediator_secrets`.
/// On startup, the mediator authenticates to the VTA, fetches fresh secrets,
/// and caches them locally for offline resilience.
///
/// All fields can be overridden via environment variables:
/// `VTA_CREDENTIAL`, `VTA_CONTEXT`, `VTA_URL`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VtaConfigRaw {
    /// VTA credential string with storage scheme prefix:
    /// - `string://<base64url>` — inline credential (dev/CI)
    /// - `aws_secrets://<secret_name>` — AWS Secrets Manager (requires `vta-aws-secrets` feature)
    /// - `keyring://<service>/<user>` — OS keyring (requires `vta-keyring` feature)
    pub credential: String,
    /// VTA context ID that holds this mediator's DID and keys.
    /// Defaults to `"mediator"` if not set.
    pub context: Option<String>,
    /// Override the VTA REST URL from the credential.
    /// Set this when using `--rest` discovery or for dev/testing.
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
            if key.get(..13) == Some("MEDIATOR_TAG_")
                && let Some(tag_key) = key.get(13..)
            {
                tags.insert(tag_key.to_lowercase(), value);
            }
        }

        // Set up a common secrets resolver
        // Do this here and pass into the defaults so that they don't create multiple instances of the same
        // When you instantiate config, the ..Config::default() will run the full default() function again
        // If SecretsResolver was instantiated in default(), it would create two copies of it (though only use one)
        let secrets_resolver = Arc::new(ThreadedSecretsResolver::new(None).await.0);

        // Initialize VTA integration if vta:// scheme is used for DID or secrets.
        // Uses integration::startup() which authenticates, fetches fresh secrets,
        // caches them locally, and falls back to the cache if VTA is unreachable.
        let needs_vta = raw.mediator_did.starts_with("vta://")
            || raw.security.mediator_secrets.starts_with("vta://");

        let vta_startup = if needs_vta {
            let vta_config = raw.vta.as_ref().ok_or_else(|| {
                MediatorError::ConfigError(
                    12,
                    "NA".into(),
                    "[vta] config section is required when using vta:// scheme for mediator_did or mediator_secrets".into(),
                )
            })?;

            // Resolve the credential from its storage backend (string://, aws_secrets://, keyring://)
            let credential_raw = load_vta_credential(&vta_config.credential, &aws_config).await?;
            let context = vta_config
                .context
                .clone()
                .unwrap_or_else(|| "mediator".into());

            let service_config = VtaServiceConfig {
                credential: credential_raw,
                context,
                url_override: vta_config.url.clone().filter(|u| !u.is_empty()),
                timeout: None,
            };

            let cache = vta_cache::MediatorSecretCache::from_credential_config(
                &vta_config.credential,
                &aws_config,
            );

            info!("Starting VTA integration...");
            let result = integration::startup(&service_config, &cache)
                .await
                .map_err(|e| {
                    MediatorError::ConfigError(12, "NA".into(), format!("VTA startup failed: {e}"))
                })?;

            // Mediator-specific: probe VTA health to detect circular dependency.
            if let Some(client) = &result.client {
                match client.health().await {
                    Ok(health) => {
                        if health.mediator_did.as_deref() == Some(&result.did) {
                            warn!(
                                "CIRCULAR DEPENDENCY: This mediator's DID ({}) matches the VTA's \
                                 configured mediator DID. REST bootstrapping prevents startup deadlock, \
                                 but both services are interdependent.",
                                result.did
                            );
                        } else if let Some(vta_med_url) = &health.mediator_url
                            && health.mediator_did.is_some()
                        {
                            info!(
                                "VTA reports mediator dependency — mediator_did: {:?}, mediator_url: {:?}",
                                health.mediator_did.as_deref().unwrap_or("none"),
                                vta_med_url,
                            );
                        }
                    }
                    Err(e) => {
                        warn!(
                            "Could not check VTA health for circular dependency detection (non-fatal): {e}"
                        );
                    }
                }
            }

            Some(result)
        } else {
            None
        };

        // Resolve mediator DID — from VTA startup result or config
        let mediator_did = if let Some(ref result) = vta_startup {
            if raw.mediator_did.starts_with("vta://") {
                result.did.clone()
            } else {
                read_did_config(&raw.mediator_did, &aws_config, "mediator_did", None).await?
            }
        } else {
            read_did_config(&raw.mediator_did, &aws_config, "mediator_did", None).await?
        };

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
            admin_did: read_did_config(&raw.server.admin_did, &aws_config, "admin_did", None)
                .await?,
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
                .convert(
                    secrets_resolver.clone(),
                    &aws_config,
                    vta_startup.as_ref().map(|r| &r.bundle),
                )
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
