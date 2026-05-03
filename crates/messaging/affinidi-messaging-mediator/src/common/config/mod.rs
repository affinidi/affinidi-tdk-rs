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
    MediatorSecrets,
    database::config::{DatabaseConfig, DatabaseConfigRaw},
    errors::MediatorError,
    secrets::open_store,
};
use affinidi_secrets_resolver::ThreadedSecretsResolver;
use async_convert::{TryFrom, async_trait};
#[cfg(feature = "aws")]
use aws_config::{self, BehaviorVersion, Region};
use didwebvh_rs::log_entry::{LogEntry, LogEntryMethods};
use vta_sdk::credentials::CredentialBundle;

/// AWS SDK configuration type — conditionally compiled.
/// When the `aws` feature is enabled, this is `aws_config::SdkConfig`.
/// When disabled, this is `()` (zero-size placeholder).
#[cfg(feature = "aws")]
pub(crate) type AwsConfig = aws_config::SdkConfig;
#[cfg(not(feature = "aws"))]
pub(crate) type AwsConfig = ();
use serde::{Deserialize, Serialize};
use sha256::digest;
use std::{collections::HashMap, env, fmt, sync::Arc};
use tracing::{error, info, warn};
use tracing_subscriber::{EnvFilter, filter::LevelFilter};
use vta_sdk::integration::{
    self, SecretSource, TransportPreference, VtaIntegrationError, VtaServiceConfig,
};

use helpers::{
    get_hostname, load_forwarding_protection_blocks, read_config_file, read_did_config,
    read_document,
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

/// `[secrets]` config section — the unified secret-storage backend.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecretsConfigRaw {
    /// Backend URL. Examples: `keyring://affinidi-mediator`,
    /// `file:///var/lib/mediator/secrets.json`,
    /// `aws_secrets://us-east-1/prod/mediator/`.
    pub backend: String,
    /// Maximum age for the cached VTA bundle (humantime format, e.g.
    /// `"30d"` or `"12h"`). `None` or `"0"` means no expiry. Defaults to
    /// 30 days when unset.
    #[serde(default)]
    pub cache_ttl: Option<String>,
}

/// Default VTA cache TTL when `[secrets].cache_ttl` is not set.
const DEFAULT_CACHE_TTL_SECS: u64 = 30 * 86_400; // 30 days

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
    /// Unified secret backend — required whenever the mediator has any
    /// persistent identity (which is effectively always).
    pub secrets: SecretsConfigRaw,
    /// Optional storage backend selector. Absent → Redis (legacy
    /// behaviour, uses `[database]`). Present with `backend = "fjall"`
    /// → embedded Fjall at `data_dir`, `[database]` is ignored.
    #[serde(default)]
    pub storage: Option<StorageConfig>,
}

/// `[storage]` section — selects the mediator's storage backend.
/// Mirrors the wizard recipe shape so a `mediator.toml` produced by
/// the wizard parses unchanged.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StorageConfig {
    /// `"redis"` (default) or `"fjall"`. Memory backend is not
    /// exposed here — it's a tests-only backend.
    pub backend: String,
    /// On-disk path for the Fjall data directory. Required when
    /// `backend = "fjall"`. The mediator creates this directory if
    /// it doesn't exist.
    #[serde(default)]
    pub data_dir: Option<String>,
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
    /// Extracted DID document JSON served at `/.well-known/did.json`
    /// when self-hosting. Populated whether the on-disk source was a
    /// raw DID Document (did:web shape) or a webvh log entry — the
    /// loader extracts `state` from the latter so both routes serve
    /// canonical-shape content.
    pub mediator_did_doc: Option<String>,
    /// Raw webvh log entry stream served at `/.well-known/did.jsonl`.
    /// `Some` only when the on-disk source parsed as a `LogEntry`
    /// (did:webvh self-host); `None` for the did:web shape, where the
    /// jsonl route is not registered.
    pub mediator_did_log: Option<String>,
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
    /// URL of the unified secret backend (`[secrets].backend` from
    /// the config file). Surfaced in `/readyz` so operators can
    /// confirm the mediator is talking to the backend they expect
    /// without having to read the on-disk TOML.
    #[serde(skip_serializing)]
    pub secrets_backend_url: String,
    /// Open handle to the unified secret backend. Cloned cheaply (it
    /// wraps an `Arc<dyn SecretStore>`) so the readiness handler can
    /// re-probe live without coordinating with the rest of the
    /// startup code path.
    #[serde(skip_serializing)]
    pub secrets_backend: MediatorSecrets,
    /// `true` when self-hosted operating keys were loaded from the
    /// backend at startup OR when VTA-managed operating keys came back
    /// from the VTA. `false` only in the (rare) configuration where
    /// neither source produced keys — typically a misconfiguration the
    /// operator wants to see surfaced on /readyz.
    #[serde(skip_serializing)]
    pub operating_keys_loaded: bool,
    /// Resolved storage backend selector. `None` → use the legacy
    /// `[database]` Redis path. `Some(StorageConfig)` → honour the
    /// `[storage]` section the wizard wrote.
    #[serde(default)]
    pub storage: Option<StorageConfig>,
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
    /// Construct a [`Config`] with placeholder identity fields and
    /// stubbed secret/JWT material. Embedding callers (and the
    /// `MediatorBuilder` it backs) start here and overwrite the
    /// fields that matter for their deployment.
    ///
    /// Not suitable for direct use — `mediator_did`, `admin_did`,
    /// `secrets_backend`, the database config, and the JWT keys must
    /// all be set before passing the result to the server.
    pub fn headless(secrets_resolver: Arc<ThreadedSecretsResolver>) -> Self {
        Self::default(secrets_resolver)
    }

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
            mediator_did_log: None,
            admin_did: "".into(),
            database: DatabaseConfig::default(),
            streaming_enabled: true,
            streaming_uuid: "".into(),
            did_resolver_config,
            api_prefix: "/mediator/v1/".into(),
            // The default config is only used inside the early-startup
            // path before we've parsed `[secrets].backend`. Stub with
            // an empty URL + an in-memory store so the field is always
            // populated; production code overwrites it from the parsed
            // raw config below.
            secrets_backend_url: String::new(),
            secrets_backend: MediatorSecrets::new(std::sync::Arc::new(
                affinidi_messaging_mediator_common::secrets::backends::MemoryStore::new("memory"),
            )),
            operating_keys_loaded: false,
            storage: None,
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

/// Render a `VtaIntegrationError` from `integration::startup()` into a
/// `MediatorError::ConfigError` whose message names *both* what went
/// wrong and what the operator can do about it. Also emits a structured
/// `error!` log before returning so the failure cause is captured
/// independently of however the calling panic / process exit is
/// surfaced upstream.
///
/// `NoCachedSecrets` is the most operator-hostile path — the mediator
/// has never successfully contacted the VTA *and* the wizard didn't
/// seed the cache (or the cache was wiped). Spell out both remediation
/// paths so the operator doesn't have to read the SDK source to figure
/// out which one applies.
fn vta_startup_error(context: &str, err: VtaIntegrationError) -> MediatorError {
    let detail = match &err {
        VtaIntegrationError::NoCachedSecrets => format!(
            "VTA is unreachable (or rejected the request) and no cached secrets \
             exist for context '{context}'. Either (a) restore VTA connectivity \
             and restart, or (b) re-run the setup wizard so it can seed the \
             last-known-bundle cache with the mediator's provisioned keys."
        ),
        VtaIntegrationError::EmptySecretsBundle(ctx) => format!(
            "VTA context '{ctx}' returned an empty secrets bundle. The context \
             must have at least one key provisioned — check the wizard's Vta \
             step completed, or inspect the context on the VTA admin side."
        ),
        VtaIntegrationError::CacheError(inner) => format!(
            "Local secret-cache backend failed for context '{context}': {inner}. \
             Check that the configured secret store (keyring / file / AWS / ...) \
             is reachable and that the mediator process has permission to read \
             from it."
        ),
        VtaIntegrationError::Vta(e) => format!(
            "VTA call failed for context '{context}' and no usable cache fallback \
             was available: {e}. If the VTA is reachable, look at the SDK warning \
             above for the specific error — a `validation error` typically means \
             the VTA-side context or DID is misconfigured rather than a network \
             problem."
        ),
    };
    error!(
        context = context,
        error = %err,
        "VTA startup failed terminally — mediator cannot boot"
    );
    MediatorError::ConfigError(12, "NA".into(), detail)
}

#[async_trait]
impl TryFrom<ConfigRaw> for Config {
    type Error = MediatorError;

    async fn try_from(raw: ConfigRaw) -> Result<Self, Self::Error> {
        // Lazy AWS initialization — only load AWS SDK config when an AWS scheme
        // is actually used in the configuration. This avoids the 3+ second IMDS
        // timeout on non-AWS machines.
        let needs_aws = helpers::config_needs_aws(&raw);

        #[cfg(feature = "aws")]
        let aws_config: Option<AwsConfig> = if needs_aws {
            info!("AWS scheme detected in config — initializing AWS SDK");
            let mut builder = aws_config::defaults(BehaviorVersion::latest());
            if let Ok(region) = env::var("AWS_REGION") {
                builder = builder.region(Region::new(region));
            }
            Some(builder.load().await)
        } else {
            None
        };

        #[cfg(not(feature = "aws"))]
        let aws_config: Option<AwsConfig> = {
            if needs_aws {
                return Err(MediatorError::ConfigError(
                    12,
                    "NA".into(),
                    "Configuration uses aws_secrets:// or aws_parameter_store:// but the 'aws' \
                     feature is not enabled. Rebuild with: cargo build --features aws"
                        .into(),
                ));
            }
            None
        };

        let mut tags = HashMap::from([("app".to_string(), "mediator".to_string())]);
        for (key, value) in env::vars() {
            if key.get(..13) == Some("MEDIATOR_TAG_")
                && let Some(tag_key) = key.get(13..)
            {
                tags.insert(tag_key.to_lowercase(), value);
            }
        }

        let secrets_resolver = Arc::new(ThreadedSecretsResolver::new(None).await.0);

        // ── Secret backend ──────────────────────────────────────────────
        // Open the unified secret store and probe end-to-end. Failing here
        // with a clear error beats discovering the backend is unreachable
        // on the first request.
        let store = open_store(&raw.secrets.backend).map_err(|e| {
            MediatorError::ConfigError(
                12,
                "NA".into(),
                format!(
                    "Could not open secret backend '{}': {e}",
                    raw.secrets.backend
                ),
            )
        })?;
        let mediator_secrets = MediatorSecrets::new(store);
        mediator_secrets.probe().await.map_err(|e| {
            MediatorError::ConfigError(
                12,
                "NA".into(),
                format!("Secret backend '{}' failed probe: {e}", raw.secrets.backend),
            )
        })?;
        if raw.secrets.backend.starts_with("file://") {
            warn!(
                "Secret backend is file:// — secrets are plaintext on disk. \
                 Only use this for local dev/test."
            );
        }

        // ── VTA integration ────────────────────────────────────────────
        // If the backend has an admin credential, we're in VTA mode:
        // authenticate, fetch fresh operating keys, cache them, fall back
        // to the cached copy if the VTA is unreachable.
        let admin_cred = mediator_secrets
            .load_admin_credential()
            .await
            .map_err(|e| {
                MediatorError::ConfigError(
                    12,
                    "NA".into(),
                    format!("Could not load admin credential: {e}"),
                )
            })?;

        // Only the VTA-linked shape drives the VTA startup branch.
        // Self-hosted admin credentials (stored so subsequent wizard
        // runs can recover the private key) have `vta_did` / `vta_url`
        // unset; the mediator skips VTA integration for those.
        let vta_startup = if let Some(admin) = admin_cred.as_ref().filter(|a| a.is_vta_linked()) {
            let credential = CredentialBundle {
                did: admin.did.clone(),
                private_key_multibase: admin.private_key_multibase.clone(),
                vta_did: admin
                    .vta_did
                    .clone()
                    .expect("is_vta_linked() guarantees vta_did is Some"),
                vta_url: admin.vta_url.clone(),
            };
            // vta-sdk 0.6.x split `VtaServiceConfig` into an
            // `auth` block (credential + URL + timeout) and a
            // `context` block (id + transport preferences + DID
            // resolver). Construct explicitly rather than using
            // `VtaServiceConfig::new` because we want to express
            // each transport default in a comment, not hide them
            // behind the convenience constructor.
            let service_config = VtaServiceConfig {
                auth: integration::VtaAuthConfig {
                    credential,
                    url_override: admin.vta_url.clone().filter(|u| !u.is_empty()),
                    timeout: None,
                },
                context: integration::VtaContextConfig {
                    id: admin.context.clone(),
                    // DIDComm-first with REST fallback: the mediator
                    // already speaks DIDComm for its primary workload,
                    // and the VTA exposes its `DIDCommMessaging`
                    // service endpoint in its DID doc. Auto-preference
                    // lets the SDK try DIDComm when `mediator_did` is
                    // resolvable and fall through to REST otherwise —
                    // no circular-dependency hazard because
                    // `integration::startup` resolves the VTA's
                    // mediator from the VTA's DID doc, not from our
                    // own config.
                    mediator_did: None,
                    transport_preference: TransportPreference::Auto,
                    // `None` → SDK builds a one-shot resolver on
                    // demand. Mediator boot is a one-shot flow so we
                    // don't share our own `did_resolver` here; it
                    // isn't constructed until later in this TryFrom.
                    // Sharing it would require reordering the config
                    // build, which is a bigger change than this
                    // wire-up warrants.
                    did_resolver: None,
                },
            };

            // Parse cache TTL — default to 30 days when unset, `0` means
            // no expiry. Humantime handles `"30d"`, `"12h"`, etc.
            let ttl_secs = match raw.secrets.cache_ttl.as_deref() {
                None | Some("") => DEFAULT_CACHE_TTL_SECS,
                Some("0") => 0,
                Some(s) => humantime::parse_duration(s)
                    .map(|d| d.as_secs())
                    .unwrap_or_else(|e| {
                        warn!("Could not parse [secrets].cache_ttl '{s}' ({e}); using default");
                        DEFAULT_CACHE_TTL_SECS
                    }),
            };
            let cache = vta_cache::MediatorSecretCache::new(mediator_secrets.clone(), ttl_secs);

            // Two-line bootstrap narrative: what we're *attempting* first,
            // what we actually *got* second (see the post-startup match
            // below). Operators reading `journalctl` / container logs
            // need both — "did it try?" + "did it succeed, and from
            // where?" — without chasing the SDK's internal log lines.
            info!(
                context = %service_config.context.id,
                vta_url = %service_config.auth.url_override.as_deref().unwrap_or("(from DID doc)"),
                "Starting VTA integration — attempting live fetch with cache fallback"
            );
            let result = integration::startup(&service_config, &cache)
                .await
                .map_err(|e| vta_startup_error(&service_config.context.id, e))?;
            match result.source {
                SecretSource::Vta => info!(
                    context = %service_config.context.id,
                    did = %result.did,
                    secrets = result.bundle.secrets.len(),
                    "VTA integration OK — loaded fresh secrets from VTA"
                ),
                SecretSource::Cache => warn!(
                    context = %service_config.context.id,
                    did = %result.did,
                    secrets = result.bundle.secrets.len(),
                    "VTA integration DEGRADED — booted from LAST-KNOWN CACHED secrets. \
                     Mediator will continue to run with keys as of the last successful VTA \
                     contact; the runtime will refresh the cache on the next successful call. \
                     Investigate the preceding SDK warning for the root cause."
                ),
            }

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

        // Resolve mediator DID — from VTA startup result (if VTA mode)
        // or the mediator.toml `mediator_did` field (self-hosted mode).
        let mediator_did = if let Some(ref result) = vta_startup {
            result.did.clone()
        } else {
            read_did_config(&raw.mediator_did, &aws_config, "mediator_did").await?
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
            admin_did: read_did_config(&raw.server.admin_did, &aws_config, "admin_did").await?,
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
                    &mediator_secrets,
                    vta_startup.as_ref().map(|r| &r.bundle),
                )
                .await?,
            processors: ProcessorsConfig {
                forwarding: raw.processors.forwarding.clone().try_into()?,
                message_expiry_cleanup: raw.processors.message_expiry_cleanup.clone().try_into()?,
            },
            limits: raw.limits.try_into()?,
            tags,
            secrets_backend_url: raw.secrets.backend.clone(),
            secrets_backend: mediator_secrets.clone(),
            // Pass the optional `[storage]` section through unchanged.
            // server::serve_internal inspects it to decide between the
            // legacy Redis path and the embedded Fjall path.
            storage: raw.storage.clone(),
            // Operating keys come either from the VTA (when integration
            // is active) or from the unified backend's well-known
            // `mediator/operating/secrets` entry (self-hosted). The
            // security converter has just done both lookups by the time
            // we get here, so we can ask the backend directly: if the
            // entry is present we loaded it; otherwise the VTA bundle
            // (when present) supplied them.
            operating_keys_loaded: vta_startup.is_some()
                || mediator_secrets
                    .load_entry::<Vec<affinidi_secrets_resolver::secrets::Secret>>(
                        affinidi_messaging_mediator_common::OPERATING_SECRETS,
                        "operating-secrets",
                    )
                    .await
                    .ok()
                    .flatten()
                    .is_some(),
            ..Config::default(secrets_resolver)
        };

        config.mediator_did_hash = digest(&config.mediator_did);

        // Initialise a mutable did document for later use on validation and resolver loading
        let mut did_document: Option<Document> = None;

        // Are we self-hosting our own did:web Document?
        if let Some(path) = raw.server.did_web_self_hosted {
            let document_json = read_document(&path, &aws_config).await?;

            // Validate and parse as LogEntry (webvh format) first, then fall back to direct
            // Document. We split the canonical DID Document (served at `did.json`) from the
            // raw log entry stream (served at `did.jsonl`) so each well-known route returns
            // the correct shape — the previous version served the raw input verbatim at both
            // routes, which meant `did.jsonl` returned a DID Document for did:web sources and
            // `did.json` returned a log envelope for did:webvh sources.
            let parsed_document = match LogEntry::deserialize_string(&document_json, None) {
                Ok(log_entry) => {
                    // did:webvh source — extract the DID document for `did.json`, keep the
                    // raw log entry for `did.jsonl`.
                    let did_doc_value = log_entry.get_did_document().map_err(|err| {
                        error!("Couldn't extract DID Document from LogEntry: {err}");
                        MediatorError::ConfigError(
                            12,
                            "NA".into(),
                            format!("Couldn't extract DID Document from LogEntry: {err}"),
                        )
                    })?;

                    // Serialise the extracted DID document for the did.json handler. The
                    // resolver receives the typed `Document` below (parsed from the same
                    // value) so we don't pay double parse costs at request time.
                    let extracted_json = serde_json::to_string(&did_doc_value).map_err(|err| {
                        error!("Couldn't serialise extracted DID Document as JSON. Reason: {err}");
                        MediatorError::ConfigError(
                            12,
                            "NA".into(),
                            format!(
                                "Couldn't serialise extracted DID Document as JSON. Reason: {err}"
                            ),
                        )
                    })?;

                    config.mediator_did_doc = Some(extracted_json);
                    config.mediator_did_log = Some(document_json);

                    serde_json::from_value(did_doc_value).map_err(|err| {
                        error!("Couldn't convert DID Document value to Document struct. Reason: {err}");
                        MediatorError::ConfigError(
                            12,
                            "NA".into(),
                            format!("Couldn't convert DID Document value to Document struct. Reason: {err}"),
                        )
                    })?
                }
                Err(_log_entry_err) => {
                    // did:web source — the raw input is the DID document; no log entry to serve.
                    let parsed =
                        serde_json::from_str::<Document>(&document_json).map_err(|err| {
                            error!("Couldn't parse content as LogEntry or Document. Reason: {err}");
                            MediatorError::ConfigError(
                                12,
                                "NA".into(),
                                format!(
                                    "Couldn't parse content as LogEntry or Document. Reason: {err}"
                                ),
                            )
                        })?;
                    config.mediator_did_doc = Some(document_json);
                    config.mediator_did_log = None;
                    parsed
                }
            };

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
