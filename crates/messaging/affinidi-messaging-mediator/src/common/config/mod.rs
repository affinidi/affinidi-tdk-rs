pub mod helpers;
pub mod limits;
pub mod processors;
pub mod security;
pub mod validate;
pub(crate) mod vta_bootstrap;
pub mod vta_cache;

pub use limits::*;
pub use processors::*;
pub use security::*;

// The raw TOML schema types now live in the dependency-light
// `affinidi-messaging-mediator-config` crate. Re-exported here so existing
// `crate::common::config::*` paths (and external consumers like
// `affinidi-messaging-test-mediator`) keep resolving. Only the *types* are
// re-exported — the crate's `env` / `validate` modules are used fully-qualified
// (a bare `env` would shadow `std::env`). The resolved runtime `Config` and
// every `ConfigRaw → Config` conversion stay in this module.
pub use affinidi_messaging_mediator_config::{
    ConfigRaw, DIDResolverConfig, ForwardingConfigRaw, LimitsConfigRaw,
    MessageExpiryCleanupConfigRaw, ProcessorsConfigRaw, SecretsConfigRaw, SecurityConfigRaw,
    ServerConfig, SessionExpiryCleanupConfigRaw, StorageConfig, StreamingConfig,
};

use affinidi_did_common::Document;
use affinidi_did_resolver_cache_sdk::{
    DIDCacheClient,
    config::{DIDCacheConfig, DIDCacheConfigBuilder},
};
use affinidi_messaging_mediator_common::{
    MediatorSecrets, database::config::DatabaseConfig, did_web::rewrite_did_document_to_web,
    errors::MediatorError, secrets::open_store,
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
use serde::Serialize;
use sha256::digest;
use std::{collections::HashMap, env, fmt, sync::Arc};
use tracing::{error, info, warn};
use tracing_subscriber::{EnvFilter, filter::LevelFilter};
use vta_sdk::integration::{
    self, SecretSource, TransportPreference, VtaIntegrationError, VtaServiceConfig,
};

use helpers::{
    assert_operating_secrets_cover_key_agreement, get_hostname, load_forwarding_protection_blocks,
    preload_self_did, read_did_config, read_document,
};

/// Build the runtime [`DIDCacheConfig`] from the raw [`DIDResolverConfig`]
/// schema. Was `DIDResolverConfig::convert`; became a free function when the
/// raw type relocated to `affinidi-messaging-mediator-config` (inherent impls
/// must live in the type's crate, and this conversion pulls the DID-resolver
/// SDK, which the schema crate avoids).
fn did_resolver_cache_config(raw: &DIDResolverConfig) -> DIDCacheConfig {
    let mut config = DIDCacheConfigBuilder::default()
        .with_cache_capacity(raw.cache_capacity.parse().unwrap_or(1000))
        .with_cache_ttl(raw.cache_ttl.parse().unwrap_or(300))
        .with_network_timeout(raw.network_timeout.parse().unwrap_or(5))
        .with_network_cache_limit_count(raw.network_limit.parse().unwrap_or(100));

    if let Some(address) = &raw.address {
        config = config.with_network_mode(address);
    }

    config.build()
}

/// Build the runtime [`DatabaseConfig`] from the raw `[database]` schema.
/// `DatabaseConfigRaw` lives in the config crate and `DatabaseConfig` in
/// mediator-common, so this is a free function (the orphan rule forbids a
/// `TryFrom` impl here). Mirrors mediator-common's former
/// `TryFrom<DatabaseConfigRaw>` exactly: the circuit-breaker tuning is fixed
/// here and `database_timeout` falls back to 2 on a parse error.
fn database_config_from_raw(
    raw: affinidi_messaging_mediator_config::DatabaseConfigRaw,
) -> DatabaseConfig {
    DatabaseConfig {
        functions_file: Some(raw.functions_file),
        database_url: raw.database_url,
        database_timeout: raw.database_timeout.parse().unwrap_or(2),
        circuit_breaker_threshold: 5,
        circuit_breaker_recovery_secs: 10,
    }
}

/// Default VTA cache TTL when `[secrets].cache_ttl` is not set.
const DEFAULT_CACHE_TTL_SECS: u64 = 30 * 86_400; // 30 days

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
    /// Typed copy of the mediator's own DID document, parsed once during
    /// config load (`from_raw`). Carried so the request-time server
    /// resolver can preload it via [`preload_self_did`] without
    /// re-deserialising `mediator_did_doc`. `Some` whenever this mediator
    /// self-hosts a document; `None` for builder-constructed configs,
    /// which set only the string form (the server then parses that as a
    /// fallback).
    #[serde(skip)]
    pub mediator_did_document: Option<Document>,
    /// Raw webvh log entry stream served at `/.well-known/did.jsonl`.
    /// `Some` only when the on-disk source parsed as a `LogEntry`
    /// (did:webvh self-host); `None` for the did:web shape, where the
    /// jsonl route is not registered.
    pub mediator_did_log: Option<String>,
    pub admin_did: String,
    pub api_prefix: String,
    /// Operator-declared URL aliases the mediator considers local. See
    /// [`ServerConfig::local_endpoints`]. Used by the routing 2.0
    /// forward handler to short-circuit when a next-hop's DIDComm
    /// service URI points back at this mediator under a different
    /// hostname (e.g., LB-fronted deployments).
    #[serde(default)]
    pub local_endpoints: Vec<String>,
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
    /// the config file). Used by the secret-backend probe and surfaced
    /// in startup logs and the authenticated `/admin/status` endpoint
    /// so operators can confirm the mediator is talking to the backend
    /// they expect. Intentionally NOT echoed in `/readyz`, which is
    /// unauthenticated and must not leak backend identity.
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
    /// Inputs for the periodic VTA refresh task. `Some` only in
    /// VTA-linked deployments. The task itself is spawned by
    /// [`crate::server::serve_internal`] alongside the other
    /// background workers, gated on this field being `Some`.
    #[serde(skip)]
    pub vta_refresher: Option<crate::tasks::vta_refresh::VtaRefresher>,
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
            mediator_did_document: None,
            mediator_did_log: None,
            admin_did: "".into(),
            local_endpoints: Vec::new(),
            database: DatabaseConfig::default(),
            streaming_enabled: true,
            streaming_uuid: "".into(),
            did_resolver_config,
            api_prefix: "/mediator/v1".into(),
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
            vta_refresher: None,
            security: SecurityConfig::default(secrets_resolver),
            processors: ProcessorsConfig {
                forwarding: ForwardingConfig::default(),
                message_expiry_cleanup: MessageExpiryCleanupConfig::default(),
                session_expiry_cleanup: SessionExpiryCleanupConfig::default(),
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
    if matches!(
        err,
        VtaIntegrationError::NoCachedSecrets | VtaIntegrationError::Vta(_)
    ) {
        print_vta_recovery_playbook(context);
    }
    MediatorError::ConfigError(12, "NA".into(), detail)
}

/// Print an operator-facing recovery playbook to stderr when the
/// mediator can't boot because the cached VTA bundle is gone (or stale)
/// AND the VTA is unreachable.
///
/// The block is intentionally formatted for `journalctl` / `docker logs`
/// readability: a banner that's easy to spot in a wall of structured
/// log output, followed by numbered steps with concrete commands. We
/// write to stderr (not via `tracing`) so the message survives any
/// `RUST_LOG` filter — the operator needs this regardless of log
/// configuration when the process is about to exit.
fn print_vta_recovery_playbook(context: &str) {
    eprintln!(
        "
================================================================================
  MEDIATOR CANNOT START — VTA UNREACHABLE AND NO USABLE CACHE
================================================================================

  Context: {context}

  The mediator could not contact the VTA AND has no fresh cached secret
  bundle to fall back on. To recover, request fresh credentials from the
  VTA admin / Personal Network Manager (PNM) and re-seed this mediator's
  cache. Pick whichever path matches your situation:

  ──────────────────────────────────────────────────────────────────────
  OPTION A — Restore VTA connectivity (fastest)
  ──────────────────────────────────────────────────────────────────────

    If the VTA outage is transient (network blip, VTA host restarting,
    DNS hiccup, etc.) the simplest fix is to restore connectivity and
    restart the mediator. The next successful VTA call will re-seed the
    cache automatically.

      1. Confirm reachability from this host:
           curl -fsS <vta-url>/healthz
      2. Restart the mediator once the VTA is responding.

  ──────────────────────────────────────────────────────────────────────
  OPTION B — Re-provision credentials (sealed-export mode)
  ──────────────────────────────────────────────────────────────────────

    Use this when the existing context on the VTA is intact but this
    mediator's local cache and/or secrets are gone (e.g. lost host,
    wiped disk, expired keyring). Sealed-export reissues the bundle
    without minting a new DID — your mediator's identity stays the
    same.

    You'll need the original setup recipe (`recipe.toml`) used to
    deploy this mediator, with `vta_mode = \"sealed-export\"`. If it's
    been lost, see Option C.

      1. On the mediator host, regenerate a request:
           mediator-setup --from <recipe.toml> --force-reprovision

      2. Hand the resulting request file to your VTA admin. On the VTA
         host, they run:
           vta contexts reprovision --id {context} \\
             --recipient <request.json> \\
             --output <bundle.armor>

      3. Copy `bundle.armor` back to the mediator host and finalise:
           mediator-setup --from <recipe.toml> --bundle <bundle.armor>

      4. Restart the mediator.

  ──────────────────────────────────────────────────────────────────────
  OPTION C — Greenfield re-setup
  ──────────────────────────────────────────────────────────────────────

    Use this only when the context itself is gone on the VTA side, or
    you want to start over with a new mediator DID. This MINTS A NEW
    IDENTITY — clients will need to re-authenticate against the new
    DID.

      mediator-setup

    Pick `Full setup — VTA mints my mediator DID` and follow the
    prompts. See docs/setup-guide.md for the full walkthrough.

  ──────────────────────────────────────────────────────────────────────
  More: docs/setup-guide.md (sections 'Online' and 'Sealed-export')
================================================================================
"
    );
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
            let result = vta_bootstrap::bootstrap_vta(&service_config, &cache, &mediator_secrets)
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

            // Build the refresher alongside the startup result so the
            // outer scope can stash it on Config without re-deriving
            // service_config / ttl_secs.
            let refresher = crate::tasks::vta_refresh::VtaRefresher::new(
                service_config.clone(),
                mediator_secrets.clone(),
                ttl_secs,
                secrets_resolver.clone(),
            );

            Some((result, refresher))
        } else {
            None
        };

        // Resolve mediator DID — from VTA startup result (if VTA mode)
        // or the mediator.toml `mediator_did` field (self-hosted mode).
        let mediator_did = if let Some((ref result, _)) = vta_startup {
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
            local_endpoints: raw.server.local_endpoints,
            database: database_config_from_raw(raw.database),
            streaming_enabled: raw.streaming.enabled.parse().unwrap_or_else(|_| {
                warn!(
                    "Could not parse streaming.enabled value '{}', using default: true",
                    raw.streaming.enabled
                );
                true
            }),
            did_resolver_config: did_resolver_cache_config(&raw.did_resolver),
            api_prefix: {
                let normalized = helpers::normalize_api_prefix(&raw.server.api_prefix);
                if normalized != raw.server.api_prefix {
                    info!(
                        original = %raw.server.api_prefix,
                        normalized = %normalized,
                        "api_prefix normalized — empty/`/` means mount at root, otherwise canonical form is `/<segment>` with no trailing slash"
                    );
                }
                normalized
            },
            security: raw
                .security
                .convert(
                    secrets_resolver.clone(),
                    &mediator_secrets,
                    vta_startup.as_ref().map(|(r, _)| &r.bundle),
                )
                .await?,
            processors: ProcessorsConfig {
                forwarding: processors::forwarding_config_from_raw(
                    raw.processors.forwarding.clone(),
                )?,
                message_expiry_cleanup: raw.processors.message_expiry_cleanup.clone().try_into()?,
                session_expiry_cleanup: raw.processors.session_expiry_cleanup.clone().try_into()?,
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
            // VTA-linked deployments get a periodic refresh task; built
            // alongside the StartupResult above so the service config
            // and TTL parsing aren't re-derived here.
            vta_refresher: vta_startup.as_ref().map(|(_, refresher)| refresher.clone()),
            ..Config::default(secrets_resolver)
        };

        config.mediator_did_hash = digest(&config.mediator_did);

        // Initialise a mutable did document for later use on validation and resolver loading
        let mut did_document: Option<Document> = None;

        // Are we self-hosting our own did:web Document?
        if let Some(path) = raw.server.did_web_self_hosted {
            let document_json = read_document(&path, &aws_config).await?;

            let (did_json, did_jsonl, parsed_document) =
                split_self_hosted_did_source(document_json)?;
            config.mediator_did_doc = Some(did_json);
            config.mediator_did_log = did_jsonl;

            // Store the parsed Document for later use
            did_document = Some(parsed_document);
        }

        // Cross-field config invariants (incl. JWT access < refresh) are
        // validated as one pass once `config` is fully populated — see the
        // `validate::validate_config` call before `Ok(config)` below.

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

        // Load the Local DID Document if self hosted. Preload it into this
        // (config-validation) resolver so forwarding-loop detection can
        // resolve our own DID, and stash the typed document on the config so
        // the request-time server resolver can preload the same document
        // without parsing it a second time.
        if let Some(mediator_doc) = did_document {
            preload_self_did(&mut did_resolver, &config.mediator_did, &mediator_doc).await;
            config.mediator_did_document = Some(mediator_doc);
        }

        // ── Guard: operating secrets must be able to decrypt our own traffic ──
        //
        // See `assert_operating_secrets_cover_key_agreement`. For a self-hosted
        // DID we check against the local document we just loaded. For a
        // VTA-managed / network-published DID (no `did_web_self_hosted`) we
        // resolve our *own* published DID and check against that — that path was
        // previously unguarded, so a VTA key-label/kid mismatch booted clean and
        // failed every request at runtime. A resolver failure is logged and
        // skipped (a transient DID-host blip must not block boot); only a
        // *confirmed* coverage gap aborts startup.
        match &config.mediator_did_document {
            Some(doc) => {
                assert_operating_secrets_cover_key_agreement(
                    doc,
                    config.security.mediator_secrets.as_ref(),
                )
                .await?;
            }
            None => match did_resolver.resolve(&config.mediator_did).await {
                Ok(resolved) => {
                    assert_operating_secrets_cover_key_agreement(
                        &resolved.doc,
                        config.security.mediator_secrets.as_ref(),
                    )
                    .await?;
                }
                Err(err) => {
                    warn!(
                        mediator_did = %config.mediator_did,
                        error = %err,
                        "Could not resolve our own published DID document at boot; skipping the \
                         operating-secret coverage guard. Inbound DIDComm decryption is unverified \
                         — a key/kid mismatch would surface at runtime as \"No local secret matches \
                         any JWE recipient\"."
                    );
                }
            },
        }

        load_forwarding_protection_blocks(
            &did_resolver,
            &mut config.processors.forwarding,
            &config.mediator_did,
            &raw.processors.forwarding.blocked_forwarding_dids,
        )
        .await?;

        // Boot-time invariant validation: hard conflicts abort startup with
        // an actionable message; suspicious-but-legal combinations warn.
        validate::validate_config(&config)?;

        Ok(config)
    }
}

/// Split a self-hosted DID source into the bodies served at the well-known
/// routes, returning `(did.json body, did.jsonl body, typed Document)`.
///
/// We split the canonical DID Document (served at `did.json`) from the raw
/// log entry stream (served at `did.jsonl`) so each well-known route returns
/// the correct shape — an earlier version served the raw input verbatim at
/// both routes, which meant `did.jsonl` returned a DID Document for did:web
/// sources and `did.json` returned a log envelope for did:webvh sources.
///
/// For did:webvh sources the `did.json` body's identifier is additionally
/// rewritten from `did:webvh:{scid}:{domain}` to `did:web:{domain}` (id,
/// controller, key and service self-references). `did.json` is the did:web
/// resolution surface; without the rewrite a `did:web:{domain}` resolver
/// receives a document whose id and `#key-…` references all live under
/// `did:webvh:`, so they can't be dereferenced. The `did.jsonl` body
/// (`Some` only for did:webvh sources) and the typed Document both stay
/// verbatim (real did:webvh) for did:webvh resolvers and the mediator's own
/// DID.
fn split_self_hosted_did_source(
    document_json: String,
) -> Result<(String, Option<String>, Document), MediatorError> {
    // Validate and parse as LogEntry (webvh format) first, then fall back to
    // a direct DID Document (did:web source).
    match LogEntry::deserialize_string(&document_json, None) {
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

            // The extracted state's `id` is the did:webvh DID; rewrite it (and every
            // self-reference) to the did:web form for the `did.json` handler. The
            // typed `Document` below is parsed from the original `did:webvh` value so
            // the resolver preload keeps the mediator's real DID.
            let webvh_did = did_doc_value
                .get("id")
                .and_then(|id| id.as_str())
                .ok_or_else(|| {
                    error!("Extracted DID Document from LogEntry is missing an `id`");
                    MediatorError::ConfigError(
                        12,
                        "NA".into(),
                        "Extracted DID Document from LogEntry is missing an `id`".into(),
                    )
                })?
                .to_string();

            let (_web_did, web_doc_value) = rewrite_did_document_to_web(&did_doc_value, &webvh_did)
                .map_err(|err| {
                    error!("Couldn't rewrite did:webvh document to did:web. Reason: {err}");
                    MediatorError::ConfigError(
                        12,
                        "NA".into(),
                        format!("Couldn't rewrite did:webvh document to did:web. Reason: {err}"),
                    )
                })?;

            // Serialise the rewritten did:web document for the did.json handler. The
            // resolver receives the typed `Document` below (parsed from the original
            // did:webvh value) so we don't pay double parse costs at request time.
            let did_json = serde_json::to_string(&web_doc_value).map_err(|err| {
                error!("Couldn't serialise extracted DID Document as JSON. Reason: {err}");
                MediatorError::ConfigError(
                    12,
                    "NA".into(),
                    format!("Couldn't serialise extracted DID Document as JSON. Reason: {err}"),
                )
            })?;

            let typed = serde_json::from_value(did_doc_value).map_err(|err| {
                error!("Couldn't convert DID Document value to Document struct. Reason: {err}");
                MediatorError::ConfigError(
                    12,
                    "NA".into(),
                    format!(
                        "Couldn't convert DID Document value to Document struct. Reason: {err}"
                    ),
                )
            })?;

            Ok((did_json, Some(document_json), typed))
        }
        Err(_log_entry_err) => {
            // did:web source — the raw input is the DID document; no log entry to serve.
            let typed = serde_json::from_str::<Document>(&document_json).map_err(|err| {
                error!("Couldn't parse content as LogEntry or Document. Reason: {err}");
                MediatorError::ConfigError(
                    12,
                    "NA".into(),
                    format!("Couldn't parse content as LogEntry or Document. Reason: {err}"),
                )
            })?;
            Ok((document_json, None, typed))
        }
    }
}

/// Ensure the mediator's DID document advertises a `TSPTransport` service so peers can
/// discover its TSP endpoint (remote routed/nested forwarding resolves it from the DID
/// document). For **did:web** the service is added automatically, mirroring the
/// `DIDCommMessaging` endpoint (TSP and DIDComm share `/inbound`); **did:peer** and
/// **did:webvh** bind the document to the DID, so their service must be baked in at DID
/// generation — there we only warn. A no-op unless the `tsp` feature is on.
///
/// Called once at startup ([`crate::server::serve_internal`]) so it covers both the
/// config-file path (typed `mediator_did_document`) and the builder path (served JSON
/// only).
#[cfg(feature = "tsp")]
pub(crate) fn apply_tsp_did_advertisement(config: &mut Config) {
    // Work from the typed document if we have it (config-file path), else parse the
    // served JSON (builder path). No self-hosted document (e.g. a network-published
    // did:peer) → nothing to advertise here.
    let mut doc = match config.mediator_did_document.clone() {
        Some(doc) => doc,
        None => match config
            .mediator_did_doc
            .as_ref()
            .and_then(|json| serde_json::from_str::<Document>(json).ok())
        {
            Some(doc) => doc,
            None => return,
        },
    };

    // did:web (no webvh log) is the only form we may safely mutate in place.
    if config.mediator_did_log.is_none()
        && let Some(augmented) = augment_did_web_doc_with_tsp_service(&mut doc, &config.mediator_did)
    {
        config.mediator_did_doc = Some(augmented);
        config.mediator_did_document = Some(doc.clone());
    }

    if !doc
        .service
        .iter()
        .any(|s| s.type_.iter().any(|t| t == affinidi_tsp::TSP_SERVICE_TYPE))
    {
        warn!(
            "TSP is enabled but the mediator DID document advertises no '{}' service; \
             other mediators cannot discover this mediator's TSP endpoint for routed/nested \
             forwarding. For did:web it is added automatically from the DIDCommMessaging \
             endpoint (is one present?); for did:peer / did:webvh add the service at DID \
             generation.",
            affinidi_tsp::TSP_SERVICE_TYPE
        );
    }
}

/// Ensure a self-hosted **did:web** document advertises a `TSPTransport` service,
/// mirroring the `DIDCommMessaging` endpoint (TSP and DIDComm share the mediator's
/// `/inbound`). Returns the re-serialised document JSON when a service was added, or
/// `None` if the document already advertises TSP or has no DIDComm endpoint to mirror.
///
/// Only safe for did:web, where the served document is authoritative — did:peer and
/// did:webvh bind the document to the DID, so their service must be set at generation.
#[cfg(feature = "tsp")]
fn augment_did_web_doc_with_tsp_service(doc: &mut Document, did: &str) -> Option<String> {
    use affinidi_did_common::ServiceBuilder;
    use affinidi_did_common::service::Endpoint;

    let tsp_type = affinidi_tsp::TSP_SERVICE_TYPE;

    // Already advertised — nothing to do.
    if doc
        .service
        .iter()
        .any(|s| s.type_.iter().any(|t| t == tsp_type))
    {
        return None;
    }

    // Mirror the first DIDCommMessaging endpoint URI — TSP lands on the same `/inbound`.
    let uri = doc
        .service
        .iter()
        .find(|s| s.type_.iter().any(|t| t == "DIDCommMessaging"))
        .and_then(|s| s.service_endpoint.get_uri())?;
    let endpoint = url::Url::parse(uri.trim_matches('"')).ok()?;

    let service = ServiceBuilder::new(tsp_type, Endpoint::Url(endpoint))
        .id(&format!("{did}#tsp"))
        .ok()?
        .build();
    doc.service.push(service);

    serde_json::to_string(doc).ok()
}

pub async fn init(config_file: &str, with_ansi: bool) -> Result<Config, MediatorError> {
    // Read configuration file parameters. `read_config_file` lives in the config
    // crate now (returns its lean `ConfigError`); map it back to MediatorError.
    let config =
        affinidi_messaging_mediator_config::env::read_config_file(config_file).map_err(|e| {
            MediatorError::ConfigError(
                crate::common::error_codes::CONFIG_ERROR,
                "NA".into(),
                e.to_string(),
            )
        })?;

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

#[cfg(test)]
mod self_hosted_did_tests {
    use super::*;

    // A real did:webvh log entry (didwebvh-rs `basic-create` test vector).
    // `state.id` is `did:webvh:{scid}:example.com`.
    const WEBVH_LOG: &str = r#"{"versionId":"1-QmPFhMuZH9gjY2JZgyyrgRuFTywQ4mDhoKGVoGE8uy7hFD","versionTime":"2000-01-01T00:00:00Z","parameters":{"method":"did:webvh:1.0","scid":"Qmdxt11AjZewCNXX69bpEDobgjySeZ7eFwjf4tgpF6p2Dg","updateKeys":["z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG"],"portable":false,"nextKeyHashes":[],"watchers":[],"witness":{},"deactivated":false},"state":{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/multikey/v1"],"id":"did:webvh:Qmdxt11AjZewCNXX69bpEDobgjySeZ7eFwjf4tgpF6p2Dg:example.com","controller":"did:webvh:Qmdxt11AjZewCNXX69bpEDobgjySeZ7eFwjf4tgpF6p2Dg:example.com","verificationMethod":[{"type":"Multikey","controller":"did:webvh:Qmdxt11AjZewCNXX69bpEDobgjySeZ7eFwjf4tgpF6p2Dg:example.com","publicKeyMultibase":"z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG","id":"did:webvh:Qmdxt11AjZewCNXX69bpEDobgjySeZ7eFwjf4tgpF6p2Dg:example.com#P5RDjVJG"}],"authentication":["did:webvh:Qmdxt11AjZewCNXX69bpEDobgjySeZ7eFwjf4tgpF6p2Dg:example.com#P5RDjVJG"],"assertionMethod":[],"keyAgreement":[],"capabilityDelegation":[],"capabilityInvocation":[]},"proof":[{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","verificationMethod":"did:key:z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG#z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG","created":"2000-01-01T00:00:00Z","proofPurpose":"assertionMethod","proofValue":"z3gfipj528cwTsP7aSSWMsPzA5uqSUGSN7WNzJQFf1WTvjpHf9Ftjk6StQmqqzjyjQT9xyqTjEsRp2jw4DBjcyqac"}]}"#;

    // A plain did:web DID document (no webvh log envelope).
    const WEB_DOC: &str = r#"{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/multikey/v1"],"id":"did:web:example.com","controller":"did:web:example.com","verificationMethod":[{"type":"Multikey","controller":"did:web:example.com","publicKeyMultibase":"z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG","id":"did:web:example.com#P5RDjVJG"}],"authentication":["did:web:example.com#P5RDjVJG"]}"#;

    /// did:webvh source: the did.json body must have its id (and every
    /// self-reference) rewritten to did:web, while the did.jsonl body stays
    /// the verbatim webvh log and the typed Document keeps the real did:webvh
    /// id.
    #[test]
    fn webvh_source_rewrites_did_json_only() {
        let (did_json, did_jsonl, typed) =
            split_self_hosted_did_source(WEBVH_LOG.to_string()).unwrap();

        // did.json: rewritten to did:web, no webvh traces anywhere.
        let doc: serde_json::Value = serde_json::from_str(&did_json).unwrap();
        assert_eq!(doc["id"], "did:web:example.com");
        assert_eq!(doc["controller"], "did:web:example.com");
        assert!(!did_json.contains("did:webvh:"));
        for vm in doc["verificationMethod"].as_array().unwrap() {
            assert!(
                vm["id"]
                    .as_str()
                    .unwrap()
                    .starts_with("did:web:example.com#")
            );
        }

        // did.jsonl: verbatim webvh log, unchanged.
        assert_eq!(did_jsonl.as_deref(), Some(WEBVH_LOG));

        // typed Document: the mediator's real did:webvh identity.
        assert_eq!(
            typed.id.as_str(),
            "did:webvh:Qmdxt11AjZewCNXX69bpEDobgjySeZ7eFwjf4tgpF6p2Dg:example.com"
        );
    }

    /// did:web source: served verbatim at did.json, no did.jsonl log.
    #[test]
    fn web_source_served_verbatim_without_log() {
        let (did_json, did_jsonl, typed) =
            split_self_hosted_did_source(WEB_DOC.to_string()).unwrap();

        assert_eq!(did_json, WEB_DOC);
        assert!(did_jsonl.is_none());
        assert_eq!(typed.id.as_str(), "did:web:example.com");
    }
}

#[cfg(all(test, feature = "tsp"))]
mod tsp_advertise_tests {
    use super::*;

    fn did_doc(services: &str) -> Document {
        let json = format!(
            r#"{{ "id": "did:web:mediator.example.com", "service": [{services}] }}"#
        );
        serde_json::from_str(&json).expect("valid DID document")
    }

    const DIDCOMM: &str = r#"{
        "id": "did:web:mediator.example.com#didcomm",
        "type": "DIDCommMessaging",
        "serviceEndpoint": "https://mediator.example.com/inbound"
    }"#;

    #[test]
    fn adds_tsp_service_mirroring_the_didcomm_endpoint() {
        let mut doc = did_doc(DIDCOMM);
        let out = augment_did_web_doc_with_tsp_service(&mut doc, "did:web:mediator.example.com");
        assert!(out.is_some(), "a TSPTransport service should have been added");

        let tsp: Vec<_> = doc
            .service
            .iter()
            .filter(|s| s.type_.iter().any(|t| t == affinidi_tsp::TSP_SERVICE_TYPE))
            .collect();
        assert_eq!(tsp.len(), 1, "exactly one TSPTransport service");
        assert_eq!(
            tsp[0].service_endpoint.get_uri().as_deref(),
            Some("https://mediator.example.com/inbound"),
            "the TSP endpoint mirrors the DIDCommMessaging endpoint"
        );
        // The re-serialised JSON carries the new service.
        assert!(out.unwrap().contains(affinidi_tsp::TSP_SERVICE_TYPE));
    }

    #[test]
    fn no_change_when_tsp_already_advertised() {
        let tsp = r#"{
            "id": "did:web:mediator.example.com#tsp",
            "type": "TSPTransport",
            "serviceEndpoint": "https://mediator.example.com/inbound"
        }"#;
        let mut doc = did_doc(&format!("{DIDCOMM},{tsp}"));
        let out = augment_did_web_doc_with_tsp_service(&mut doc, "did:web:mediator.example.com");
        assert!(out.is_none(), "already advertised — no mutation");
        assert_eq!(doc.service.len(), 2, "no extra service appended");
    }

    #[test]
    fn no_change_without_a_didcomm_endpoint_to_mirror() {
        let other = r#"{
            "id": "did:web:mediator.example.com#other",
            "type": "SomeOtherService",
            "serviceEndpoint": "https://mediator.example.com/other"
        }"#;
        let mut doc = did_doc(other);
        let out = augment_did_web_doc_with_tsp_service(&mut doc, "did:web:mediator.example.com");
        assert!(out.is_none(), "no DIDComm endpoint to mirror — no mutation");
    }
}
