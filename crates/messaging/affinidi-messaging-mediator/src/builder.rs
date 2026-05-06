//! Programmatic mediator startup.
//!
//! [`MediatorBuilder`] is the embedding entry point: assemble a config
//! field-by-field, hand it to [`MediatorBuilder::start`], and get a
//! [`MediatorHandle`] back with the bound listener URL, the mediator
//! DID, and a shutdown control.
//!
//! No TOML, no CWD, no global tracing or signal handlers by default.
//! Callers (tests, embedded apps, the mediator binary) opt in to those
//! behaviours via [`StartOpts`].
//!
//! The mediator binary's `start(config_path)` continues to work and
//! routes through this same code path internally.

use crate::common::config::{Config, LimitsConfig, ProcessorsConfig, SecurityConfig, helpers};
use affinidi_did_resolver_cache_sdk::config::{DIDCacheConfig, DIDCacheConfigBuilder};
use affinidi_messaging_mediator_common::{
    MediatorSecrets, database::config::DatabaseConfig, errors::MediatorError, store::MediatorStore,
};
use affinidi_secrets_resolver::ThreadedSecretsResolver;
use axum_server::tls_rustls::RustlsConfig;
use sha256::digest;
use std::{collections::HashMap, net::SocketAddr, sync::Arc};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing_subscriber::filter::LevelFilter;
use url::Url;

// ─── Public types ────────────────────────────────────────────────────────────

/// TLS termination mode for the listener.
pub enum TlsMode {
    /// Plaintext HTTP/WS. Tests and trusted internal networks.
    Plain,
    /// TLS with the supplied rustls config. Caller is responsible for
    /// loading certificates (e.g. via `RustlsConfig::from_pem_file`).
    Rustls(RustlsConfig),
}

impl std::fmt::Debug for TlsMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TlsMode::Plain => f.write_str("TlsMode::Plain"),
            TlsMode::Rustls(_) => f.write_str("TlsMode::Rustls(<rustls>)"),
        }
    }
}

/// Tracing subscriber strategy.
#[derive(Debug)]
pub enum TracingMode {
    /// The caller has already installed a tracing subscriber. The
    /// mediator does not touch the global subscriber. Default for
    /// embedded use — multiple `start_with_config` calls in one process
    /// would otherwise fail when the second tries to install.
    External,
    /// Install the production tracing subscriber. Used by the mediator
    /// binary at startup. Calling this when a subscriber is already
    /// installed is a no-op (the install fails silently).
    InstallProduction {
        ansi: bool,
        log_json: bool,
        log_level: LevelFilter,
    },
}

/// Deployment-time knobs that are not part of [`Config`].
#[derive(Debug)]
pub struct StartOpts {
    pub tls: TlsMode,
    pub tracing: TracingMode,
    /// Install SIGINT/SIGTERM handlers that cancel the shutdown token
    /// passed to [`MediatorBuilder::start`]. The mediator binary sets
    /// this `true`; embedded callers own their own signal handling and
    /// leave it `false`.
    pub install_signal_handlers: bool,
}

impl Default for StartOpts {
    fn default() -> Self {
        Self {
            tls: TlsMode::Plain,
            tracing: TracingMode::External,
            install_signal_handlers: false,
        }
    }
}

/// Handle returned by [`MediatorBuilder::start`].
///
/// The server is running in a background task by the time this is
/// returned. The listener is already bound — `bound_addr` and
/// `http_endpoint` reflect the actual port even when the caller
/// requested `:0`.
pub struct MediatorHandle {
    /// Base HTTP endpoint, e.g. `http://127.0.0.1:50321/mediator/v1/`.
    /// Scheme is `https` when [`TlsMode::Rustls`] is selected.
    pub http_endpoint: Url,
    /// WebSocket endpoint, e.g. `ws://127.0.0.1:50321/mediator/v1/ws`.
    /// Scheme is `wss` when [`TlsMode::Rustls`] is selected.
    pub ws_endpoint: Url,
    /// Bound socket address as the OS reports it. Populated even when
    /// the caller requested an ephemeral port (`:0`).
    pub bound_addr: SocketAddr,
    /// Mediator's DID, useful for tests that need to construct DIDComm
    /// envelopes addressed to this instance.
    pub mediator_did: String,
    /// Admin DID configured at startup.
    pub admin_did: String,

    shutdown_token: CancellationToken,
    server_task: JoinHandle<Result<(), MediatorError>>,
}

impl MediatorHandle {
    /// Internal constructor — `server::serve_internal` builds the
    /// handle once the listener is bound and the server task is
    /// spawned. Not part of the public API.
    #[doc(hidden)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn __from_internals(
        http_endpoint: Url,
        ws_endpoint: Url,
        bound_addr: SocketAddr,
        mediator_did: String,
        admin_did: String,
        shutdown_token: CancellationToken,
        server_task: JoinHandle<Result<(), MediatorError>>,
    ) -> Self {
        Self {
            http_endpoint,
            ws_endpoint,
            bound_addr,
            mediator_did,
            admin_did,
            shutdown_token,
            server_task,
        }
    }

    /// Trigger graceful shutdown. The server stops accepting new
    /// connections and drains in-flight requests for up to 30s.
    pub fn shutdown(&self) {
        self.shutdown_token.cancel();
    }

    /// Clone of the shutdown token. Useful when the caller wants to
    /// share cancellation with other tasks.
    pub fn shutdown_token(&self) -> CancellationToken {
        self.shutdown_token.clone()
    }

    /// Wait for the server task to finish. Returns the server's exit
    /// status — `Ok(())` for graceful shutdown, `Err` for runtime
    /// errors. Consumes the handle.
    pub async fn join(self) -> Result<(), MediatorError> {
        match self.server_task.await {
            Ok(result) => result,
            Err(join_err) => Err(MediatorError::InternalError(
                500,
                "shutdown".into(),
                format!("Mediator server task panicked: {join_err}"),
            )),
        }
    }
}

impl std::fmt::Debug for MediatorHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MediatorHandle")
            .field("http_endpoint", &self.http_endpoint.as_str())
            .field("ws_endpoint", &self.ws_endpoint.as_str())
            .field("bound_addr", &self.bound_addr)
            .field("mediator_did", &self.mediator_did)
            .field("admin_did", &self.admin_did)
            .finish()
    }
}

// ─── Builder ─────────────────────────────────────────────────────────────────

/// Fluent builder for an embedded mediator instance.
///
/// All required fields must be set explicitly: the builder fails fast
/// on `start()` with a `ConfigError` when something load-bearing is
/// missing. Optional fields take sensible defaults — see the per-method
/// documentation.
///
/// # Example
///
/// ```ignore
/// use affinidi_messaging_mediator::builder::{MediatorBuilder, TlsMode};
/// use tokio_util::sync::CancellationToken;
///
/// let token = CancellationToken::new();
/// let mediator = MediatorBuilder::new(secrets_resolver)
///     .mediator_did("did:peer:2.Ez6...")
///     .admin_did("did:peer:2.Ez6...")
///     .secrets_backend(backend)
///     .database(redis_config)
///     .listen_addr("127.0.0.1:0".parse().unwrap())
///     .tls(TlsMode::Plain)
///     .start(token.clone())
///     .await?;
///
/// println!("Mediator listening at {}", mediator.http_endpoint);
/// // ... do work ...
/// mediator.shutdown();
/// mediator.join().await?;
/// ```
pub struct MediatorBuilder {
    config: Config,
    listen_addr: Option<SocketAddr>,
    streaming_uuid_set: bool,
    opts: StartOpts,
    /// Pre-built store. When `Some`, the server skips Redis-specific
    /// bootstrap (`DatabaseHandler::new`, `Database::initialize`, Lua
    /// loading) and skips background tasks that take a raw
    /// `Database` (statistics, message expiry, forwarding processor,
    /// websocket streaming). The store is wired into `SharedData`
    /// directly. Memory and Fjall backends use this path.
    store: Option<Arc<dyn MediatorStore>>,
}

impl MediatorBuilder {
    /// Begin building a mediator with the given secrets resolver.
    ///
    /// The resolver provides the operating keys — it must already be
    /// populated with the mediator's signing and key-agreement secrets
    /// before `start` is called. Embedded callers typically do this by
    /// calling `ThreadedSecretsResolver::insert_vec` immediately after
    /// constructing the resolver, or by using the helper in
    /// `affinidi-messaging-test-mediator`.
    pub fn new(secrets_resolver: Arc<ThreadedSecretsResolver>) -> Self {
        let mut config = Config::headless(secrets_resolver);
        // Auto-generate a streaming UUID — callers can override via
        // `streaming_uuid()` if they need a deterministic value.
        config.streaming_uuid = uuid::Uuid::new_v4().to_string();
        // Embedded callers don't go through the VTA bootstrap, so the
        // operating-keys-loaded gate is satisfied by their resolver
        // injection instead. Default to `true`; callers that haven't
        // populated the resolver will fail at first signing attempt.
        config.operating_keys_loaded = true;
        // Embedded mode tags itself for telemetry.
        config
            .tags
            .insert("startup".to_string(), "embedded".to_string());

        Self {
            config,
            listen_addr: None,
            streaming_uuid_set: false,
            opts: StartOpts::default(),
            store: None,
        }
    }

    /// Supply a pre-built [`MediatorStore`]. When set, the server uses
    /// this store directly instead of constructing a Redis-backed one
    /// from the [`DatabaseConfig`]. Memory and Fjall backends are
    /// expected to use this; production Redis deployments leave it
    /// unset and rely on the [`database`](Self::database) setter.
    ///
    /// Setting a store also causes the server to skip background
    /// tasks that take a raw `Database` (statistics, message-expiry
    /// sweep, forwarding processor, websocket streaming). Subsequent
    /// commits refactor those tasks to take a trait object so they
    /// can run on any backend.
    pub fn store(mut self, store: Arc<dyn MediatorStore>) -> Self {
        self.store = Some(store);
        self
    }

    /// Convenience: open a `FjallStore` at the given on-disk path
    /// and wire it in via [`store`](Self::store). Equivalent to
    /// `builder.store(Arc::new(FjallStore::open(path)?))`.
    ///
    /// Available when the `fjall-backend` feature is enabled.
    #[cfg(feature = "fjall-backend")]
    pub fn fjall_path(self, path: impl AsRef<std::path::Path>) -> Result<Self, MediatorError> {
        let store = crate::store::FjallStore::open(path)?;
        Ok(self.store(Arc::new(store)))
    }

    /// Convenience: construct a fresh in-memory `MemoryStore` and
    /// wire it in. Available when the `memory-backend` feature is
    /// enabled. Tests typically reach for this directly via
    /// `affinidi-messaging-test-mediator`.
    #[cfg(feature = "memory-backend")]
    pub fn memory_store(self) -> Self {
        let store = crate::store::MemoryStore::new();
        self.store(Arc::new(store))
    }

    /// Set the mediator's DID. Required.
    pub fn mediator_did(mut self, did: impl Into<String>) -> Self {
        self.config.mediator_did = did.into();
        self.config.mediator_did_hash = digest(self.config.mediator_did.as_str());
        self
    }

    /// Set the admin DID for this mediator. Required.
    pub fn admin_did(mut self, did: impl Into<String>) -> Self {
        self.config.admin_did = did.into();
        self
    }

    /// Set the unified secret backend. Required.
    pub fn secrets_backend(mut self, backend: MediatorSecrets) -> Self {
        self.config.secrets_backend = backend;
        self
    }

    /// Set a human-readable URL for the secrets backend. Surfaced in
    /// `/readyz` so operators can see which backend the mediator is
    /// using. Defaults to `"(programmatic)"` when not set.
    pub fn secrets_backend_url(mut self, url: impl Into<String>) -> Self {
        self.config.secrets_backend_url = url.into();
        self
    }

    /// Set the database configuration. Required.
    ///
    /// Once the [`MediatorStore`] trait refactor lands (commits 5–6),
    /// this becomes `store(Arc<dyn MediatorStore>)`. Until then the
    /// builder takes a [`DatabaseConfig`] directly so the existing
    /// Redis path keeps working.
    ///
    /// [`MediatorStore`]: affinidi_messaging_mediator_common::store::MediatorStore
    pub fn database(mut self, database: DatabaseConfig) -> Self {
        self.config.database = database;
        self
    }

    /// Set the address to bind. Defaults to `127.0.0.1:0` (ephemeral
    /// port chosen by the OS) when not set.
    pub fn listen_addr(mut self, addr: SocketAddr) -> Self {
        self.listen_addr = Some(addr);
        self.config.listen_address = addr.to_string();
        self
    }

    /// Set the URL prefix for mediator routes. Defaults to
    /// `/mediator/v1`. The supplied value is normalised to canonical
    /// form (`""` for root, otherwise `"/<segment>"` with no trailing
    /// slash) — leading/trailing slashes and surrounding whitespace are
    /// stripped, so `"/foo/"`, `"foo"`, and `"/foo"` all behave the
    /// same.
    pub fn api_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.config.api_prefix = helpers::normalize_api_prefix(&prefix.into());
        self
    }

    /// Declare URL aliases the mediator should treat as pointing at
    /// itself when classifying a routing 2.0 next-hop's service
    /// endpoint as local vs. remote. The bind address from
    /// [`listen_addr`] is always considered local; use this for
    /// additional public-facing hostnames (e.g. when fronted by a
    /// load balancer or reverse proxy).
    ///
    /// Each entry is parsed as a URL — `http://`, `https://`, `ws://`,
    /// and `wss://` are all accepted. Only the host and port are
    /// retained for comparison.
    ///
    /// [`listen_addr`]: Self::listen_addr
    pub fn local_endpoints<I, S>(mut self, endpoints: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.config.local_endpoints = endpoints.into_iter().map(Into::into).collect();
        self
    }

    /// Set the streaming task UUID. Defaults to a random `Uuid::new_v4`
    /// generated in [`MediatorBuilder::new`]. Override only when tests
    /// need a deterministic value.
    pub fn streaming_uuid(mut self, uuid: impl Into<String>) -> Self {
        self.config.streaming_uuid = uuid.into();
        self.streaming_uuid_set = true;
        self
    }

    /// Enable or disable the WebSocket streaming task. Defaults to
    /// enabled. Tests that don't exercise live delivery can disable to
    /// skip the task spawn.
    pub fn streaming_enabled(mut self, enabled: bool) -> Self {
        self.config.streaming_enabled = enabled;
        self
    }

    /// Replace the security config wholesale. Use this to inject
    /// pre-built JWT keys from your secrets backend, configure CORS,
    /// adjust ACL defaults, etc.
    ///
    /// Defaults from [`Config::headless`] use zero-byte JWT keys —
    /// **that is not usable in production**. Embedded callers must set
    /// real keys before starting.
    pub fn security(mut self, security: SecurityConfig) -> Self {
        self.config.security = security;
        self
    }

    /// Replace the limits config (rate limits, queue sizes, request
    /// body cap). Defaults from [`LimitsConfig::default`] are sane for
    /// development; production deployments tune these.
    pub fn limits(mut self, limits: LimitsConfig) -> Self {
        self.config.limits = limits;
        self
    }

    /// Replace the processors config (forwarding, message expiry).
    /// Defaults disable both — embedded tests that don't need these
    /// background tasks save the spawn cost.
    pub fn processors(mut self, processors: ProcessorsConfig) -> Self {
        self.config.processors = processors;
        self
    }

    /// Replace the DID resolver config. Defaults to in-process network
    /// resolution. Tests typically wire a static resolver via the
    /// `network_mode` configuration of the cache SDK so the test
    /// mediator can resolve its own DID without DNS.
    pub fn did_resolver(mut self, did_resolver: DIDCacheConfig) -> Self {
        self.config.did_resolver_config = did_resolver;
        self
    }

    /// Convenience: build a DID resolver config with the given
    /// `network_mode` URL.
    pub fn did_resolver_url(self, url: impl Into<String>) -> Self {
        let cfg = DIDCacheConfigBuilder::default()
            .with_cache_capacity(1000)
            .with_cache_ttl(300)
            .with_network_timeout(5)
            .with_network_cache_limit_count(100)
            .with_network_mode(url.into().as_str())
            .build();
        self.did_resolver(cfg)
    }

    /// Add a metric tag pair. Tags appear in Prometheus exports and
    /// the admin status endpoint. Repeated calls accumulate.
    pub fn tag(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.config.tags.insert(key.into(), value.into());
        self
    }

    /// Replace the entire tag map.
    pub fn tags(mut self, tags: HashMap<String, String>) -> Self {
        self.config.tags = tags;
        self
    }

    /// Serve a self-hosted DID document at `/.well-known/did.json`.
    /// Pass the JSON-serialised DID document.
    pub fn mediator_did_doc(mut self, doc_json: impl Into<String>) -> Self {
        self.config.mediator_did_doc = Some(doc_json.into());
        self
    }

    /// Serve a self-hosted did:webvh log at `/.well-known/did.jsonl`.
    /// Pass the JSONL log entry stream.
    pub fn mediator_did_log(mut self, log_jsonl: impl Into<String>) -> Self {
        self.config.mediator_did_log = Some(log_jsonl.into());
        self
    }

    /// Configure TLS for the listener. Defaults to [`TlsMode::Plain`].
    pub fn tls(mut self, tls: TlsMode) -> Self {
        self.opts.tls = tls;
        match &self.opts.tls {
            TlsMode::Plain => self.config.security.use_ssl = false,
            TlsMode::Rustls(_) => self.config.security.use_ssl = true,
        }
        self
    }

    /// Configure tracing subscriber strategy. Defaults to
    /// [`TracingMode::External`] — i.e., the mediator does not touch
    /// the global subscriber.
    pub fn tracing(mut self, mode: TracingMode) -> Self {
        self.opts.tracing = mode;
        self
    }

    /// Whether to install SIGINT/SIGTERM handlers. Defaults to `false`;
    /// the mediator binary opts in.
    pub fn install_signal_handlers(mut self, install: bool) -> Self {
        self.opts.install_signal_handlers = install;
        self
    }

    /// Direct mutable access to the underlying [`Config`] for fields
    /// not yet covered by typed setters. Prefer the typed setters when
    /// available — they handle derived fields (e.g. DID hashes).
    pub fn config_mut(&mut self) -> &mut Config {
        &mut self.config
    }

    /// Validate the builder state and start the mediator.
    ///
    /// The returned [`MediatorHandle`] resolves once the listener is
    /// bound. The server itself runs in a background task.
    pub async fn start(
        mut self,
        shutdown_token: CancellationToken,
    ) -> Result<MediatorHandle, MediatorError> {
        // Default listen address: ephemeral port on loopback. Most
        // common case for tests and embedded deployments. Production
        // operators set this explicitly.
        if self.listen_addr.is_none() {
            let default: SocketAddr = "127.0.0.1:0".parse().unwrap();
            self.listen_addr = Some(default);
            self.config.listen_address = default.to_string();
        }

        // Default secrets_backend_url so /readyz has something to show.
        if self.config.secrets_backend_url.is_empty() {
            self.config.secrets_backend_url = "(programmatic)".to_string();
        }

        // Validate required fields. Bail with a clear message rather
        // than letting the inner startup panic on empty strings.
        // The database-config requirement is waived when the caller
        // supplied a pre-built store via [`store`](Self::store) — that
        // store replaces the Redis-built one entirely.
        validate(&self.config, self.store.is_some())?;

        // Preserve the hostname-tag convention used by the TOML path.
        // Failures here are non-fatal — the tag is only used in metric
        // exports and `/admin/status`, and embedded callers can pass
        // their own via `tag()` if they care.
        if !self.config.tags.contains_key("hostname")
            && let Ok(host) = hostname::get()
            && let Ok(host) = host.into_string()
        {
            self.config.tags.insert("hostname".to_string(), host);
        }

        crate::server::serve_internal(self.config, self.opts, shutdown_token, self.store).await
    }
}

// ─── Validation ──────────────────────────────────────────────────────────────

fn validate(config: &Config, has_store: bool) -> Result<(), MediatorError> {
    if config.mediator_did.is_empty() {
        return Err(MediatorError::ConfigError(
            12,
            "builder".into(),
            "mediator_did is required (call MediatorBuilder::mediator_did)".into(),
        ));
    }
    if config.admin_did.is_empty() {
        return Err(MediatorError::ConfigError(
            12,
            "builder".into(),
            "admin_did is required (call MediatorBuilder::admin_did)".into(),
        ));
    }
    if !has_store && config.database.database_url.is_empty() {
        return Err(MediatorError::ConfigError(
            12,
            "builder".into(),
            "database is required (call MediatorBuilder::database with a DatabaseConfig, \
             or supply a pre-built store via MediatorBuilder::store)"
                .into(),
        ));
    }
    Ok(())
}
