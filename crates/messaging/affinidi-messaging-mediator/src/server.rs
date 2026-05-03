use crate::{
    SharedData,
    builder::{MediatorHandle, StartOpts, TlsMode, TracingMode},
    common::{
        config::{Config, init},
        did_rate_limiter::DidRateLimiter,
        error_codes,
        metrics::{self, metrics_handler},
        rate_limiter::{RateLimitLayer, RateLimiterState},
        request_id::RequestIdLayer,
    },
    database::Database,
    handlers::{admin_status, application_routes, health_checker_handler, readiness_handler},
    tasks::{
        forwarding_processor::ForwardingProcessor, statistics::statistics,
        websocket_streaming::StreamingTask,
    },
};
use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use affinidi_messaging_mediator_common::database::DatabaseHandler;
use affinidi_messaging_mediator_common::errors::MediatorError;
use affinidi_messaging_mediator_processors::message_expiry_cleanup::processor::MessageExpiryCleanupProcessor;
#[cfg(feature = "didcomm")]
use affinidi_messaging_sdk::protocols::discover_features::DiscoverFeatures;
use axum::{Router, routing::get};
use std::{env, net::SocketAddr, sync::Arc, sync::atomic::AtomicUsize, time::Duration};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::trace::{self, TraceLayer};
use tracing::{Level, error, info, warn};
use tracing_subscriber::EnvFilter;
use url::Url;

/// Run the mediator HTTP server from a TOML config path.
///
/// This is the historical CLI entry point and remains the primary path
/// for the mediator binary. Internally it loads the TOML, installs the
/// production tracing subscriber via [`init`], and then delegates to
/// [`serve_internal`] (the same code path that backs
/// [`MediatorBuilder::start`](crate::builder::MediatorBuilder::start)).
///
/// `config_path` resolves relative to the current working directory —
/// `conf/mediator.toml` is the historical default. Embedded callers
/// should use [`MediatorBuilder`](crate::builder::MediatorBuilder)
/// instead so they can construct config in-memory and avoid CWD coupling.
pub async fn start(config_path: &str) -> Result<(), MediatorError> {
    let ansi = env::var("LOCAL").is_ok();

    if ansi {
        print_banner();
    }

    println!("[Loading Affinidi Secure Messaging Mediator configuration]");

    // `init` reads the TOML, installs the global tracing subscriber,
    // and returns a fully resolved Config. It also pulls operating keys
    // from the secrets backend (and the VTA, when configured).
    let config = init(config_path, ansi).await.map_err(|e| {
        error!("Couldn't initialize mediator: {e}");
        e
    })?;

    // Build the matching StartOpts for the binary path. TLS comes from
    // the TOML; tracing is already installed by `init`; the binary
    // owns signal handling.
    let tls = if config.security.use_ssl {
        info!("This mediator is using SSL/TLS for secure communication.");
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let cert_file = config
            .security
            .ssl_certificate_file
            .clone()
            .ok_or_else(|| {
                error!("SSL Certificate file must be specified in the config");
                MediatorError::ConfigError(
                    error_codes::CONFIG_ERROR,
                    "NA".into(),
                    "SSL Certificate file must be specified in the config".into(),
                )
            })?;
        let key_file = config.security.ssl_key_file.clone().ok_or_else(|| {
            error!("SSL Certificate key file must be specified in the config");
            MediatorError::ConfigError(
                error_codes::CONFIG_ERROR,
                "NA".into(),
                "SSL Certificate key file must be specified in the config".into(),
            )
        })?;
        let rustls_config =
            axum_server::tls_rustls::RustlsConfig::from_pem_file(cert_file, key_file)
                .await
                .map_err(|e| {
                    error!("Invalid TLS certificate/key: {e}");
                    MediatorError::ConfigError(
                        error_codes::CONFIG_ERROR,
                        "NA".into(),
                        format!("Invalid TLS certificate/key: {e}"),
                    )
                })?;
        TlsMode::Rustls(rustls_config)
    } else {
        warn!("**** WARNING: Running without SSL/TLS ****");
        TlsMode::Plain
    };

    let opts = StartOpts {
        tls,
        // Tracing is already installed by `init` above.
        tracing: TracingMode::External,
        install_signal_handlers: true,
    };

    // Honour the optional `[storage]` section. When the operator
    // picked `fjall` via the wizard (or hand-edited `mediator.toml`),
    // build a `FjallStore` here and hand it to the inner serve path
    // so the Redis bootstrap is skipped.
    let pre_built_store: Option<Arc<dyn affinidi_messaging_mediator_common::store::MediatorStore>> =
        match config.storage.as_ref().map(|s| s.backend.as_str()) {
            Some("fjall") => {
                #[cfg(feature = "fjall-backend")]
                {
                    let data_dir = config
                        .storage
                        .as_ref()
                        .and_then(|s| s.data_dir.clone())
                        .ok_or_else(|| {
                            MediatorError::ConfigError(
                                error_codes::CONFIG_ERROR,
                                "NA".into(),
                                "[storage] backend = \"fjall\" requires `data_dir`".into(),
                            )
                        })?;
                    info!("Opening Fjall data directory at {data_dir}");
                    let store = crate::store::FjallStore::open(&data_dir).map_err(|e| {
                        error!("Failed to open Fjall data directory: {e}");
                        e
                    })?;
                    Some(Arc::new(store) as Arc<_>)
                }
                #[cfg(not(feature = "fjall-backend"))]
                {
                    return Err(MediatorError::ConfigError(
                        error_codes::CONFIG_ERROR,
                        "NA".into(),
                        "[storage] backend = \"fjall\" but the `fjall-backend` feature \
                     is not compiled in. Rebuild the mediator with --features \
                     fjall-backend or switch to backend = \"redis\""
                            .into(),
                    ));
                }
            }
            Some("redis") | None => None,
            Some(other) => {
                return Err(MediatorError::ConfigError(
                    error_codes::CONFIG_ERROR,
                    "NA".into(),
                    format!(
                        "[storage] backend = \"{other}\" is not supported. \
                     Use \"redis\" or \"fjall\"."
                    ),
                ));
            }
        };

    let shutdown_token = CancellationToken::new();
    let handle = serve_internal(config, opts, shutdown_token, pre_built_store).await?;
    info!("Mediator listening on {}", handle.bound_addr);
    handle.join().await
}

/// The actual server start path. Used by both [`start`] (the binary)
/// and [`MediatorBuilder::start`](crate::builder::MediatorBuilder::start)
/// (embedded callers).
///
/// Does NOT install a tracing subscriber by default — that's controlled
/// via `opts.tracing`. Does NOT install signal handlers by default —
/// `opts.install_signal_handlers` controls that. The caller passes a
/// [`CancellationToken`] that drives graceful shutdown; cancelling it
/// (or `MediatorHandle::shutdown`) tells the server to drain.
///
/// Returns once the listener is bound. The actual server runs in a
/// `tokio::spawn`-ed task whose handle lives on [`MediatorHandle`].
pub async fn serve_internal(
    config: Config,
    opts: StartOpts,
    shutdown_token: CancellationToken,
    pre_built_store: Option<Arc<dyn affinidi_messaging_mediator_common::store::MediatorStore>>,
) -> Result<MediatorHandle, MediatorError> {
    if let TracingMode::InstallProduction {
        log_json,
        log_level,
        ansi,
    } = &opts.tracing
    {
        install_production_tracing(*ansi, *log_json, *log_level)?;
    }

    // When the caller supplies a pre-built store (Memory, Fjall, or
    // any future backend), we skip the Redis-specific setup path and
    // wire that store straight into `SharedData`. Background tasks
    // that take a raw `Database` (statistics, message expiry,
    // forwarding processor, websocket streaming) are skipped on this
    // path until they're refactored to take a trait object.
    let database: Option<Database> = if let Some(store) = &pre_built_store {
        // Initialise the store (no-op for Memory; opens partitions
        // for Fjall; loads Lua + runs migrations for Redis if a
        // RedisStore was passed in directly).
        store.initialize().await.map_err(|e| {
            error!("Store initialize failed: {e}");
            e
        })?;
        None
    } else {
        // Set up the Redis database with a 30s connection timeout.
        let handler = match tokio::time::timeout(
            Duration::from_secs(30),
            DatabaseHandler::new(&config.database),
        )
        .await
        {
            Ok(Ok(db)) => db,
            Ok(Err(err)) => {
                error!("Error opening database: {err}");
                return Err(MediatorError::DatabaseError(
                    error_codes::DB_OPERATION_ERROR,
                    "NA".into(),
                    format!("Error opening database: {err}"),
                ));
            }
            Err(_) => {
                error!("Database connection timed out after 30 seconds");
                return Err(MediatorError::DatabaseError(
                    error_codes::DB_OPERATION_ERROR,
                    "NA".into(),
                    "Database connection timed out after 30 seconds".into(),
                ));
            }
        };

        let database = Database::new(
            handler,
            config.database.circuit_breaker_threshold,
            config.database.circuit_breaker_recovery_secs,
        );

        database.initialize(&config).await.map_err(|e| {
            error!("Error initializing database: {e}");
            e
        })?;

        if let Some(functions_file) = &config.database.functions_file {
            info!(
                "Loading LUA scripts into the database from file: {}",
                functions_file
            );
            database.load_scripts(functions_file).await.map_err(|e| {
                error!("Failed to load LUA scripts: {e}");
                e
            })?;
        } else {
            error!("LUA scripts file is required but not specified in the configuration");
            return Err(MediatorError::ConfigError(
                error_codes::CONFIG_ERROR,
                "NA".into(),
                "LUA scripts file is required but not specified in the configuration".into(),
            ));
        }
        Some(database)
    };

    // Build the polymorphic store now so background tasks can take
    // `Arc<dyn MediatorStore>` instead of the concrete `Database`.
    // Pre-built stores (Memory/Fjall) flow through; otherwise wrap
    // the Redis `Database` in a `RedisStore`.
    use affinidi_messaging_mediator_common::store::MediatorStore;
    let store: Arc<dyn MediatorStore> = if let Some(store) = pre_built_store {
        store
    } else {
        // Fall through to the Redis path. When the binary is built
        // without `redis-backend`, `database` is unconditionally
        // `None` and this branch is unreachable — but the compiler
        // still needs a value here. Gate the construction so the
        // build doesn't break on Memory-only or Fjall-only feature
        // sets.
        #[cfg(feature = "redis-backend")]
        {
            use crate::store::RedisStore;
            let database = database
                .as_ref()
                .expect("database must exist when pre_built_store is None");
            Arc::new(RedisStore::new(
                database.clone(),
                config.database.functions_file.clone(),
            ))
        }
        #[cfg(not(feature = "redis-backend"))]
        {
            return Err(MediatorError::ConfigError(
                error_codes::CONFIG_ERROR,
                "NA".into(),
                "no pre-built store supplied and `redis-backend` feature is disabled — \
                 either enable `redis-backend` or pass MediatorBuilder::store(...)"
                    .into(),
            ));
        }
    };

    // Optional signal handler — cancels the same token the caller
    // provided so the embedded path's caller-driven cancellation and
    // the binary's signal-driven cancellation share a code path.
    if opts.install_signal_handlers {
        let signal_token = shutdown_token.clone();
        tokio::spawn(async move {
            shutdown_signal().await;
            info!("Shutdown signal received, initiating graceful shutdown...");
            signal_token.cancel();
        });
    }

    let metrics_handle = metrics::init_metrics();

    // Statistics task — runs against any backend via the trait.
    let stats_store = store.clone();
    let tags = config.tags.clone();
    let stats_token = shutdown_token.clone();
    tokio::spawn(async move {
        tokio::select! {
            result = statistics(stats_store, tags) => {
                if let Err(e) = result {
                    error!("Statistics thread error: {}", e);
                }
            }
            _ = stats_token.cancelled() => {
                info!("Statistics thread shutting down");
            }
        }
    });

    // Forwarding processor — runs against any backend via the trait.
    if config.processors.forwarding.enabled && config.processors.forwarding.external_forwarding {
        let _database = store.clone();
        let _config = config.processors.forwarding.clone();
        let fwd_token = shutdown_token.clone();
        tokio::spawn(async move {
            let processor = match ForwardingProcessor::new(_config, _database) {
                Ok(p) => p,
                Err(e) => {
                    error!("Failed to create forwarding processor: {}", e);
                    return;
                }
            };
            tokio::select! {
                result = processor.start() => {
                    if let Err(e) = result {
                        error!("Forwarding processor error: {}", e);
                    }
                }
                _ = fwd_token.cancelled() => {
                    info!("Forwarding processor shutting down");
                }
            }
        });
    }

    // The remaining background tasks still take the concrete
    // `Database` (Redis-specific). When a pre-built store is
    // supplied they are skipped — Memory and Fjall don't have a
    // `Database` to give them. Migrating each onto
    // `Arc<dyn MediatorStore>` is tracked as follow-up work.
    if let Some(database) = &database {
        if config.processors.message_expiry_cleanup.enabled {
            let _database = database.handler.clone();
            let _config = config.processors.message_expiry_cleanup.clone();
            let _admin_did_hash = config.mediator_did_hash.clone();
            let cleanup_token = shutdown_token.clone();
            tokio::spawn(async move {
                let _processor =
                    MessageExpiryCleanupProcessor::new(_config, _database, _admin_did_hash);
                tokio::select! {
                    result = _processor.start() => {
                        if let Err(e) = result {
                            error!("Message expiry cleanup error: {}", e);
                        }
                    }
                    _ = cleanup_token.cancelled() => {
                        info!("Message expiry cleanup shutting down");
                    }
                }
            });
        }
    }

    // Streaming task: subscribes via the trait, so it runs on any
    // backend. RedisStore bridges Redis pub/sub into a tokio
    // broadcast; Memory and Fjall feed the broadcast directly.
    let (streaming_task, _) = if config.streaming_enabled {
        let _database = store.clone();
        let uuid = config.streaming_uuid.clone();
        let (_task, _handle) = StreamingTask::new(_database, &uuid).await.map_err(|e| {
            error!("Error starting streaming task: {e}");
            e
        })?;
        (Some(_task), Some(_handle))
    } else {
        (None, None)
    };

    let did_resolver = DIDCacheClient::new(config.did_resolver_config.clone())
        .await
        .map_err(|e| {
            error!("Failed to create DID resolver: {e}");
            MediatorError::ConfigError(
                error_codes::CONFIG_ERROR,
                "NA".into(),
                format!("Failed to create DID resolver: {e}"),
            )
        })?;

    #[cfg(feature = "didcomm")]
    let discover_features = Arc::new(DiscoverFeatures {
        protocols: vec![
            "https://didcomm.org/discover-features/2.0".to_string(),
            "https://didcomm.org/routing/2.0".to_string(),
            "https://didcomm.org/trust-ping/2.0".to_string(),
            "https://didcomm.org/out-of-band/2.0".to_string(),
            "https://didcomm.org/messagepickup/3.0".to_string(),
            "https://affinidi.com/atm/1.0/authenticate".to_string(),
            "https://didcomm.org/mediator/1.0/admin-management".to_string(),
            "https://didcomm.org/mediator/1.0/account-management".to_string(),
            "https://didcomm.org/mediator/1.0/acl-management".to_string(),
            "https://didcomm.org/report-problem/2.0".to_string(),
        ],
        ..Default::default()
    });

    let did_rate_limiter = DidRateLimiter::new(
        config.limits.did_rate_limit_per_second,
        config.limits.did_rate_limit_burst,
    );
    if config.limits.did_rate_limit_per_second > 0 {
        info!(
            "Per-DID rate limiting enabled: {} req/s per DID, burst: {}",
            config.limits.did_rate_limit_per_second, config.limits.did_rate_limit_burst,
        );
    }

    let mediator_did = config.mediator_did.clone();
    let admin_did = config.admin_did.clone();
    let api_prefix = config.api_prefix.clone();

    let shared_state = SharedData {
        config: config.clone(),
        service_start_timestamp: chrono::Utc::now(),
        did_resolver,
        database: store,
        streaming_task,
        #[cfg(feature = "didcomm")]
        discover_features,
        active_websocket_count: Arc::new(AtomicUsize::new(0)),
        did_rate_limiter,
        shutdown_token: shutdown_token.clone(),
    };

    let app: Router = application_routes(&api_prefix, &shared_state);

    let rate_limiter = RateLimiterState::new(
        config.limits.rate_limit_per_ip,
        config.limits.rate_limit_burst,
    );
    if config.limits.rate_limit_per_ip > 0 {
        info!(
            "Rate limiting enabled: {} req/s per IP, burst: {}",
            config.limits.rate_limit_per_ip, config.limits.rate_limit_burst,
        );
    }

    let app = Router::new()
        .merge(app)
        .layer(config.security.cors_allow_origin.clone())
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(trace::DefaultMakeSpan::new().level(Level::INFO))
                .on_response(trace::DefaultOnResponse::new().level(Level::INFO)),
        )
        .layer(RequestBodyLimitLayer::new(config.limits.http_size as usize))
        .layer(RateLimitLayer::new(rate_limiter))
        .layer(RequestIdLayer::new())
        .route(
            format!("{}healthchecker", &api_prefix).as_str(),
            get(health_checker_handler).with_state(shared_state.clone()),
        )
        .route(
            format!("{}readyz", &api_prefix).as_str(),
            get(readiness_handler).with_state(shared_state.clone()),
        )
        .route(
            format!("{}admin/status", &api_prefix).as_str(),
            get(admin_status::admin_status_handler).with_state(shared_state),
        );

    let app = if let Some(handle) = metrics_handle {
        app.route(
            format!("{}metrics", &api_prefix).as_str(),
            get(metrics_handler).with_state(handle),
        )
    } else {
        app
    };

    // Bind synchronously with std so we can extract the actual port
    // before async work begins. `from_tcp` then takes the listener as
    // input — this is how the embedded path can hand the bound URL
    // back to the caller while the server runs in a spawned task.
    let configured_addr = config.listen_address.parse::<SocketAddr>().map_err(|e| {
        error!("Invalid listen_address '{}': {e}", config.listen_address);
        MediatorError::ConfigError(
            error_codes::CONFIG_ERROR,
            "NA".into(),
            format!("Invalid listen_address '{}': {e}", config.listen_address),
        )
    })?;
    let std_listener = std::net::TcpListener::bind(configured_addr).map_err(|e| {
        error!("Failed to bind {}: {e}", configured_addr);
        MediatorError::InternalError(
            error_codes::INTERNAL_ERROR,
            "NA".into(),
            format!("Failed to bind {configured_addr}: {e}"),
        )
    })?;
    std_listener.set_nonblocking(true).map_err(|e| {
        MediatorError::InternalError(
            error_codes::INTERNAL_ERROR,
            "NA".into(),
            format!("Failed to set listener nonblocking: {e}"),
        )
    })?;
    let bound_addr = std_listener.local_addr().map_err(|e| {
        MediatorError::InternalError(
            error_codes::INTERNAL_ERROR,
            "NA".into(),
            format!("Failed to read bound listener address: {e}"),
        )
    })?;

    // Graceful shutdown: when the token cancels, signal axum_server to
    // drain. 30s drain matches the previous (TOML-only) behaviour.
    let server_handle = axum_server::Handle::new();
    let drain_handle = server_handle.clone();
    let server_shutdown_token = shutdown_token.clone();
    tokio::spawn(async move {
        server_shutdown_token.cancelled().await;
        info!("Gracefully shutting down HTTP server...");
        drain_handle.graceful_shutdown(Some(Duration::from_secs(30)));
    });

    let app_with_state = app.into_make_service_with_connect_info::<SocketAddr>();

    let (server_task, scheme, ws_scheme) = match opts.tls {
        TlsMode::Plain => {
            // `axum_server::from_tcp` returns `io::Result<Server>` —
            // wrap the std listener now (errors here mean the listener
            // we just bound is somehow unusable, which would be a bug).
            let server = axum_server::from_tcp(std_listener).map_err(|e| {
                error!("Failed to wrap TCP listener: {e}");
                MediatorError::InternalError(
                    error_codes::INTERNAL_ERROR,
                    "NA".into(),
                    format!("Failed to wrap TCP listener: {e}"),
                )
            })?;
            let task: JoinHandle<Result<(), MediatorError>> = tokio::spawn(async move {
                server
                    .handle(server_handle)
                    .serve(app_with_state)
                    .await
                    .map_err(|e| {
                        error!("HTTP server error: {e}");
                        MediatorError::InternalError(
                            error_codes::INTERNAL_ERROR,
                            "NA".into(),
                            format!("HTTP server error: {e}"),
                        )
                    })?;
                info!("Mediator shutdown complete.");
                Ok(())
            });
            (task, "http", "ws")
        }
        TlsMode::Rustls(rustls_config) => {
            let server =
                axum_server::from_tcp_rustls(std_listener, rustls_config).map_err(|e| {
                    error!("Failed to wrap TCP listener with TLS: {e}");
                    MediatorError::InternalError(
                        error_codes::INTERNAL_ERROR,
                        "NA".into(),
                        format!("Failed to wrap TCP listener with TLS: {e}"),
                    )
                })?;
            let task: JoinHandle<Result<(), MediatorError>> = tokio::spawn(async move {
                server
                    .handle(server_handle)
                    .serve(app_with_state)
                    .await
                    .map_err(|e| {
                        error!("HTTPS server error: {e}");
                        MediatorError::InternalError(
                            error_codes::INTERNAL_ERROR,
                            "NA".into(),
                            format!("HTTPS server error: {e}"),
                        )
                    })?;
                info!("Mediator shutdown complete.");
                Ok(())
            });
            (task, "https", "wss")
        }
    };

    let http_endpoint =
        Url::parse(&format!("{scheme}://{bound_addr}{api_prefix}")).map_err(|e| {
            MediatorError::InternalError(
                error_codes::INTERNAL_ERROR,
                "NA".into(),
                format!("Failed to build http endpoint URL: {e}"),
            )
        })?;
    let ws_endpoint =
        Url::parse(&format!("{ws_scheme}://{bound_addr}{api_prefix}ws")).map_err(|e| {
            MediatorError::InternalError(
                error_codes::INTERNAL_ERROR,
                "NA".into(),
                format!("Failed to build ws endpoint URL: {e}"),
            )
        })?;

    Ok(MediatorHandle::__from_internals(
        http_endpoint,
        ws_endpoint,
        bound_addr,
        mediator_did,
        admin_did,
        shutdown_token,
        server_task,
    ))
}

fn install_production_tracing(
    ansi: bool,
    log_json: bool,
    log_level: tracing_subscriber::filter::LevelFilter,
) -> Result<(), MediatorError> {
    let filter = if env::var("RUST_LOG").is_ok() {
        EnvFilter::from_default_env()
    } else {
        EnvFilter::new(log_level.to_string())
    };

    let subscriber = tracing_subscriber::fmt()
        .compact()
        .with_file(false)
        .with_line_number(false)
        .with_thread_ids(false)
        .with_target(true)
        .with_ansi(ansi)
        .with_env_filter(filter);

    if log_json {
        let subscriber = subscriber.json().finish();
        // Errors here mean a subscriber is already installed — that's
        // fine for embedded callers who switched modes mid-process.
        let _ = tracing::subscriber::set_global_default(subscriber);
    } else {
        let subscriber = subscriber.finish();
        let _ = tracing::subscriber::set_global_default(subscriber);
    }
    Ok(())
}

fn print_banner() {
    println!();
    println!(
        r#"        db          ad88     ad88  88               88           88  88     88b           d88                       88  88"#
    );
    println!(
        r#"       d88b        d8"      d8"    ""               ""           88  ""     888b         d888                       88  ""                ,d"#
    );
    println!(
        r#"      d8'`8b       88       88                                   88         88`8b       d8'88                       88                    88"#
    );
    println!(
        r#"     d8'  `8b    MM88MMM  MM88MMM  88  8b,dPPYba,   88   ,adPPYb,88  88     88 `8b     d8' 88   ,adPPYba,   ,adPPYb,88  88  ,adPPYYba,  MM88MMM  ,adPPYba,   8b,dPPYba,"#
    );
    println!(
        r#"    d8YaaaaY8b     88       88     88  88P'   `"8a  88  a8"    `Y88  88     88  `8b   d8'  88  a8P_____88  a8"    `Y88  88  ""     `Y8    88    a8"     "8a  88P'   "Y8"#
    );
    println!(
        r#"   d8""""""""8b    88       88     88  88       88  88  8b       88  88     88   `8b d8'   88  8PP"""""""  8b       88  88  ,adPPPPP88    88    8b       d8  88"#
    );
    println!(
        r#"  d8'        `8b   88       88     88  88       88  88  "8a,   ,d88  88     88    `888'    88  "8b,   ,aa  "8a,   ,d88  88  88,    ,88    88,   "8a,   ,a8"  88"#
    );
    println!(
        r#" d8'          `8b  88       88     88  88       88  88   `"8bbdP"Y8  88     88     `8'     88   `"Ybbd8"'   `"8bbdP"Y8  88  `"8bbdP"Y8    "Y888  `"YbbdP"'   88"#
    );
    println!();
}

/// Wait for a shutdown signal (SIGINT or SIGTERM).
///
/// If a handler fails to install, log it and stay pending on that
/// branch so the other handler can still trigger shutdown. If both
/// fail, the mediator only stops on SIGKILL.
async fn shutdown_signal() {
    let ctrl_c = async {
        match tokio::signal::ctrl_c().await {
            Ok(()) => {}
            Err(err) => {
                error!("Failed to install Ctrl+C handler: {err}");
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(err) => {
                error!("Failed to install SIGTERM handler: {err}");
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
