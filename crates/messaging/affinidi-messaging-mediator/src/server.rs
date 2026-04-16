use crate::{
    SharedData,
    common::{
        config::init,
        did_rate_limiter::DidRateLimiter,
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
use affinidi_messaging_mediator_processors::message_expiry_cleanup::processor::MessageExpiryCleanupProcessor;
#[cfg(feature = "didcomm")]
use affinidi_messaging_sdk::protocols::discover_features::DiscoverFeatures;
use axum::{Router, routing::get};
use axum_server::tls_rustls::RustlsConfig;
use std::{env, net::SocketAddr, sync::Arc, sync::atomic::AtomicUsize};
use tokio_util::sync::CancellationToken;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::trace::{self, TraceLayer};
use tracing::{Level, error, info, warn};

pub async fn start() {
    let ansi = env::var("LOCAL").is_ok();

    if ansi {
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

    println!("[Loading Affinidi Secure Messaging Mediator configuration]");

    let config = init("conf/mediator.toml", ansi)
        .await
        .expect("Couldn't initialize mediator!");

    // Start setting up the database durability and handling
    let database = match tokio::time::timeout(
        std::time::Duration::from_secs(30),
        DatabaseHandler::new(&config.database),
    )
    .await
    {
        Ok(Ok(db)) => db,
        Ok(Err(err)) => {
            error!("Error opening database: {}", err);
            error!("Exiting...");
            std::process::exit(1);
        }
        Err(_) => {
            error!("Database connection timed out after 30 seconds");
            error!("Exiting...");
            std::process::exit(1);
        }
    };

    // Convert from the common generic DatabaseHandler to the Mediator specific Database
    let database = Database::new(
        database,
        config.database.circuit_breaker_threshold,
        config.database.circuit_breaker_recovery_secs,
    );

    database
        .initialize(&config)
        .await
        .expect("Error initializing database");

    if let Some(functions_file) = &config.database.functions_file {
        info!(
            "Loading LUA scripts into the database from file: {}",
            functions_file
        );
        if let Err(e) = database.load_scripts(functions_file).await {
            error!("Failed to load LUA scripts: {}", e);
            return;
        }
    } else {
        info!("No LUA scripts file specified in the configuration. Skipping loading LUA scripts.");
        return;
    }

    // Create a cancellation token for coordinated graceful shutdown
    let shutdown_token = CancellationToken::new();

    // Spawn signal handler for graceful shutdown
    let signal_token = shutdown_token.clone();
    tokio::spawn(async move {
        shutdown_signal().await;
        info!("Shutdown signal received, initiating graceful shutdown...");
        signal_token.cancel();
    });

    // Initialize Prometheus metrics recorder
    let metrics_handle = metrics::init_metrics();

    // Start the statistics thread
    let _stats_database = database.clone(); // Clone the database handler for the statistics thread
    let tags = config.tags.clone(); // Clone the tags config for the statistics thread
    let stats_token = shutdown_token.clone();

    tokio::spawn(async move {
        tokio::select! {
            result = statistics(_stats_database, tags) => {
                if let Err(e) = result {
                    error!("Statistics thread error: {}", e);
                }
            }
            _ = stats_token.cancelled() => {
                info!("Statistics thread shutting down");
            }
        }
    });

    // Start the message expiry cleanup thread if required
    if config.processors.message_expiry_cleanup.enabled {
        let _database = database.handler.clone(); // Clone the DatabaseHandler for the message expiry cleanup thread
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

    // Start the forwarding processor if enabled
    if config.processors.forwarding.enabled && config.processors.forwarding.external_forwarding {
        let _database = database.clone();
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

    // Start the streaming thread if enabled
    let (streaming_task, _) = if config.streaming_enabled {
        let _database = database.clone(); // Clone the database handler for the subscriber thread
        let uuid = config.streaming_uuid.clone();
        let (_task, _handle) = StreamingTask::new(_database.clone(), &uuid)
            .await
            .expect("Error starting streaming task");
        (Some(_task), Some(_handle))
    } else {
        (None, None)
    };

    // Create the DID Resolver
    let did_resolver = match DIDCacheClient::new(config.did_resolver_config.clone()).await {
        Ok(r) => r,
        Err(e) => {
            error!("Failed to create DID resolver: {}", e);
            return;
        }
    };

    // Create the Discover Feature Protocol set for the mediator
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

    // Set up per-DID rate limiting for authenticated endpoints
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

    // Create the shared application State
    let shared_state = SharedData {
        config: config.clone(),
        service_start_timestamp: chrono::Utc::now(),
        did_resolver,
        database,
        streaming_task,
        #[cfg(feature = "didcomm")]
        discover_features,
        active_websocket_count: Arc::new(AtomicUsize::new(0)),
        did_rate_limiter,
        shutdown_token: shutdown_token.clone(),
    };

    // build our application routes
    let app: Router = application_routes(&config.api_prefix, &shared_state);

    // Set up per-IP rate limiting
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

    // Add middleware to all routes
    let app = Router::new()
        .merge(app)
        .layer(config.security.cors_allow_origin)
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(trace::DefaultMakeSpan::new().level(Level::INFO))
                .on_response(trace::DefaultOnResponse::new().level(Level::INFO)),
        )
        .layer(RequestBodyLimitLayer::new(config.limits.http_size as usize))
        .layer(RateLimitLayer::new(rate_limiter))
        .layer(RequestIdLayer::new())
        // Add the healthcheck route after the tracing so we don't fill up logs with healthchecks
        .route(
            format!("{}healthchecker", &config.api_prefix).as_str(),
            get(health_checker_handler).with_state(shared_state.clone()),
        )
        // Deep readiness check for load balancers and orchestrators
        .route(
            format!("{}readyz", &config.api_prefix).as_str(),
            get(readiness_handler).with_state(shared_state.clone()),
        )
        // Admin status endpoint for monitoring tools (mediator-monitor TUI, etc.)
        .route(
            format!("{}admin/status", &config.api_prefix).as_str(),
            get(admin_status::admin_status_handler).with_state(shared_state),
        );

    // Add Prometheus metrics endpoint if metrics recorder is available
    let app = if let Some(handle) = metrics_handle {
        app.route(
            format!("{}metrics", &config.api_prefix).as_str(),
            get(metrics_handler).with_state(handle),
        )
    } else {
        app
    };

    let server_shutdown_token = shutdown_token.clone();

    if config.security.use_ssl {
        info!("This mediator is using SSL/TLS for secure communication.");
        // configure certificate and private key used by https
        // TODO: Build a proper TLS Config
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let ssl_config = RustlsConfig::from_pem_file(
            config
                .security
                .ssl_certificate_file
                .expect("SSL Certificate file must be specified in the Config"),
            config
                .security
                .ssl_key_file
                .expect("SSL Certificate key file must be specified in the Config"),
        )
        .await
        .expect("bad certificate/key");

        let handle = axum_server::Handle::new();
        let shutdown_handle = handle.clone();
        tokio::spawn(async move {
            server_shutdown_token.cancelled().await;
            info!("Gracefully shutting down HTTP server...");
            shutdown_handle.graceful_shutdown(Some(std::time::Duration::from_secs(30)));
        });

        let addr = match config.listen_address.parse::<std::net::SocketAddr>() {
            Ok(addr) => addr,
            Err(e) => {
                error!("Invalid listen_address '{}': {}", config.listen_address, e);
                return;
            }
        };

        info!("Mediator listening on {}", config.listen_address);

        axum_server::bind_rustls(addr, ssl_config)
            .handle(handle)
            .serve(app.into_make_service_with_connect_info::<SocketAddr>())
            .await
            .unwrap();
    } else {
        warn!("**** WARNING: Running without SSL/TLS ****");

        let handle = axum_server::Handle::new();
        let shutdown_handle = handle.clone();
        tokio::spawn(async move {
            server_shutdown_token.cancelled().await;
            info!("Gracefully shutting down HTTP server...");
            shutdown_handle.graceful_shutdown(Some(std::time::Duration::from_secs(30)));
        });

        let addr = match config.listen_address.parse::<std::net::SocketAddr>() {
            Ok(addr) => addr,
            Err(e) => {
                error!("Invalid listen_address '{}': {}", config.listen_address, e);
                return;
            }
        };

        info!("Mediator listening on {}", config.listen_address);

        axum_server::bind(addr)
            .handle(handle)
            .serve(app.into_make_service_with_connect_info::<SocketAddr>())
            .await
            .unwrap();
    }

    info!("Mediator shutdown complete.");
}

/// Wait for a shutdown signal (SIGINT or SIGTERM).
async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("Failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
