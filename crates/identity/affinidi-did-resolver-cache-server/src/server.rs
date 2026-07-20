use crate::{
    SharedData,
    config::init,
    handlers::{application_routes, health_checker_handler},
    statistics::{Statistics, statistics},
};
use affinidi_did_resolver_cache_sdk::{
    DIDCacheClient, config::DIDCacheConfigBuilder, errors::DIDCacheError,
};
use affinidi_rate_limit::{RateLimitLayer, RateLimiterState};
use affinidi_task_utils::TaskSupervisor;
use axum::{Router, routing::get};
use http::Method;
use std::{env, net::SocketAddr, sync::Arc, time::Duration};
use tokio::sync::{Mutex, Semaphore};
use tokio_util::sync::CancellationToken;
use tower_http::{
    cors::CorsLayer,
    trace::{self, TraceLayer},
};
use tracing::{Level, event};
use tracing_subscriber::{filter, layer::SubscriberExt, reload, util::SubscriberInitExt};

/// Start the cache-server using the default config path
/// (`conf/cache-conf.toml`, relative to the working directory).
pub async fn start() -> Result<(), DIDCacheError> {
    start_with_config(crate::config::DEFAULT_CONFIG_PATH).await
}

/// Start the cache-server with an explicit config path.
///
/// Useful when the binary is installed in one location but its config lives
/// elsewhere (passed via the `-c/--config` CLI flag in `main`).
pub async fn start_with_config(config_path: &str) -> Result<(), DIDCacheError> {
    // setup logging/tracing framework
    let filter = filter::LevelFilter::INFO; // This can be changed in the config file!
    let (filter, reload_handle) = reload::Layer::new(filter);
    let ansi = env::var("LOCAL").is_ok();
    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer().with_ansi(ansi))
        .init();

    if ansi {
        event!(Level::INFO, "");
        event!(
            Level::INFO,
            r#"         db    888888888888  888b      88        88888888ba,    88  88888888ba,            ,ad8888ba,                           88                       "#
        );
        event!(
            Level::INFO,
            r#"        d88b        88       8888b     88        88      `"8b   88  88      `"8b          d8"'    `"8b                          88                       "#
        );
        event!(
            Level::INFO,
            r#"       d8'`8b       88       88 `8b    88        88        `8b  88  88        `8b        d8'                                    88                       "#
        );
        event!(
            Level::INFO,
            r#"      d8'  `8b      88       88  `8b   88        88         88  88  88         88        88             ,adPPYYba,   ,adPPYba,  88,dPPYba,    ,adPPYba,  "#
        );
        event!(
            Level::INFO,
            r#"     d8YaaaaY8b     88       88   `8b  88        88         88  88  88         88        88             ""     `Y8  a8"     ""  88P'    "8a  a8P_____88  "#
        );
        event!(
            Level::INFO,
            r#"    d8""""""""8b    88       88    `8b 88        88         8P  88  88         8P        Y8,            ,adPPPPP88  8b          88       88  8PP"""""""  "#
        );
        event!(
            Level::INFO,
            r#"   d8'        `8b   88       88     `8888        88      .a8P   88  88      .a8P          Y8a.    .a8P  88,    ,88  "8a,   ,aa  88       88  "8b,   ,aa  "#
        );
        event!(
            Level::INFO,
            r#"  d8'          `8b  88       88      `888        88888888Y"'    88  88888888Y"'            `"Y8888Y"'   `"8bbdP"Y8   `"Ybbd8"'  88       88   `"Ybbd8"'  "#
        );
        event!(Level::INFO, "");
    }

    event!(Level::INFO, "[Loading Affinidi DID Cache configuration]");

    let config = init(config_path, Some(reload_handle))
        .map_err(|e| DIDCacheError::ConfigError(format!("Couldn't initialize DID Cache: {e}")))?;

    // Use the affinidi-did-resolver-cache-sdk in local mode
    let cache_config = DIDCacheConfigBuilder::default()
        .with_cache_capacity(config.cache_capacity_count)
        .with_cache_ttl(config.cache_expire)
        .build();

    let resolver = DIDCacheClient::new(cache_config).await?;

    // One shared HTTP client for did:webvh log fetches, built once so
    // connections are pooled (was previously rebuilt per request). Refuses
    // redirects to avoid SSRF pivots, matching the previous per-call config.
    let webvh_client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| {
            DIDCacheError::ConfigError(format!("Failed to build WebVH HTTP client: {e}"))
        })?;

    // Agent name resolution is off unless explicitly enabled: it makes this
    // server issue HTTP requests to caller-supplied hosts. The resolver keeps
    // its default hardening (HTTPS only, non-public addresses refused on every
    // redirect hop).
    let agent_name_resolver = if config.enable_agent_names {
        Some(Arc::new(agent_names::HttpRedirectResolver::new()))
    } else {
        None
    };

    // Create the shared application State
    let shared_state = SharedData {
        service_start_timestamp: chrono::Utc::now(),
        stats: Arc::new(Mutex::new(Statistics::default())),
        resolver,
        resolve_timeout: config.resolve_timeout,
        max_did_size: config.max_did_size,
        webvh_client,
        agent_name_resolver,
        agent_name_permits: Arc::new(Semaphore::new(config.agent_name_concurrency)),
    };

    // Supervise the statistics task through the shared TaskSupervisor: a
    // panic or error restarts it with capped exponential backoff and is
    // logged with its restart history, and its lifecycle is tracked in the
    // supervisor's health registry. It is non-load-bearing — a wedged stats
    // loop must never take the resolver down. The supervisor owns
    // cancellation, so it aborts the task when `shutdown` fires.
    let shutdown = CancellationToken::new();
    {
        let stats = shared_state.stats.clone();
        let cache = shared_state.resolver.get_cache();
        let interval = config.statistics_interval;
        let stats_shutdown = shutdown.clone();
        TaskSupervisor::new(shutdown.clone()).spawn("statistics", false, move || {
            // Re-clone per (re)start so each attempt gets fresh handles.
            let stats = stats.clone();
            let cache = cache.clone();
            let stats_shutdown = stats_shutdown.clone();
            async move { statistics(interval, &stats, cache, stats_shutdown).await }
        });
    }

    // build our application routes
    // Per-IP rate limiting. `ConnectInfo` is attached below via
    // `into_make_service_with_connect_info`, which the layer requires: a
    // request it cannot attribute to an IP is refused rather than exempted.
    let rate_limiter = RateLimiterState::new(config.rate_limit_per_ip, config.rate_limit_burst);
    rate_limiter.spawn_gc(shutdown.clone());
    if rate_limiter.is_enabled() {
        event!(
            Level::INFO,
            "Rate limiting enabled: {} req/s per IP, burst {}",
            config.rate_limit_per_ip,
            config.rate_limit_burst
        );
    } else {
        event!(
            Level::WARN,
            "Rate limiting is DISABLED (rate_limit_per_ip = 0)"
        );
    }

    let app: Router = application_routes(&shared_state, &config);

    // Add middleware to all routes
    let app = Router::new()
        .merge(app)
        .layer(
            // DID documents are public, so any origin is fine, but the server
            // only exposes GET endpoints — don't advertise write methods.
            CorsLayer::new()
                .allow_origin(tower_http::cors::Any)
                .allow_headers([http::header::CONTENT_TYPE])
                .allow_methods([Method::GET]),
        )
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(trace::DefaultMakeSpan::new().level(Level::INFO))
                .on_response(trace::DefaultOnResponse::new().level(Level::INFO)),
        )
        // Add the healthcheck route after the tracing so we don't fill up logs with healthchecks
        .route(
            "/did/healthchecker",
            get(health_checker_handler).with_state(shared_state),
        )
        // Outermost: rate limiting runs before routing, so a throttled client
        // costs nothing beyond the token-bucket check. Placed after the
        // healthcheck route in builder order, which means it wraps that too —
        // deliberate, since an unlimited healthcheck is itself a cheap way to
        // hold a connection open.
        .layer(RateLimitLayer::new(rate_limiter));

    let listen_address = config
        .listen_address
        .parse::<std::net::SocketAddr>()
        .map_err(|e| {
            DIDCacheError::ConfigError(format!(
                "Invalid listen_address ({}): {e}",
                config.listen_address
            ))
        })?;

    // On Ctrl-C, cancel background tasks and let in-flight requests drain.
    let server_handle = axum_server::Handle::new();
    {
        let server_handle = server_handle.clone();
        let shutdown = shutdown.clone();
        tokio::spawn(async move {
            match tokio::signal::ctrl_c().await {
                Ok(()) => event!(
                    Level::INFO,
                    "Shutdown signal received; draining connections"
                ),
                Err(e) => {
                    event!(Level::ERROR, "Failed to listen for shutdown signal: {e}");
                    return;
                }
            }
            shutdown.cancel();
            server_handle.graceful_shutdown(Some(Duration::from_secs(10)));
        });
    }

    axum_server::bind(listen_address)
        .handle(server_handle)
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        .await
        .map_err(|e| DIDCacheError::TransportError(format!("server error: {e}")))?;

    // Server has stopped — cancel the supervised statistics task. The
    // supervisor aborts it and marks it Stopped; any panic or error during
    // its life was already logged and restarted by the supervisor.
    shutdown.cancel();

    Ok(())
}
