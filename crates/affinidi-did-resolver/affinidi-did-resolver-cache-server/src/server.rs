use crate::{
    SharedData,
    config::init,
    handlers::{application_routes, health_checker_handler},
    statistics::{Statistics, statistics},
};
use affinidi_did_resolver_cache_sdk::{
    DIDCacheClient, config::DIDCacheConfigBuilder, errors::DIDCacheError,
};
use axum::{Router, routing::get};
use http::Method;
use std::{env, net::SocketAddr, sync::Arc};
use tokio::sync::Mutex;
use tower_http::{
    cors::CorsLayer,
    trace::{self, TraceLayer},
};
use tracing::{Level, event};
use tracing_subscriber::{filter, layer::SubscriberExt, reload, util::SubscriberInitExt};

pub async fn start() -> Result<(), DIDCacheError> {
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

    let config = init(Some(reload_handle)).expect("Couldn't initialize DID Cache!");

    // Use the affinidi-did-resolver-cache-sdk in local mode
    let cache_config = DIDCacheConfigBuilder::default()
        .with_cache_capacity(config.cache_capacity_count)
        .with_cache_ttl(config.cache_expire)
        .build();

    let resolver = DIDCacheClient::new(cache_config).await?;

    // Create the shared application State
    let shared_state = SharedData {
        service_start_timestamp: chrono::Utc::now(),
        stats: Arc::new(Mutex::new(Statistics::default())),
        resolver,
    };

    // Start the statistics thread
    let _stats = shared_state.stats.clone();
    let _cache = shared_state.resolver.get_cache();
    tokio::spawn(async move {
        statistics(config.statistics_interval, &_stats, _cache)
            .await
            .expect("Error starting statistics thread");
    });

    // build our application routes
    let app: Router = application_routes(&shared_state, &config);

    // Add middleware to all routes
    let app = Router::new()
        .merge(app)
        .layer(
            CorsLayer::new()
                .allow_origin(tower_http::cors::Any)
                .allow_headers([http::header::CONTENT_TYPE])
                .allow_methods([
                    Method::GET,
                    Method::POST,
                    Method::PUT,
                    Method::DELETE,
                    Method::PATCH,
                ]),
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
        );

    axum_server::bind(config.listen_address.parse().unwrap())
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        .await
        .unwrap();

    Ok(())
}
