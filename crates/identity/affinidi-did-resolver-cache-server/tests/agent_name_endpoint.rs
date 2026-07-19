//! `GET /did/v1/resolve-name/{*name}` — the agent name lookup endpoint.
//!
//! Exercises the router directly rather than binding a port, so these run
//! without the fixed-8080 assumption the main integration test makes.

use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
use affinidi_did_resolver_cache_server::{
    SharedData, config::Config, handlers::application_routes, statistics::Statistics,
};
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use std::{sync::Arc, time::Duration};
use tokio::sync::Mutex;
use tower::ServiceExt;

/// A router with agent name resolution either on or off.
async fn app(enable_agent_names: bool) -> axum::Router {
    let resolver = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
        .await
        .unwrap();

    let config = Config {
        enable_agent_names,
        ..Default::default()
    };

    let state = SharedData {
        service_start_timestamp: chrono::Utc::now(),
        stats: Arc::new(Mutex::new(Statistics::default())),
        resolver,
        resolve_timeout: Duration::from_secs(5),
        max_did_size: 1024,
        webvh_client: reqwest::Client::new(),
        agent_name_resolver: if enable_agent_names {
            Some(Arc::new(agent_names::HttpRedirectResolver::new()))
        } else {
            None
        },
    };

    application_routes(&state, &config)
}

async fn get(app: axum::Router, uri: &str) -> (StatusCode, String) {
    let response = app
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, String::from_utf8_lossy(&bytes).to_string())
}

/// The endpoint must not exist unless explicitly switched on — it makes the
/// server fetch caller-supplied URLs.
#[tokio::test]
async fn route_is_absent_when_disabled() {
    let (status, _) = get(app(false).await, "/did/v1/resolve-name/example.com/@alice").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn route_exists_when_enabled() {
    let (status, _) = get(app(true).await, "/did/v1/resolve-name/example.com/@alice").await;
    assert_ne!(
        status,
        StatusCode::NOT_FOUND,
        "route should be registered when enabled"
    );
}

#[tokio::test]
async fn rejects_a_malformed_agent_name() {
    // Reaches the route (contains '/@') but has an empty local name.
    let (status, body) = get(app(true).await, "/did/v1/resolve-name/example.com/@").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body.contains("error"), "got {body}");
}

#[tokio::test]
async fn rejects_a_name_without_the_marker() {
    let (status, body) = get(app(true).await, "/did/v1/resolve-name/example.com/alice").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body.contains("error"), "got {body}");
}

/// A name pointing at a loopback address must be refused rather than fetched —
/// this is the SSRF guard, exercised through the real endpoint.
#[tokio::test]
async fn refuses_a_name_resolving_to_a_private_address() {
    let (status, body) = get(app(true).await, "/did/v1/resolve-name/127.0.0.1/@alice").await;
    assert_eq!(
        status,
        StatusCode::BAD_GATEWAY,
        "a private-address name should fail upstream, got body {body}"
    );
    assert!(
        body.contains("non-public") || body.contains("127.0.0.1"),
        "expected a blocked-address error, got {body}"
    );
}

#[tokio::test]
async fn path_qualified_names_reach_the_handler() {
    let (status, _) = get(
        app(true).await,
        "/did/v1/resolve-name/127.0.0.1/@alice/h2hsummit",
    )
    .await;
    // Blocked upstream rather than 404, proving the wildcard captured all the
    // segments instead of failing to match the route.
    assert_eq!(status, StatusCode::BAD_GATEWAY);
}

/// The DID endpoint must be unaffected by the new route.
#[tokio::test]
async fn did_resolution_still_works() {
    let (status, body) = get(
        app(true).await,
        "/did/v1/resolve/did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("did:key:"), "got {body}");
}
