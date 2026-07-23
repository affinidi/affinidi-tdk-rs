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
use tokio::sync::Semaphore;
use tower::ServiceExt;

/// A router with agent name resolution either on or off.
async fn app(enable_agent_names: bool) -> axum::Router {
    app_with_permits(enable_agent_names, 16).await
}

/// A router with an explicit outbound-fetch ceiling.
async fn app_with_permits(enable_agent_names: bool, permits: usize) -> axum::Router {
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
        agent_name_permits: Arc::new(Semaphore::new(permits)),
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
    // Reaches the route (contains '/@'), but the community name takes no path.
    let (status, body) = get(app(true).await, "/did/v1/resolve-name/example.com/@/path").await;
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

/// With every outbound-fetch permit already taken, a lookup must be **shed**
/// rather than queued. Queueing would turn the fetch ceiling into an unbounded
/// backlog, which is precisely what the ceiling exists to prevent.
#[tokio::test]
async fn sheds_lookups_once_the_fetch_ceiling_is_reached() {
    let permits = Arc::new(Semaphore::new(1));
    let held = permits.clone().acquire_owned().await.unwrap();

    let resolver = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
        .await
        .unwrap();
    let state = SharedData {
        service_start_timestamp: chrono::Utc::now(),
        stats: Arc::new(Mutex::new(Statistics::default())),
        resolver,
        resolve_timeout: Duration::from_secs(5),
        max_did_size: 1024,
        webvh_client: reqwest::Client::new(),
        agent_name_resolver: Some(Arc::new(agent_names::HttpRedirectResolver::new())),
        agent_name_permits: permits.clone(),
    };
    let config = Config {
        enable_agent_names: true,
        ..Default::default()
    };

    let (status, body) = get(
        application_routes(&state, &config),
        "/did/v1/resolve-name/example.com/@alice",
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "body: {body}");
    assert!(body.contains("retry shortly"), "got {body}");

    // Releasing the permit lets lookups through again — the ceiling must not
    // latch. This one fails upstream (no such host), which is fine: anything
    // other than 503 proves the permit was reacquired.
    drop(held);
    let (status, _) = get(
        application_routes(&state, &config),
        "/did/v1/resolve-name/127.0.0.1/@alice",
    )
    .await;
    assert_ne!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "the ceiling should not latch after a permit is released"
    );
}

/// A permit must be returned when a lookup fails, not leaked. A ceiling that
/// drains on the error path would wedge the endpoint permanently.
#[tokio::test]
async fn a_failed_lookup_returns_its_permit() {
    let app = app_with_permits(true, 1).await;
    // Blocked-address failures, repeated well past the ceiling of 1.
    for i in 0..5 {
        let (status, _) = get(app.clone(), "/did/v1/resolve-name/127.0.0.1/@alice").await;
        assert_eq!(
            status,
            StatusCode::BAD_GATEWAY,
            "iteration {i} should still reach the resolver, not exhaust permits"
        );
    }
}
