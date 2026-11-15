//! `GET /did/v1/resolve-name/{*name}` — the agent name lookup endpoint.
//!
//! Exercises the router directly rather than binding a port, so these run
//! without the fixed-8080 assumption the main integration test makes.

use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
use affinidi_did_resolver_cache_server::name_lookup::AgentNameLookups;
use affinidi_did_resolver_cache_server::{
    SharedData, config::Config, handlers::application_routes, limits::WsLimits,
    statistics::Statistics,
};
use affinidi_rate_limit::{ClientIpExtractor, RateLimiterState};
use axum::response::IntoResponse;
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
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
        webvh_log_cache: None,
        agent_name_resolver: if enable_agent_names {
            Some(Arc::new(agent_names::HttpRedirectResolver::new()))
        } else {
            None
        },
        agent_name_permits: Arc::new(Semaphore::new(permits)),
        agent_name_lookups: AgentNameLookups::new(1000, Duration::from_secs(60)),
        rate_limiter: RateLimiterState::new(0, 0),
        client_ip_extractor: ClientIpExtractor::direct_peer(),
        ws_limits: Arc::new(WsLimits::from_config(&Config::default())),
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
///
/// The refusal's detail (which address was blocked) is logged under a
/// reference, not returned: echoing it would make the endpoint an oracle for
/// what the server can and cannot reach.
#[tokio::test]
async fn refuses_a_name_resolving_to_a_private_address() {
    let (status, body) = get(app(true).await, "/did/v1/resolve-name/127.0.0.1/@alice").await;
    assert_eq!(
        status,
        StatusCode::BAD_GATEWAY,
        "a private-address name should fail upstream, got body {body}"
    );
    let json: serde_json::Value = serde_json::from_str(&body).expect("a JSON error body");
    assert!(
        json["reference"].is_string(),
        "expected a reference, got {body}"
    );
    assert!(
        !body.contains("non-public") && !body.contains("127.0.0.1"),
        "upstream detail must not reach the client, got {body}"
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
        webvh_log_cache: None,
        agent_name_resolver: Some(Arc::new(agent_names::HttpRedirectResolver::new())),
        agent_name_permits: permits.clone(),
        agent_name_lookups: AgentNameLookups::new(1000, Duration::from_secs(60)),
        rate_limiter: RateLimiterState::new(0, 0),
        client_ip_extractor: ClientIpExtractor::direct_peer(),
        ws_limits: Arc::new(WsLimits::from_config(&Config::default())),
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
    let response = application_routes(&state, &config)
        .oneshot(
            Request::builder()
                .uri("/did/v1/resolve-name/example.com/@bob")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        response
            .headers()
            .get(http::header::RETRY_AFTER)
            .and_then(|v| v.to_str().ok()),
        Some("1"),
        "a shed lookup tells the client when to retry"
    );

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
        // A distinct name each time, so the negative cache does not answer.
        let (status, _) = get(
            app.clone(),
            &format!("/did/v1/resolve-name/127.0.0.1/@alice{i}"),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_GATEWAY,
            "iteration {i} should still reach the resolver, not exhaust permits"
        );
    }
}

// ---------------------------------------------------------------------------
// Negative cache and single-flight, against a local upstream that counts hits.
// ---------------------------------------------------------------------------

/// What the local upstream answers.
#[derive(Clone, Copy)]
enum Upstream {
    /// `404`: a definitive "this name does not redirect".
    NotFound,
    /// `503`: a transient upstream failure.
    Unavailable,
    /// A redirect to a DID.
    Redirect,
}

const ALICE_DID: &str = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";

/// Start an upstream that answers every request with `answer` after `delay`,
/// counting requests. Returns its base URL and the counter.
async fn upstream(answer: Upstream, delay: Duration) -> (String, Arc<AtomicUsize>) {
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = hits.clone();
    let app = axum::Router::new().fallback(move || {
        let counter = counter.clone();
        async move {
            counter.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(delay).await;
            match answer {
                Upstream::NotFound => StatusCode::NOT_FOUND.into_response(),
                Upstream::Unavailable => StatusCode::SERVICE_UNAVAILABLE.into_response(),
                Upstream::Redirect => {
                    (StatusCode::FOUND, [(http::header::LOCATION, ALICE_DID)]).into_response()
                }
            }
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("http://{addr}"), hits)
}

/// A router whose agent name resolver may reach the local upstream (plain HTTP,
/// loopback), with the given fetch ceiling and negative-cache TTL.
async fn local_app(permits: usize, negative_ttl: Duration) -> axum::Router {
    let resolver = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
        .await
        .unwrap();
    let config = Config {
        enable_agent_names: true,
        ..Default::default()
    };
    let state = SharedData {
        service_start_timestamp: chrono::Utc::now(),
        stats: Arc::new(Mutex::new(Statistics::default())),
        resolver,
        resolve_timeout: Duration::from_secs(5),
        max_did_size: 1024,
        webvh_client: reqwest::Client::new(),
        webvh_log_cache: None,
        agent_name_resolver: Some(Arc::new(
            agent_names::HttpRedirectResolver::new()
                .allow_insecure_http(true)
                .allow_private_addresses(true),
        )),
        agent_name_permits: Arc::new(Semaphore::new(permits)),
        agent_name_lookups: AgentNameLookups::new(1000, negative_ttl),
        rate_limiter: RateLimiterState::new(0, 0),
        client_ip_extractor: ClientIpExtractor::direct_peer(),
        ws_limits: Arc::new(WsLimits::from_config(&Config::default())),
    };
    application_routes(&state, &config)
}

/// A name that fails definitively is fetched once; repeats are answered from
/// the negative cache with the same status and reference.
#[tokio::test]
async fn a_repeated_failing_name_is_fetched_once() {
    let (base, hits) = upstream(Upstream::NotFound, Duration::ZERO).await;
    let app = local_app(4, Duration::from_secs(60)).await;
    let uri = format!("/did/v1/resolve-name/{base}/@nobody");

    let (status, first) = get(app.clone(), &uri).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY, "{first}");
    for _ in 0..5 {
        let (status, body) = get(app.clone(), &uri).await;
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert_eq!(body, first, "a cached failure answers as the original did");
    }
    assert_eq!(hits.load(Ordering::SeqCst), 1, "one upstream fetch");

    // A different name is its own lookup.
    let (status, _) = get(app.clone(), &format!("/did/v1/resolve-name/{base}/@other")).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert_eq!(hits.load(Ordering::SeqCst), 2);
}

/// With the negative cache disabled, every failure is fetched again.
#[tokio::test]
async fn a_zero_negative_ttl_caches_nothing() {
    let (base, hits) = upstream(Upstream::NotFound, Duration::ZERO).await;
    let app = local_app(4, Duration::ZERO).await;
    let uri = format!("/did/v1/resolve-name/{base}/@nobody");
    for _ in 0..3 {
        let (status, _) = get(app.clone(), &uri).await;
        assert_eq!(status, StatusCode::BAD_GATEWAY);
    }
    assert_eq!(hits.load(Ordering::SeqCst), 3);
}

/// A transient failure is remembered only briefly (at most 5 seconds, and
/// never longer than the negative TTL), so the name is retried soon after.
#[tokio::test]
async fn a_transient_failure_is_cached_briefly() {
    let (base, hits) = upstream(Upstream::Unavailable, Duration::ZERO).await;
    // A 1s negative TTL caps the transient TTL to 1s too.
    let app = local_app(4, Duration::from_secs(1)).await;
    let uri = format!("/did/v1/resolve-name/{base}/@flaky");
    let (status, _) = get(app.clone(), &uri).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    let (status, _) = get(app.clone(), &uri).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let (status, _) = get(app.clone(), &uri).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert_eq!(hits.load(Ordering::SeqCst), 2, "expired, so fetched again");
}

/// Successes are not cached: the next lookup fetches the redirect again.
#[tokio::test]
async fn a_success_is_not_cached() {
    let (base, hits) = upstream(Upstream::Redirect, Duration::ZERO).await;
    let app = local_app(4, Duration::from_secs(60)).await;
    let uri = format!("/did/v1/resolve-name/{base}/@alice");
    for _ in 0..2 {
        let (status, body) = get(app.clone(), &uri).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(body.contains(ALICE_DID), "{body}");
    }
    assert_eq!(hits.load(Ordering::SeqCst), 2);
}

/// Concurrent lookups of one name share a single fetch (and a single permit:
/// with a ceiling of 1, none of them is shed).
#[tokio::test]
async fn concurrent_identical_lookups_coalesce() {
    let (base, hits) = upstream(Upstream::Redirect, Duration::from_millis(300)).await;
    let app = local_app(1, Duration::from_secs(60)).await;
    let uri = format!("/did/v1/resolve-name/{base}/@alice");

    let mut lookups = tokio::task::JoinSet::new();
    for _ in 0..8 {
        let (app, uri) = (app.clone(), uri.clone());
        lookups.spawn(async move { get(app, &uri).await });
    }
    while let Some(result) = lookups.join_next().await {
        let (status, body) = result.unwrap();
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(body.contains(ALICE_DID), "{body}");
    }
    assert_eq!(hits.load(Ordering::SeqCst), 1, "one upstream fetch for all");
}

/// With the ceiling taken by a slow lookup, a lookup of another name is shed
/// with 503 and `Retry-After` instead of queueing behind it.
#[tokio::test]
async fn a_saturated_ceiling_sheds_other_names() {
    let (base, _hits) = upstream(Upstream::Redirect, Duration::from_millis(800)).await;
    let app = local_app(1, Duration::from_secs(60)).await;

    let slow = {
        let (app, uri) = (app.clone(), format!("/did/v1/resolve-name/{base}/@slow"));
        tokio::spawn(async move { get(app, &uri).await })
    };
    tokio::time::sleep(Duration::from_millis(200)).await;

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/did/v1/resolve-name/{base}/@other"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        response
            .headers()
            .get(http::header::RETRY_AFTER)
            .and_then(|v| v.to_str().ok()),
        Some("1")
    );

    let (status, _) = slow.await.unwrap();
    assert_eq!(status, StatusCode::OK);
    // A shed lookup is not remembered: once the ceiling frees, it goes through.
    let (status, _) = get(app, &format!("/did/v1/resolve-name/{base}/@other")).await;
    assert_eq!(status, StatusCode::OK);
}
