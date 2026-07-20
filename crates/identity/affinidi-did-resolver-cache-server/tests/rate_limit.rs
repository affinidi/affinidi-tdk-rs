//! Per-IP rate limiting on the cache server.
//!
//! These drive the layer directly over a trivial inner service rather than
//! standing up the whole server, so they assert the wiring contract — which
//! requests are charged, which are refused, and what a refusal looks like —
//! without a socket.

use affinidi_rate_limit::{RateLimitLayer, RateLimiterState};
use axum::{Router, body::Body, extract::ConnectInfo, routing::get};
use http::{Request, StatusCode, header};
use std::net::SocketAddr;
use tower::ServiceExt;

fn app(per_second: u32, burst: u32) -> Router {
    Router::new()
        .route("/ping", get(|| async { "pong" }))
        .layer(RateLimitLayer::new(RateLimiterState::new(
            per_second, burst,
        )))
}

/// Send a request carrying a client address, as `into_make_service_with_connect_info`
/// does in the real server.
async fn get_from(app: Router, ip: &str) -> StatusCode {
    let mut req = Request::builder().uri("/ping").body(Body::empty()).unwrap();
    let addr: SocketAddr = format!("{ip}:40000").parse().unwrap();
    req.extensions_mut().insert(ConnectInfo(addr));
    app.oneshot(req).await.unwrap().status()
}

#[tokio::test]
async fn normal_traffic_is_served() {
    let app = app(100, 50);
    assert_eq!(get_from(app, "203.0.113.10").await, StatusCode::OK);
}

#[tokio::test]
async fn refuses_once_the_burst_is_spent() {
    let app = app(1, 3);
    for i in 0..3 {
        assert_eq!(
            get_from(app.clone(), "203.0.113.10").await,
            StatusCode::OK,
            "request {i} should be within the burst"
        );
    }
    assert_eq!(
        get_from(app, "203.0.113.10").await,
        StatusCode::TOO_MANY_REQUESTS
    );
}

/// One noisy client must not throttle another.
#[tokio::test]
async fn one_client_cannot_exhaust_anothers_quota() {
    let app = app(1, 2);
    while get_from(app.clone(), "203.0.113.10").await == StatusCode::OK {}
    assert_eq!(
        get_from(app, "198.51.100.20").await,
        StatusCode::OK,
        "a different IP must have its own bucket"
    );
}

#[tokio::test]
async fn a_refusal_carries_retry_after() {
    let app = app(1, 1);
    assert_eq!(get_from(app.clone(), "203.0.113.10").await, StatusCode::OK);

    let mut req = Request::builder().uri("/ping").body(Body::empty()).unwrap();
    let addr: SocketAddr = "203.0.113.10:40000".parse().unwrap();
    req.extensions_mut().insert(ConnectInfo(addr));
    let response = app.oneshot(req).await.unwrap();

    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    let retry: u64 = response
        .headers()
        .get(header::RETRY_AFTER)
        .expect("Retry-After must be set")
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    assert!(retry >= 1, "Retry-After must never be 0, got {retry}");
}

/// A request with no `ConnectInfo` is refused, not waved through. Failing open
/// would make per-IP limiting trivially bypassable.
#[tokio::test]
async fn a_request_without_a_client_ip_is_refused() {
    let app = app(100, 50);
    let req = Request::builder().uri("/ping").body(Body::empty()).unwrap();
    assert_eq!(
        app.oneshot(req).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
}

/// `rate_limit_per_ip = 0` must be a genuine pass-through, not a silent block.
#[tokio::test]
async fn zero_disables_limiting_entirely() {
    let app = app(0, 0);
    for i in 0..200 {
        assert_eq!(
            get_from(app.clone(), "203.0.113.10").await,
            StatusCode::OK,
            "request {i} should pass with limiting disabled"
        );
    }
}

/// With limiting disabled the layer must not require a client IP either.
#[tokio::test]
async fn disabled_limiting_does_not_require_a_client_ip() {
    let app = app(0, 0);
    let req = Request::builder().uri("/ping").body(Body::empty()).unwrap();
    assert_eq!(app.oneshot(req).await.unwrap().status(), StatusCode::OK);
}
