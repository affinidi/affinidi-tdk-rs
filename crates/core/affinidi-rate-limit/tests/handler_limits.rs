//! Limits a service applies from its own handlers, through the public API only.

use std::{net::SocketAddr, time::Duration};

use affinidi_rate_limit::{
    ClientIpExtractor, KeyedRateLimiterState, RateLimitLayer, RateLimiterState, Refusal,
};
use axum::{
    Router,
    body::Body,
    extract::ConnectInfo,
    http::{HeaderMap, Request, StatusCode},
    routing::get,
};
use tower::ServiceExt;

fn extractor() -> ClientIpExtractor {
    ClientIpExtractor::trusted_proxies(vec!["10.0.0.0/8".parse().unwrap()])
        .unwrap()
        .ipv6_prefix(64)
        .unwrap()
}

fn forwarded(client: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert("x-forwarded-for", client.parse().unwrap());
    headers
}

fn request(peer: &str, client: &str) -> Request<Body> {
    let mut request = Request::builder()
        .uri("/")
        .header("x-forwarded-for", client)
        .body(Body::empty())
        .unwrap();
    request
        .extensions_mut()
        .insert(ConnectInfo(peer.parse::<SocketAddr>().unwrap()));
    request
}

/// A handler limit and the layer, given the same extractor, charge a client
/// rotating addresses inside its /64 to one bucket.
#[tokio::test]
async fn handler_and_layer_charge_the_same_client() {
    let in_handler = RateLimiterState::per_window(1, Duration::from_secs(60));
    let proxy = "10.0.0.5".parse().unwrap();
    let first = extractor()
        .client_key(proxy, &forwarded("2001:db8:1:2::1"))
        .unwrap();
    let rotated = extractor()
        .client_key(proxy, &forwarded("2001:db8:1:2::2"))
        .unwrap();
    assert!(in_handler.check(first).is_ok());
    assert!(matches!(
        in_handler.check(rotated),
        Err(Refusal::RateLimited { .. })
    ));

    let app = Router::new().route("/", get(|| async { "ok" })).layer(
        RateLimitLayer::new(RateLimiterState::per_window(1, Duration::from_secs(60)))
            .client_ip_extractor(extractor()),
    );
    let allowed = app
        .clone()
        .oneshot(request("10.0.0.5:4000", "2001:db8:1:2::1"))
        .await
        .unwrap();
    assert_eq!(allowed.status(), StatusCode::OK);
    let refused = app
        .oneshot(request("10.0.0.5:4000", "2001:db8:1:2::2"))
        .await
        .unwrap();
    assert_eq!(refused.status(), StatusCode::TOO_MANY_REQUESTS);
}

/// A per-source limit keyed by what the transport vouches for, with its name
/// available as a `&'static str` for the service's own refusal.
#[test]
fn a_per_source_limit_names_itself_and_reports_once() {
    let per_source = KeyedRateLimiterState::<String>::per_window(1, Duration::from_secs(60))
        .with_limiter_name("passkey-redeem-per-source");
    let source = "vid:did:example:alice".to_owned();

    assert!(per_source.check(source.clone()).is_ok());
    let refusal = per_source.check(source.clone()).unwrap_err();
    assert!(matches!(
        refusal,
        Refusal::RateLimited {
            retry_after_secs: 60
        }
    ));
    let name: Option<&'static str> = per_source.limiter_name();
    assert_eq!(name, Some("passkey-redeem-per-source"));
    assert!(per_source.first_refusal_in_window(&source));
    assert!(!per_source.first_refusal_in_window(&source));
}

/// One budget shared by every caller.
#[test]
fn a_global_limit_is_one_budget() {
    let global = KeyedRateLimiterState::<()>::per_window(2, Duration::from_secs(60));
    assert!(global.check(()).is_ok());
    assert!(global.check(()).is_ok());
    assert!(global.check(()).is_err());
}
