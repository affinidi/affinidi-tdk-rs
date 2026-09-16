//! Per-DID rate limiting (`limits.did_rate_limit_per_second` /
//! `did_rate_limit_burst`).
//!
//! The limit is charged once per authenticated HTTP request, after the token has
//! been validated, and a refusal is a `429` carrying the mediator's rate-limit
//! attribution contract. These tests pin, against a running mediator:
//!
//! - a DID over its quota is refused on the authenticated routes — `/whoami`,
//!   `/inbound` and the `/ws` upgrade — with the contract;
//! - a second DID has its own bucket;
//! - `0` (the default) refuses nothing;
//! - the admin DID is exempt;
//! - anonymous inter-mediator relay traffic, which carries no DID, is never
//!   charged, so one peer's forwards cannot throttle routing.
//!
//! Frames on an established WebSocket are not metered; that gap is documented
//! in the mediator's CHANGELOG and `conf/mediator.toml`.

mod common;

use std::time::Duration;

use affinidi_messaging_sdk::errors::HttpStatusError;
use affinidi_messaging_test_mediator::{TestEnvironment, TestMediator, TestUser, acl};
use common::init_tracing;
use tokio_tungstenite::{
    connect_async,
    tungstenite::{self, ClientRequestBuilder, http::Uri},
};

/// Burst used by the limited mediators. Sustained rate is 1/s, so a tight loop
/// of local requests exhausts the burst long before a token is replenished.
const BURST: u32 = 3;

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("reqwest client")
}

async fn access_token(env: &TestEnvironment, did: &str) -> String {
    env.tdk
        .authentication()
        .authenticate(did.to_string(), env.mediator.did().to_string(), 3, None)
        .await
        .expect("authenticate")
        .access_token
}

async fn whoami(env: &TestEnvironment, token: &str) -> reqwest::Response {
    client()
        .get(format!("{}whoami", env.mediator.endpoint()))
        .bearer_auth(token)
        .send()
        .await
        .expect("whoami request")
}

/// Assert `response` is a per-DID refusal carrying the attribution contract,
/// and that the SDK reads it as the mediator's.
async fn assert_per_did_429(response: reqwest::Response) {
    assert_eq!(response.status().as_u16(), 429);
    let header = |name: &str| {
        response
            .headers()
            .get(name)
            .map(|v| v.to_str().unwrap().to_owned())
    };
    let source = header("x-rate-limit-source");
    let retry_after = header("retry-after");
    assert_eq!(source.as_deref(), Some("mediator"));
    let body = response.text().await.expect("body");
    let json: serde_json::Value = serde_json::from_str(&body).expect("JSON body");
    assert_eq!(json["error"], "rate_limited");
    assert_eq!(json["limiter"], "mediator");
    assert_eq!(json["scope"], "did");
    let retry_after_secs: u64 = retry_after
        .as_deref()
        .expect("Retry-After")
        .parse()
        .unwrap();
    assert!(retry_after_secs >= 1);
    assert_eq!(json["retryAfterSecs"], retry_after_secs);

    let parsed =
        HttpStatusError::from_parts("test", 429, source.as_deref(), retry_after.as_deref(), body);
    assert!(parsed.is_rate_limited());
    assert_eq!(parsed.rate_limit_source.as_deref(), Some("mediator"));
}

/// Call `/whoami` until refused. Returns how many calls succeeded first and the
/// refusal, or panics if no refusal came within a generous bound.
async fn exhaust(env: &TestEnvironment, token: &str) -> (u32, reqwest::Response) {
    for allowed in 0..(BURST * 5) {
        let response = whoami(env, token).await;
        match response.status().as_u16() {
            200 => continue,
            429 => return (allowed, response),
            other => panic!("unexpected status {other} from /whoami"),
        }
    }
    panic!("no 429 after {} requests", BURST * 5);
}

async fn limited_env() -> (TestEnvironment, TestUser, TestUser) {
    let mediator = TestMediator::builder()
        .did_rate_limit(1, BURST)
        .spawn()
        .await
        .expect("spawn mediator");
    let env = TestEnvironment::new(mediator).await.expect("environment");
    let alice = env.add_user("Alice").await.expect("alice");
    let bob = env.add_user("Bob").await.expect("bob");
    (env, alice, bob)
}

#[tokio::test]
async fn a_did_over_its_quota_is_refused_with_the_contract() {
    init_tracing();
    let (env, alice, _bob) = limited_env().await;
    let token = access_token(&env, &alice.did).await;

    let (allowed, refused) = exhaust(&env, &token).await;
    assert!(
        allowed >= BURST,
        "the burst ({BURST}) must be honoured before refusing, got {allowed}"
    );
    assert_per_did_429(refused).await;

    // `/inbound` (DIDComm and TSP ingress) is refused the same way, before the
    // body is looked at.
    let inbound = client()
        .post(format!("{}inbound", env.mediator.endpoint()))
        .bearer_auth(&token)
        .body("{}")
        .send()
        .await
        .expect("inbound request");
    assert_per_did_429(inbound).await;

    // So is the WebSocket upgrade.
    let uri: Uri = env.mediator.ws_endpoint().as_str().parse().unwrap();
    let request = ClientRequestBuilder::new(uri)
        .with_sub_protocol("affinidi.test")
        .with_sub_protocol(format!("bearer.{token}"));
    match connect_async(request).await {
        Err(tungstenite::Error::Http(response)) => {
            assert_eq!(response.status().as_u16(), 429);
            assert_eq!(response.headers()["x-rate-limit-source"], "mediator");
        }
        Err(other) => panic!("expected an HTTP 429 on the upgrade, got {other:?}"),
        Ok(_) => panic!("the upgrade must be refused once the DID is over quota"),
    }

    env.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn independent_dids_do_not_share_a_bucket() {
    init_tracing();
    let (env, alice, bob) = limited_env().await;
    let alice_token = access_token(&env, &alice.did).await;
    let bob_token = access_token(&env, &bob.did).await;

    let (_, refused) = exhaust(&env, &alice_token).await;
    assert_eq!(refused.status().as_u16(), 429);

    assert_eq!(
        whoami(&env, &bob_token).await.status().as_u16(),
        200,
        "Bob must not pay for Alice's traffic"
    );

    env.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn zero_disables_the_limit() {
    init_tracing();
    let mediator = TestMediator::builder()
        .did_rate_limit(0, 1)
        .spawn()
        .await
        .expect("spawn mediator");
    let env = TestEnvironment::new(mediator).await.expect("environment");
    let alice = env.add_user("Alice").await.expect("alice");
    let token = access_token(&env, &alice.did).await;

    for i in 0..20 {
        assert_eq!(
            whoami(&env, &token).await.status().as_u16(),
            200,
            "request {i} refused with the per-DID limit disabled"
        );
    }

    env.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn the_admin_did_is_exempt() {
    init_tracing();
    let admin = TestMediator::random_admin_identity().expect("admin identity");
    let mediator = TestMediator::builder()
        .did_rate_limit(1, 1)
        .admin_identity(admin.clone())
        .spawn()
        .await
        .expect("spawn mediator");
    let env = TestEnvironment::new(mediator).await.expect("environment");
    let admin_user = env.add_admin(admin).await.expect("admin");
    let token = access_token(&env, &admin_user.did).await;

    for i in 0..10 {
        assert_eq!(
            whoami(&env, &token).await.status().as_u16(),
            200,
            "admin request {i} was throttled"
        );
    }

    env.shutdown().await.expect("shutdown");
}

/// An inter-mediator hop is posted anonymously. It has no DID to charge, and
/// must not be charged to a shared bucket either: that would let one peer's
/// forwards throttle every other peer's.
#[tokio::test]
async fn anonymous_relay_traffic_is_not_charged() {
    init_tracing();
    let mediator = TestMediator::builder()
        .did_rate_limit(1, 1)
        .enable_forwarding(true)
        .enable_external_forwarding(true)
        .global_acl_default(acl::allow_all())
        .enable_inter_mediator_relay(true)
        .spawn()
        .await
        .expect("spawn relay mediator");
    let env = TestEnvironment::new(mediator).await.expect("environment");

    for i in 0..10 {
        let response = client()
            .post(format!("{}inbound", env.mediator.endpoint()))
            .body("{}")
            .send()
            .await
            .expect("anonymous inbound");
        assert_ne!(
            response.status().as_u16(),
            429,
            "anonymous relay request {i} was rate limited"
        );
    }

    env.shutdown().await.expect("shutdown");
}
