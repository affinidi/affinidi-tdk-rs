//! End-to-end tests for the live-streaming, forwarding, and ACL
//! surfaces of the mediator.
//!
//! These tests focus on entry points the SDK exercises: the
//! WebSocket upgrade for live delivery, the admin status endpoint
//! for ops visibility, and (when the test runs with forwarding
//! enabled) the routing 2.0 forward path. ACL coverage at this layer
//! is limited to admin-status visibility — full ACL behaviour testing
//! belongs to handler-level integration tests with a controlled
//! sender/receiver.

mod common;

use std::time::Duration;

use affinidi_messaging_test_mediator::{TestEnvironment, TestMediator};
use common::{init_tracing, skip_if_no_redis};
use serde_json::Value as JsonValue;

/// The `/ws` endpoint requires JWT auth — without a Bearer token,
/// the handshake fails before the upgrade. This test verifies the
/// rejection is structured (401, not a connection error / panic / 5xx)
/// — i.e., the route is wired up and the auth middleware is engaged.
/// Authenticated WebSocket round-trips belong in SDK-level tests
/// where the auth flow is exercised properly.
#[tokio::test]
async fn websocket_endpoint_rejects_unauthenticated_handshake() {
    init_tracing();
    if skip_if_no_redis() {
        return;
    }

    let mediator = TestMediator::spawn().await.expect("spawn");
    let ws_url = mediator.ws_endpoint().clone();

    let result = tokio::time::timeout(
        Duration::from_secs(5),
        tokio_tungstenite::connect_async(ws_url.as_str()),
    )
    .await
    .expect("ws handshake within 5s");

    // We expect a 401 rejection from the auth middleware before the
    // WebSocket upgrade completes. tokio-tungstenite surfaces this as
    // `Error::Http(Response { status: 401, ... })`.
    match result {
        Ok((_, response)) => panic!(
            "expected unauthenticated /ws to fail, got status: {}",
            response.status()
        ),
        Err(tokio_tungstenite::tungstenite::Error::Http(resp)) => {
            assert_eq!(
                resp.status().as_u16(),
                401,
                "ws upgrade should be rejected with 401, got: {}",
                resp.status()
            );
        }
        Err(e) => panic!("unexpected ws handshake error: {e:?}"),
    }

    mediator.shutdown();
    let _ = mediator.join().await;
}

/// `/admin/status` returns operational metrics as JSON. We don't
/// assert specific field values — only that the endpoint serves
/// well-formed JSON containing the expected top-level keys.
#[tokio::test]
async fn admin_status_returns_metrics_json() {
    init_tracing();
    if skip_if_no_redis() {
        return;
    }

    let mediator = TestMediator::spawn().await.expect("spawn");
    let url = format!("{}admin/status", mediator.endpoint());

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("client");
    let resp = client.get(&url).send().await.expect("admin status");
    assert!(
        resp.status().is_success(),
        "admin status returned: {}",
        resp.status()
    );

    let body: JsonValue = resp.json().await.expect("json body");
    // The handler builds an `AdminStatus` struct; we just confirm a
    // few load-bearing keys are present rather than mirroring the
    // full schema (which evolves).
    let obj = body.as_object().expect("admin status is a JSON object");
    assert!(
        obj.contains_key("circuit_breaker") || obj.contains_key("queue_length"),
        "admin status missing both circuit_breaker and queue_length: {body}"
    );

    mediator.shutdown();
    let _ = mediator.join().await;
}

/// Authentication challenge endpoint accepts a request payload
/// containing a DID and returns the next-step challenge data.
/// This exercises the auth handler bootstrap path without completing
/// the full challenge-response cycle (which requires DID-based
/// signing of the challenge payload — covered in SDK tests).
#[tokio::test]
async fn authenticate_challenge_endpoint_responds() {
    init_tracing();
    if skip_if_no_redis() {
        return;
    }

    let env = TestEnvironment::spawn().await.expect("env spawn");
    let alice = env.add_user("Alice").await.expect("add Alice");
    let url = format!("{}authenticate/challenge", env.mediator.endpoint());

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("client");
    let resp = client
        .post(&url)
        .json(&serde_json::json!({ "did": alice.did }))
        .send()
        .await
        .expect("challenge request");

    // Either the handler returns a challenge (200) or rejects with a
    // structured problem report. Both indicate the endpoint is wired
    // up correctly. We reject 5xx — those would mean the handler
    // panicked on a valid request shape.
    let status = resp.status().as_u16();
    assert!(
        (200..500).contains(&status),
        "authenticate/challenge returned 5xx: {status}"
    );

    env.shutdown().await.expect("env shutdown");
}

/// `/whoami` is a marker endpoint that 401s when called without auth.
/// Verifying the 401 confirms auth middleware is wired into the
/// router for protected endpoints.
#[tokio::test]
async fn protected_endpoint_rejects_unauthenticated_request() {
    init_tracing();
    if skip_if_no_redis() {
        return;
    }

    let mediator = TestMediator::spawn().await.expect("spawn");
    let url = format!("{}whoami", mediator.endpoint());

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("client");
    let resp = client.get(&url).send().await.expect("whoami request");
    let status = resp.status().as_u16();
    assert!(
        status == 401 || status == 403,
        "/whoami without auth returned: {status} (expected 401/403)"
    );

    mediator.shutdown();
    let _ = mediator.join().await;
}

/// `/healthchecker` is publicly accessible — confirms route exemption
/// from the auth middleware works.
#[tokio::test]
async fn healthchecker_does_not_require_auth() {
    init_tracing();
    if skip_if_no_redis() {
        return;
    }

    let mediator = TestMediator::spawn().await.expect("spawn");
    let url = format!("{}healthchecker", mediator.endpoint());

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("client");
    let resp = client.get(&url).send().await.expect("hc request");
    assert_eq!(resp.status().as_u16(), 200, "healthchecker not 200");

    mediator.shutdown();
    let _ = mediator.join().await;
}

/// Forwarding processor runs only when explicitly enabled. Spawning
/// with forwarding enabled must not panic at startup. (The actual
/// forward-routing flow needs two mediators and a multi-hop message,
/// covered by separate integration tests once the trait refactor
/// lands.)
#[tokio::test]
async fn forwarding_processor_starts_when_enabled() {
    init_tracing();
    if skip_if_no_redis() {
        return;
    }

    let mediator = TestMediator::builder()
        .enable_forwarding(true)
        .spawn()
        .await
        .expect("spawn with forwarding");

    // Brief settle so the spawned processor has a chance to fail-fast
    // if its initial XGROUP CREATE on FORWARD_Q goes wrong.
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Confirm the mediator still serves traffic — i.e. the forwarding
    // task didn't take down the runtime.
    let url = format!("{}healthchecker", mediator.endpoint());
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("client");
    let resp = client.get(&url).send().await.expect("hc after fwd start");
    assert_eq!(resp.status().as_u16(), 200);

    mediator.shutdown();
    let _ = mediator.join().await;
}
