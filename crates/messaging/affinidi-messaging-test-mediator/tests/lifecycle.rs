//! End-to-end lifecycle tests for the test mediator fixture.
//!
//! These tests exercise the externally observable surface of a running
//! mediator: HTTP endpoints reachable, identities issued, multiple
//! instances can coexist, graceful shutdown completes. They are not
//! exhaustive protocol-level tests — those live alongside the routing
//! and authentication code.
//!
//! Each Redis-touching test calls `skip_if_no_redis()` so the suite
//! degrades cleanly on machines without Redis. Once `MemoryStore`
//! lands (commit 11) the gate disappears.

mod common;

use std::time::Duration;

use affinidi_messaging_test_mediator::{TestEnvironment, TestMediator};
use common::{init_tracing, skip_if_no_redis};

/// Smoke test: spawning and shutting down a mediator runs to
/// completion without panics or hangs.
#[tokio::test]
async fn spawn_and_shutdown_round_trip() {
    init_tracing();
    if skip_if_no_redis() {
        return;
    }

    let mediator = TestMediator::spawn().await.expect("test mediator spawn");

    // Sanity-check the handle has the data we expect.
    assert_eq!(mediator.endpoint().scheme(), "http");
    assert!(mediator.did().starts_with("did:peer:2."));
    assert!(!mediator.admin_did().is_empty());
    assert!(mediator.bound_addr().port() > 0);

    mediator.shutdown();
    mediator
        .join()
        .await
        .expect("mediator joins cleanly after shutdown");
}

/// Each `add_user` call mints a fresh `did:peer` distinct from prior
/// users and from the mediator itself. Catches any accidental key
/// reuse in the fixture.
#[tokio::test]
async fn add_user_creates_distinct_dids() {
    init_tracing();
    if skip_if_no_redis() {
        return;
    }

    let env = TestEnvironment::spawn().await.expect("env spawn");

    let alice = env.add_user("Alice").await.expect("add Alice");
    let bob = env.add_user("Bob").await.expect("add Bob");

    assert!(alice.did.starts_with("did:peer:2."));
    assert!(bob.did.starts_with("did:peer:2."));
    assert_ne!(alice.did, bob.did, "Alice and Bob must have distinct DIDs");
    assert_ne!(
        alice.did,
        env.mediator.did(),
        "users and mediator must have distinct DIDs"
    );
    assert_eq!(alice.alias, "Alice");
    assert_eq!(bob.alias, "Bob");
    assert_eq!(alice.secrets.len(), 2, "Ed25519 + X25519 = 2 secrets");
    assert_eq!(bob.secrets.len(), 2);

    env.shutdown().await.expect("env shutdown");
}

/// `/healthchecker` answers without authentication. This is the most
/// minimal "the HTTP server is up" probe.
#[tokio::test]
async fn mediator_serves_healthchecker() {
    init_tracing();
    if skip_if_no_redis() {
        return;
    }

    let mediator = TestMediator::spawn().await.expect("spawn");
    let url = format!("{}healthchecker", mediator.endpoint());

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("reqwest client");

    let resp = client
        .get(&url)
        .send()
        .await
        .expect("healthchecker request");
    assert!(
        resp.status().is_success(),
        "healthchecker status: {}",
        resp.status()
    );

    mediator.shutdown();
    let _ = mediator.join().await;
}

/// `/readyz` returns a structured response covering Redis connectivity,
/// circuit breaker state, queue depth, and load shedding. We don't
/// assert the exact payload — only that the endpoint is reachable and
/// returns either 200 (healthy) or 503 (one of its checks failed).
#[tokio::test]
async fn mediator_serves_readyz() {
    init_tracing();
    if skip_if_no_redis() {
        return;
    }

    let mediator = TestMediator::spawn().await.expect("spawn");
    let url = format!("{}readyz", mediator.endpoint());

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("reqwest client");

    let resp = client.get(&url).send().await.expect("readyz request");
    let status = resp.status().as_u16();
    assert!(
        status == 200 || status == 503,
        "readyz returned unexpected status: {status}"
    );

    mediator.shutdown();
    let _ = mediator.join().await;
}

/// The bound URL on the handle reflects the listener's actual port —
/// not the requested `:0`. Connecting to the URL must succeed.
#[tokio::test]
async fn bound_url_reflects_actual_listener() {
    init_tracing();
    if skip_if_no_redis() {
        return;
    }

    let mediator = TestMediator::spawn().await.expect("spawn");
    let url = mediator.endpoint().clone();
    let bound = mediator.bound_addr();

    assert_ne!(bound.port(), 0, "OS-assigned port must be non-zero");
    assert_eq!(
        url.host_str(),
        Some(&bound.ip().to_string() as &str),
        "endpoint host must match bound listener IP"
    );
    assert_eq!(
        url.port(),
        Some(bound.port()),
        "endpoint port must match bound listener port"
    );

    mediator.shutdown();
    let _ = mediator.join().await;
}

/// Two simultaneously running mediators each get their own ephemeral
/// port. Verifies isolation when a single test process spawns multiple
/// fixtures (parallel test orchestration, multi-mediator scenarios).
#[tokio::test]
async fn parallel_mediators_use_distinct_ports() {
    init_tracing();
    if skip_if_no_redis() {
        return;
    }

    let m1 = TestMediator::spawn().await.expect("spawn first mediator");
    let m2 = TestMediator::spawn().await.expect("spawn second mediator");

    assert_ne!(
        m1.bound_addr().port(),
        m2.bound_addr().port(),
        "two test mediators must bind to different ports"
    );
    assert_ne!(
        m1.did(),
        m2.did(),
        "two test mediators must have distinct DIDs"
    );

    m1.shutdown();
    m2.shutdown();
    let _ = m1.join().await;
    let _ = m2.join().await;
}

/// `TestEnvironment` exposes the mediator handle, TDK state, and SDK
/// client all together. Verify the SDK got configured with the
/// mediator's DID by checking that adding a user resolves the
/// mediator pointer through the SDK's profile registration.
#[tokio::test]
async fn environment_wires_sdk_profile_to_mediator() {
    init_tracing();
    if skip_if_no_redis() {
        return;
    }

    let env = TestEnvironment::spawn().await.expect("env spawn");
    let alice = env.add_user("Alice").await.expect("add Alice");

    // The user's profile should report the mediator's DID via `dids()`.
    let (profile_did, mediator_did) = alice
        .profile
        .dids()
        .expect("profile has mediator configured");
    assert_eq!(profile_did, alice.did);
    assert_eq!(mediator_did, env.mediator.did());

    env.shutdown().await.expect("env shutdown");
}
