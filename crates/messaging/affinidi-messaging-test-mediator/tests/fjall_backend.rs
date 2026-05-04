//! End-to-end smoke tests against the Fjall on-disk backend.
//!
//! The default e2e suite (`lifecycle.rs`, `streaming_forwarding_acl.rs`)
//! runs against `MemoryStore`. This file repeats a representative
//! subset against `FjallStore` so regressions in the disk-backed code
//! path show up in the same `cargo test` invocation, without forcing
//! every existing test to spin up a temp directory.
//!
//! The fixture wraps each `FjallStore` in a `tempfile::TempDir` whose
//! lifetime is tied to the handle, so partition files don't leak.
//!
//! Compiled only when the `fjall-backend` feature is enabled — keeps
//! the default test build cheap and avoids pulling in the LSM
//! dependencies for callers that don't need them.

#![cfg(feature = "fjall-backend")]

mod common;

use std::time::Duration;

use affinidi_messaging_test_mediator::TestMediator;
use common::init_tracing;

/// Spawning + shutting down the Fjall-backed fixture runs cleanly:
/// the temp directory opens, partitions initialise, the listener
/// binds, and graceful shutdown completes.
#[tokio::test]
async fn fjall_spawn_and_shutdown_round_trip() {
    init_tracing();

    let mediator = TestMediator::builder()
        .fjall_backend()
        .expect("open fjall temp store")
        .spawn()
        .await
        .expect("spawn fjall-backed test mediator");

    assert_eq!(mediator.endpoint().scheme(), "http");
    assert!(mediator.did().starts_with("did:peer:2."));
    assert!(!mediator.admin_did().is_empty());
    assert!(mediator.bound_addr().port() > 0);

    mediator.shutdown();
    mediator
        .join()
        .await
        .expect("fjall-backed mediator joins cleanly");
}

/// `/healthchecker` returns 200 against the Fjall backend just like
/// it does against Memory. Confirms the backend's `health()` impl
/// doesn't trip up the readiness path.
#[tokio::test]
async fn fjall_serves_healthchecker() {
    init_tracing();

    let mediator = TestMediator::builder()
        .fjall_backend()
        .expect("open fjall temp store")
        .spawn()
        .await
        .expect("spawn fjall-backed test mediator");

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
        "fjall healthchecker status: {}",
        resp.status()
    );

    mediator.shutdown();
    let _ = mediator.join().await;
}

/// `/readyz` checks the storage backend's health, so it's the most
/// direct regression signal for the Fjall path. Verifies the trait's
/// `health()` returns `Healthy` against a freshly-initialised store.
#[tokio::test]
async fn fjall_serves_readyz() {
    init_tracing();

    let mediator = TestMediator::builder()
        .fjall_backend()
        .expect("open fjall temp store")
        .spawn()
        .await
        .expect("spawn fjall-backed test mediator");

    let url = format!("{}readyz", mediator.endpoint());
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("reqwest client");
    let resp = client.get(&url).send().await.expect("readyz request");
    assert!(
        resp.status().is_success(),
        "fjall readyz status: {}",
        resp.status()
    );

    mediator.shutdown();
    let _ = mediator.join().await;
}

/// Two Fjall-backed mediators bind to distinct ephemeral ports and
/// generate distinct DIDs — same parallel-instance guarantee as the
/// Memory backend.
#[tokio::test]
async fn fjall_parallel_mediators_use_distinct_ports() {
    init_tracing();

    let m1 = TestMediator::builder()
        .fjall_backend()
        .expect("open fjall #1")
        .spawn()
        .await
        .expect("spawn fjall #1");
    let m2 = TestMediator::builder()
        .fjall_backend()
        .expect("open fjall #2")
        .spawn()
        .await
        .expect("spawn fjall #2");

    assert_ne!(
        m1.bound_addr().port(),
        m2.bound_addr().port(),
        "two fjall-backed mediators must bind to different ports"
    );
    assert_ne!(
        m1.did(),
        m2.did(),
        "two fjall-backed mediators must have distinct DIDs"
    );

    m1.shutdown();
    m2.shutdown();
    let _ = m1.join().await;
    let _ = m2.join().await;
}
