//! TI1 — multi-mediator [`TestTopology`] fixture.
//!
//! These are the first consumers of the topology fixture and the home for the
//! pending #385/#388 relay e2e: a two-hop forward over the memory backend, and
//! a rewrap-mode relay that must preserve the inner (recipient-addressed)
//! envelope end to end. Both run as plain `#[tokio::test]` with no Redis and no
//! external network — every identity is `did:peer`, so the only real socket
//! traffic is the loopback `/inbound` hop between the two mediators.
//!
//! The single-mediator builder knobs (explicit trusted-peer allowlists, a
//! non-relay posture) are exercised in `cross_mediator_forwarding.rs`; this file
//! covers the fixture itself.

mod common;

use std::time::Duration;

use affinidi_messaging_test_mediator::TestTopology;
use common::init_tracing;

/// Alice on mediator 0 sends to Bob on mediator 1; the message must arrive
/// having traversed both mediators, with no Redis. This is the routing-2.0
/// double forward wrapped behind `TestTopology::forward`.
#[tokio::test]
async fn two_hop_forward_delivers_over_memory_backend() {
    init_tracing();

    let topology = TestTopology::builder()
        .mediators(2)
        .spawn()
        .await
        .expect("spawn 2-mediator topology");

    assert_eq!(topology.len(), 2);
    assert_ne!(
        topology.mediator_did(0).unwrap(),
        topology.mediator_did(1).unwrap(),
        "the two mediators must have distinct DIDs for a real cross-mediator hop"
    );

    let alice = topology
        .add_user(0, "Alice")
        .await
        .expect("add Alice on node 0");
    let bob = topology
        .add_user(1, "Bob")
        .await
        .expect("add Bob on node 1");

    let text = "Hello Bob — routed across two mediators via TestTopology.";
    let received = topology
        .forward(0, &alice, 1, &bob, text, Duration::from_secs(15))
        .await
        .expect("forward Alice -> Bob");

    assert_eq!(
        received.as_deref(),
        Some(text),
        "Bob should receive Alice's message after it routes node 0 -> node 1"
    );

    topology.shutdown().await.expect("shutdown topology");
}

/// Relay-REWRAP envelope preservation (#388): in rewrap mode each mediator
/// re-encrypts the inter-mediator hop from itself to the next mediator, hiding
/// the original sender on the wire — but the inner authcrypt addressed to Bob is
/// preserved, so Bob still decrypts Alice's original content. (The on-wire
/// rewrap crypto properties themselves are covered by the mediator crate's
/// `tests/relay_rewrap.rs`; here we assert the end-to-end preservation through
/// the fixture.)
#[tokio::test]
async fn rewrap_relay_preserves_inner_envelope_end_to_end() {
    init_tracing();

    let topology = TestTopology::builder()
        .mediators(2)
        .rewrap()
        .spawn()
        .await
        .expect("spawn 2-mediator rewrap topology");

    let alice = topology.add_user(0, "Alice").await.expect("add Alice");
    let bob = topology.add_user(1, "Bob").await.expect("add Bob");

    let text = "Rewrapped across two mediators — inner envelope intact.";
    let received = topology
        .forward(0, &alice, 1, &bob, text, Duration::from_secs(15))
        .await
        .expect("forward Alice -> Bob in rewrap mode");

    assert_eq!(
        received.as_deref(),
        Some(text),
        "rewrap relay must preserve the inner envelope so Bob sees Alice's content"
    );

    topology.shutdown().await.expect("shutdown topology");
}
