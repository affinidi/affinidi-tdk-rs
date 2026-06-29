//! Two-mediator **TSP federation** end-to-end: a TSP message crosses from one
//! mediator to another over the wire.
//!
//! Alice is homed on mediator A, Bob on mediator B. Alice sends Bob a TSP
//! message **routed through both mediators**: the inner is sealed end-to-end
//! Alice → Bob, and the routing layer is sealed to Alice's mediator A with the
//! onward route `[mediator_B, bob]`. A unwraps its routing layer, sees the next
//! hop is mediator B (not a local account), resolves B's advertised
//! `TSPTransport` endpoint from its DID document, re-seals the onward route to B,
//! and the forwarding processor POSTs the re-sealed message to B's `/inbound`
//! over loopback HTTP. B unwraps its routing layer, sees the next hop is Bob (a
//! local account), and stores the opaque inner for him. Bob fetches and unpacks
//! it, recovering Alice's plaintext and her VID as the original sender.
//!
//! This is the TSP analogue of `cross_mediator_forwarding.rs` (the DIDComm
//! two-mediator double-forward): the federation hop is the same loopback
//! mediator-A → mediator-B `/inbound` POST, but driven by the SDK's TSP routed
//! send and the mediator's `forward_tsp_remote` path (DID-doc `TSPTransport`
//! resolution → forwarding-queue enqueue → REST delivery as `application/tsp`).
//!
//! All identities are `did:peer:2.*`, so every DID (both mediators, both users)
//! resolves locally; the only real socket traffic is the forwarding processor's
//! loopback HTTP hop from A to B.
#![cfg(feature = "tsp")]

mod common;

use std::time::Duration;

use affinidi_messaging_sdk::messages::fetch::FetchOptions;
use affinidi_messaging_test_mediator::TestTopology;
use common::init_tracing;

/// Alice (on mediator A) sends a TSP message to Bob (on mediator B); it crosses
/// A → B over the wire via B's advertised `TSPTransport` endpoint, and Bob
/// recovers Alice's plaintext + VID.
#[tokio::test]
async fn tsp_message_federates_across_two_mediators() {
    init_tracing();

    // Mediator 0 = A (Alice's), mediator 1 = B (Bob's). Both relay-enabled with
    // an allow-all default ACL, so the cross-mediator forward sender is accepted.
    let topology = TestTopology::builder()
        .mediators(2)
        .spawn()
        .await
        .expect("spawn two-mediator topology");

    let mediator_a_did = topology
        .mediator_did(0)
        .expect("mediator A did")
        .to_string();
    let mediator_b_did = topology
        .mediator_did(1)
        .expect("mediator B did")
        .to_string();

    let alice = topology.add_user(0, "alice").await.expect("add alice on A");
    let bob = topology.add_user(1, "bob").await.expect("add bob on B");

    let payload = b"hello bob, across two mediators, over TSP";

    // Route: alice -> mediator A (the routing-layer recipient, route[0]) ->
    // mediator B (the onward hop A forwards to over the wire) -> bob (the final
    // recipient the inner is sealed to, route.last()).
    //
    // `send_routed` seals the inner end-to-end to `route.last()` (bob) and wraps
    // a routing layer sealed to `route[0]` — which must be alice's own mediator A,
    // since the SDK posts the routed message to A's `/inbound` and A must be the
    // routing-layer receiver. A unwraps it, sees `next = mediator_B` with the
    // remaining route `[bob]` (non-empty → an intermediate hop), re-seals the
    // onward route to B and forwards over the wire; B unwraps it, sees
    // `next = bob` with an empty remaining route (the exit hop) and delivers the
    // opaque inner to bob locally.
    let route = vec![
        mediator_a_did.clone(),
        mediator_b_did.clone(),
        bob.did.clone(),
    ];
    topology
        .node(0)
        .expect("node A")
        .atm
        .tsp()
        .send_routed(&alice.profile, &route, payload)
        .await
        .expect("alice sends a federated TSP message via mediator A onward to mediator B");

    // The forwarding processor delivers A -> B's /inbound asynchronously; poll
    // Bob's mailbox on B until the relayed (now opaque Direct) message lands,
    // like the DIDComm cross-mediator test waits on the live stream.
    let bob_env = topology.node(1).expect("node B");
    let stored = {
        let mut found = None;
        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        while std::time::Instant::now() < deadline {
            let fetched = bob_env
                .atm
                .fetch_messages(&bob.profile, &FetchOptions::default())
                .await
                .expect("bob fetches messages");
            if let Some(element) = fetched.success.first()
                && let Some(msg) = element.msg.as_ref()
            {
                found = Some(msg.clone());
                break;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        found.expect("bob received the federated TSP message within the deadline")
    };

    // It is recognised as TSP and unpacks to Alice's original payload + VID.
    assert!(
        bob_env.atm.tsp().is_tsp(&stored),
        "the federated message is recognised as TSP"
    );
    let (recovered, sender) = bob_env
        .atm
        .tsp()
        .unpack(&bob.profile, &stored)
        .await
        .expect("bob unpacks the federated TSP message");

    assert_eq!(
        recovered, payload,
        "payload round-trips end to end across both mediators"
    );
    assert_eq!(
        sender, alice.did,
        "the original sender VID is recovered (alice), not either relaying mediator"
    );

    topology.shutdown().await.expect("shutdown topology");
}
