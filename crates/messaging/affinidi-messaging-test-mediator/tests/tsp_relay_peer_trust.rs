//! `processors.forwarding.relay_trusted_mediators` applied to TSP relay hops
//! (issue #758).
//!
//! Until now the allowlist was DIDComm-only, so a TSP deployment that needed its
//! relaying peer authenticated had no lever at all. It does now, and TSP gets a
//! stronger version than DIDComm: a routed hop addressed to this mediator is
//! unpacked, which verifies an Ed25519 signature over the envelope *and* opens
//! the payload with HPKE-Auth, so the peer is authenticated twice over. There is
//! no `RelayMode` to choose — TSP routed relay is re-wrap-like by construction.
//!
//! # The distinction these tests exist to pin
//!
//! On the DIDComm side only a peer mediator ever produces a re-wrap layer, so
//! peeling one is inter-mediator by construction. **A TSP routed message is
//! not**: an ordinary client sends one through its own mediator for metadata
//! privacy, and that client is not a peer mediator. Gating those on this list
//! would refuse every routed client the moment an operator populated it.
//!
//! The gate is therefore scoped to *anonymous* sessions, which is how an
//! inter-mediator hop arrives (POSTed to `/inbound` with no Authorization
//! header). [`client_routed_message_is_unaffected_by_the_peer_allowlist`] is the
//! test that holds that line.
#![cfg(feature = "tsp")]

use std::time::Duration;

use affinidi_messaging_sdk::messages::fetch::FetchOptions;
use affinidi_messaging_test_mediator::{TestEnvironment, TestMediator, topology::TestTopology};

/// A DID that is definitely not any mediator in these fixtures.
const STRANGER: &str = "did:peer:2.Ez6LSpSrLxbAhg2SHwKk7kwpsH7DM7QjFS5iK6PrfgtSSXhWH";

/// An ordinary client's routed message must still be relayed when the operator
/// has populated the peer allowlist. The client is not a peer mediator, and its
/// session is authenticated, so the allowlist must not apply to it.
///
/// This is the regression that matters: an implementation that gates every
/// routed hop on the allowlist passes every other test in this file and breaks
/// metadata-private routing for real clients.
#[tokio::test]
async fn client_routed_message_is_unaffected_by_the_peer_allowlist() {
    let mediator = TestMediator::builder()
        .local_direct_delivery(true, false)
        .relay_trusted_mediators([STRANGER])
        .spawn()
        .await
        .expect("spawn mediator with a populated peer allowlist");
    let env = TestEnvironment::new(mediator)
        .await
        .expect("wire the SDK to the mediator");

    let alice = env.add_user("alice").await.expect("add alice");
    let bob = env.add_user("bob").await.expect("add bob");
    let mediator_did = env.mediator.did().to_string();

    let payload = b"routed through my own mediator, for metadata privacy";
    env.atm
        .tsp()
        .send_routed(&alice.profile, &[mediator_did, bob.did.clone()], payload)
        .await
        .expect("a client's own routed message must not be gated by the peer allowlist");

    let fetched = env
        .atm
        .fetch_messages(&bob.profile, &FetchOptions::default())
        .await
        .expect("fetch messages");
    assert_eq!(
        fetched.success.len(),
        1,
        "bob must receive the relayed message"
    );

    env.shutdown().await.expect("shutdown");
}

/// An inter-mediator hop from a peer that is not on the allowlist is refused.
///
/// Alice on mediator A sends nested+routed to Bob on mediator B, so A relays to
/// B over B's anonymous `/inbound`. B's allowlist names only a stranger, so B
/// refuses the hop and nothing reaches Bob.
///
/// `send_nested_routed` still succeeds — it only ever reaches A, and the refusal
/// happens a hop later — so the assertion has to be on Bob's mailbox.
#[tokio::test]
async fn inter_mediator_hop_from_an_untrusted_peer_is_refused() {
    let topology = TestTopology::builder()
        .mediators(2)
        // Applied to both mediators, which is harmless: A only ever sees Alice
        // on an authenticated session, where the allowlist does not apply.
        .configure_each(|b| b.relay_trusted_mediators([STRANGER]))
        .spawn()
        .await
        .expect("spawn two-mediator topology");

    let mediator_a = topology.mediator_did(0).expect("mediator A").to_string();
    let mediator_b = topology.mediator_did(1).expect("mediator B").to_string();
    let alice = topology.add_user(0, "alice").await.expect("add alice on A");
    let bob = topology.add_user(1, "bob").await.expect("add bob on B");

    topology
        .node(0)
        .unwrap()
        .atm
        .tsp()
        .send_nested_routed(
            &alice.profile,
            &[mediator_a, mediator_b],
            &bob.did,
            b"should not arrive",
        )
        .await
        .expect("alice's send reaches her own mediator regardless");

    // Give the forwarding processor time to attempt the hop and be refused. The
    // positive case in `tsp_cross_mediator` arrives well within this window, so
    // an empty mailbox here is a refusal rather than impatience.
    let bob_env = topology.node(1).unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        let fetched = bob_env
            .atm
            .fetch_messages(&bob.profile, &FetchOptions::default())
            .await
            .expect("fetch messages");
        assert!(
            fetched.success.is_empty(),
            "a hop from an untrusted peer must not be delivered"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    topology.shutdown().await.expect("shutdown");
}

/// Control for the refusal: the same topology with an **empty** allowlist, which
/// admits any peer. Without this, the test above would pass just as happily
/// against a fixture where cross-mediator TSP delivery is simply broken.
///
/// Empty rather than naming mediator A explicitly, because A's DID does not
/// exist until the topology spawns and `configure_each` runs before that. The
/// pairing is still decisive: same topology, same route, same hop — only the
/// allowlist differs, and only the empty one delivers.
#[tokio::test]
async fn inter_mediator_hop_with_an_empty_allowlist_is_accepted() {
    let topology = TestTopology::builder()
        .mediators(2)
        .spawn()
        .await
        .expect("spawn two-mediator topology");

    let mediator_a = topology.mediator_did(0).expect("mediator A").to_string();
    let mediator_b = topology.mediator_did(1).expect("mediator B").to_string();
    let alice = topology.add_user(0, "alice").await.expect("add alice on A");
    let bob = topology.add_user(1, "bob").await.expect("add bob on B");

    let payload = b"hop from a trusted peer";
    topology
        .node(0)
        .unwrap()
        .atm
        .tsp()
        .send_nested_routed(&alice.profile, &[mediator_a, mediator_b], &bob.did, payload)
        .await
        .expect("alice sends nested+routed to bob on B");

    let bob_env = topology.node(1).unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    let stored = loop {
        let fetched = bob_env
            .atm
            .fetch_messages(&bob.profile, &FetchOptions::default())
            .await
            .expect("fetch messages");
        if let Some(msg) = fetched.success.first().and_then(|e| e.msg.as_ref()) {
            break msg.clone();
        }
        assert!(
            std::time::Instant::now() < deadline,
            "trusted hop was not delivered within the deadline"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    };

    let (recovered, sender) = bob_env
        .atm
        .tsp()
        .unpack(&bob.profile, &stored)
        .await
        .expect("bob unpacks");
    assert_eq!(recovered, payload);
    assert_eq!(sender, alice.did);

    topology.shutdown().await.expect("shutdown");
}
