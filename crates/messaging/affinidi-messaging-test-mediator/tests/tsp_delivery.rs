//! End-to-end TSP Direct delivery through the mediator, driven entirely by the
//! SDK's `atm.tsp()`: Alice packs a TSP Direct message and POSTs it to
//! `/inbound`; the mediator sniffs the TSP magic byte and stores it for Bob; Bob
//! fetches and unpacks it. Exercises the full sniff → store → fetch → unpack path
//! across the SDK + mediator (memory backend, no Redis needed).
#![cfg(feature = "tsp")]

use affinidi_messaging_sdk::messages::fetch::FetchOptions;
use affinidi_messaging_test_mediator::TestEnvironment;

#[tokio::test]
async fn tsp_direct_message_round_trips_through_the_mediator() {
    let env = TestEnvironment::spawn()
        .await
        .expect("spawn test environment");

    // Two locally-served, authenticated users (did:peer profiles).
    let alice = env.add_user("alice").await.expect("add alice");
    let bob = env.add_user("bob").await.expect("add bob");

    let payload = b"hello over TSP";

    // Alice packs a TSP Direct message to Bob and sends it to the mediator.
    env.atm
        .tsp()
        .send(&alice.profile, &bob.did, payload)
        .await
        .expect("alice sends a TSP message to bob");

    // Bob fetches his mailbox; the message is the stored TSP (CESR qb64) string.
    let fetched = env
        .atm
        .fetch_messages(&bob.profile, &FetchOptions::default())
        .await
        .expect("bob fetches messages");

    let element = fetched
        .success
        .first()
        .expect("bob has one fetched message");
    let stored = element
        .msg
        .as_ref()
        .expect("fetched message carries its body");

    // It is recognised as TSP and unpacks to the original payload + sender.
    assert!(
        env.atm.tsp().is_tsp(stored),
        "the stored message is recognised as TSP"
    );
    let (recovered, sender) = env
        .atm
        .tsp()
        .unpack(&bob.profile, stored)
        .await
        .expect("bob unpacks the TSP message");

    assert_eq!(recovered, payload, "payload round-trips end to end");
    assert_eq!(sender, alice.did, "sender VID is recovered");
}

/// End-to-end TSP **Routed** relay: Alice sends through the mediator as a relay
/// hop to Bob. The payload is sealed end-to-end to Bob; the outer routing layer
/// is sealed to the mediator, which unwraps it and forwards the opaque inner to
/// Bob (a local recipient). Proves the mediator's routed-relay path: derive its
/// own TSP identity → unpack the layer sealed to it → `next_hop` → deliver.
#[tokio::test]
async fn tsp_routed_message_relays_through_the_mediator() {
    let env = TestEnvironment::spawn()
        .await
        .expect("spawn test environment");

    let alice = env.add_user("alice").await.expect("add alice");
    let bob = env.add_user("bob").await.expect("add bob");
    let mediator_did = env.mediator.did().to_string();

    let payload = b"routed hello over TSP";

    // Route: alice -> mediator (relay hop) -> bob.
    let route = vec![mediator_did, bob.did.clone()];
    env.atm
        .tsp()
        .send_routed(&alice.profile, &route, payload)
        .await
        .expect("alice sends a routed TSP message via the mediator");

    // Bob fetches the relayed (now opaque Direct) message and unpacks it.
    let fetched = env
        .atm
        .fetch_messages(&bob.profile, &FetchOptions::default())
        .await
        .expect("bob fetches messages");
    let element = fetched
        .success
        .first()
        .expect("bob has one relayed message");
    let stored = element
        .msg
        .as_ref()
        .expect("relayed message carries its body");

    let (recovered, sender) = env
        .atm
        .tsp()
        .unpack(&bob.profile, stored)
        .await
        .expect("bob unpacks the relayed TSP message");

    assert_eq!(recovered, payload, "payload survives the relay end to end");
    assert_eq!(sender, alice.did, "original sender VID is recovered, not the relay");
}
