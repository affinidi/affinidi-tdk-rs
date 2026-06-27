//! End-to-end **pure-TSP client authentication** through the mediator.
//!
//! Unlike `tsp_delivery.rs` (which lets the SDK authenticate over the built-in
//! DIDComm flow), this environment registers a `TspAuthHandler` as the *only*
//! authentication path: every profile authenticates by signing the mediator's
//! `/authenticate/challenge` with its Ed25519 VID key and POSTing the signature
//! to `POST /tsp/authenticate`, minting the JWT used for the REST send/fetch.
//!
//! Driving a flow that *requires* authentication (Alice sends a TSP Direct
//! message to Bob; Bob fetches and unpacks it) proves the whole pure-TSP auth
//! chain end to end:
//!
//! ```text
//! challenge → Ed25519-sign-with-VID → /tsp/authenticate → JWT → REST send/fetch
//! ```
//!
//! Both the send and the fetch require a valid token the `TspAuthHandler`
//! produced, so a green round-trip is only possible if pure-TSP auth works.
#![cfg(feature = "tsp")]

use affinidi_messaging_sdk::messages::MessageProtocol;
use affinidi_messaging_sdk::messages::fetch::FetchOptions;
use affinidi_messaging_test_mediator::TestEnvironment;

#[tokio::test]
async fn pure_tsp_authentication_round_trips_a_direct_message() {
    // The environment's only auth handler is the `TspAuthHandler`, so every
    // profile below authenticates over `/tsp/authenticate`.
    let env = TestEnvironment::spawn_with_tsp_auth()
        .await
        .expect("spawn TSP-auth test environment");

    // Alice + Bob: their secrets land in the SAME resolver the `TspAuthHandler`
    // holds, so it can load each one's Ed25519 VID key to sign the challenge.
    let alice = env.add_user("alice").await.expect("add alice");
    let bob = env.add_user("bob").await.expect("add bob");

    let payload = b"hello over pure-TSP auth";

    // Alice sends a TSP Direct message to Bob. This first authenticates Alice's
    // profile (challenge → sign → /tsp/authenticate → JWT) and then POSTs the
    // packed message to `/inbound` with that token.
    env.atm
        .tsp()
        .send(&alice.profile, &bob.did, payload)
        .await
        .expect("alice authenticates over TSP and sends a message to bob");

    // Bob fetches his mailbox — which likewise authenticates Bob's profile over
    // TSP before the authenticated `/fetch` REST call.
    let fetched = env
        .atm
        .fetch_messages(&bob.profile, &FetchOptions::default())
        .await
        .expect("bob authenticates over TSP and fetches messages");

    let element = fetched
        .success
        .first()
        .expect("bob has one fetched message");
    let stored = element
        .msg
        .as_ref()
        .expect("fetched message carries its body");

    assert!(
        env.atm.tsp().is_tsp(stored),
        "the stored message is recognised as TSP"
    );
    assert_eq!(
        element.protocol,
        Some(MessageProtocol::Tsp),
        "fetch tags the message as TSP"
    );

    let (recovered, sender) = env
        .atm
        .tsp()
        .unpack(&bob.profile, stored)
        .await
        .expect("bob unpacks the TSP message");

    assert_eq!(
        recovered, payload,
        "payload round-trips end to end under pure-TSP auth"
    );
    assert_eq!(sender, alice.did, "sender VID is recovered");

    env.shutdown().await.expect("shut down the environment");
}
