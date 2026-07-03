//! Cross-mediator TSP delivery for service-less (`did:key`-style) peers (#577 P1).
//!
//! - The metadata-private carriage primitive (`send_nested_routed`) delivers a
//!   Nested-wrapped Direct message across two mediators, with the recipient
//!   hidden from the sender's mediator (it is not a route hop).
//! - `atm.send_to` routes cross-mediator automatically when the peer's mediator
//!   is known and differs from the sender's.
//! - The peer's mediator is learned from a routed relationship invite
//!   (`form_relationship_routed` → `record_incoming_control`).
#![cfg(feature = "tsp")]

use affinidi_messaging_didcomm::Message;
use affinidi_messaging_sdk::messages::fetch::FetchOptions;
use affinidi_messaging_sdk::{SendProtocol, TspPolicy, TspSupport};
use affinidi_messaging_test_mediator::{TestEnvironment, topology::TestTopology};
use serde_json::json;
use std::time::Duration;
use uuid::Uuid;

fn basic_message(from: &str, to: &str, text: &str) -> Message {
    Message::build(
        Uuid::new_v4().to_string(),
        "https://didcomm.org/basicmessage/2.0/message".to_string(),
        json!({ "content": text }),
    )
    .to(to.to_string())
    .from(from.to_string())
    .finalize()
}

/// Poll a node's mailbox until a message lands (cross-mediator forwarding is
/// asynchronous), returning the stored message.
async fn poll_inbox(
    env: &TestEnvironment,
    profile: &std::sync::Arc<affinidi_messaging_sdk::profiles::ATMProfile>,
) -> String {
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    while std::time::Instant::now() < deadline {
        let fetched = env
            .atm
            .fetch_messages(profile, &FetchOptions::default())
            .await
            .expect("fetch messages");
        if let Some(msg) = fetched.success.first().and_then(|e| e.msg.as_ref()) {
            return msg.clone();
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    panic!("no message received within the deadline");
}

/// The carriage primitive: `send_nested_routed` delivers across two mediators
/// while the recipient stays off the route (hidden from the sender's mediator).
#[tokio::test]
async fn send_nested_routed_delivers_cross_mediator() {
    let topology = TestTopology::builder()
        .mediators(2)
        .spawn()
        .await
        .expect("spawn two-mediator topology");
    let mediator_a = topology.mediator_did(0).expect("mediator A").to_string();
    let mediator_b = topology.mediator_did(1).expect("mediator B").to_string();
    let alice = topology.add_user(0, "alice").await.expect("add alice on A");
    let bob = topology.add_user(1, "bob").await.expect("add bob on B");

    let payload = b"hello bob, nested over routed, recipient hidden from mediator A";
    let route = vec![mediator_a, mediator_b];
    topology
        .node(0)
        .unwrap()
        .atm
        .tsp()
        .send_nested_routed(&alice.profile, &route, &bob.did, payload)
        .await
        .expect("alice sends nested+routed to bob on B");

    let bob_env = topology.node(1).unwrap();
    let stored = poll_inbox(bob_env, &bob.profile).await;
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

/// `send_to` routes cross-mediator automatically when the peer's mediator is
/// known (here injected out-of-band) and differs from the sender's.
#[tokio::test]
async fn send_to_routes_cross_mediator_when_peer_mediator_known() {
    let topology = TestTopology::builder()
        .mediators(2)
        .tsp_policy(TspPolicy::Preferred)
        .spawn()
        .await
        .expect("spawn two-mediator topology with Preferred policy");
    let mediator_b = topology.mediator_did(1).expect("mediator B").to_string();
    let alice = topology.add_user(0, "alice").await.expect("add alice on A");
    let bob = topology.add_user(1, "bob").await.expect("add bob on B");
    let a = topology.node(0).unwrap();

    // Alice knows bob speaks TSP and lives on mediator B (learned out-of-band).
    a.atm
        .tsp()
        .set_peer_capability(&alice.profile, &bob.did, TspSupport::Supported)
        .await
        .expect("set bob supported");
    a.atm
        .tsp()
        .set_peer_mediator(&alice.profile, &bob.did, Some(mediator_b.clone()))
        .await
        .expect("set bob's mediator");

    let msg = basic_message(&alice.did, &bob.did, "cross-mediator via send_to");
    let via = a
        .atm
        .send_to(&alice.profile, &msg, &bob.did, Some(&alice.did), None)
        .await
        .expect("send_to bob");
    assert_eq!(via, SendProtocol::Tsp, "known peer capability → TSP");

    // Bob, on mediator B, receives and unpacks the routed message.
    let bob_env = topology.node(1).unwrap();
    let stored = poll_inbox(bob_env, &bob.profile).await;
    let (payload, sender) = bob_env
        .atm
        .tsp()
        .unpack(&bob.profile, &stored)
        .await
        .expect("bob unpacks");
    assert_eq!(sender, alice.did);
    let recovered: Message = serde_json::from_slice(&payload).expect("payload is a Message");
    assert_eq!(
        recovered.body,
        json!({ "content": "cross-mediator via send_to" })
    );

    topology.shutdown().await.expect("shutdown");
}

/// A **routed** invite advertises the inviter's mediator; the recipient learns
/// and caches it via `record_incoming_control`, so a later `send_to` can route
/// to that peer. (Single mediator — this exercises the learning wire path; the
/// cross-mediator delivery is covered above.)
#[tokio::test]
async fn routed_invite_teaches_peer_mediator() {
    let env = TestEnvironment::spawn_with_tsp_policy(TspPolicy::Preferred)
        .await
        .expect("spawn env with Preferred policy");
    let alice = env.add_user("alice").await.expect("add alice");
    let bob = env.add_user("bob").await.expect("add bob");

    // Alice's own mediator DID — what her routed invite advertises.
    let (_, alice_mediator) = alice.profile.dids().expect("alice dids");
    let alice_mediator = alice_mediator.to_string();

    // Alice forms a relationship with a routed invite (advertises her mediator).
    env.atm
        .tsp()
        .form_relationship_routed(&alice.profile, &bob.did)
        .await
        .expect("alice forms routed relationship");

    // Bob fetches and records the invite.
    let stored = poll_inbox(&env, &bob.profile).await;
    let invite_qb2 = env.atm.tsp().decode(&stored).expect("decode invite");
    let (invite, sender, _digest) = env
        .atm
        .tsp()
        .unpack_control(&bob.profile, &invite_qb2)
        .await
        .expect("bob unpacks the invite control");
    assert_eq!(sender, alice.did);
    env.atm
        .tsp()
        .record_incoming_control(&bob.profile, &alice.did, &invite)
        .await
        .expect("bob records the invite");

    // Bob now knows alice's mediator.
    let cap = env
        .atm
        .tsp()
        .peer_capability(&bob.profile, &alice.did)
        .await
        .unwrap()
        .expect("bob has a capability record for alice");
    assert_eq!(
        cap.mediator,
        Some(alice_mediator),
        "bob learned alice's mediator from the routed invite"
    );
}
