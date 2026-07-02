//! End-to-end coverage of TSP capability learning (SDD phase 2): a peer is
//! marked `Supported` once we observe an inbound TSP message from them or
//! complete a relationship, so `atm.send_to` auto-upgrades DIDComm → TSP.
#![cfg(feature = "tsp")]

use affinidi_messaging_didcomm::Message;
use affinidi_messaging_sdk::messages::MessageProtocol;
use affinidi_messaging_sdk::messages::fetch::FetchOptions;
use affinidi_messaging_sdk::{SendProtocol, TspPolicy, TspSupport};
use affinidi_messaging_test_mediator::TestEnvironment;
use affinidi_tsp::relationship::RelationshipState;
use serde_json::json;
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

/// The headline phase-2 behaviour: alice sends DIDComm to a peer she knows
/// nothing about; after the peer sends her a TSP message she unpacks, the peer
/// is cached `Supported` and her next `send_to` upgrades to TSP.
#[tokio::test]
async fn observed_inbound_tsp_upgrades_send_to() {
    let env = TestEnvironment::spawn_with_tsp_policy(TspPolicy::Preferred)
        .await
        .expect("spawn env with Preferred policy");
    let alice = env.add_user("alice").await.expect("add alice");
    let bob = env.add_user("bob").await.expect("add bob");

    // No signal yet (bob's did:peer advertises no TSPTransport) → DIDComm.
    assert_eq!(
        env.atm
            .tsp()
            .peer_capability(&alice.profile, &bob.did)
            .await
            .unwrap(),
        None
    );
    let m1 = basic_message(&alice.did, &bob.did, "first");
    let via1 = env
        .atm
        .send_to(&alice.profile, &m1, &bob.did, Some(&alice.did), None)
        .await
        .expect("send_to bob (1)");
    assert_eq!(via1, SendProtocol::DidComm, "no TSP signal yet → DIDComm");

    // Bob sends Alice a TSP message; Alice fetches + unpacks it.
    env.atm
        .tsp()
        .send(&bob.profile, &alice.did, b"hi from bob over tsp")
        .await
        .expect("bob sends TSP to alice");
    let fetched = env
        .atm
        .fetch_messages(&alice.profile, &FetchOptions::default())
        .await
        .expect("alice fetches");
    let stored = fetched
        .success
        .iter()
        .find(|e| e.protocol == Some(MessageProtocol::Tsp))
        .and_then(|e| e.msg.as_ref())
        .expect("alice has a TSP message");
    let (_payload, sender) = env
        .atm
        .tsp()
        .unpack(&alice.profile, stored)
        .await
        .expect("alice unpacks bob's TSP message");
    assert_eq!(sender, bob.did);

    // Observing that inbound TSP cached bob as Supported → send_to upgrades.
    let cap = env
        .atm
        .tsp()
        .peer_capability(&alice.profile, &bob.did)
        .await
        .unwrap();
    assert!(
        matches!(cap.map(|c| c.tsp), Some(TspSupport::Supported)),
        "observing inbound TSP marks the sender Supported"
    );
    let m2 = basic_message(&alice.did, &bob.did, "second");
    let via2 = env
        .atm
        .send_to(&alice.profile, &m2, &bob.did, Some(&alice.did), None)
        .await
        .expect("send_to bob (2)");
    assert_eq!(
        via2,
        SendProtocol::Tsp,
        "learned capability upgrades to TSP"
    );
}

/// Under the default `Off` policy, capability tracking is inert — observing an
/// inbound TSP message writes nothing, so behaviour is unchanged.
#[tokio::test]
async fn observed_inbound_is_inert_under_off_policy() {
    let env = TestEnvironment::spawn()
        .await
        .expect("spawn default (Off) env");
    let alice = env.add_user("alice").await.expect("add alice");
    let bob = env.add_user("bob").await.expect("add bob");

    env.atm
        .tsp()
        .send(&bob.profile, &alice.did, b"tsp under off")
        .await
        .expect("bob sends TSP to alice");
    let fetched = env
        .atm
        .fetch_messages(&alice.profile, &FetchOptions::default())
        .await
        .expect("alice fetches");
    let stored = fetched
        .success
        .first()
        .and_then(|e| e.msg.as_ref())
        .expect("alice has a message");
    env.atm
        .tsp()
        .unpack(&alice.profile, stored)
        .await
        .expect("alice unpacks");

    assert_eq!(
        env.atm
            .tsp()
            .peer_capability(&alice.profile, &bob.did)
            .await
            .unwrap(),
        None,
        "Off policy tracks no capability"
    );
}

/// Completing a relationship marks both peers `Supported`, so `send_to` uses
/// TSP afterwards. Also the repo's first end-to-end TSP relationship handshake.
#[tokio::test]
async fn completed_relationship_marks_peers_tsp_supported() {
    let env = TestEnvironment::spawn_with_tsp_policy(TspPolicy::Preferred)
        .await
        .expect("spawn env with Preferred policy");
    let alice = env.add_user("alice").await.expect("add alice");
    let bob = env.add_user("bob").await.expect("add bob");

    // Alice initiates: invite → Pending.
    let alice_state = env
        .atm
        .tsp()
        .form_relationship(&alice.profile, &bob.did)
        .await
        .expect("alice forms relationship");
    assert_eq!(alice_state, RelationshipState::Pending);

    // Bob receives the invite, records it, and accepts → Bidirectional.
    let bob_inbox = env
        .atm
        .fetch_messages(&bob.profile, &FetchOptions::default())
        .await
        .expect("bob fetches invite");
    let invite_stored = bob_inbox
        .success
        .first()
        .and_then(|e| e.msg.as_ref())
        .expect("bob has the invite");
    let invite_qb2 = env.atm.tsp().decode(invite_stored).expect("decode invite");
    let (invite, invite_sender, invite_digest) = env
        .atm
        .tsp()
        .unpack_control(&bob.profile, &invite_qb2)
        .await
        .expect("bob unpacks the invite control");
    assert_eq!(invite_sender, alice.did);
    env.atm
        .tsp()
        .record_incoming_control(&bob.profile, &alice.did, &invite)
        .await
        .expect("bob records the invite");
    let bob_state = env
        .atm
        .tsp()
        .accept_relationship(&bob.profile, &alice.did, invite_digest)
        .await
        .expect("bob accepts");
    assert_eq!(bob_state, RelationshipState::Bidirectional);
    assert!(
        matches!(
            env.atm
                .tsp()
                .peer_capability(&bob.profile, &alice.did)
                .await
                .unwrap()
                .map(|c| c.tsp),
            Some(TspSupport::Supported)
        ),
        "bob learned alice speaks TSP"
    );

    // Alice receives the accept → Bidirectional, learns bob is Supported.
    let alice_inbox = env
        .atm
        .fetch_messages(&alice.profile, &FetchOptions::default())
        .await
        .expect("alice fetches accept");
    let accept_stored = alice_inbox
        .success
        .first()
        .and_then(|e| e.msg.as_ref())
        .expect("alice has the accept");
    let accept_qb2 = env.atm.tsp().decode(accept_stored).expect("decode accept");
    let (accept, accept_sender, _digest) = env
        .atm
        .tsp()
        .unpack_control(&alice.profile, &accept_qb2)
        .await
        .expect("alice unpacks the accept control");
    assert_eq!(accept_sender, bob.did);
    let alice_final = env
        .atm
        .tsp()
        .record_incoming_control(&alice.profile, &bob.did, &accept)
        .await
        .expect("alice records the accept");
    assert_eq!(alice_final, RelationshipState::Bidirectional);
    assert!(
        matches!(
            env.atm
                .tsp()
                .peer_capability(&alice.profile, &bob.did)
                .await
                .unwrap()
                .map(|c| c.tsp),
            Some(TspSupport::Supported)
        ),
        "alice learned bob speaks TSP"
    );

    // send_to now uses TSP.
    let m = basic_message(&alice.did, &bob.did, "post-relationship");
    let via = env
        .atm
        .send_to(&alice.profile, &m, &bob.did, Some(&alice.did), None)
        .await
        .expect("send_to after relationship");
    assert_eq!(via, SendProtocol::Tsp);
}
