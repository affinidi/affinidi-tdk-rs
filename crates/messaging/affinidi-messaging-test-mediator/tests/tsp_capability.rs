//! End-to-end coverage of TSP capability learning (SDD phase 2): a peer is
//! marked `Supported` once we observe an inbound TSP message from them or
//! complete a relationship, so `atm.send_to` auto-upgrades DIDComm → TSP.
#![cfg(feature = "tsp")]

use affinidi_messaging_didcomm::Message;
use affinidi_messaging_sdk::messages::MessageProtocol;
use affinidi_messaging_sdk::messages::fetch::FetchOptions;
use affinidi_messaging_sdk::{SendProtocol, TspPolicy, TspSupport};
use affinidi_messaging_test_mediator::TestEnvironment;
use affinidi_tsp::message::control::ControlMessage;
use affinidi_tsp::relationship::RelationshipState;
use serde_json::json;
use uuid::Uuid;

/// Fetch the next stored message for `profile`, waiting briefly for it to
/// arrive. Delivery through the mediator is not instantaneous, so a single
/// fetch races it.
async fn poll_inbox(
    env: &TestEnvironment,
    profile: &std::sync::Arc<affinidi_messaging_sdk::profiles::ATMProfile>,
) -> String {
    for _ in 0..40 {
        let fetched = env
            .atm
            .fetch_messages(profile, &FetchOptions::default())
            .await
            .expect("fetch messages");
        if let Some(stored) = fetched.success.first().and_then(|e| e.msg.clone()) {
            let ids: Vec<String> = fetched.success.iter().map(|e| e.msg_id.clone()).collect();
            env.atm
                .delete_messages_direct(
                    profile,
                    &affinidi_messaging_sdk::messages::DeleteMessageRequest { message_ids: ids },
                )
                .await
                .expect("delete fetched");
            return stored;
        }
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
    panic!("no message arrived");
}

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
    // Gating off: this test's subject is what an observed inbound message
    // teaches, and §7.2.2 would discard a message from a peer we have no
    // relationship with — while seeding one would itself signal TSP support
    // and settle the question before the test asks it.
    let env = TestEnvironment::spawn_ungated_with_tsp_policy(TspPolicy::Preferred)
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
    // Gating off for the same reason as the tests above: the subject is what an
    // observed inbound message teaches, which §7.2.2 would prevent happening.
    let env = TestEnvironment::spawn_ungated_with_tsp_policy(TspPolicy::Off)
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
    // Gating off: this test's subject is what an observed inbound message
    // teaches, and §7.2.2 would discard a message from a peer we have no
    // relationship with — while seeding one would itself signal TSP support
    // and settle the question before the test asks it.
    let env = TestEnvironment::spawn_ungated_with_tsp_policy(TspPolicy::Preferred)
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
    assert_eq!(alice_final.state, RelationshipState::Bidirectional);
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

/// Rev 3 §7.2.5, parallel relationship forming: an endpoint uses a relationship
/// it already has to introduce a second VID, and a relationship forms between
/// the new pair.
///
/// The point is that the peer learns the new identifier over a channel it
/// already trusts, so there is no out-of-band introduction to secure — §11
/// notes that an out-of-band introduction has no authenticity of its own and
/// "a party able to interfere with that channel could substitute a VID of its
/// own".
///
/// Two things this asserts that a unit test could not: the introduction
/// survives a real round trip through the mediator, and the accept forms the
/// relationship between the *new* pair rather than touching the original one.
#[tokio::test]
async fn a_referral_opens_a_parallel_relationship() {
    let env = TestEnvironment::spawn_with_tsp_policy(TspPolicy::Preferred)
        .await
        .expect("spawn env");

    // The existing relationship.
    let alice = env.add_user("alice").await.expect("add alice");
    let bob = env.add_user("bob").await.expect("add bob");
    env.relate(&alice, &bob)
        .await
        .expect("alice and bob relate");

    // A second identity each, not yet known to the other.
    let alice2 = env.add_user("alice-parallel").await.expect("add alice2");
    let bob2 = env.add_user("bob-parallel").await.expect("add bob2");

    // Alice introduces her new VID over the relationship she already has.
    env.atm
        .tsp()
        .form_parallel_relationship(&alice.profile, &bob.did, &alice2.profile)
        .await
        .expect("alice introduces her parallel VID");

    // Bob picks it up. The invite arrives on the existing relationship and
    // carries the referral; recording it verifies the introduced VID's own
    // signature, which is what makes the introduction worth trusting.
    let stored = poll_inbox(&env, &bob.profile).await;
    let qb2 = env.atm.tsp().decode(&stored).expect("decode invite");
    let (invite, sender, invite_digest) = env
        .atm
        .tsp()
        .unpack_control(&bob.profile, &qb2)
        .await
        .expect("bob unpacks the referral invite");
    assert_eq!(sender, alice.did);

    let referral = invite
        .referral
        .as_ref()
        .expect("the invite carries a referral");
    assert_eq!(
        referral.new_vid, alice2.did,
        "it introduces alice's new VID"
    );

    // Recording it on the relationship it arrived over verifies the introduced
    // VID's signature but advances nothing: the pair §7.2.5 forms is bob's new
    // VID and alice's, and bob has not picked his yet.
    let carrying = env
        .atm
        .tsp()
        .record_incoming_control(&bob.profile, &alice.did, &invite)
        .await
        .expect("bob records the referral, verifying the introduced VID signed it");
    assert_eq!(
        carrying.state,
        RelationshipState::Bidirectional,
        "the relationship the referral arrived on is left as it was"
    );

    // Bob answers from his own new VID to Alice's — §7.2.5 puts the accept
    // between the new pair, not over the relationship it arrived on.
    let state = env
        .atm
        .tsp()
        .accept_parallel_relationship(&bob2.profile, &alice2.did, invite_digest)
        .await
        .expect("bob accepts from his parallel VID");
    assert_eq!(state, RelationshipState::Bidirectional);

    // Alice's new VID completes its side.
    let stored = poll_inbox(&env, &alice2.profile).await;
    let qb2 = env.atm.tsp().decode(&stored).expect("decode accept");
    let (accept, accept_sender, _) = env
        .atm
        .tsp()
        .unpack_control(&alice2.profile, &qb2)
        .await
        .expect("alice's new VID unpacks the accept");
    assert_eq!(
        accept_sender, bob2.did,
        "the accept comes from bob's new VID"
    );

    // Alice could not know bob would answer from `bob2`, so her pending invite
    // is filed against the peer she sent it to; this moves it onto the real pair.
    let final_state = env
        .atm
        .tsp()
        .record_parallel_accept(&alice2.profile, &bob2.did, &bob.did, &accept)
        .await
        .expect("alice records the accept");
    assert_eq!(final_state.state, RelationshipState::Bidirectional);

    // A stranger cannot answer an introduction it never received.
    let mallory = env.add_user("mallory").await.expect("add mallory");
    let forged = ControlMessage::accept([9u8; 32]);
    let err = env
        .atm
        .tsp()
        .record_parallel_accept(&alice2.profile, &mallory.did, &bob.did, &forged)
        .await
        .expect_err("an accept that echoes the wrong digest is rejected");
    assert!(
        err.to_string().contains("does not echo the digest"),
        "rejected for the right reason, got: {err}"
    );

    // The parallel relationship stands beside the original, which is untouched.
    assert_eq!(
        env.atm
            .tsp()
            .relationship_state(&alice.profile, &bob.did)
            .await
            .unwrap(),
        RelationshipState::Bidirectional,
        "the relationship the introduction travelled over is unchanged"
    );

    // And the new pair can now talk directly.
    env.atm
        .tsp()
        .send(
            &alice2.profile,
            &bob2.did,
            b"over the parallel relationship",
        )
        .await
        .expect("the parallel pair exchange an application message");

    let stored = poll_inbox(&env, &bob2.profile).await;
    let (payload, from) = env
        .atm
        .tsp()
        .unpack(&bob2.profile, &stored)
        .await
        .expect("bob's new VID unpacks it");
    assert_eq!(payload, b"over the parallel relationship");
    assert_eq!(from, alice2.did);

    env.shutdown().await.expect("shutdown");
}
