//! Rev 3 §7.3 end to end: a cancellation of a relationship held in both
//! directions is answered with a cancellation before it is forgotten.
//!
//! Keyring VTI-38: the answer was left to the caller, but by the time a caller
//! could send it the relationship was already `None`, so the only API for it
//! (`cancel_relationship`) refused and the peer was never answered.
#![cfg(feature = "tsp")]

use std::sync::Arc;

use affinidi_messaging_sdk::messages::DeleteMessageRequest;
use affinidi_messaging_sdk::messages::fetch::FetchOptions;
use affinidi_messaging_sdk::profiles::ATMProfile;
use affinidi_messaging_sdk::{ATM, TspPolicy};
use affinidi_messaging_test_mediator::TestEnvironment;
use affinidi_tsp::message::control::{ControlMessage, ControlType};
use affinidi_tsp::relationship::RelationshipState;

/// Everything stored for `profile`, drained. Waits for at least one message,
/// then gives stragglers a moment so "exactly one" is a real claim.
async fn drain_inbox(atm: &ATM, profile: &Arc<ATMProfile>) -> Vec<String> {
    let mut out = Vec::new();
    let mut quiet_rounds = 0;
    for _ in 0..40 {
        let fetched = atm
            .fetch_messages(profile, &FetchOptions::default())
            .await
            .expect("fetch messages");
        let ids: Vec<String> = fetched.success.iter().map(|e| e.msg_id.clone()).collect();
        out.extend(fetched.success.iter().filter_map(|e| e.msg.clone()));
        if !ids.is_empty() {
            atm.delete_messages_direct(profile, &DeleteMessageRequest { message_ids: ids })
                .await
                .expect("delete fetched");
            quiet_rounds = 0;
        } else if !out.is_empty() {
            quiet_rounds += 1;
            if quiet_rounds >= 4 {
                break;
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
    out
}

/// Unpack a single stored control message addressed to `profile`.
async fn unpack(
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    stored: &str,
) -> (ControlMessage, String, [u8; 32]) {
    let qb2 = atm.tsp().decode(stored).expect("decode");
    atm.tsp()
        .unpack_control(profile, &qb2)
        .await
        .expect("unpack control")
}

#[tokio::test]
async fn mutual_cancellation_is_answered_once_naming_the_relationship() {
    let env = TestEnvironment::spawn_ungated_with_tsp_policy(TspPolicy::Preferred)
        .await
        .expect("spawn env");
    let atm = &env.atm;
    let alice = env.add_user("alice").await.expect("add alice");
    let bob = env.add_user("bob").await.expect("add bob");

    // Form alice → bob, both sides Bidirectional.
    atm.tsp()
        .form_relationship(&alice.profile, &bob.did)
        .await
        .expect("alice invites");
    let inbox = drain_inbox(atm, &bob.profile).await;
    assert_eq!(inbox.len(), 1, "bob has the invite");
    let (invite, _, invite_digest) = unpack(atm, &bob.profile, &inbox[0]).await;
    atm.tsp()
        .record_incoming_control(&bob.profile, &alice.did, &invite)
        .await
        .expect("bob records the invite");
    atm.tsp()
        .accept_relationship(&bob.profile, &alice.did, invite_digest)
        .await
        .expect("bob accepts");
    let inbox = drain_inbox(atm, &alice.profile).await;
    assert_eq!(inbox.len(), 1, "alice has the accept");
    let (accept, _, _) = unpack(atm, &alice.profile, &inbox[0]).await;
    let recorded = atm
        .tsp()
        .record_incoming_control(&alice.profile, &bob.did, &accept)
        .await
        .expect("alice records the accept");
    assert_eq!(recorded.state, RelationshipState::Bidirectional);

    // `answer_cancellation` is only for a relationship already forgotten.
    let refused = atm
        .tsp()
        .answer_cancellation(&bob.profile, &alice.did, invite_digest)
        .await;
    assert!(
        refused.is_err(),
        "answer_cancellation must refuse while the relationship is held"
    );

    // Alice cancels.
    let alice_after = atm
        .tsp()
        .cancel_relationship(&alice.profile, &bob.did, invite_digest)
        .await
        .expect("alice cancels");
    assert_eq!(alice_after, RelationshipState::None);

    // Bob receives it: recording forgets the relationship and answers it.
    let inbox = drain_inbox(atm, &bob.profile).await;
    assert_eq!(inbox.len(), 1, "bob has the cancellation");
    let (cancel, sender, _) = unpack(atm, &bob.profile, &inbox[0]).await;
    assert_eq!(sender, alice.did);
    assert_eq!(cancel.control_type, ControlType::RelationshipCancel);
    let incoming = atm
        .tsp()
        .record_incoming_control(&bob.profile, &alice.did, &cancel)
        .await
        .expect("bob records the cancellation");
    assert_eq!(incoming.state, RelationshipState::None);
    assert!(
        !incoming.reply_expected,
        "the SDK sent the §7.3 answer, so nothing is owed by the caller"
    );
    assert_eq!(
        atm.tsp()
            .relationship_state(&bob.profile, &alice.did)
            .await
            .unwrap(),
        RelationshipState::None
    );

    // A caller that still answers the old way is refused and sends nothing.
    assert!(
        atm.tsp()
            .cancel_relationship(&bob.profile, &alice.did, invite_digest)
            .await
            .is_err()
    );

    // Exactly one cancellation came back, naming the relationship.
    let inbox = drain_inbox(atm, &alice.profile).await;
    assert_eq!(inbox.len(), 1, "exactly one §7.3 answer: {inbox:?}");
    let (answer, sender, _) = unpack(atm, &alice.profile, &inbox[0]).await;
    assert_eq!(sender, bob.did);
    assert_eq!(answer.control_type, ControlType::RelationshipCancel);
    assert_eq!(answer.reply, Some(invite_digest));

    // Alice already forgot it, so the answer is discarded, not answered — no
    // cancellation ping-pong.
    assert!(
        atm.tsp()
            .record_incoming_control(&alice.profile, &bob.did, &answer)
            .await
            .is_err()
    );
    assert_eq!(
        atm.tsp()
            .relationship_state(&alice.profile, &bob.did)
            .await
            .unwrap(),
        RelationshipState::None
    );
}

/// Only a relationship held in both directions is answered: cancelling a
/// pending invite (the peer holds `InviteReceived`) forgets it silently.
#[tokio::test]
async fn one_directional_cancellation_is_not_answered() {
    let env = TestEnvironment::spawn_ungated_with_tsp_policy(TspPolicy::Preferred)
        .await
        .expect("spawn env");
    let atm = &env.atm;
    let alice = env.add_user("alice").await.expect("add alice");
    let bob = env.add_user("bob").await.expect("add bob");

    atm.tsp()
        .form_relationship(&alice.profile, &bob.did)
        .await
        .expect("alice invites");
    let inbox = drain_inbox(atm, &bob.profile).await;
    let (invite, _, invite_digest) = unpack(atm, &bob.profile, &inbox[0]).await;
    atm.tsp()
        .record_incoming_control(&bob.profile, &alice.did, &invite)
        .await
        .expect("bob records the invite");

    atm.tsp()
        .cancel_relationship(&alice.profile, &bob.did, invite_digest)
        .await
        .expect("alice withdraws");
    let inbox = drain_inbox(atm, &bob.profile).await;
    let (cancel, _, _) = unpack(atm, &bob.profile, &inbox[0]).await;
    let incoming = atm
        .tsp()
        .record_incoming_control(&bob.profile, &alice.did, &cancel)
        .await
        .expect("bob records the withdrawal");
    assert_eq!(incoming.state, RelationshipState::None);
    assert!(!incoming.reply_expected);

    // Nothing comes back to alice.
    tokio::time::sleep(std::time::Duration::from_millis(750)).await;
    let fetched = atm
        .fetch_messages(&alice.profile, &FetchOptions::default())
        .await
        .expect("alice fetches");
    assert!(fetched.success.is_empty(), "no answer to a one-way cancel");
}
