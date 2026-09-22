//! A Trust Task is answered over whichever transport the profile and mediator
//! have in common — the caller writes the same code either way.
//!
//! Every `trust_tasks()` method funnels through one `exchange`, so this pins
//! the choice there rather than per method: under `TspPolicy::Required` a
//! fallback to DIDComm is not allowed, so an answer at all is proof the TSP
//! arm carried it — the document sealed to the mediator, and its sealed reply
//! collected from the inbox by thread id.
#![cfg(feature = "tsp")]

mod common;

use affinidi_messaging_sdk::TspPolicy;
use affinidi_messaging_sdk::protocols::tsp::{RelationshipState, SendProtocol};
use affinidi_messaging_test_mediator::TestEnvironment;
use common::init_tracing;

#[tokio::test]
async fn a_trust_task_is_answered_over_tsp_when_that_is_the_transport() {
    init_tracing();
    let env = TestEnvironment::spawn_with_tsp_policy(TspPolicy::Required)
        .await
        .expect("spawn with TSP required");
    let alice = env.add_user("alice").await.expect("add alice");
    let mediator_vid = env.mediator.did().to_string();

    // §7.2.2: the mediator's sealed reply is an application message, so it is
    // discarded at the receiver without a relationship. A TSP client that
    // talks to its mediator holds one; seeded here rather than handshaken.
    for (ours, theirs) in [(&alice.did, &mediator_vid), (&mediator_vid, &alice.did)] {
        env.relationship_store
            .set(ours, theirs, RelationshipState::Bidirectional)
            .await
            .expect("seed the relationship with the mediator");
    }

    // Under `Required` there is no DIDComm fallback, so this is the wire.
    let chosen = env
        .atm
        .tsp()
        .select_protocol(&alice.profile, &mediator_vid)
        .await
        .expect("select a protocol for the mediator");
    assert_eq!(chosen, SendProtocol::Tsp, "TSP is the chosen transport");

    // The ordinary call — no TSP-specific method, no transport argument.
    let account = env
        .atm
        .trust_tasks()
        .account_get(&alice.profile, None)
        .await
        .expect("account/get answered over TSP");
    assert_eq!(account.did.as_str(), alice.did_hash().as_str());
    assert_eq!(account.account_type.to_string(), "standard");

    // A second exchange still works: the first took its reply out of the
    // inbox and left everything else, so nothing is wedged behind it.
    let again = env
        .atm
        .trust_tasks()
        .account_get(&alice.profile, None)
        .await
        .expect("a second Trust Task is answered over TSP");
    assert_eq!(again.did.as_str(), alice.did_hash().as_str());
}

#[tokio::test]
async fn the_default_policy_keeps_trust_tasks_on_didcomm() {
    init_tracing();
    // `TspPolicy::Off` is the default, so an application that has not opted in
    // sees exactly what it saw before: DIDComm, unchanged.
    let env = TestEnvironment::spawn_with_direct_delivery()
        .await
        .expect("spawn test environment");
    let alice = env.add_user("alice").await.expect("add alice");
    env.atm
        .profile_add(&alice.profile, true)
        .await
        .expect("enable websocket for alice");

    assert_eq!(
        env.atm
            .tsp()
            .select_protocol(&alice.profile, env.mediator.did())
            .await
            .expect("select a protocol"),
        SendProtocol::DidComm,
        "the default policy stays on DIDComm"
    );
    let account = env
        .atm
        .trust_tasks()
        .account_get(&alice.profile, None)
        .await
        .expect("account/get answered over DIDComm");
    assert_eq!(account.did.as_str(), alice.did_hash().as_str());
}
