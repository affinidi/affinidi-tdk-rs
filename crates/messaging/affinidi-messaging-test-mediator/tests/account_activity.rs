//! Each account's activity — the last message the mediator accepted for it and
//! its last completed authentication — is recorded by the running mediator,
//! not just storable. A store-level test would still pass if the call sites
//! were deleted; this drives a real authentication and a real delivery.

mod common;

use std::time::{SystemTime, UNIX_EPOCH};

use affinidi_messaging_didcomm::Message;
use affinidi_messaging_test_mediator::{TestEnvironment, TestMediator};
use common::init_tracing;
use serde_json::json;
use uuid::Uuid;

fn unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after epoch")
        .as_secs()
}

#[tokio::test]
async fn authenticating_and_receiving_are_recorded() {
    init_tracing();
    let before = unix_secs();
    let mediator = TestMediator::builder()
        .local_direct_delivery(true, false)
        .spawn()
        .await
        .expect("spawn mediator");
    let env = TestEnvironment::new(mediator)
        .await
        .expect("wire the SDK to the mediator");
    let alice = env.add_user("alice").await.expect("add alice");
    let bob = env.add_user("bob").await.expect("add bob");
    let (alice_hash, bob_hash) = (sha256::digest(&alice.did), sha256::digest(&bob.did));
    let store = env.mediator.store();

    let now = unix_secs();
    let msg = Message::build(
        Uuid::new_v4().to_string(),
        "https://didcomm.org/basicmessage/2.0/message".to_string(),
        json!({ "content": "activity probe" }),
    )
    .to(bob.did.clone())
    .from(alice.did.clone())
    .created_time(now)
    .expires_time(now + 60)
    .finalize();
    let (packed, _) = env
        .atm
        .pack_encrypted(&msg, &bob.did, Some(&alice.did), Some(&alice.did))
        .await
        .expect("pack");
    env.atm
        .send_message(&alice.profile, &packed, &msg.id, false, false)
        .await
        .expect("send alice -> bob");

    let got = store
        .account_activity(&[alice_hash, bob_hash])
        .await
        .expect("read activity");
    let after = unix_secs();
    let within = |t: Option<u64>| t.is_some_and(|t| (before..=after).contains(&t));

    assert!(
        within(got[0].last_authenticated),
        "sending authenticated alice: {:?}",
        got[0]
    );
    assert!(
        within(got[1].last_received),
        "bob was sent a message: {:?}",
        got[1]
    );
    assert_eq!(got[0].last_received, None, "nothing was sent to alice");

    // Over the wire, the times come back only when the request asks for them.
    env.atm
        .profile_add(&bob.profile, true)
        .await
        .expect("enable websocket for bob");
    let quiet = env
        .atm
        .trust_tasks()
        .account_get(&bob.profile, None)
        .await
        .expect("bob reads his own account");
    assert_eq!(
        (quiet.last_received_at, quiet.last_authenticated_at),
        (None, None),
        "a request that didn't ask gets neither time"
    );

    let asked = env
        .atm
        .trust_tasks()
        .account_get_with_activity(&bob.profile, None, true)
        .await
        .expect("bob reads his own account, asking for activity");
    assert!(
        within(asked.last_received_at),
        "the message alice sent: {:?}",
        asked.last_received_at
    );
    assert!(
        within(asked.last_authenticated_at),
        "bob authenticated: {:?}",
        asked.last_authenticated_at
    );
}
