//! The mediator counts each message it accepts against both accounts, so an
//! operator can read an account's lifetime totals from the mediator rather
//! than adding up a live feed.
//!
//! A store-level test would still pass if the counting call site were
//! deleted; this drives a real delivery and reads the counters back.

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
async fn a_delivered_message_is_counted_for_both_accounts() {
    init_tracing();
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
        json!({ "content": "one for the counters" }),
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
        .account_stats(&[alice_hash, bob_hash])
        .await
        .expect("read the counters");
    let (alice_stats, bob_stats) = (got[0], got[1]);

    assert_eq!(bob_stats.messages_received, 1, "bob was sent one message");
    assert!(
        bob_stats.bytes_received > 0,
        "the message had a size: {bob_stats:?}"
    );
    assert_eq!(
        bob_stats.received_by_protocol.didcomm, 1,
        "counted against the wire it arrived in: {bob_stats:?}"
    );
    assert_eq!(bob_stats.messages_sent, 0, "bob sent nothing");

    assert_eq!(alice_stats.messages_sent, 1, "alice sent one message");
    assert_eq!(alice_stats.sent_by_protocol.didcomm, 1);
    assert_eq!(
        alice_stats.bytes_sent, bob_stats.bytes_received,
        "both sides count the same message, so the sizes agree"
    );
    assert_eq!(
        alice_stats.messages_received, 0,
        "nothing was sent to alice"
    );

    // Over the wire: the counters come back only when the request asks.
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
    assert!(
        quiet.stats.is_none(),
        "a request that didn't ask gets no counters: {quiet:?}"
    );

    let asked = env
        .atm
        .trust_tasks()
        .account_get_detailed(&bob.profile, None, false, true)
        .await
        .expect("bob reads his own account, asking for counters");
    let served = asked.stats.expect("counters were asked for");
    // Still 1, though the mediator has since stored a Trust Task answer for
    // bob: its own traffic with an account is not counted, or a console
    // polling these numbers would inflate them.
    assert_eq!(served.messages_received, Some(1));
    assert_eq!(
        served.bytes_received,
        Some(bob_stats.bytes_received),
        "the served counters are the mediator's own"
    );
    assert_eq!(
        served.received_by_protocol.as_ref().and_then(|p| p.didcomm),
        Some(1),
        "the protocol split survives the wire: {served:?}"
    );
}
