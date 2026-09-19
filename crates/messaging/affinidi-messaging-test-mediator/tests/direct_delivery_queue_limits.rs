//! Queue-depth gates on the **direct delivery** path.
//!
//! The three gates — per-relationship, sender total, recipient total — lived in
//! `protocols::routing` and so ran only for a `forward`. A client sending an
//! already-packed envelope to a local DID reached the store with no depth limit
//! of any kind, which meant the per-relationship gate added for VTI-29 did not
//! protect this path at all: one sender could fill any inbox without bound.
//!
//! A unit test on the gate function would not have caught that, because the
//! function was correct — it was simply never called here. So these tests drive
//! the real protocol end to end and assert on the recipient's mailbox as well
//! as on the send result, which is what distinguishes "the mediator refused"
//! from "the mediator refused *and* stored nothing".

mod common;

use std::time::{SystemTime, UNIX_EPOCH};

use affinidi_messaging_didcomm::Message;
use affinidi_messaging_sdk::messages::{FetchDeletePolicy, fetch::FetchOptions};
use affinidi_messaging_test_mediator::{TestEnvironment, TestMediator, TestUser};
use common::init_tracing;
use serde_json::json;
use uuid::Uuid;

/// The per-relationship cap these tests run against. Small enough to reach in a
/// handful of real sends; the production default is 50.
const PER_PEER: i32 = 4;

/// How many messages actually fit under a cap of [`PER_PEER`].
///
/// `queue_at_capacity` refuses when `queued + incoming >= limit`, so a limit of
/// L admits L-1 — the incoming message is counted against the cap it is being
/// checked against. That is the mediator's existing convention (the forward
/// path has always worked this way) and is deliberately not changed here;
/// naming it is how these tests avoid encoding an off-by-one as an
/// expectation.
const FITS: i32 = PER_PEER - 1;

fn unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before the epoch")
        .as_secs()
}

/// How many messages are sitting in `user`'s mailbox.
async fn inbox_len(env: &TestEnvironment, user: &TestUser) -> usize {
    env.atm
        .fetch_messages(&user.profile, &FetchOptions::default())
        .await
        .expect("fetch mailbox")
        .success
        .len()
}

/// Collect `user`'s mailbox, **deleting** as it reads.
///
/// `FetchOptions::default()` is `DoNotDelete`, so [`inbox_len`] peeks without
/// draining — deletion is what decrements the per-relationship count, so a
/// test about the count recovering has to ask for it explicitly.
async fn collect_inbox(env: &TestEnvironment, user: &TestUser) -> usize {
    env.atm
        .fetch_messages(
            &user.profile,
            &FetchOptions {
                delete_policy: FetchDeletePolicy::OnReceive,
                ..Default::default()
            },
        )
        .await
        .expect("collect mailbox")
        .success
        .len()
}

/// Direct delivery is off in the stock fixture, so enable it — otherwise every
/// send here is refused before any queue gate is consulted and the tests would
/// pass for the wrong reason.
async fn spawn_env(per_peer: i32) -> TestEnvironment {
    let mediator = TestMediator::builder()
        .local_direct_delivery(true, false)
        .queue_send_limit_per_peer(per_peer)
        .spawn()
        .await
        .expect("spawn mediator with direct delivery and a small per-peer cap");
    TestEnvironment::new(mediator)
        .await
        .expect("wire the SDK to the mediator")
}

/// Pack a message and hand it to the mediator **unwrapped**, so it resolves
/// `to` as a local DID and takes the direct-delivery path.
async fn send_direct(
    env: &TestEnvironment,
    sender: &TestUser,
    recipient: &TestUser,
) -> Result<(), String> {
    let now = unix_secs();
    let msg = Message::build(
        Uuid::new_v4().to_string(),
        "https://didcomm.org/basicmessage/2.0/message".to_string(),
        json!({ "content": "queue depth probe" }),
    )
    .to(recipient.did.clone())
    .from(sender.did.clone())
    .created_time(now)
    .expires_time(now + 60)
    .finalize();
    let msg_id = msg.id.clone();

    let (packed, _) = env
        .atm
        .pack_encrypted(&msg, &recipient.did, Some(&sender.did), Some(&sender.did))
        .await
        .map_err(|e| format!("pack_encrypted failed: {e}"))?;

    env.atm
        .send_message(&sender.profile, &packed, &msg_id, false, false)
        .await
        .map(|_| ())
        .map_err(|e| e.to_string())
}

/// The regression: a direct sender is stopped at the per-relationship cap.
///
/// Before the gates reached this path every one of these sends succeeded, and
/// the only thing bounding the recipient's inbox was the expiry sweeper.
#[tokio::test]
async fn direct_delivery_is_refused_at_the_per_peer_cap() {
    init_tracing();
    let env = spawn_env(PER_PEER).await;
    let alice = env.add_user("alice").await.expect("add alice");
    let bob = env.add_user("bob").await.expect("add bob");

    for i in 0..FITS {
        send_direct(&env, &alice, &bob)
            .await
            .unwrap_or_else(|e| panic!("send {i} is under the cap and must succeed: {e}"));
    }

    let err = send_direct(&env, &alice, &bob)
        .await
        .expect_err("the send at the cap must be refused");
    assert!(
        err.contains("limits.queue.peer"),
        "refusal should name the per-relationship gate, got: {err}"
    );

    assert_eq!(
        inbox_len(&env, &bob).await,
        FITS as usize,
        "the refused message must not have been stored"
    );
}

/// The cap is per *relationship*, not per sender: a second recipient is
/// unaffected by alice having filled bob's.
///
/// This is the fan-out case VTI-29 was about, now checked on the direct path
/// rather than only on forwards.
#[tokio::test]
async fn a_full_relationship_does_not_block_a_different_recipient() {
    init_tracing();
    let env = spawn_env(PER_PEER).await;
    let alice = env.add_user("alice").await.expect("add alice");
    let bob = env.add_user("bob").await.expect("add bob");
    let carol = env.add_user("carol").await.expect("add carol");

    for _ in 0..FITS {
        send_direct(&env, &alice, &bob).await.expect("fill bob");
    }
    send_direct(&env, &alice, &bob)
        .await
        .expect_err("bob's relationship is at the cap");

    // Same sender, different relationship — must still be accepted.
    send_direct(&env, &alice, &carol)
        .await
        .expect("carol's relationship is empty and must accept");
    assert_eq!(inbox_len(&env, &carol).await, 1);
}

/// Collecting frees the relationship again: the count tracks what is *queued*,
/// not what has ever been sent.
#[tokio::test]
async fn collecting_reopens_a_capped_relationship() {
    init_tracing();
    let env = spawn_env(PER_PEER).await;
    let alice = env.add_user("alice").await.expect("add alice");
    let bob = env.add_user("bob").await.expect("add bob");

    for _ in 0..FITS {
        send_direct(&env, &alice, &bob).await.expect("fill bob");
    }
    send_direct(&env, &alice, &bob)
        .await
        .expect_err("at the cap");

    // Bob collects, which is what decrements the per-relationship count.
    assert_eq!(collect_inbox(&env, &bob).await, FITS as usize);

    send_direct(&env, &alice, &bob)
        .await
        .expect("the relationship has room again once bob has collected");
}

/// `-1` disables the gate, and disabling it must not disable the *other* two.
/// This pins the escape hatch so raising the cap cannot silently turn the
/// direct path back into an ungated one.
#[tokio::test]
async fn the_per_peer_gate_can_be_disabled() {
    init_tracing();
    let env = spawn_env(-1).await;
    let alice = env.add_user("alice").await.expect("add alice");
    let bob = env.add_user("bob").await.expect("add bob");

    for i in 0..(PER_PEER + 2) {
        send_direct(&env, &alice, &bob)
            .await
            .unwrap_or_else(|e| panic!("send {i} must succeed with the gate disabled: {e}"));
    }
    assert_eq!(inbox_len(&env, &bob).await, (PER_PEER + 2) as usize);
}
