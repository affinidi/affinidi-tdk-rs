//! A recipient that cannot unpack what it is sent must still collect it.
//!
//! The mediator keeps a message until its recipient deletes it, and counts it
//! against the **sender's** per-recipient queue (`limits.queue.peer`) until
//! then. The live websocket stream used to log a frame it could not unpack and
//! leave it in the inbox, so every such frame stayed in the sender's quota for
//! its whole lifetime. A sender whose frames this recipient could not read was
//! therefore cut off from it entirely once the quota filled — refused
//! `limits.queue.peer` although the recipient was connected and "receiving".
//! Seen in production as OpenVTC admin sessions holding 49 VTA replies each,
//! with every further reply refused.
//!
//! The live stream now deletes a frame whose failure is a property of its
//! bytes, so a connected recipient keeps its senders' queues empty whatever
//! they send it.

mod common;

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use affinidi_messaging_didcomm::Message;
use affinidi_messaging_sdk::messages::fetch::FetchOptions;
use affinidi_messaging_test_mediator::{TestEnvironment, TestMediator, TestUser};
use common::init_tracing;
use serde_json::json;
use uuid::Uuid;

/// Small enough to reach in a few sends: a limit of 4 admits 3.
const PER_PEER: i32 = 4;

/// Comfortably more than the cap admits.
const SENDS: usize = 12;

fn unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before the epoch")
        .as_secs()
}

async fn inbox_len(env: &TestEnvironment, user: &TestUser) -> usize {
    env.atm
        .fetch_messages(&user.profile, &FetchOptions::default())
        .await
        .expect("fetch mailbox")
        .success
        .len()
}

/// Authcrypt a message from `sender` to `recipient`, then corrupt its
/// ciphertext: the mediator routes it on the (intact) recipient header, and the
/// recipient can never decrypt it.
async fn undecryptable_frame(
    env: &TestEnvironment,
    sender: &TestUser,
    recipient: &TestUser,
) -> String {
    let now = unix_secs();
    let msg = Message::build(
        Uuid::new_v4().to_string(),
        "https://didcomm.org/basicmessage/2.0/message".to_string(),
        json!({ "content": "you will never read this" }),
    )
    .to(recipient.did.clone())
    .from(sender.did.clone())
    .created_time(now)
    .expires_time(now + 300)
    .finalize();
    let (packed, _) = env
        .atm
        .pack_encrypted(&msg, &recipient.did, Some(&sender.did), Some(&sender.did))
        .await
        .expect("pack");
    let mut jwe: serde_json::Value = serde_json::from_str(&packed).expect("JWE json");
    let ciphertext = jwe["ciphertext"].as_str().expect("ciphertext").to_string();
    // Flip the first character to another valid base64url one.
    let first = ciphertext.chars().next().expect("non-empty");
    let flipped = if first == 'A' { 'B' } else { 'A' };
    jwe["ciphertext"] = json!(format!("{flipped}{}", &ciphertext[1..]));
    jwe.to_string()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_connected_recipient_deletes_frames_it_cannot_unpack() {
    init_tracing();
    let mediator = TestMediator::builder()
        .local_direct_delivery(true, false)
        .queue_send_limit_per_peer(PER_PEER)
        .spawn()
        .await
        .expect("spawn mediator");
    let env = TestEnvironment::new(mediator).await.expect("env");
    let alice = env.add_user("alice").await.expect("add alice");
    let bob = env.add_user("bob").await.expect("add bob");
    env.atm
        .profile_enable_websocket(&bob.profile)
        .await
        .expect("bob is live");
    let health = bob
        .profile
        .receive_health()
        .await
        .expect("a live websocket publishes receive health");

    for i in 0..SENDS {
        let frame = undecryptable_frame(&env, &alice, &bob).await;
        env.atm
            .send_message(
                &alice.profile,
                &frame,
                &Uuid::new_v4().to_string(),
                false,
                false,
            )
            .await
            .unwrap_or_else(|e| {
                panic!(
                    "send {i} refused — bob is connected but the frames he cannot unpack are \
                     still counting against alice's queue: {e}"
                )
            });
        // Let bob's transport receive the frame and its deletion land, so the
        // next send is judged against an emptied queue.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while inbox_len(&env, &bob).await > 0 && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    assert_eq!(
        inbox_len(&env, &bob).await,
        0,
        "nothing left in bob's inbox"
    );
    assert!(
        health.borrow().unprocessable_deleted >= SENDS as u64,
        "every frame was deleted by the live stream, got {:?}",
        *health.borrow()
    );

    env.shutdown().await.expect("shutdown");
}
