//! Cross-mediator forwarding over the in-memory backend.
//!
//! Two independent in-process mediators (A and B) on `127.0.0.1`, with
//! Alice homed on A and Bob on B. Alice sends a basic message that
//! routes Alice → mediator-A → mediator-B → Bob via the routing-2.0
//! double forward: an OUTER forward addressed to Alice's own mediator
//! wraps an INNER forward addressed to Bob's mediator, which delivers
//! locally to Bob. Each mediator only ever decrypts its own layer.
//!
//! This exercises the forwarding *processor* delivering across
//! mediators — the path PR #399 unblocked on non-Redis backends. Before
//! that change, mediator A's forwarding processor was compiled out on
//! the memory backend, so the outer forward was enqueued to `FORWARD_Q`
//! and never delivered; Bob would time out. Running this on the default
//! memory backend (no Redis) is the end-to-end regression guard for that
//! fix, and the first multi-mediator scenario built purely on the
//! published `TestMediator` / `TestEnvironment` fixtures.
//!
//! All identities are `did:peer:2.*`, so every DID involved (both
//! mediators, both users) resolves locally — no DNS or real network
//! resolution. The only real socket traffic is the loopback HTTP hop the
//! forwarding processor makes from mediator A to mediator B's `/inbound`.

mod common;

use std::time::Duration;

use affinidi_messaging_didcomm::Message;
use affinidi_messaging_test_mediator::{TestEnvironment, TestMediator, TestUser, acl};
use common::init_tracing;
use serde_json::json;
use uuid::Uuid;

/// Spawn a forwarding-enabled mediator wired to an SDK environment.
///
/// `global_acl_default = allow_all` makes this a *relay* deployment: when
/// an inner forward arrives whose sender is homed on the *other* mediator
/// (and therefore has no account here), the routing handler auto-registers
/// that sender via `relay_sender_acls(global_default)`, which only seeds
/// `SEND_FORWARDED` when the global default grants it. Without that, the
/// inbound relayed forward is rejected with 403 and never reaches the
/// recipient — so a mediator that accepts cross-mediator forwards must
/// default-grant it. (Locally-registered users like Bob are added with an
/// explicit `allow_all` ACL by `add_user`, independent of this default.)
async fn spawn_relay_environment() -> TestEnvironment {
    let mediator = TestMediator::builder()
        .enable_forwarding(true)
        .enable_external_forwarding(true)
        .global_acl_default(acl::allow_all())
        .spawn()
        .await
        .expect("spawn forwarding mediator");
    TestEnvironment::new(mediator)
        .await
        .expect("wire SDK environment to forwarding mediator")
}

/// Add a user and bring up its WebSocket live-stream connection.
///
/// Retrieval uses message-pickup `live_stream_get` (the supported
/// real-time path); over plain HTTP the SDK's delivery-request returns a
/// `RestAPI` response variant that `send_delivery_request` doesn't unwrap,
/// so the connection must be live before the forward arrives. `add_user`
/// registers the DID as LOCAL/allow_all, which is what lets the WS upgrade
/// through.
async fn add_live_user(env: &TestEnvironment, alias: &str) -> TestUser {
    let user = env.add_user(alias).await.expect("add user");
    env.atm
        .profile_enable_websocket(&user.profile)
        .await
        .expect("enable WebSocket live streaming");
    user
}

/// Drive one cross-mediator delivery: wrap `text` as the routing-2.0
/// double forward, send it to the sender's own mediator, then poll the
/// recipient's mediator until the decrypted message arrives.
///
/// Returns the recipient's view of the `content` body field, or `None`
/// if nothing arrived within the timeout.
#[allow(clippy::too_many_arguments)]
async fn forward_and_receive(
    sender_env: &TestEnvironment,
    sender: &TestUser,
    sender_mediator_did: &str,
    recipient_env: &TestEnvironment,
    recipient: &TestUser,
    recipient_mediator_did: &str,
    text: &str,
) -> Option<String> {
    let now = unix_secs();

    // 1. Plaintext basic message, Alice → Bob.
    let msg = Message::build(
        Uuid::new_v4().to_string(),
        "https://didcomm.org/basicmessage/2.0/message".to_string(),
        json!({ "content": text }),
    )
    .to(recipient.did.clone())
    .from(sender.did.clone())
    .created_time(now)
    .expires_time(now + 60)
    .finalize();
    let msg_id = msg.id.clone();

    // 2. Authcrypt (encrypt + sign) for the recipient.
    let (packed, _) = sender_env
        .atm
        .pack_encrypted(&msg, &recipient.did, Some(&sender.did), Some(&sender.did))
        .await
        .expect("authcrypt for recipient");

    // 3. INNER forward: encrypted for the recipient's mediator, next = recipient.
    let (_inner_id, inner_fwd) = sender_env
        .atm
        .routing()
        .forward_message(
            &sender.profile,
            false,
            &packed,
            recipient_mediator_did,
            &recipient.did,
            None,
            None,
        )
        .await
        .expect("wrap inner forward");

    // 4. OUTER forward: encrypted for the sender's own mediator, next =
    //    recipient's mediator (so the sender's mediator relays the inner
    //    forward over the wire to the recipient's mediator).
    let (_outer_id, outer_fwd) = sender_env
        .atm
        .routing()
        .forward_message(
            &sender.profile,
            false,
            &inner_fwd,
            sender_mediator_did,
            recipient_mediator_did,
            None,
            None,
        )
        .await
        .expect("wrap outer forward");

    // 5. Send the outer forward to the sender's own mediator. From here the
    //    forwarding processor (running on the memory backend thanks to #399)
    //    relays the inner forward to the recipient's mediator's /inbound,
    //    which stores it for the recipient and live-delivers it.
    sender_env
        .atm
        .send_message(&sender.profile, &outer_fwd, &msg_id, false, false)
        .await
        .expect("send outer forward to own mediator");

    // 6. Receive on the recipient's live stream. The unwrapped message id is
    //    the original basic-message id (the mediator stores the innermost
    //    authcrypt addressed to the recipient), so we wait on `msg_id`.
    match recipient_env
        .atm
        .message_pickup()
        .live_stream_get(&recipient.profile, &msg_id, Duration::from_secs(15), true)
        .await
    {
        Ok(Some((received, _meta))) => received
            .body
            .get("content")
            .and_then(|c| c.as_str())
            .map(str::to_string),
        _ => None,
    }
}

/// Alice on mediator A sends to Bob on mediator B; the message must arrive
/// having traversed both mediators. This is the core regression for #399.
#[tokio::test]
async fn cross_mediator_forward_delivers_over_memory_backend() {
    init_tracing();

    let env_a = spawn_relay_environment().await;
    let env_b = spawn_relay_environment().await;

    let mediator_a_did = env_a.mediator.did().to_string();
    let mediator_b_did = env_b.mediator.did().to_string();
    assert_ne!(
        mediator_a_did, mediator_b_did,
        "the two mediators must have distinct DIDs for a real cross-mediator hop"
    );

    let alice = add_live_user(&env_a, "Alice").await;
    let bob = add_live_user(&env_b, "Bob").await;

    let text = "Hello Bob — routed across two mediators.";
    let received = forward_and_receive(
        &env_a,
        &alice,
        &mediator_a_did,
        &env_b,
        &bob,
        &mediator_b_did,
        text,
    )
    .await;

    assert_eq!(
        received.as_deref(),
        Some(text),
        "Bob should receive Alice's message after it routes A → B"
    );

    env_a.shutdown().await.expect("shutdown mediator A");
    env_b.shutdown().await.expect("shutdown mediator B");
}

/// Both directions over the two mediators: Alice → Bob, then Bob → Alice.
/// Exercises the relay-sender auto-registration on *both* mediators (each
/// sees the other's user as an account-less forward sender).
#[tokio::test]
async fn cross_mediator_forward_round_trips() {
    init_tracing();

    let env_a = spawn_relay_environment().await;
    let env_b = spawn_relay_environment().await;

    let mediator_a_did = env_a.mediator.did().to_string();
    let mediator_b_did = env_b.mediator.did().to_string();

    let alice = add_live_user(&env_a, "Alice").await;
    let bob = add_live_user(&env_b, "Bob").await;

    let to_bob = "Ping from Alice.";
    let got_by_bob = forward_and_receive(
        &env_a,
        &alice,
        &mediator_a_did,
        &env_b,
        &bob,
        &mediator_b_did,
        to_bob,
    )
    .await;
    assert_eq!(
        got_by_bob.as_deref(),
        Some(to_bob),
        "Bob should receive Alice's ping (A → B)"
    );

    let to_alice = "Pong from Bob.";
    let got_by_alice = forward_and_receive(
        &env_b,
        &bob,
        &mediator_b_did,
        &env_a,
        &alice,
        &mediator_a_did,
        to_alice,
    )
    .await;
    assert_eq!(
        got_by_alice.as_deref(),
        Some(to_alice),
        "Alice should receive Bob's pong (B → A)"
    );

    env_a.shutdown().await.expect("shutdown mediator A");
    env_b.shutdown().await.expect("shutdown mediator B");
}

fn unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
