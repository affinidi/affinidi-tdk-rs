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
use affinidi_messaging_test_mediator::{
    MediatorACLSet, RelayMode, TestEnvironment, TestMediator, TestUser, acl,
};
use common::{await_monitor_event, init_tracing};
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

/// Spawn a forwarding mediator running in `RelayMode::Rewrap`, with an
/// optional trusted-peer allowlist.
///
/// In rewrap mode each mediator re-encrypts the inner forward from itself
/// to the next hop (hiding the original sender on the mediator↔mediator
/// wire) and the receiver authenticates the relaying peer. `trusted_peers`
/// is the receiver-side allowlist: empty accepts any relaying peer,
/// non-empty admits only the listed mediator DIDs (an unlisted peer's
/// relay is rejected with `authorization.relay.untrusted_peer`).
///
/// Otherwise identical to [`spawn_relay_environment`] — same relay
/// deployment ACLs, so the cross-mediator sender is still auto-registered
/// with `SEND_FORWARDED` once its layer is peeled.
async fn spawn_rewrap_environment(trusted_peers: &[String]) -> TestEnvironment {
    let mediator = TestMediator::builder()
        .enable_forwarding(true)
        .enable_external_forwarding(true)
        .global_acl_default(acl::allow_all())
        .relay_mode(RelayMode::Rewrap)
        .relay_trusted_mediators(trusted_peers.iter().cloned())
        .spawn()
        .await
        .expect("spawn rewrap forwarding mediator");
    TestEnvironment::new(mediator)
        .await
        .expect("wire SDK environment to rewrap mediator")
}

/// Spawn a mediator that is explicitly NOT a relay: its global default ACL
/// does not grant `SEND_FORWARDED` and `enable_inter_mediator_relay` is off,
/// so it must refuse the anonymous inter-mediator `/inbound` hop. Locally
/// registered users (added via `add_user` with an explicit allow-all ACL) can
/// still authenticate and receive their own direct messages.
async fn spawn_non_relay_environment() -> TestEnvironment {
    let mediator = TestMediator::builder()
        .enable_forwarding(true)
        .enable_external_forwarding(true)
        .global_acl_default(acl::deny_all())
        .enable_inter_mediator_relay(false)
        .spawn()
        .await
        .expect("spawn non-relay mediator");
    TestEnvironment::new(mediator)
        .await
        .expect("wire SDK environment to non-relay mediator")
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
/// double forward, send it to the sender's own mediator, then wait up to
/// `wait` for the recipient's live stream to surface the decrypted message.
///
/// Returns the recipient's view of the `content` body field, or `None`
/// if nothing arrived within `wait` (used by the negative trust test,
/// which expects no delivery, with a shorter `wait`).
#[allow(clippy::too_many_arguments)]
async fn forward_and_receive(
    sender_env: &TestEnvironment,
    sender: &TestUser,
    sender_mediator_did: &str,
    recipient_env: &TestEnvironment,
    recipient: &TestUser,
    recipient_mediator_did: &str,
    text: &str,
    wait: Duration,
) -> Option<String> {
    let msg_id = send_double_forward(
        sender_env,
        sender,
        sender_mediator_did,
        recipient,
        recipient_mediator_did,
        text,
    )
    .await;

    // 6. Receive on the recipient's live stream. The unwrapped message id is
    //    the original basic-message id (the mediator stores the innermost
    //    authcrypt addressed to the recipient), so we wait on `msg_id`.
    match recipient_env
        .atm
        .message_pickup()
        .live_stream_get(&recipient.profile, &msg_id, wait, true)
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

/// Steps 1–5 of [`forward_and_receive`]: wrap `text` as the routing-2.0
/// double forward and hand it to the sender's own mediator. Returns the
/// basic message's id.
async fn send_double_forward(
    sender_env: &TestEnvironment,
    sender: &TestUser,
    sender_mediator_did: &str,
    recipient: &TestUser,
    recipient_mediator_did: &str,
    text: &str,
) -> String {
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
    msg_id
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
        Duration::from_secs(15),
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

/// Negative counterpart of the above + the end-to-end half of T12: a mediator
/// that is NOT configured as a relay must drop the anonymous inter-mediator
/// hop, so a cross-mediator forward never reaches the recipient. (The flag's
/// gate logic in isolation is unit-tested in `jwt_auth`; here we confirm the
/// observable end-to-end behaviour with relay off.)
#[tokio::test]
async fn non_relay_mediator_rejects_cross_mediator_forward() {
    init_tracing();

    let env_a = spawn_relay_environment().await;
    let env_b = spawn_non_relay_environment().await;

    let mediator_a_did = env_a.mediator.did().to_string();
    let mediator_b_did = env_b.mediator.did().to_string();
    assert_ne!(mediator_a_did, mediator_b_did);

    let alice = add_live_user(&env_a, "Alice").await;
    let bob = add_live_user(&env_b, "Bob").await;

    let received = forward_and_receive(
        &env_a,
        &alice,
        &mediator_a_did,
        &env_b,
        &bob,
        &mediator_b_did,
        "This must not arrive — mediator B is not a relay.",
        Duration::from_secs(4),
    )
    .await;

    assert_eq!(
        received, None,
        "a non-relay mediator must drop the anonymous cross-mediator hop"
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
        Duration::from_secs(15),
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
        Duration::from_secs(15),
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

// ─── RelayMode::Rewrap (per-hop re-encryption) ──────────────────────────────
//
// Same Alice → A → B → Bob double-forward construction as the blind tests
// above — only the mediators' relay posture changes. In rewrap mode each
// mediator re-encrypts the inner forward from itself to the next hop, so the
// A → B wire envelope is authcrypted `from = mediator A` (not the original
// sender) and B authenticates A before peeling. These exercise the full
// rewrap plumbing end-to-end (routing rewrap → FORWARD_Q → processor → HTTP
// → inbound peel pre-pass) on the memory backend; the on-wire crypto
// properties themselves are covered by the mediator crate's
// `tests/relay_rewrap.rs`.

/// Rewrap relay round-trips end to end (empty allowlist = accept any peer).
#[tokio::test]
async fn rewrap_relay_round_trips_end_to_end() {
    init_tracing();

    let env_a = spawn_rewrap_environment(&[]).await;
    let env_b = spawn_rewrap_environment(&[]).await;

    let mediator_a_did = env_a.mediator.did().to_string();
    let mediator_b_did = env_b.mediator.did().to_string();

    let alice = add_live_user(&env_a, "Alice").await;
    let bob = add_live_user(&env_b, "Bob").await;

    let to_bob = "Rewrapped ping from Alice.";
    let got_by_bob = forward_and_receive(
        &env_a,
        &alice,
        &mediator_a_did,
        &env_b,
        &bob,
        &mediator_b_did,
        to_bob,
        Duration::from_secs(15),
    )
    .await;
    assert_eq!(
        got_by_bob.as_deref(),
        Some(to_bob),
        "Bob should receive Alice's message relayed in rewrap mode (A → B)"
    );

    let to_alice = "Rewrapped pong from Bob.";
    let got_by_alice = forward_and_receive(
        &env_b,
        &bob,
        &mediator_b_did,
        &env_a,
        &alice,
        &mediator_a_did,
        to_alice,
        Duration::from_secs(15),
    )
    .await;
    assert_eq!(
        got_by_alice.as_deref(),
        Some(to_alice),
        "Alice should receive Bob's rewrapped reply (B → A)"
    );

    env_a.shutdown().await.expect("shutdown mediator A");
    env_b.shutdown().await.expect("shutdown mediator B");
}

/// A populated allowlist that names the relaying peer admits the relay —
/// the item-3 trust gate's positive case.
#[tokio::test]
async fn rewrap_relay_admits_trusted_peer() {
    init_tracing();

    // Spawn A first so its DID can be placed on B's trusted-peer allowlist.
    let env_a = spawn_rewrap_environment(&[]).await;
    let mediator_a_did = env_a.mediator.did().to_string();

    let env_b = spawn_rewrap_environment(std::slice::from_ref(&mediator_a_did)).await;
    let mediator_b_did = env_b.mediator.did().to_string();

    let alice = add_live_user(&env_a, "Alice").await;
    let bob = add_live_user(&env_b, "Bob").await;

    let text = "Hello from a trusted relay.";
    let received = forward_and_receive(
        &env_a,
        &alice,
        &mediator_a_did,
        &env_b,
        &bob,
        &mediator_b_did,
        text,
        Duration::from_secs(15),
    )
    .await;
    assert_eq!(
        received.as_deref(),
        Some(text),
        "Bob should receive the relay because mediator A is on B's trusted-peer allowlist"
    );

    env_a.shutdown().await.expect("shutdown mediator A");
    env_b.shutdown().await.expect("shutdown mediator B");
}

/// A populated allowlist that does NOT name the relaying peer rejects the
/// relay (`authorization.relay.untrusted_peer`), so nothing reaches Bob —
/// the item-3 trust gate's negative case.
#[tokio::test]
async fn rewrap_relay_rejects_untrusted_peer() {
    init_tracing();

    let env_a = spawn_rewrap_environment(&[]).await;
    let mediator_a_did = env_a.mediator.did().to_string();

    // B trusts only some *other* mediator — never A — so A's re-wrapped
    // relay must be rejected at B's inbound peel pre-pass.
    let stranger = "did:peer:2.NotTheRelayingMediator".to_string();
    let env_b = spawn_rewrap_environment(std::slice::from_ref(&stranger)).await;
    let mediator_b_did = env_b.mediator.did().to_string();

    let alice = add_live_user(&env_a, "Alice").await;
    let bob = add_live_user(&env_b, "Bob").await;

    let received = forward_and_receive(
        &env_a,
        &alice,
        &mediator_a_did,
        &env_b,
        &bob,
        &mediator_b_did,
        "This relay should be dropped.",
        // Short wait: delivery is sub-second on success, so a few seconds of
        // silence is conclusive that the untrusted relay was rejected.
        Duration::from_secs(5),
    )
    .await;
    assert_eq!(
        received, None,
        "Bob must NOT receive a relay from a mediator absent from his trusted-peer allowlist"
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

// ─── Blind relay into DIRECT DELIVERY ───────────────────────────────────────
//
// Every test above builds the routing-2.0 *double* forward, so the envelope
// mediator B receives is itself a `forward` addressed to B — B unpacks it and
// takes inbound.rs's `to_did == mediator_did` branch, where the session/sender
// match has always been skipped for unauthenticated sessions. That is why they
// pass on both sides of this fix and never caught the defect.
//
// A client that sends a *single* forward (`next` = the remote recipient, not
// the remote mediator) is the shape production actually uses, and it lands on
// the other branch: in `RelayMode::Blind` mediator A relays the inner envelope
// verbatim, so what arrives at B is addressed to Bob, not to B — a direct
// delivery, on the anonymous `ANON-INBOUND` relay session. Before the guard was
// added there, B answered every such hop with HTTP 400
// `e.p.authorization.did.session_mismatch`.

/// Blind relay mediator that also accepts direct delivery.
///
/// A relayed inner envelope addressed to a local account *is* a direct
/// delivery as far as the receiving mediator is concerned, so a mediator that
/// terminates single-forward relays has to have the path enabled; the fixture
/// ships it off. Anonymous direct delivery stays off — the relayed envelope
/// carries an authcrypt sender, so this test must not depend on the
/// `allow_anon` escape hatch.
async fn spawn_direct_delivery_relay_environment() -> TestEnvironment {
    let mediator = TestMediator::builder()
        .enable_forwarding(true)
        .enable_external_forwarding(true)
        .global_acl_default(acl::allow_all())
        .local_direct_delivery(true, false)
        .spawn()
        .await
        .expect("spawn blind relay mediator with direct delivery enabled");
    TestEnvironment::new(mediator)
        .await
        .expect("wire SDK environment to direct-delivery relay mediator")
}

/// Drive one cross-mediator delivery using a SINGLE forward: Alice wraps the
/// authcrypt for Bob in one `forward` addressed to her own mediator with
/// `next = Bob`. Mediator A resolves Bob's DID document, finds it mediated by
/// B, and relays the inner envelope there.
async fn single_forward_and_receive(
    sender_env: &TestEnvironment,
    sender: &TestUser,
    sender_mediator_did: &str,
    recipient_env: &TestEnvironment,
    recipient: &TestUser,
    text: &str,
    wait: Duration,
) -> Option<String> {
    let now = unix_secs();

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

    let (packed, _) = sender_env
        .atm
        .pack_encrypted(&msg, &recipient.did, Some(&sender.did), Some(&sender.did))
        .await
        .expect("authcrypt for recipient");

    // The single forward: addressed to Alice's own mediator, `next` = Bob
    // himself. There is no second forward layer for mediator B to unwrap, so
    // the envelope B receives is the authcrypt addressed to Bob.
    let (_fwd_id, forward) = sender_env
        .atm
        .routing()
        .forward_message(
            &sender.profile,
            false,
            &packed,
            sender_mediator_did,
            &recipient.did,
            None,
            None,
        )
        .await
        .expect("wrap single forward");

    sender_env
        .atm
        .send_message(&sender.profile, &forward, &msg_id, false, false)
        .await
        .expect("send forward to own mediator");

    match recipient_env
        .atm
        .message_pickup()
        .live_stream_get(&recipient.profile, &msg_id, wait, true)
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

/// Rewrap relay of a single forward under an open default, with no recipient
/// ACL in play: the relay layer must be encrypted to the peer mediator Bob's
/// DID document names, not to Bob, or B cannot peel it. Isolates the
/// `relay_to` change from the access-list change.
#[tokio::test]
async fn rewrap_single_forward_encrypts_the_relay_layer_to_the_peer_mediator() {
    init_tracing();

    let spawn = || async {
        let mediator = TestMediator::builder()
            .enable_forwarding(true)
            .enable_external_forwarding(true)
            .global_acl_default(acl::allow_all())
            .local_direct_delivery(true, false)
            .relay_mode(RelayMode::Rewrap)
            .spawn()
            .await
            .expect("spawn rewrap mediator with direct delivery");
        TestEnvironment::new(mediator).await.expect("environment")
    };
    let env_a = spawn().await;
    let env_b = spawn().await;
    let mediator_a_did = env_a.mediator.did().to_string();

    let alice = add_live_user(&env_a, "Alice").await;
    let bob = add_live_user(&env_b, "Bob").await;

    let text = "Single forward, rewrapped to mediator B.";
    let received = single_forward_and_receive(
        &env_a,
        &alice,
        &mediator_a_did,
        &env_b,
        &bob,
        text,
        Duration::from_secs(15),
    )
    .await;
    assert_eq!(received.as_deref(), Some(text));

    env_a.shutdown().await.expect("shutdown mediator A");
    env_b.shutdown().await.expect("shutdown mediator B");
}

/// The regression for the production `session_mismatch` refusal: a blind relay
/// whose inner envelope is addressed to a local account must be delivered, not
/// refused for failing to match the anonymous relay session's (empty) DID.
#[tokio::test]
async fn blind_relay_direct_delivery_reaches_recipient() {
    init_tracing();

    let env_a = spawn_direct_delivery_relay_environment().await;
    let env_b = spawn_direct_delivery_relay_environment().await;

    let mediator_a_did = env_a.mediator.did().to_string();
    assert_ne!(
        mediator_a_did,
        env_b.mediator.did(),
        "the two mediators must have distinct DIDs for a real cross-mediator hop"
    );

    let alice = add_live_user(&env_a, "Alice").await;
    let bob = add_live_user(&env_b, "Bob").await;

    let text = "Single-forward hello, relayed blind and delivered directly.";
    let received = single_forward_and_receive(
        &env_a,
        &alice,
        &mediator_a_did,
        &env_b,
        &bob,
        text,
        Duration::from_secs(15),
    )
    .await;

    assert_eq!(
        received.as_deref(),
        Some(text),
        "Bob should receive Alice's single-forward message; a session_mismatch \
         refusal on mediator B's direct-delivery path shows up as no delivery"
    );

    env_a.shutdown().await.expect("shutdown mediator A");
    env_b.shutdown().await.expect("shutdown mediator B");
}

/// The guard is scoped to *unauthenticated* sessions only: an authenticated
/// client that hands its own mediator a direct delivery claiming somebody
/// else's sender DID is still refused. Without this, "relax the check for
/// anonymous relay" could silently become "stop checking".
#[tokio::test]
async fn authenticated_direct_delivery_still_enforces_session_match() {
    init_tracing();

    let env = spawn_direct_delivery_relay_environment().await;
    // Plain HTTP users: the refusal has to come back as the POST /inbound
    // response, not be swallowed by a live-stream socket.
    let alice = env.add_user("Alice").await.expect("add Alice");
    let bob = env.add_user("Bob").await.expect("add Bob");
    let mallory = env.add_user("Mallory").await.expect("add Mallory");

    let now = unix_secs();
    let msg = Message::build(
        Uuid::new_v4().to_string(),
        "https://didcomm.org/basicmessage/2.0/message".to_string(),
        json!({ "content": "Spoofed sender." }),
    )
    .to(bob.did.clone())
    .from(alice.did.clone())
    .created_time(now)
    .expires_time(now + 60)
    .finalize();
    let msg_id = msg.id.clone();

    // Authcrypted as Alice, but handed to the mediator over Mallory's
    // authenticated session — the envelope's claimed sender and the session
    // DID disagree.
    let (packed, _) = env
        .atm
        .pack_encrypted(&msg, &bob.did, Some(&alice.did), Some(&alice.did))
        .await
        .expect("authcrypt as Alice");

    let result = env
        .atm
        .send_message(&mallory.profile, &packed, &msg_id, false, false)
        .await;

    let error = result.expect_err("mediator must refuse a spoofed direct delivery");
    assert!(
        format!("{error:?}").contains("session_mismatch"),
        "expected a session_mismatch problem report, got: {error:?}"
    );

    env.shutdown().await.expect("shutdown mediator");
}

/// An administrator of mediator A, subscribed to A's traffic with mediator
/// B — the relay hop's recipient.
async fn watch_relays_to(env: &TestEnvironment, peer_mediator_did: &str) -> TestUser {
    use affinidi_messaging_mediator_common::types::accounts::AccountType;
    use trust_tasks_rs::specs::messaging::monitor::subscribe::v0_1::MonitorFilter;

    let admin = env.add_user("admin").await.expect("admin");
    env.mediator
        .store()
        .account_set_role(&admin.did_hash(), &AccountType::Admin)
        .await
        .expect("promote");
    env.atm
        .profile_add(&admin.profile, true)
        .await
        .expect("admin live");
    let filter: MonitorFilter =
        serde_json::from_value(json!({ "dids": [sha256::digest(peer_mediator_did)] })).unwrap();
    env.atm
        .trust_tasks()
        .monitor_subscribe(&admin.profile, Some(filter), Some(120), None, None)
        .await
        .expect("admin subscribes");
    admin
}

/// The monitor on the relaying mediator follows the relay: `stored` on the
/// peer-mediator channel when it is queued, `forwarded` — with the time it
/// spent queued — only once the peer has accepted it.
#[tokio::test]
async fn the_monitor_sees_a_relay_queued_then_forwarded() {
    init_tracing();
    let env_a = spawn_relay_environment().await;
    let env_b = spawn_relay_environment().await;
    let mediator_a_did = env_a.mediator.did().to_string();
    let mediator_b_did = env_b.mediator.did().to_string();
    let alice = add_live_user(&env_a, "Alice").await;
    let bob = add_live_user(&env_b, "Bob").await;
    let admin = watch_relays_to(&env_a, &mediator_b_did).await;

    send_double_forward(
        &env_a,
        &alice,
        &mediator_a_did,
        &bob,
        &mediator_b_did,
        "watched",
    )
    .await;

    // Both steps can land in one batch, so collect until the relay is done.
    let seen = std::cell::RefCell::new(Vec::new());
    await_monitor_event(
        &env_a,
        &admin,
        |e| {
            seen.borrow_mut().push(e.clone());
            e["stage"] == "forwarded"
        },
        Duration::from_secs(15),
    )
    .await
    .expect("the relay is seen accepted by the peer");
    let seen = seen.into_inner();
    let stages: Vec<&str> = seen.iter().filter_map(|e| e["stage"].as_str()).collect();
    assert_eq!(stages, ["stored", "forwarded"], "queued, then relayed");
    let (queued, forwarded) = (&seen[0], &seen[1]);

    assert_eq!(queued["channel"], "peerMediator");
    assert_eq!(
        queued["to"],
        sha256::digest(mediator_b_did.as_str()).as_str()
    );
    assert_eq!(queued["from"], alice.did_hash().as_str());
    assert_eq!(forwarded["msgId"], queued["msgId"], "one relay, one id");
    assert!(forwarded.get("outcome").is_none(), "{forwarded}");
    assert!(forwarded["latencyMs"].is_u64(), "{forwarded}");

    env_a.shutdown().await.expect("shutdown A");
    env_b.shutdown().await.expect("shutdown B");
}

/// A relay the peer never accepts is not reported `forwarded`: the failed
/// attempt is, with outcome `forwardingRetry`.
#[tokio::test]
async fn the_monitor_reports_a_failed_relay_attempt() {
    init_tracing();
    let env_a = spawn_relay_environment().await;
    let env_b = spawn_relay_environment().await;
    let mediator_a_did = env_a.mediator.did().to_string();
    let mediator_b_did = env_b.mediator.did().to_string();
    let alice = add_live_user(&env_a, "Alice").await;
    let bob = add_live_user(&env_b, "Bob").await;
    let admin = watch_relays_to(&env_a, &mediator_b_did).await;
    // B's DID still resolves (did:peer), to an endpoint nobody answers.
    env_b.shutdown().await.expect("shutdown B");

    send_double_forward(
        &env_a,
        &alice,
        &mediator_a_did,
        &bob,
        &mediator_b_did,
        "lost",
    )
    .await;

    let failed = await_monitor_event(
        &env_a,
        &admin,
        |e| e["stage"] == "forwarded",
        Duration::from_secs(20),
    )
    .await
    .expect("the failed attempt is seen");
    assert_eq!(failed["outcome"]["code"], "forwardingRetry", "{failed}");
    assert_eq!(failed["channel"], "peerMediator");

    env_a.shutdown().await.expect("shutdown A");
}

// ─── Consent-based default: closed per-DID access lists ────────────────────
//
// Every relay above runs an `ALLOW_ALL` default, so every inbox is open and
// no access list ever refuses anything. A consent-based deployment starts each
// new DID with an empty allowlist instead. The recipient's access list is
// enforced by the mediator that holds the recipient's inbox; the sender's
// mediator only relays, and the placeholder account it registers for a remote
// next hop is not the recipient's real policy.

/// A consent-based default: forwarding granted, every new inbox an empty
/// allowlist its owner may open.
fn consent_based_default() -> MediatorACLSet {
    MediatorACLSet::from_string_ruleset(
        "DENY_ALL,ALLOW_ALL_SELF_CHANGE,SEND_MESSAGES,RECEIVE_MESSAGES,SEND_FORWARDED,\
         RECEIVE_FORWARDED,CREATE_INVITES,ANON_RECEIVE,SELF_MANAGE_LIST,\
         SELF_MANAGE_SEND_QUEUE_LIMIT,SELF_MANAGE_RECEIVE_QUEUE_LIMIT,MODE_SELF_CHANGE,\
         MODE_EXPLICIT_ALLOW,LOCAL",
    )
    .expect("consent-based ruleset")
}

/// Blind relay with direct delivery, registering unknown DIDs with
/// [`consent_based_default`].
async fn spawn_consent_relay_environment() -> TestEnvironment {
    spawn_consent_environment(RelayMode::Blind).await
}

/// [`spawn_consent_relay_environment`] in the given relay mode.
async fn spawn_consent_environment(relay_mode: RelayMode) -> TestEnvironment {
    let mediator = TestMediator::builder()
        .enable_forwarding(true)
        .enable_external_forwarding(true)
        .global_acl_default(consent_based_default())
        .local_direct_delivery(true, false)
        .relay_mode(relay_mode)
        // A refusal by the peer is final, but a transport failure is retried;
        // keep the budget short so a test never waits on a long backoff.
        .forwarding_retry_policy(1, Duration::from_millis(100), Duration::from_millis(100))
        .spawn()
        .await
        .expect("spawn consent-based relay mediator");
    TestEnvironment::new(mediator)
        .await
        .expect("wire SDK environment to consent-based relay mediator")
}

/// The sender's mediator must not apply its placeholder for a remote next hop:
/// both the single forward (`next` = Bob) and the double forward (`next` =
/// mediator B) reach Bob.
#[tokio::test]
async fn consent_based_relay_reaches_remote_recipient() {
    relay_reaches_remote_recipient(RelayMode::Blind).await;
}

/// The same in `rewrap` mode: the single forward's relay layer is encrypted to
/// mediator B (Bob's mediator), not to Bob.
#[tokio::test]
async fn rewrap_relay_reaches_remote_recipient() {
    relay_reaches_remote_recipient(RelayMode::Rewrap).await;
}

async fn relay_reaches_remote_recipient(relay_mode: RelayMode) {
    init_tracing();

    let env_a = spawn_consent_environment(relay_mode).await;
    let env_b = spawn_consent_environment(relay_mode).await;
    let mediator_a_did = env_a.mediator.did().to_string();
    let mediator_b_did = env_b.mediator.did().to_string();

    let alice = add_live_user(&env_a, "Alice").await;
    let bob = add_live_user(&env_b, "Bob").await;

    let text = "Single forward through a consent-based relay.";
    let received = single_forward_and_receive(
        &env_a,
        &alice,
        &mediator_a_did,
        &env_b,
        &bob,
        text,
        Duration::from_secs(15),
    )
    .await;
    assert_eq!(received.as_deref(), Some(text), "single forward next = Bob");

    let text = "Double forward through a consent-based relay.";
    let received = forward_and_receive(
        &env_a,
        &alice,
        &mediator_a_did,
        &env_b,
        &bob,
        &mediator_b_did,
        text,
        Duration::from_secs(15),
    )
    .await;
    assert_eq!(received.as_deref(), Some(text), "double forward next = B");

    // A relayed both without registering an account for either remote hop.
    for (hop, did) in [("Bob", &bob.did), ("mediator B", &mediator_b_did)] {
        let account = env_a
            .mediator
            .store()
            .account_get(&sha256::digest(did.as_str()))
            .await
            .expect("account lookup");
        assert!(account.is_none(), "A registered a placeholder for {hop}");
    }

    env_a.shutdown().await.expect("shutdown mediator A");
    env_b.shutdown().await.expect("shutdown mediator B");
}

/// Bob's own mediator still enforces Bob's allowlist: A accepts the forward
/// and relays it, B refuses it. Once Bob admits Alice, a new message is
/// delivered.
#[tokio::test]
async fn consent_based_relay_honours_recipients_access_list() {
    recipients_access_list_is_enforced_by_their_mediator(RelayMode::Blind).await;
}

/// The same in `rewrap` mode, where B sees mediator A as the authenticated
/// sender of the outer layer. B peels that layer before any recipient check,
/// so Bob's list is checked against Alice: admitting Alice (not A) is what
/// lets the message in.
#[tokio::test]
async fn rewrap_relay_honours_recipients_access_list() {
    recipients_access_list_is_enforced_by_their_mediator(RelayMode::Rewrap).await;
}

async fn recipients_access_list_is_enforced_by_their_mediator(relay_mode: RelayMode) {
    init_tracing();

    let env_a = spawn_consent_environment(relay_mode).await;
    let env_b = spawn_consent_environment(relay_mode).await;
    let mediator_a_did = env_a.mediator.did().to_string();

    let alice = add_live_user(&env_a, "Alice").await;
    let bob = add_live_user(&env_b, "Bob").await;
    env_b
        .mediator
        .set_acl(&bob.did, consent_based_default())
        .await
        .expect("close Bob's inbox");
    // Single forward: the relay hop's recipient is Bob himself.
    let admin = watch_relays_to(&env_a, &bob.did).await;

    // Alice sends over WebSocket, so a refusal by A would not fail this call.
    // That A accepted and relayed the forward is shown by the monitor events
    // below.
    let received = single_forward_and_receive(
        &env_a,
        &alice,
        &mediator_a_did,
        &env_b,
        &bob,
        "This must not arrive — Bob has not admitted Alice.",
        Duration::from_secs(1),
    )
    .await;
    assert_eq!(received, None, "B must refuse a sender off Bob's allowlist");

    // A did relay it and B refused it. A drops it at once rather than retrying
    // (a refusal that was retried could turn into a delivery if Bob admitted
    // Alice meanwhile), so the monitor shows the refusal and no retry.
    let seen = std::cell::RefCell::new(Vec::new());
    await_monitor_event(
        &env_a,
        &admin,
        |e| {
            seen.borrow_mut().push(e.clone());
            e["stage"] == "forwarded" && e["outcome"]["code"] == "e.p.me.res.forwarding.refused"
        },
        Duration::from_secs(15),
    )
    .await
    .expect("A drops the relay B refuses, with the refused outcome");
    let codes: Vec<String> = seen
        .borrow()
        .iter()
        .filter_map(|e| e["outcome"]["code"].as_str().map(str::to_string))
        .collect();
    assert!(
        !codes.iter().any(|c| c == "forwardingRetry"),
        "a refusal must not be retried: {codes:?}"
    );

    env_b
        .mediator
        .store()
        .access_list_add(100, &bob.did_hash(), &[alice.did_hash()])
        .await
        .expect("Bob admits Alice");

    let text = "Admitted, so delivered.";
    let received = single_forward_and_receive(
        &env_a,
        &alice,
        &mediator_a_did,
        &env_b,
        &bob,
        text,
        Duration::from_secs(15),
    )
    .await;
    // The first message was dropped above, so it cannot arrive late.
    assert_eq!(received.as_deref(), Some(text), "Bob admitted Alice");

    env_a.shutdown().await.expect("shutdown mediator A");
    env_b.shutdown().await.expect("shutdown mediator B");
}

/// An access list the next hop holds on the relaying mediator is still
/// honoured even when its DID document points elsewhere — the case of a
/// local account this mediator fails to recognise as its own. A refuses at
/// once, before relaying.
#[tokio::test]
async fn relay_honours_an_access_list_the_next_hop_holds_locally() {
    init_tracing();

    let env_a = spawn_consent_relay_environment().await;
    let env_b = spawn_consent_relay_environment().await;
    let mediator_a_did = env_a.mediator.did().to_string();

    // Over REST, so the refusal comes back as the send's own answer.
    let alice = env_a.add_user("Alice").await.expect("add Alice");
    let bob = env_b.add_user("Bob").await.expect("add Bob");
    let store_a = env_a.mediator.store();
    store_a
        .account_add(&bob.did_hash(), &consent_based_default(), None)
        .await
        .expect("Bob holds an account on A");
    store_a
        .access_list_add(100, &bob.did_hash(), &[sha256::digest("did:example:carol")])
        .await
        .expect("Bob's list on A admits only Carol");

    let now = unix_secs();
    let msg = Message::build(
        Uuid::new_v4().to_string(),
        "https://didcomm.org/basicmessage/2.0/message".to_string(),
        json!({ "content": "Bob's list on A does not admit Alice." }),
    )
    .to(bob.did.clone())
    .from(alice.did.clone())
    .created_time(now)
    .expires_time(now + 60)
    .finalize();
    let (packed, _) = env_a
        .atm
        .pack_encrypted(&msg, &bob.did, Some(&alice.did), Some(&alice.did))
        .await
        .expect("authcrypt for Bob");
    let (_fwd_id, forward) = env_a
        .atm
        .routing()
        .forward_message(
            &alice.profile,
            false,
            &packed,
            &mediator_a_did,
            &bob.did,
            None,
            None,
        )
        .await
        .expect("wrap forward");

    let error = env_a
        .atm
        .send_message(&alice.profile, &forward, &msg.id, false, false)
        .await
        .expect_err("A must apply the list Bob holds there");
    assert!(
        format!("{error:?}").contains("delivery.refused"),
        "expected delivery.refused, got: {error:?}"
    );

    env_a.shutdown().await.expect("shutdown mediator A");
    env_b.shutdown().await.expect("shutdown mediator B");
}

/// An in-place upgrade keeps the accounts the old version registered. A
/// placeholder it left for a remote recipient (the default ACL, an empty list)
/// must not refuse the relay: the recipient's own mediator decides.
#[tokio::test]
async fn relay_ignores_a_placeholder_account_left_by_an_earlier_version() {
    init_tracing();

    let env_a = spawn_consent_relay_environment().await;
    let env_b = spawn_consent_relay_environment().await;
    let mediator_a_did = env_a.mediator.did().to_string();

    let alice = add_live_user(&env_a, "Alice").await;
    let bob = add_live_user(&env_b, "Bob").await;
    env_a
        .mediator
        .store()
        .account_add(&bob.did_hash(), &consent_based_default(), None)
        .await
        .expect("the old version's placeholder for Bob on A");
    env_b
        .mediator
        .set_acl(&bob.did, consent_based_default())
        .await
        .expect("close Bob's inbox");
    env_b
        .mediator
        .store()
        .access_list_add(100, &bob.did_hash(), &[alice.did_hash()])
        .await
        .expect("Bob admits Alice");

    let text = "Relayed past a stale placeholder.";
    let received = single_forward_and_receive(
        &env_a,
        &alice,
        &mediator_a_did,
        &env_b,
        &bob,
        text,
        Duration::from_secs(15),
    )
    .await;
    assert_eq!(
        received.as_deref(),
        Some(text),
        "the placeholder is ignored"
    );

    env_a.shutdown().await.expect("shutdown mediator A");
    env_b.shutdown().await.expect("shutdown mediator B");
}

/// A forward to a local account still checks that account's access list.
#[tokio::test]
async fn consent_based_mediator_guards_local_forward() {
    init_tracing();

    let env = spawn_consent_relay_environment().await;
    let mediator_did = env.mediator.did().to_string();
    let alice = env.add_user("Alice").await.expect("add Alice");
    let carol = env.add_user("Carol").await.expect("add Carol");
    env.mediator
        .set_acl(&carol.did, consent_based_default())
        .await
        .expect("close Carol's inbox");

    let now = unix_secs();
    let msg = Message::build(
        Uuid::new_v4().to_string(),
        "https://didcomm.org/basicmessage/2.0/message".to_string(),
        json!({ "content": "Carol has not admitted Alice." }),
    )
    .to(carol.did.clone())
    .from(alice.did.clone())
    .created_time(now)
    .expires_time(now + 60)
    .finalize();
    let (packed, _) = env
        .atm
        .pack_encrypted(&msg, &carol.did, Some(&alice.did), Some(&alice.did))
        .await
        .expect("authcrypt for Carol");
    let (_fwd_id, forward) = env
        .atm
        .routing()
        .forward_message(
            &alice.profile,
            false,
            &packed,
            &mediator_did,
            &carol.did,
            None,
            None,
        )
        .await
        .expect("wrap forward");

    let error = env
        .atm
        .send_message(&alice.profile, &forward, &msg.id, false, false)
        .await
        .expect_err("a local inbox's allowlist must refuse Alice");
    assert!(
        format!("{error:?}").contains("delivery.refused"),
        "expected delivery.refused, got: {error:?}"
    );

    env.shutdown().await.expect("shutdown mediator");
}
