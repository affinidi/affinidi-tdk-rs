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
use affinidi_messaging_test_mediator::{RelayMode, TestEnvironment, TestMediator, TestUser, acl};
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
