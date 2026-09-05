//! End-to-end coverage for the recipient-side `RECEIVE_MESSAGES` gate.
//!
//! Until mediator 0.17.11 this ACL bit was settable, shipped in the default
//! ACL string, reported over the wire and gated for self-change — while being
//! read by no code path at all. Clearing it did nothing. The gate now runs on
//! direct delivery, and these tests exist so it cannot quietly go inert a
//! second time: a unit test on the bit-level `require_capability` would still
//! pass if the call site were deleted.
//!
//! Both directions are covered deliberately. The denial test alone would pass
//! against a fixture that never manages to deliver anything, so
//! [`direct_delivery_succeeds_when_recipient_has_receive_messages`] is the
//! control that makes the denial meaningful, and
//! [`direct_delivery_ignores_unrelated_acl_bits`] pins the gate to the *right*
//! bit rather than to any revoked capability. Each test also asserts the
//! recipient's mailbox, so "rejected the request" is distinguished from
//! "rejected the request and stored nothing".
//!
//! Both direct-delivery protocols are covered: DIDComm here, TSP in the
//! [`tsp`] module. They are separate call sites and were verified to fail
//! independently.

mod common;

use std::time::{SystemTime, UNIX_EPOCH};

use affinidi_messaging_didcomm::Message;
use affinidi_messaging_sdk::messages::fetch::FetchOptions;
use affinidi_messaging_test_mediator::{
    MediatorACLSet, TestEnvironment, TestMediator, TestUser, acl,
};
use common::init_tracing;
use serde_json::json;
use uuid::Uuid;

/// How many messages are sitting in `user`'s mailbox.
///
/// Asserting on this as well as on the send result is what distinguishes "the
/// mediator returned an error" from "the mediator returned an error *and*
/// stored nothing" — a gate that rejected the response while still queueing
/// the message would pass the weaker check.
async fn inbox_len(env: &TestEnvironment, user: &TestUser) -> usize {
    env.atm
        .fetch_messages(&user.profile, &FetchOptions::default())
        .await
        .expect("fetch messages")
        .success
        .len()
}

fn unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after epoch")
        .as_secs()
}

/// The fixture ships with `local_direct_delivery_allowed = false`, which
/// rejects every unwrapped message before any ACL is consulted. These tests
/// need the direct-delivery path reachable, so enable it explicitly —
/// otherwise all three would pass or fail for reasons unrelated to the ACL.
async fn spawn_direct_delivery_env() -> TestEnvironment {
    let mediator = TestMediator::builder()
        .local_direct_delivery(true, false)
        .spawn()
        .await
        .expect("spawn mediator with direct delivery enabled");
    TestEnvironment::new(mediator)
        .await
        .expect("wire the SDK to the mediator")
}

/// Pack a basic message from `sender` to `recipient` and hand it to the
/// mediator **unwrapped** — no forwarding envelope, so the mediator resolves
/// `to` as a local DID and takes the direct-delivery path where the
/// `RECEIVE_MESSAGES` gate lives. (Forwarded delivery is governed by
/// `RECEIVE_FORWARDED` instead and is not what these tests exercise.)
///
/// Returns the mediator's rejection rendered as a string so assertions can
/// match on the problem report without importing the SDK error type.
async fn send_direct(
    env: &TestEnvironment,
    sender: &TestUser,
    recipient: &TestUser,
) -> Result<(), String> {
    let now = unix_secs();
    let msg = Message::build(
        Uuid::new_v4().to_string(),
        "https://didcomm.org/basicmessage/2.0/message".to_string(),
        json!({ "content": "receive_messages acl probe" }),
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

/// Revoking `RECEIVE_MESSAGES` stops directly-delivered messages reaching the
/// recipient. This is the behaviour the bit always claimed to have.
#[tokio::test]
async fn direct_delivery_is_refused_when_recipient_lacks_receive_messages() {
    init_tracing();
    let env = spawn_direct_delivery_env().await;
    let alice = env.add_user("alice").await.expect("add alice");
    let bob = env.add_user("bob").await.expect("add bob");

    // Revoke exactly one bit from an otherwise-permissive set, so the gate is
    // the single variable between this test and the control below.
    let mut bob_acls = acl::allow_all();
    bob_acls
        .set_receive_messages(false, true, true)
        .expect("revoke receive_messages");
    env.mediator
        .set_acl(&bob.did, bob_acls)
        .await
        .expect("set bob's ACLs");

    let err = send_direct(&env, &alice, &bob)
        .await
        .expect_err("delivery must be refused when the recipient lacks RECEIVE_MESSAGES");

    assert!(
        err.contains("authorization.receive") || err.contains("not authorized to receive"),
        "expected a RECEIVE_MESSAGES denial, got: {err}"
    );
    assert_eq!(
        inbox_len(&env, &bob).await,
        0,
        "a refused message must not be stored for the recipient"
    );

    env.shutdown().await.expect("shutdown");
}

/// Control for the test above: with the bit granted, the very same exchange
/// goes through. Without this, a fixture that could never deliver at all
/// would satisfy the denial test.
#[tokio::test]
async fn direct_delivery_succeeds_when_recipient_has_receive_messages() {
    init_tracing();
    let env = spawn_direct_delivery_env().await;
    let alice = env.add_user("alice").await.expect("add alice");
    let bob = env.add_user("bob").await.expect("add bob");

    // `add_user` registers an ALLOW_ALL account, which grants
    // RECEIVE_MESSAGES. Set it explicitly anyway so the test states its own
    // precondition rather than depending on the fixture's default.
    env.mediator
        .set_acl(&bob.did, acl::allow_all())
        .await
        .expect("set bob's ACLs");

    send_direct(&env, &alice, &bob)
        .await
        .expect("delivery must be accepted when the recipient has RECEIVE_MESSAGES");
    assert_eq!(
        inbox_len(&env, &bob).await,
        1,
        "an accepted message must reach the recipient's mailbox"
    );

    env.shutdown().await.expect("shutdown");
}

/// The gate must key off `RECEIVE_MESSAGES` specifically. Revoking an
/// unrelated capability — one with no bearing on direct delivery — must not
/// block the message, which a gate wired to the wrong bit (or to "any
/// missing capability") would.
#[tokio::test]
async fn direct_delivery_ignores_unrelated_acl_bits() {
    init_tracing();
    let env = spawn_direct_delivery_env().await;
    let alice = env.add_user("alice").await.expect("add alice");
    let bob = env.add_user("bob").await.expect("add bob");

    let mut bob_acls: MediatorACLSet = acl::allow_all();
    bob_acls
        .set_create_invites(false, true, true)
        .expect("revoke create_invites");
    bob_acls
        .set_send_forwarded(false, true, true)
        .expect("revoke send_forwarded");
    env.mediator
        .set_acl(&bob.did, bob_acls)
        .await
        .expect("set bob's ACLs");

    send_direct(&env, &alice, &bob)
        .await
        .expect("revoking unrelated capabilities must not affect direct delivery");

    env.shutdown().await.expect("shutdown");
}

/// The mediator enforces `RECEIVE_MESSAGES` on **two** direct-delivery paths —
/// DIDComm (above) and TSP. They are separate call sites in `inbound.rs`, so
/// covering only one leaves the other free to regress silently: while
/// validating this suite, disabling the TSP gate alone left every test above
/// green.
///
/// TSP needs no `local_direct_delivery_allowed` opt-in (that config gates the
/// DIDComm path only), so these use the default fixture.
#[cfg(feature = "tsp")]
mod tsp {
    use super::*;

    #[tokio::test]
    async fn tsp_delivery_is_refused_when_recipient_lacks_receive_messages() {
        init_tracing();
        let env = spawn_direct_delivery_env().await;
        let alice = env.add_user("alice").await.expect("add alice");
        let bob = env.add_user("bob").await.expect("add bob");

        let mut bob_acls = acl::allow_all();
        bob_acls
            .set_receive_messages(false, true, true)
            .expect("revoke receive_messages");
        env.mediator
            .set_acl(&bob.did, bob_acls)
            .await
            .expect("set bob's ACLs");

        let result = env
            .atm
            .tsp()
            .send(&alice.profile, &bob.did, b"receive_messages acl probe")
            .await;

        let err = result
            .expect_err("TSP delivery must be refused when the recipient lacks RECEIVE_MESSAGES")
            .to_string();
        assert!(
            err.contains("authorization.receive") || err.contains("not authorized to receive"),
            "expected a RECEIVE_MESSAGES denial, got: {err}"
        );
        assert_eq!(
            inbox_len(&env, &bob).await,
            0,
            "a refused TSP message must not be stored for the recipient"
        );

        env.shutdown().await.expect("shutdown");
    }

    /// Control for the TSP denial, mirroring the DIDComm one.
    #[tokio::test]
    async fn tsp_delivery_succeeds_when_recipient_has_receive_messages() {
        init_tracing();
        let env = spawn_direct_delivery_env().await;
        let alice = env.add_user("alice").await.expect("add alice");
        let bob = env.add_user("bob").await.expect("add bob");

        env.mediator
            .set_acl(&bob.did, acl::allow_all())
            .await
            .expect("set bob's ACLs");

        env.atm
            .tsp()
            .send(&alice.profile, &bob.did, b"receive_messages acl probe")
            .await
            .expect("TSP delivery must be accepted when the recipient has RECEIVE_MESSAGES");
        assert_eq!(
            inbox_len(&env, &bob).await,
            1,
            "an accepted TSP message must reach the recipient's mailbox"
        );

        env.shutdown().await.expect("shutdown");
    }
}
