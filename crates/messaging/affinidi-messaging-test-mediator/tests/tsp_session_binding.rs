//! End-to-end coverage for the sender-side gates on the TSP ingress path.
//!
//! A TSP envelope names its sender in the clear and the mediator does not
//! decrypt it, so `meta.sender` is a *claim* — the exact position the DIDComm
//! direct-delivery path was in before mediator 0.15.5, where an authenticated
//! session could set the JWE `skid` to any DID and have the recipient's access
//! list evaluated against it. `handle_inbound_tsp` was written after that fix
//! and did not carry it: it never consulted the session at all.
//!
//! Reported as affinidi-tdk-rs#754, measured against a public deployment: a TSP
//! frame sent on a socket authenticated as DID A, with envelope sender DID E,
//! was forwarded normally.
//!
//! Each test asserts the recipient's mailbox as well as the send result, so
//! "the mediator returned an error" is distinguished from "the mediator
//! returned an error *and* stored nothing" — the DIDComm ACL tests make the
//! same distinction for the same reason.
#![cfg(feature = "tsp")]

use affinidi_messaging_sdk::messages::fetch::FetchOptions;
use affinidi_messaging_test_mediator::{
    AccessListModeType, TestEnvironment, TestMediator, TestUser, acl,
};

async fn inbox_len(env: &TestEnvironment, user: &TestUser) -> usize {
    env.atm
        .fetch_messages(&user.profile, &FetchOptions::default())
        .await
        .expect("fetch messages")
        .success
        .len()
}

/// The regression for #754: a frame whose envelope sender is not the session
/// DID is refused.
///
/// Mallory packs the message — so it is a genuinely well-formed TSP envelope
/// naming her as sender, not a hand-mangled one — and Alice hands it to the
/// mediator over her own authenticated session via `send_raw`.
#[tokio::test]
async fn spoofed_envelope_sender_is_refused() {
    let env = TestEnvironment::spawn().await.expect("spawn environment");
    let alice = env.add_user("alice").await.expect("add alice");
    let bob = env.add_user("bob").await.expect("add bob");
    let mallory = env.add_user("mallory").await.expect("add mallory");

    let spoofed = env
        .atm
        .tsp()
        .pack(&mallory.profile, &bob.did, b"sent as mallory")
        .await
        .expect("mallory packs a TSP message to bob");

    let err = env
        .atm
        .tsp()
        .send_raw(&alice.profile, &spoofed)
        .await
        .expect_err("a TSP envelope claiming another DID as sender must be refused")
        .to_string();

    assert!(
        err.contains("session_mismatch"),
        "expected a session-mismatch denial, got: {err}"
    );
    assert_eq!(
        inbox_len(&env, &bob).await,
        0,
        "a refused TSP message must not be stored for the recipient"
    );

    env.shutdown().await.expect("shutdown");
}

/// Control for the denial above: the same path, same fixture, sender matching
/// the session. Without this the denial test would pass against a fixture that
/// never manages to deliver anything at all.
#[tokio::test]
async fn envelope_sender_matching_the_session_is_accepted() {
    let env = TestEnvironment::spawn().await.expect("spawn environment");
    let alice = env.add_user("alice").await.expect("add alice");
    let bob = env.add_user("bob").await.expect("add bob");

    env.atm
        .tsp()
        .send(&alice.profile, &bob.did, b"sent as alice")
        .await
        .expect("a TSP message whose sender is the session DID must be accepted");

    assert_eq!(
        inbox_len(&env, &bob).await,
        1,
        "an accepted TSP message must reach the recipient's mailbox"
    );

    env.shutdown().await.expect("shutdown");
}

/// What the gap actually cost: the claimed sender feeds the recipient's
/// access-list lookup, so before the fix Alice could borrow an allow-listed
/// VID to get past an allowlist that does not admit her.
///
/// Bob runs `ExplicitAllow` (allowlist) with Mallory on it and Alice not. The
/// first assertion pins that the allowlist is load-bearing — Alice as herself
/// is refused — and the second that she cannot buy her way past it by naming
/// Mallory in the envelope.
#[tokio::test]
async fn spoofed_sender_cannot_pass_the_recipients_access_list() {
    let env = TestEnvironment::spawn().await.expect("spawn environment");
    let alice = env.add_user("alice").await.expect("add alice");
    let bob = env.add_user("bob").await.expect("add bob");
    let mallory = env.add_user("mallory").await.expect("add mallory");

    // Bob admits Mallory, then switches his inbox to allowlist mode. In that
    // order: the trust-task reply is itself a delivery to Bob, so populating the
    // list while he is still in denylist mode keeps the setup from tripping the
    // gate it is setting up. The access list is stored separately from the ACL
    // bitset, so the later `set_acl` leaves it intact.
    env.atm
        .profile_add(&bob.profile, true)
        .await
        .expect("enable websocket for bob so the trust-task reply arrives");
    env.atm
        .trust_tasks()
        .access_list_update(&bob.profile, None, false, vec![mallory.did_hash()], vec![])
        .await
        .expect("bob allows mallory");

    let mut bob_acls = acl::allow_all();
    bob_acls
        .set_access_list_mode(AccessListModeType::ExplicitAllow, true, true)
        .expect("put bob's inbox in allowlist mode");
    env.mediator
        .set_acl(&bob.did, bob_acls)
        .await
        .expect("set bob's ACLs");

    // The allowlist is real: Alice, sending honestly as herself, is refused.
    let honest = env
        .atm
        .tsp()
        .send(&alice.profile, &bob.did, b"alice, honestly")
        .await
        .expect_err("alice is not on bob's allowlist")
        .to_string();
    assert!(
        honest.contains("access_list") || honest.contains("ACLs"),
        "expected an access-list denial for the honest send, got: {honest}"
    );

    // And she cannot borrow Mallory's place on it.
    let spoofed = env
        .atm
        .tsp()
        .pack(&mallory.profile, &bob.did, b"alice, as mallory")
        .await
        .expect("pack a message naming mallory as sender");
    let err = env
        .atm
        .tsp()
        .send_raw(&alice.profile, &spoofed)
        .await
        .expect_err("borrowing an allow-listed sender VID must not pass the access list")
        .to_string();
    assert!(
        err.contains("session_mismatch"),
        "expected a session-mismatch denial, got: {err}"
    );

    assert_eq!(
        inbox_len(&env, &bob).await,
        0,
        "neither send may reach bob's mailbox"
    );

    env.shutdown().await.expect("shutdown");
}

/// The binding is governed by the same switch as the DIDComm one, so a
/// deployment that has deliberately turned `force_session_did_match` off keeps
/// the old behaviour rather than finding TSP newly restricted.
#[tokio::test]
async fn force_session_did_match_off_still_accepts_a_mismatched_sender() {
    let mediator = TestMediator::builder()
        .force_session_did_match(false)
        .spawn()
        .await
        .expect("spawn mediator with session matching disabled");
    let env = TestEnvironment::new(mediator)
        .await
        .expect("wire the SDK to the mediator");

    let alice = env.add_user("alice").await.expect("add alice");
    let bob = env.add_user("bob").await.expect("add bob");
    let mallory = env.add_user("mallory").await.expect("add mallory");

    let spoofed = env
        .atm
        .tsp()
        .pack(&mallory.profile, &bob.did, b"sent as mallory")
        .await
        .expect("mallory packs a TSP message to bob");

    env.atm
        .tsp()
        .send_raw(&alice.profile, &spoofed)
        .await
        .expect("with the check disabled the mismatched sender is still accepted");

    assert_eq!(inbox_len(&env, &bob).await, 1, "the message is delivered");

    env.shutdown().await.expect("shutdown");
}
