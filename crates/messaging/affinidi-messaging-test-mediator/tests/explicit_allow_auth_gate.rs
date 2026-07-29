//! End-to-end coverage for the `mediator_acl_mode = explicit_allow`
//! authentication gate.
//!
//! Until mediator 0.18.0 the mode never gated authentication: any DID that
//! completed `/authenticate/challenge` was auto-registered with
//! `global_acl_default` and issued a session, in *either* mode. The mode now
//! closes the mediator — an unknown DID is rejected at the challenge step and
//! no account record is created for it.
//!
//! Both directions are covered deliberately. The rejection test alone would
//! pass against a mediator that rejects everyone, so
//! [`preregistered_did_authenticates_in_explicit_allow_mode`] is the control
//! proving the gate admits known DIDs through the *full* auth flow, and
//! [`unknown_did_registered_and_authenticated_in_explicit_deny_mode`] pins
//! the open behaviour of `explicit_deny` so the gate cannot silently widen
//! to both modes.
//!
//! The rejection is also asserted to be byte-indistinguishable (modulo the
//! per-request session id) from the blocked-DID rejection:
//! `/authenticate/challenge` is unauthenticated, and a distinguishable error
//! would let anyone probe whether an arbitrary DID holds an account here.

mod common;

use std::{sync::Arc, time::Duration};

use affinidi_messaging_mediator::store::MemoryStore;
use affinidi_messaging_mediator_common::store::MediatorStore;
use affinidi_messaging_sdk::messages::fetch::FetchOptions;
use affinidi_messaging_test_mediator::{
    AccessListModeType, TestEnvironment, TestMediator, TestMediatorHandle, acl,
};
use affinidi_tdk::dids::{DID, KeyType, PeerKeyRole};
use common::init_tracing;
use serde_json::Value as JsonValue;

/// A fresh `did:peer:2.*` that has never been registered on `mediator`.
/// The secrets are discarded — these tests only exercise the challenge
/// step, which needs no signature.
fn unknown_did(mediator: &TestMediatorHandle) -> String {
    let (did, _secrets) = DID::generate_did_peer(
        vec![
            (PeerKeyRole::Verification, KeyType::Ed25519),
            (PeerKeyRole::Encryption, KeyType::X25519),
        ],
        Some(mediator.did().to_string()),
    )
    .expect("generate did:peer");
    did
}

/// POST `did` to `/authenticate/challenge` and return (status, JSON body).
async fn challenge(mediator: &TestMediatorHandle, did: &str) -> (u16, JsonValue) {
    let url = format!("{}authenticate/challenge", mediator.endpoint());
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("reqwest client");
    let resp = client
        .post(&url)
        .json(&serde_json::json!({ "did": did }))
        .send()
        .await
        .expect("challenge request");
    let status = resp.status().as_u16();
    let body: JsonValue = resp.json().await.expect("json body");
    (status, body)
}

/// Spawn an `explicit_allow` mediator around a store the test keeps a
/// handle on, so account side-effects can be asserted directly.
async fn spawn_explicit_allow() -> (TestMediatorHandle, Arc<MemoryStore>) {
    let store = Arc::new(MemoryStore::new());
    let mediator = TestMediator::builder()
        .store(store.clone())
        .acl_mode(AccessListModeType::ExplicitAllow)
        .spawn()
        .await
        .expect("spawn explicit_allow mediator");
    (mediator, store)
}

/// An unknown DID must be rejected at the challenge step with 403, and —
/// just as importantly — must NOT leave an account record behind. Before
/// 0.18.0 this request auto-registered the DID with `global_acl_default`.
#[tokio::test]
async fn unknown_did_challenge_rejected_in_explicit_allow_mode() {
    init_tracing();

    let (mediator, store) = spawn_explicit_allow().await;
    let did = unknown_did(&mediator);

    let (status, body) = challenge(&mediator, &did).await;
    assert_eq!(
        status, 403,
        "unknown DID must be rejected in explicit_allow mode, got {status}: {body}"
    );
    assert_eq!(
        body["errorCode"].as_u64(),
        Some(25),
        "rejection must carry the authentication.blocked error code: {body}"
    );

    assert!(
        !store
            .account_exists(&sha256::digest(&did))
            .await
            .expect("account_exists"),
        "a rejected DID must not be auto-registered"
    );

    mediator.shutdown();
    let _ = mediator.join().await;
}

/// Control: a DID an admin pre-registered completes the FULL auth flow
/// (challenge + signed response, via the SDK) and can use its session.
/// Without this, the rejection test would pass against a mediator that
/// rejects everyone.
#[tokio::test]
async fn preregistered_did_authenticates_in_explicit_allow_mode() {
    init_tracing();

    let (mediator, _store) = spawn_explicit_allow().await;
    let env = TestEnvironment::new(mediator)
        .await
        .expect("wire the SDK to the mediator");

    // `add_user` pre-registers the DID on the mediator (the admin path),
    // so it is "known" before the SDK ever authenticates.
    let alice = env.add_user("Alice").await.expect("add Alice");

    // First SDK operation triggers the full challenge/response auth flow.
    let fetched = env
        .atm
        .fetch_messages(&alice.profile, &FetchOptions::default())
        .await
        .expect("pre-registered DID must authenticate and fetch in explicit_allow mode");
    assert!(fetched.success.is_empty(), "fresh mailbox should be empty");

    env.shutdown().await.expect("env shutdown");
}

/// The unknown-DID rejection must be indistinguishable from the blocked-DID
/// rejection (same status, error code, and problem report), so the
/// unauthenticated challenge endpoint cannot be used to probe which DIDs
/// hold accounts. Only the per-request `sessionId` may differ.
#[tokio::test]
async fn unknown_did_rejection_indistinguishable_from_blocked() {
    init_tracing();

    let (mediator, store) = spawn_explicit_allow().await;

    // A registered-but-blocked DID.
    let blocked_did = unknown_did(&mediator);
    let mut blocked_acls = acl::allow_all();
    blocked_acls.set_blocked(true);
    store
        .account_add(&sha256::digest(&blocked_did), &blocked_acls, None)
        .await
        .expect("register blocked DID");

    let (blocked_status, mut blocked_body) = challenge(&mediator, &blocked_did).await;
    let (unknown_status, mut unknown_body) = challenge(&mediator, &unknown_did(&mediator)).await;

    assert_eq!(blocked_status, 403);
    assert_eq!(unknown_status, 403);

    // The session id is random per request; everything else must match.
    for body in [&mut blocked_body, &mut unknown_body] {
        body.as_object_mut()
            .expect("error body is an object")
            .remove("sessionId");
    }
    assert_eq!(
        blocked_body, unknown_body,
        "blocked and unknown DIDs must receive identical rejections"
    );

    mediator.shutdown();
    let _ = mediator.join().await;
}

/// `explicit_deny` keeps the historical open behaviour: an unknown DID gets
/// a challenge and is auto-registered with `global_acl_default`.
#[tokio::test]
async fn unknown_did_registered_and_authenticated_in_explicit_deny_mode() {
    init_tracing();

    let store = Arc::new(MemoryStore::new());
    let mediator = TestMediator::builder()
        .store(store.clone())
        .acl_mode(AccessListModeType::ExplicitDeny)
        .spawn()
        .await
        .expect("spawn explicit_deny mediator");
    let did = unknown_did(&mediator);

    let (status, body) = challenge(&mediator, &did).await;
    assert_eq!(
        status, 200,
        "unknown DID must get a challenge in explicit_deny mode, got {status}: {body}"
    );
    assert!(
        body["data"]["challenge"]
            .as_str()
            .is_some_and(|c| !c.is_empty()),
        "challenge body must contain the challenge string: {body}"
    );

    assert!(
        store
            .account_exists(&sha256::digest(&did))
            .await
            .expect("account_exists"),
        "explicit_deny must auto-register the DID at the challenge step"
    );

    mediator.shutdown();
    let _ = mediator.join().await;
}
