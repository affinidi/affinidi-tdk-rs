//! Verifies that DIDs registered via
//! [`TestMediatorBuilder::local_did`] / [`local_dids`] can complete
//! the WebSocket authentication handshake.
//!
//! The mediator's WS handler refuses upgrades unless the authenticated
//! session has the LOCAL ACL bit set. The default `global_acl_default`
//! used by the test fixture has `local = false`, so a DID that
//! authenticates fresh against the mediator gets registered as a
//! non-local account and cannot upgrade. This test demonstrates the
//! escape hatch — pre-register the DID as LOCAL and the upgrade
//! succeeds end-to-end.

mod common;

use affinidi_messaging_sdk::profiles::ATMProfile;
use affinidi_messaging_test_mediator::{TestEnvironment, TestMediator};
use affinidi_secrets_resolver::SecretsResolver;
use affinidi_tdk::dids::{DID, KeyType, PeerKeyRole};
use common::{init_tracing, skip_if_no_redis};

#[tokio::test]
async fn local_did_completes_websocket_authentication() {
    init_tracing();
    if skip_if_no_redis() {
        return;
    }

    // Generate the user DID up front so we can pre-register it as a
    // LOCAL account at mediator startup. The DID needs no service
    // endpoint — the SDK uses the mediator's DID document for routing,
    // not the user's.
    let (user_did, user_secrets) = DID::generate_did_peer(
        vec![
            (PeerKeyRole::Verification, KeyType::Ed25519),
            (PeerKeyRole::Encryption, KeyType::X25519),
        ],
        None,
    )
    .expect("generate user DID");

    let mediator = TestMediator::builder()
        .local_did(user_did.clone())
        .spawn()
        .await
        .expect("spawn test mediator");

    let env = TestEnvironment::new(mediator)
        .await
        .expect("wire test environment");

    // The user's secrets must be available to the SDK's resolver so it
    // can sign the auth response and decrypt mediator-bound traffic.
    env.tdk.secrets_resolver().insert_vec(&user_secrets).await;

    let profile = ATMProfile::new(
        &env.atm,
        Some("LocalUser".to_string()),
        user_did.clone(),
        Some(env.mediator.did().to_string()),
    )
    .await
    .expect("create profile");

    // `profile_add(_, true)` does the JWT auth + WS upgrade. If the
    // pre-registered LOCAL ACL bit weren't honoured, the upgrade would
    // fail with HTTP 403 and bubble up as a transport error.
    let added = env
        .atm
        .profile_add(&profile, true)
        .await
        .expect("profile_add with live_stream must succeed for a LOCAL DID");

    let (profile_did, mediator_did) = added.dids().expect("profile has mediator");
    assert_eq!(profile_did, user_did);
    assert_eq!(mediator_did, env.mediator.did());

    env.shutdown().await.expect("env shutdown");
}

#[tokio::test]
async fn local_dids_setter_accepts_iterable() {
    // Just exercise the IntoIterator setter — registration is
    // covered by the round-trip test above.
    init_tracing();
    if skip_if_no_redis() {
        return;
    }

    let dids = vec![
        "did:key:z6MkExample1".to_string(),
        "did:key:z6MkExample2".to_string(),
    ];
    let mediator = TestMediator::builder()
        .local_dids(dids)
        .spawn()
        .await
        .expect("spawn with iterable local_dids");

    mediator.shutdown();
    let _ = mediator.join().await;
}
