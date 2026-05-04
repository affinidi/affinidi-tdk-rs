//! Integration tests for sender authentication across the pack/unpack pipeline.
//!
//! These tests verify that the mediator correctly identifies the sender in
//! all DIDComm encryption modes:
//! - **Authcrypt** (ECDH-1PU): sender authenticated at JWE layer
//! - **Anoncrypt** (ECDH-ES): no sender authentication
//!
//! Tests exercise the full `didcomm_compat::pack_encrypted` → `didcomm_compat::unpack`
//! round-trip with real cryptographic operations on the test DIDs from `common.rs`.

mod common;

use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
use affinidi_messaging_didcomm::message::Message;
use affinidi_messaging_mediator::didcomm_compat;
use affinidi_secrets_resolver::{SimpleSecretsResolver, secrets::Secret};
use common::{ALICE_DID, ALICE_E1, ALICE_V1, BOB_DID, BOB_E1, BOB_V1};
use serde_json::json;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn build_test_message(from: &str, to: &str, typ: &str) -> Message {
    let now = now_secs();
    Message::build(Uuid::new_v4().to_string(), typ.to_owned(), json!({}))
        .from(from.to_owned())
        .to(to.to_owned())
        .created_time(now)
        .expires_time(now + 300)
        .finalize()
}

async fn setup() -> (DIDCacheClient, SimpleSecretsResolver, SimpleSecretsResolver) {
    let did_resolver = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
        .await
        .unwrap();

    let alice_secrets = SimpleSecretsResolver::new(&[
        Secret::from_str(&format!("{ALICE_DID}#key-1"), &ALICE_V1).expect("Alice V1 key"),
        Secret::from_str(&format!("{ALICE_DID}#key-2"), &ALICE_E1).expect("Alice E1 key"),
    ])
    .await;

    let bob_secrets = SimpleSecretsResolver::new(&[
        Secret::from_str(&format!("{BOB_DID}#key-1"), &BOB_V1).expect("Bob V1 key"),
        Secret::from_str(&format!("{BOB_DID}#key-2"), &BOB_E1).expect("Bob E1 key"),
    ])
    .await;

    (did_resolver, alice_secrets, bob_secrets)
}

// ---------------------------------------------------------------------------
// Authcrypt tests (ECDH-1PU): sender is authenticated at the JWE layer
// ---------------------------------------------------------------------------

#[tokio::test]
async fn authcrypt_message_metadata_shows_authenticated() {
    let (resolver, alice_secrets, bob_secrets) = setup().await;

    let msg = build_test_message(ALICE_DID, BOB_DID, "https://example.com/test");

    // Pack with authcrypt (from = Some)
    let (packed, pack_meta) =
        didcomm_compat::pack_encrypted(&msg, BOB_DID, Some(ALICE_DID), &resolver, &alice_secrets)
            .await
            .expect("authcrypt pack failed");

    assert!(
        pack_meta.from_kid.is_some(),
        "authcrypt should have from_kid"
    );

    // Unpack as Bob
    let (unpacked, metadata) = didcomm_compat::unpack(&packed, &resolver, &bob_secrets)
        .await
        .expect("authcrypt unpack failed");

    assert_eq!(unpacked.id, msg.id);
    assert!(metadata.encrypted, "message should be encrypted");
    assert!(
        metadata.authenticated,
        "authcrypt message should be authenticated"
    );
    assert!(
        !metadata.anonymous_sender,
        "authcrypt message should not be anonymous"
    );
    assert!(
        metadata.encrypted_from_kid.is_some(),
        "authcrypt should have encrypted_from_kid"
    );
    // The sender kid should be Alice's key agreement key
    let from_kid = metadata.encrypted_from_kid.unwrap();
    assert!(
        from_kid.starts_with(ALICE_DID),
        "encrypted_from_kid ({from_kid}) should start with Alice's DID"
    );
}

#[tokio::test]
async fn authcrypt_is_not_blocked_by_anonymous_check() {
    let (resolver, alice_secrets, bob_secrets) = setup().await;

    let msg = build_test_message(ALICE_DID, BOB_DID, "https://example.com/test");
    let (packed, _) =
        didcomm_compat::pack_encrypted(&msg, BOB_DID, Some(ALICE_DID), &resolver, &alice_secrets)
            .await
            .unwrap();

    let (_, metadata) = didcomm_compat::unpack(&packed, &resolver, &bob_secrets)
        .await
        .unwrap();

    // This is the exact check from inbound.rs — authcrypt should NOT trigger it
    let would_be_blocked = !metadata.authenticated && metadata.sign_from.is_none();
    assert!(
        !would_be_blocked,
        "authcrypt messages must NOT be blocked by block_anonymous_outer_envelope"
    );
}

#[tokio::test]
async fn authcrypt_sender_kid_matches_session_did() {
    let (resolver, alice_secrets, bob_secrets) = setup().await;

    let msg = build_test_message(ALICE_DID, BOB_DID, "https://example.com/test");
    let (packed, _) =
        didcomm_compat::pack_encrypted(&msg, BOB_DID, Some(ALICE_DID), &resolver, &alice_secrets)
            .await
            .unwrap();

    let (_, metadata) = didcomm_compat::unpack(&packed, &resolver, &bob_secrets)
        .await
        .unwrap();

    // This is the sender_kid logic from inbound.rs
    let sender_kid = metadata
        .sign_from
        .as_ref()
        .or(metadata.encrypted_from_kid.as_ref());

    assert!(sender_kid.is_some(), "authcrypt must provide a sender kid");

    // Extract DID from kid (did:...#key-N → did:...)
    let kid = sender_kid.unwrap();
    let (did, _fragment) = kid.split_once('#').expect("kid should have # fragment");
    assert_eq!(
        did, ALICE_DID,
        "sender DID extracted from kid should match Alice"
    );
}

// ---------------------------------------------------------------------------
// Anoncrypt tests (ECDH-ES): no sender authentication
// ---------------------------------------------------------------------------

#[tokio::test]
async fn anoncrypt_message_metadata_shows_anonymous() {
    let (resolver, alice_secrets, bob_secrets) = setup().await;

    let msg = build_test_message(ALICE_DID, BOB_DID, "https://example.com/test");

    // Pack with anoncrypt (from = None)
    let (packed, pack_meta) = didcomm_compat::pack_encrypted(
        &msg,
        BOB_DID,
        None, // anoncrypt
        &resolver,
        &alice_secrets,
    )
    .await
    .expect("anoncrypt pack failed");

    assert!(
        pack_meta.from_kid.is_none(),
        "anoncrypt should not have from_kid"
    );

    // Unpack as Bob
    let (unpacked, metadata) = didcomm_compat::unpack(&packed, &resolver, &bob_secrets)
        .await
        .expect("anoncrypt unpack failed");

    assert_eq!(unpacked.id, msg.id);
    assert!(metadata.encrypted, "message should be encrypted");
    assert!(
        !metadata.authenticated,
        "anoncrypt message should not be authenticated"
    );
    assert!(
        metadata.anonymous_sender,
        "anoncrypt message should be anonymous"
    );
    assert!(
        metadata.encrypted_from_kid.is_none(),
        "anoncrypt should not have encrypted_from_kid"
    );
    assert!(
        metadata.sign_from.is_none(),
        "anoncrypt should not have sign_from"
    );
}

#[tokio::test]
async fn anoncrypt_is_blocked_by_anonymous_check() {
    let (resolver, alice_secrets, bob_secrets) = setup().await;

    let msg = build_test_message(ALICE_DID, BOB_DID, "https://example.com/test");
    let (packed, _) = didcomm_compat::pack_encrypted(
        &msg,
        BOB_DID,
        None, // anoncrypt
        &resolver,
        &alice_secrets,
    )
    .await
    .unwrap();

    let (_, metadata) = didcomm_compat::unpack(&packed, &resolver, &bob_secrets)
        .await
        .unwrap();

    // This is the exact check from inbound.rs — anoncrypt SHOULD trigger it
    let would_be_blocked = !metadata.authenticated && metadata.sign_from.is_none();
    assert!(
        would_be_blocked,
        "anoncrypt messages MUST be blocked by block_anonymous_outer_envelope"
    );
}

#[tokio::test]
async fn anoncrypt_has_no_sender_kid_for_session_match() {
    let (resolver, alice_secrets, bob_secrets) = setup().await;

    let msg = build_test_message(ALICE_DID, BOB_DID, "https://example.com/test");
    let (packed, _) = didcomm_compat::pack_encrypted(
        &msg,
        BOB_DID,
        None, // anoncrypt
        &resolver,
        &alice_secrets,
    )
    .await
    .unwrap();

    let (_, metadata) = didcomm_compat::unpack(&packed, &resolver, &bob_secrets)
        .await
        .unwrap();

    // This is the sender_kid logic from inbound.rs
    let sender_kid = metadata
        .sign_from
        .as_ref()
        .or(metadata.encrypted_from_kid.as_ref());

    assert!(
        sender_kid.is_none(),
        "anoncrypt must NOT provide a sender kid"
    );
}

// ---------------------------------------------------------------------------
// Protocol message simulation: live-delivery-change with authcrypt
// ---------------------------------------------------------------------------

#[tokio::test]
async fn live_delivery_change_with_authcrypt_accepted() {
    let (resolver, alice_secrets, bob_secrets) = setup().await;

    // Build a live-delivery-change message (the exact type that was failing)
    let now = now_secs();
    let msg = Message::build(
        Uuid::new_v4().to_string(),
        "https://didcomm.org/messagepickup/3.0/live-delivery-change".to_owned(),
        json!({"live_delivery": true}),
    )
    .from(ALICE_DID.to_owned())
    .to(BOB_DID.to_owned())
    .created_time(now)
    .expires_time(now + 300)
    .finalize();

    // Pack with authcrypt (what the SDK does)
    let (packed, _) =
        didcomm_compat::pack_encrypted(&msg, BOB_DID, Some(ALICE_DID), &resolver, &alice_secrets)
            .await
            .unwrap();

    // Unpack and verify it passes all mediator checks
    let (unpacked, metadata) = didcomm_compat::unpack(&packed, &resolver, &bob_secrets)
        .await
        .unwrap();

    // 1. Should not be blocked by anonymous check
    let would_be_blocked = !metadata.authenticated && metadata.sign_from.is_none();
    assert!(
        !would_be_blocked,
        "live-delivery-change with authcrypt must not be blocked"
    );

    // 2. Should have a sender kid for session matching
    let sender_kid = metadata
        .sign_from
        .as_ref()
        .or(metadata.encrypted_from_kid.as_ref());
    assert!(sender_kid.is_some(), "must have sender identity");

    // 3. Sender DID should match the message from field
    let kid = sender_kid.unwrap();
    let (did, _) = kid.split_once('#').unwrap();
    assert_eq!(did, ALICE_DID);
    assert_eq!(unpacked.from.as_deref(), Some(ALICE_DID));

    // 4. Message type should survive round-trip
    assert_eq!(
        unpacked.typ,
        "https://didcomm.org/messagepickup/3.0/live-delivery-change"
    );
}

// ---------------------------------------------------------------------------
// Envelope detection: MetaEnvelope pre-parsing
// ---------------------------------------------------------------------------

#[tokio::test]
async fn meta_envelope_detects_authcrypt_sender() {
    let (resolver, alice_secrets, _bob_secrets) = setup().await;

    let msg = build_test_message(ALICE_DID, BOB_DID, "https://example.com/test");
    let (packed, _) =
        didcomm_compat::pack_encrypted(&msg, BOB_DID, Some(ALICE_DID), &resolver, &alice_secrets)
            .await
            .unwrap();

    let envelope = didcomm_compat::MetaEnvelope::new(&packed, &resolver)
        .await
        .unwrap();

    assert!(envelope.metadata.encrypted);
    assert!(envelope.metadata.authenticated);
    assert!(
        envelope.from_did.is_some(),
        "authcrypt envelope should have from_did"
    );
    assert_eq!(envelope.from_did.as_deref(), Some(ALICE_DID));
}

#[tokio::test]
async fn meta_envelope_detects_anoncrypt_no_sender() {
    let (resolver, alice_secrets, _bob_secrets) = setup().await;

    let msg = build_test_message(ALICE_DID, BOB_DID, "https://example.com/test");
    let (packed, _) = didcomm_compat::pack_encrypted(
        &msg,
        BOB_DID,
        None, // anoncrypt
        &resolver,
        &alice_secrets,
    )
    .await
    .unwrap();

    let envelope = didcomm_compat::MetaEnvelope::new(&packed, &resolver)
        .await
        .unwrap();

    assert!(envelope.metadata.encrypted);
    assert!(!envelope.metadata.authenticated);
    assert!(
        envelope.from_did.is_none(),
        "anoncrypt envelope should not have from_did"
    );
}
