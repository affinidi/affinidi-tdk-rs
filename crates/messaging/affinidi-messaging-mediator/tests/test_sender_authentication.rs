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

// ---------------------------------------------------------------------------
// Regression: nested-envelope classification.
//
// The compat unpack used to decrypt only ONE outer JWE layer and never
// populate `sign_from` / never recurse, so it mis-classified several valid
// sender-authenticated wrappings as anonymous (rejected by inbound.rs).
//
// For the SAME Alice→Bob DIDs/keys, pack all four wrappings and assert that
// unpack now populates `authenticated`/`sign_from` correctly, so the inbound.rs
// anonymous-block decision accepts the first three and blocks only the fourth.
// ---------------------------------------------------------------------------

use affinidi_crypto::jose::key_agreement::{Curve, PrivateKeyAgreement, PublicKeyAgreement};
use affinidi_did_common::document::DocumentExt;
use affinidi_messaging_didcomm::{jwe::encrypt, jws::sign::sign_ed25519};
use base64::Engine;

/// Resolve a DID's first key-agreement public key (mirrors what the compat
/// layer does internally) so the test can build inner JWE layers.
async fn resolve_ka_public(did: &str, resolver: &DIDCacheClient) -> (String, PublicKeyAgreement) {
    let doc = resolver.resolve(did).await.unwrap();
    let kids = doc.doc.find_key_agreement(None);
    let kid = kids.first().unwrap().to_string();
    let vm = doc.doc.get_verification_method(&kid).unwrap();
    let multibase = vm.property_set["publicKeyMultibase"].as_str().unwrap();
    let (codec, bytes) = affinidi_encoding::decode_multikey_with_codec(multibase).unwrap();
    let curve = match codec {
        affinidi_encoding::X25519_PUB => Curve::X25519,
        affinidi_encoding::P256_PUB => Curve::P256,
        affinidi_encoding::SECP256K1_PUB => Curve::K256,
        affinidi_encoding::P384_PUB => Curve::P384,
        affinidi_encoding::P521_PUB => Curve::P521,
        other => panic!("unexpected KA codec {other:#x}"),
    };
    (
        kid,
        PublicKeyAgreement::from_raw_bytes(curve, &bytes).unwrap(),
    )
}

/// Decode the 32-byte `d` of an OKP/EC JWK (the JWKs here use url-safe base64).
fn jwk_d_bytes(jwk: &serde_json::Value) -> Vec<u8> {
    let d = jwk["d"].as_str().unwrap();
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(d)
        .unwrap()
}

#[tokio::test]
async fn nested_wrappings_classified_correctly() {
    let (resolver, _alice_secrets, bob_secrets) = setup().await;

    let alice_ka_kid = format!("{ALICE_DID}#key-2");
    let alice_sign_kid = format!("{ALICE_DID}#key-1");
    let (bob_ka_kid, bob_ka_pub) = resolve_ka_public(BOB_DID, &resolver).await;

    // Alice's sender keys: key-agreement (secp256k1, ALICE_E1) for authcrypt,
    // Ed25519 (ALICE_V1) for signing.
    let alice_ka_priv =
        PrivateKeyAgreement::from_raw_bytes(Curve::K256, &jwk_d_bytes(&ALICE_E1)).unwrap();
    let alice_ed: [u8; 32] = jwk_d_bytes(&ALICE_V1).try_into().unwrap();

    let msg = build_test_message(ALICE_DID, BOB_DID, "https://example.com/test");
    let plaintext = msg.to_json().unwrap();

    // 1. authcrypt(plaintext)
    let authcrypt = encrypt::authcrypt(
        &plaintext,
        &alice_ka_kid,
        &alice_ka_priv,
        &[(&bob_ka_kid, &bob_ka_pub)],
    )
    .unwrap();

    // 2. anoncrypt(signed(plaintext))
    let inner_jws = sign_ed25519(&plaintext, &alice_sign_kid, &alice_ed).unwrap();
    let anon_signed =
        encrypt::anoncrypt(inner_jws.as_bytes(), &[(&bob_ka_kid, &bob_ka_pub)]).unwrap();

    // 3. anoncrypt(authcrypt(plaintext))
    let anon_auth =
        encrypt::anoncrypt(authcrypt.as_bytes(), &[(&bob_ka_kid, &bob_ka_pub)]).unwrap();

    // 4. anoncrypt(plaintext)
    let anon_plain = encrypt::anoncrypt(&plaintext, &[(&bob_ka_kid, &bob_ka_pub)]).unwrap();

    let (_, m_authcrypt) = didcomm_compat::unpack(&authcrypt, &resolver, &bob_secrets)
        .await
        .expect("authcrypt(plaintext) must unpack");
    let (_, m_anon_signed) = didcomm_compat::unpack(&anon_signed, &resolver, &bob_secrets)
        .await
        .expect("anoncrypt(signed(plaintext)) must unpack");
    let (_, m_anon_auth) = didcomm_compat::unpack(&anon_auth, &resolver, &bob_secrets)
        .await
        .expect("anoncrypt(authcrypt(plaintext)) must unpack");
    let (_, m_anon_plain) = didcomm_compat::unpack(&anon_plain, &resolver, &bob_secrets)
        .await
        .expect("anoncrypt(plaintext) must unpack");

    // Metadata assertions per wrapping.
    assert!(
        m_authcrypt.authenticated,
        "authcrypt(plaintext) must be authenticated"
    );
    assert!(
        m_anon_signed.sign_from.is_some(),
        "anoncrypt(signed) must surface a verified signer (sign_from)"
    );
    assert!(
        m_anon_auth.authenticated,
        "anoncrypt(authcrypt) must recover inner authentication"
    );
    assert!(
        !m_anon_plain.authenticated && m_anon_plain.sign_from.is_none(),
        "pure anoncrypt must remain anonymous"
    );

    // The exact inbound.rs anonymous-block decision.
    let blocked = |m: &affinidi_messaging_sdk::messages::compat::UnpackMetadata| {
        !m.authenticated && m.sign_from.is_none()
    };
    assert!(!blocked(&m_authcrypt), "authcrypt must be accepted");
    assert!(
        !blocked(&m_anon_signed),
        "anoncrypt(signed) must be accepted"
    );
    assert!(
        !blocked(&m_anon_auth),
        "anoncrypt(authcrypt) must be accepted"
    );
    assert!(blocked(&m_anon_plain), "pure anoncrypt must be blocked");
}

/// A nested signed JWS with a BAD signature must NOT be accepted — verification
/// must fail (we never trust an unverified signer kid).
#[tokio::test]
async fn nested_signed_with_bad_signature_is_rejected() {
    let (resolver, _alice_secrets, bob_secrets) = setup().await;

    let alice_sign_kid = format!("{ALICE_DID}#key-1");
    let (bob_ka_kid, bob_ka_pub) = resolve_ka_public(BOB_DID, &resolver).await;

    // Sign with a DIFFERENT key (arbitrary 32-byte seed) but claim Alice's
    // kid — the resolver will fetch Alice's REAL Ed25519 key, so verification
    // against this forged signature must fail.
    let wrong_key: [u8; 32] = [7u8; 32];
    let msg = build_test_message(ALICE_DID, BOB_DID, "https://example.com/test");
    let forged_jws = sign_ed25519(&msg.to_json().unwrap(), &alice_sign_kid, &wrong_key).unwrap();
    let anon_forged =
        encrypt::anoncrypt(forged_jws.as_bytes(), &[(&bob_ka_kid, &bob_ka_pub)]).unwrap();

    let result = didcomm_compat::unpack(&anon_forged, &resolver, &bob_secrets).await;
    assert!(
        result.is_err(),
        "a forged inner signature must be rejected, not pass as authenticated"
    );
}

// ---------------------------------------------------------------------------
// ES256 (ECDSA P-256) signed messages.
//
// The EdDSA signed paths above use `sign_ed25519`. These exercise the ES256
// dispatch arm end-to-end: `extract_jws_alg` → `verify_inner_jws` (`"ES256"`)
// → `resolve_did_p256_verification` (P-256 did:key) → `verify_p256`. The
// didcomm crate is verify-only for ES256, so the JWS is hand-built and signed
// with `affinidi_crypto::p256`.
// ---------------------------------------------------------------------------

/// Hand-build an ES256 JWS (General JSON Serialization) over `payload`, signing
/// the JWS signing input with the given P-256 private key.
fn build_es256_jws(payload: &[u8], signer_kid: &str, p256_private: &[u8]) -> String {
    let protected = json!({
        "typ": "application/didcomm-signed+json",
        "alg": "ES256",
        "kid": signer_kid,
    });
    let protected_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&protected).unwrap());
    let payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload);
    let signing_input = format!("{protected_b64}.{payload_b64}");
    let sig = affinidi_crypto::p256::sign(p256_private, signing_input.as_bytes()).unwrap();
    let jws = json!({
        "payload": payload_b64,
        "signatures": [{
            "protected": protected_b64,
            "signature": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&sig),
        }],
    });
    serde_json::to_string(&jws).unwrap()
}

/// A P-256/ES256 signed message must verify, attribute the signer, and be
/// accepted by the anonymous-block decision.
#[tokio::test]
async fn es256_signed_message_verifies_and_attributes_signer() {
    let (resolver, _alice_secrets, bob_secrets) = setup().await;
    let (bob_ka_kid, bob_ka_pub) = resolve_ka_public(BOB_DID, &resolver).await;

    // A P-256 signer as a did:key (resolvable offline).
    let (signer_did, key) =
        affinidi_did_common::DID::generate_key(affinidi_crypto::KeyType::P256).unwrap();
    let signer_did = signer_did.to_string();

    let msg = build_test_message(&signer_did, BOB_DID, "https://example.com/es256");
    let es256_jws = build_es256_jws(&msg.to_json().unwrap(), &key.id, key.private_bytes());

    // Sign-then-encrypt: anoncrypt(signed(plaintext)) to Bob.
    let anon_signed =
        encrypt::anoncrypt(es256_jws.as_bytes(), &[(&bob_ka_kid, &bob_ka_pub)]).unwrap();

    let (unpacked, metadata) = didcomm_compat::unpack(&anon_signed, &resolver, &bob_secrets)
        .await
        .expect("ES256 signed message must unpack");

    assert_eq!(unpacked.id, msg.id, "verified payload must survive");
    assert!(
        metadata.non_repudiation,
        "ES256 signed message must set non_repudiation"
    );
    let blocked = !metadata.authenticated && metadata.sign_from.is_none();
    assert!(!blocked, "ES256 signed message must be accepted");

    let sign_from = metadata
        .sign_from
        .as_deref()
        .expect("ES256 signed message must set sign_from");
    let (did, _frag) = sign_from.split_once('#').expect("sign_from has fragment");
    assert_eq!(did, signer_did, "sign_from DID must be the P-256 signer");
}

/// An ES256 JWS signed with the WRONG P-256 key but claiming the signer's kid
/// must fail verification — the resolver fetches the real P-256 key.
#[tokio::test]
async fn es256_signed_with_wrong_key_is_rejected() {
    let (resolver, _alice_secrets, bob_secrets) = setup().await;
    let (bob_ka_kid, bob_ka_pub) = resolve_ka_public(BOB_DID, &resolver).await;

    // The claimed signer (its real key lives in the resolved DID document)…
    let (signer_did, _key) =
        affinidi_did_common::DID::generate_key(affinidi_crypto::KeyType::P256).unwrap();
    let signer_did = signer_did.to_string();
    // …but we sign with a DIFFERENT P-256 key while claiming the signer's kid.
    let wrong = affinidi_crypto::p256::generate_random();

    let msg = build_test_message(&signer_did, BOB_DID, "https://example.com/es256");
    let claimed_kid = format!("{signer_did}#forged");
    let forged_jws = build_es256_jws(&msg.to_json().unwrap(), &claimed_kid, &wrong.private_bytes);
    let anon_forged =
        encrypt::anoncrypt(forged_jws.as_bytes(), &[(&bob_ka_kid, &bob_ka_pub)]).unwrap();

    let result = didcomm_compat::unpack(&anon_forged, &resolver, &bob_secrets).await;
    assert!(
        result.is_err(),
        "an ES256 signature from the wrong key must be rejected"
    );
}

// ---------------------------------------------------------------------------
// Fully-specified `Ed25519` alg (draft-ietf-jose-fully-specified-algorithms).
//
// `sign_ed25519` emits the polymorphic `EdDSA` alg. Verification must ALSO
// accept the fully-specified `Ed25519` alg (both denote Ed25519 signatures),
// and must still reject an unsupported alg rather than assuming a default.
// ---------------------------------------------------------------------------

/// Hand-build an Ed25519 JWS with an explicit `alg` value (so we can exercise
/// both `EdDSA` and the fully-specified `Ed25519`).
fn build_ed25519_jws(payload: &[u8], signer_kid: &str, ed_private: &[u8; 32], alg: &str) -> String {
    let protected = json!({
        "typ": "application/didcomm-signed+json",
        "alg": alg,
        "kid": signer_kid,
    });
    let protected_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&protected).unwrap());
    let payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload);
    let signing_input = format!("{protected_b64}.{payload_b64}");
    let sig = affinidi_crypto::jose::signing::sign(signing_input.as_bytes(), ed_private).unwrap();
    let jws = json!({
        "payload": payload_b64,
        "signatures": [{
            "protected": protected_b64,
            "signature": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig),
        }],
    });
    serde_json::to_string(&jws).unwrap()
}

/// Shared body: a message signed with an Ed25519 key and declaring `alg` must
/// verify and be attributed to the signer — whether the header uses the
/// polymorphic `EdDSA` or the fully-specified `Ed25519`.
async fn assert_ed25519_signed_message_accepted(alg: &str) {
    let (resolver, _alice_secrets, bob_secrets) = setup().await;
    let (bob_ka_kid, bob_ka_pub) = resolve_ka_public(BOB_DID, &resolver).await;

    let (signer_did, key) =
        affinidi_did_common::DID::generate_key(affinidi_crypto::KeyType::Ed25519).unwrap();
    let signer_did = signer_did.to_string();
    let ed_private: [u8; 32] = key
        .private_bytes()
        .try_into()
        .expect("32-byte Ed25519 seed");

    let msg = build_test_message(&signer_did, BOB_DID, "https://example.com/ed25519");
    let jws = build_ed25519_jws(&msg.to_json().unwrap(), &key.id, &ed_private, alg);
    let anon_signed = encrypt::anoncrypt(jws.as_bytes(), &[(&bob_ka_kid, &bob_ka_pub)]).unwrap();

    let (unpacked, metadata) = didcomm_compat::unpack(&anon_signed, &resolver, &bob_secrets)
        .await
        .unwrap_or_else(|e| panic!("{alg}-signed message must unpack: {e}"));

    assert_eq!(unpacked.id, msg.id, "verified payload must survive ({alg})");
    assert!(
        metadata.non_repudiation,
        "{alg}-signed message must set non_repudiation"
    );
    let sign_from = metadata
        .sign_from
        .as_deref()
        .unwrap_or_else(|| panic!("{alg}-signed message must set sign_from"));
    let (did, _frag) = sign_from.split_once('#').expect("sign_from has fragment");
    assert_eq!(did, signer_did, "sign_from DID must be the signer ({alg})");
}

/// The polymorphic `EdDSA` alg (RFC 8037) must verify and attribute the signer.
#[tokio::test]
async fn eddsa_alg_signed_message_is_accepted() {
    assert_ed25519_signed_message_accepted("EdDSA").await;
}

/// The fully-specified `Ed25519` alg must verify identically to `EdDSA`.
#[tokio::test]
async fn ed25519_alg_signed_message_is_accepted() {
    assert_ed25519_signed_message_accepted("Ed25519").await;
}

/// A JWS declaring an unsupported alg (here `RS256`) must be rejected outright —
/// the mediator never falls back to a default algorithm.
#[tokio::test]
async fn unsupported_alg_signed_message_is_rejected() {
    let (resolver, _alice_secrets, bob_secrets) = setup().await;
    let (bob_ka_kid, bob_ka_pub) = resolve_ka_public(BOB_DID, &resolver).await;

    let (signer_did, key) =
        affinidi_did_common::DID::generate_key(affinidi_crypto::KeyType::Ed25519).unwrap();
    let signer_did = signer_did.to_string();
    let ed_private: [u8; 32] = key
        .private_bytes()
        .try_into()
        .expect("32-byte Ed25519 seed");

    let msg = build_test_message(&signer_did, BOB_DID, "https://example.com/test");
    // A validly-signed JWS, but the header declares an unsupported alg.
    let jws = build_ed25519_jws(&msg.to_json().unwrap(), &key.id, &ed_private, "RS256");
    let anon = encrypt::anoncrypt(jws.as_bytes(), &[(&bob_ka_kid, &bob_ka_pub)]).unwrap();

    let result = didcomm_compat::unpack(&anon, &resolver, &bob_secrets).await;
    assert!(
        result.is_err(),
        "a JWS with an unsupported alg (RS256) must be rejected, not assumed EdDSA"
    );
}
