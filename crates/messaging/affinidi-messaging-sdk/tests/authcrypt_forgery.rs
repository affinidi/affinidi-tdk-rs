//! Hand-built authcrypt envelopes that name a sender other than the key that
//! encrypted them must be refused by `ATM::unpack`, whatever the policy and
//! however they are wrapped.

#[path = "../../affinidi-messaging-didcomm/tests/support/forge.rs"]
mod forge;

use affinidi_crypto::jose::key_agreement::{Curve, PrivateKeyAgreement, PublicKeyAgreement};
use affinidi_did_common::{DID, PeerCreateKey, PeerKeyPurpose, PeerKeyType};
use affinidi_messaging_didcomm::jwe::encrypt;
use affinidi_messaging_didcomm::message::{Message, pack};
use affinidi_messaging_sdk::ATM;
use affinidi_messaging_sdk::config::{ATMConfig, MessageWrappingType, UnpackPolicy};
use affinidi_secrets_resolver::SecretsResolver;
use affinidi_secrets_resolver::secrets::Secret;
use affinidi_tdk_common::TDKSharedState;
use affinidi_tdk_common::config::TDKConfig;
use base64::Engine;
use forge::{forge, header_with};
use serde_json::json;
use std::sync::Arc;

/// A did:peer:2 with an Ed25519 verification key (`#key-1`) and an X25519
/// key agreement key (`#key-2`).
struct Party {
    did: String,
    signing_private: [u8; 32],
    key_agreement: Secret,
}

impl Party {
    fn new() -> Self {
        let key_agreement = Secret::generate_x25519(Some("temp"), None).unwrap();
        let multibase = key_agreement.get_public_keymultibase().unwrap();
        let keys = vec![
            PeerCreateKey::new(PeerKeyPurpose::Verification, PeerKeyType::Ed25519),
            PeerCreateKey::from_multibase(PeerKeyPurpose::Encryption, multibase),
        ];
        let (did, created) = DID::generate_peer(&keys, None).unwrap();
        let did = did.to_string();
        let signing_private: [u8; 32] = base64::prelude::BASE64_URL_SAFE_NO_PAD
            .decode(&created[0].d)
            .unwrap()
            .try_into()
            .unwrap();
        let mut key_agreement = key_agreement;
        key_agreement.id = format!("{did}#key-2");
        Party {
            did,
            signing_private,
            key_agreement,
        }
    }

    fn kid(&self) -> String {
        format!("{}#key-2", self.did)
    }

    fn private(&self) -> PrivateKeyAgreement {
        PrivateKeyAgreement::from_raw_bytes(Curve::X25519, self.key_agreement.get_private_bytes())
            .unwrap()
    }

    fn public(&self) -> PublicKeyAgreement {
        PublicKeyAgreement::from_raw_bytes(Curve::X25519, self.key_agreement.get_public_bytes())
            .unwrap()
    }
}

async fn atm(secrets: Vec<Secret>, policy: UnpackPolicy) -> ATM {
    let config = ATMConfig::builder()
        .with_unpack_policy(policy)
        .build()
        .unwrap();
    let tdk = Arc::new(
        TDKSharedState::new(TDKConfig::headless().unwrap())
            .await
            .unwrap(),
    );
    for secret in &secrets {
        tdk.secrets_resolver().insert(secret.clone()).await;
    }
    ATM::new(config, tdk).await.unwrap()
}

/// Every wrapping accepted, and no addressing check: the weakest policy a
/// caller can choose.
fn permissive() -> UnpackPolicy {
    UnpackPolicy {
        expected: vec![
            MessageWrappingType::Plaintext,
            MessageWrappingType::SignedPlaintext,
            MessageWrappingType::AnoncryptPlaintext,
            MessageWrappingType::AuthcryptPlaintext,
            MessageWrappingType::AnoncryptSignPlaintext,
            MessageWrappingType::AuthcryptSignPlaintext,
            MessageWrappingType::AnoncryptAuthcryptPlaintext,
        ],
        validate_addressing_consistency: false,
        ..UnpackPolicy::default()
    }
}

fn message(from: &str, to: &str, id: &str) -> String {
    String::from_utf8(
        Message::build(id.to_string(), "example/v1".to_string(), json!({"k": 1}))
            .from(from.to_string())
            .to(to.to_string())
            .finalize()
            .to_json()
            .unwrap(),
    )
    .unwrap()
}

fn forward_to(next: &str, inner: &str) -> String {
    json!({
        "id": "fwd-1",
        "type": "https://didcomm.org/routing/2.0/forward",
        "typ": "application/didcomm-plain+json",
        "body": {"next": next},
        "attachments": [{"data": {"json": serde_json::from_str::<serde_json::Value>(inner).unwrap()}}]
    })
    .to_string()
}

#[tokio::test]
async fn forged_authcrypt_is_refused_under_every_policy() {
    let alice = Party::new();
    let mallory = Party::new();
    let bob = Party::new();
    let carol = Party::new();
    let default_policy = atm(vec![bob.key_agreement.clone()], UnpackPolicy::default()).await;
    let permissive_policy = atm(vec![bob.key_agreement.clone()], permissive()).await;

    let bob_kid = bob.kid();
    let bob_public = bob.public();
    let to_bob = [(bob_kid.as_str(), &bob_public)];
    let (alice_kid, mallory_kid) = (alice.kid(), mallory.kid());
    let alice_verification_kid = format!("{}#key-1", alice.did);
    let mallory_private = mallory.private();
    let from_alice = message(&alice.did, &bob.did, "forged");
    let forged = |kdf_apu: &str, skid: Option<&str>, apu: Option<&str>| {
        forge(
            from_alice.as_bytes(),
            kdf_apu.as_bytes(),
            &mallory_private,
            &to_bob,
            header_with(skid, apu),
            None,
            None,
        )
    };

    let skid_mallory_apu_alice = forged(&alice_kid, Some(&mallory_kid), Some(&alice_kid));
    let named_alice = forged(&alice_kid, Some(&alice_kid), Some(&alice_kid));
    let honest_mallory_inner = forged(&mallory_kid, Some(&mallory_kid), Some(&mallory_kid));
    let carol_kid = carol.kid();
    let carol_public = carol.public();

    let cases: Vec<(&str, String)> = vec![
        ("skid mallory, apu alice", skid_mallory_apu_alice.clone()),
        (
            "skid mallory, apu alice, KEK over skid",
            forged(&mallory_kid, Some(&mallory_kid), Some(&alice_kid)),
        ),
        ("skid = apu = alice, mallory's key", named_alice.clone()),
        (
            "skid = alice's verification key",
            forged(
                &alice_verification_kid,
                Some(&alice_verification_kid),
                Some(&alice_verification_kid),
            ),
        ),
        (
            "skid is a bare DID",
            forged(&alice.did, Some(&alice.did), Some(&alice.did)),
        ),
        (
            "skid only outside the protected header",
            forge(
                from_alice.as_bytes(),
                alice_kid.as_bytes(),
                &mallory_private,
                &to_bob,
                header_with(None, Some(&alice_kid)),
                Some(json!({"unprotected": {"skid": alice_kid}})),
                Some(json!({"skid": alice_kid})),
            ),
        ),
        (
            "anoncrypt(skid mallory, apu alice)",
            encrypt::anoncrypt(skid_mallory_apu_alice.as_bytes(), &to_bob).unwrap(),
        ),
        (
            "anoncrypt(skid = alice, mallory's key)",
            encrypt::anoncrypt(named_alice.as_bytes(), &to_bob).unwrap(),
        ),
        (
            "forward(skid mallory, apu alice)",
            forward_to(&bob.did, &skid_mallory_apu_alice),
        ),
        (
            "anoncrypt(forward(skid mallory, apu alice))",
            encrypt::anoncrypt(
                forward_to(&bob.did, &skid_mallory_apu_alice).as_bytes(),
                &to_bob,
            )
            .unwrap(),
        ),
        (
            "several recipients",
            forge(
                from_alice.as_bytes(),
                alice_kid.as_bytes(),
                &mallory_private,
                &[
                    (carol_kid.as_str(), &carol_public),
                    (bob_kid.as_str(), &bob_public),
                ],
                header_with(Some(&mallory_kid), Some(&alice_kid)),
                None,
                None,
            ),
        ),
        (
            "authcrypt(authcrypt(from alice))",
            encrypt::authcrypt(
                honest_mallory_inner.as_bytes(),
                &mallory_kid,
                &mallory_private,
                &to_bob,
            )
            .unwrap(),
        ),
    ];

    for (name, envelope) in &cases {
        for (policy, atm) in [
            ("default", &default_policy),
            ("permissive", &permissive_policy),
        ] {
            let result = atm.unpack(envelope).await;
            assert!(
                result.is_err(),
                "{name}: accepted under the {policy} policy as {:?}",
                result
                    .as_ref()
                    .ok()
                    .map(|(msg, meta)| (&msg.from, &meta.encrypted_from_kid))
            );
        }
    }
}

/// Mallory's own key and header, but `from` (or an inner signature) naming
/// Alice. The default policy refuses the mismatch; with the addressing check
/// turned off the message is attributed to Mallory, never to Alice.
#[tokio::test]
async fn honest_header_with_another_from_is_attributed_to_the_key() {
    let alice = Party::new();
    let mallory = Party::new();
    let bob = Party::new();
    let default_policy = atm(vec![bob.key_agreement.clone()], UnpackPolicy::default()).await;
    let permissive_policy = atm(vec![bob.key_agreement.clone()], permissive()).await;
    let bob_kid = bob.kid();
    let bob_public = bob.public();
    let to_bob = [(bob_kid.as_str(), &bob_public)];
    let mallory_kid = mallory.kid();
    let mallory_private = mallory.private();

    let from_alice = message(&alice.did, &bob.did, "lie");
    let lie = forge(
        from_alice.as_bytes(),
        mallory_kid.as_bytes(),
        &mallory_private,
        &to_bob,
        header_with(Some(&mallory_kid), Some(&mallory_kid)),
        None,
        None,
    );
    assert!(default_policy.unpack(&lie).await.is_err());
    let anoncrypted = encrypt::anoncrypt(lie.as_bytes(), &to_bob).unwrap();
    assert!(default_policy.unpack(&anoncrypted).await.is_err());
    let (_, meta) = permissive_policy.unpack(&lie).await.unwrap();
    assert_eq!(
        meta.encrypted_from_kid.as_deref(),
        Some(mallory_kid.as_str())
    );

    let alice_signed = pack::pack_signed(
        &Message::build("s".to_string(), "example/v1".to_string(), json!({}))
            .from(alice.did.clone())
            .to(bob.did.clone())
            .finalize(),
        &format!("{}#key-1", alice.did),
        &alice.signing_private,
    )
    .unwrap();
    let wrapped = encrypt::authcrypt(
        alice_signed.as_bytes(),
        &mallory_kid,
        &mallory_private,
        &to_bob,
    )
    .unwrap();
    assert!(default_policy.unpack(&wrapped).await.is_err());
    let (_, meta) = permissive_policy.unpack(&wrapped).await.unwrap();
    assert_eq!(
        meta.encrypted_from_kid.as_deref(),
        Some(mallory_kid.as_str())
    );
    assert_eq!(
        meta.sign_from.as_deref(),
        Some(format!("{}#key-1", alice.did).as_str())
    );
}

#[tokio::test]
async fn honest_authcrypt_is_accepted() {
    let mallory = Party::new();
    let bob = Party::new();
    let default_policy = atm(vec![bob.key_agreement.clone()], UnpackPolicy::default()).await;
    let bob_kid = bob.kid();
    let bob_public = bob.public();
    let to_bob = [(bob_kid.as_str(), &bob_public)];
    let mallory_kid = mallory.kid();

    let honest = forge(
        message(&mallory.did, &bob.did, "honest").as_bytes(),
        mallory_kid.as_bytes(),
        &mallory.private(),
        &to_bob,
        header_with(Some(&mallory_kid), Some(&mallory_kid)),
        None,
        None,
    );
    let (_, meta) = default_policy.unpack(&honest).await.unwrap();
    assert_eq!(
        meta.encrypted_from_kid.as_deref(),
        Some(mallory_kid.as_str())
    );
    let anoncrypted = encrypt::anoncrypt(honest.as_bytes(), &to_bob).unwrap();
    default_policy.unpack(&anoncrypted).await.unwrap();
    default_policy
        .unpack(&forward_to(&bob.did, &honest))
        .await
        .unwrap();
}
