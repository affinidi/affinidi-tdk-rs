//! Hand-built authcrypt JWEs that name a sender other than the key that
//! encrypted them, or name it ambiguously, must never decrypt as that sender.

mod support;

use affinidi_crypto::jose::{Curve, PrivateKeyAgreement};
use affinidi_messaging_didcomm::{
    DIDCommAgent, DIDCommError, Message, SenderKey, SignerKey, UnpackResult,
    identity::PrivateIdentity,
    jwe::decrypt::{authcrypt_sender_kid, decrypt_bound},
    jws::verify::VerifyKey,
    message::{pack, unpack},
};
use support::forge::{b64, forge, header_with};

const ALICE: &str = "did:example:alice#key-agreement-1";
const MALLORY: &str = "did:example:mallory#key-agreement-1";
const BOB: &str = "did:example:bob#key-agreement-1";

fn plaintext_from(from: &str) -> Vec<u8> {
    Message::new("https://example.com/t", serde_json::json!({"x": 1}))
        .from(from)
        .to(vec!["did:example:bob".into()])
        .to_json()
        .unwrap()
}

struct Keys {
    alice: PrivateKeyAgreement,
    mallory: PrivateKeyAgreement,
    bob: PrivateKeyAgreement,
}

fn keys() -> Keys {
    Keys {
        alice: PrivateKeyAgreement::generate(Curve::X25519),
        mallory: PrivateKeyAgreement::generate(Curve::X25519),
        bob: PrivateKeyAgreement::generate(Curve::X25519),
    }
}

/// Every bound entry point refuses `jwe`, whichever sender key is offered.
fn refused_by_every_entry_point(jwe: &str, keys: &Keys) {
    let alice = keys.alice.public_key();
    let mallory = keys.mallory.public_key();
    for sender in [
        None,
        Some(SenderKey::new(ALICE, &alice)),
        Some(SenderKey::new(MALLORY, &mallory)),
        Some(SenderKey::new(MALLORY, &alice)),
    ] {
        let kid = sender.map(|sender| sender.kid());
        assert!(
            decrypt_bound(jwe, BOB, &keys.bob, sender).is_err(),
            "decrypt_bound with {kid:?}"
        );
        assert!(
            unpack::unpack_bound(jwe, Some(BOB), Some(&keys.bob), sender, None).is_err(),
            "unpack_bound with {kid:?}"
        );
        assert!(
            pack::unpack_encrypted_bound(jwe, BOB, &keys.bob, sender).is_err(),
            "unpack_encrypted_bound with {kid:?}"
        );
    }
}

#[test]
fn skid_naming_the_sender_and_apu_another_is_refused() {
    let keys = keys();
    let bob = keys.bob.public_key();
    for kdf_apu in [ALICE, MALLORY] {
        let jwe = forge(
            &plaintext_from("did:example:alice"),
            kdf_apu.as_bytes(),
            &keys.mallory,
            &[(BOB, &bob)],
            header_with(Some(MALLORY), Some(ALICE)),
            None,
            None,
        );
        assert!(matches!(
            authcrypt_sender_kid(&jwe),
            Err(DIDCommError::SenderKeyBinding(_))
        ));
        refused_by_every_entry_point(&jwe, &keys);
    }
}

#[test]
fn skid_and_apu_naming_a_key_the_sender_does_not_hold_is_refused() {
    let keys = keys();
    let bob = keys.bob.public_key();
    let jwe = forge(
        &plaintext_from("did:example:alice"),
        ALICE.as_bytes(),
        &keys.mallory,
        &[(BOB, &bob)],
        header_with(Some(ALICE), Some(ALICE)),
        None,
        None,
    );
    assert_eq!(authcrypt_sender_kid(&jwe).unwrap().as_deref(), Some(ALICE));
    refused_by_every_entry_point(&jwe, &keys);
}

/// The helper builds valid authcrypt when the header is honest, so the
/// refusals above are due to the header and not to the helper.
#[test]
fn honest_header_from_the_helper_decrypts() {
    let keys = keys();
    let bob = keys.bob.public_key();
    let mallory = keys.mallory.public_key();
    let jwe = forge(
        &plaintext_from("did:example:mallory"),
        MALLORY.as_bytes(),
        &keys.mallory,
        &[(BOB, &bob)],
        header_with(Some(MALLORY), Some(MALLORY)),
        None,
        None,
    );
    let result = decrypt_bound(
        &jwe,
        BOB,
        &keys.bob,
        Some(SenderKey::new(MALLORY, &mallory)),
    )
    .unwrap();
    assert_eq!(result.sender_kid.as_deref(), Some(MALLORY));
}

#[test]
fn duplicate_header_members_are_refused() {
    let keys = keys();
    let bob = keys.bob.public_key();
    let mallory = keys.mallory.public_key();
    let members = [
        format!(
            r#""skid":"{ALICE}","skid":"{MALLORY}","apu":"{}""#,
            b64(MALLORY.as_bytes())
        ),
        format!(
            r#""skid":"{MALLORY}","skid":"{ALICE}","apu":"{}""#,
            b64(MALLORY.as_bytes())
        ),
        format!(
            r#""skid":"{MALLORY}","apu":"{}","apu":"{}""#,
            b64(MALLORY.as_bytes()),
            b64(ALICE.as_bytes())
        ),
        format!(
            r#""skid":"{MALLORY}","apu":"{}","apu":"{}""#,
            b64(ALICE.as_bytes()),
            b64(MALLORY.as_bytes())
        ),
    ];
    for members in members {
        let header_members = members.clone();
        let jwe = forge(
            &plaintext_from("did:example:alice"),
            MALLORY.as_bytes(),
            &keys.mallory,
            &[(BOB, &bob)],
            move |epk, apv| {
                format!(
                    r#"{{"typ":"application/didcomm-encrypted+json","alg":"ECDH-1PU+A256KW","enc":"A256CBC-HS512",{header_members},"apv":"{apv}","epk":{epk}}}"#
                )
            },
            None,
            None,
        );
        assert!(
            decrypt_bound(
                &jwe,
                BOB,
                &keys.bob,
                Some(SenderKey::new(MALLORY, &mallory))
            )
            .is_err(),
            "accepted {members}"
        );
        assert!(authcrypt_sender_kid(&jwe).is_err());
    }

    let jwe = forge(
        &plaintext_from("did:example:alice"),
        MALLORY.as_bytes(),
        &keys.mallory,
        &[(BOB, &bob)],
        |epk, apv| {
            format!(
                r#"{{"alg":"ECDH-ES+A256KW","alg":"ECDH-1PU+A256KW","enc":"A256CBC-HS512","skid":"{MALLORY}","apu":"{}","apv":"{apv}","epk":{epk}}}"#,
                b64(MALLORY.as_bytes())
            )
        },
        None,
        None,
    );
    assert!(
        decrypt_bound(
            &jwe,
            BOB,
            &keys.bob,
            Some(SenderKey::new(MALLORY, &mallory))
        )
        .is_err()
    );
}

/// `skid`/`apu` outside the protected header are not integrity-protected and
/// are ignored.
#[test]
fn sender_members_outside_the_protected_header_are_ignored() {
    let keys = keys();
    let bob = keys.bob.public_key();
    let mallory = keys.mallory.public_key();
    let jwe = forge(
        &plaintext_from("did:example:alice"),
        MALLORY.as_bytes(),
        &keys.mallory,
        &[(BOB, &bob)],
        header_with(Some(MALLORY), Some(MALLORY)),
        Some(serde_json::json!({
            "unprotected": {"skid": ALICE, "apu": b64(ALICE.as_bytes())},
            "header": {"skid": ALICE},
        })),
        Some(serde_json::json!({"skid": ALICE})),
    );
    assert_eq!(
        authcrypt_sender_kid(&jwe).unwrap().as_deref(),
        Some(MALLORY)
    );
    let result = decrypt_bound(
        &jwe,
        BOB,
        &keys.bob,
        Some(SenderKey::new(MALLORY, &mallory)),
    )
    .unwrap();
    assert_eq!(result.sender_kid.as_deref(), Some(MALLORY));

    let jwe = forge(
        &plaintext_from("did:example:alice"),
        ALICE.as_bytes(),
        &keys.mallory,
        &[(BOB, &bob)],
        header_with(None, Some(ALICE)),
        Some(serde_json::json!({"unprotected": {"skid": ALICE}})),
        Some(serde_json::json!({"skid": ALICE})),
    );
    refused_by_every_entry_point(&jwe, &keys);
}

#[test]
fn key_ids_are_compared_exactly() {
    let keys = keys();
    let bob = keys.bob.public_key();
    let mallory = keys.mallory.public_key();
    for skid in [
        "did:example:mallory#key-agreement-1 ",
        " did:example:mallory#key-agreement-1",
        "did:example:mallory#KEY-AGREEMENT-1",
        "did:example:mallory%23key-agreement-1",
        "did:example:mallory#key-agreement-1\u{0}",
        "did:example:mallory?x=1#key-agreement-1",
    ] {
        let jwe = forge(
            &plaintext_from("did:example:mallory"),
            skid.as_bytes(),
            &keys.mallory,
            &[(BOB, &bob)],
            header_with(Some(skid), Some(skid)),
            None,
            None,
        );
        assert!(
            decrypt_bound(
                &jwe,
                BOB,
                &keys.bob,
                Some(SenderKey::new(MALLORY, &mallory))
            )
            .is_err(),
            "{skid:?} matched {MALLORY}"
        );
    }
    for skid in ["did:example:mallory", "#key-1", "did:example:mallory#", ""] {
        let jwe = forge(
            &plaintext_from("did:example:mallory"),
            skid.as_bytes(),
            &keys.mallory,
            &[(BOB, &bob)],
            header_with(Some(skid), Some(skid)),
            None,
            None,
        );
        assert!(authcrypt_sender_kid(&jwe).is_err(), "accepted {skid:?}");
        assert!(decrypt_bound(&jwe, BOB, &keys.bob, Some(SenderKey::new(skid, &mallory))).is_err());
    }
}

#[test]
fn compact_serialisation_is_refused() {
    let keys = keys();
    let mallory = keys.mallory.public_key();
    let compact = "eyJhbGciOiJFQ0RILTFQVStBMjU2S1cifQ.a.b.c.d";
    assert!(
        decrypt_bound(
            compact,
            BOB,
            &keys.bob,
            Some(SenderKey::new(MALLORY, &mallory))
        )
        .is_err()
    );
    assert!(authcrypt_sender_kid(compact).is_err());
}

#[test]
fn forgery_to_several_recipients_is_refused() {
    let keys = keys();
    let bob = keys.bob.public_key();
    let carol = PrivateKeyAgreement::generate(Curve::X25519).public_key();
    let jwe = forge(
        &plaintext_from("did:example:alice"),
        ALICE.as_bytes(),
        &keys.mallory,
        &[("did:example:carol#k", &carol), (BOB, &bob)],
        header_with(Some(MALLORY), Some(ALICE)),
        None,
        None,
    );
    refused_by_every_entry_point(&jwe, &keys);
}

/// The key-only entry points cannot tell whose key they are given, so they
/// refuse any authcrypt JWE a sender key is passed for.
#[test]
#[allow(deprecated)]
fn deprecated_key_only_entry_points_refuse_authcrypt() {
    use affinidi_messaging_didcomm::jwe::decrypt::decrypt;

    let keys = keys();
    let bob = keys.bob.public_key();
    let alice = keys.alice.public_key();
    let mallory = keys.mallory.public_key();

    let forged = forge(
        &plaintext_from("did:example:alice"),
        ALICE.as_bytes(),
        &keys.mallory,
        &[(BOB, &bob)],
        header_with(Some(MALLORY), Some(ALICE)),
        None,
        None,
    );
    let named_alice = forge(
        &plaintext_from("did:example:alice"),
        ALICE.as_bytes(),
        &keys.mallory,
        &[(BOB, &bob)],
        header_with(Some(ALICE), Some(ALICE)),
        None,
        None,
    );
    for jwe in [&forged, &named_alice] {
        for public in [None, Some(&alice), Some(&mallory)] {
            assert!(decrypt(jwe, BOB, &keys.bob, public).is_err());
            assert!(unpack::unpack(jwe, Some(BOB), Some(&keys.bob), public, None).is_err());
            assert!(pack::unpack_encrypted(jwe, BOB, &keys.bob, public).is_err());
        }
    }

    // Mallory's key, which a caller might hold for the peer it expects,
    // must not authenticate a JWE naming Alice.
    assert!(matches!(
        decrypt(&named_alice, BOB, &keys.bob, Some(&mallory)),
        Err(DIDCommError::SenderKeyBinding(_))
    ));
}

/// A JWS whose header names Alice's key but which Mallory signed is not
/// reported as Alice's.
#[test]
fn jws_signer_is_the_key_it_verified_under() {
    let mallory = PrivateIdentity::generate("did:example:mallory");
    let alice = PrivateIdentity::generate("did:example:alice");
    let alice_kid = alice.signing_kid.clone().unwrap();
    let mallory_kid = mallory.signing_kid.clone().unwrap();
    let mallory_key = VerifyKey::Ed25519(mallory.verifying_key().unwrap());
    let alice_key = VerifyKey::Ed25519(alice.verifying_key().unwrap());

    let msg = Message::new("t", serde_json::json!({})).from("did:example:alice");
    let jws =
        pack::pack_signed(&msg, &alice_kid, mallory.signing_private.as_ref().unwrap()).unwrap();

    assert!(matches!(
        unpack::unpack_bound(
            &jws,
            None,
            None,
            None,
            Some(SignerKey::new(&mallory_kid, &mallory_key))
        ),
        Err(DIDCommError::SignerKeyBinding(_))
    ));
    assert!(
        unpack::unpack_bound(
            &jws,
            None,
            None,
            None,
            Some(SignerKey::new(&alice_kid, &alice_key))
        )
        .is_err()
    );

    let mut agent = DIDCommAgent::new();
    agent.add_peer(mallory.to_resolved());
    agent.add_peer(alice.to_resolved());
    assert!(agent.unpack(&jws, Some("did:example:mallory")).is_err());
    assert!(agent.unpack(&jws, Some("did:example:alice")).is_err());

    let honest = pack::pack_signed(
        &msg,
        &mallory_kid,
        mallory.signing_private.as_ref().unwrap(),
    )
    .unwrap();
    match agent.unpack(&honest, Some("did:example:mallory")).unwrap() {
        UnpackResult::Signed { signer_kid, .. } => {
            assert_eq!(signer_kid.as_deref(), Some(mallory_kid.as_str()))
        }
        _ => panic!("expected Signed"),
    }
}

#[cfg(feature = "messaging-core")]
mod adapter {
    use super::*;
    use affinidi_messaging_core::MessagingProtocol;
    use affinidi_messaging_didcomm::adapter::DIDCommAdapter;

    #[tokio::test]
    async fn agent_and_adapter_refuse_a_sender_other_than_the_key() {
        let alice = PrivateIdentity::generate("did:example:alice");
        let mallory = PrivateIdentity::generate("did:example:mallory");
        let bob = PrivateIdentity::generate("did:example:bob");
        let mallory_kid = mallory.key_agreement_kid.clone();
        let alice_kid = alice.key_agreement_kid.clone();
        let bob_kid = bob.key_agreement_kid.clone();
        let bob_public = bob.public_key_agreement();

        let mut bob_agent = DIDCommAgent::new();
        bob_agent.add_peer(alice.to_resolved());
        bob_agent.add_peer(mallory.to_resolved());
        bob_agent.add_identity(bob);
        let adapter = DIDCommAdapter::new(bob_agent);
        let to_bob = [(bob_kid.as_str(), &bob_public)];
        let mallory_private = &mallory.key_agreement_private;

        // skid = Mallory, apu = Alice, from = Alice.
        let jwe = forge(
            &plaintext_from("did:example:alice"),
            alice_kid.as_bytes(),
            mallory_private,
            &to_bob,
            header_with(Some(&mallory_kid), Some(&alice_kid)),
            None,
            None,
        );
        for expected in [None, Some("did:example:alice"), Some("did:example:mallory")] {
            assert!(adapter.agent().unpack(&jwe, expected).is_err());
        }
        assert!(adapter.unpack(jwe.as_bytes()).await.is_err());

        // Honest header from Mallory, but `from` claims Alice.
        let jwe = forge(
            &plaintext_from("did:example:alice"),
            mallory_kid.as_bytes(),
            mallory_private,
            &to_bob,
            header_with(Some(&mallory_kid), Some(&mallory_kid)),
            None,
            None,
        );
        match adapter
            .agent()
            .unpack(&jwe, Some("did:example:mallory"))
            .unwrap()
        {
            UnpackResult::Encrypted { sender_kid, .. } => {
                assert_eq!(sender_kid.as_deref(), Some(mallory_kid.as_str()))
            }
            _ => panic!("expected Encrypted"),
        }
        assert!(
            adapter
                .agent()
                .unpack(&jwe, Some("did:example:alice"))
                .is_err()
        );
        assert!(adapter.unpack(jwe.as_bytes()).await.is_err());

        // skid = apu = Alice, encrypted with Mallory's key.
        let jwe = forge(
            &plaintext_from("did:example:alice"),
            alice_kid.as_bytes(),
            mallory_private,
            &to_bob,
            header_with(Some(&alice_kid), Some(&alice_kid)),
            None,
            None,
        );
        assert!(
            adapter
                .agent()
                .unpack(&jwe, Some("did:example:alice"))
                .is_err()
        );
        assert!(adapter.unpack(jwe.as_bytes()).await.is_err());

        // Mallory as herself, without `from`.
        let jwe = forge(
            &Message::new("t", serde_json::json!({})).to_json().unwrap(),
            mallory_kid.as_bytes(),
            mallory_private,
            &to_bob,
            header_with(Some(&mallory_kid), Some(&mallory_kid)),
            None,
            None,
        );
        let received = adapter.unpack(jwe.as_bytes()).await.unwrap();
        assert_eq!(received.sender.as_deref(), Some("did:example:mallory"));
        assert!(received.verified);
    }
}
