//! End to end: envelopes that name a sender other than the key that
//! authenticated them are refused by the mediator and never reach the
//! recipient; honest forwards still deliver.

mod common;
#[path = "../../affinidi-messaging-didcomm/tests/support/forge.rs"]
mod forge;

use affinidi_crypto::jose::{Curve, PrivateKeyAgreement, PublicKeyAgreement};
use affinidi_did_common::document::DocumentExt;
use affinidi_messaging_didcomm::jwe::encrypt;
use affinidi_messaging_didcomm::message::pack;
use affinidi_messaging_didcomm::{Attachment, Message};
use affinidi_messaging_sdk::messages::fetch::FetchOptions;
use affinidi_messaging_test_mediator::{TestEnvironment, TestMediator, TestUser};
use forge::{b64, forge, header_with};
use serde_json::json;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

async fn key_agreement_public(env: &TestEnvironment, did: &str) -> (String, PublicKeyAgreement) {
    let doc = env.tdk.did_resolver().resolve(did).await.unwrap().doc;
    let kid = doc.find_key_agreement(None).first().unwrap().to_string();
    let kid = if kid.starts_with('#') {
        format!("{did}{kid}")
    } else {
        kid
    };
    let (_, bytes) = doc
        .get_verification_method(&kid)
        .unwrap()
        .decode_public_key()
        .unwrap();
    (
        kid,
        PublicKeyAgreement::from_raw_bytes(Curve::X25519, &bytes).unwrap(),
    )
}

fn key_agreement_private(user: &TestUser) -> (String, PrivateKeyAgreement) {
    let secret = user
        .secrets
        .iter()
        .find(|secret| secret.id.ends_with("#key-2"))
        .unwrap();
    (
        secret.id.clone(),
        PrivateKeyAgreement::from_raw_bytes(Curve::X25519, secret.get_private_bytes()).unwrap(),
    )
}

fn signing_private(user: &TestUser) -> (String, [u8; 32]) {
    let secret = user
        .secrets
        .iter()
        .find(|secret| secret.id.ends_with("#key-1"))
        .unwrap();
    (
        secret.id.clone(),
        secret.get_private_bytes().try_into().unwrap(),
    )
}

fn basic_message(from: &str, to: &str) -> Message {
    Message::build(
        Uuid::new_v4().to_string(),
        "https://didcomm.org/basicmessage/2.0/message",
        json!({"content": "hi"}),
    )
    .from(from.to_string())
    .to(to.to_string())
    .created_time(now())
    .expires_time(now() + 60)
    .finalize()
}

fn forward(from: Option<&str>, mediator: &str, next: &str, inner: &str) -> Message {
    let mut builder = Message::build(
        Uuid::new_v4().to_string(),
        "https://didcomm.org/routing/2.0/forward",
        json!({"next": next}),
    )
    .to(mediator.to_string())
    .expires_time(now() + 60)
    .attachment(Attachment::base64(b64(inner.as_bytes())).finalize());
    if let Some(from) = from {
        builder = builder.from(from.to_string());
    }
    builder.finalize()
}

fn json_string(message: &Message) -> String {
    String::from_utf8(message.to_json().unwrap()).unwrap()
}

async fn send(env: &TestEnvironment, sender: &TestUser, packed: &str) -> Result<(), String> {
    env.atm
        .send_message(
            &sender.profile,
            packed,
            &Uuid::new_v4().to_string(),
            false,
            false,
        )
        .await
        .map(|_| ())
        .map_err(|e| e.to_string())
}

async fn inbox(env: &TestEnvironment, user: &TestUser) -> Vec<String> {
    env.atm
        .fetch_messages(&user.profile, &FetchOptions::default())
        .await
        .unwrap()
        .success
        .into_iter()
        .map(|element| element.msg.unwrap_or_default())
        .collect()
}

async fn run(force_session_did_match: bool) {
    common::init_tracing();
    let mediator = TestMediator::builder()
        .force_session_did_match(force_session_did_match)
        .spawn()
        .await
        .unwrap();
    let env = TestEnvironment::new(mediator).await.unwrap();
    let alice = env.add_user("alice").await.unwrap();
    let mallory = env.add_user("mallory").await.unwrap();
    let bob = env.add_user("bob").await.unwrap();
    let mediator_did = env.mediator.did().to_string();
    let (mediator_kid, mediator_public) = key_agreement_public(&env, &mediator_did).await;
    let (bob_kid, bob_public) = key_agreement_public(&env, &bob.did).await;
    let (mallory_kid, mallory_private) = key_agreement_private(&mallory);
    let (alice_kid, _) = key_agreement_private(&alice);
    let to_mediator = [(mediator_kid.as_str(), &mediator_public)];
    let to_bob = [(bob_kid.as_str(), &bob_public)];

    let honest_inner = encrypt::authcrypt(
        &basic_message(&mallory.did, &bob.did).to_json().unwrap(),
        &mallory_kid,
        &mallory_private,
        &to_bob,
    )
    .unwrap();
    let forward_from_alice = json_string(&forward(
        Some(&alice.did),
        &mediator_did,
        &bob.did,
        &honest_inner,
    ));
    let forward_from_mallory = json_string(&forward(
        Some(&mallory.did),
        &mediator_did,
        &bob.did,
        &honest_inner,
    ));
    let to_mediator_as =
        |plaintext: &[u8], kdf_apu: &str, skid: Option<&str>, apu: Option<&str>| {
            forge(
                plaintext,
                kdf_apu.as_bytes(),
                &mallory_private,
                &to_mediator,
                header_with(skid, apu),
                None,
                None,
            )
        };

    let skid_mallory_apu_alice = to_mediator_as(
        forward_from_alice.as_bytes(),
        &alice_kid,
        Some(&mallory_kid),
        Some(&alice_kid),
    );
    let honest_header_from_alice = to_mediator_as(
        forward_from_alice.as_bytes(),
        &mallory_kid,
        Some(&mallory_kid),
        Some(&mallory_kid),
    );
    let (alice_signing_kid, alice_signing) = signing_private(&alice);
    let alice_signed_forward = pack::pack_signed(
        &forward(Some(&alice.did), &mediator_did, &bob.did, &honest_inner),
        &alice_signing_kid,
        &alice_signing,
    )
    .unwrap();
    let forged_inner = forge(
        &basic_message(&alice.did, &bob.did).to_json().unwrap(),
        alice_kid.as_bytes(),
        &mallory_private,
        &to_bob,
        header_with(Some(&mallory_kid), Some(&alice_kid)),
        None,
        None,
    );
    let ping_as_alice = Message::build(
        Uuid::new_v4().to_string(),
        "https://didcomm.org/trust-ping/2.0/ping",
        json!({"response_requested": false}),
    )
    .from(alice.did.clone())
    .to(mediator_did.clone())
    .created_time(now())
    .expires_time(now() + 60)
    .finalize()
    .to_json()
    .unwrap();

    let refused: Vec<(&str, String)> = vec![
        (
            "forward: skid mallory, apu alice",
            skid_mallory_apu_alice.clone(),
        ),
        (
            "forward: skid mallory, apu alice, KEK over skid",
            to_mediator_as(
                forward_from_alice.as_bytes(),
                &mallory_kid,
                Some(&mallory_kid),
                Some(&alice_kid),
            ),
        ),
        (
            "forward: skid = apu = alice, mallory's key",
            to_mediator_as(
                forward_from_alice.as_bytes(),
                &alice_kid,
                Some(&alice_kid),
                Some(&alice_kid),
            ),
        ),
        (
            "forward: honest header, from alice",
            honest_header_from_alice.clone(),
        ),
        (
            "forward: no skid",
            to_mediator_as(
                forward_from_alice.as_bytes(),
                &alice_kid,
                None,
                Some(&alice_kid),
            ),
        ),
        (
            "forward: no apu",
            forge(
                forward_from_alice.as_bytes(),
                b"",
                &mallory_private,
                &to_mediator,
                header_with(Some(&mallory_kid), None),
                None,
                None,
            ),
        ),
        (
            "anoncrypt(skid mallory, apu alice)",
            encrypt::anoncrypt(skid_mallory_apu_alice.as_bytes(), &to_mediator).unwrap(),
        ),
        (
            "anoncrypt(honest header, from alice)",
            encrypt::anoncrypt(honest_header_from_alice.as_bytes(), &to_mediator).unwrap(),
        ),
        (
            "anoncrypt(forward from alice)",
            encrypt::anoncrypt(forward_from_alice.as_bytes(), &to_mediator).unwrap(),
        ),
        (
            "authcrypt by mallory over a forward alice signed",
            encrypt::authcrypt(
                alice_signed_forward.as_bytes(),
                &mallory_kid,
                &mallory_private,
                &to_mediator,
            )
            .unwrap(),
        ),
        (
            "mallory's forward of a forged inner envelope",
            encrypt::authcrypt(
                json_string(&forward(
                    Some(&mallory.did),
                    &mediator_did,
                    &bob.did,
                    &forged_inner,
                ))
                .as_bytes(),
                &mallory_kid,
                &mallory_private,
                &to_mediator,
            )
            .unwrap(),
        ),
        (
            "ping: skid mallory, apu alice",
            to_mediator_as(
                &ping_as_alice,
                &alice_kid,
                Some(&mallory_kid),
                Some(&alice_kid),
            ),
        ),
        (
            "ping: honest header, from alice",
            to_mediator_as(
                &ping_as_alice,
                &mallory_kid,
                Some(&mallory_kid),
                Some(&mallory_kid),
            ),
        ),
    ];

    for (name, packed) in &refused {
        let result = send(&env, &mallory, packed).await;
        assert!(
            result.is_err(),
            "[force_session_did_match={force_session_did_match}] {name} was accepted"
        );
    }
    assert!(
        inbox(&env, &bob).await.is_empty(),
        "[force_session_did_match={force_session_did_match}] bob received a message from a forged send"
    );

    let honest = encrypt::authcrypt(
        forward_from_mallory.as_bytes(),
        &mallory_kid,
        &mallory_private,
        &to_mediator,
    )
    .unwrap();
    send(&env, &mallory, &honest)
        .await
        .expect("authcrypt forward");
    send(
        &env,
        &mallory,
        &encrypt::anoncrypt(honest.as_bytes(), &to_mediator).unwrap(),
    )
    .await
    .expect("anoncrypt(authcrypt) forward");
    let (mallory_signing_kid, mallory_signing) = signing_private(&mallory);
    let mallory_signed_forward = pack::pack_signed(
        &forward(Some(&mallory.did), &mediator_did, &bob.did, &honest_inner),
        &mallory_signing_kid,
        &mallory_signing,
    )
    .unwrap();
    send(
        &env,
        &mallory,
        &encrypt::authcrypt(
            mallory_signed_forward.as_bytes(),
            &mallory_kid,
            &mallory_private,
            &to_mediator,
        )
        .unwrap(),
    )
    .await
    .expect("authcrypt(sign) forward");
    send(
        &env,
        &mallory,
        &encrypt::anoncrypt(mallory_signed_forward.as_bytes(), &to_mediator).unwrap(),
    )
    .await
    .expect("anoncrypt(sign) forward");
    let (_, sdk_forward) = env
        .atm
        .routing()
        .forward_message(
            &mallory.profile,
            false,
            &honest_inner,
            &mediator_did,
            &bob.did,
            Some(now() + 60),
            None,
        )
        .await
        .unwrap();
    send(&env, &mallory, &sdk_forward)
        .await
        .expect("SDK forward");

    let delivered = inbox(&env, &bob).await;
    assert!(!delivered.is_empty());
    for message in &delivered {
        let (msg, meta) = env.atm.unpack(message).await.expect("honest delivery");
        assert_eq!(msg.from.as_deref(), Some(mallory.did.as_str()));
        assert_eq!(
            meta.encrypted_from_kid.as_deref(),
            Some(mallory_kid.as_str())
        );
    }

    // A forged envelope for Bob, relayed inside Mallory's honest forward. The
    // mediator cannot open it; Bob must refuse it.
    let forged_for_bob = forge(
        &basic_message(&alice.did, &bob.did).to_json().unwrap(),
        alice_kid.as_bytes(),
        &mallory_private,
        &to_bob,
        header_with(Some(&alice_kid), Some(&alice_kid)),
        None,
        None,
    );
    let relayed = json_string(&forward(
        Some(&mallory.did),
        &mediator_did,
        &bob.did,
        &forged_for_bob,
    ));
    let _ = send(
        &env,
        &mallory,
        &encrypt::authcrypt(
            relayed.as_bytes(),
            &mallory_kid,
            &mallory_private,
            &to_mediator,
        )
        .unwrap(),
    )
    .await;
    for message in inbox(&env, &bob).await {
        if !delivered.contains(&message) {
            assert!(env.atm.unpack(&message).await.is_err());
        }
    }

    env.shutdown().await.unwrap();
}

#[tokio::test]
async fn forged_senders_are_refused_without_session_did_match() {
    run(false).await;
}

#[tokio::test]
async fn forged_senders_are_refused_with_session_did_match() {
    run(true).await;
}
