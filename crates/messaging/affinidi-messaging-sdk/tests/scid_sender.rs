//! A did:scid identity sends authcrypt DIDComm as itself.
//!
//! The sender presents `did:scid:vh:1:<scid>?src=…` as `from`; its document
//! lists its keys under the bare DID (VTI-KEY-161). A recipient that has never
//! seen the sender resolves it from the `skid`, which carries the same `src`
//! (VTI-KEY-163), binds the sender by DID (ignoring `src`), and can then
//! resolve the bare DID through the source it learned.

use std::sync::Arc;

use affinidi_did_common::{DID, PeerCreateKey, PeerKeyPurpose, PeerKeyType};
use affinidi_did_resolver_cache_sdk::{
    DIDCacheClient, config::DIDCacheConfigBuilder, network_resolvers::HostPolicy,
};
use affinidi_messaging_didcomm::message::Message;
use affinidi_messaging_sdk::ATM;
use affinidi_messaging_sdk::config::ATMConfig;
use affinidi_secrets_resolver::SecretsResolver;
use affinidi_secrets_resolver::secrets::Secret;
use affinidi_tdk_common::TDKSharedState;
use affinidi_tdk_common::config::TDKConfig;
use didwebvh_rs::{DIDWebVHState, Multibase, log_entry::LogEntryMethods, parameters::Parameters};
use serde_json::json;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

/// Serves `body` as `did.jsonl` to every request on a loopback port.
async fn serve(listener: TcpListener, body: String) {
    while let Ok((mut stream, _)) = listener.accept().await {
        let body = body.clone();
        tokio::spawn(async move {
            let mut request = [0u8; 4096];
            let _ = stream.read(&mut request).await;
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: text/jsonl\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes()).await;
        });
    }
}

/// A did:scid sender: its log served on loopback, its DID URL with `src`, its
/// bare DID, and its key agreement secret under the bare DID.
async fn scid_sender() -> (String, String, Secret) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let mut update_key = Secret::generate_ed25519(None, None);
    let update_pk = update_key.get_public_keymultibase().unwrap();
    update_key.id = format!("did:key:{update_pk}#{update_pk}");
    let mut key_agreement = Secret::generate_x25519(None, None).unwrap();
    let ka_pk = key_agreement.get_public_keymultibase().unwrap();

    let template = format!("did:webvh:{{SCID}}:localhost%3A{port}");
    let doc = json!({
        "id": template,
        "@context": ["https://www.w3.org/ns/did/v1"],
        "verificationMethod": [{
            "id": format!("{template}#key-1"),
            "type": "Multikey",
            "publicKeyMultibase": ka_pk,
            "controller": template
        }],
        "keyAgreement": [format!("{template}#key-1")],
    });
    let params = Parameters {
        update_keys: Some(Arc::new(vec![Multibase::new(update_pk)])),
        portable: Some(false),
        ..Default::default()
    };
    let mut state = DIDWebVHState::default();
    state
        .create_log_entry(None, &doc, &params, &update_key)
        .await
        .unwrap();
    let jsonl = state
        .log_entries()
        .iter()
        .map(|entry| serde_json::to_string(&entry.log_entry).unwrap())
        .collect::<Vec<_>>()
        .join("\n");
    tokio::spawn(serve(listener, jsonl));

    let webvh_did = state.log_entries()[0].log_entry.get_did_document().unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let scid = webvh_did.split(':').nth(2).unwrap();
    let did = format!("did:scid:vh:1:{scid}");
    let did_url = format!("{did}?src=localhost:{port}");
    key_agreement.id = format!("{did}#key-1");
    (did_url, did, key_agreement)
}

/// A did:peer:2 recipient and its key agreement secret.
fn peer_recipient() -> (String, Secret) {
    let key_agreement = Secret::generate_x25519(None, None).unwrap();
    let keys = vec![
        PeerCreateKey::new(PeerKeyPurpose::Verification, PeerKeyType::Ed25519),
        PeerCreateKey::from_multibase(
            PeerKeyPurpose::Encryption,
            key_agreement.get_public_keymultibase().unwrap(),
        ),
    ];
    let (did, _) = DID::generate_peer(&keys, None).unwrap();
    let did = did.to_string();
    let mut key_agreement = key_agreement;
    key_agreement.id = format!("{did}#key-2");
    (did, key_agreement)
}

/// An ATM with its own resolver (so its own did:scid sources), allowed to
/// resolve loopback hosts.
async fn atm(secret: Secret) -> ATM {
    let resolver = DIDCacheClient::new(
        DIDCacheConfigBuilder::default()
            .with_host_policy(HostPolicy::AllowPrivate)
            .build(),
    )
    .await
    .unwrap();
    let tdk_config = TDKConfig::builder()
        .with_load_environment(false)
        .with_did_resolver(resolver)
        .build()
        .unwrap();
    let tdk = Arc::new(TDKSharedState::new(tdk_config).await.unwrap());
    tdk.secrets_resolver().insert(secret).await;
    ATM::new(ATMConfig::builder().build().unwrap(), tdk)
        .await
        .unwrap()
}

#[tokio::test]
async fn a_did_scid_sender_is_resolved_and_bound_on_first_contact() {
    let (sender_url, sender_did, sender_secret) = scid_sender().await;
    let (recipient_did, recipient_secret) = peer_recipient();
    let sender = atm(sender_secret).await;
    let recipient = atm(recipient_secret).await;

    let message = Message::build("m-1".to_string(), "example/v1".to_string(), json!({"k": 1}))
        .from(sender_url.clone())
        .to(recipient_did.clone())
        .finalize();
    let (packed, packed_meta) = sender
        .pack_encrypted(&message, &recipient_did, Some(&sender_url), None)
        .await
        .expect("packs as the did:scid");
    // The skid is the document's key, with the src the recipient needs.
    assert_eq!(
        packed_meta.from_kid.as_deref(),
        Some(format!("{sender_url}#key-1").as_str())
    );

    let (received, meta) = recipient
        .unpack(&packed)
        .await
        .expect("the recipient resolves the sender from the skid's src");
    assert!(meta.authenticated);
    assert_eq!(received.from.as_deref(), Some(sender_url.as_str()));

    // Having resolved it once, the recipient can address the bare DID.
    let doc = recipient
        .get_tdk()
        .did_resolver()
        .resolve(&sender_did)
        .await
        .expect("bare DID resolves through the learned source");
    assert_eq!(doc.doc.id.as_str(), sender_did);
}
