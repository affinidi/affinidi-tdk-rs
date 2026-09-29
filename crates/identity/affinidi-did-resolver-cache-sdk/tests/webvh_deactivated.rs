//! A did:webvh whose log ends in a deactivation does not resolve.
//!
//! `didwebvh-rs` resolves such a log `Ok`, with the last document unchanged
//! and `deactivated` set only in the metadata this client never hands on — so
//! before, a retired DID kept verifying signatures with its last keys.
//!
//! Each test serves a real, signed log from a loopback listener (allowed by
//! `HostPolicy::AllowPrivate`).

#![cfg(feature = "did-webvh")]

use std::time::Duration;

use affinidi_did_resolver_cache_sdk::{
    DIDCacheClient, config::DIDCacheConfigBuilder, network_resolvers::HostPolicy,
};
use affinidi_secrets_resolver::secrets::Secret;
use didwebvh_rs::{DIDWebVHState, Multibase, log_entry::LogEntryMethods, parameters::Parameters};
use serde_json::json;
use std::sync::Arc;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    task::JoinHandle,
};

const RESOLVE_DEADLINE: Duration = Duration::from_secs(20);

/// A loopback HTTP listener serving `body` as `did.jsonl` to every request.
struct LogListener {
    port: u16,
    accept_task: JoinHandle<()>,
}

impl LogListener {
    async fn bind() -> (TcpListener, u16) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback listener");
        let port = listener.local_addr().expect("listener address").port();
        (listener, port)
    }

    fn serve(listener: TcpListener, port: u16, body: String) -> Self {
        let accept_task = tokio::spawn(async move {
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
        });
        Self { port, accept_task }
    }
}

impl Drop for LogListener {
    fn drop(&mut self) {
        self.accept_task.abort();
    }
}

/// Build a signed did:webvh log for `localhost:{port}`, deactivated or not.
/// Returns the DID and the log as JSONL.
async fn signed_log(port: u16, deactivate: bool) -> (String, String) {
    let mut key = Secret::generate_ed25519(None, None);
    let pk = key.get_public_keymultibase().expect("public key");
    key.id = format!("did:key:{pk}#{pk}");

    let did_template = format!("did:webvh:{{SCID}}:localhost%3A{port}");
    let doc = json!({
        "id": did_template,
        "@context": ["https://www.w3.org/ns/did/v1"],
        "verificationMethod": [{
            "id": format!("{did_template}#key-0"),
            "type": "Multikey",
            "publicKeyMultibase": pk,
            "controller": did_template
        }],
        "authentication": [format!("{did_template}#key-0")],
        "assertionMethod": [format!("{did_template}#key-0")],
    });
    let params = Parameters {
        update_keys: Some(Arc::new(vec![Multibase::new(pk)])),
        portable: Some(false),
        ..Default::default()
    };

    // Backdated so the deactivation entry's versionTime is strictly later.
    let genesis_time = (chrono::Utc::now() - chrono::Duration::seconds(100)).fixed_offset();
    let mut state = DIDWebVHState::default();
    state
        .create_log_entry(Some(genesis_time), &doc, &params, &key)
        .await
        .expect("genesis entry");
    if deactivate {
        state.deactivate(&key).await.expect("deactivation entry");
    }

    let did = state
        .log_entries()
        .last()
        .expect("an entry")
        .log_entry
        .get_did_document()
        .expect("document")["id"]
        .as_str()
        .expect("document id")
        .to_string();
    let jsonl = state
        .log_entries()
        .iter()
        .map(|entry| serde_json::to_string(&entry.log_entry).expect("serialize entry"))
        .collect::<Vec<_>>()
        .join("\n");
    (did, jsonl)
}

async fn serve_log(deactivate: bool) -> (LogListener, String) {
    let (listener, port) = LogListener::bind().await;
    let (did, jsonl) = signed_log(port, deactivate).await;
    (LogListener::serve(listener, port, jsonl), did)
}

async fn client() -> DIDCacheClient {
    DIDCacheClient::new(
        DIDCacheConfigBuilder::default()
            .with_host_policy(HostPolicy::AllowPrivate)
            .build(),
    )
    .await
    .expect("build cache client")
}

#[tokio::test]
async fn a_live_webvh_did_resolves() {
    let (listener, did) = serve_log(false).await;
    assert!(
        did.contains(&format!("localhost%3A{}", listener.port)),
        "{did}"
    );

    let response = tokio::time::timeout(RESOLVE_DEADLINE, client().await.resolve(&did))
        .await
        .expect("resolution finishes within the deadline")
        .expect("a live DID resolves");
    assert_eq!(response.doc.id.to_string(), did);
}

#[tokio::test]
async fn a_deactivated_webvh_did_does_not_resolve() {
    let (_listener, did) = serve_log(true).await;

    let error = tokio::time::timeout(RESOLVE_DEADLINE, client().await.resolve(&did))
        .await
        .expect("resolution finishes within the deadline")
        .expect_err("a deactivated DID must not hand back its last keys");
    let message = error.to_string();
    assert!(message.contains("deactivated"), "{message}");
    assert!(message.contains(&did), "{message}");
}
