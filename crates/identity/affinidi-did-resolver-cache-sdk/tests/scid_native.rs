//! A did:scid:vh:1 DID resolves to its own document, under the bare DID.
//!
//! `?src=` is a locator, not part of the identity (VTI-KEY-160): a resolved
//! document's `id` is `did:scid:vh:1:<scid>` and its keys are under it, the bare
//! DID resolves through the source last seen for its SCID, and a source serving
//! an older copy of the log than one already verified is refused (VTI-KEY-162).
//!
//! Each test serves a real, signed log from a loopback listener (allowed by
//! `HostPolicy::AllowPrivate`).

#![cfg(feature = "did-scid")]

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use affinidi_did_resolver_cache_sdk::{
    DIDCacheClient, config::DIDCacheConfigBuilder, network_resolvers::HostPolicy,
};
use affinidi_secrets_resolver::secrets::Secret;
use didwebvh_rs::{DIDWebVHState, Multibase, log_entry::LogEntryMethods, parameters::Parameters};
use serde_json::{Value, json};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    task::JoinHandle,
};

const RESOLVE_DEADLINE: Duration = Duration::from_secs(20);

/// A loopback HTTP listener serving whatever `body` holds as `did.jsonl`.
struct LogListener {
    port: u16,
    body: Arc<Mutex<String>>,
    accept_task: JoinHandle<()>,
}

impl LogListener {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback listener");
        let port = listener.local_addr().expect("listener address").port();
        let body = Arc::new(Mutex::new(String::new()));
        let served = body.clone();
        let accept_task = tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let body = served.lock().unwrap().clone();
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
        Self {
            port,
            body,
            accept_task,
        }
    }

    fn serve(&self, jsonl: &str) {
        *self.body.lock().unwrap() = jsonl.to_string();
    }
}

impl Drop for LogListener {
    fn drop(&mut self) {
        self.accept_task.abort();
    }
}

/// A signed did:webvh log for `localhost:{port}`, as JSONL after each entry.
/// `versions` entries are written; the did:webvh DID is returned with them.
async fn signed_log(port: u16, versions: usize) -> (String, Vec<String>) {
    let mut key = Secret::generate_ed25519(None, None);
    let pk = key.get_public_keymultibase().expect("public key");
    key.id = format!("did:key:{pk}#{pk}");

    let did_template = format!("did:webvh:{{SCID}}:localhost%3A{port}");
    let mut doc = json!({
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

    let start = chrono::Utc::now() - chrono::Duration::seconds(100);
    let mut state = DIDWebVHState::default();
    let mut logs = vec![];
    for version in 0..versions {
        let time = (start + chrono::Duration::seconds(version as i64 * 10)).fixed_offset();
        state
            .create_log_entry(Some(time), &doc, &params, &key)
            .await
            .expect("log entry");
        logs.push(
            state
                .log_entries()
                .iter()
                .map(|entry| serde_json::to_string(&entry.log_entry).expect("serialize entry"))
                .collect::<Vec<_>>()
                .join("\n"),
        );
        // The next version is a real change, under the DID the log now has.
        doc = state
            .log_entries()
            .last()
            .unwrap()
            .log_entry
            .get_did_document()
            .expect("document");
        doc["alsoKnownAs"] = json!([format!("https://example.com/v{version}")]);
    }

    let did = state
        .log_entries()
        .last()
        .unwrap()
        .log_entry
        .get_did_document()
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    (did, logs)
}

/// The did:scid DID and DID URL of a `did:webvh:<scid>:localhost%3A<port>` DID.
fn scid_forms(webvh_did: &str, port: u16) -> (String, String) {
    let scid = webvh_did.split(':').nth(2).unwrap();
    (
        format!("did:scid:vh:1:{scid}"),
        format!("did:scid:vh:1:{scid}?src=localhost:{port}"),
    )
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

async fn resolve(
    client: &DIDCacheClient,
    did: &str,
) -> Result<affinidi_did_common::Document, String> {
    tokio::time::timeout(RESOLVE_DEADLINE, client.resolve(did))
        .await
        .expect("resolution finishes within the deadline")
        .map(|response| response.doc)
        .map_err(|e| e.to_string())
}

#[tokio::test]
async fn resolves_to_its_own_document_under_the_bare_did() {
    let listener = LogListener::start().await;
    let (webvh, logs) = signed_log(listener.port, 1).await;
    listener.serve(&logs[0]);
    let (did, url) = scid_forms(&webvh, listener.port);

    let doc = resolve(&client().await, &url).await.expect("resolves");

    assert_eq!(doc.id.as_str(), did);
    let doc = serde_json::to_value(&doc).unwrap();
    assert_eq!(doc["verificationMethod"][0]["id"], format!("{did}#key-0"));
    assert_eq!(doc["verificationMethod"][0]["controller"], did);
    assert_eq!(doc["authentication"][0], format!("{did}#key-0"));
    let aliases: Vec<&str> = doc["alsoKnownAs"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(aliases.contains(&webvh.as_str()), "{aliases:?}");
}

#[tokio::test]
async fn bare_did_resolves_through_the_source_last_seen() {
    let listener = LogListener::start().await;
    let (webvh, logs) = signed_log(listener.port, 1).await;
    listener.serve(&logs[0]);
    let (did, url) = scid_forms(&webvh, listener.port);
    let client = client().await;

    resolve(&client, &url).await.expect("resolves with src");
    // Out of the cache, so this resolves over the network again.
    client
        .remove(&did)
        .await
        .expect("cached under the bare DID");

    let doc = resolve(&client, &did).await.expect("resolves without src");
    assert_eq!(doc.id.as_str(), did);
}

#[tokio::test]
async fn bare_did_with_no_known_source_does_not_resolve() {
    let listener = LogListener::start().await;
    let (webvh, logs) = signed_log(listener.port, 1).await;
    listener.serve(&logs[0]);
    let (did, _) = scid_forms(&webvh, listener.port);

    let error = resolve(&client().await, &did).await.expect_err("no source");
    assert!(error.contains("no source"), "{error}");
}

#[tokio::test]
async fn a_seeded_source_resolves_the_bare_did() {
    let listener = LogListener::start().await;
    let (webvh, logs) = signed_log(listener.port, 1).await;
    listener.serve(&logs[0]);
    let (did, url) = scid_forms(&webvh, listener.port);
    let client = client().await;

    assert!(client.scid_sources().add_source(&url));
    let doc = resolve(&client, &did).await.expect("resolves");
    assert_eq!(doc.id.as_str(), did);
}

#[tokio::test]
async fn an_older_copy_of_the_log_is_refused() {
    let listener = LogListener::start().await;
    let (webvh, logs) = signed_log(listener.port, 2).await;
    let (did, url) = scid_forms(&webvh, listener.port);
    let client = client().await;

    listener.serve(&logs[1]);
    resolve(&client, &url)
        .await
        .expect("latest version resolves");

    // The source now serves the first version only, as a stale mirror would.
    listener.serve(&logs[0]);
    client.remove(&did).await;
    let error = resolve(&client, &url).await.expect_err("rolled back");
    assert!(error.contains("behind"), "{error}");
}
