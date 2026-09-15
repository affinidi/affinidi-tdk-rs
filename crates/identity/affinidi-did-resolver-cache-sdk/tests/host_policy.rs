//! Host policy through the resolver cache: one `DIDCacheConfigBuilder` setting
//! decides whether did:web and did:webvh resolution may contact a private host.
//!
//! Each test points a DID at a loopback TCP listener and counts the connections
//! it accepts. Nothing serves a valid document: under the default policy the
//! listener must see no connection at all, and under `AllowPrivate` reaching it
//! is the assertion.

use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use affinidi_did_resolver_cache_sdk::{
    DIDCacheClient, config::DIDCacheConfigBuilder, errors::DIDCacheError,
    network_resolvers::HostPolicy,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    task::JoinHandle,
};

#[cfg(feature = "did-webvh")]
const SCID: &str = "Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai";

const RESOLVE_DEADLINE: Duration = Duration::from_secs(20);

/// Long enough for a connection the resolver did open to be accepted and
/// counted before the test reads the counter.
const ACCEPT_GRACE: Duration = Duration::from_millis(200);

/// A loopback listener that answers every connection with a 404 and counts
/// the connections it accepts.
struct CountingListener {
    port: u16,
    connections: Arc<AtomicUsize>,
    accept_task: JoinHandle<()>,
}

impl CountingListener {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback listener");
        let port = listener.local_addr().expect("listener address").port();
        let connections = Arc::new(AtomicUsize::new(0));
        let counter = connections.clone();
        let accept_task = tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                counter.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    let mut request = [0u8; 4096];
                    let _ = stream.read(&mut request).await;
                    let _ = stream
                        .write_all(
                            b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
                        )
                        .await;
                });
            }
        });
        Self {
            port,
            connections,
            accept_task,
        }
    }

    async fn connections_after_grace(&self) -> usize {
        tokio::time::sleep(ACCEPT_GRACE).await;
        self.connections.load(Ordering::SeqCst)
    }
}

impl Drop for CountingListener {
    fn drop(&mut self) {
        self.accept_task.abort();
    }
}

async fn cache_client(policy: Option<HostPolicy>) -> DIDCacheClient {
    let mut builder = DIDCacheConfigBuilder::default();
    if let Some(policy) = policy {
        builder = builder.with_host_policy(policy);
    }
    DIDCacheClient::new(builder.build())
        .await
        .expect("build cache client")
}

async fn resolve(client: &DIDCacheClient, did: &str) -> Result<(), DIDCacheError> {
    tokio::time::timeout(RESOLVE_DEADLINE, client.resolve(did))
        .await
        .expect("resolution finishes within the deadline")
        .map(|_| ())
}

#[cfg(feature = "did-webvh")]
#[tokio::test]
async fn webvh_localhost_is_refused_by_default_without_connecting() {
    let listener = CountingListener::start().await;
    let did = format!("did:webvh:{SCID}:localhost%3A{}", listener.port);

    let error = resolve(&cache_client(None).await, &did)
        .await
        .expect_err("a localhost did:webvh must not resolve under the default policy");

    match error {
        DIDCacheError::DIDError(message) => {
            assert!(message.contains("BlockedHost"), "{message}");
        }
        other => panic!("expected a blocked-host DIDError, got {other:?}"),
    }
    assert_eq!(listener.connections_after_grace().await, 0);
}

#[cfg(feature = "did-webvh")]
#[tokio::test]
async fn webvh_localhost_is_contacted_under_allow_private() {
    let listener = CountingListener::start().await;
    let did = format!("did:webvh:{SCID}:localhost%3A{}", listener.port);

    let error = resolve(&cache_client(Some(HostPolicy::AllowPrivate)).await, &did)
        .await
        .expect_err("the listener serves no log");

    if let DIDCacheError::DIDError(message) = &error {
        assert!(!message.contains("BlockedHost"), "{message}");
    }
    assert!(
        listener.connections_after_grace().await > 0,
        "AllowPrivate must let resolution reach the local host ({error:?})"
    );
}

#[tokio::test]
async fn web_localhost_is_refused_by_default_without_connecting() {
    let listener = CountingListener::start().await;
    let did = format!("did:web:localhost%3A{}", listener.port);

    resolve(&cache_client(None).await, &did)
        .await
        .expect_err("a localhost did:web must not resolve under the default policy");

    assert_eq!(listener.connections_after_grace().await, 0);
}

#[tokio::test]
async fn web_localhost_is_contacted_under_allow_private() {
    let listener = CountingListener::start().await;
    let did = format!("did:web:localhost%3A{}", listener.port);

    let error = resolve(&cache_client(Some(HostPolicy::AllowPrivate)).await, &did)
        .await
        .expect_err("the listener serves no document");

    assert!(
        listener.connections_after_grace().await > 0,
        "the same setting must let did:web reach the local host ({error:?})"
    );
}
