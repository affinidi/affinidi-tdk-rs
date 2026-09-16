//! A DID host that refuses a fetch reaches the caller as a typed
//! `DIDCacheError::NetworkFetch` carrying the HTTP status, not as a string that
//! reads the same as an invalid DID.
//!
//! Each test serves did:webvh from a loopback listener (allowed by
//! `HostPolicy::AllowPrivate`) that answers every request with a fixed status.

#![cfg(feature = "did-webvh")]

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

const SCID: &str = "Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai";

const RESOLVE_DEADLINE: Duration = Duration::from_secs(20);

/// A loopback HTTP listener answering every request with `status_line`, after
/// `delay`, and counting the requests it receives.
struct StatusListener {
    port: u16,
    requests: Arc<AtomicUsize>,
    accept_task: JoinHandle<()>,
}

impl StatusListener {
    async fn start(status_line: &'static str, delay: Duration) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback listener");
        let port = listener.local_addr().expect("listener address").port();
        let requests = Arc::new(AtomicUsize::new(0));
        let counter = requests.clone();
        let accept_task = tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let counter = counter.clone();
                tokio::spawn(async move {
                    let mut request = [0u8; 4096];
                    if matches!(stream.read(&mut request).await, Ok(read) if read > 0) {
                        counter.fetch_add(1, Ordering::SeqCst);
                    }
                    tokio::time::sleep(delay).await;
                    let response = format!(
                        "HTTP/1.1 {status_line}\r\nretry-after: 30\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                });
            }
        });
        Self {
            port,
            requests,
            accept_task,
        }
    }

    fn did(&self) -> String {
        format!("did:webvh:{SCID}:localhost%3A{}", self.port)
    }
}

impl Drop for StatusListener {
    fn drop(&mut self) {
        self.accept_task.abort();
    }
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

async fn resolve(client: &DIDCacheClient, did: &str) -> DIDCacheError {
    tokio::time::timeout(RESOLVE_DEADLINE, client.resolve(did))
        .await
        .expect("resolution finishes within the deadline")
        .expect_err("the listener serves no log")
}

#[tokio::test]
async fn webvh_http_429_is_a_typed_rate_limit() {
    let listener = StatusListener::start("429 Too Many Requests", Duration::ZERO).await;

    let error = resolve(&client().await, &listener.did()).await;

    let DIDCacheError::NetworkFetch(fetch) = &error else {
        panic!("expected NetworkFetch, got {error:?}");
    };
    assert!(fetch.is_rate_limited(), "{fetch:?}");
    assert_eq!(fetch.status, Some(429));
    let url = fetch.url.as_deref().expect("the fetched URL is recorded");
    assert!(
        url.contains(&format!("localhost:{}", listener.port)),
        "{url}"
    );
    assert!(url.ends_with("did.jsonl"), "{url}");
    assert_eq!(
        error.to_string(),
        format!("DID host {url} rate-limited resolution (HTTP 429)")
    );
}

#[tokio::test]
async fn webvh_http_404_keeps_its_status_and_is_not_a_rate_limit() {
    let listener = StatusListener::start("404 Not Found", Duration::ZERO).await;

    let error = resolve(&client().await, &listener.did()).await;

    let DIDCacheError::NetworkFetch(fetch) = &error else {
        panic!("expected NetworkFetch, got {error:?}");
    };
    assert_eq!(fetch.status, Some(404));
    assert!(!fetch.is_rate_limited());
}

/// Concurrent resolutions of a DID whose host is rate-limiting make one fetch,
/// and every caller gets the typed error. Before, each waiter became the next
/// leader in turn and fetched again — N callers, N requests to a host that had
/// just asked us to back off.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_resolutions_of_a_rate_limited_did_fetch_once() {
    let listener = StatusListener::start("429 Too Many Requests", Duration::from_millis(300)).await;
    let client = client().await;
    let did = listener.did();

    let mut callers = Vec::new();
    for _ in 0..8 {
        let client = client.clone();
        let did = did.clone();
        callers.push(tokio::spawn(async move { resolve(&client, &did).await }));
    }
    for caller in callers {
        let error = caller.await.expect("caller task");
        assert!(
            matches!(&error, DIDCacheError::NetworkFetch(fetch) if fetch.is_rate_limited()),
            "{error:?}"
        );
    }
    assert_eq!(listener.requests.load(Ordering::SeqCst), 1);

    // The failure was shared, not cached: the next resolution fetches again.
    resolve(&client, &did).await;
    assert_eq!(listener.requests.load(Ordering::SeqCst), 2);
}
