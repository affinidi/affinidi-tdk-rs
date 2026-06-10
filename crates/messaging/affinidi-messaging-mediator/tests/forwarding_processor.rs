//! Forwarding processor over non-Redis backends.
//!
//! The `ForwardingProcessor` consumes the `forward_queue_*` methods on
//! `Arc<dyn MediatorStore>`, so it must deliver queued forwards
//! regardless of which storage backend is in use. These tests run it
//! against `MemoryStore` with a local stub standing in for the remote
//! mediator's `/inbound` endpoint.
//!
//! Run with: `cargo test -p affinidi-messaging-mediator --features memory-backend`
#![cfg(feature = "memory-backend")]

use affinidi_messaging_mediator::store::MemoryStore;
use affinidi_messaging_mediator_common::{
    store::{MediatorStore, types::ForwardQueueEntry},
    tasks::forwarding::{ForwardingConfig, ForwardingProcessor},
};
use axum::{Router, extract::State, http::StatusCode, routing::post};
use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
    time::Duration,
};
use tokio::sync::mpsc;

/// Stub remote mediator: answers `POST /inbound`, records each body on
/// the channel, and fails the first `fail_first` requests with HTTP 500
/// so tests can exercise the retry path.
struct StubMediator {
    endpoint_url: String,
    received: mpsc::UnboundedReceiver<String>,
}

async fn spawn_stub_mediator(fail_first: u32) -> StubMediator {
    #[derive(Clone)]
    struct StubState {
        tx: mpsc::UnboundedSender<String>,
        fail_remaining: Arc<AtomicU32>,
    }

    async fn inbound(State(state): State<StubState>, body: String) -> StatusCode {
        let _ = state.tx.send(body);
        if state
            .fail_remaining
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
            .is_ok()
        {
            StatusCode::INTERNAL_SERVER_ERROR
        } else {
            StatusCode::OK
        }
    }

    let (tx, rx) = mpsc::unbounded_channel();
    let app = Router::new()
        .route("/inbound", post(inbound))
        .with_state(StubState {
            tx,
            fail_remaining: Arc::new(AtomicU32::new(fail_first)),
        });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind stub mediator");
    let addr: SocketAddr = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("stub mediator serve");
    });

    StubMediator {
        endpoint_url: format!("http://{addr}"),
        received: rx,
    }
}

fn forward_entry(endpoint_url: &str, message: &str) -> ForwardQueueEntry {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_millis();
    ForwardQueueEntry {
        stream_id: String::new(),
        message: message.into(),
        to_did_hash: "to-hash".into(),
        from_did_hash: "from-hash".into(),
        from_did: "did:example:from".into(),
        to_did: "did:example:to".into(),
        endpoint_url: endpoint_url.into(),
        received_at_ms: now_ms,
        delay_milli: 0,
        expires_at: (now_ms / 1000) as u64 + 300,
        retry_count: 0,
        hop_count: 1,
    }
}

/// Test config: REST-only (WS threshold out of reach) with fast retry
/// backoff so the retry test completes quickly.
fn test_config() -> ForwardingConfig {
    ForwardingConfig {
        ws_threshold_msgs_per_10s: u64::MAX,
        initial_backoff_ms: 10,
        max_backoff_ms: 50,
        ..Default::default()
    }
}

fn spawn_processor(config: ForwardingConfig, store: Arc<dyn MediatorStore>) {
    let processor = ForwardingProcessor::new(config, store).expect("create processor");
    tokio::spawn(async move {
        let _ = processor.start().await;
    });
}

/// Wait until the forward queue drains (entry ACKed + deleted) or time out.
async fn assert_queue_drains(store: &Arc<dyn MediatorStore>) {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if store.forward_queue_len().await.expect("queue len") == 0 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("forward queue did not drain");
}

#[tokio::test]
async fn memory_store_processor_delivers_via_rest() {
    let mut stub = spawn_stub_mediator(0).await;
    let store: Arc<dyn MediatorStore> = Arc::new(MemoryStore::new());

    store
        .forward_queue_enqueue(&forward_entry(&stub.endpoint_url, "encrypted-forward-1"), 0)
        .await
        .expect("enqueue");

    spawn_processor(test_config(), store.clone());

    let body = tokio::time::timeout(Duration::from_secs(10), stub.received.recv())
        .await
        .expect("timed out waiting for delivery")
        .expect("stub channel closed");
    assert_eq!(body, "encrypted-forward-1");

    assert_queue_drains(&store).await;
}

#[tokio::test]
async fn memory_store_processor_retries_failed_delivery() {
    // First attempt gets HTTP 500; the processor must re-enqueue with an
    // incremented retry count and succeed on the second attempt.
    let mut stub = spawn_stub_mediator(1).await;
    let store: Arc<dyn MediatorStore> = Arc::new(MemoryStore::new());

    store
        .forward_queue_enqueue(&forward_entry(&stub.endpoint_url, "encrypted-forward-2"), 0)
        .await
        .expect("enqueue");

    spawn_processor(test_config(), store.clone());

    let mut deliveries = 0;
    while deliveries < 2 {
        let body = tokio::time::timeout(Duration::from_secs(10), stub.received.recv())
            .await
            .expect("timed out waiting for retry delivery")
            .expect("stub channel closed");
        assert_eq!(body, "encrypted-forward-2");
        deliveries += 1;
    }

    assert_queue_drains(&store).await;
}
