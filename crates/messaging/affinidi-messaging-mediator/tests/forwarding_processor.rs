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
    tasks::forwarding::{ForwardingConfig, ForwardingProcessor, SystemMessagePacker},
    types::messages::{Folder, MessageListElement},
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

// ─── Abandonment problem reports ────────────────────────────────────────────
//
// When the retry budget runs out the processor tells the original sender why,
// by storing a `report-problem/2.0` in their inbox. That report used to go in
// as bare plaintext, which every SDK client on the default (authcrypt-only)
// receive policy discards — so the abandonment was silent. It is now packed
// through the injected `SystemMessagePacker`. These cover the seam; the
// end-to-end assertion that the sender can actually *unpack* what lands in
// their inbox is `affinidi-messaging-test-mediator`'s
// `tests/forwarding_abandonment_report.rs`, over real mediators and real keys.

/// Records what it was asked to pack and returns a recognisable envelope, so a
/// test can tell "packed" from "stored raw" without doing crypto here.
struct RecordingPacker {
    mediator_did: String,
    packed: Arc<std::sync::Mutex<Vec<(serde_json::Value, String)>>>,
    fail: bool,
}

#[async_trait::async_trait]
impl SystemMessagePacker for RecordingPacker {
    fn mediator_did(&self) -> &str {
        &self.mediator_did
    }

    async fn pack(&self, plaintext: &serde_json::Value, to_did: &str) -> Result<String, String> {
        self.packed
            .lock()
            .expect("packer log")
            .push((plaintext.clone(), to_did.to_string()));
        if self.fail {
            return Err("recipient has no key agreement key".into());
        }
        Ok(format!(
            "PACKED({})",
            plaintext["id"].as_str().unwrap_or("")
        ))
    }
}

/// Config that abandons on the first failure, with negligible backoff.
fn abandon_immediately_config() -> ForwardingConfig {
    ForwardingConfig {
        max_retries: 0,
        ..test_config()
    }
}

/// Drain the sender's inbox, or `None` if nothing has landed yet.
async fn sender_inbox(store: &Arc<dyn MediatorStore>) -> Option<MessageListElement> {
    let listed = store
        .list_messages("from-hash", Folder::Inbox, None, 10)
        .await
        .expect("list sender inbox");
    let element = listed.into_iter().next()?;
    store
        .get_message("from-hash", &element.msg_id)
        .await
        .expect("get stored report")
}

/// Poll the sender's inbox until a report lands, or time out.
async fn await_sender_report(store: &Arc<dyn MediatorStore>) -> MessageListElement {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Some(element) = sender_inbox(store).await {
                return element;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("no abandonment report reached the sender's inbox")
}

/// The report the sender receives is the packer's envelope, not the plaintext
/// JSON — the regression this guards is a stored body that starts `{"type":`,
/// which is exactly what the SDK's default policy refuses.
#[tokio::test]
async fn abandoned_forward_stores_a_packed_report_for_the_sender() {
    let mut stub = spawn_stub_mediator(u32::MAX).await;
    let store: Arc<dyn MediatorStore> = Arc::new(MemoryStore::new());
    let packed_log = Arc::new(std::sync::Mutex::new(Vec::new()));

    store
        .forward_queue_enqueue(&forward_entry(&stub.endpoint_url, "doomed-forward"), 0)
        .await
        .expect("enqueue");

    let processor = ForwardingProcessor::new(abandon_immediately_config(), store.clone())
        .expect("create processor")
        .with_system_packer(Arc::new(RecordingPacker {
            mediator_did: "did:example:mediator".into(),
            packed: packed_log.clone(),
            fail: false,
        }));
    tokio::spawn(async move {
        let _ = processor.start().await;
    });

    // The stub has to actually reject the delivery before abandonment.
    let _ = tokio::time::timeout(Duration::from_secs(10), stub.received.recv())
        .await
        .expect("timed out waiting for the failed delivery attempt");

    let stored = await_sender_report(&store).await;
    let body = stored.msg.expect("stored report carries a body");
    assert!(
        body.starts_with("PACKED("),
        "the report must be stored packed, got: {body}"
    );

    // What was handed to the packer is a complete DIDComm plaintext addressed
    // from the mediator to the abandoned forward's original sender.
    let log = packed_log.lock().expect("packer log");
    let (plaintext, to_did) = log.first().expect("the packer was asked to pack a report");
    assert_eq!(to_did, "did:example:from");
    assert_eq!(plaintext["from"], "did:example:mediator");
    assert_eq!(plaintext["to"], serde_json::json!(["did:example:from"]));
    assert_eq!(plaintext["body"]["code"], "e.p.me.res.forwarding.abandoned");

    // The mediator authored it, so it is the sender of record.
    assert_eq!(
        stored.from_address.as_deref(),
        Some(sha256::digest("did:example:mediator").as_str()),
        "the report's sender is the mediator's DID hash, not a placeholder"
    );
}

/// A report that cannot be packed is not stored as plaintext instead: an
/// envelope the recipient's policy refuses is the defect, and storing one just
/// re-fails on every fetch. The abandonment stays visible in the operator log.
#[tokio::test]
async fn unpackable_report_is_not_stored_as_plaintext() {
    let mut stub = spawn_stub_mediator(u32::MAX).await;
    let store: Arc<dyn MediatorStore> = Arc::new(MemoryStore::new());

    store
        .forward_queue_enqueue(&forward_entry(&stub.endpoint_url, "doomed-forward"), 0)
        .await
        .expect("enqueue");

    let processor = ForwardingProcessor::new(abandon_immediately_config(), store.clone())
        .expect("create processor")
        .with_system_packer(Arc::new(RecordingPacker {
            mediator_did: "did:example:mediator".into(),
            packed: Arc::new(std::sync::Mutex::new(Vec::new())),
            fail: true,
        }));
    tokio::spawn(async move {
        let _ = processor.start().await;
    });

    let _ = tokio::time::timeout(Duration::from_secs(10), stub.received.recv())
        .await
        .expect("timed out waiting for the failed delivery attempt");
    assert_queue_drains(&store).await;

    // The queue has drained, so the abandonment has been processed; give the
    // store a moment in case a write were still in flight, then assert nothing
    // landed.
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        sender_inbox(&store).await.is_none(),
        "a report that could not be packed must not be stored in plaintext"
    );
}

/// Without a packer (the standalone `forwarding_processor` binary, which has no
/// mediator identity in its config) the same rule applies — the forward is
/// still abandoned and dequeued, but nothing unreadable is left behind.
#[tokio::test]
async fn abandonment_without_a_packer_stores_nothing() {
    let mut stub = spawn_stub_mediator(u32::MAX).await;
    let store: Arc<dyn MediatorStore> = Arc::new(MemoryStore::new());

    store
        .forward_queue_enqueue(&forward_entry(&stub.endpoint_url, "doomed-forward"), 0)
        .await
        .expect("enqueue");

    spawn_processor(abandon_immediately_config(), store.clone());

    let _ = tokio::time::timeout(Duration::from_secs(10), stub.received.recv())
        .await
        .expect("timed out waiting for the failed delivery attempt");
    assert_queue_drains(&store).await;

    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        sender_inbox(&store).await.is_none(),
        "with no packer configured there is nothing readable to store"
    );
}
