//! Forwarding processor over non-Redis backends.
//!
//! The `ForwardingProcessor` consumes the `forward_queue_*` methods on
//! `Arc<dyn MediatorStore>`, so it must deliver queued forwards
//! regardless of which storage backend is in use. These tests run it
//! against `MemoryStore` with a local stub standing in for the remote
//! mediator's `/inbound` endpoint.
//!
//! The stub listens on 127.0.0.1, a next hop the forwarding client's egress
//! guard refuses unless `affinidi-messaging-mediator-common`'s `test-clock`
//! feature admits loopback. That feature must never reach the mediator's own
//! graph (`scripts/check-test-clock-isolation.sh`), so these tests live here,
//! in the fixture crate that enables it, rather than in the mediator. There
//! they went unrun: the mediator never enabled the feature, so all five timed
//! out on deliveries the guard refused, from #819 on.
//!
//! Run with: `cargo test -p affinidi-messaging-test-mediator --test forwarding_processor`

use affinidi_messaging_mediator::store::MemoryStore;
use affinidi_messaging_mediator_common::{
    store::{MediatorStore, types::ForwardQueueEntry},
    tasks::forwarding::{
        ForwardOutcome, ForwardingConfig, ForwardingObserver, ForwardingProcessor,
        SystemMessagePacker,
    },
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
        not_before_ms: 0,
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

// ─── Scheduling across endpoints ────────────────────────────────────────────

/// Accepts connections and never answers, so a request to it runs until the
/// client gives up.
async fn spawn_unresponsive_endpoint() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind unresponsive endpoint");
    let addr = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((socket, _)) = listener.accept().await {
            held.push(socket);
        }
    });
    format!("http://{addr}")
}

/// Records every outcome the processor reports.
#[derive(Default)]
struct RecordingObserver {
    outcomes: std::sync::Mutex<Vec<(String, ForwardOutcome)>>,
}

impl ForwardingObserver for RecordingObserver {
    fn observe(&self, entry: &ForwardQueueEntry, outcome: ForwardOutcome) {
        self.outcomes
            .lock()
            .expect("observer log")
            .push((entry.message.clone(), outcome));
    }
}

/// Endpoints that never answer each hold up their own deliveries only: a
/// forward to a responsive endpoint, read in the same batch, goes out at once
/// rather than after the others time out.
#[tokio::test]
async fn an_unresponsive_endpoint_does_not_delay_another() {
    let mut healthy = spawn_stub_mediator(0).await;
    let store: Arc<dyn MediatorStore> = Arc::new(MemoryStore::new());

    for i in 0..3 {
        let stalled = spawn_unresponsive_endpoint().await;
        store
            .forward_queue_enqueue(&forward_entry(&stalled, &format!("stalled-{i}")), 0)
            .await
            .expect("enqueue");
    }
    store
        .forward_queue_enqueue(&forward_entry(&healthy.endpoint_url, "prompt-forward"), 0)
        .await
        .expect("enqueue");

    spawn_processor(
        ForwardingConfig {
            delivery_timeout_seconds: 30,
            ..test_config()
        },
        store.clone(),
    );

    let body = tokio::time::timeout(Duration::from_secs(5), healthy.received.recv())
        .await
        .expect("the responsive endpoint waited on the unresponsive ones")
        .expect("stub channel closed");
    assert_eq!(body, "prompt-forward");
}

/// A next hop the egress policy does not admit, or whose URL does not parse,
/// is dropped on the first attempt — no retries — and the sender is told
/// with a report of its own.
#[tokio::test]
async fn an_endpoint_that_is_not_permitted_is_dropped_without_retrying() {
    let store: Arc<dyn MediatorStore> = Arc::new(MemoryStore::new());
    let packed_log = Arc::new(std::sync::Mutex::new(Vec::new()));
    let observer = Arc::new(RecordingObserver::default());

    store
        .forward_queue_enqueue(
            &forward_entry("https://169.254.169.254", "link-local-forward"),
            0,
        )
        .await
        .expect("enqueue");
    store
        .forward_queue_enqueue(&forward_entry("not a url", "unparsable-forward"), 0)
        .await
        .expect("enqueue");

    // The default retry budget: a final answer must not spend it.
    let processor = ForwardingProcessor::new(
        ForwardingConfig {
            max_retries: 5,
            ..test_config()
        },
        store.clone(),
    )
    .expect("create processor")
    .with_system_packer(Arc::new(RecordingPacker {
        mediator_did: "did:example:mediator".into(),
        packed: packed_log.clone(),
        fail: false,
    }))
    .with_observer(observer.clone());
    tokio::spawn(async move {
        let _ = processor.start().await;
    });

    assert_queue_drains(&store).await;
    // Both reports are stored by the time the queue is empty; allow the
    // second a moment in case its write is still in flight.
    tokio::time::timeout(Duration::from_secs(5), async {
        while packed_log.lock().expect("packer log").len() < 2 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("both senders get a report");

    let outcomes = observer.outcomes.lock().expect("observer log").clone();
    assert_eq!(
        outcomes.len(),
        2,
        "one outcome each, no retries: {outcomes:?}"
    );
    for (message, outcome) in &outcomes {
        assert_eq!(*outcome, ForwardOutcome::NotPermitted, "{message}");
    }

    for (plaintext, _) in packed_log.lock().expect("packer log").iter() {
        assert_eq!(
            plaintext["body"]["code"],
            "e.p.me.res.forwarding.endpoint-not-permitted"
        );
    }
}

/// A failed attempt is retried only after the endpoint's backoff, even by a
/// second processor sharing the queue, which has seen no failure itself.
#[tokio::test]
async fn a_retry_waits_out_the_backoff_on_every_processor() {
    retry_waits_out_the_backoff(Arc::new(MemoryStore::new())).await;
}

#[cfg(feature = "redis-backend")]
#[tokio::test]
async fn a_retry_waits_out_the_backoff_on_every_processor_redis() {
    let Some(store) = redis_store(11).await else {
        return;
    };
    retry_waits_out_the_backoff(store).await;
}

async fn retry_waits_out_the_backoff(store: Arc<dyn MediatorStore>) {
    let mut stub = spawn_stub_mediator(1).await;

    store
        .forward_queue_enqueue(&forward_entry(&stub.endpoint_url, "retried-forward"), 0)
        .await
        .expect("enqueue");

    // One failure backs off `initial_backoff_ms * 2`.
    let config = ForwardingConfig {
        initial_backoff_ms: 400,
        max_backoff_ms: 5_000,
        ..test_config()
    };
    spawn_processor(config.clone(), store.clone());
    spawn_processor(config, store.clone());

    let first = tokio::time::timeout(Duration::from_secs(10), stub.received.recv())
        .await
        .expect("timed out waiting for the first attempt")
        .expect("stub channel closed");
    let failed_at = std::time::Instant::now();
    let second = tokio::time::timeout(Duration::from_secs(10), stub.received.recv())
        .await
        .expect("timed out waiting for the retry")
        .expect("stub channel closed");
    let waited = failed_at.elapsed();

    assert_eq!(first, "retried-forward");
    assert_eq!(second, "retried-forward");
    assert!(
        waited >= Duration::from_millis(700),
        "the retry went out {waited:?} after the failure, inside the 800ms backoff"
    );
    assert_queue_drains(&store).await;
}

// ─── Claims across processors, held-back messages, shares ───────────────────

/// A Redis store on logical DB `db`, flushed and initialised, or `None` (the
/// test is skipped) when `REDIS_URL` is unset.
#[cfg(feature = "redis-backend")]
async fn redis_store(db: u8) -> Option<Arc<dyn MediatorStore>> {
    use affinidi_messaging_mediator::store::RedisStore;
    use affinidi_messaging_mediator_common::database::{DatabaseHandler, config::DatabaseConfig};

    let base = match std::env::var("REDIS_URL") {
        Ok(url) if !url.trim().is_empty() => url,
        _ => {
            eprintln!("SKIP redis forwarding test (db {db}): REDIS_URL not set");
            return None;
        }
    };
    let config = DatabaseConfig {
        functions_file: Some(
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../affinidi-messaging-mediator/conf/atm-functions.lua"
            )
            .to_string(),
        ),
        database_url: format!("{}/{db}", base.trim_end_matches('/')),
        database_timeout: 2,
        circuit_breaker_threshold: 5,
        circuit_breaker_recovery_secs: 10,
    };
    let handler = DatabaseHandler::new(&config)
        .await
        .expect("connect to REDIS_URL");
    let store = RedisStore::new(handler, 5, 10, config.functions_file.clone());
    let mut conn = store.get_connection().await.expect("redis connection");
    redis::cmd("FLUSHDB")
        .query_async::<()>(&mut conn)
        .await
        .expect("FLUSHDB");
    store.initialize().await.expect("store initialize");
    Some(Arc::new(store))
}

/// Stub remote mediator that never answers its first request and accepts
/// every later one, counting the accepted bodies.
struct CountingMediator {
    endpoint_url: String,
    first_arrived: Arc<tokio::sync::Notify>,
    accepted: Arc<std::sync::Mutex<std::collections::HashMap<String, u32>>>,
}

async fn spawn_counting_mediator_that_stalls_once() -> CountingMediator {
    #[derive(Clone)]
    struct StubState {
        seen: Arc<AtomicU32>,
        first_arrived: Arc<tokio::sync::Notify>,
        accepted: Arc<std::sync::Mutex<std::collections::HashMap<String, u32>>>,
    }

    async fn inbound(State(state): State<StubState>, body: String) -> StatusCode {
        if state.seen.fetch_add(1, Ordering::SeqCst) == 0 {
            state.first_arrived.notify_one();
            std::future::pending::<()>().await;
        }
        *state
            .accepted
            .lock()
            .expect("accepted log")
            .entry(body)
            .or_default() += 1;
        StatusCode::OK
    }

    let first_arrived = Arc::new(tokio::sync::Notify::new());
    let accepted = Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
    let app = Router::new()
        .route("/inbound", post(inbound))
        .with_state(StubState {
            seen: Arc::new(AtomicU32::new(0)),
            first_arrived: first_arrived.clone(),
            accepted: accepted.clone(),
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
    CountingMediator {
        endpoint_url: format!("http://{addr}"),
        first_arrived,
        accepted,
    }
}

/// A processor stopped while it holds claimed entries — one mid-delivery,
/// the rest waiting their turn — does not strand them: once their claims go
/// idle, the processors still running take them over and each is accepted by
/// the peer exactly once, though two processors are sweeping for them.
#[tokio::test]
async fn entries_held_by_a_stopped_processor_are_delivered_once() {
    held_entries_survive_a_stopped_processor(Arc::new(MemoryStore::new())).await;
}

#[cfg(feature = "redis-backend")]
#[tokio::test]
async fn entries_held_by_a_stopped_processor_are_delivered_once_redis() {
    let Some(store) = redis_store(12).await else {
        return;
    };
    held_entries_survive_a_stopped_processor(store).await;
}

async fn held_entries_survive_a_stopped_processor(store: Arc<dyn MediatorStore>) {
    let stub = spawn_counting_mediator_that_stalls_once().await;
    let messages: Vec<String> = (0..6).map(|i| format!("held-forward-{i}")).collect();
    for message in &messages {
        store
            .forward_queue_enqueue(&forward_entry(&stub.endpoint_url, message), 0)
            .await
            .expect("enqueue");
    }
    let config = ForwardingConfig {
        reclaim_idle_seconds: 1,
        delivery_timeout_seconds: 30,
        ..test_config()
    };

    // The first processor claims all six and stalls on the first delivery.
    let first = ForwardingProcessor::new(config.clone(), store.clone()).expect("create processor");
    let first = tokio::spawn(async move {
        let _ = first.start().await;
    });
    tokio::time::timeout(Duration::from_secs(10), stub.first_arrived.notified())
        .await
        .expect("the first processor never attempted a delivery");
    first.abort();
    let _ = first.await;

    spawn_processor(config.clone(), store.clone());
    spawn_processor(config, store.clone());

    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if store.forward_queue_len().await.expect("queue len") == 0 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the stopped processor's entries were not taken over");
    // Let any duplicate still in flight land before counting.
    tokio::time::sleep(Duration::from_millis(500)).await;

    let accepted = stub.accepted.lock().expect("accepted log").clone();
    for message in &messages {
        assert_eq!(
            accepted.get(message).copied(),
            Some(1),
            "{message} accepted exactly once: {accepted:?}"
        );
    }
}

/// Messages held back because their endpoint is backing off were never sent,
/// so they keep their retry budget: with no retries allowed, the one that
/// failed is abandoned and the rest are delivered after the backoff.
#[tokio::test]
async fn held_back_messages_keep_their_retry_budget() {
    let mut stub = spawn_stub_mediator(1).await;
    let store: Arc<dyn MediatorStore> = Arc::new(MemoryStore::new());
    let observer = Arc::new(RecordingObserver::default());

    for i in 0..4 {
        store
            .forward_queue_enqueue(
                &forward_entry(&stub.endpoint_url, &format!("budget-{i}")),
                0,
            )
            .await
            .expect("enqueue");
    }

    let processor = ForwardingProcessor::new(
        ForwardingConfig {
            max_retries: 0,
            initial_backoff_ms: 100,
            max_backoff_ms: 1_000,
            ..test_config()
        },
        store.clone(),
    )
    .expect("create processor")
    .with_observer(observer.clone());
    tokio::spawn(async move {
        let _ = processor.start().await;
    });

    for _ in 0..4 {
        tokio::time::timeout(Duration::from_secs(10), stub.received.recv())
            .await
            .expect("timed out waiting for a delivery")
            .expect("stub channel closed");
    }
    assert_queue_drains(&store).await;

    let outcomes = observer.outcomes.lock().expect("observer log").clone();
    let abandoned: Vec<_> = outcomes
        .iter()
        .filter(|(_, o)| matches!(o, ForwardOutcome::Abandoned { .. }))
        .collect();
    let relayed = outcomes
        .iter()
        .filter(|(_, o)| matches!(o, ForwardOutcome::Relayed { .. }))
        .count();
    assert_eq!(
        abandoned.len(),
        1,
        "only the message that was sent and failed: {outcomes:?}"
    );
    assert_eq!(abandoned[0].0, "budget-0");
    assert_eq!(relayed, 3, "{outcomes:?}");
    assert!(
        !outcomes
            .iter()
            .any(|(_, o)| matches!(o, ForwardOutcome::Retrying { .. })),
        "holding a message back is not a retry: {outcomes:?}"
    );
}

/// A backlog for one endpoint that cannot drain holds only its share of what
/// the processor takes in, so a forward to another endpoint queued behind it
/// is still read and delivered.
#[tokio::test]
async fn a_backlogged_endpoint_does_not_stop_others_being_read() {
    let mut healthy = spawn_stub_mediator(0).await;
    let stalled = spawn_unresponsive_endpoint().await;
    let store: Arc<dyn MediatorStore> = Arc::new(MemoryStore::new());

    for i in 0..10 {
        store
            .forward_queue_enqueue(&forward_entry(&stalled, &format!("backlog-{i}")), 0)
            .await
            .expect("enqueue");
    }
    store
        .forward_queue_enqueue(
            &forward_entry(&healthy.endpoint_url, "behind-the-backlog"),
            0,
        )
        .await
        .expect("enqueue");

    // At most 2 x 2 = 4 entries held, 2 of them for any one endpoint.
    spawn_processor(
        ForwardingConfig {
            batch_size: 2,
            max_concurrent_endpoints: 2,
            delivery_timeout_seconds: 30,
            ..test_config()
        },
        store.clone(),
    );

    let body = tokio::time::timeout(Duration::from_secs(5), healthy.received.recv())
        .await
        .expect("the backlog stopped the other endpoint's forward being read")
        .expect("stub channel closed");
    assert_eq!(body, "behind-the-backlog");
}

// ─── Failing endpoints, concurrent processors, unconfirmed claims ───────────

/// Stub remote mediator that accepts every request, the first after
/// `first_delay`, and tallies the accepted bodies.
async fn spawn_tallying_mediator(first_delay: Duration) -> CountingMediator {
    #[derive(Clone)]
    struct StubState {
        seen: Arc<AtomicU32>,
        first_delay: Duration,
        first_arrived: Arc<tokio::sync::Notify>,
        accepted: Arc<std::sync::Mutex<std::collections::HashMap<String, u32>>>,
    }

    async fn inbound(State(state): State<StubState>, body: String) -> StatusCode {
        if state.seen.fetch_add(1, Ordering::SeqCst) == 0 {
            state.first_arrived.notify_one();
            tokio::time::sleep(state.first_delay).await;
        }
        *state
            .accepted
            .lock()
            .expect("accepted log")
            .entry(body)
            .or_default() += 1;
        StatusCode::OK
    }

    let first_arrived = Arc::new(tokio::sync::Notify::new());
    let accepted = Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
    let app = Router::new()
        .route("/inbound", post(inbound))
        .with_state(StubState {
            seen: Arc::new(AtomicU32::new(0)),
            first_delay,
            first_arrived: first_arrived.clone(),
            accepted: accepted.clone(),
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
    CountingMediator {
        endpoint_url: format!("http://{addr}"),
        first_arrived,
        accepted,
    }
}

/// Two endpoints that fail every attempt, each with a backlog, hold only a
/// batch each while they back off, so a forward to a working endpoint queued
/// behind both backlogs is still read and delivered.
#[tokio::test]
async fn failing_endpoints_with_backlogs_do_not_stop_a_healthy_one() {
    let mut healthy = spawn_stub_mediator(0).await;
    let store: Arc<dyn MediatorStore> = Arc::new(MemoryStore::new());

    for dead in 0..2 {
        let failing = spawn_stub_mediator(u32::MAX).await;
        for i in 0..20 {
            store
                .forward_queue_enqueue(
                    &forward_entry(&failing.endpoint_url, &format!("dead-{dead}-{i}")),
                    0,
                )
                .await
                .expect("enqueue");
        }
        // Keep the failing stub's channel alive for the test.
        std::mem::forget(failing);
    }

    // At most 2 x 4 = 8 held, 4 for an endpoint, 2 while it backs off.
    spawn_processor(
        ForwardingConfig {
            batch_size: 2,
            max_concurrent_endpoints: 4,
            max_retries: 100,
            initial_backoff_ms: 10_000,
            max_backoff_ms: 60_000,
            ..test_config()
        },
        store.clone(),
    );
    // Both endpoints fail and back off, and their backlogs are read, before
    // the healthy forward is queued behind them.
    tokio::time::sleep(Duration::from_secs(1)).await;
    store
        .forward_queue_enqueue(
            &forward_entry(&healthy.endpoint_url, "behind-two-backlogs"),
            0,
        )
        .await
        .expect("enqueue");

    let body = tokio::time::timeout(Duration::from_secs(5), healthy.received.recv())
        .await
        .expect("the failing endpoints' backlogs stopped the healthy forward being read")
        .expect("stub channel closed");
    assert_eq!(body, "behind-two-backlogs");
}

/// Two processors on one queue, a mixed workload, and one endpoint that
/// fails every attempt: every forward to a working endpoint is delivered
/// exactly once and every forward to the failing one is abandoned exactly
/// once, across both processors.
#[tokio::test]
async fn two_processors_settle_each_forward_once() {
    two_processors_settle_each_forward_once_on(Arc::new(MemoryStore::new())).await;
}

#[cfg(feature = "redis-backend")]
#[tokio::test]
async fn two_processors_settle_each_forward_once_redis() {
    let Some(store) = redis_store(13).await else {
        return;
    };
    two_processors_settle_each_forward_once_on(store).await;
}

async fn two_processors_settle_each_forward_once_on(store: Arc<dyn MediatorStore>) {
    let first = spawn_tallying_mediator(Duration::ZERO).await;
    let second = spawn_tallying_mediator(Duration::ZERO).await;
    let failing = spawn_stub_mediator(u32::MAX).await;
    let observer = Arc::new(RecordingObserver::default());

    let mut healthy = Vec::new();
    let mut doomed = Vec::new();
    for i in 0..20 {
        for (stub, name) in [(&first, "first"), (&second, "second")] {
            let message = format!("{name}-{i}");
            store
                .forward_queue_enqueue(&forward_entry(&stub.endpoint_url, &message), 0)
                .await
                .expect("enqueue");
            healthy.push(message);
        }
        if i % 4 == 0 {
            let message = format!("doomed-{i}");
            store
                .forward_queue_enqueue(&forward_entry(&failing.endpoint_url, &message), 0)
                .await
                .expect("enqueue");
            doomed.push(message);
        }
    }

    let config = ForwardingConfig {
        batch_size: 4,
        max_retries: 1,
        initial_backoff_ms: 50,
        max_backoff_ms: 200,
        reclaim_idle_seconds: 1,
        ..test_config()
    };
    for _ in 0..2 {
        let processor = ForwardingProcessor::new(config.clone(), store.clone())
            .expect("create processor")
            .with_observer(observer.clone());
        tokio::spawn(async move {
            let _ = processor.start().await;
        });
    }

    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if store.forward_queue_len().await.expect("queue len") == 0 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the queue did not drain");
    // Two reclaim windows, for any duplicate to surface.
    tokio::time::sleep(Duration::from_secs(2)).await;

    let mut accepted = first.accepted.lock().expect("accepted log").clone();
    accepted.extend(second.accepted.lock().expect("accepted log").clone());
    let outcomes = observer.outcomes.lock().expect("observer log").clone();
    let count = |message: &str, matches: fn(&ForwardOutcome) -> bool| {
        outcomes
            .iter()
            .filter(|(m, o)| m == message && matches(o))
            .count()
    };
    for message in &healthy {
        assert_eq!(
            accepted.get(message).copied(),
            Some(1),
            "{message} accepted once"
        );
        assert_eq!(
            count(message, |o| matches!(o, ForwardOutcome::Relayed { .. })),
            1,
            "{message} relayed once"
        );
    }
    for message in &doomed {
        assert_eq!(
            count(message, |o| matches!(o, ForwardOutcome::Abandoned { .. })),
            1,
            "{message} abandoned once: {outcomes:?}"
        );
        assert!(
            count(message, |o| matches!(o, ForwardOutcome::Relayed { .. })) == 0,
            "{message} was never relayed"
        );
    }
}

/// A processor that cannot confirm its claims stops sending: the send under
/// way finishes, the rest wait, and another processor takes them over once
/// their claims go idle. Each message is accepted once.
#[tokio::test]
async fn a_processor_that_cannot_confirm_its_claims_stops_sending() {
    let stub = spawn_tallying_mediator(Duration::from_millis(1_000)).await;
    let store: Arc<dyn MediatorStore> = Arc::new(MemoryStore::new());
    let messages: Vec<String> = (0..6).map(|i| format!("unconfirmed-{i}")).collect();
    for message in &messages {
        store
            .forward_queue_enqueue(&forward_entry(&stub.endpoint_url, message), 0)
            .await
            .expect("enqueue");
    }
    // Refreshes every 500 ms; unconfirmed after 1 s; reclaimable after 2 s.
    let config = ForwardingConfig {
        reclaim_idle_seconds: 2,
        ..test_config()
    };

    let fault = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stalled_side = Arc::new(RecordingObserver::default());
    let first = ForwardingProcessor::new(config.clone(), store.clone())
        .expect("create processor")
        .with_observer(stalled_side.clone())
        .with_claim_refresh_fault(fault.clone());
    tokio::spawn(async move {
        let _ = first.start().await;
    });
    tokio::time::timeout(Duration::from_secs(10), stub.first_arrived.notified())
        .await
        .expect("the first processor never attempted a delivery");
    fault.store(true, Ordering::SeqCst);

    let other_side = Arc::new(RecordingObserver::default());
    let second = ForwardingProcessor::new(config, store.clone())
        .expect("create processor")
        .with_observer(other_side.clone());
    tokio::spawn(async move {
        let _ = second.start().await;
    });

    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if store.forward_queue_len().await.expect("queue len") == 0 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the other processor did not take the entries over");
    tokio::time::sleep(Duration::from_millis(500)).await;

    let accepted = stub.accepted.lock().expect("accepted log").clone();
    for message in &messages {
        assert_eq!(
            accepted.get(message).copied(),
            Some(1),
            "{message}: {accepted:?}"
        );
    }
    let relayed = |observer: &RecordingObserver| {
        observer
            .outcomes
            .lock()
            .expect("observer log")
            .iter()
            .filter(|(_, o)| matches!(o, ForwardOutcome::Relayed { .. }))
            .count()
    };
    assert_eq!(
        relayed(&stalled_side),
        1,
        "only the send already under way went out unconfirmed"
    );
    assert_eq!(
        relayed(&other_side),
        5,
        "the rest went through the other processor"
    );
}

/// Stub remote mediator whose WebSocket route refuses the upgrade — the
/// first time only after `first_ws_delay` — so every WebSocket attempt falls
/// back to REST, where every request is accepted and tallied.
async fn spawn_mediator_refusing_websocket(first_ws_delay: Duration) -> CountingMediator {
    #[derive(Clone)]
    struct StubState {
        ws_seen: Arc<AtomicU32>,
        first_ws_delay: Duration,
        first_arrived: Arc<tokio::sync::Notify>,
        accepted: Arc<std::sync::Mutex<std::collections::HashMap<String, u32>>>,
    }

    async fn ws(State(state): State<StubState>) -> StatusCode {
        if state.ws_seen.fetch_add(1, Ordering::SeqCst) == 0 {
            state.first_arrived.notify_one();
            tokio::time::sleep(state.first_ws_delay).await;
        }
        StatusCode::FORBIDDEN
    }

    async fn inbound(State(state): State<StubState>, body: String) -> StatusCode {
        *state
            .accepted
            .lock()
            .expect("accepted log")
            .entry(body)
            .or_default() += 1;
        StatusCode::OK
    }

    let first_arrived = Arc::new(tokio::sync::Notify::new());
    let accepted = Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
    let app = Router::new()
        .route("/ws", axum::routing::get(ws))
        .route("/inbound", post(inbound))
        .with_state(StubState {
            ws_seen: Arc::new(AtomicU32::new(0)),
            first_ws_delay,
            first_arrived: first_arrived.clone(),
            accepted: accepted.clone(),
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
    CountingMediator {
        endpoint_url: format!("http://{addr}"),
        first_arrived,
        accepted,
    }
}

/// The REST fallback after a failed WebSocket attempt is a new send, held to
/// the same check as the first: if the processor's claims went unconfirmed
/// while the WebSocket attempt ran, it does not fall back. The entry keeps
/// its retries, and another processor takes it over and delivers it once.
#[tokio::test]
async fn no_rest_fallback_once_claims_are_unconfirmed() {
    let stub = spawn_mediator_refusing_websocket(Duration::from_millis(1_500)).await;
    let store: Arc<dyn MediatorStore> = Arc::new(MemoryStore::new());
    store
        .forward_queue_enqueue(&forward_entry(&stub.endpoint_url, "after-websocket"), 0)
        .await
        .expect("enqueue");
    // WebSocket first; refreshes every 500 ms; unconfirmed after 1 s;
    // reclaimable after 2 s.
    let config = ForwardingConfig {
        ws_threshold_msgs_per_10s: 0,
        reclaim_idle_seconds: 2,
        ..test_config()
    };

    let fault = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stalled_side = Arc::new(RecordingObserver::default());
    let first = ForwardingProcessor::new(config.clone(), store.clone())
        .expect("create processor")
        .with_observer(stalled_side.clone())
        .with_claim_refresh_fault(fault.clone());
    tokio::spawn(async move {
        let _ = first.start().await;
    });
    tokio::time::timeout(Duration::from_secs(10), stub.first_arrived.notified())
        .await
        .expect("the first processor never tried the WebSocket");
    fault.store(true, Ordering::SeqCst);

    let other_side = Arc::new(RecordingObserver::default());
    let second = ForwardingProcessor::new(config, store.clone())
        .expect("create processor")
        .with_observer(other_side.clone());
    tokio::spawn(async move {
        let _ = second.start().await;
    });

    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if store.forward_queue_len().await.expect("queue len") == 0 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the other processor did not take the entry over");
    tokio::time::sleep(Duration::from_millis(500)).await;

    let accepted = stub.accepted.lock().expect("accepted log").clone();
    assert_eq!(
        accepted.get("after-websocket").copied(),
        Some(1),
        "{accepted:?}"
    );
    let stalled = stalled_side.outcomes.lock().expect("observer log").clone();
    assert!(
        stalled.is_empty(),
        "no fallback, no retry, no backoff on the unconfirmed side: {stalled:?}"
    );
    let other = other_side.outcomes.lock().expect("observer log").clone();
    assert!(
        matches!(other.as_slice(), [(_, ForwardOutcome::Relayed { .. })]),
        "{other:?}"
    );
}

/// A next hop that accepts the connection but never answers the WebSocket
/// upgrade costs only the relay's connect limit: the forward then falls back
/// to REST inside the same delivery attempt, and a forward to another
/// endpoint is not held up meanwhile.
#[tokio::test]
async fn a_websocket_upgrade_that_never_completes_falls_back_to_rest() {
    let stalling = spawn_mediator_refusing_websocket(Duration::from_secs(3600)).await;
    let mut healthy = spawn_stub_mediator(0).await;
    let store: Arc<dyn MediatorStore> = Arc::new(MemoryStore::new());
    store
        .forward_queue_enqueue(
            &forward_entry(&stalling.endpoint_url, "after-stalled-upgrade"),
            0,
        )
        .await
        .expect("enqueue");
    store
        .forward_queue_enqueue(&forward_entry(&healthy.endpoint_url, "prompt-forward"), 0)
        .await
        .expect("enqueue");

    spawn_processor(
        ForwardingConfig {
            // WebSocket first, for every endpoint.
            ws_threshold_msgs_per_10s: 0,
            delivery_timeout_seconds: 60,
            ..test_config()
        },
        store.clone(),
    );

    tokio::time::timeout(Duration::from_secs(5), stalling.first_arrived.notified())
        .await
        .expect("the stalled upgrade was never attempted");
    let body = tokio::time::timeout(Duration::from_secs(5), healthy.received.recv())
        .await
        .expect("the healthy endpoint waited on the stalled upgrade")
        .expect("stub channel closed");
    assert_eq!(body, "prompt-forward");

    // The connect limit (10 s), then REST — well inside the 60 s attempt.
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if stalling
                .accepted
                .lock()
                .expect("accepted log")
                .contains_key("after-stalled-upgrade")
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the forward did not fall back to REST after the stalled upgrade");
    assert_queue_drains(&store).await;
    let accepted = stalling.accepted.lock().expect("accepted log").clone();
    assert_eq!(
        accepted.get("after-stalled-upgrade").copied(),
        Some(1),
        "{accepted:?}"
    );
}

/// With a delivery timeout shorter than the WebSocket limits, the WebSocket
/// attempt is cut to a share of it, so a stalled upgrade still falls back to
/// REST inside the same delivery attempt rather than being cancelled with it.
#[tokio::test]
async fn a_short_delivery_timeout_still_leaves_time_for_the_rest_fallback() {
    let stalling = spawn_mediator_refusing_websocket(Duration::from_secs(3600)).await;
    let store: Arc<dyn MediatorStore> = Arc::new(MemoryStore::new());
    store
        .forward_queue_enqueue(&forward_entry(&stalling.endpoint_url, "short-timeout"), 0)
        .await
        .expect("enqueue");

    let observer = Arc::new(RecordingObserver::default());
    let processor = ForwardingProcessor::new(
        ForwardingConfig {
            ws_threshold_msgs_per_10s: 0,
            // The WebSocket attempt gets a third: 2 s.
            delivery_timeout_seconds: 6,
            ..test_config()
        },
        store.clone(),
    )
    .expect("create processor")
    .with_observer(observer.clone());
    tokio::spawn(async move {
        let _ = processor.start().await;
    });

    assert_queue_drains(&store).await;
    let accepted = stalling.accepted.lock().expect("accepted log").clone();
    assert_eq!(
        accepted.get("short-timeout").copied(),
        Some(1),
        "{accepted:?}"
    );
    let outcomes = observer.outcomes.lock().expect("observer log").clone();
    assert!(
        matches!(outcomes.as_slice(), [(_, ForwardOutcome::Relayed { .. })]),
        "delivered on the first attempt: {outcomes:?}"
    );
}
