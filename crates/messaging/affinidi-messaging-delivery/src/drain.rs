//! The drain: send due outbox entries over a [`MessageTransport`], advancing
//! their state on a truthful hop-accept (`Sent`) or rescheduling with backoff on
//! failure.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use affinidi_messaging_core::MessageTransport;

use crate::outbox::{OutboxError, OutboxState, OutboxStore};

/// First-retry backoff.
const BACKOFF_BASE_MS: u64 = 1_000;
/// Backoff ceiling.
const BACKOFF_CAP_MS: u64 = 60_000;

/// Exponential backoff for the `attempts`-th failed send: 1s, 2s, 4s, … capped
/// at 60s. `attempts == 0` is `0` (a fresh entry attempts immediately).
///
/// Jitter is deliberately omitted here so a drain is deterministic; a scheduler
/// that needs anti-thundering-herd jitter can add it around this base.
pub fn backoff_ms(attempts: u32) -> u64 {
    if attempts == 0 {
        return 0;
    }
    let shift = (attempts - 1).min(6); // 2^6 · base = 64s > cap
    (BACKOFF_BASE_MS << shift).min(BACKOFF_CAP_MS)
}

/// What one [`drain_once`] pass did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct DrainReport {
    /// Entries the transport hop-accepted this pass (→ `Sent`).
    pub sent: usize,
    /// Entries whose send failed and were rescheduled with backoff (stay
    /// `Queued`).
    pub retried: usize,
    /// Entries whose delivery window expired while still queued (→ `Failed`).
    pub failed: usize,
}

/// One drain pass at logical time `now_ms`: attempt every due entry once.
///
/// - **window expired** (`now_ms >= deliver_by_ms`) while still `Queued`: the
///   entry never hop-accepted in time and delivery was expected → `Failed`
///   (surfaced/escalated, never a silent success).
/// - **`Ok(hop-accept)`** → `Sent`; the entry is **not** re-sent (the mediator
///   owns redelivery — re-sending would double-send). End-to-end confirmation
///   (`Sent → Delivered`) is a separate step.
/// - **`Err`** (transport down / send failed): stay `Queued`, bump `attempts`,
///   schedule `next_attempt_at_ms` with [`backoff_ms`].
pub async fn drain_once(
    store: &dyn OutboxStore,
    transport: &dyn MessageTransport,
    now_ms: u64,
) -> Result<DrainReport, OutboxError> {
    let due = store.due(now_ms).await?;
    let mut report = DrainReport::default();

    for mut entry in due {
        if now_ms >= entry.deliver_by_ms {
            entry.state = OutboxState::Failed;
            store.put(entry).await?;
            report.failed += 1;
            continue;
        }

        match transport.send(&entry.dest_did, entry.packed.clone()).await {
            Ok(_receipt) => {
                entry.state = OutboxState::Sent;
                store.put(entry).await?;
                report.sent += 1;
            }
            Err(_e) => {
                entry.attempts += 1;
                entry.next_attempt_at_ms = now_ms.saturating_add(backoff_ms(entry.attempts));
                store.put(entry).await?;
                report.retried += 1;
            }
        }
    }

    Ok(report)
}

/// Run [`drain_once`] every `interval`, forever (until the task is dropped),
/// using the wall clock. A store error on one tick is logged and retried on the
/// next — the drain never aborts on a transient backend hiccup.
pub async fn drain_loop(
    store: Arc<dyn OutboxStore>,
    transport: Arc<dyn MessageTransport>,
    interval: Duration,
) {
    let mut ticker = tokio::time::interval(interval);
    loop {
        ticker.tick().await;
        match drain_once(store.as_ref(), transport.as_ref(), now_unix_ms()).await {
            Ok(report) if report != DrainReport::default() => {
                tracing::debug!(
                    sent = report.sent,
                    retried = report.retried,
                    failed = report.failed,
                    "outbox drain pass",
                );
            }
            Ok(_) => {}
            Err(e) => tracing::warn!(error = %e, "outbox drain pass failed; retrying next tick"),
        }
    }
}

/// Current wall-clock time in Unix milliseconds (`0` before the epoch, which
/// cannot happen in practice).
fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::outbox::{InMemoryOutboxStore, OutboxEntry};
    use affinidi_messaging_core::{
        ConnState, Inbound, InboundAck, MessageTransport, MessagingError, SendReceipt,
        TransportKind,
    };
    use futures_util::stream::{self, BoxStream};
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio::sync::watch;

    /// A controllable transport: `send` succeeds and records the payload, or
    /// fails when `fail` is set.
    struct MockTransport {
        fail: AtomicBool,
        sent: Mutex<Vec<Vec<u8>>>,
        _conn_tx: watch::Sender<ConnState>,
        conn_rx: watch::Receiver<ConnState>,
    }

    impl MockTransport {
        fn new(fail: bool) -> Self {
            let (tx, rx) = watch::channel(ConnState::Connected);
            Self {
                fail: AtomicBool::new(fail),
                sent: Mutex::new(Vec::new()),
                _conn_tx: tx,
                conn_rx: rx,
            }
        }
    }

    #[async_trait::async_trait]
    impl MessageTransport for MockTransport {
        fn kind(&self) -> TransportKind {
            TransportKind::Didcomm
        }
        async fn send(&self, _dest: &str, packed: Vec<u8>) -> Result<SendReceipt, MessagingError> {
            if self.fail.load(Ordering::SeqCst) {
                return Err(MessagingError::Transport("mock send failed".into()));
            }
            self.sent.lock().unwrap().push(packed);
            Ok(SendReceipt {
                via: TransportKind::Didcomm,
                hop_id: None,
            })
        }
        fn connection_state(&self) -> watch::Receiver<ConnState> {
            self.conn_rx.clone()
        }
        fn inbound(&self) -> BoxStream<'static, Inbound> {
            Box::pin(stream::empty())
        }
        async fn ack(&self, _ack: InboundAck) -> Result<(), MessagingError> {
            Ok(())
        }
    }

    fn queued(key: &str, now: u64) -> OutboxEntry {
        OutboxEntry::new(key, "did:example:bob", vec![9, 9], now, now + 60_000)
    }

    #[test]
    fn backoff_is_exponential_and_capped() {
        assert_eq!(backoff_ms(0), 0);
        assert_eq!(backoff_ms(1), 1_000);
        assert_eq!(backoff_ms(2), 2_000);
        assert_eq!(backoff_ms(3), 4_000);
        assert_eq!(backoff_ms(7), 60_000); // capped
        assert_eq!(backoff_ms(100), 60_000);
    }

    #[tokio::test]
    async fn hop_accept_marks_sent_and_transmits_once() {
        let store = InMemoryOutboxStore::new();
        store.put(queued("k1", 1_000)).await.unwrap();
        let transport = MockTransport::new(false);

        let report = drain_once(&store, &transport, 1_000).await.unwrap();
        assert_eq!(report.sent, 1);
        assert_eq!(
            store.get("k1").await.unwrap().unwrap().state,
            OutboxState::Sent
        );
        assert_eq!(transport.sent.lock().unwrap().len(), 1);

        // A second drain does NOT re-send a Sent entry.
        let report = drain_once(&store, &transport, 2_000).await.unwrap();
        assert_eq!(report, DrainReport::default());
        assert_eq!(transport.sent.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn send_failure_reschedules_with_backoff() {
        let store = InMemoryOutboxStore::new();
        store.put(queued("k1", 1_000)).await.unwrap();
        let transport = MockTransport::new(true);

        let report = drain_once(&store, &transport, 1_000).await.unwrap();
        assert_eq!(report.retried, 1);
        let e = store.get("k1").await.unwrap().unwrap();
        assert_eq!(e.state, OutboxState::Queued);
        assert_eq!(e.attempts, 1);
        assert_eq!(e.next_attempt_at_ms, 1_000 + backoff_ms(1));

        // Not due again until the backoff elapses.
        assert!(store.due(1_500).await.unwrap().is_empty());
        assert_eq!(store.due(2_000).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn window_expiry_fails_without_sending() {
        let store = InMemoryOutboxStore::new();
        // deliver_by is now + 60_000; drain past it.
        store.put(queued("k1", 1_000)).await.unwrap();
        let transport = MockTransport::new(false);

        let report = drain_once(&store, &transport, 1_000 + 60_000)
            .await
            .unwrap();
        assert_eq!(report.failed, 1);
        assert_eq!(
            store.get("k1").await.unwrap().unwrap().state,
            OutboxState::Failed
        );
        assert!(
            transport.sent.lock().unwrap().is_empty(),
            "expired entry is not sent"
        );
    }
}
