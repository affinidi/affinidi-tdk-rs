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

/// One drain pass at logical time `now_ms`: attempt every due **unbound** entry
/// once.
///
/// - **window expired** (`now_ms >= deliver_by_ms`) while still `Queued`: the
///   entry never hop-accepted in time and delivery was expected → `Failed`
///   (surfaced/escalated, never a silent success).
/// - **`Ok(hop-accept)`** → `Sent`; the entry is **not** re-sent (the mediator
///   owns redelivery — re-sending would double-send). End-to-end confirmation
///   (`Sent → Delivered`) is a separate step.
/// - **`Err`** (transport down / send failed): stay `Queued`, bump `attempts`,
///   schedule `next_attempt_at_ms` with [`backoff_ms`].
///
/// Entries with [`OutboxEntry::via`](crate::OutboxEntry::via) set are **skipped**:
/// they are pinned to a named transport and belong to
/// [`drain_once_via`]. `via` is `None` unless a caller sets it, so a
/// single-identity service sees no change.
pub async fn drain_once(
    store: &dyn OutboxStore,
    transport: &dyn MessageTransport,
    now_ms: u64,
) -> Result<DrainReport, OutboxError> {
    drain_filtered(store, transport, now_ms, |entry_via| entry_via.is_none()).await
}

/// [`drain_once`] for the entries pinned to **one** transport: only entries whose
/// [`via`](crate::OutboxEntry::via) equals `transport_id` are attempted.
///
/// This is the multi-identity drain. A service holding one transport per identity
/// runs one of these per transport over a shared store, and every entry is
/// claimed by exactly one of them — an unbound entry by [`drain_once`], a pinned
/// entry by the `drain_once_via` whose id it names. Nothing is drained twice, and
/// nothing goes out over the wrong identity.
///
/// A pinned entry whose transport is not currently installed is simply not due
/// for this drain; it waits rather than being re-routed, because re-routing it
/// would send it from the wrong identity — the exact thing the pin prevents. Its
/// `deliver_by_ms` still settles it visibly if the transport never returns.
pub async fn drain_once_via(
    store: &dyn OutboxStore,
    transport_id: &str,
    transport: &dyn MessageTransport,
    now_ms: u64,
) -> Result<DrainReport, OutboxError> {
    drain_filtered(store, transport, now_ms, |entry_via| {
        entry_via == Some(transport_id)
    })
    .await
}

/// Shared body of [`drain_once`] and [`drain_once_via`]; `claims` decides which
/// entries this drain owns, from an entry's `via`.
async fn drain_filtered(
    store: &dyn OutboxStore,
    transport: &dyn MessageTransport,
    now_ms: u64,
    claims: impl Fn(Option<&str>) -> bool,
) -> Result<DrainReport, OutboxError> {
    let due = store.due(now_ms).await?;
    let mut report = DrainReport::default();

    for mut entry in due {
        if !claims(entry.via.as_deref()) {
            continue;
        }
        if now_ms >= entry.deliver_by_ms {
            entry.state = OutboxState::Failed;
            store.put(entry).await?;
            report.failed += 1;
            continue;
        }

        match transport.send(&entry.dest_did, entry.packed.clone()).await {
            Ok(receipt) => {
                entry.state = OutboxState::Sent;
                // Record the hop-id so the confirmation watcher can watch this
                // exact message drain from the sender's outbox (§5a).
                entry.hop_id = receipt.hop_id;
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

/// [`drain_loop`] for one named transport — the multi-identity drain loop, running
/// [`drain_once_via`] on each tick.
///
/// One of these per identity, over a shared store. The transport is passed as a
/// concrete handle rather than resolved from the id on each tick: an identity's
/// socket is not interchangeable, so following a `promote` (as
/// `MessagingService::primary_handle` deliberately does) would be wrong here.
pub async fn drain_loop_via(
    store: Arc<dyn OutboxStore>,
    transport_id: String,
    transport: Arc<dyn MessageTransport>,
    interval: Duration,
) {
    let mut ticker = tokio::time::interval(interval);
    loop {
        ticker.tick().await;
        match drain_once_via(
            store.as_ref(),
            &transport_id,
            transport.as_ref(),
            now_unix_ms(),
        )
        .await
        {
            Ok(report) if report != DrainReport::default() => {
                tracing::debug!(
                    transport = %transport_id,
                    sent = report.sent,
                    retried = report.retried,
                    failed = report.failed,
                    "outbox drain pass",
                );
            }
            Ok(_) => {}
            Err(e) => tracing::warn!(
                transport = %transport_id,
                error = %e,
                "outbox drain pass failed; retrying next tick"
            ),
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

    /// The safety property the pin exists for: an entry bound to an identity must
    /// not go out over the primary, which is a different sender.
    #[tokio::test]
    async fn drain_once_skips_a_pinned_entry() {
        let store = InMemoryOutboxStore::new();
        store
            .put(queued("k1", 1_000).with_via("persona-a"))
            .await
            .unwrap();
        let transport = MockTransport::new(false);

        let report = drain_once(&store, &transport, 1_000).await.unwrap();
        assert_eq!(report, DrainReport::default(), "nothing was claimed");
        assert!(transport.sent.lock().unwrap().is_empty());
        assert_eq!(
            store.get("k1").await.unwrap().unwrap().state,
            OutboxState::Queued,
            "still waiting for its own transport"
        );
    }

    #[tokio::test]
    async fn drain_once_via_claims_only_its_own_id() {
        let store = InMemoryOutboxStore::new();
        store
            .put(queued("mine", 1_000).with_via("persona-a"))
            .await
            .unwrap();
        store
            .put(queued("theirs", 1_000).with_via("persona-b"))
            .await
            .unwrap();
        let transport = MockTransport::new(false);

        let report = drain_once_via(&store, "persona-a", &transport, 1_000)
            .await
            .unwrap();
        assert_eq!(report.sent, 1);
        assert_eq!(
            store.get("mine").await.unwrap().unwrap().state,
            OutboxState::Sent
        );
        assert_eq!(
            store.get("theirs").await.unwrap().unwrap().state,
            OutboxState::Queued,
            "another identity's entry is untouched"
        );
    }

    /// The whole point of the split: over one shared store, every entry is claimed
    /// by exactly one drain. Nothing double-sends, nothing is orphaned.
    #[tokio::test]
    async fn every_entry_is_claimed_exactly_once_across_drains() {
        let store = InMemoryOutboxStore::new();
        store.put(queued("unbound", 1_000)).await.unwrap();
        store
            .put(queued("a", 1_000).with_via("persona-a"))
            .await
            .unwrap();
        store
            .put(queued("b", 1_000).with_via("persona-b"))
            .await
            .unwrap();

        let primary = MockTransport::new(false);
        let a = MockTransport::new(false);
        let b = MockTransport::new(false);

        let unbound_report = drain_once(&store, &primary, 1_000).await.unwrap();
        let a_report = drain_once_via(&store, "persona-a", &a, 1_000)
            .await
            .unwrap();
        let b_report = drain_once_via(&store, "persona-b", &b, 1_000)
            .await
            .unwrap();

        assert_eq!(
            (unbound_report.sent, a_report.sent, b_report.sent),
            (1, 1, 1)
        );
        for transport in [&primary, &a, &b] {
            assert_eq!(
                transport.sent.lock().unwrap().len(),
                1,
                "each transport sent exactly its own entry"
            );
        }
        for key in ["unbound", "a", "b"] {
            assert_eq!(
                store.get(key).await.unwrap().unwrap().state,
                OutboxState::Sent,
                "{key} was drained"
            );
        }
    }

    /// A pinned entry still settles visibly when its transport never returns —
    /// the window is what stops it waiting forever.
    #[tokio::test]
    async fn a_pinned_entry_still_expires_on_its_own_drain() {
        let store = InMemoryOutboxStore::new();
        store
            .put(queued("k1", 1_000).with_via("persona-a"))
            .await
            .unwrap();
        let transport = MockTransport::new(false);

        let report = drain_once_via(&store, "persona-a", &transport, 1_000 + 60_000)
            .await
            .unwrap();
        assert_eq!(report.failed, 1);
        assert_eq!(
            store.get("k1").await.unwrap().unwrap().state,
            OutboxState::Failed
        );
        assert!(transport.sent.lock().unwrap().is_empty());
    }
}
