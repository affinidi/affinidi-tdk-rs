//! The drain: send due outbox entries over a [`MessageTransport`], advancing
//! their state on a truthful hop-accept (`Sent`) or rescheduling with backoff on
//! failure.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use affinidi_messaging_core::MessageTransport;

use crate::outbox::{OutboxError, OutboxState, OutboxStore};

/// First-retry backoff.
const BACKOFF_BASE_MS: u64 = 1_000;
/// Backoff ceiling.
const BACKOFF_CAP_MS: u64 = 60_000;

/// How long a destination is left alone after a queue-full refusal that came
/// with no `Retry-After`.
///
/// Matches the mediator's own hint, so a mediator that sends one and a mediator
/// that does not produce the same pacing rather than two different behaviours
/// a operator would have to know about.
const QUEUE_FULL_FALLBACK_MS: u64 = 30_000;

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
    /// Entries deferred because their destination's queue at the mediator is
    /// full (stay `Queued`).
    ///
    /// Counted apart from `retried` because it is not a failure of the send and
    /// carries a different remedy: nothing about this message or this wire is
    /// wrong, and no number of retries will help until the destination's queue
    /// drains. A climbing `backpressured` beside a flat `retried` means a peer
    /// has stopped collecting, not that the network is unhealthy.
    pub backpressured: usize,
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
    // Destinations refused this pass, and when they may be tried again.
    //
    // Without this the drain re-learns the same refusal once per queued
    // message: a peer holding fifty undelivered messages costs fifty sends,
    // fifty refusals and fifty store writes on every tick, against a mediator
    // that is refusing precisely because it is already holding too much. One
    // refusal is enough to know the answer for the rest.
    let mut blocked: HashMap<String, u64> = HashMap::new();

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

        // A destination already refused in this pass: defer without sending.
        // Checked before `deliver_by_ms` would be, deliberately after it — an
        // entry whose window has closed is `Failed` whatever the destination's
        // queue is doing, and reporting it as merely deferred would hide a
        // delivery that is never going to happen.
        if let Some(&until) = blocked.get(&entry.dest_did) {
            entry.next_attempt_at_ms = until;
            store.put(entry).await?;
            report.backpressured += 1;
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
            Err(e) if e.queue_full().is_some() => {
                let gate = e.queue_full().expect("just matched");
                let wait_ms = e
                    .retry_after()
                    .map(|d| d.as_millis().min(u64::MAX as u128) as u64)
                    .unwrap_or(QUEUE_FULL_FALLBACK_MS);
                let until = now_ms.saturating_add(wait_ms);

                // `attempts` is deliberately NOT incremented. It drives
                // exponential backoff, and backing off exponentially here
                // would punish a message for a condition it did not cause and
                // cannot fix — a relationship that clears in a minute would be
                // waiting fifteen. The server's own pacing hint is the right
                // clock, and `deliver_by_ms` remains the bound that stops this
                // going on for ever.
                entry.next_attempt_at_ms = until;
                let dest = entry.dest_did.clone();
                store.put(entry).await?;
                report.backpressured += 1;

                tracing::warn!(
                    dest = %dest,
                    ?gate,
                    wait_ms,
                    "destination queue full at the mediator — deferring this destination \
                     for the rest of this pass"
                );
                blocked.insert(dest, until);
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
        /// Every destination `send` was called for, so a test can prove a
        /// deferred destination was not dialled again.
        dests: Mutex<Vec<String>>,
        /// Destination that answers with a queue-full 503, and the
        /// `Retry-After` it carries (`None` = the header is absent).
        queue_full_dest: Mutex<Option<(String, Option<u64>)>>,
        _conn_tx: watch::Sender<ConnState>,
        conn_rx: watch::Receiver<ConnState>,
    }

    impl MockTransport {
        fn new(fail: bool) -> Self {
            let (tx, rx) = watch::channel(ConnState::Connected);
            Self {
                fail: AtomicBool::new(fail),
                sent: Mutex::new(Vec::new()),
                dests: Mutex::new(Vec::new()),
                queue_full_dest: Mutex::new(None),
                _conn_tx: tx,
                conn_rx: rx,
            }
        }

        /// Make `dest` answer as the mediator does when a queue-depth gate
        /// refuses: a 503 whose body is the serialised problem report.
        fn refusing(dest: &str, retry_after: Option<u64>) -> Self {
            let t = Self::new(false);
            *t.queue_full_dest.lock().unwrap() = Some((dest.to_string(), retry_after));
            t
        }
    }

    #[async_trait::async_trait]
    impl MessageTransport for MockTransport {
        fn kind(&self) -> TransportKind {
            TransportKind::Didcomm
        }
        async fn send(&self, _dest: &str, packed: Vec<u8>) -> Result<SendReceipt, MessagingError> {
            self.dests.lock().unwrap().push(_dest.to_string());
            if self.fail.load(Ordering::SeqCst) {
                return Err(MessagingError::Transport("mock send failed".into()));
            }
            if let Some((dest, retry_after)) = self.queue_full_dest.lock().unwrap().as_ref()
                && dest == _dest
            {
                let report =
                    serde_json::json!({ "code": "e.p.limits.queue.peer", "comment": "full" })
                        .to_string();
                let body = serde_json::json!({
                    "sessionId": "s",
                    "httpCode": 503,
                    "errorCode": 95,
                    "errorCodeStr": "DIDCommProblemReport",
                    "message": report,
                })
                .to_string();
                let retry = retry_after.map(|s| s.to_string());
                return Err(affinidi_messaging_core::HttpStatusError::from_parts(
                    "send",
                    503,
                    None,
                    retry.as_deref(),
                    body,
                )
                .into());
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

    fn queued_to(key: &str, dest: &str, now: u64) -> OutboxEntry {
        OutboxEntry::new(key, dest, vec![9, 9], now, now + 600_000)
    }

    /// A queue-full refusal is not this message's failure, so it must not
    /// inflate the message's backoff — the server's own pacing hint is the
    /// right clock.
    #[tokio::test]
    async fn a_queue_full_refusal_defers_without_bumping_attempts() {
        let store = InMemoryOutboxStore::new();
        store
            .put(queued_to("k1", "did:example:bob", 1_000))
            .await
            .unwrap();
        let transport = MockTransport::refusing("did:example:bob", Some(45));

        let report = drain_once(&store, &transport, 1_000).await.unwrap();
        assert_eq!(report.backpressured, 1);
        assert_eq!(report.retried, 0, "a full queue is not a failed send");
        assert_eq!(report.sent, 0);

        let e = store.get("k1").await.unwrap().unwrap();
        assert_eq!(e.state, OutboxState::Queued);
        assert_eq!(e.attempts, 0, "backoff must not escalate on a full queue");
        assert_eq!(
            e.next_attempt_at_ms,
            1_000 + 45_000,
            "the server's Retry-After is the schedule"
        );
    }

    /// With no `Retry-After` the drain still paces itself rather than hot
    /// looping into a queue that is full because nothing is draining it.
    #[tokio::test]
    async fn a_refusal_without_a_hint_uses_the_fallback_wait() {
        let store = InMemoryOutboxStore::new();
        store
            .put(queued_to("k1", "did:example:bob", 1_000))
            .await
            .unwrap();
        let transport = MockTransport::refusing("did:example:bob", None);

        drain_once(&store, &transport, 1_000).await.unwrap();
        let e = store.get("k1").await.unwrap().unwrap();
        assert_eq!(e.next_attempt_at_ms, 1_000 + QUEUE_FULL_FALLBACK_MS);
    }

    /// The point of the per-destination map: one refusal answers for every
    /// other entry aimed at the same peer, instead of the drain re-learning it
    /// once per queued message against a mediator already holding too much.
    #[tokio::test]
    async fn one_refusal_defers_the_whole_destination_without_more_sends() {
        let store = InMemoryOutboxStore::new();
        for k in ["k1", "k2", "k3"] {
            store
                .put(queued_to(k, "did:example:bob", 1_000))
                .await
                .unwrap();
        }
        let transport = MockTransport::refusing("did:example:bob", Some(30));

        let report = drain_once(&store, &transport, 1_000).await.unwrap();
        assert_eq!(report.backpressured, 3, "all three are deferred");
        assert_eq!(
            transport.dests.lock().unwrap().len(),
            1,
            "only the first entry is actually sent; the rest are deferred unsent"
        );
        for k in ["k1", "k2", "k3"] {
            let e = store.get(k).await.unwrap().unwrap();
            assert_eq!(e.state, OutboxState::Queued);
            assert_eq!(e.next_attempt_at_ms, 1_000 + 30_000);
        }
    }

    /// The blast radius of `limits.queue.peer` is one relationship, and the
    /// drain must respect that — deferring every destination because one peer
    /// stopped collecting is the failure #828 exists to prevent, reintroduced
    /// client-side.
    #[tokio::test]
    async fn a_blocked_destination_does_not_stop_the_others() {
        let store = InMemoryOutboxStore::new();
        store
            .put(queued_to("blocked", "did:example:bob", 1_000))
            .await
            .unwrap();
        store
            .put(queued_to("fine", "did:example:carol", 1_000))
            .await
            .unwrap();
        let transport = MockTransport::refusing("did:example:bob", Some(30));

        let report = drain_once(&store, &transport, 1_000).await.unwrap();
        assert_eq!(report.backpressured, 1);
        assert_eq!(report.sent, 1, "the healthy peer still gets its message");
        assert_eq!(
            store.get("fine").await.unwrap().unwrap().state,
            OutboxState::Sent
        );
        assert_eq!(
            store.get("blocked").await.unwrap().unwrap().state,
            OutboxState::Queued
        );
    }

    /// An ordinary transport failure keeps its old behaviour exactly: bump
    /// attempts, back off exponentially, count as retried.
    #[tokio::test]
    async fn an_ordinary_failure_is_still_a_backoff_retry() {
        let store = InMemoryOutboxStore::new();
        store
            .put(queued_to("k1", "did:example:bob", 1_000))
            .await
            .unwrap();
        let transport = MockTransport::new(true);

        let report = drain_once(&store, &transport, 1_000).await.unwrap();
        assert_eq!(report.retried, 1);
        assert_eq!(report.backpressured, 0);
        let e = store.get("k1").await.unwrap().unwrap();
        assert_eq!(e.attempts, 1);
        assert_eq!(e.next_attempt_at_ms, 1_000 + backoff_ms(1));
    }

    /// A closed delivery window outranks a full queue: reporting an entry as
    /// merely deferred when it can never be delivered would hide a failure.
    #[tokio::test]
    async fn an_expired_window_fails_even_when_the_destination_is_blocked() {
        let store = InMemoryOutboxStore::new();
        let mut expired = queued_to("late", "did:example:bob", 1_000);
        expired.deliver_by_ms = 1_500;
        store.put(expired).await.unwrap();
        let transport = MockTransport::refusing("did:example:bob", Some(30));

        let report = drain_once(&store, &transport, 2_000).await.unwrap();
        assert_eq!(report.failed, 1);
        assert_eq!(report.backpressured, 0);
        assert_eq!(
            store.get("late").await.unwrap().unwrap().state,
            OutboxState::Failed
        );
    }
}
