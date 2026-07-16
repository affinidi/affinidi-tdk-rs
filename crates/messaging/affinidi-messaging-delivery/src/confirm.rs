//! End-to-end delivery confirmation (§5a): the `Sent → Delivered | Unconfirmed`
//! transitions.
//!
//! A `Sent` entry is hop-accepted (durably queued at the mediator), **not**
//! delivered. It is watched until either:
//!
//! - **evidence arrives** → [`confirm_delivered`] transitions it `Delivered`
//!   (the strongest evidence — a layer receipt — proves the recipient has and
//!   will process the message; a correlated protocol reply is equivalent); or
//! - **the delivery window passes with no evidence** → the sweep
//!   ([`sweep_confirmations`]) settles it `Unconfirmed`, a truthful "we can't
//!   know", never a false "delivered".
//!
//! This module owns the state machine. The *evidence sources* — the receiver
//! auto-emitting a layer receipt on durable persist, polling the mediator's own
//! outbox for drain, and re-sending over an alternate binding on expiry — layer
//! on top and call [`confirm_delivered`] / drive the sweep.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use affinidi_messaging_core::MessageTransport;

use crate::outbox::{OutboxEntry, OutboxError, OutboxState, OutboxStore};

/// What one confirmation sweep settled.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ConfirmReport {
    /// Expired `Sent` entries settled `Unconfirmed` — no end-to-end evidence was
    /// possible (no layer, no reply, no pickup).
    pub unconfirmed: usize,
    /// Expired `Sent` entries settled `Failed` — delivery-critical, escalation
    /// exhausted. **Surface these** (metric + operator alert).
    pub failed: usize,
    /// Expired `Sent` entries **re-sent over an alternate binding** and re-armed
    /// with a fresh window (a dead mediator ≠ a dead peer); still watched.
    pub rebound: usize,
}

/// How an expired, still-unconfirmed `Sent` entry is escalated (§5a) — the
/// window passing is **never** a silent success. Returned by an
/// [`ExpiryEscalator`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Escalation {
    /// The escalator re-resolved the peer and **re-sent over an alternate
    /// binding** (another transport/mediator the DID document offers). Keep
    /// watching until `deliver_by_ms`, correlating the new hop via `hop_id`. The
    /// entry stays `Sent` (re-hop-accepted on the alternate); the previous
    /// outbox observation is reset.
    Rebound {
        /// The fresh delivery window for the re-sent message.
        deliver_by_ms: u64,
        /// The alternate hop's id, for outbox-drain correlation (`None` if the
        /// alternate binding returns no id).
        hop_id: Option<String>,
    },
    /// No alternate binding is possible (a dead mediator with no fallback) → the
    /// delivery-critical send **failed**; surface it. Distinct from a silent
    /// drop and from `Unconfirmed`.
    Failed,
    /// No end-to-end evidence was ever possible for this recipient (no layer, no
    /// reply, never picks up) → a truthful "we can't know", not a failure.
    Unconfirmed,
}

/// The escalation policy the confirmation sweep applies when a `Sent` entry's
/// delivery window expires with no evidence.
///
/// The concrete escalator — which re-resolves the peer's DID document and
/// re-sends over an alternate transport/mediator — is wired by the service that
/// owns the transports (it lands with multi-transport / Phase 4); the delivery
/// layer only applies the [`Escalation`] outcome. The default policy (no
/// escalator, i.e. [`sweep_confirmations`]) settles every expired entry
/// `Unconfirmed`.
#[async_trait::async_trait]
pub trait ExpiryEscalator: Send + Sync {
    /// Decide how the expired, still-unconfirmed `entry` escalates. Any
    /// alternate-binding re-send is the escalator's own work; it reports the
    /// outcome here.
    async fn escalate(&self, entry: &OutboxEntry) -> Escalation;
}

/// The default policy: settle every expired entry `Unconfirmed` (no alternate
/// binding attempted). What [`sweep_confirmations`] uses.
struct SettleUnconfirmed;

#[async_trait::async_trait]
impl ExpiryEscalator for SettleUnconfirmed {
    async fn escalate(&self, _entry: &OutboxEntry) -> Escalation {
        Escalation::Unconfirmed
    }
}

/// Record end-to-end delivery evidence for `idempotency_key`: transition its
/// outbox entry `Sent → Delivered`.
///
/// Returns `Ok(true)` if an entry was transitioned, `Ok(false)` if there was no
/// matching `Sent` entry (absent, or already terminal — evidence is
/// **idempotent**, so a re-delivered receipt for an already-`Delivered` entry is
/// a harmless no-op).
pub async fn confirm_delivered(
    store: &dyn OutboxStore,
    idempotency_key: &str,
) -> Result<bool, OutboxError> {
    if let Some(mut entry) = store.get(idempotency_key).await?
        && entry.state == OutboxState::Sent
    {
        entry.state = OutboxState::Delivered;
        store.put(entry).await?;
        return Ok(true);
    }
    Ok(false)
}

/// One confirmation sweep at logical time `now_ms`: any `Sent` entry whose
/// delivery window has passed without evidence settles `Unconfirmed`.
///
/// `Unconfirmed` is deliberately distinct from `Failed`: the message *was*
/// hop-accepted (the mediator took it), we just never got end-to-end evidence —
/// a truthful "we can't know", not "delivery failed". (A `Queued` entry that
/// expires before it can even hop-accept is the drain's `Failed` case.)
///
/// To escalate expired entries — re-send over an alternate binding, or fail
/// visibly — instead of always settling `Unconfirmed`, use
/// [`sweep_confirmations_with`].
pub async fn sweep_confirmations(
    store: &dyn OutboxStore,
    now_ms: u64,
) -> Result<ConfirmReport, OutboxError> {
    sweep_confirmations_with(store, now_ms, &SettleUnconfirmed).await
}

/// One confirmation sweep that **escalates** each expired `Sent` entry through
/// `escalator` (§5a) rather than always settling `Unconfirmed`: the window
/// passing is never a silent success.
///
/// Per expired entry, the [`Escalation`] outcome is applied:
/// - [`Escalation::Rebound`] → re-armed with the fresh window + hop, still `Sent`
///   (the escalator already re-sent over the alternate binding), the earlier
///   outbox observation reset so a later drain is unambiguous;
/// - [`Escalation::Failed`] → `Failed` (surface it);
/// - [`Escalation::Unconfirmed`] → `Unconfirmed`.
pub async fn sweep_confirmations_with(
    store: &dyn OutboxStore,
    now_ms: u64,
    escalator: &dyn ExpiryEscalator,
) -> Result<ConfirmReport, OutboxError> {
    let mut report = ConfirmReport::default();
    for mut entry in store.awaiting_confirmation().await? {
        if now_ms < entry.deliver_by_ms {
            continue;
        }
        match escalator.escalate(&entry).await {
            Escalation::Rebound {
                deliver_by_ms,
                hop_id,
            } => {
                entry.deliver_by_ms = deliver_by_ms;
                entry.hop_id = hop_id;
                entry.outbox_observed = false;
                // Stays Sent: the escalator re-sent over the alternate binding
                // and it hop-accepted; we keep watching for evidence.
                store.put(entry).await?;
                report.rebound += 1;
            }
            Escalation::Failed => {
                entry.state = OutboxState::Failed;
                store.put(entry).await?;
                report.failed += 1;
            }
            Escalation::Unconfirmed => {
                entry.state = OutboxState::Unconfirmed;
                store.put(entry).await?;
                report.unconfirmed += 1;
            }
        }
    }
    Ok(report)
}

/// Run [`sweep_confirmations`] every `interval`, forever (until the task is
/// dropped), using the wall clock. A store error on one tick is logged and
/// retried on the next.
pub async fn confirmation_loop(store: Arc<dyn OutboxStore>, interval: Duration) {
    confirmation_loop_with(store, interval, Arc::new(SettleUnconfirmed)).await
}

/// Run [`sweep_confirmations_with`] every `interval`, forever, escalating
/// expired entries through `escalator`. Logs a warning tick whenever entries
/// `Failed` (the operator-alert surface) and a debug tick for rebinds. A store
/// error on one tick is logged and retried on the next.
pub async fn confirmation_loop_with(
    store: Arc<dyn OutboxStore>,
    interval: Duration,
    escalator: Arc<dyn ExpiryEscalator>,
) {
    let mut ticker = tokio::time::interval(interval);
    loop {
        ticker.tick().await;
        match sweep_confirmations_with(store.as_ref(), now_unix_ms(), escalator.as_ref()).await {
            Ok(report) if report.failed > 0 => {
                tracing::warn!(
                    failed = report.failed,
                    unconfirmed = report.unconfirmed,
                    rebound = report.rebound,
                    "delivery window expired with no evidence and no alternate binding — messages FAILED",
                );
            }
            Ok(report) if report != ConfirmReport::default() => {
                tracing::debug!(
                    unconfirmed = report.unconfirmed,
                    rebound = report.rebound,
                    "confirmation sweep escalated expired entries",
                );
            }
            Ok(_) => {}
            Err(e) => {
                tracing::warn!(error = %e, "confirmation sweep failed; retrying next tick")
            }
        }
    }
}

/// What one [`poll_outbox_drain`] pass observed.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct DrainPollReport {
    /// `Sent` entries confirmed `Delivered` because their hop-id **drained** from
    /// the sender's outbox (recipient took pickup).
    pub delivered: usize,
    /// `Sent` entries seen still present in the outbox this pass (awaiting pickup).
    pub observed: usize,
}

/// Poll the transport's outbox for §5a **outbox-drain** evidence.
///
/// The mediator holds a sent message in the sender's outbox until the recipient
/// acks pickup, then deletes it. So a `Sent` entry whose `hop_id` has **drained**
/// from [`MessageTransport::outbox_message_ids`] — after being seen present there
/// — is the transport-level signal that the recipient took delivery, and the
/// entry settles `Delivered`.
///
/// The `outbox_observed` guard handles the mediator's eventual consistency: a
/// hop-id absent immediately after send may simply not be indexed yet, so
/// "absent" only counts as pickup **after** the id has been observed present.
///
/// A transport that gives no outbox signal (`outbox_message_ids` returns `None`,
/// e.g. a stateless REST POST) yields an empty report.
pub async fn poll_outbox_drain(
    transport: &dyn MessageTransport,
    store: &dyn OutboxStore,
) -> Result<DrainPollReport, OutboxError> {
    let Some(ids) = transport
        .outbox_message_ids()
        .await
        .map_err(|e| OutboxError::Backend(format!("outbox list failed: {e}")))?
    else {
        return Ok(DrainPollReport::default());
    };
    let present: HashSet<&str> = ids.iter().map(String::as_str).collect();

    let mut report = DrainPollReport::default();
    for mut entry in store.awaiting_confirmation().await? {
        let Some(hop_id) = entry.hop_id.clone() else {
            continue;
        };
        if present.contains(hop_id.as_str()) {
            // Still queued at the mediator — awaiting pickup. Record that we've
            // now seen it, so a later drain is unambiguous.
            if !entry.outbox_observed {
                entry.outbox_observed = true;
                store.put(entry).await?;
            }
            report.observed += 1;
        } else if entry.outbox_observed {
            // Was present, now gone → recipient picked up → Delivered.
            confirm_delivered(store, &entry.idempotency_key).await?;
            report.delivered += 1;
        }
        // else: absent and never observed → too early (eventual consistency); skip.
    }
    Ok(report)
}

/// Run [`poll_outbox_drain`] every `interval`, forever (until the task is
/// dropped). A store/transport error on one tick is logged and retried next.
pub async fn outbox_drain_loop(
    transport: Arc<dyn MessageTransport>,
    store: Arc<dyn OutboxStore>,
    interval: Duration,
) {
    let mut ticker = tokio::time::interval(interval);
    loop {
        ticker.tick().await;
        match poll_outbox_drain(transport.as_ref(), store.as_ref()).await {
            Ok(report) if report.delivered > 0 => {
                tracing::debug!(
                    delivered = report.delivered,
                    observed = report.observed,
                    "outbox-drain confirmed deliveries",
                );
            }
            Ok(_) => {}
            Err(e) => tracing::warn!(error = %e, "outbox-drain poll failed; retrying next tick"),
        }
    }
}

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

    /// A `Sent` entry with `deliver_by = created + 60s`.
    async fn sent_entry(store: &InMemoryOutboxStore, key: &str, created: u64) {
        let mut e = OutboxEntry::new(key, "did:example:bob", vec![1], created, created + 60_000);
        e.state = OutboxState::Sent;
        store.put(e).await.unwrap();
    }

    #[tokio::test]
    async fn evidence_confirms_a_sent_entry_and_is_idempotent() {
        let store = InMemoryOutboxStore::new();
        sent_entry(&store, "k1", 1_000).await;

        assert!(confirm_delivered(&store, "k1").await.unwrap());
        assert_eq!(
            store.get("k1").await.unwrap().unwrap().state,
            OutboxState::Delivered
        );

        // Evidence is idempotent: a second (re-delivered) receipt is a no-op.
        assert!(!confirm_delivered(&store, "k1").await.unwrap());
        // Unknown key → no-op, not an error.
        assert!(!confirm_delivered(&store, "nope").await.unwrap());
    }

    #[tokio::test]
    async fn confirm_does_not_touch_a_queued_entry() {
        let store = InMemoryOutboxStore::new();
        // Queued (not yet hop-accepted) — evidence for it shouldn't apply.
        store
            .put(OutboxEntry::new("k1", "did:x", vec![1], 1_000, 61_000))
            .await
            .unwrap();
        assert!(!confirm_delivered(&store, "k1").await.unwrap());
        assert_eq!(
            store.get("k1").await.unwrap().unwrap().state,
            OutboxState::Queued
        );
    }

    #[tokio::test]
    async fn sweep_settles_expired_sent_entries_unconfirmed() {
        let store = InMemoryOutboxStore::new();
        sent_entry(&store, "expired", 1_000).await; // deliver_by = 61_000
        sent_entry(&store, "in_window", 1_000).await;
        // Confirm one so it's terminal (Delivered) — the sweep ignores it.
        confirm_delivered(&store, "in_window").await.unwrap();

        // Before expiry: nothing settled.
        assert_eq!(
            sweep_confirmations(&store, 30_000)
                .await
                .unwrap()
                .unconfirmed,
            0
        );

        // Past the window: the still-Sent entry settles Unconfirmed.
        let report = sweep_confirmations(&store, 61_000).await.unwrap();
        assert_eq!(report.unconfirmed, 1);
        assert_eq!(
            store.get("expired").await.unwrap().unwrap().state,
            OutboxState::Unconfirmed
        );
        // The Delivered entry is untouched.
        assert_eq!(
            store.get("in_window").await.unwrap().unwrap().state,
            OutboxState::Delivered
        );
    }

    // ── Escalation on window expiry (§5a) ────────────────────────────────

    /// An escalator that returns a fixed decision, for driving the sweep.
    struct FixedEscalator(Escalation);
    #[async_trait::async_trait]
    impl ExpiryEscalator for FixedEscalator {
        async fn escalate(&self, _entry: &OutboxEntry) -> Escalation {
            self.0.clone()
        }
    }

    #[tokio::test]
    async fn escalate_rebound_rearms_the_window_and_keeps_watching() {
        let store = InMemoryOutboxStore::new();
        sent_entry(&store, "k", 1_000).await; // deliver_by = 61_000, Sent
        // Mark it observed so we can prove the rebind resets that observation.
        let mut e = store.get("k").await.unwrap().unwrap();
        e.outbox_observed = true;
        store.put(e).await.unwrap();

        let esc = FixedEscalator(Escalation::Rebound {
            deliver_by_ms: 200_000,
            hop_id: Some("h2".into()),
        });
        let report = sweep_confirmations_with(&store, 61_000, &esc)
            .await
            .unwrap();
        assert_eq!(report.rebound, 1);
        assert_eq!(report.failed, 0);
        assert_eq!(report.unconfirmed, 0);

        let e = store.get("k").await.unwrap().unwrap();
        assert_eq!(e.state, OutboxState::Sent); // still watched
        assert_eq!(e.deliver_by_ms, 200_000); // fresh window
        assert_eq!(e.hop_id.as_deref(), Some("h2")); // alternate hop
        assert!(!e.outbox_observed); // reset for the alternate binding

        // Before the NEW window expires, another sweep leaves it alone.
        let report = sweep_confirmations_with(&store, 100_000, &esc)
            .await
            .unwrap();
        assert_eq!(report, ConfirmReport::default());
        assert_eq!(
            store.get("k").await.unwrap().unwrap().state,
            OutboxState::Sent
        );
    }

    #[tokio::test]
    async fn escalate_failed_settles_failed_and_is_reported() {
        let store = InMemoryOutboxStore::new();
        sent_entry(&store, "k", 1_000).await;
        let report = sweep_confirmations_with(&store, 61_000, &FixedEscalator(Escalation::Failed))
            .await
            .unwrap();
        assert_eq!(report.failed, 1);
        assert_eq!(
            store.get("k").await.unwrap().unwrap().state,
            OutboxState::Failed
        );
    }

    #[tokio::test]
    async fn escalate_unconfirmed_matches_the_default_sweep() {
        let store = InMemoryOutboxStore::new();
        sent_entry(&store, "k", 1_000).await;
        let report =
            sweep_confirmations_with(&store, 61_000, &FixedEscalator(Escalation::Unconfirmed))
                .await
                .unwrap();
        assert_eq!(report.unconfirmed, 1);
        assert_eq!(
            store.get("k").await.unwrap().unwrap().state,
            OutboxState::Unconfirmed
        );
    }

    #[tokio::test]
    async fn escalator_is_not_called_before_expiry() {
        // An in-window entry must never be escalated (it would fail a live send).
        let store = InMemoryOutboxStore::new();
        sent_entry(&store, "k", 1_000).await; // deliver_by = 61_000
        let report = sweep_confirmations_with(&store, 30_000, &FixedEscalator(Escalation::Failed))
            .await
            .unwrap();
        assert_eq!(report, ConfirmReport::default());
        assert_eq!(
            store.get("k").await.unwrap().unwrap().state,
            OutboxState::Sent
        );
    }

    // ── Outbox-drain evidence (§5a) ──────────────────────────────────────

    use affinidi_messaging_core::{ConnState, Inbound, InboundAck, SendReceipt, TransportKind};
    use futures_util::stream::{self, BoxStream};
    use std::sync::Mutex;
    use tokio::sync::watch;

    /// A transport whose `outbox_message_ids` the test drives.
    struct DrainMockTransport {
        outbox: Mutex<Option<Vec<String>>>,
        conn_rx: watch::Receiver<ConnState>,
        _conn_tx: watch::Sender<ConnState>,
    }

    impl DrainMockTransport {
        fn new(outbox: Option<Vec<String>>) -> Self {
            let (tx, rx) = watch::channel(ConnState::Connected);
            Self {
                outbox: Mutex::new(outbox),
                conn_rx: rx,
                _conn_tx: tx,
            }
        }
        fn set_outbox(&self, ids: Vec<String>) {
            *self.outbox.lock().unwrap() = Some(ids);
        }
    }

    #[async_trait::async_trait]
    impl MessageTransport for DrainMockTransport {
        fn kind(&self) -> TransportKind {
            TransportKind::Didcomm
        }
        async fn send(
            &self,
            _dest: &str,
            _packed: Vec<u8>,
        ) -> Result<SendReceipt, affinidi_messaging_core::MessagingError> {
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
        async fn ack(
            &self,
            _ack: InboundAck,
        ) -> Result<(), affinidi_messaging_core::MessagingError> {
            Ok(())
        }
        async fn outbox_message_ids(
            &self,
        ) -> Result<Option<Vec<String>>, affinidi_messaging_core::MessagingError> {
            Ok(self.outbox.lock().unwrap().clone())
        }
    }

    async fn sent_with_hop(store: &InMemoryOutboxStore, key: &str, hop: &str) {
        let mut e = OutboxEntry::new(key, "did:example:bob", vec![1], 1_000, 61_000);
        e.state = OutboxState::Sent;
        e.hop_id = Some(hop.to_string());
        store.put(e).await.unwrap();
    }

    #[tokio::test]
    async fn drain_observes_then_confirms_delivered() {
        let store = InMemoryOutboxStore::new();
        sent_with_hop(&store, "k1", "h1").await;
        let transport = DrainMockTransport::new(Some(vec!["h1".to_string()]));

        // Pass 1: h1 is present → observed, not yet delivered.
        let r = poll_outbox_drain(&transport, &store).await.unwrap();
        assert_eq!(r.observed, 1);
        assert_eq!(r.delivered, 0);
        let e = store.get("k1").await.unwrap().unwrap();
        assert!(e.outbox_observed);
        assert_eq!(e.state, OutboxState::Sent);

        // h1 drains from the outbox (recipient picked up).
        transport.set_outbox(vec![]);

        // Pass 2: h1 absent AFTER being observed → Delivered.
        let r = poll_outbox_drain(&transport, &store).await.unwrap();
        assert_eq!(r.delivered, 1);
        assert_eq!(
            store.get("k1").await.unwrap().unwrap().state,
            OutboxState::Delivered
        );
    }

    #[tokio::test]
    async fn drain_absent_before_observed_does_not_confirm() {
        // Eventual-consistency guard: a hop-id not yet indexed in the outbox
        // must NOT be read as a drain.
        let store = InMemoryOutboxStore::new();
        sent_with_hop(&store, "k1", "h1").await;
        let transport = DrainMockTransport::new(Some(vec![])); // h1 not indexed yet

        let r = poll_outbox_drain(&transport, &store).await.unwrap();
        assert_eq!(r.delivered, 0);
        let e = store.get("k1").await.unwrap().unwrap();
        assert_eq!(e.state, OutboxState::Sent);
        assert!(!e.outbox_observed);
    }

    #[tokio::test]
    async fn drain_no_transport_signal_is_a_noop() {
        let store = InMemoryOutboxStore::new();
        sent_with_hop(&store, "k1", "h1").await;
        let transport = DrainMockTransport::new(None); // transport gives no outbox signal

        let r = poll_outbox_drain(&transport, &store).await.unwrap();
        assert_eq!(r, DrainPollReport::default());
        assert_eq!(
            store.get("k1").await.unwrap().unwrap().state,
            OutboxState::Sent
        );
    }
}
