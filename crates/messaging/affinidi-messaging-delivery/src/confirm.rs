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

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::outbox::{OutboxError, OutboxState, OutboxStore};

/// What one [`sweep_confirmations`] pass settled.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ConfirmReport {
    /// `Sent` entries whose window expired with no evidence (→ `Unconfirmed`).
    pub unconfirmed: usize,
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
pub async fn sweep_confirmations(
    store: &dyn OutboxStore,
    now_ms: u64,
) -> Result<ConfirmReport, OutboxError> {
    let mut report = ConfirmReport::default();
    for mut entry in store.awaiting_confirmation().await? {
        if now_ms >= entry.deliver_by_ms {
            entry.state = OutboxState::Unconfirmed;
            store.put(entry).await?;
            report.unconfirmed += 1;
        }
    }
    Ok(report)
}

/// Run [`sweep_confirmations`] every `interval`, forever (until the task is
/// dropped), using the wall clock. A store error on one tick is logged and
/// retried on the next.
pub async fn confirmation_loop(store: Arc<dyn OutboxStore>, interval: Duration) {
    let mut ticker = tokio::time::interval(interval);
    loop {
        ticker.tick().await;
        match sweep_confirmations(store.as_ref(), now_unix_ms()).await {
            Ok(report) if report != ConfirmReport::default() => {
                tracing::debug!(
                    unconfirmed = report.unconfirmed,
                    "confirmation sweep settled entries as Unconfirmed",
                );
            }
            Ok(_) => {}
            Err(e) => {
                tracing::warn!(error = %e, "confirmation sweep failed; retrying next tick")
            }
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
}
