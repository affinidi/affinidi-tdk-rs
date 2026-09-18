//! Removing outbox entries that are finished with.
//!
//! # Why this had to be added
//!
//! [`OutboxStore`] had no way to remove anything. `put` upserted, state moved
//! `Queued → Sent → Delivered | Unconfirmed | Failed`, and there it stopped —
//! so an outbox keyspace grew for the life of the deployment. Nothing was ever
//! freed, and `due()` re-read and re-decoded **every entry ever written** on
//! every tick, so the cost of draining rose with everything that had already
//! drained successfully.
//!
//! # Why terminal entries are kept for a while first
//!
//! `idempotency_key` is what makes at-least-once retry safe: the receiver drops
//! a duplicate carrying a key it has seen. Deleting an entry the moment it
//! settles throws away the local half of that record, so a retry arriving after
//! the reap looks new. The retention window is the compromise — long enough to
//! cover any plausible in-flight duplicate, short enough that the queue is
//! bounded.
//!
//! [`OutboxStore`]: crate::outbox::OutboxStore

use crate::outbox::{OutboxError, OutboxStore};
use std::sync::Arc;
use std::time::Duration;

/// How long a terminal entry is kept before it is reaped.
///
/// Seven days, matching the mediator's own `message_expiry_seconds` default: a
/// duplicate cannot arrive from a message the mediator has already expired, so
/// keeping the dedup record past that point protects against nothing.
pub const TERMINAL_RETENTION: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// What one reap pass did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ReapReport {
    /// Entries removed.
    pub reaped: usize,
    /// Entries whose removal failed. They stay, and the next pass retries them
    /// — a reap that cannot delete must not report success.
    pub failed: usize,
}

/// Remove terminal entries older than `retention`.
///
/// Only terminal entries are eligible: a `Queued` entry is unfinished work and
/// a `Sent` one is still awaiting evidence, and reaping either would be losing
/// a message rather than tidying up after one.
pub async fn reap_terminal(
    store: &dyn OutboxStore,
    now_ms: u64,
    retention: Duration,
) -> Result<ReapReport, OutboxError> {
    let cutoff = now_ms.saturating_sub(retention.as_millis() as u64);
    let mut report = ReapReport::default();

    for entry in store.terminal_before(cutoff).await? {
        // Re-checked rather than trusted: `terminal_before` is implemented per
        // store, and a store that got its filter wrong would otherwise have
        // this delete undelivered work on its behalf.
        if !entry.state.is_terminal() || entry.created_at_ms > cutoff {
            continue;
        }
        match store.remove(&entry.idempotency_key).await {
            Ok(()) => report.reaped += 1,
            Err(e) => {
                tracing::warn!(
                    key = %entry.idempotency_key,
                    error = %e,
                    "outbox reap: could not remove a terminal entry; it stays for the next pass"
                );
                report.failed += 1;
            }
        }
    }

    if report.reaped > 0 || report.failed > 0 {
        tracing::debug!(
            reaped = report.reaped,
            failed = report.failed,
            "outbox reap pass"
        );
    }
    Ok(report)
}

/// Run [`reap_terminal`] every `interval`, forever.
///
/// Errors are logged and the loop continues: a reap is housekeeping, and a
/// store that is briefly unreadable must not stop the process.
pub async fn reap_loop(store: Arc<dyn OutboxStore>, interval: Duration, retention: Duration) {
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        if let Err(e) = reap_terminal(store.as_ref(), now_ms, retention).await {
            tracing::warn!(error = %e, "outbox reap failed; retrying next tick");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::outbox::{InMemoryOutboxStore, OutboxEntry, OutboxState};

    const DAY_MS: u64 = 24 * 60 * 60 * 1000;

    fn entry(key: &str, state: OutboxState, created_at_ms: u64) -> OutboxEntry {
        let mut e = OutboxEntry::new(key, "did:example:dest", vec![1, 2, 3], created_at_ms, 0);
        e.state = state;
        e
    }

    #[tokio::test]
    async fn a_settled_entry_past_retention_is_removed() {
        let store = InMemoryOutboxStore::new();
        store
            .put(entry("old", OutboxState::Delivered, 0))
            .await
            .unwrap();

        let now = 8 * DAY_MS;
        let report = reap_terminal(&store, now, TERMINAL_RETENTION)
            .await
            .unwrap();

        assert_eq!(
            report,
            ReapReport {
                reaped: 1,
                failed: 0
            }
        );
        assert!(store.get("old").await.unwrap().is_none());
    }

    /// The dedup record has to outlive any duplicate that could still arrive,
    /// or a retry landing after the reap reads as new work.
    #[tokio::test]
    async fn a_recently_settled_entry_is_kept() {
        let store = InMemoryOutboxStore::new();
        store
            .put(entry("fresh", OutboxState::Delivered, 7 * DAY_MS))
            .await
            .unwrap();

        let report = reap_terminal(&store, 8 * DAY_MS, TERMINAL_RETENTION)
            .await
            .unwrap();

        assert_eq!(report.reaped, 0);
        assert!(store.get("fresh").await.unwrap().is_some());
    }

    /// The property that matters most: reaping must never lose a message. A
    /// `Queued` entry is unfinished work and a `Sent` one is still awaiting
    /// evidence — age does not make either disposable.
    #[tokio::test]
    async fn unfinished_work_is_never_reaped_however_old() {
        let store = InMemoryOutboxStore::new();
        store.put(entry("q", OutboxState::Queued, 0)).await.unwrap();
        store.put(entry("s", OutboxState::Sent, 0)).await.unwrap();

        let report = reap_terminal(&store, 365 * DAY_MS, TERMINAL_RETENTION)
            .await
            .unwrap();

        assert_eq!(report.reaped, 0, "neither is finished with");
        assert!(store.get("q").await.unwrap().is_some());
        assert!(store.get("s").await.unwrap().is_some());
    }

    /// Every terminal state is eligible — `Unconfirmed` and `Failed` are as
    /// finished as `Delivered`, and leaving them is how the queue grew.
    #[tokio::test]
    async fn every_terminal_state_is_reaped() {
        let store = InMemoryOutboxStore::new();
        for (k, st) in [
            ("d", OutboxState::Delivered),
            ("u", OutboxState::Unconfirmed),
            ("f", OutboxState::Failed),
        ] {
            store.put(entry(k, st, 0)).await.unwrap();
        }

        let report = reap_terminal(&store, 8 * DAY_MS, TERMINAL_RETENTION)
            .await
            .unwrap();

        assert_eq!(report.reaped, 3);
    }
}
