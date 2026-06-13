use crate::common::metrics::names;
use affinidi_messaging_mediator_common::{
    errors::MediatorError,
    store::{MediatorStore, types::MetadataStats},
};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tracing::{Instrument, Level, debug, info, span};

/// Periodically logs statistics about the database.
/// Is spawned as a task from main().
pub async fn statistics(
    database: Arc<dyn MediatorStore>,
    tags: HashMap<String, String>,
) -> Result<(), MediatorError> {
    let _span = span!(Level::INFO, "statistics");

    async move {
        debug!("Starting statistics thread...");
        let mut interval = tokio::time::interval(Duration::from_secs(60));

        let mut previous_stats = MetadataStats::default();

        loop {
            interval.tick().await;
            let stats = database.get_global_stats().await?;
            let delta = stats.delta(&previous_stats);
            info!(
                event_type = "UpdateStats",
                ?tags,
                received_bytes = stats.received_bytes,
                sent_bytes = stats.sent_bytes,
                deleted_bytes = stats.deleted_bytes,
                received_count = stats.received_count,
                sent_count = stats.sent_count,
                deleted_count = stats.deleted_count,
                websocket_open = stats.websocket_open,
                websocket_close = stats.websocket_close,
                sessions_created = stats.sessions_created,
                sessions_success = stats.sessions_success,
                oob_invites_created = stats.oob_invites_created,
                oob_invites_claimed = stats.oob_invites_claimed
            );

            info!(
                event_type = "UpdateDeltaStats",
                ?tags,
                received_bytes = delta.received_bytes,
                sent_bytes = delta.sent_bytes,
                deleted_bytes = delta.deleted_bytes,
                received_count = delta.received_count,
                sent_count = delta.sent_count,
                deleted_count = delta.deleted_count,
                websocket_open = delta.websocket_open,
                websocket_close = delta.websocket_close,
                sessions_created = delta.sessions_created,
                sessions_success = delta.sessions_success,
                oob_invites_created = delta.oob_invites_created,
                oob_invites_claimed = delta.oob_invites_claimed
            );

            publish_metrics(&database, &stats).await;

            previous_stats = stats;
        }
    }
    .instrument(_span)
    .await
}

/// Bridge the store's cumulative metadata into Prometheus on each statistics
/// cycle. The byte/count/connection/session totals are monotonic absolute
/// values, so they are published as counters via `.absolute()`; the forwarding
/// queue length is a point-in-time depth, so it is a gauge.
///
/// This is the only place these totals reach Prometheus — they are otherwise
/// log-only (the `UpdateStats` event above). Sampling them here (rather than
/// incrementing at each call site) keeps the hot paths untouched and the store's
/// own counters authoritative.
async fn publish_metrics(database: &Arc<dyn MediatorStore>, stats: &MetadataStats) {
    // Forwarding queue depth — point-in-time gauge. Best-effort: a transient
    // store error here must not disturb the stats loop.
    match database.forward_queue_len().await {
        Ok(len) => metrics::gauge!(names::FORWARD_QUEUE_LENGTH).set(len as f64),
        Err(e) => debug!("forward_queue_len for metrics unavailable this cycle: {e}"),
    }

    // Cumulative store totals → absolute counters. `i64` values are clamped at 0
    // before the `u64` cast (the store never reports negatives, but the cast must
    // be saturating rather than wrapping).
    let totals: [(&str, i64); 12] = [
        (names::MESSAGES_STORED_TOTAL, stats.received_count),
        (names::MESSAGES_DELIVERED_TOTAL, stats.sent_count),
        (names::MESSAGES_DELETED_TOTAL, stats.deleted_count),
        (names::STORE_RECEIVED_BYTES_TOTAL, stats.received_bytes),
        (names::STORE_SENT_BYTES_TOTAL, stats.sent_bytes),
        (names::STORE_DELETED_BYTES_TOTAL, stats.deleted_bytes),
        (
            names::WEBSOCKET_CONNECTIONS_OPENED_TOTAL,
            stats.websocket_open,
        ),
        (
            names::WEBSOCKET_CONNECTIONS_CLOSED_TOTAL,
            stats.websocket_close,
        ),
        (names::SESSIONS_CREATED_TOTAL, stats.sessions_created),
        (names::SESSIONS_AUTHENTICATED_TOTAL, stats.sessions_success),
        (names::OOB_INVITES_CREATED_TOTAL, stats.oob_invites_created),
        (names::OOB_INVITES_CLAIMED_TOTAL, stats.oob_invites_claimed),
    ];
    for (name, value) in totals {
        metrics::counter!(name).absolute(value.max(0) as u64);
    }
}
