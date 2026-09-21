use crate::common::metrics::names;
use crate::tasks::queue_survey::{
    self, QueueSnapshot, QueueSnapshotCell, QueueSurvey, SurveyDefaults,
};
use affinidi_messaging_mediator_common::{
    errors::MediatorError,
    store::{MediatorStore, types::MetadataStats},
    types::clock::Clock,
};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tracing::{Instrument, Level, debug, info, span, warn};

/// [`statistics_with_snapshot`] without a snapshot consumer — for embedded
/// callers that spawn the task themselves and serve no Trust Tasks.
pub async fn statistics(
    database: Arc<dyn MediatorStore>,
    tags: HashMap<String, String>,
    clock: Arc<dyn Clock>,
    queue_defaults: SurveyDefaults,
) -> Result<(), MediatorError> {
    statistics_with_snapshot(
        database,
        tags,
        clock,
        queue_defaults,
        QueueSnapshotCell::default(),
    )
    .await
}

/// Periodically logs statistics about the database.
/// Is spawned as a task from main().
pub async fn statistics_with_snapshot(
    database: Arc<dyn MediatorStore>,
    tags: HashMap<String, String>,
    clock: Arc<dyn Clock>,
    queue_defaults: SurveyDefaults,
    snapshot: QueueSnapshotCell,
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
            publish_queue_metrics(&database, &clock, queue_defaults, &tags, &snapshot).await;

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

/// Run a queue survey and publish it.
///
/// Best-effort like the rest of this task: a store error here is logged and
/// the cycle moves on, because a metrics path that can stall the statistics
/// loop is worse than a missing sample.
///
/// The gauges are set on every cycle including the empty one — a queue that
/// drains must drive its age gauge back to zero rather than leaving the last
/// non-zero reading standing, which would look identical to a queue that is
/// still stuck.
async fn publish_queue_metrics(
    database: &Arc<dyn MediatorStore>,
    clock: &Arc<dyn Clock>,
    defaults: SurveyDefaults,
    tags: &HashMap<String, String>,
    snapshot: &QueueSnapshotCell,
) {
    let survey = match queue_survey::survey(database.as_ref(), clock, defaults).await {
        Ok(survey) => survey,
        Err(e) => {
            debug!("queue survey unavailable this cycle: {e}");
            return;
        }
    };

    for (folder, stats) in [("inbox", &survey.inbox), ("outbox", &survey.outbox)] {
        metrics::gauge!(names::QUEUE_DEPTH_MESSAGES, "folder" => folder).set(stats.messages as f64);
        metrics::gauge!(names::QUEUE_DEPTH_BYTES, "folder" => folder).set(stats.bytes as f64);
        metrics::gauge!(names::QUEUE_OLDEST_AGE_SECONDS, "folder" => folder)
            .set(stats.oldest.as_ref().map_or(0.0, |o| o.age_secs as f64));
        metrics::gauge!(names::QUEUE_MAX_SATURATION_RATIO, "folder" => folder)
            .set(stats.max_saturation.unwrap_or(0.0));
        metrics::gauge!(names::QUEUE_DELIVERED_UNACKED, "folder" => folder)
            .set(stats.delivered_unacked as f64);
        metrics::gauge!(names::QUEUE_DELIVERED_UNACKED_SAMPLE_SIZE, "folder" => folder)
            .set(stats.sampled as f64);
    }
    metrics::gauge!(names::QUEUE_ACCOUNTS_SURVEYED).set(survey.accounts_surveyed as f64);
    metrics::gauge!(names::QUEUE_SURVEY_TRUNCATED).set(u8::from(survey.truncated) as f64);

    log_survey(&survey, tags);

    let taken_at = chrono::DateTime::from_timestamp(clock.unix_secs() as i64, 0)
        .unwrap_or_else(chrono::Utc::now);
    snapshot.publish(QueueSnapshot { taken_at, survey });
}

/// Log the survey alongside the `UpdateStats` events, so a deployment without
/// a Prometheus scrape still gets the numbers.
///
/// The oldest queue's DID hash is logged but never used as a metric label:
/// there is one label value per DID, which is exactly the unbounded
/// cardinality that makes a Prometheus server fall over. The log line is where
/// an operator learns *which* queue is stuck; the gauge only says that one is.
fn log_survey(survey: &QueueSurvey, tags: &HashMap<String, String>) {
    if survey.truncated {
        warn!(
            ?tags,
            accounts_surveyed = survey.accounts_surveyed,
            cap = queue_survey::MAX_ACCOUNTS_PER_SURVEY,
            "queue survey hit its account cap — depth totals and saturation are lower bounds, \
             not true values"
        );
    }
    info!(
        event_type = "QueueSurvey",
        ?tags,
        accounts_surveyed = survey.accounts_surveyed,
        truncated = survey.truncated,
        inbox_messages = survey.inbox.messages,
        inbox_bytes = survey.inbox.bytes,
        inbox_max_saturation = survey.inbox.max_saturation,
        inbox_oldest_age_secs = survey.inbox.oldest.as_ref().map(|o| o.age_secs),
        inbox_oldest_did_hash = survey.inbox.oldest.as_ref().map(|o| o.did_hash.as_str()),
        inbox_delivered_unacked = survey.inbox.delivered_unacked,
        inbox_sampled = survey.inbox.sampled,
        outbox_messages = survey.outbox.messages,
        outbox_bytes = survey.outbox.bytes,
        outbox_max_saturation = survey.outbox.max_saturation,
        outbox_oldest_age_secs = survey.outbox.oldest.as_ref().map(|o| o.age_secs),
        outbox_oldest_did_hash = survey.outbox.oldest.as_ref().map(|o| o.did_hash.as_str()),
        outbox_delivered_unacked = survey.outbox.delivered_unacked,
        outbox_sampled = survey.outbox.sampled,
    );
}
