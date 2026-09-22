//! Prometheus metrics setup and HTTP endpoint.
//!
//! Uses the `metrics` facade with the `metrics-exporter-prometheus` backend.
//! Key counters, gauges, and histograms are defined here and recorded
//! throughout the mediator codebase.

use axum::{extract::State, response::IntoResponse};
use http::{StatusCode, header};
use metrics_exporter_prometheus::{Matcher, PrometheusBuilder, PrometheusHandle};
use tracing::{Level, event};

/// Metric names used across the mediator.
///
/// Each constant documents its Prometheus type (counter, gauge, or histogram)
/// for use with the `metrics` crate macros:
/// - **counter**: monotonically increasing (use `metrics::counter!()`)
/// - **gauge**: value that can go up or down (use `metrics::gauge!()`)
/// - **histogram**: distribution of values (use `metrics::histogram!()`)
pub mod names {
    // ── HTTP ────────────────────────────────────────────────────────────────

    /// counter: Total HTTP requests received (all endpoints)
    pub const HTTP_REQUESTS_TOTAL: &str = "http_requests_total";
    /// gauge: HTTP requests currently being processed
    pub const HTTP_REQUESTS_IN_FLIGHT: &str = "http_requests_in_flight";
    /// histogram: HTTP request processing duration in seconds
    pub const HTTP_REQUEST_DURATION_SECONDS: &str = "http_request_duration_seconds";

    // ── Authentication ──────────────────────────────────────────────────────

    /// counter: Authentication challenges issued
    pub const AUTH_CHALLENGES_TOTAL: &str = "auth_challenges_total";
    /// counter: Successful authentications
    pub const AUTH_SUCCESS_TOTAL: &str = "auth_success_total";
    /// counter: Failed authentication attempts (label: reason)
    pub const AUTH_FAILURES_TOTAL: &str = "auth_failures_total";
    /// counter: JWT token refreshes
    pub const AUTH_REFRESH_TOTAL: &str = "auth_refresh_total";

    // ── Messaging ───────────────────────────────────────────────────────────

    /// counter: Messages received at the inbound endpoint
    pub const MESSAGES_INBOUND_TOTAL: &str = "messages_inbound_total";
    /// counter: Messages stored in database
    pub const MESSAGES_STORED_TOTAL: &str = "messages_stored_total";
    /// counter: Messages delivered to recipients
    pub const MESSAGES_DELIVERED_TOTAL: &str = "messages_delivered_total";
    /// counter: Messages enqueued for remote forwarding
    pub const MESSAGES_FORWARDED_TOTAL: &str = "messages_forwarded_total";
    /// counter: Messages deleted (by user or expiry)
    pub const MESSAGES_DELETED_TOTAL: &str = "messages_deleted_total";
    /// counter: Messages removed by the expiry cleanup processor
    pub const MESSAGES_EXPIRED_TOTAL: &str = "messages_expired_total";
    /// counter: Activity-record writes the store refused or failed
    pub const ACCOUNT_ACTIVITY_WRITE_FAILURES_TOTAL: &str = "account_activity_write_failures_total";
    /// counter: Total inbound message bytes
    pub const MESSAGE_BYTES_INBOUND_TOTAL: &str = "message_bytes_inbound_total";

    // ── Latency histograms ──────────────────────────────────────────────────

    /// histogram: Time to store a message in Redis (seconds)
    pub const MESSAGE_STORE_DURATION_SECONDS: &str = "message_store_duration_seconds";
    /// histogram: Time to fetch messages from Redis (seconds)
    pub const MESSAGE_FETCH_DURATION_SECONDS: &str = "message_fetch_duration_seconds";
    /// histogram: Generic database operation duration (seconds)
    pub const DB_OPERATION_DURATION_SECONDS: &str = "db_operation_duration_seconds";

    // ── Forwarding queue ────────────────────────────────────────────────────

    /// gauge: Current depth of the forwarding queue (FORWARD_Q stream length)
    pub const FORWARD_QUEUE_LENGTH: &str = "forward_queue_length";
    /// counter: Messages dropped due to forwarding loop detection (hop count exceeded)
    pub const FORWARD_LOOP_DETECTED_TOTAL: &str = "forward_loop_detected_total";
    /// counter: Messages successfully forwarded to remote mediators
    pub const FORWARD_SUCCESS_TOTAL: &str = "forward_success_total";
    /// counter: Messages that failed to forward (will retry or be abandoned)
    pub const FORWARD_FAILURE_TOTAL: &str = "forward_failure_total";

    // ── Circuit breaker ─────────────────────────────────────────────────────

    /// gauge: Redis circuit breaker state (0=closed, 1=open, 2=half_open)
    pub const CIRCUIT_BREAKER_STATE: &str = "circuit_breaker_state";
    /// counter: Number of times the circuit breaker tripped (closed → open)
    pub const CIRCUIT_BREAKER_TRIPS_TOTAL: &str = "circuit_breaker_trips_total";

    // ── WebSocket ───────────────────────────────────────────────────────────

    /// gauge: Currently active WebSocket connections
    pub const ACTIVE_WEBSOCKET_CONNECTIONS: &str = "active_websocket_connections";
    /// counter: Messages delivered via WebSocket live streaming
    pub const WEBSOCKET_MESSAGES_TOTAL: &str = "websocket_messages_total";
    /// counter: Live-delivery pushes dropped because the send-buffer byte budget
    /// (`limits.ws_send_buffer`) or a connection's queue was full. Not message
    /// loss — the message is durable in the recipient's inbox and arrives on the
    /// next poll or on reconnect. A rising rate means slow WebSocket consumers,
    /// or a `ws_send_buffer` sized too small for the live-delivery fan-out.
    pub const WS_LIVE_DELIVERY_DROPPED: &str = "ws_live_delivery_dropped_total";
    /// counter: Message-pickup `status` messages pushed to a client because a
    /// live notification for it had been dropped.
    ///
    /// Pairs with [`WS_LIVE_DELIVERY_DROPPED`], and the two do not match one
    /// for one by design: repeated drops for the same congested client collapse
    /// into a single signal, since the client's answer to any number of them is
    /// the same single drain, and a further one is suppressed until
    /// `MIN_RESYNC_INTERVAL` has passed.
    ///
    /// So a flat count beside climbing drops is **not** on its own a fault — a
    /// sustained-congestion client produces exactly that. Read it with
    /// [`WS_LIVE_RESYNC_SUPPRESSED`]: drops climbing while *both* stay flat is
    /// the shape that means the signal is not going out at all.
    pub const WS_LIVE_RESYNC_SENT: &str = "ws_live_resync_sent_total";
    /// counter: Resync signals held back because the per-socket minimum
    /// interval had not elapsed.
    ///
    /// Not an error: the signal stays raised and goes out on the next wake-up
    /// past the floor. It exists so that "suppressed by design" can be told
    /// apart from "never generated", which is the distinction an alert on
    /// [`WS_LIVE_RESYNC_SENT`] alone cannot make.
    pub const WS_LIVE_RESYNC_SUPPRESSED: &str = "ws_live_resync_suppressed_total";
    /// gauge: Bytes currently free in the global WebSocket send-buffer pool.
    pub const WS_SEND_BUFFER_AVAILABLE_BYTES: &str = "ws_send_buffer_available_bytes";
    /// counter: Old WebSocket sessions displaced by a newer duplicate for the same DID
    pub const WEBSOCKET_DUPLICATE_REPLACEMENTS_TOTAL: &str =
        "websocket_duplicate_replacements_total";
    /// counter: Inbox messages re-pushed to a surviving socket after a duplicate replacement
    pub const WEBSOCKET_REDELIVERED_MESSAGES_TOTAL: &str = "websocket_redelivered_messages_total";
    /// counter: Duplicate replacements occurring within the churn window (flip-flop signal)
    pub const WEBSOCKET_DUPLICATE_CHURN_TOTAL: &str = "websocket_duplicate_churn_total";
    /// counter: New WebSocket registrations refused because the DID was in a
    /// sustained replacement duel and the incumbent socket was still alive.
    /// Non-zero means the duel damper is holding a DID's slot steady — pair it
    /// with `WEBSOCKET_DUPLICATE_CHURN_TOTAL` to find the offending DID.
    pub const WEBSOCKET_CHURN_REFUSED_TOTAL: &str = "websocket_churn_refused_total";

    // ── Rate limiting ───────────────────────────────────────────────────────

    /// counter: Requests rejected by rate limiter (label: scope = ip|did)
    pub const RATE_LIMITED_TOTAL: &str = "rate_limited_total";

    // ── Queue depth ─────────────────────────────────────────────────────────
    //
    // Sampled once per statistics cycle by `tasks::queue_survey`. Until these
    // existed the only queue a deployment could see was the forwarding one
    // (`FORWARD_QUEUE_LENGTH`) — a per-DID inbox or outbox backing up was
    // invisible until it crossed a limit and started refusing traffic, which
    // is a page rather than an alert.

    /// counter: Messages refused by a queue-depth gate (label: gate =
    /// peer|sender|recipient), counted where the gate refuses in
    /// `messages::queue_limits`.
    ///
    /// `peer` is the per-relationship cap and the one that moves first when a
    /// single peer stops collecting; `sender` and `recipient` are the coarse
    /// per-DID ceilings. A rising `peer` beside flat totals is one stuck
    /// relationship. Rising `sender` means a DID is at its global ceiling,
    /// which after the defaults moved to 2000/10000 should be rare enough to
    /// alert on directly.
    pub const QUEUE_LIMIT_REFUSALS_TOTAL: &str = "queue_limit_refusals_total";
    /// gauge: Messages currently queued across surveyed accounts (label:
    /// folder = inbox|outbox).
    ///
    /// Inbox and outbox count the *same* stored messages from the two ends —
    /// a message is one recipient's inbox entry and one sender's outbox entry
    /// — so they are not additive, and outbox is the lower of the two by
    /// construction (anonymous senders have no outbox entry at all; see
    /// [`QUEUE_OLDEST_AGE_SECONDS`]).
    pub const QUEUE_DEPTH_MESSAGES: &str = "queue_depth_messages";
    /// gauge: Bytes currently queued across surveyed accounts (label: folder
    /// = inbox|outbox). Same non-additive caveat as [`QUEUE_DEPTH_MESSAGES`].
    pub const QUEUE_DEPTH_BYTES: &str = "queue_depth_bytes";
    /// gauge: Age in seconds of the oldest message still queued, across the
    /// accounts probed this cycle (label: folder = inbox|outbox).
    ///
    /// **The signal for a queue that has stopped draining.** Depth alone
    /// cannot distinguish a busy queue from a stuck one; age can. A value
    /// climbing steadily toward `message_expiry_seconds` means nothing is
    /// collecting and the only thing that will clear the queue is expiry.
    ///
    /// Two limits on what it sees, both by construction rather than by
    /// accident. It covers only the accounts probed this cycle — the deepest
    /// queues, capped at `MAX_AGE_PROBES` — so a shallow queue that is very
    /// old can be missed while deeper ones exist. And the outbox series is
    /// blind to anonymous senders: an outbox entry is only allocated when the
    /// sender is known, so anonymous traffic appears in the inbox series
    /// alone. Read the pair, not either half.
    pub const QUEUE_OLDEST_AGE_SECONDS: &str = "queue_oldest_age_seconds";
    /// gauge: Highest ratio of used-to-permitted queue depth seen on any
    /// surveyed account (label: folder = inbox|outbox), where 1.0 means an
    /// account is exactly at the limit at which it starts being refused.
    ///
    /// This is the early warning the refusal counters cannot be: it moves
    /// before anything is refused. An account with no explicit limit is
    /// measured against the configured default; an account set to unlimited
    /// (`-1`) is excluded rather than counted as 0, since it has no ratio.
    pub const QUEUE_MAX_SATURATION_RATIO: &str = "queue_max_saturation_ratio";
    /// gauge: Messages in the sample that had already been handed to their
    /// recipient (label: folder = inbox|outbox).
    ///
    /// A **sample**, not a census — read with
    /// [`QUEUE_DELIVERED_UNACKED_SAMPLE_SIZE`]. A full count would mean reading
    /// every queued message's delivery state every cycle, which is the scan
    /// this survey exists to avoid.
    ///
    /// **This pair is what says whether `limits.delivered_expiry_seconds` is
    /// worth turning on.** A high ratio means queues are holding work that is
    /// already done, occupying senders' allowances for nothing; a ratio near
    /// zero means enabling it would change little and is not worth the
    /// durability trade. Multiply the ratio by
    /// [`QUEUE_DEPTH_MESSAGES`] for an estimate of the messages involved.
    ///
    /// Sampled from the **oldest** end of the deepest queues, because that is
    /// where a delivered-and-still-queued message accumulates; the newest end
    /// is mostly messages nobody has had a chance to collect.
    pub const QUEUE_DELIVERED_UNACKED: &str = "queue_delivered_unacked_messages";
    /// gauge: How many messages were examined to produce
    /// [`QUEUE_DELIVERED_UNACKED`] (label: folder = inbox|outbox).
    ///
    /// Zero means nothing was sampled this cycle — every probed queue was
    /// empty, or every sample failed — and the companion gauge should be read
    /// as "no data" rather than "none delivered".
    pub const QUEUE_DELIVERED_UNACKED_SAMPLE_SIZE: &str = "queue_delivered_unacked_sample_size";
    /// gauge: Accounts examined in the most recent survey.
    pub const QUEUE_ACCOUNTS_SURVEYED: &str = "queue_accounts_surveyed";
    /// gauge: 1 when the survey stopped at `MAX_ACCOUNTS_PER_SURVEY` before
    /// reaching the end of the account list, 0 when it covered everything.
    ///
    /// Non-zero means the depth totals and the saturation maximum are lower
    /// bounds rather than true values. It exists so a partial survey reports
    /// itself instead of quietly under-reporting, which for a metric whose
    /// job is to catch a queue nobody is watching would be the worst
    /// available failure.
    pub const QUEUE_SURVEY_TRUNCATED: &str = "queue_survey_truncated";

    // ── Delivery state ──────────────────────────────────────────────────────
    //
    // Defined in `mediator-common` beside the code that emits them, and
    // re-exported here so every metric name is still findable in one place.

    /// counter: Messages whose expiry was brought forward because they had
    /// been delivered (`limits.delivered_expiry_seconds`).
    ///
    /// Absent on a default deployment, where that limit is `0` and the
    /// shortening is off — the series is not emitted at all rather than
    /// emitted as a flat zero, because those mean different things.
    pub use affinidi_messaging_mediator_common::store::delivery_metrics::DELIVERED_EXPIRY_ADVANCED as MESSAGES_DELIVERED_EXPIRY_ADVANCED_TOTAL;
    /// counter: Messages handed to a recipient for the **first** time.
    ///
    /// Paired with [`MESSAGES_REDELIVERED_TOTAL`]: the ratio between them is
    /// how much of a deployment's pickup traffic is re-doing work it has
    /// already done.
    pub use affinidi_messaging_mediator_common::store::delivery_metrics::FIRST_DELIVERED as MESSAGES_FIRST_DELIVERED_TOTAL;
    /// counter: Handovers of a message already delivered at least
    /// `POISON_ATTEMPTS` times.
    ///
    /// **Classification only — nothing is evicted because of it.** `attempts`
    /// is driven by the recipient, which decides when to fetch, so a threshold
    /// on it is something a recipient can reach at will. Making eviction more
    /// aggressive on that basis would let a recipient destroy a sender's
    /// messages by doing nothing but collecting them repeatedly, so this
    /// counts and reports rather than acting.
    ///
    /// What it is good for is telling apart two failures that look identical
    /// on a depth graph: a recipient that never came back, and a recipient
    /// that keeps taking a message and never finishing with it.
    pub use affinidi_messaging_mediator_common::store::delivery_metrics::POISON_SUSPECTED as MESSAGES_POISON_SUSPECTED_TOTAL;
    /// counter: Handovers of a message that had already been delivered.
    ///
    /// Normal in small numbers — a reconnect, a restart, a client that polls
    /// before acknowledging. A sustained rate means messages are being
    /// collected and not released, which is the shape that fills a sender's
    /// queue with work that is already done.
    pub use affinidi_messaging_mediator_common::store::delivery_metrics::REDELIVERED as MESSAGES_REDELIVERED_TOTAL;

    // ── Redis stored functions ──────────────────────────────────────────────

    /// gauge: whether the Lua library the deployment loads is the one this
    /// binary was built against — `1` match, `0` mismatch, `-1` the check
    /// could not be performed.
    ///
    /// `0` does **not** mean the library failed to load — a failed load is a
    /// startup error and the mediator never gets here. It means the load
    /// succeeded against a *different* file: `functions_file` points at a copy
    /// from another release. That is a silent downgrade, because the function
    /// names are unchanged between versions and only the bodies differ, so
    /// every call still succeeds and simply does less. The per-relationship
    /// accounting added in 0.27.0 is the worked example — an older library
    /// never writes `PEER_Q`, so `peer_queue_count` reads 0 for ever and the
    /// gate that depends on it is inert while appearing healthy.
    ///
    /// `-1` is a distinct state on purpose. A check that could not read its
    /// file has reached no verdict, and collapsing that into either `0` or `1`
    /// gives one value two meanings — one benign, one not. Alert on `== 0`
    /// for a wrong library and on `< 0` for a check that is not running; a
    /// series that is merely absent is a third thing again.
    ///
    /// A non-`1` value also shows as `degraded` on `/readyz` (200, in
    /// rotation) via the `redis_stored_functions` component. It is
    /// deliberately not load-bearing: what it reports is a *fairness* control
    /// being inert, not an authorization one, so nothing becomes reachable
    /// that was not already.
    pub const REDIS_FUNCTIONS_MATCH_BUILD: &str = "redis_functions_match_build";

    // ── Accounts ────────────────────────────────────────────────────────────

    /// gauge: Currently active authenticated sessions
    pub const ACTIVE_SESSIONS: &str = "active_sessions";
    /// counter: Requests denied by ACL checks (label: action)
    pub const ACL_DENIALS_TOTAL: &str = "acl_denials_total";

    // ── VTA secrets refresh ───────────────────────────────────────────────────

    /// counter: VTA secrets-refresh attempts (label: result = vta|cache|error).
    /// `vta` = fresh material fetched, `cache` = VTA unreachable so the cache was
    /// reused, `error` = the refresh call itself failed.
    pub const VTA_REFRESH_TOTAL: &str = "vta_refresh_total";
    /// histogram: VTA refresh round-trip duration in seconds
    pub const VTA_REFRESH_DURATION_SECONDS: &str = "vta_refresh_duration_seconds";
    /// gauge: Unix timestamp (seconds) of the last successful refresh *from the
    /// VTA*. Alert on `time() - <this>` exceeding the expected cadence to catch a
    /// VTA that has been unreachable across several refresh windows.
    pub const VTA_LAST_SUCCESS_TIMESTAMP_SECONDS: &str = "vta_last_success_timestamp_seconds";

    // ── Global store totals ───────────────────────────────────────────────────
    //
    // Sampled once per cycle by the statistics task from the store's own
    // cumulative metadata (`get_global_stats`) and published with `.absolute()`.
    // These are authoritative server-side totals — distinct from the per-request
    // counters above (e.g. `messages_inbound_total` counts inbound HTTP requests,
    // while `messages_stored_total` — defined in the Messaging section above and
    // activated here — is the store's persisted total).

    /// counter: Message bytes received/stored (cumulative store total)
    pub const STORE_RECEIVED_BYTES_TOTAL: &str = "store_received_bytes_total";
    /// counter: Message bytes sent/delivered (cumulative store total)
    pub const STORE_SENT_BYTES_TOTAL: &str = "store_sent_bytes_total";
    /// counter: Message bytes deleted (cumulative store total)
    pub const STORE_DELETED_BYTES_TOTAL: &str = "store_deleted_bytes_total";
    /// counter: WebSocket connections opened (cumulative store total)
    pub const WEBSOCKET_CONNECTIONS_OPENED_TOTAL: &str = "websocket_connections_opened_total";
    /// counter: WebSocket connections closed (cumulative store total)
    pub const WEBSOCKET_CONNECTIONS_CLOSED_TOTAL: &str = "websocket_connections_closed_total";
    /// counter: Sessions created (cumulative store total)
    pub const SESSIONS_CREATED_TOTAL: &str = "sessions_created_total";
    /// counter: Sessions that completed authentication (cumulative store total)
    pub const SESSIONS_AUTHENTICATED_TOTAL: &str = "sessions_authenticated_total";
    /// counter: OOB invitations created (cumulative store total)
    pub const OOB_INVITES_CREATED_TOTAL: &str = "oob_invites_created_total";
    /// counter: OOB invitations claimed (cumulative store total)
    pub const OOB_INVITES_CLAIMED_TOTAL: &str = "oob_invites_claimed_total";
}

/// Histogram bucket boundaries (seconds) applied to every `*_duration_seconds`
/// metric. Without this, the Prometheus exporter falls back to its default
/// summary/quantile rendering, which loses the cross-instance aggregatability
/// that fixed buckets give. The range spans sub-millisecond local work up to the
/// ~10s tail of a slow VTA round-trip or contended store operation.
const DURATION_BUCKETS_SECONDS: &[f64] = &[
    0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

/// Initialize the Prometheus metrics recorder and return a handle
/// that can be used to render the metrics output.
pub fn init_metrics() -> Option<PrometheusHandle> {
    let builder = match PrometheusBuilder::new().set_buckets_for_metric(
        Matcher::Suffix("_duration_seconds".into()),
        DURATION_BUCKETS_SECONDS,
    ) {
        Ok(builder) => builder,
        Err(e) => {
            // A bad bucket set is a programming error, not a runtime one — fall
            // back to the default exporter rather than dropping metrics entirely.
            event!(
                Level::WARN,
                "Failed to configure metrics histogram buckets: {}. Using exporter defaults.",
                e
            );
            PrometheusBuilder::new()
        }
    };
    match builder.install_recorder() {
        Ok(handle) => {
            event!(Level::INFO, "Prometheus metrics recorder installed");
            Some(handle)
        }
        Err(e) => {
            event!(
                Level::WARN,
                "Failed to install Prometheus metrics recorder: {}. Metrics will be unavailable.",
                e
            );
            None
        }
    }
}

/// GET /metrics — renders Prometheus text exposition format.
pub async fn metrics_handler(State(handle): State<PrometheusHandle>) -> impl IntoResponse {
    let body = handle.render();
    (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        body,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The histogram buckets must be strictly ascending and accepted by the
    /// exporter — otherwise `init_metrics` silently falls back to the default
    /// (bucket-less) renderer, and the duration histograms lose their fixed
    /// boundaries without any compile- or boot-time signal.
    #[test]
    fn duration_buckets_are_sorted_and_accepted() {
        assert!(
            DURATION_BUCKETS_SECONDS.windows(2).all(|w| w[0] < w[1]),
            "duration buckets must be strictly ascending"
        );
        assert!(
            PrometheusBuilder::new()
                .set_buckets_for_metric(
                    Matcher::Suffix("_duration_seconds".into()),
                    DURATION_BUCKETS_SECONDS,
                )
                .is_ok(),
            "exporter rejected the duration bucket set"
        );
    }
}
