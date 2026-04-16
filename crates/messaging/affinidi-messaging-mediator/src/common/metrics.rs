//! Prometheus metrics setup and HTTP endpoint.
//!
//! Uses the `metrics` facade with the `metrics-exporter-prometheus` backend.
//! Key counters, gauges, and histograms are defined here and recorded
//! throughout the mediator codebase.

use axum::{extract::State, response::IntoResponse};
use http::{StatusCode, header};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
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

    // ── Rate limiting ───────────────────────────────────────────────────────

    /// counter: Requests rejected by rate limiter (label: scope = ip|did)
    pub const RATE_LIMITED_TOTAL: &str = "rate_limited_total";

    // ── Accounts ────────────────────────────────────────────────────────────

    /// gauge: Currently active authenticated sessions
    pub const ACTIVE_SESSIONS: &str = "active_sessions";
    /// counter: Requests denied by ACL checks (label: action)
    pub const ACL_DENIALS_TOTAL: &str = "acl_denials_total";
}

/// Initialize the Prometheus metrics recorder and return a handle
/// that can be used to render the metrics output.
pub fn init_metrics() -> Option<PrometheusHandle> {
    match PrometheusBuilder::new().install_recorder() {
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
