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
pub mod names {
    // ── HTTP ────────────────────────────────────────────────────────────────
    pub const HTTP_REQUESTS_TOTAL: &str = "http_requests_total";
    pub const HTTP_REQUESTS_IN_FLIGHT: &str = "http_requests_in_flight";
    pub const HTTP_REQUEST_DURATION_SECONDS: &str = "http_request_duration_seconds";

    // ── Authentication ──────────────────────────────────────────────────────
    pub const AUTH_CHALLENGES_TOTAL: &str = "auth_challenges_total";
    pub const AUTH_SUCCESS_TOTAL: &str = "auth_success_total";
    pub const AUTH_FAILURES_TOTAL: &str = "auth_failures_total";
    pub const AUTH_REFRESH_TOTAL: &str = "auth_refresh_total";

    // ── Messaging ───────────────────────────────────────────────────────────
    pub const MESSAGES_INBOUND_TOTAL: &str = "messages_inbound_total";
    pub const MESSAGES_STORED_TOTAL: &str = "messages_stored_total";
    pub const MESSAGES_DELIVERED_TOTAL: &str = "messages_delivered_total";
    pub const MESSAGES_FORWARDED_TOTAL: &str = "messages_forwarded_total";
    pub const MESSAGES_DELETED_TOTAL: &str = "messages_deleted_total";
    pub const MESSAGES_EXPIRED_TOTAL: &str = "messages_expired_total";
    pub const MESSAGE_BYTES_INBOUND_TOTAL: &str = "message_bytes_inbound_total";

    // ── Latency histograms ──────────────────────────────────────────────────
    pub const MESSAGE_STORE_DURATION_SECONDS: &str = "message_store_duration_seconds";
    pub const MESSAGE_FETCH_DURATION_SECONDS: &str = "message_fetch_duration_seconds";
    pub const DB_OPERATION_DURATION_SECONDS: &str = "db_operation_duration_seconds";

    // ── Forwarding queue ────────────────────────────────────────────────────
    pub const FORWARD_QUEUE_LENGTH: &str = "forward_queue_length";
    pub const FORWARD_LOOP_DETECTED_TOTAL: &str = "forward_loop_detected_total";
    pub const FORWARD_SUCCESS_TOTAL: &str = "forward_success_total";
    pub const FORWARD_FAILURE_TOTAL: &str = "forward_failure_total";

    // ── Circuit breaker ─────────────────────────────────────────────────────
    pub const CIRCUIT_BREAKER_STATE: &str = "circuit_breaker_state";
    pub const CIRCUIT_BREAKER_TRIPS_TOTAL: &str = "circuit_breaker_trips_total";

    // ── WebSocket ───────────────────────────────────────────────────────────
    pub const ACTIVE_WEBSOCKET_CONNECTIONS: &str = "active_websocket_connections";
    pub const WEBSOCKET_MESSAGES_TOTAL: &str = "websocket_messages_total";

    // ── Rate limiting ───────────────────────────────────────────────────────
    pub const RATE_LIMITED_TOTAL: &str = "rate_limited_total";

    // ── Accounts ────────────────────────────────────────────────────────────
    pub const ACTIVE_SESSIONS: &str = "active_sessions";
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
