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
    // HTTP
    pub const HTTP_REQUESTS_TOTAL: &str = "http_requests_total";
    pub const HTTP_REQUESTS_IN_FLIGHT: &str = "http_requests_in_flight";
    pub const HTTP_REQUEST_DURATION_SECONDS: &str = "http_request_duration_seconds";

    // Authentication
    pub const AUTH_CHALLENGES_TOTAL: &str = "auth_challenges_total";
    pub const AUTH_SUCCESS_TOTAL: &str = "auth_success_total";
    pub const AUTH_FAILURES_TOTAL: &str = "auth_failures_total";
    pub const AUTH_REFRESH_TOTAL: &str = "auth_refresh_total";

    // Messaging
    pub const MESSAGES_INBOUND_TOTAL: &str = "messages_inbound_total";
    pub const MESSAGES_FORWARDED_TOTAL: &str = "messages_forwarded_total";
    pub const MESSAGES_DELETED_TOTAL: &str = "messages_deleted_total";

    // Forwarding queue
    pub const FORWARD_QUEUE_LENGTH: &str = "forward_queue_length";
    pub const FORWARD_LOOP_DETECTED_TOTAL: &str = "forward_loop_detected_total";

    // Circuit breaker
    pub const CIRCUIT_BREAKER_STATE: &str = "circuit_breaker_state";

    // WebSocket
    pub const ACTIVE_WEBSOCKET_CONNECTIONS: &str = "active_websocket_connections";

    // Rate limiting
    pub const RATE_LIMITED_TOTAL: &str = "rate_limited_total";
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
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4; charset=utf-8")],
        body,
    )
}
