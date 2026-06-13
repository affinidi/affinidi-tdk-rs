//! Per-request metrics + structured access-logging middleware.
//!
//! A single `axum::middleware::from_fn` layer that, for every routed request:
//! - tracks in-flight requests (gauge), total requests (counter), and request
//!   duration (histogram) — the `http_requests_*` metrics defined in
//!   [`super::metrics`], previously named but unemitted;
//! - emits one structured `tracing` event with the request id, method, matched
//!   route, status, and latency.
//!
//! **Cardinality:** the metric `route` label is the axum [`MatchedPath`] (the
//! route *template*, e.g. `/inbound`), never the raw URI — so path parameters
//! can't blow up the Prometheus series count. Requests that don't match a route
//! (404s) are bucketed under a single `unmatched` label.
//!
//! Wired as the innermost layer in `server.rs`, so it runs after the request-id
//! layer has stamped the id and inside the router where `MatchedPath` is set.

use axum::{extract::MatchedPath, extract::Request, middleware::Next, response::Response};
use std::time::Instant;
use tracing::info;

use super::metrics::names;
use super::request_id::RequestId;

/// Label value used when a request matches no route (e.g. a 404).
const UNMATCHED_ROUTE: &str = "unmatched";

/// Middleware: record HTTP request metrics and emit a structured access log.
pub async fn track_request(req: Request, next: Next) -> Response {
    let start = Instant::now();
    let method = req.method().clone();
    // Route *template* (bounded cardinality), not the raw path.
    let route = req
        .extensions()
        .get::<MatchedPath>()
        .map(|m| m.as_str().to_owned())
        .unwrap_or_else(|| UNMATCHED_ROUTE.to_owned());
    // Stamped by the outer `RequestIdLayer`; absent only if that layer is gone.
    let request_id = req
        .extensions()
        .get::<RequestId>()
        .map(|r| r.0.clone())
        .unwrap_or_default();

    metrics::gauge!(names::HTTP_REQUESTS_IN_FLIGHT).increment(1.0);
    let response = next.run(req).await;
    metrics::gauge!(names::HTTP_REQUESTS_IN_FLIGHT).decrement(1.0);

    let latency = start.elapsed();
    let status = response.status().as_u16();
    let method = method.as_str();

    metrics::counter!(
        names::HTTP_REQUESTS_TOTAL,
        "method" => method.to_owned(),
        "route" => route.clone(),
        "status" => status.to_string(),
    )
    .increment(1);
    metrics::histogram!(
        names::HTTP_REQUEST_DURATION_SECONDS,
        "method" => method.to_owned(),
        "route" => route.clone(),
    )
    .record(latency.as_secs_f64());

    info!(
        target: "http_access",
        request_id = %request_id,
        method = %method,
        route = %route,
        status = status,
        latency_ms = latency.as_millis() as u64,
        "http request completed"
    );

    response
}
