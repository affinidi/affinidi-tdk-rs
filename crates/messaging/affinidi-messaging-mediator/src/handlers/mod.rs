use crate::{
    SharedData, common::session::Session, common::storage_timeout::with_storage_timeout,
    tasks::supervisor::ComponentState,
};
use affinidi_messaging_mediator_common::errors::AppError;
use affinidi_messaging_sdk::messages::SuccessResponse;
use axum::{
    Json, Router,
    extract::State,
    response::IntoResponse,
    routing::{delete, get, post},
};
use http::StatusCode;
use tracing::warn;

pub mod admin_status;
#[cfg(feature = "didcomm")]
pub mod authenticate;
pub mod inbox_fetch;
pub mod message_delete;
#[cfg(feature = "didcomm")]
pub mod message_inbound;
pub mod message_list;
pub mod message_outbound;
#[cfg(feature = "didcomm")]
pub(crate) mod oob_discovery;
pub mod websocket;
pub mod well_known_did_fetch;

pub fn application_routes(api_prefix: &str, shared_data: &SharedData) -> Router {
    #[cfg_attr(not(feature = "didcomm"), allow(unused_mut))]
    let mut app = Router::new()
        // Outbound message handling to ATM clients
        .route(
            "/outbound",
            post(message_outbound::message_outbound_handler),
        )
        .route("/fetch", post(inbox_fetch::inbox_fetch_handler))
        // Listing of messages for a DID
        .route(
            "/list/{did_hash}/{folder}",
            get(message_list::message_list_handler),
        )
        // Delete/remove messages stored in ATM
        .route("/delete", delete(message_delete::message_delete_handler))
        // Websocket endpoint for ATM clients
        .route("/ws", get(websocket::websocket_handler))
        // Helps to test if you are who you think you are
        .route("/whoami", get(whoami_handler))
        .route(
            "/.well-known/did",
            get(well_known_did_fetch::well_known_did_fetch_handler),
        );

    // DIDComm-specific routes
    #[cfg(feature = "didcomm")]
    {
        app = app
            // Inbound message handling from ATM clients
            .route("/inbound", post(message_inbound::message_inbound_handler))
            // Authentication step 1/2 - Client requests challenge from server
            .route(
                "/authenticate/challenge",
                post(authenticate::authentication_challenge),
            )
            // Authentication step 2/2 - Client sends encrypted challenge to server
            .route("/authenticate", post(authenticate::authentication_response))
            .route(
                "/authenticate/refresh",
                post(authenticate::authentication_refresh),
            )
            // Out Of Band Discovery Routes
            .route("/oob", post(oob_discovery::oob_invite_handler))
            .route("/oob", get(oob_discovery::oobid_handler))
            .route("/oob", delete(oob_discovery::delete_oobid_handler));
    }

    // TSP clients reuse `/authenticate/challenge`, then prove control of their VID
    // by signing the challenge (Ed25519) and posting it here. Requires both
    // protocols — it mints the same DIDComm JWT session for a TSP-authenticated VID.
    #[cfg(all(feature = "didcomm", feature = "tsp"))]
    {
        app = app.route(
            "/tsp/authenticate",
            post(authenticate::tsp::tsp_authentication_response),
        );
    }

    // `api_prefix` arrives in the canonical form produced by
    // `config::helpers::normalize_api_prefix`: either `""` (mount at
    // root) or `"/<segment>"` with no trailing slash (the form axum's
    // `Router::nest` requires).
    let api_router = if api_prefix.is_empty() {
        Router::new().merge(app)
    } else {
        Router::new().nest(api_prefix, app)
    };

    // `/.well-known/did.json` and `/.well-known/did.jsonl` are well-known URIs (RFC 8615);
    // both did:web and did:webvh resolvers fetch them at the bare host root, regardless of
    // any HTTP API prefix the service uses for its other routes. Register them on the
    // outer router so they sit at root even when the inner app is nested under `api_prefix`.
    let api_router = if shared_data.config.mediator_did_doc.is_some() {
        let mut r = api_router.route(
            "/.well-known/did.json",
            get(well_known_did_fetch::well_known_did_json_handler),
        );
        // `did.jsonl` is the webvh log stream — register only when the loaded source
        // actually was a log entry. did:web deployments don't have a log to serve.
        if shared_data.config.mediator_did_log.is_some() {
            r = r.route(
                "/.well-known/did.jsonl",
                get(well_known_did_fetch::well_known_did_jsonl_handler),
            );
        }
        r
    } else {
        api_router
    };

    api_router.with_state(shared_data.to_owned())
}

pub async fn health_checker_handler(State(state): State<SharedData>) -> impl IntoResponse {
    let message: String = format!(
        "Affinidi Secure Messaging Mediator Service, Version: {}, Started: UTC {}",
        env!("CARGO_PKG_VERSION"),
        state.service_start_timestamp.format("%Y-%m-%d %H:%M:%S"),
    );

    let response_json = serde_json::json!({
        "status": "success".to_string(),
        "message": message,
    });
    Json(response_json)
}

/// Process-liveness probe. Returns 200 whenever the HTTP server can answer
/// — deliberately decoupled from component readiness so an orchestrator
/// does not kill a mediator that is still serving traffic while a
/// background component is degraded or restarting. Use `/readyz` to decide
/// whether an instance should *receive* traffic.
pub async fn liveness_handler() -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(serde_json::json!({ "status": "alive" })),
    )
}

/// Deep readiness check that verifies the mediator can serve traffic.
/// Checks Redis connectivity, queue health, shutdown state, and the health
/// of supervised background tasks.
///
/// Returns 503 `not_ready` when a hard dependency or a **load-bearing**
/// background task is down; 200 `degraded` when only non-load-bearing
/// components are unhealthy; 200 `ready` otherwise.
pub async fn readiness_handler(State(state): State<SharedData>) -> impl IntoResponse {
    let mut checks: Vec<serde_json::Value> = Vec::new();
    let mut all_ok = true;
    // Non-fatal degradation (non-load-bearing components down). Keeps the
    // instance in rotation (200) but flags the condition for dashboards.
    let mut degraded = false;

    // Check if shutdown has been initiated
    if state.shutdown_token.is_cancelled() {
        all_ok = false;
        checks.push(serde_json::json!({
            "name": "shutdown",
            "status": "fail",
            "message": "Shutdown in progress"
        }));
    } else {
        checks.push(serde_json::json!({
            "name": "shutdown",
            "status": "pass"
        }));
    }

    // Check Redis circuit breaker state
    let cb_state = state.database.circuit_breaker_state();
    if cb_state != "closed" {
        all_ok = false;
        checks.push(serde_json::json!({
            "name": "redis_circuit_breaker",
            "status": "fail",
            "state": cb_state,
            "message": "Redis circuit breaker is not closed"
        }));
    } else {
        checks.push(serde_json::json!({
            "name": "redis_circuit_breaker",
            "status": "pass",
            "state": cb_state
        }));
    }

    // Check Redis connectivity. Bounded so a wedged backend fails the probe
    // promptly rather than hanging the load-balancer health check.
    match with_storage_timeout(
        state.storage_timeout(),
        "get_global_stats",
        "NA",
        state.database.get_global_stats(),
    )
    .await
    {
        Ok(_) => {
            checks.push(serde_json::json!({
                "name": "redis",
                "status": "pass"
            }));
        }
        Err(e) => {
            all_ok = false;
            checks.push(serde_json::json!({
                "name": "redis",
                "status": "fail",
                "message": format!("Redis check failed: {e}")
            }));
        }
    }

    // Check FORWARD_Q length (bounded — see above).
    match with_storage_timeout(
        state.storage_timeout(),
        "forward_queue_len",
        "NA",
        state.database.forward_queue_len(),
    )
    .await
    {
        Ok(len) => {
            let queue_status = if len >= state.config.limits.forward_task_queue {
                all_ok = false;
                "warn"
            } else {
                "pass"
            };
            checks.push(serde_json::json!({
                "name": "forward_queue",
                "status": queue_status,
                "length": len,
                "limit": state.config.limits.forward_task_queue
            }));
        }
        Err(e) => {
            all_ok = false;
            checks.push(serde_json::json!({
                "name": "forward_queue",
                "status": "fail",
                "message": format!("Queue check failed: {e}")
            }));
        }
    }

    // ── Unified secret backend: live probe + cache freshness ─────────
    //
    // Boot-time probe already happened in `Config::TryFrom<ConfigRaw>`
    // (Phase E), so a backend that was reachable at boot is highly
    // likely still reachable here. Re-probing on every /readyz catches
    // mid-flight credential expiries / network blips that the boot-
    // time probe couldn't.
    //
    // /readyz is unauthenticated, so the response must not echo the
    // backend URL or the underlying probe error: those can leak
    // internal hostnames, ARNs, Vault paths, or credential-shaped
    // strings to anyone who can reach the load-balancer probe path.
    // Keep a boolean `secrets_backend_reachable` for monitoring; log
    // the detailed error at warn level for operators.
    let backend_reachable = match state.config.secrets_backend.probe().await {
        Ok(()) => {
            checks.push(serde_json::json!({
                "name": "secrets_backend",
                "status": "pass",
            }));
            true
        }
        Err(e) => {
            all_ok = false;
            warn!(error = %e, "Secret backend probe failed");
            checks.push(serde_json::json!({
                "name": "secrets_backend",
                "status": "fail",
                "message": "Secret backend probe failed",
            }));
            false
        }
    };

    // VTA cache age — `None` means "no cache present", which is fine
    // when self-hosting; only flag it as a problem when the cache is
    // expected but stale beyond its TTL (load_vta_cached_bundle
    // already enforces TTL by returning None on expiry, so a present
    // cache here is by definition still valid).
    let vta_cache_age_secs = match state.config.secrets_backend.load_vta_cached_bundle().await {
        Ok(Some(cached)) => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(cached.fetched_at);
            Some(now.saturating_sub(cached.fetched_at))
        }
        Ok(None) => None,
        Err(e) => {
            // Failing to read the cache isn't fatal — the mediator can
            // still serve traffic from in-memory keys — but it's worth
            // surfacing because it usually indicates an HMAC mismatch
            // (admin key was rotated externally) or a corrupt entry.
            checks.push(serde_json::json!({
                "name": "vta_cache",
                "status": "warn",
                "message": format!("Could not read VTA cache: {e}"),
            }));
            None
        }
    };

    // ── Supervised background-task health ────────────────────────────
    //
    // A load-bearing component that isn't `Running` fails readiness (503);
    // a non-load-bearing one only marks the instance `degraded` (still 200,
    // stays in rotation). A component that is `Running` but has restarted is
    // reported for visibility without affecting the verdict.
    let mut components: Vec<serde_json::Value> = Vec::new();
    for entry in state.component_health.iter() {
        let h = entry.value();
        let healthy = h.state == ComponentState::Running;
        if !healthy {
            if h.load_bearing {
                all_ok = false;
            } else {
                degraded = true;
            }
        }
        components.push(serde_json::json!({
            "name": h.name,
            "state": h.state,
            "load_bearing": h.load_bearing,
            "restarts": h.restarts,
            "last_error": h.last_error,
        }));
    }
    // Stable order so dashboards diffing the payload don't see churn.
    components.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));

    let status_code = if all_ok {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    let status = if !all_ok {
        "not_ready"
    } else if degraded {
        "degraded"
    } else {
        "ready"
    };

    let response = serde_json::json!({
        "status": status,
        "version": env!("CARGO_PKG_VERSION"),
        "uptime_seconds": (chrono::Utc::now() - state.service_start_timestamp).num_seconds(),
        "checks": checks,
        "components": components,
        // Top-level fields (alongside `checks`) so ops dashboards can
        // pluck them without parsing the variable-length checks list.
        // The secrets backend URL is intentionally NOT exposed here —
        // /readyz is unauthenticated and an attacker scraping it should
        // not learn the backend's identity. Operators can read the URL
        // from logs or the authenticated /admin/status endpoint.
        "secrets_backend_reachable": backend_reachable,
        "vta_cache_age_secs": vta_cache_age_secs,
        "operating_keys_loaded": state.config.operating_keys_loaded,
    });

    (status_code, Json(response))
}

/// Determine the current load state of the mediator.
/// Used for load shedding decisions.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum LoadState {
    /// Normal operation
    Normal,
    /// Elevated load — non-essential operations may be deferred
    Elevated,
    /// Critical load — only essential operations allowed
    Critical,
}

impl LoadState {
    pub async fn current(state: &SharedData) -> Self {
        // Check circuit breaker
        if state.database.circuit_breaker_state() != "closed" {
            return LoadState::Critical;
        }

        // Check shutdown
        if state.shutdown_token.is_cancelled() {
            return LoadState::Critical;
        }

        // Check queue depth
        if let Ok(queue_len) = state.database.forward_queue_len().await {
            let limit = state.config.limits.forward_task_queue;
            if queue_len >= limit {
                return LoadState::Critical;
            }
            if queue_len >= limit * 80 / 100 {
                return LoadState::Elevated;
            }
        }

        LoadState::Normal
    }
}

/// Handler that returns the DID registered for this session
pub async fn whoami_handler(
    session: Session,
) -> Result<(StatusCode, Json<SuccessResponse<String>>), AppError> {
    Ok((
        StatusCode::OK,
        Json(SuccessResponse {
            sessionId: "".to_string(),
            data: Some(session.did.clone()),
            httpCode: StatusCode::OK.as_u16(),
            errorCode: 0,
            errorCodeStr: "NA".to_string(),
            message: "Success".to_string(),
        }),
    ))
}
