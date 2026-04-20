use crate::{SharedData, database::session::Session};
use affinidi_messaging_mediator_common::errors::AppError;
use affinidi_messaging_sdk::messages::SuccessResponse;
use axum::{
    Json, Router,
    extract::State,
    response::IntoResponse,
    routing::{delete, get, post},
};
use http::StatusCode;

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

    let has_prefix = api_prefix.is_empty() || api_prefix == "/";

    app = if shared_data.config.mediator_did_doc.is_some() {
        let well_known_prefix = if has_prefix { "/.well-known" } else { "" };
        app.route(
            &format!("{}/did.json", well_known_prefix),
            get(well_known_did_fetch::well_known_did_doc_handler),
        )
        .route(
            &format!("{}/did.jsonl", well_known_prefix),
            get(well_known_did_fetch::well_known_did_doc_handler),
        )
    } else {
        app
    };

    (if has_prefix {
        Router::new().merge(app)
    } else {
        Router::new().nest(api_prefix, app)
    })
    .with_state(shared_data.to_owned())
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

/// Deep readiness check that verifies the mediator can serve traffic.
/// Checks Redis connectivity, queue health, and shutdown state.
pub async fn readiness_handler(State(state): State<SharedData>) -> impl IntoResponse {
    let mut checks: Vec<serde_json::Value> = Vec::new();
    let mut all_ok = true;

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

    // Check Redis connectivity
    match state.database.get_db_metadata().await {
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

    // Check FORWARD_Q length
    match state.database.get_forward_tasks_len().await {
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
    let backend_reachable = match state.config.secrets_backend.probe().await {
        Ok(()) => {
            checks.push(serde_json::json!({
                "name": "secrets_backend",
                "status": "pass",
                "url": state.config.secrets_backend_url,
            }));
            true
        }
        Err(e) => {
            all_ok = false;
            checks.push(serde_json::json!({
                "name": "secrets_backend",
                "status": "fail",
                "url": state.config.secrets_backend_url,
                "message": format!("Secret backend probe failed: {e}"),
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

    let status_code = if all_ok {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    let response = serde_json::json!({
        "status": if all_ok { "ready" } else { "not_ready" },
        "version": env!("CARGO_PKG_VERSION"),
        "uptime_seconds": (chrono::Utc::now() - state.service_start_timestamp).num_seconds(),
        "checks": checks,
        // Top-level fields (alongside `checks`) so ops dashboards can
        // pluck them without parsing the variable-length checks list.
        "secrets_backend_reachable": backend_reachable,
        "secrets_backend_url": state.config.secrets_backend_url,
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
        if let Ok(queue_len) = state.database.get_forward_tasks_len().await {
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
