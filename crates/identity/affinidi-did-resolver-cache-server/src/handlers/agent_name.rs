//! Agent name (DID shortcut) lookup: `GET /did/v1/resolve-name/{*name}`.
//!
//! # Scope: this endpoint maps a name to a DID, and stops there
//!
//! It deliberately does **not** return a DID Document. Following the redirect is
//! the expensive, network-facing, cacheable half of agent name resolution and is
//! worth centralising; turning the resulting DID into a document is already
//! served by `/resolve/{did}`.
//!
//! More importantly it keeps the trust model honest. The mandatory Layer-1 check
//! — that the resolved document's `alsoKnownAs` claims the name — **must** be
//! performed by the client against a document the client resolved itself. A
//! server that returned "here is the name, the DID, and the document, and I
//! promise they agree" would be asking to be trusted as an authority. It is a
//! cache, never a trust anchor. This mirrors `verify_network_response`, where the
//! client independently re-verifies webvh logs rather than believing the server.
//!
//! # SSRF
//!
//! The name is entirely caller-supplied, so this endpoint makes the server issue
//! an HTTP request to an arbitrary host. Two mitigations:
//!
//! - It is **off by default** (`enable_agent_names` in the config).
//! - The resolver refuses non-public addresses (loopback, private, link-local,
//!   cloud metadata) on every redirect hop.
//!
//! Neither is complete — see `agent_names::HttpRedirectResolver::allow_private_addresses`
//! on the residual DNS-rebinding exposure. Enable this only if you accept that
//! your cache server will fetch caller-chosen URLs.

use agent_names::{AgentName, AgentNameResolver};
use axum::{
    Json,
    extract::{Path, State},
};
use http::StatusCode;
use serde_json::{Value, json};
use tracing::{debug, warn};

use crate::SharedData;

/// `GET /did/v1/resolve-name/{*name}`
///
/// The wildcard capture is required because an agent name contains slashes
/// (`example.com/@alice`), which a single `{name}` segment cannot match.
///
/// Success is `200 {"name": "<canonical>", "did": "<did>"}`. The canonical name
/// is echoed so the caller can see exactly what was resolved after
/// normalisation.
pub async fn resolve_name_handler(
    State(state): State<SharedData>,
    Path(name): Path<String>,
) -> (StatusCode, Json<Value>) {
    if name.len() > state.max_did_size {
        state.stats.lock().await.increment_agent_name_error();
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": format!(
                    "Agent name exceeds maximum length of {} bytes",
                    state.max_did_size
                )
            })),
        );
    }

    let parsed = match AgentName::parse(&name) {
        Ok(parsed) => parsed,
        Err(e) => {
            state.stats.lock().await.increment_agent_name_error();
            debug!("rejecting malformed agent name '{name}': {e}");
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": e.to_string() })),
            );
        }
    };

    let Some(resolver) = state.agent_name_resolver.as_ref() else {
        // Route is only registered when enabled, so this is unreachable in
        // practice; answer honestly rather than panicking if it ever is not.
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "Agent name resolution is not enabled on this server" })),
        );
    };

    let outcome = tokio::time::timeout(state.resolve_timeout, resolver.resolve(&parsed)).await;

    match outcome {
        Ok(Some(Ok(did))) => {
            state.stats.lock().await.increment_agent_name_success();
            debug!("resolved agent name '{parsed}' -> '{did}'");
            (
                StatusCode::OK,
                Json(json!({ "name": parsed.as_str(), "did": did })),
            )
        }
        Ok(Some(Err(e))) => {
            state.stats.lock().await.increment_agent_name_error();
            warn!("failed to resolve agent name '{parsed}': {e}");
            (
                StatusCode::BAD_GATEWAY,
                Json(json!({ "error": e.to_string() })),
            )
        }
        Ok(None) => {
            state.stats.lock().await.increment_agent_name_error();
            (
                StatusCode::NOT_FOUND,
                Json(json!({ "error": format!("No resolver could resolve '{parsed}'") })),
            )
        }
        Err(_elapsed) => {
            state.stats.lock().await.increment_agent_name_error();
            warn!("timed out resolving agent name '{parsed}'");
            (
                StatusCode::GATEWAY_TIMEOUT,
                Json(json!({
                    "error": format!(
                        "Timed out after {} seconds resolving agent name",
                        state.resolve_timeout.as_secs()
                    )
                })),
            )
        }
    }
}
