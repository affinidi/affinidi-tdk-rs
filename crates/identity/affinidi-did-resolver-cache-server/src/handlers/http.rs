use crate::{
    SharedData,
    handlers::{did_within_size_limit, fetch_webvh_log, resolve_with_timeout},
};
use affinidi_did_resolver_cache_sdk::DIDMethod;
use axum::{
    Json,
    extract::{Path, State},
};
use http::StatusCode;
use serde_json::{Value, json};
use tracing::error;

pub async fn resolver_handler(
    State(state): State<SharedData>,
    Path(did): Path<String>,
) -> (StatusCode, Json<Value>) {
    if !did_within_size_limit(&did, state.max_did_size) {
        state.stats.lock().await.increment_resolver_error();
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": format!(
                    "DID exceeds maximum length of {} bytes",
                    state.max_did_size
                )
            })),
        );
    }

    match resolve_with_timeout(&state.resolver, state.resolve_timeout, &did).await {
        Ok(doc) => {
            let mut stats = state.stats.lock().await;
            stats.increment_resolver_success();
            if doc.cache_hit {
                stats.increment_cache_hit();
            }
            stats.increment_did_method_success(doc.method.clone());
            drop(stats);

            // For WebVH DIDs, include the raw log so clients can verify
            let (did_log, did_witness_log) = if doc.method == DIDMethod::WEBVH {
                fetch_webvh_log(&state.webvh_client, &did).await
            } else {
                (None, None)
            };

            match serde_json::to_value(&doc.doc) {
                Ok(mut value) => {
                    // Attach log data as metadata fields when available
                    if let Some(obj) = value.as_object_mut() {
                        if let Some(log) = did_log {
                            obj.insert("_did_log".to_string(), Value::String(log));
                        }
                        if let Some(witness_log) = did_witness_log {
                            obj.insert("_did_witness_log".to_string(), Value::String(witness_log));
                        }
                    }
                    (StatusCode::OK, Json(value))
                }
                Err(e) => {
                    state.stats.lock().await.increment_resolver_error();
                    error!("Error serializing DID ({}) document: {:?}", did, e);
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({ "error": e.to_string() })),
                    )
                }
            }
        }
        Err(e) => {
            state.stats.lock().await.increment_resolver_error();
            error!("Error resolving DID ({}): {:?}", did, e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": e.to_string() })),
            )
        }
    }
}
