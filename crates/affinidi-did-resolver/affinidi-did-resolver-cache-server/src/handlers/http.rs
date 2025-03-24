use crate::SharedData;
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
    match state.resolver.resolve(&did).await {
        Ok(doc) => match serde_json::to_value(doc.doc) {
            Ok(value) => {
                if doc.cache_hit {
                    let mut stats = state.stats.lock().await;
                    stats.increment_cache_hit();
                    stats.increment_resolver_success();
                    stats.increment_did_method_success(doc.method);
                }
                (StatusCode::OK, Json(value))
            }
            Err(e) => {
                let mut stats = state.stats.lock().await;
                stats.increment_resolver_error();
                error!("Error serializing DID ({}) document: {:?}", did, e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "error": e.to_string() })),
                )
            }
        },
        Err(e) => {
            let mut stats = state.stats.lock().await;
            stats.increment_resolver_error();
            error!("Error resolving DID ({}): {:?}", did, e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": e.to_string() })),
            )
        }
    }
}
