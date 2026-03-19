use crate::SharedData;
use affinidi_did_resolver_cache_sdk::DIDMethod;
use axum::{
    Json,
    extract::{Path, State},
};
use http::StatusCode;
use serde_json::{Value, json};
use tracing::{error, warn};

/// For did:webvh DIDs, fetch the raw DID log from the source HTTP endpoint
/// so clients can independently verify the cryptographic chain.
async fn fetch_webvh_log(did: &str) -> (Option<String>, Option<String>) {
    let parsed_url = match didwebvh_rs::url::WebVHURL::parse_did_url(did) {
        Ok(url) => url,
        Err(e) => {
            warn!("Failed to parse WebVH DID URL for log fetch: {e}");
            return (None, None);
        }
    };

    let log_url = match parsed_url.get_http_url(Some("did.jsonl")) {
        Ok(url) => url,
        Err(e) => {
            warn!("Failed to construct log URL for WebVH DID: {e}");
            return (None, None);
        }
    };

    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            warn!("Failed to create HTTP client for WebVH log fetch: {e}");
            return (None, None);
        }
    };

    let did_log = match client.get(log_url).send().await {
        Ok(resp) if resp.status().is_success() => match resp.text().await {
            Ok(text) => Some(text),
            Err(e) => {
                warn!("Failed to read WebVH log response body: {e}");
                None
            }
        },
        Ok(resp) => {
            warn!("WebVH log fetch returned HTTP {}: {}", resp.status(), did);
            None
        }
        Err(e) => {
            warn!("Failed to fetch WebVH log for {}: {e}", did);
            None
        }
    };

    // Fetch witness proofs if log was successfully retrieved
    let did_witness_log = if did_log.is_some() {
        let witness_url = match parsed_url.get_http_url(Some("did-witness.json")) {
            Ok(url) => url,
            Err(_) => return (did_log, None),
        };
        match client.get(witness_url).send().await {
            Ok(resp) if resp.status().is_success() => resp.text().await.ok(),
            _ => None,
        }
    } else {
        None
    };

    (did_log, did_witness_log)
}

pub async fn resolver_handler(
    State(state): State<SharedData>,
    Path(did): Path<String>,
) -> (StatusCode, Json<Value>) {
    match state.resolver.resolve(&did).await {
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
                fetch_webvh_log(&did).await
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
                            obj.insert(
                                "_did_witness_log".to_string(),
                                Value::String(witness_log),
                            );
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
