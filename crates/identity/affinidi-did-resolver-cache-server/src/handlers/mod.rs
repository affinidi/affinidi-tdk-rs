use crate::{SharedData, config::Config};
use axum::{Json, Router, extract::State, response::IntoResponse, routing::get};
use tracing::{info, warn};

pub(crate) mod http;
#[cfg(feature = "network")]
pub(crate) mod websocket;

const MAX_WEBVH_LOG_BYTES: usize = 1024 * 1024;

/// Read a response body as UTF-8 text, refusing anything larger than `limit` bytes.
async fn read_text_limited(mut resp: reqwest::Response, limit: usize) -> Option<String> {
    let mut buf = Vec::new();
    loop {
        match resp.chunk().await {
            Ok(Some(chunk)) => {
                if buf.len() + chunk.len() > limit {
                    warn!("WebVH log body exceeded {limit} byte cap; dropping");
                    return None;
                }
                buf.extend_from_slice(&chunk);
            }
            Ok(None) => break,
            Err(e) => {
                warn!("Failed to read WebVH log response body: {e}");
                return None;
            }
        }
    }
    String::from_utf8(buf).ok()
}

/// For did:webvh DIDs, fetch the raw DID log + witness file from the source
/// HTTP endpoint so clients can independently verify the cryptographic chain.
///
/// The target host is derived from the caller-supplied DID, so this client
/// refuses redirects and caps the response body to avoid being used as an SSRF
/// pivot / reflection oracle or memory-exhaustion vector.
pub(crate) async fn fetch_webvh_log(did: &str) -> (Option<String>, Option<String>) {
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
        .redirect(reqwest::redirect::Policy::none())
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            warn!("Failed to create HTTP client for WebVH log fetch: {e}");
            return (None, None);
        }
    };

    let did_log = match client.get(log_url).send().await {
        Ok(resp) if resp.status().is_success() => {
            read_text_limited(resp, MAX_WEBVH_LOG_BYTES).await
        }
        Ok(resp) => {
            warn!("WebVH log fetch returned HTTP {}: {}", resp.status(), did);
            None
        }
        Err(e) => {
            warn!("Failed to fetch WebVH log for {}: {e}", did);
            None
        }
    };

    let did_witness_log = if did_log.is_some() {
        let witness_url = match parsed_url.get_http_url(Some("did-witness.json")) {
            Ok(url) => url,
            Err(_) => return (did_log, None),
        };
        match client.get(witness_url).send().await {
            Ok(resp) if resp.status().is_success() => {
                read_text_limited(resp, MAX_WEBVH_LOG_BYTES).await
            }
            _ => None,
        }
    } else {
        None
    };

    (did_log, did_witness_log)
}

pub fn application_routes(shared_data: &SharedData, config: &Config) -> Router {
    let mut app = Router::new();

    #[cfg(feature = "network")]
    if config.enable_websocket_endpoint {
        info!("Enabling WebSocket Resolver endpoint");
        app = app.route("/ws", get(websocket::websocket_handler));
    }
    #[cfg(not(feature = "network"))]
    if config.enable_websocket_endpoint {
        info!(
            "WebSocket Resolver endpoint requested but `network` feature is disabled — skipping /ws"
        );
    }

    if config.enable_http_endpoint {
        info!("Enabling HTTP Resolver endpoint");
        app = app.route("/resolve/{did}", get(http::resolver_handler));
    }

    Router::new()
        .nest("/did/v1", app)
        .with_state(shared_data.to_owned())
}

pub async fn health_checker_handler(State(state): State<SharedData>) -> impl IntoResponse {
    let message: String = format!(
        "Affinidi Trust Network - DID Cache, Version: {}, Started: UTC {}",
        env!("CARGO_PKG_VERSION"),
        state.service_start_timestamp.format("%Y-%m-%d %H:%M:%S"),
    );

    let response_json = serde_json::json!({
        "status": "success".to_string(),
        "message": message,
    });
    Json(response_json)
}
