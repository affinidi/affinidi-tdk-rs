use crate::{SharedData, config::Config};
use affinidi_did_resolver_cache_sdk::{DIDCacheClient, ResolveResponse, errors::DIDCacheError};
use axum::{Json, Router, extract::State, response::IntoResponse, routing::get};
use std::future::Future;
use std::time::Duration;
use tracing::{info, warn};

pub(crate) mod http;
#[cfg(feature = "network")]
pub(crate) mod websocket;

const MAX_WEBVH_LOG_BYTES: usize = 1024 * 1024;

/// Outcome of a timeout-bounded upstream resolution.
#[derive(Debug)]
pub(crate) enum ResolveError {
    /// The resolver itself returned an error.
    Resolver(DIDCacheError),
    /// Resolution did not complete within the configured timeout (seconds).
    Timeout(u64),
}

impl std::fmt::Display for ResolveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResolveError::Resolver(e) => write!(f, "{e}"),
            ResolveError::Timeout(secs) => write!(f, "resolution timed out after {secs}s"),
        }
    }
}

/// Bound a resolution future by `timeout`, turning a hung upstream into a
/// distinct [`ResolveError::Timeout`] so the request path returns an error to
/// the client instead of blocking the connection indefinitely.
async fn apply_timeout<T>(
    timeout: Duration,
    fut: impl Future<Output = Result<T, DIDCacheError>>,
) -> Result<T, ResolveError> {
    match tokio::time::timeout(timeout, fut).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(e)) => Err(ResolveError::Resolver(e)),
        Err(_elapsed) => Err(ResolveError::Timeout(timeout.as_secs())),
    }
}

/// Resolve `did` through `resolver`, bounded by `timeout`.
pub(crate) async fn resolve_with_timeout(
    resolver: &DIDCacheClient,
    timeout: Duration,
    did: &str,
) -> Result<ResolveResponse, ResolveError> {
    apply_timeout(timeout, resolver.resolve(did)).await
}

/// Whether `did` is within the configured byte-length limit. Oversized DIDs are
/// rejected before resolution so a crafted request can't drive unbounded work.
pub(crate) fn did_within_size_limit(did: &str, max: usize) -> bool {
    did.len() <= max
}

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
pub(crate) async fn fetch_webvh_log(
    client: &reqwest::Client,
    did: &str,
) -> (Option<String>, Option<String>) {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn apply_timeout_trips_on_hung_resolution() {
        // A never-resolving future must surface as a timeout, not a hang.
        let fut = std::future::pending::<Result<(), DIDCacheError>>();
        let res = apply_timeout(Duration::from_millis(50), fut).await;
        assert!(matches!(res, Err(ResolveError::Timeout(_))));
    }

    #[tokio::test]
    async fn apply_timeout_passes_fast_success() {
        let res = apply_timeout(
            Duration::from_secs(5),
            std::future::ready(Ok::<_, DIDCacheError>(42)),
        )
        .await;
        assert_eq!(res.unwrap(), 42);
    }

    #[tokio::test]
    async fn apply_timeout_passes_resolver_error() {
        let fut = std::future::ready(Err::<(), _>(DIDCacheError::DIDError("bad".into())));
        let res = apply_timeout(Duration::from_secs(5), fut).await;
        assert!(matches!(res, Err(ResolveError::Resolver(_))));
    }

    #[test]
    fn did_size_limit_boundary() {
        assert!(did_within_size_limit("did:key:zABC", 1024));
        assert!(did_within_size_limit(&"d".repeat(1024), 1024)); // exactly at limit
        assert!(!did_within_size_limit(&"d".repeat(1025), 1024)); // one over
    }
}
