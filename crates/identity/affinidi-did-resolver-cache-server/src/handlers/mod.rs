use crate::{SharedData, WebvhLogCache, WebvhLogs, config::Config};
use affinidi_did_resolver_cache_sdk::{DIDCacheClient, ResolveResponse, errors::DIDCacheError};
use axum::{Json, Router, extract::State, http::StatusCode, response::IntoResponse, routing::get};
use std::future::Future;
use std::time::Duration;
use tracing::{info, warn};

pub(crate) mod agent_name;
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

impl ResolveError {
    /// The HTTP status for this failure, as the agent name endpoint answers:
    ///
    /// - `400` — the request is at fault: a malformed DID, an unsupported
    ///   method, or a DID that cannot be resolved as given.
    /// - `404` — the DID's host answered 404 or 410.
    /// - `502` — the DID's host failed (any other status, or no answer), or a
    ///   transport to it failed.
    /// - `504` — resolution timed out.
    /// - `500` — this server is at fault.
    pub(crate) fn status_code(&self) -> StatusCode {
        match self {
            ResolveError::Timeout(_) => StatusCode::GATEWAY_TIMEOUT,
            ResolveError::Resolver(error) => match error {
                DIDCacheError::DIDError(_)
                | DIDCacheError::UnsupportedMethod(_)
                | DIDCacheError::ParsingError(_) => StatusCode::BAD_REQUEST,
                DIDCacheError::NetworkFetch(fetch) => match fetch.status {
                    Some(404 | 410) => StatusCode::NOT_FOUND,
                    _ => StatusCode::BAD_GATEWAY,
                },
                DIDCacheError::TransportError(_) => StatusCode::BAD_GATEWAY,
                DIDCacheError::NetworkTimeout => StatusCode::GATEWAY_TIMEOUT,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            },
        }
    }
}

/// What a client is told about a failure.
///
/// A request-side failure (`4xx`) keeps its detail: it describes the caller's
/// own input and tells them what to fix. A server-side or upstream failure
/// (`5xx`) does not: its text can carry upstream URLs, transport errors and
/// resolver internals, which would make this endpoint an oracle for probing
/// what the server can reach. Those get a generic message and a `reference`
/// (a random correlation id) instead, and the detail is logged under the same
/// reference for the operator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ClientError {
    pub(crate) message: String,
    /// Set for server-side failures: quote it to find the detail in the logs.
    pub(crate) reference: Option<String>,
}

impl ClientError {
    /// Classify `detail` for a response with `status`. `context` names the
    /// operation in the log line (e.g. the DID being resolved).
    pub(crate) fn new(status: StatusCode, detail: &dyn std::fmt::Display, context: &str) -> Self {
        if !status.is_server_error() {
            return Self {
                message: detail.to_string(),
                reference: None,
            };
        }
        let reference = uuid::Uuid::new_v4().simple().to_string();
        warn!(reference = %reference, status = status.as_u16(), "{context}: {detail}");
        let message = match status {
            StatusCode::BAD_GATEWAY => {
                "The DID's host could not be reached or answered with an error"
            }
            StatusCode::GATEWAY_TIMEOUT => "Resolution timed out",
            StatusCode::SERVICE_UNAVAILABLE => "Service temporarily unavailable",
            _ => "Internal server error",
        };
        Self {
            message: message.to_string(),
            reference: Some(reference),
        }
    }

    /// The JSON body of an HTTP error response.
    pub(crate) fn to_json(&self) -> serde_json::Value {
        match &self.reference {
            Some(reference) => serde_json::json!({ "error": self.message, "reference": reference }),
            None => serde_json::json!({ "error": self.message }),
        }
    }

    /// The single string the WebSocket protocol carries for an error.
    pub(crate) fn to_text(&self) -> String {
        match &self.reference {
            Some(reference) => format!("{} (reference {reference})", self.message),
            None => self.message.clone(),
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
/// The target host is derived from the caller-supplied DID, so the URLs are
/// built under `HostPolicy::PublicOnly` (the policy this server's resolver
/// uses), the client refuses redirects and non-public DNS answers, and the
/// response body is capped, to avoid being used as an SSRF pivot / reflection
/// oracle or memory-exhaustion vector.
pub(crate) async fn fetch_webvh_log(
    client: &reqwest::Client,
    cache: Option<&WebvhLogCache>,
    doc_cache_hit: bool,
    did: &str,
) -> WebvhLogs {
    cached_webvh_log(cache, did, doc_cache_hit, || {
        fetch_webvh_log_uncached(client, did)
    })
    .await
}

/// Caching wrapper around an upstream log fetch.
///
/// Split out from [`fetch_webvh_log`] so the caching policy can be tested
/// without network access — the policy, not the HTTP call, is what decides how
/// much load reaches the DID's host.
///
/// Two properties this enforces:
///
/// * **The log tracks the document.** `doc_cache_hit` is whether the DID
///   *document* was served from the resolver's own cache. On a document cache
///   *miss* the server has just resolved a fresh `did:webvh` document — which
///   for webvh means replaying a freshly-fetched log — so a stale cached raw
///   log would disagree with the returned document and a verifying client would
///   reject the pair. On a miss we therefore drop any cached log and refetch,
///   keeping the two in step; only on a document cache *hit* is a cached log
///   served. (Because a miss refreshes the log, a log TTL longer than the
///   document TTL buys nothing — the server clamps it, see `server.rs`.)
/// * **A failed fetch is never cached.** Caching `None` would pin a transient
///   upstream failure (or a rate-limited response) for the whole TTL and turn a
///   blip into sustained unavailability.
///
/// The upstream fetch is single-flighted through moka's `try_get_with`, so N
/// concurrent resolutions of the same cold DID — the exact stampede a cache
/// exists to prevent, and which for a brand-new hot DID are all document cache
/// misses — collapse into one request against the DID's host instead of N.
async fn cached_webvh_log<F, Fut>(
    cache: Option<&WebvhLogCache>,
    did: &str,
    doc_cache_hit: bool,
    fetch: F,
) -> WebvhLogs
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = WebvhLogs>,
{
    // No cache configured: preserve the fetch-on-every-resolution behaviour.
    let Some(cache) = cache else {
        return fetch().await;
    };

    // Document cache miss: the freshly-resolved document must be paired with a
    // freshly-fetched log, never a possibly-stale cached one. Drop any cached
    // entry first; the fetch below is still single-flighted, so a cold hot-DID
    // (every concurrent resolution a miss) collapses to one upstream request.
    if !doc_cache_hit {
        cache.invalidate(did).await;
    }

    // Single-flight the fetch and never cache a failure: `try_get_with` runs the
    // init closure once for concurrent callers of the same key and stores
    // nothing when it returns `Err`, so a failed/`None` fetch leaves the cache
    // untouched. Map that `Err` back to the uncached fetch result.
    cache
        .try_get_with(did.to_string(), async {
            match fetch().await {
                logs @ (Some(_), _) => Ok(logs),
                failed => Err(failed),
            }
        })
        .await
        .unwrap_or_else(|failed| (*failed).clone())
}

async fn fetch_webvh_log_uncached(
    client: &reqwest::Client,
    did: &str,
) -> (Option<String>, Option<String>) {
    let policy = didwebvh_rs::resolve::HostPolicy::PublicOnly;
    let parsed_url = match didwebvh_rs::url::WebVHURL::parse_did_url(did) {
        Ok(url) => url,
        Err(e) => {
            warn!("Failed to parse WebVH DID URL for log fetch: {e}");
            return (None, None);
        }
    };

    let log_url = match parsed_url.get_fetch_url("did.jsonl", policy) {
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
        let witness_url = match parsed_url.get_fetch_url("did-witness.json", policy) {
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

    if config.enable_agent_names {
        // A wildcard capture is required: an agent name contains slashes
        // (`example.com/@alice`), which a single path segment cannot match.
        info!("Enabling Agent Name resolution endpoint (server will fetch caller-supplied URLs)");
        app = app.route(
            "/resolve-name/{*name}",
            get(agent_name::resolve_name_handler),
        );
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
    use std::sync::atomic::{AtomicUsize, Ordering};

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
    fn resolution_failures_map_to_http_statuses() {
        use affinidi_did_resolver_cache_sdk::errors::NetworkFetchError;
        let resolver = |e| ResolveError::Resolver(e).status_code();
        assert_eq!(
            ResolveError::Timeout(30).status_code(),
            StatusCode::GATEWAY_TIMEOUT
        );
        assert_eq!(
            resolver(DIDCacheError::DIDError("bad".into())),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            resolver(DIDCacheError::UnsupportedMethod("foo".into())),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            resolver(DIDCacheError::NetworkFetch(
                NetworkFetchError::new("gone").with_status(404)
            )),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            resolver(DIDCacheError::NetworkFetch(
                NetworkFetchError::new("slow down").with_status(429)
            )),
            StatusCode::BAD_GATEWAY
        );
        assert_eq!(
            resolver(DIDCacheError::NetworkFetch(NetworkFetchError::new(
                "no answer"
            ))),
            StatusCode::BAD_GATEWAY
        );
        assert_eq!(
            resolver(DIDCacheError::TransportError("x".into())),
            StatusCode::BAD_GATEWAY
        );
        assert_eq!(
            resolver(DIDCacheError::NetworkTimeout),
            StatusCode::GATEWAY_TIMEOUT
        );
        assert_eq!(
            resolver(DIDCacheError::ConfigError("x".into())),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    #[test]
    fn did_size_limit_boundary() {
        assert!(did_within_size_limit("did:key:zABC", 1024));
        assert!(did_within_size_limit(&"d".repeat(1024), 1024)); // exactly at limit
        assert!(!did_within_size_limit(&"d".repeat(1025), 1024)); // one over
    }

    fn test_log_cache() -> WebvhLogCache {
        moka::future::Cache::builder()
            .max_capacity(16)
            .time_to_live(Duration::from_secs(60))
            .build()
    }

    /// The whole point of the cache: a repeat resolution of a hot DID must not
    /// reach the DID's own host, which is what rate-limits the client.
    #[tokio::test]
    async fn cache_hit_costs_no_upstream_fetch() {
        let cache = test_log_cache();
        let calls = AtomicUsize::new(0);
        let did = "did:webvh:scid:example.com";
        let fetch = || async {
            calls.fetch_add(1, Ordering::SeqCst);
            (Some("log".to_string()), None)
        };

        for _ in 0..5 {
            let logs = cached_webvh_log(Some(&cache), did, true, fetch).await;
            assert_eq!(
                logs.0.as_deref(),
                Some("log"),
                "cached value is served back"
            );
        }
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "only the first call fetches"
        );
    }

    /// A failed fetch must not be cached: pinning a transient upstream error
    /// (or a 429) for the whole TTL would turn a blip into sustained outage.
    #[tokio::test]
    async fn failed_fetch_is_not_cached() {
        let cache = test_log_cache();
        let calls = AtomicUsize::new(0);
        let fetch = || async {
            calls.fetch_add(1, Ordering::SeqCst);
            (None, None)
        };

        for _ in 0..3 {
            cached_webvh_log(Some(&cache), "did:webvh:scid:example.com", true, fetch).await;
        }
        assert_eq!(
            calls.load(Ordering::SeqCst),
            3,
            "every call retries upstream"
        );
    }

    /// `None` disables caching entirely, preserving the previous behaviour for
    /// operators who need a newly-published log entry visible immediately.
    #[tokio::test]
    async fn disabled_cache_always_fetches() {
        let calls = AtomicUsize::new(0);
        let fetch = || async {
            calls.fetch_add(1, Ordering::SeqCst);
            (Some("log".to_string()), None)
        };

        for _ in 0..3 {
            cached_webvh_log(None, "did:webvh:scid:example.com", true, fetch).await;
        }
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    /// Distinct DIDs must not share an entry.
    #[tokio::test]
    async fn cache_is_keyed_by_did() {
        let cache = test_log_cache();
        let a = cached_webvh_log(Some(&cache), "did:webvh:scid:a.example", true, || async {
            (Some("a".to_string()), None)
        })
        .await;
        let b = cached_webvh_log(Some(&cache), "did:webvh:scid:b.example", true, || async {
            (Some("b".to_string()), None)
        })
        .await;
        assert_eq!(a.0.as_deref(), Some("a"));
        assert_eq!(b.0.as_deref(), Some("b"));
    }

    /// A document cache *miss* must never serve a stale cached log: the freshly
    /// resolved document and its attached `_did_log` have to agree, so a miss
    /// drops any cached entry, refetches, and refreshes the cache.
    #[tokio::test]
    async fn doc_cache_miss_bypasses_stale_log() {
        let cache = test_log_cache();
        // Seed a stale log the way an earlier resolution would have.
        cache
            .insert(
                "did:webvh:scid:example.com".to_string(),
                (Some("stale".to_string()), None),
            )
            .await;

        let calls = AtomicUsize::new(0);
        let fresh = || async {
            calls.fetch_add(1, Ordering::SeqCst);
            (Some("fresh".to_string()), None)
        };

        // Document was a cache MISS: must fetch fresh, not serve "stale".
        let logs = cached_webvh_log(Some(&cache), "did:webvh:scid:example.com", false, fresh).await;
        assert_eq!(
            logs.0.as_deref(),
            Some("fresh"),
            "miss serves the fresh log"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1, "miss fetches upstream");

        // ...and the cache was refreshed, so a subsequent document cache HIT now
        // serves the fresh log without another fetch.
        let hit = cached_webvh_log(Some(&cache), "did:webvh:scid:example.com", true, fresh).await;
        assert_eq!(
            hit.0.as_deref(),
            Some("fresh"),
            "the miss refreshed the entry"
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "the later hit is served from cache"
        );
    }

    /// Single-flight: concurrent cold resolutions of the same DID — a brand-new
    /// hot DID, so all document cache misses — must collapse into exactly one
    /// upstream fetch, not a stampede against the DID's host.
    #[tokio::test]
    async fn concurrent_misses_fetch_once() {
        let cache = test_log_cache();
        let calls = std::sync::Arc::new(AtomicUsize::new(0));
        let did = "did:webvh:scid:hot.example";

        let resolve = |calls: std::sync::Arc<AtomicUsize>| {
            let cache = &cache;
            async move {
                cached_webvh_log(Some(cache), did, false, || async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    // Yield so the other resolutions reach `try_get_with` while
                    // this fetch is still in flight, exercising the coalescing.
                    tokio::task::yield_now().await;
                    (Some("log".to_string()), None)
                })
                .await
            }
        };

        let (a, b, c, d) = tokio::join!(
            resolve(calls.clone()),
            resolve(calls.clone()),
            resolve(calls.clone()),
            resolve(calls.clone()),
        );

        for logs in [&a, &b, &c, &d] {
            assert_eq!(logs.0.as_deref(), Some("log"), "every caller gets the log");
        }
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "concurrent misses coalesce into one upstream fetch"
        );
    }
    /// A request-side failure keeps its detail; a server-side or upstream one
    /// returns only a generic message and a correlation reference, never the
    /// internal error text (upstream URLs, transport errors).
    #[test]
    fn client_errors_hide_server_side_detail() {
        let refused = ResolveError::Resolver(DIDCacheError::DIDError("bad DID".into()));
        let error = ClientError::new(refused.status_code(), &refused, "test");
        assert_eq!(error.reference, None);
        assert!(error.message.contains("bad DID"), "{error:?}");
        assert_eq!(
            error.to_json(),
            serde_json::json!({ "error": error.message })
        );

        let secret = "http://10.0.0.7:8080/.well-known/did.json connection refused";
        for e in [
            ResolveError::Resolver(DIDCacheError::TransportError(secret.into())),
            ResolveError::Resolver(DIDCacheError::ConfigError(secret.into())),
            ResolveError::Timeout(30),
        ] {
            let status = e.status_code();
            assert!(status.is_server_error(), "{e}");
            let error = ClientError::new(status, &e, "test");
            let reference = error
                .reference
                .clone()
                .expect("a server error has a reference");
            assert_eq!(reference.len(), 32);
            let body = error.to_json().to_string();
            let text = error.to_text();
            for leaked in [&body, &text] {
                assert!(!leaked.contains("10.0.0.7"), "{leaked}");
                assert!(!leaked.contains("30s"), "{leaked}");
                assert!(leaked.contains(&reference), "{leaked}");
            }
        }
        let a = ClientError::new(StatusCode::INTERNAL_SERVER_ERROR, &"x", "test");
        let b = ClientError::new(StatusCode::INTERNAL_SERVER_ERROR, &"x", "test");
        assert_ne!(
            a.reference, b.reference,
            "references are unique per failure"
        );
    }
}
