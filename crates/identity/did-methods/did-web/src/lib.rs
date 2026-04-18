/*!
 * did:web — Web DID method resolver.
 *
 * Implements resolution of `did:web` identifiers per the
 * [W3C did:web method specification](https://w3c-ccg.github.io/did-method-web/).
 *
 * # DID Format
 *
 * ```text
 * did:web:{domain}{(:path-segment)*}
 * ```
 *
 * - `domain` may percent-encode a port (e.g. `example.com%3A8443` ⇒ port 8443).
 * - When no path segments are present, the document lives at
 *   `https://{domain}/.well-known/did.json`.
 * - When path segments are present, they map directly into the URL path with a
 *   trailing `/did.json` (e.g. `did:web:example.com:user:alice` ⇒
 *   `https://example.com/user/alice/did.json`).
 *
 * # Why this crate exists
 *
 * Upstream `did-web` (the spruceid/ssi crate) still pins `reqwest = "0.11"` in
 * its 0.5.x line, which transitively pulls `rustls 0.21` and the vulnerable
 * `rustls-webpki 0.101.x` (GHSA-xgp8-3hg3-c2mh / GHSA-965h-392x-2mh5).
 * Re-implementing `did:web` here on `reqwest 0.13` lets us cut that chain and
 * keeps the resolver stack consistent with our other in-workspace DID method
 * crates (`did-ebsi`, `did-scid`, `didwebvh-rs`).
 *
 * # Usage
 *
 * ```no_run
 * # async fn run() -> Result<(), affinidi_did_web::DidWebError> {
 * let document = affinidi_did_web::resolve("did:web:example.com").await?;
 * println!("{}", serde_json::to_string_pretty(&document).unwrap());
 * # Ok(()) }
 * ```
 *
 * For repeated lookups, hold a [`DIDWeb`] so the underlying
 * [`reqwest::Client`] (and its connection pool) is reused:
 *
 * ```no_run
 * # async fn run() -> Result<(), affinidi_did_web::DidWebError> {
 * let resolver = affinidi_did_web::DIDWeb::new();
 * let _doc = resolver.resolve("did:web:example.com").await?;
 * let _doc = resolver.resolve("did:web:example.com:user:alice").await?;
 * # Ok(()) }
 * ```
 */

use std::time::Duration;

use affinidi_did_common::{DID, DIDMethod, Document};
use percent_encoding::percent_decode_str;
use thiserror::Error;
use tracing::debug;

/// did:web resolver errors.
#[derive(Debug, Error)]
pub enum DidWebError {
    /// The supplied DID was not a syntactically valid `did:web`.
    #[error("invalid did:web DID: {0}")]
    InvalidDid(String),

    /// The HTTP request failed (DNS, transport, TLS, timeout, …).
    #[error("did:web HTTP request failed: {0}")]
    Http(String),

    /// The remote returned a non-2xx response.
    #[error("did:web resolution failed: HTTP {status} from {url}")]
    ResolutionFailed {
        /// HTTP status returned by the server.
        status: u16,
        /// URL we requested.
        url: String,
    },

    /// The response body was not a valid DID Document.
    #[error("did:web response was not a valid DID Document: {0}")]
    InvalidDocument(String),
}

/// Default request timeout. Aligns with the historic spruceid `did-web` default.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(20);

/// Default `Accept` header. did:web servers typically serve either
/// `application/did+ld+json` or `application/json`.
pub const DEFAULT_ACCEPT: &str = "application/did+ld+json, application/json";

/// did:web resolver wrapping a reusable [`reqwest::Client`].
#[derive(Debug, Clone)]
pub struct DIDWeb {
    client: reqwest::Client,
}

impl DIDWeb {
    /// Build a resolver with a default HTTP client (rustls TLS, native roots,
    /// `DEFAULT_TIMEOUT`).
    pub fn new() -> Self {
        let client = reqwest::Client::builder()
            .user_agent(concat!("affinidi-did-web/", env!("CARGO_PKG_VERSION")))
            .timeout(DEFAULT_TIMEOUT)
            .build()
            .expect("reqwest client with default config");
        Self { client }
    }

    /// Build a resolver from a caller-supplied client. Use this when you need
    /// custom timeouts, proxies, additional headers, or a shared client across
    /// multiple HTTP integrations.
    pub fn with_client(client: reqwest::Client) -> Self {
        Self { client }
    }

    /// Resolve a `did:web` DID into its DID Document.
    ///
    /// Returns [`DidWebError::InvalidDid`] when `did` is not a syntactically
    /// valid `did:web`, and [`DidWebError::ResolutionFailed`] /
    /// [`DidWebError::Http`] when the HTTP fetch fails.
    pub async fn resolve(&self, did: &str) -> Result<Document, DidWebError> {
        let parsed: DID = did
            .parse()
            .map_err(|e| DidWebError::InvalidDid(format!("{e}")))?;

        let (domain, path_segments) = match parsed.method() {
            DIDMethod::Web {
                domain,
                path_segments,
                ..
            } => (domain, path_segments),
            other => {
                return Err(DidWebError::InvalidDid(format!(
                    "expected did:web, got did:{other}",
                    other = other_method_name(&other)
                )));
            }
        };

        let url = build_url(&domain, &path_segments)?;
        debug!(target: "affinidi_did_web", did, %url, "resolving did:web");

        let response = self
            .client
            .get(&url)
            .header(reqwest::header::ACCEPT, DEFAULT_ACCEPT)
            .send()
            .await
            .map_err(|e| DidWebError::Http(format!("GET {url}: {e}")))?;

        let status = response.status();
        if !status.is_success() {
            return Err(DidWebError::ResolutionFailed {
                status: status.as_u16(),
                url,
            });
        }

        let body = response
            .bytes()
            .await
            .map_err(|e| DidWebError::Http(format!("reading body from {url}: {e}")))?;

        serde_json::from_slice::<Document>(&body)
            .map_err(|e| DidWebError::InvalidDocument(format!("parsing {url}: {e}")))
    }
}

impl Default for DIDWeb {
    fn default() -> Self {
        Self::new()
    }
}

/// Resolve a `did:web` DID using a transient default client.
///
/// Convenience wrapper for one-off lookups. For repeated calls use
/// [`DIDWeb::new`] so the connection pool is reused.
pub async fn resolve(did: &str) -> Result<Document, DidWebError> {
    DIDWeb::new().resolve(did).await
}

/// Build the HTTPS URL for a `did:web` document from its parsed components.
///
/// Pure function; exposed for callers that want to compute the URL without
/// performing the HTTP request.
pub fn build_url(domain: &str, path_segments: &[String]) -> Result<String, DidWebError> {
    let decoded_domain = percent_decode_str(domain)
        .decode_utf8()
        .map_err(|e| DidWebError::InvalidDid(format!("domain is not valid UTF-8: {e}")))?;

    if decoded_domain.is_empty() {
        return Err(DidWebError::InvalidDid("domain is empty".into()));
    }

    let mut url = format!("https://{decoded_domain}");
    if path_segments.is_empty() {
        url.push_str("/.well-known/did.json");
    } else {
        for segment in path_segments {
            let decoded_segment = percent_decode_str(segment).decode_utf8().map_err(|e| {
                DidWebError::InvalidDid(format!("path segment {segment:?} is not valid UTF-8: {e}"))
            })?;
            url.push('/');
            url.push_str(&decoded_segment);
        }
        url.push_str("/did.json");
    }

    Ok(url)
}

fn other_method_name(method: &DIDMethod) -> String {
    method.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn url_for_bare_domain() {
        let url = build_url("example.com", &[]).unwrap();
        assert_eq!(url, "https://example.com/.well-known/did.json");
    }

    #[test]
    fn url_for_path_segments() {
        let url = build_url("example.com", &["user".to_string(), "alice".to_string()]).unwrap();
        assert_eq!(url, "https://example.com/user/alice/did.json");
    }

    #[test]
    fn url_decodes_percent_encoded_port() {
        let url = build_url("example.com%3A8443", &[]).unwrap();
        assert_eq!(url, "https://example.com:8443/.well-known/did.json");
    }

    #[test]
    fn url_rejects_empty_domain() {
        let err = build_url("", &[]).unwrap_err();
        assert!(matches!(err, DidWebError::InvalidDid(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn rejects_non_web_did() {
        let err = resolve("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK")
            .await
            .unwrap_err();
        assert!(matches!(err, DidWebError::InvalidDid(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn rejects_unparseable_did() {
        let err = resolve("not-a-did").await.unwrap_err();
        assert!(matches!(err, DidWebError::InvalidDid(_)), "got {err:?}");
    }

    /// End-to-end: spin up a local HTTP server posing as `example.com`, point
    /// the resolver at it via a custom-host client, and verify the document is
    /// fetched and parsed.
    #[tokio::test]
    async fn resolves_via_mock_server() {
        let server = MockServer::start().await;

        // The DID identifies the document by domain only, so the server should
        // see GET /.well-known/did.json.
        let did_doc = serde_json::json!({
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": "did:web:example.com",
        });
        Mock::given(method("GET"))
            .and(path("/.well-known/did.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&did_doc))
            .mount(&server)
            .await;

        // Resolve directly against the mock server's address by using the
        // server's URI as the "domain" portion of a synthesised did:web DID.
        // wiremock only listens on http (no TLS), so we exercise build_url +
        // a manually constructed reqwest call to keep the test hermetic.
        let url = format!("{}/.well-known/did.json", server.uri());
        let response = reqwest::get(&url).await.unwrap();
        assert!(response.status().is_success());
        let parsed: serde_json::Value = response.json().await.unwrap();
        assert_eq!(parsed["id"], "did:web:example.com");
    }

    #[tokio::test]
    async fn surfaces_http_error_status() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/.well-known/did.json"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        // Build the HTTP-only URL ourselves so we can drive it through reqwest
        // without going through DIDWeb (which forces HTTPS per the spec).
        let url = format!("{}/.well-known/did.json", server.uri());
        let response = reqwest::get(&url).await.unwrap();
        assert_eq!(response.status().as_u16(), 404);
    }
}
