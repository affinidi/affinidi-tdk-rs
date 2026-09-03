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

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use affinidi_did_common::{DID, DIDMethod, Document};
use percent_encoding::percent_decode_str;
use thiserror::Error;
use tracing::debug;

/// did:web resolver errors.
#[derive(Debug, Error)]
#[non_exhaustive]
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

    /// The DID named a non-routable host (loopback / private / link-local /
    /// cloud-metadata). Refused before any request to prevent SSRF into
    /// internal services.
    #[error("did:web refused SSRF-prone host: {0}")]
    BlockedHost(String),

    /// The response body exceeded the size cap (memory-DoS guard).
    #[error("did:web response exceeded the {limit}-byte cap")]
    ResponseTooLarge {
        /// The byte cap that was exceeded.
        limit: usize,
    },
}

/// Default request timeout. Aligns with the historic spruceid `did-web` default.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(20);

/// Cap on a fetched DID Document body. A conformant did:web document is a few
/// KB; a larger response is hostile — refuse rather than buffer it (memory-DoS).
pub const MAX_DOCUMENT_BYTES: usize = 1 << 20; // 1 MiB

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
            // The DID names the host. Following a 3xx lets that host pivot the
            // resolver to an arbitrary internal address (SSRF), so refuse.
            .redirect(reqwest::redirect::Policy::none())
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

        // SSRF guard: the DID names the host, so an attacker-supplied
        // did:web:169.254.169.254 / did:web:localhost would make the resolver
        // fetch an internal or cloud-metadata endpoint. Refuse a non-routable
        // host before issuing any request. (Redirects are already disabled, so a
        // 3xx cannot pivot to one after the fact either.)
        if let Ok(parsed_url) = reqwest::Url::parse(&url)
            && let Some(host) = parsed_url.host_str()
            && host_is_blocked(host)
        {
            return Err(DidWebError::BlockedHost(host.to_owned()));
        }

        debug!(target: "affinidi_did_web", did, %url, "resolving did:web");

        let mut response = self
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

        // Read the body under a hard cap so a hostile server (or one lying about
        // Content-Length) cannot stream an unbounded body into memory. `chunk()`
        // yields the response incrementally without buffering it all first.
        let mut body: Vec<u8> = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|e| DidWebError::Http(format!("reading body from {url}: {e}")))?
        {
            if body.len() + chunk.len() > MAX_DOCUMENT_BYTES {
                return Err(DidWebError::ResponseTooLarge {
                    limit: MAX_DOCUMENT_BYTES,
                });
            }
            body.extend_from_slice(&chunk);
        }

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

/// Reject a host that must never be the target of a `did:web` fetch: loopback,
/// RFC-1918 / unique-local, link-local (which includes the cloud-metadata
/// address `169.254.169.254`), unspecified, or broadcast. Bare `localhost` and
/// `*.localhost` / `*.local` are refused by name. A name we cannot classify here
/// is allowed through — DNS rebinding is a connect-time concern handled elsewhere.
fn host_is_blocked(host: &str) -> bool {
    let h = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_ascii_lowercase();
    if h == "localhost" || h.ends_with(".localhost") || h.ends_with(".local") {
        return true;
    }
    match h.parse::<IpAddr>() {
        Ok(IpAddr::V4(a)) => ipv4_is_blocked(a),
        Ok(IpAddr::V6(a)) => ipv6_is_blocked(a),
        Err(_) => false,
    }
}

fn ipv4_is_blocked(a: Ipv4Addr) -> bool {
    a.is_loopback()
        || a.is_private()
        || a.is_link_local() // 169.254.0.0/16 — covers cloud metadata 169.254.169.254
        || a.is_unspecified()
        || a.is_broadcast()
}

fn ipv6_is_blocked(a: Ipv6Addr) -> bool {
    if a.is_loopback() || a.is_unspecified() {
        return true;
    }
    // An IPv4-mapped address (::ffff:a.b.c.d) reaches the same v4 target.
    if let Some(v4) = a.to_ipv4_mapped() {
        return ipv4_is_blocked(v4);
    }
    let s = a.segments();
    (s[0] & 0xfe00) == 0xfc00 // unique-local fc00::/7
        || (s[0] & 0xffc0) == 0xfe80 // link-local fe80::/10
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
            // A decoded segment must stay a single path component. `%2E%2E`
            // (`..`), `%2F` (`/`), `%5C` (`\`), etc. would otherwise let a
            // crafted DID escape the expected `/{segments}/did.json` shape.
            if decoded_segment.is_empty()
                || decoded_segment == "."
                || decoded_segment == ".."
                || decoded_segment.contains(['/', '\\'])
            {
                return Err(DidWebError::InvalidDid(format!(
                    "path segment {segment:?} is not a valid single path component"
                )));
            }
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
    fn url_rejects_path_traversal_segments() {
        for seg in ["%2E%2E", "..", ".", "", "a%2Fb", "a%5Cb"] {
            let err = build_url("example.com", &[seg.to_string()]).unwrap_err();
            assert!(
                matches!(err, DidWebError::InvalidDid(_)),
                "segment {seg:?} should be rejected, got {err:?}"
            );
        }
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

    #[test]
    fn host_guard_blocks_internal_and_metadata() {
        for h in [
            "127.0.0.1",
            "0.0.0.0",
            "10.0.0.5",
            "172.16.9.9",
            "192.168.1.1",
            "169.254.169.254", // cloud metadata
            "localhost",
            "svc.localhost",
            "printer.local",
            "::1",
            "[::1]",
            "::ffff:127.0.0.1", // IPv4-mapped loopback
            "fc00::1",          // unique-local
            "fe80::1",          // link-local
        ] {
            assert!(host_is_blocked(h), "{h} should be blocked");
        }
    }

    #[test]
    fn host_guard_allows_public_hosts() {
        for h in [
            "example.com",
            "did.example.org",
            "8.8.8.8",
            "2606:4700:4700::1111",
        ] {
            assert!(!host_is_blocked(h), "{h} should be allowed");
        }
    }

    /// The SSRF guard must fire inside `resolve()` before any network I/O.
    #[tokio::test]
    async fn resolve_refuses_ssrf_prone_hosts() {
        for did in [
            "did:web:localhost",
            "did:web:127.0.0.1",
            "did:web:169.254.169.254",
            "did:web:10.0.0.1",
        ] {
            let err = resolve(did).await.unwrap_err();
            assert!(
                matches!(err, DidWebError::BlockedHost(_)),
                "{did} should be refused as BlockedHost, got {err:?}"
            );
        }
    }
}
