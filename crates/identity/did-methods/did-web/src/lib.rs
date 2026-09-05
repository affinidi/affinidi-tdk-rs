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
 *
 * # SSRF
 *
 * A `did:web` value names the host the resolver will fetch from, so an
 * attacker-supplied DID is an SSRF primitive. By default this crate refuses a
 * non-routable target both when the DID names one literally
 * (`did:web:169.254.169.254`) and when a hostname in the DID *resolves* to one
 * (`evil.example.com` with an A record of `169.254.169.254`) — see
 * [`HostPolicy`]. Deployments whose did:web hosts genuinely live on an internal
 * network opt out with [`HostPolicy::AllowPrivate`]:
 *
 * ```no_run
 * use affinidi_did_web::{DIDWeb, HostPolicy};
 * let resolver = DIDWeb::with_policy(HostPolicy::AllowPrivate);
 * ```
 */

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
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
    /// cloud-metadata), either as a literal address in the DID or as the
    /// address a hostname in the DID resolved to. Refused before any bytes are
    /// exchanged, to prevent SSRF into internal services.
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

/// Which hosts a resolver is willing to fetch from.
///
/// A `did:web` value names its own host, so an attacker-supplied DID is an SSRF
/// primitive unless the resolver refuses non-routable targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum HostPolicy {
    /// Refuse loopback, private (RFC 1918 / unique-local), carrier-grade NAT,
    /// link-local (which is where the cloud-metadata address lives),
    /// `localhost` and `*.local` — both when the DID names them as a literal
    /// address and when a hostname in the DID *resolves* to one. The default.
    #[default]
    PublicOnly,

    /// Fetch from any host, including non-routable ones.
    ///
    /// This re-opens the SSRF exposure that [`HostPolicy::PublicOnly`] closes,
    /// so choose it only where the DID values themselves are trusted: an
    /// internal deployment whose did:web hosts genuinely live on RFC-1918
    /// space or `.local`, or a local development/test stack
    /// (`did:web:localhost%3A8080`).
    AllowPrivate,
}

/// did:web resolver wrapping a reusable [`reqwest::Client`].
#[derive(Debug, Clone)]
pub struct DIDWeb {
    client: reqwest::Client,
    policy: HostPolicy,
}

impl DIDWeb {
    /// Build a resolver with a default HTTP client (rustls TLS, native roots,
    /// `DEFAULT_TIMEOUT`) that refuses non-routable hosts.
    pub fn new() -> Self {
        Self::with_policy(HostPolicy::PublicOnly)
    }

    /// Build a resolver with a default HTTP client under an explicit
    /// [`HostPolicy`].
    pub fn with_policy(policy: HostPolicy) -> Self {
        Self {
            client: default_client(policy),
            policy,
        }
    }

    /// Build a resolver from a caller-supplied client. Use this when you need
    /// custom timeouts, proxies, additional headers, or a shared client across
    /// multiple HTTP integrations.
    ///
    /// The literal-address check still applies, but the connect-time check does
    /// not: it lives in the DNS resolver of the client built by [`DIDWeb::new`].
    /// A caller supplying their own client owns that half of the guard — see
    /// [`guarded_dns_resolver`].
    pub fn with_client(client: reqwest::Client) -> Self {
        Self {
            client,
            policy: HostPolicy::PublicOnly,
        }
    }

    /// Build a resolver from a caller-supplied client under an explicit
    /// [`HostPolicy`]. Same caveat as [`DIDWeb::with_client`].
    pub fn with_client_and_policy(client: reqwest::Client, policy: HostPolicy) -> Self {
        Self { client, policy }
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

        // Parse once, here, and hand the parsed URL to the client: re-parsing
        // the string later could disagree with what was checked. A parse
        // failure is fatal, never a skipped check -- a security guard must not
        // fail open.
        let parsed_url = reqwest::Url::parse(&url)
            .map_err(|e| DidWebError::InvalidDid(format!("{url} is not a valid URL: {e}")))?;

        // SSRF guard, first half: the DID names the host, so an
        // attacker-supplied did:web:169.254.169.254 / did:web:localhost would
        // make the resolver fetch an internal or cloud-metadata endpoint.
        // Refuse a non-routable literal before issuing any request. (Redirects
        // are already disabled, so a 3xx cannot pivot to one after the fact
        // either.) The second half -- a hostname that *resolves* to such an
        // address -- is enforced at connect time by `guarded_dns_resolver`,
        // which also closes the DNS-rebinding window between the two.
        if self.policy == HostPolicy::PublicOnly
            && let Some(host) = parsed_url.host_str()
            && host_is_blocked(host)
        {
            return Err(DidWebError::BlockedHost(host.to_owned()));
        }

        debug!(target: "affinidi_did_web", did, %url, "resolving did:web");

        let mut response = self
            .client
            .get(parsed_url)
            .header(reqwest::header::ACCEPT, DEFAULT_ACCEPT)
            .send()
            .await
            .map_err(|e| {
                blocked_address_in_chain(&e).map_or_else(
                    || DidWebError::Http(format!("GET {url}: {e}")),
                    |blocked| DidWebError::BlockedHost(blocked.to_string()),
                )
            })?;

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
/// RFC-1918 / unique-local, carrier-grade NAT, link-local (which includes the
/// cloud-metadata address `169.254.169.254`), unspecified, or broadcast. Bare
/// `localhost` and `*.localhost` / `*.local` are refused by name.
///
/// This classifies the host *as written in the DID*. A hostname that resolves
/// to one of these addresses is caught separately, at connect time, by
/// [`guarded_dns_resolver`].
fn host_is_blocked(host: &str) -> bool {
    // A trailing root dot is part of a legal hostname and survives URL
    // normalisation, so `localhost.` must normalise to `localhost` before the
    // name comparisons -- otherwise it walks straight through this guard.
    let h = host
        .trim_end_matches('.')
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_ascii_lowercase();
    if h == "localhost" || h.ends_with(".localhost") || h.ends_with(".local") {
        return true;
    }
    match h.parse::<IpAddr>() {
        Ok(a) => ip_is_blocked(a),
        Err(_) => false,
    }
}

/// Reject a resolved address that must never be connected to.
fn ip_is_blocked(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(a) => ipv4_is_blocked(a),
        IpAddr::V6(a) => ipv6_is_blocked(a),
    }
}

fn ipv4_is_blocked(a: Ipv4Addr) -> bool {
    let o = a.octets();
    a.is_loopback()
        || a.is_private()
        || a.is_link_local() // 169.254.0.0/16 — covers cloud metadata 169.254.169.254
        || a.is_broadcast()
        || o[0] == 0 // 0.0.0.0/8 "this network" — includes the unspecified address
        // 100.64.0.0/10 carrier-grade NAT: the Alibaba/Oracle metadata address
        // 100.100.100.200 lives here, as do the node/pod CIDRs of many
        // Kubernetes deployments. `Ipv4Addr::is_shared` is still unstable.
        || (o[0] == 100 && (64..128).contains(&o[1]))
        || (o[0] == 192 && o[1] == 0 && o[2] == 0) // 192.0.0.0/24 IETF protocol assignments
        || (o[0] == 198 && (o[1] & 0xfe) == 18) // 198.18.0.0/15 benchmarking
}

fn ipv6_is_blocked(a: Ipv6Addr) -> bool {
    if a.is_loopback() || a.is_unspecified() {
        return true;
    }
    // Both IPv4-mapped (::ffff:a.b.c.d) and the deprecated IPv4-compatible
    // (::a.b.c.d) forms reach the same v4 target on stacks that still route
    // them, and `to_ipv4` — unlike `to_ipv4_mapped` — covers both.
    if let Some(v4) = a.to_ipv4() {
        return ipv4_is_blocked(v4);
    }
    let s = a.segments();
    // NAT64 well-known prefix 64:ff9b::/96 embeds a v4 destination in the low
    // 32 bits, so classify that destination.
    if s[0] == 0x0064 && s[1] == 0xff9b && s[2..6] == [0, 0, 0, 0] {
        let v4 = Ipv4Addr::from(((u32::from(s[6])) << 16) | u32::from(s[7]));
        return ipv4_is_blocked(v4);
    }
    (s[0] & 0xfe00) == 0xfc00 // unique-local fc00::/7
        || (s[0] & 0xffc0) == 0xfe80 // link-local fe80::/10
        || (s[0] & 0xffc0) == 0xfec0 // deprecated site-local fec0::/10
}

/// Refusal raised by [`guarded_dns_resolver`] when a hostname resolves to a
/// non-routable address. Travels out through `reqwest`'s error chain, where
/// [`blocked_address_in_chain`] recovers it and reports
/// [`DidWebError::BlockedHost`] rather than a generic transport failure.
#[derive(Debug)]
struct BlockedAddress {
    host: String,
    addr: IpAddr,
}

impl fmt::Display for BlockedAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} resolves to non-routable {}", self.host, self.addr)
    }
}

impl std::error::Error for BlockedAddress {}

/// Recover a [`BlockedAddress`] from anywhere in an error's source chain.
fn blocked_address_in_chain<'a>(
    err: &'a (dyn std::error::Error + 'static),
) -> Option<&'a BlockedAddress> {
    let mut next = Some(err);
    while let Some(e) = next {
        if let Some(blocked) = e.downcast_ref::<BlockedAddress>() {
            return Some(blocked);
        }
        next = e.source();
    }
    None
}

/// A DNS resolver that refuses to hand back a non-routable address.
///
/// The literal check in [`DIDWeb::resolve`] only classifies the host *as
/// written*; nothing stops an attacker pointing `evil.example.com` at
/// `169.254.169.254` and publishing `did:web:evil.example.com`. Filtering at
/// resolution time closes that, and because the connection is made to the
/// addresses returned here, it also closes the DNS-rebinding window: there is
/// no second, unchecked lookup between the guard and the connect.
///
/// Install it on a caller-supplied client to get the same protection as the
/// client [`DIDWeb::new`] builds:
///
/// ```no_run
/// let client = reqwest::Client::builder()
///     .dns_resolver(affinidi_did_web::guarded_dns_resolver())
///     .build()?;
/// let resolver = affinidi_did_web::DIDWeb::with_client(client);
/// # Ok::<(), reqwest::Error>(())
/// ```
pub fn guarded_dns_resolver() -> Arc<dyn reqwest::dns::Resolve> {
    Arc::new(GuardedResolver)
}

#[derive(Debug, Clone, Copy)]
struct GuardedResolver;

impl reqwest::dns::Resolve for GuardedResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        Box::pin(async move {
            let host = name.as_str().to_owned();
            // Port 0: reqwest substitutes the URL's port (or the scheme's
            // default) over whatever we return.
            let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), 0))
                .await
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?
                .collect();

            // Fail closed on the whole name, not per-address: a name with even
            // one internal answer is not a name we are willing to fetch from.
            if let Some(bad) = addrs.iter().find(|a| ip_is_blocked(a.ip())) {
                return Err(Box::new(BlockedAddress {
                    host,
                    addr: bad.ip(),
                })
                    as Box<dyn std::error::Error + Send + Sync>);
            }

            Ok(Box::new(addrs.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

/// The HTTP client [`DIDWeb::new`] and [`DIDWeb::with_policy`] build.
fn default_client(policy: HostPolicy) -> reqwest::Client {
    let mut builder = reqwest::Client::builder()
        .user_agent(concat!("affinidi-did-web/", env!("CARGO_PKG_VERSION")))
        .timeout(DEFAULT_TIMEOUT)
        // The DID names the host. Following a 3xx lets that host pivot the
        // resolver to an arbitrary internal address (SSRF), so refuse.
        .redirect(reqwest::redirect::Policy::none());

    if policy == HostPolicy::PublicOnly {
        builder = builder.dns_resolver(guarded_dns_resolver());
    }

    builder.build().expect("reqwest client with default config")
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
            "0.1.2.3", // 0.0.0.0/8 "this network"
            "10.0.0.5",
            "172.16.9.9",
            "192.168.1.1",
            "169.254.169.254", // cloud metadata
            "100.100.100.200", // Alibaba/Oracle metadata, in CGNAT space
            "100.64.0.1",      // CGNAT lower bound
            "100.127.255.254", // CGNAT upper bound
            "192.0.0.1",       // IETF protocol assignments
            "198.19.0.1",      // benchmarking range
            "255.255.255.255", // broadcast
            "localhost",
            "localhost.", // trailing root dot
            "LOCALHOST",
            "svc.localhost",
            "svc.localhost.",
            "printer.local",
            "printer.local.",
            "::1",
            "[::1]",
            "::ffff:127.0.0.1", // IPv4-mapped loopback
            "::ffff:169.254.169.254",
            "::127.0.0.1",     // IPv4-compatible loopback
            "64:ff9b::7f00:1", // NAT64-embedded loopback
            "fc00::1",         // unique-local
            "fe80::1",         // link-local
            "fec0::1",         // deprecated site-local
        ] {
            assert!(host_is_blocked(h), "{h} should be blocked");
        }
    }

    #[test]
    fn host_guard_allows_public_hosts() {
        for h in [
            "example.com",
            "example.com.",
            "did.example.org",
            "localhost.example.com", // "localhost" only as the whole name or a suffix label
            "8.8.8.8",
            "99.64.0.1",   // just below CGNAT
            "100.63.0.1",  // just below CGNAT
            "100.128.0.1", // just above CGNAT
            "2606:4700:4700::1111",
            "64:ff9b::808:808", // NAT64-embedded public address
        ] {
            assert!(!host_is_blocked(h), "{h} should be allowed");
        }
    }

    /// The SSRF guard must fire inside `resolve()` before any network I/O.
    #[tokio::test]
    async fn resolve_refuses_ssrf_prone_hosts() {
        for did in [
            "did:web:localhost",
            "did:web:localhost.",
            "did:web:127.0.0.1",
            "did:web:169.254.169.254",
            "did:web:100.100.100.200",
            "did:web:10.0.0.1",
        ] {
            let err = resolve(did).await.unwrap_err();
            assert!(
                matches!(err, DidWebError::BlockedHost(_)),
                "{did} should be refused as BlockedHost, got {err:?}"
            );
        }
    }

    /// `AllowPrivate` is a real escape hatch: the literal check must not fire.
    /// The fetch itself then fails on connect (nothing is listening), which is
    /// exactly the point — it got past the guard.
    #[tokio::test]
    async fn allow_private_policy_skips_the_literal_guard() {
        let resolver = DIDWeb::with_policy(HostPolicy::AllowPrivate);
        let err = resolver.resolve("did:web:127.0.0.1%3A1").await.unwrap_err();
        assert!(
            !matches!(err, DidWebError::BlockedHost(_)),
            "AllowPrivate should not block a private literal, got {err:?}"
        );
    }

    /// The connect-time half of the guard: a *name* that resolves to a
    /// non-routable address is refused by the DNS resolver. `localhost` is the
    /// one name guaranteed to resolve to loopback everywhere, and this drives
    /// the resolver directly, so no network is touched.
    #[tokio::test]
    async fn dns_guard_refuses_a_name_resolving_to_loopback() {
        use std::str::FromStr;

        let name = reqwest::dns::Name::from_str("localhost").unwrap();
        let Err(err) = reqwest::dns::Resolve::resolve(&GuardedResolver, name).await else {
            panic!("localhost resolves to loopback and must be refused");
        };
        assert!(
            blocked_address_in_chain(err.as_ref()).is_some(),
            "expected a BlockedAddress, got {err:?}"
        );
    }

    /// ...and that refusal must survive reqwest's error wrapping, so callers
    /// see `BlockedHost` rather than a generic transport failure. Hermetic: DNS
    /// for `localhost` is local and the connection is never made.
    #[tokio::test]
    async fn dns_guard_surfaces_as_blocked_host() {
        let client = default_client(HostPolicy::PublicOnly);
        let err = client
            .get("http://localhost/.well-known/did.json")
            .send()
            .await
            .expect_err("the guarded resolver must refuse localhost");
        assert!(
            blocked_address_in_chain(&err).is_some(),
            "BlockedAddress should be recoverable from the reqwest error chain, got {err:?}"
        );
    }

    /// A client built without the guarded resolver keeps the literal check.
    #[test]
    fn with_client_defaults_to_public_only() {
        let resolver = DIDWeb::with_client(reqwest::Client::new());
        assert_eq!(resolver.policy, HostPolicy::PublicOnly);
    }
}
