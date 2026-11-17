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

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use affinidi_did_common::{DID, DIDMethod, Document, NetworkError};
use affinidi_net_guard::{EgressError, EgressPolicy};
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

    /// The remote returned a non-2xx response. The status, the URL and the
    /// host's `Retry-After` (when it sent one in seconds) are kept as data,
    /// so a caller can tell a rate limit (HTTP 429) from a DID that does not
    /// exist (HTTP 404), and when to try again.
    ///
    /// Replaced `ResolutionFailed { status, url }` in 0.2.0 (#1166).
    #[error("did:web resolution failed: {0}")]
    Network(NetworkError),

    /// The response body was not a valid DID Document.
    #[error("did:web response was not a valid DID Document: {0}")]
    InvalidDocument(String),

    /// The response document's `id` did not match the DID being resolved.
    ///
    /// A `did:web` value identifies its document only by the network location
    /// it is fetched from — nothing else ties the response to the right
    /// subject. Without this check, a host asked to resolve `did:web:a` (or
    /// one it was redirected to, or one on-path) could answer with a document
    /// whose `id` is `did:web:b`, and the caller would accept it as `a`'s.
    #[error("did:web response document id {got:?} does not match the requested DID {expected:?}")]
    DocumentIdMismatch {
        /// The DID that was requested.
        expected: String,
        /// The `id` the response document actually carried.
        got: String,
    },

    /// The DID named a host the resolver's policy refuses: a non-routable
    /// host (loopback / private / link-local / cloud-metadata), either as a
    /// literal address in the DID or as the address a hostname in the DID
    /// resolved to, or (under [`DIDWeb::with_egress_policy`]) a host the
    /// egress policy does not admit. Refused before any bytes are exchanged,
    /// to prevent SSRF into internal services.
    #[error("did:web refused SSRF-prone host: {0}")]
    BlockedHost(String),

    /// The response body exceeded the size cap (memory-DoS guard).
    #[error("did:web response exceeded the {limit}-byte cap")]
    ResponseTooLarge {
        /// The byte cap that was exceeded.
        limit: usize,
    },
}

impl DidWebError {
    /// The failed fetch behind this error, as the [`NetworkError`] every DID
    /// method crate reports: [`DidWebError::Network`] as it is (URL, status
    /// and `Retry-After`), and [`DidWebError::Http`] with its message and no
    /// status. `None` for any other error.
    pub fn network_error(&self) -> Option<NetworkError> {
        match self {
            Self::Network(network) => Some(network.clone()),
            Self::Http(message) => Some(NetworkError::new(message.clone())),
            _ => None,
        }
    }
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
///
/// A shorthand for the two common cases. For anything else (an operator
/// allow-list, named private ranges, or `affinidi-net-guard`'s full set of
/// special-use names) build an [`EgressPolicy`] and use
/// [`DIDWeb::with_egress_policy`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum HostPolicy {
    /// Refuse loopback, private (RFC 1918 / unique-local), carrier-grade NAT,
    /// link-local (which is where the cloud-metadata address lives) — both
    /// when the DID names them as a literal address and when a hostname in
    /// the DID *resolves* to one — and the special-use names of
    /// [`EgressPolicy::public_internet`]: `localhost`, `*.localhost`,
    /// `*.local`, `*.internal`, `*.home.arpa` and single-label names. The
    /// default.
    ///
    /// Addresses and names are both classified by `affinidi-net-guard`. Until
    /// 0.2.0 the names were this crate's own narrower set (`localhost`,
    /// `*.localhost`, `*.local`); `*.internal`, `*.home.arpa` and
    /// single-label hosts are now refused too (#1166).
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

/// What a [`DIDWeb`] vets each fetch against.
#[derive(Debug, Clone)]
enum Guard {
    /// [`HostPolicy::PublicOnly`]: this crate's name set and
    /// `affinidi-net-guard`'s address classes.
    PublicOnly,
    /// An [`EgressPolicy`], in full.
    Egress(EgressPolicy),
    /// [`HostPolicy::AllowPrivate`]: nothing.
    Unguarded,
}

impl From<HostPolicy> for Guard {
    fn from(policy: HostPolicy) -> Self {
        match policy {
            HostPolicy::AllowPrivate => Guard::Unguarded,
            _ => Guard::PublicOnly,
        }
    }
}

/// did:web resolver wrapping a reusable [`reqwest::Client`].
#[derive(Debug, Clone)]
pub struct DIDWeb {
    client: reqwest::Client,
    guard: Guard,
}

impl DIDWeb {
    /// Build a resolver with a default HTTP client (rustls TLS, native roots,
    /// `DEFAULT_TIMEOUT`) that refuses non-routable hosts.
    pub fn new() -> Self {
        Self::with_policy(HostPolicy::PublicOnly)
    }

    /// Build a resolver with a default HTTP client under an explicit
    /// [`HostPolicy`].
    ///
    /// # Panics
    /// If the HTTP client cannot be built (the TLS backend fails to
    /// initialise), as `reqwest::Client::new` does.
    pub fn with_policy(policy: HostPolicy) -> Self {
        Self::with_client_builder(reqwest::Client::builder(), policy)
            .expect("reqwest client with default config")
    }

    /// Build a resolver over a client the caller configures (headers, TLS,
    /// connection pool), under an explicit [`HostPolicy`].
    ///
    /// The request timeout is set to [`DEFAULT_TIMEOUT`] and the user agent
    /// to this crate's, replacing any set on `builder`. To choose the
    /// timeout, use [`DIDWeb::with_client_builder_and_timeout`]; to keep the
    /// builder's own timeout and user agent, use
    /// [`DIDWeb::with_egress_policy`].
    ///
    /// The guard settings are applied after the caller's, so nothing set on
    /// `builder` can undo them: redirects are never followed, and under
    /// [`HostPolicy::PublicOnly`] the [`guarded_dns_resolver`] is installed
    /// and every proxy, including one named by `HTTPS_PROXY`, is turned off,
    /// because a proxy resolves the hostname itself and the connect-time
    /// check would never see the address.
    ///
    /// # Errors
    /// Returns [`DidWebError::Http`] if `reqwest` cannot build the client.
    pub fn with_client_builder(
        builder: reqwest::ClientBuilder,
        policy: HostPolicy,
    ) -> Result<Self, DidWebError> {
        Self::with_client_builder_and_timeout(builder, policy, DEFAULT_TIMEOUT)
    }

    /// As [`DIDWeb::with_client_builder`], with `timeout` as the request
    /// timeout.
    ///
    /// # Errors
    /// Returns [`DidWebError::Http`] if `reqwest` cannot build the client.
    pub fn with_client_builder_and_timeout(
        builder: reqwest::ClientBuilder,
        policy: HostPolicy,
        timeout: Duration,
    ) -> Result<Self, DidWebError> {
        if policy == HostPolicy::AllowPrivate {
            tracing::warn!(
                target: "affinidi_did_web",
                "did:web resolver built with HostPolicy::AllowPrivate: it will fetch from \
                 loopback and private hosts, so SSRF protection is off. Use it only where the \
                 DIDs resolved are trusted."
            );
        }
        Self::build(default_settings(builder, timeout), policy.into())
    }

    /// Build a resolver over a client the caller configures, fetching only
    /// what `policy` admits: the URL a DID points at is vetted with
    /// [`EgressPolicy::vet_url`] before any request, and every address a
    /// hostname resolves to is vetted at connect time by
    /// `affinidi_net_guard::guarded_dns_resolver` under the same policy.
    ///
    /// Use it for what [`HostPolicy`] cannot express, such as an operator
    /// allow-list (`EgressPolicy::with_allow_list`), named private ranges
    /// (`EgressPolicy::allow_cidrs`), or `affinidi-net-guard`'s full set of
    /// special-use names ([`EgressPolicy::public_internet`]).
    ///
    /// Only the guard settings are applied: redirects are never followed and
    /// proxies are turned off. The builder's own request timeout and user
    /// agent are kept, and `reqwest` sets neither by default, so set a
    /// timeout on `builder` (for example [`DEFAULT_TIMEOUT`]).
    ///
    /// # Errors
    /// Returns [`DidWebError::Http`] if `reqwest` cannot build the client.
    pub fn with_egress_policy(
        builder: reqwest::ClientBuilder,
        policy: EgressPolicy,
    ) -> Result<Self, DidWebError> {
        Self::build(builder, Guard::Egress(policy))
    }

    fn build(builder: reqwest::ClientBuilder, guard: Guard) -> Result<Self, DidWebError> {
        let client = guard_settings(builder, &guard)
            .build()
            .map_err(|e| DidWebError::Http(format!("cannot build the HTTP client: {e}")))?;
        Ok(Self { client, guard })
    }

    /// Build a resolver from a caller-built client, under
    /// [`HostPolicy::PublicOnly`].
    ///
    /// Only the host the DID names is checked. A built client cannot be
    /// inspected or changed, so a hostname that resolves to a private
    /// address, a redirect, or a proxy is stopped only if the caller built the
    /// client to stop it.
    #[deprecated(
        since = "0.1.7",
        note = "a built client may not carry the connect-time guard; use `with_client_builder`, which applies it"
    )]
    pub fn with_client(client: reqwest::Client) -> Self {
        Self {
            client,
            guard: Guard::PublicOnly,
        }
    }

    /// Build a resolver from a caller-built client under an explicit
    /// [`HostPolicy`]. Same caveat as [`DIDWeb::with_client`].
    #[deprecated(
        since = "0.1.7",
        note = "a built client may not carry the connect-time guard; use `with_client_builder`, which applies it"
    )]
    pub fn with_client_and_policy(client: reqwest::Client, policy: HostPolicy) -> Self {
        Self {
            client,
            guard: policy.into(),
        }
    }

    /// Resolve a `did:web` DID into its DID Document.
    ///
    /// Returns [`DidWebError::InvalidDid`] when `did` is not a syntactically
    /// valid `did:web`, and [`DidWebError::Network`] /
    /// [`DidWebError::Http`] when the HTTP fetch fails.
    pub async fn resolve(&self, did: &str) -> Result<Document, DidWebError> {
        let parsed: DID = did
            .parse()
            .map_err(|e| DidWebError::InvalidDid(format!("{e}")))?;
        self.resolve_parsed(did, &parsed).await
    }

    /// Resolve an already parsed `did:web` DID, `did` being its text.
    async fn resolve_parsed(&self, did: &str, parsed: &DID) -> Result<Document, DidWebError> {
        let (domain, path_segments) = match parsed.method_ref() {
            DIDMethod::Web {
                domain,
                path_segments,
                ..
            } => (domain, path_segments),
            other => {
                return Err(DidWebError::InvalidDid(format!(
                    "expected did:web, got did:{other}",
                    other = other_method_name(other)
                )));
            }
        };

        let url = build_url(domain, path_segments)?;

        // Parse once, here, and hand the parsed URL to the client: re-parsing
        // the string later could disagree with what was checked. A parse
        // failure is fatal, never a skipped check -- a security guard must not
        // fail open.
        let parsed_url = reqwest::Url::parse(&url)
            .map_err(|e| DidWebError::InvalidDid(format!("{url} is not a valid URL: {e}")))?;

        // SSRF guard, first half: the DID names the host, so an
        // attacker-supplied did:web:169.254.169.254 / did:web:localhost would
        // make the resolver fetch an internal or cloud-metadata endpoint.
        // Refuse a host the policy does not admit before issuing any request.
        // (Redirects are already disabled, so a 3xx cannot pivot to one after
        // the fact either.) The second half -- a hostname that *resolves* to
        // such an address -- is enforced at connect time by the guarded DNS
        // resolver, which also closes the DNS-rebinding window between the two.
        match &self.guard {
            Guard::PublicOnly => {
                if let Some(host) = parsed_url.host_str()
                    && host_is_blocked(host)
                {
                    return Err(DidWebError::BlockedHost(host.to_owned()));
                }
            }
            Guard::Egress(policy) => vet(policy, &parsed_url)?,
            Guard::Unguarded => {}
        }

        debug!(target: "affinidi_did_web", did, %url, "resolving did:web");
        self.fetch_document(did, parsed_url, url).await
    }

    /// Fetch `parsed_url` (whose text is `url`) and read it as the document
    /// of `did`: the size cap, the parse and the `id` check.
    async fn fetch_document(
        &self,
        did: &str,
        parsed_url: reqwest::Url,
        url: String,
    ) -> Result<Document, DidWebError> {
        let mut response = self
            .client
            .get(parsed_url)
            .header(reqwest::header::ACCEPT, DEFAULT_ACCEPT)
            .send()
            .await
            .map_err(|e| match affinidi_net_guard::blocked_in_chain(&e) {
                Some(EgressError::BlockedAddress { host, addr, .. }) => {
                    DidWebError::BlockedHost(format!("{host} resolves to non-routable {addr}"))
                }
                Some(refusal) => DidWebError::BlockedHost(refusal.to_string()),
                None => DidWebError::Http(format!("GET {url}: {e}")),
            })?;

        let status = response.status();
        if !status.is_success() {
            let retry_after = response
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|value| value.to_str().ok());
            return Err(DidWebError::Network(
                NetworkError::new(format!("HTTP {}", status.as_u16()))
                    .with_url(url)
                    .with_status(status.as_u16())
                    .with_retry_after_header(retry_after),
            ));
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

        // A relative id or reference (`"#key-1"`) is legal in a DID document;
        // it is resolved against the document's `id`, which must be `did`.
        let document = Document::from_json_slice(&body)
            .map_err(|e| DidWebError::InvalidDocument(format!("parsing {url}: {e}")))?;
        verify_document_id(did, &document)?;
        Ok(document)
    }
}

/// The DID Resolution spec requires a resolved document's `id` to equal the
/// DID that was resolved. Check this ourselves rather than trust the remote:
/// see [`DidWebError::DocumentIdMismatch`] for why that trust would be
/// misplaced for `did:web`.
fn verify_document_id(did: &str, document: &Document) -> Result<(), DidWebError> {
    if document.id.as_str() == did {
        Ok(())
    } else {
        Err(DidWebError::DocumentIdMismatch {
            expected: did.to_string(),
            got: document.id.as_str().to_string(),
        })
    }
}

impl Default for DIDWeb {
    fn default() -> Self {
        Self::new()
    }
}

/// did:web as an `affinidi-did-resolver-traits`
/// [`AsyncResolver`](affinidi_did_resolver_traits::AsyncResolver).
#[cfg(feature = "resolver-traits")]
mod resolver_impl {
    use std::future::Future;
    use std::pin::Pin;

    use affinidi_did_common::{DID, DIDMethod};
    use affinidi_did_resolver_traits::{AsyncResolver, Resolution, ResolverError};

    use crate::{DIDWeb, DidWebError};

    /// The [`ResolverError`] for a failed did:web resolution: an unsuccessful
    /// HTTP status (with its URL) and a transport failure are
    /// [`ResolverError::NetworkFetch`], everything else
    /// [`ResolverError::ResolutionFailed`].
    pub(crate) fn resolver_error(err: DidWebError) -> ResolverError {
        match err.network_error() {
            Some(network) => ResolverError::from(network),
            None => ResolverError::ResolutionFailed(err.to_string()),
        }
    }

    /// Resolves did:web under the resolver's host policy, and declines
    /// (`None`) every other method. A DID URL resolves to the document of
    /// its DID.
    impl AsyncResolver for DIDWeb {
        fn name(&self) -> &str {
            "WebResolver"
        }

        fn resolve<'a>(
            &'a self,
            did: &'a DID,
        ) -> Pin<Box<dyn Future<Output = Resolution> + Send + 'a>> {
            Box::pin(async move {
                if !matches!(did.method_ref(), DIDMethod::Web { .. }) {
                    return None;
                }
                let bare = format!("did:web:{}", did.method_specific_id_ref());
                Some(
                    self.resolve_parsed(&bare, did)
                        .await
                        .map_err(resolver_error),
                )
            })
        }
    }
}

/// Resolve a `did:web` DID using a transient default client.
///
/// Convenience wrapper for one-off lookups. For repeated calls use
/// [`DIDWeb::new`] so the connection pool is reused.
pub async fn resolve(did: &str) -> Result<Document, DidWebError> {
    DIDWeb::new().resolve(did).await
}

/// Vet the URL a did:web DID points at under `policy`, before any request:
/// its host as written (a literal address's class, a special-use name, an
/// allow-list), its port and its userinfo. A hostname that resolves to a
/// refused address is caught separately, at connect time, by the guarded DNS
/// resolver.
fn vet(policy: &EgressPolicy, url: &reqwest::Url) -> Result<(), DidWebError> {
    policy.vet_url(url).map(|_| ()).map_err(|e| match e {
        EgressError::InvalidUrl(reason) => DidWebError::InvalidDid(reason),
        refusal => DidWebError::BlockedHost(refusal.to_string()),
    })
}

/// Reject a host that must never be the target of a `did:web` fetch under
/// [`HostPolicy::PublicOnly`]: loopback, RFC-1918 / unique-local,
/// carrier-grade NAT, link-local (which includes the cloud-metadata address
/// `169.254.169.254`), unspecified, or broadcast, and the special-use names
/// `affinidi-net-guard` refuses under [`EgressPolicy::public_internet`]
/// (`localhost`, `*.localhost`, `*.local`, `*.internal`, `*.home.arpa` and
/// single-label names).
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
    if let Ok(a) = h.parse::<IpAddr>() {
        return !affinidi_net_guard::is_globally_routable(a);
    }
    // A name: net-guard's special-use name rules, applied to the URL a
    // fetch would use. A host that does not even form a URL is refused: a
    // security guard must not fail open.
    match reqwest::Url::parse(&format!("https://{h}/")) {
        Ok(url) => EgressPolicy::public_internet().vet_url(&url).is_err(),
        Err(_) => true,
    }
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
/// It is `affinidi_net_guard::guarded_dns_resolver` under
/// [`EgressPolicy::public_internet`]: it resolves the name, fails closed if
/// *any* answer is non-routable, and returns only the vetted addresses. It
/// checks addresses only, never names. [`DIDWeb::new`],
/// [`DIDWeb::with_policy`] and [`DIDWeb::with_client_builder`] install it
/// ([`DIDWeb::with_egress_policy`] installs one under its own policy). It is
/// public for clients built for other purposes:
///
/// ```no_run
/// let client = reqwest::Client::builder()
///     .dns_resolver(affinidi_did_web::guarded_dns_resolver())
///     .no_proxy()
///     .build()?;
/// # Ok::<(), reqwest::Error>(())
/// ```
pub fn guarded_dns_resolver() -> Arc<dyn reqwest::dns::Resolve> {
    affinidi_net_guard::guarded_dns_resolver(EgressPolicy::public_internet())
}

/// The user agent and request timeout. They replace any the caller's builder
/// set; the guard settings are applied after them.
fn default_settings(builder: reqwest::ClientBuilder, timeout: Duration) -> reqwest::ClientBuilder {
    builder
        .user_agent(concat!("affinidi-did-web/", env!("CARGO_PKG_VERSION")))
        .timeout(timeout)
}

/// The guard settings. Applied last, so nothing set before can undo them.
fn guard_settings(builder: reqwest::ClientBuilder, guard: &Guard) -> reqwest::ClientBuilder {
    // The DID names the host. Following a 3xx lets that host pivot the
    // resolver to an arbitrary internal address (SSRF), so refuse.
    let builder = builder
        .redirect(reqwest::redirect::Policy::none())
        .referer(false);
    // A proxy resolves the hostname itself, so the guarded resolver would
    // see only the proxy's name.
    match guard {
        Guard::Unguarded => builder,
        Guard::PublicOnly => builder.dns_resolver(guarded_dns_resolver()).no_proxy(),
        Guard::Egress(policy) => builder
            .dns_resolver(affinidi_net_guard::guarded_dns_resolver(policy.clone()))
            .no_proxy(),
    }
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
    validate_host(&decoded_domain)?;

    let mut url = format!("https://{decoded_domain}");
    if path_segments.is_empty() {
        url.push_str("/.well-known/did.json");
    } else {
        for segment in path_segments {
            let decoded_segment = percent_decode_str(segment).decode_utf8().map_err(|e| {
                DidWebError::InvalidDid(format!("path segment {segment:?} is not valid UTF-8: {e}"))
            })?;
            // A decoded segment must stay a single path component. `%2E%2E`
            // (`..`), `%2F` (`/`), `%5C` (`\`), `%3F` (`?`), `%23` (`#`), etc.
            // would otherwise move the URL out of the expected
            // `/{segments}/did.json` shape.
            if decoded_segment.is_empty()
                || decoded_segment == "."
                || decoded_segment == ".."
                || decoded_segment
                    .chars()
                    .any(|c| c.is_control() || matches!(c, '/' | '\\' | '?' | '#' | '@' | '%'))
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

/// The decoded domain must be a host (a hostname, or an IP literal, which this
/// resolver also accepts) and an optional numeric port, and nothing a URL
/// would read as user information, a path, a query or a fragment.
fn validate_host(authority: &str) -> Result<(), DidWebError> {
    let invalid =
        |why: &str| DidWebError::InvalidDid(format!("domain {authority:?} is not a host ({why})"));
    let (host, port) = split_host_port(authority);
    if host.is_empty() {
        return Err(invalid("empty host"));
    }
    if let Some(port) = port
        && (port.is_empty()
            || !port.bytes().all(|b| b.is_ascii_digit())
            || port.parse::<u16>().is_err())
    {
        return Err(invalid("the port is not a port number"));
    }
    if let Some(literal) = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        if literal.parse::<std::net::Ipv6Addr>().is_err() {
            return Err(invalid("not an IPv6 address"));
        }
    } else if host.chars().any(|c| {
        c.is_control()
            || c.is_whitespace()
            || matches!(c, '/' | '\\' | '?' | '#' | '@' | '%' | ':' | '[' | ']')
    }) {
        return Err(invalid("a character a host cannot contain"));
    }

    let url = reqwest::Url::parse(&format!("https://{authority}/"))
        .map_err(|e| invalid(&e.to_string()))?;
    if url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(invalid("not a host and port"));
    }
    Ok(())
}

/// Split `host[:port]` (the host possibly a bracketed IPv6 literal) into the
/// host and the port.
fn split_host_port(authority: &str) -> (&str, Option<&str>) {
    if authority.starts_with('[') {
        return match authority.find(']') {
            Some(end) => {
                let (host, rest) = authority.split_at(end + 1);
                match rest.strip_prefix(':') {
                    Some(port) => (host, Some(port)),
                    None if rest.is_empty() => (host, None),
                    None => (authority, None),
                }
            }
            None => (authority, None),
        };
    }
    match authority.split_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (authority, None),
    }
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
    fn url_rejects_a_domain_that_does_not_decode_to_a_host() {
        for domain in [
            "trusted.example%40other.example",
            "other.example%2Fx.trusted.example",
            "example.com%3Fq",
            "example.com%23f",
            "example.com%5Cx",
            "example.com%25",
            "example.com%3A",
            "example.com%3Ahttp",
            "example.com%3A99999",
            "example.com%3A80%3A80",
            "exa%20mple.com",
            "exa%0Ample.com",
            "%5B%3A%3A1",
            "%5Bnot-ipv6%5D",
            "%5B%3A%3A1%5Dx",
            "%3A443",
        ] {
            let err = build_url(domain, &[]).unwrap_err();
            assert!(
                matches!(err, DidWebError::InvalidDid(_)),
                "domain {domain:?} should be rejected, got {err:?}"
            );
        }
    }

    #[test]
    fn url_accepts_hosts_ports_and_ip_literals() {
        for (domain, expected) in [
            ("example.com", "https://example.com/.well-known/did.json"),
            (
                "192.0.2.1%3A8080",
                "https://192.0.2.1:8080/.well-known/did.json",
            ),
            (
                "%5B2001%3Adb8%3A%3A1%5D",
                "https://[2001:db8::1]/.well-known/did.json",
            ),
            (
                "%5B2001%3Adb8%3A%3A1%5D%3A8443",
                "https://[2001:db8::1]:8443/.well-known/did.json",
            ),
        ] {
            assert_eq!(build_url(domain, &[]).unwrap(), expected);
        }
    }

    #[test]
    fn url_rejects_segments_that_would_leave_the_path() {
        for seg in ["a%3Fb", "a%23", "a%40b", "a%25b", "a%00", "a%0A"] {
            let err = build_url("example.com", &[seg.to_string()]).unwrap_err();
            assert!(
                matches!(err, DidWebError::InvalidDid(_)),
                "segment {seg:?} should be rejected, got {err:?}"
            );
        }
    }

    #[tokio::test]
    async fn resolve_refuses_a_did_whose_domain_decodes_to_userinfo() {
        let err = DIDWeb::with_policy(HostPolicy::AllowPrivate)
            .resolve("did:web:trusted.example%40127.0.0.1")
            .await
            .unwrap_err();
        assert!(matches!(err, DidWebError::InvalidDid(_)), "got {err:?}");
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

    /// Drive a `DIDWeb` (under `AllowPrivate`, as the mock listens on
    /// loopback) through its fetch: the response handling, the size cap, the
    /// parse and the `id` check. Only the `https` URL `resolve` builds is
    /// swapped for the mock's plain-HTTP one, as wiremock has no TLS.
    async fn resolve_via_mock(
        did: &str,
        response: ResponseTemplate,
    ) -> Result<Document, DidWebError> {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/.well-known/did.json"))
            .respond_with(response)
            .mount(&server)
            .await;
        let url = format!("{}/.well-known/did.json", server.uri());
        let parsed_url = reqwest::Url::parse(&url).unwrap();
        DIDWeb::with_policy(HostPolicy::AllowPrivate)
            .fetch_document(did, parsed_url, url)
            .await
    }

    #[tokio::test]
    async fn resolves_via_mock_server() {
        let did_doc = serde_json::json!({
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": "did:web:example.com",
        });
        let document = resolve_via_mock(
            "did:web:example.com",
            ResponseTemplate::new(200).set_body_json(&did_doc),
        )
        .await
        .unwrap();
        assert_eq!(document.id.as_str(), "did:web:example.com");
    }

    /// DID Core allows relative ids and references; they resolve against the
    /// document's `id` instead of failing to parse.
    #[tokio::test]
    async fn resolves_a_document_with_relative_ids() {
        let did_doc = serde_json::json!({
            "id": "did:web:example.com",
            "verificationMethod": [{
                "id": "#key-1",
                "type": "Multikey",
                "controller": "did:web:example.com",
                "publicKeyMultibase": "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
            }],
            "authentication": ["#key-1"],
            "service": [{
                "id": "#files",
                "type": "LinkedDomains",
                "serviceEndpoint": "https://example.com"
            }]
        });
        let document = resolve_via_mock(
            "did:web:example.com",
            ResponseTemplate::new(200).set_body_json(&did_doc),
        )
        .await
        .unwrap();
        use affinidi_did_common::DocumentExt;
        assert_eq!(
            document.verification_method[0].id.as_str(),
            "did:web:example.com#key-1"
        );
        assert!(document.contains_authentication("did:web:example.com#key-1"));
        assert_eq!(
            document.service[0].id.as_ref().map(|id| id.as_str()),
            Some("did:web:example.com#files")
        );
    }

    #[tokio::test]
    async fn a_mock_document_for_another_did_is_refused() {
        let did_doc = serde_json::json!({ "id": "did:web:evil.example.com" });
        let err = resolve_via_mock(
            "did:web:example.com",
            ResponseTemplate::new(200).set_body_json(&did_doc),
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, DidWebError::DocumentIdMismatch { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn verify_document_id_accepts_a_match() {
        let document = Document::new("did:web:example.com").unwrap();
        assert!(verify_document_id("did:web:example.com", &document).is_ok());
    }

    #[test]
    fn verify_document_id_refuses_a_mismatch() {
        // A server answering for `did:web:example.com` must not be able to
        // hand back a document that names a different subject.
        let document = Document::new("did:web:evil.example.com").unwrap();
        let err = verify_document_id("did:web:example.com", &document).unwrap_err();
        assert!(
            matches!(
                err,
                DidWebError::DocumentIdMismatch { ref expected, ref got }
                    if expected == "did:web:example.com" && got == "did:web:evil.example.com"
            ),
            "{err:?}"
        );
    }

    /// `Document::id` has no `#[serde(default)]`, so a document missing `id`
    /// entirely is already refused by deserialization, before
    /// `verify_document_id` is ever reached.
    #[test]
    fn document_without_id_fails_to_parse() {
        let err = serde_json::from_str::<Document>(r#"{"service":[]}"#).unwrap_err();
        assert!(err.to_string().contains("id"), "{err}");
    }

    /// A 429's `Retry-After` is kept as data (#1166).
    #[tokio::test]
    async fn a_rate_limit_keeps_its_retry_after() {
        let err = resolve_via_mock(
            "did:web:example.com",
            ResponseTemplate::new(429).insert_header("Retry-After", "30"),
        )
        .await
        .unwrap_err();
        let network = err.network_error().expect("a network error");
        assert!(network.is_rate_limited(), "{err:?}");
        assert_eq!(network.retry_after, Some(Duration::from_secs(30)));
    }

    #[tokio::test]
    async fn surfaces_http_error_status() {
        let err = resolve_via_mock("did:web:example.com", ResponseTemplate::new(404))
            .await
            .unwrap_err();
        assert!(
            matches!(
                &err,
                DidWebError::Network(NetworkError { status: Some(404), url: Some(url), .. })
                    if url.ends_with("/.well-known/did.json")
            ),
            "{err:?}"
        );
        let network = err.network_error().expect("a network error");
        assert_eq!(network.status, Some(404));
        assert!(
            network
                .url
                .as_deref()
                .is_some_and(|url| url.ends_with("/.well-known/did.json"))
        );
    }

    #[tokio::test]
    async fn a_body_over_the_cap_is_refused() {
        let err = resolve_via_mock(
            "did:web:example.com",
            ResponseTemplate::new(200).set_body_bytes(vec![b' '; MAX_DOCUMENT_BYTES + 1]),
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, DidWebError::ResponseTooLarge { .. }),
            "{err:?}"
        );
    }

    /// `HostPolicy::PublicOnly` and an egress policy refuse the same
    /// special-use names, `affinidi-net-guard`'s: since 0.2.0 that includes
    /// `*.internal`, `*.home.arpa` and single-label names (#1166).
    #[tokio::test]
    async fn an_egress_policy_applies_the_net_guard_special_use_names() {
        let resolver = DIDWeb::with_egress_policy(
            reqwest::Client::builder().timeout(Duration::from_secs(5)),
            EgressPolicy::public_internet(),
        )
        .unwrap();
        for host in ["metadata.internal", "router.home.arpa", "intranet"] {
            assert!(host_is_blocked(host), "{host}: PublicOnly refuses it too");
            let err = DIDWeb::new()
                .resolve(&format!("did:web:{host}"))
                .await
                .unwrap_err();
            assert!(
                matches!(err, DidWebError::BlockedHost(_)),
                "{host}: {err:?}"
            );
            let err = resolver
                .resolve(&format!("did:web:{host}"))
                .await
                .unwrap_err();
            assert!(
                matches!(err, DidWebError::BlockedHost(_)),
                "{host}: {err:?}"
            );
        }
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
        let Err(err) = guarded_dns_resolver().resolve(name).await else {
            panic!("localhost resolves to loopback and must be refused");
        };
        assert!(
            affinidi_net_guard::blocked_in_chain(err.as_ref()).is_some(),
            "expected a BlockedAddress, got {err:?}"
        );
    }

    /// ...and that refusal must survive reqwest's error wrapping, so callers
    /// see `BlockedHost` rather than a generic transport failure. Hermetic: DNS
    /// for `localhost` is local and the connection is never made.
    #[tokio::test]
    async fn dns_guard_surfaces_as_blocked_host() {
        let client = DIDWeb::new().client;
        let err = client
            .get("http://localhost/.well-known/did.json")
            .send()
            .await
            .expect_err("the guarded resolver must refuse localhost");
        assert!(
            affinidi_net_guard::blocked_in_chain(&err).is_some(),
            "BlockedAddress should be recoverable from the reqwest error chain, got {err:?}"
        );
    }

    /// A client built without the guarded resolver keeps the literal check.
    #[test]
    #[allow(deprecated)]
    fn with_client_defaults_to_public_only() {
        let resolver = DIDWeb::with_client(reqwest::Client::new());
        assert!(matches!(resolver.guard, Guard::PublicOnly));
    }

    /// A resolver under an allow-list refuses a public host outside it,
    /// before any request.
    #[tokio::test]
    async fn an_egress_policy_allow_list_is_enforced() {
        use affinidi_net_guard::{AllowList, HostRule};
        let policy = EgressPolicy::public_internet()
            .with_allow_list(AllowList::new([HostRule::Exact("did.example.org".into())]).unwrap());
        let resolver = DIDWeb::with_egress_policy(
            reqwest::Client::builder().timeout(Duration::from_secs(5)),
            policy,
        )
        .unwrap();
        let err = resolver.resolve("did:web:example.com").await.unwrap_err();
        assert!(matches!(err, DidWebError::BlockedHost(_)), "{err:?}");
        // The policy's address rules still apply.
        let err = resolver.resolve("did:web:127.0.0.1").await.unwrap_err();
        assert!(matches!(err, DidWebError::BlockedHost(_)), "{err:?}");
    }

    /// Serve `/.well-known/did.json` after `delay`, recording requests.
    async fn slow_server(delay: Duration) -> (MockServer, reqwest::Url, String) {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/.well-known/did.json"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_delay(delay)
                    .set_body_json(serde_json::json!({ "id": "did:web:example.com" })),
            )
            .mount(&server)
            .await;
        let url = format!("{}/.well-known/did.json", server.uri());
        (server, reqwest::Url::parse(&url).unwrap(), url)
    }

    /// `with_client_builder_and_timeout` is the timeout requests get (#1154).
    #[tokio::test]
    async fn the_chosen_timeout_is_applied() {
        let (_server, parsed, url) = slow_server(Duration::from_secs(10)).await;
        let resolver = DIDWeb::with_client_builder_and_timeout(
            reqwest::Client::builder(),
            HostPolicy::AllowPrivate,
            Duration::from_millis(200),
        )
        .unwrap();
        let started = std::time::Instant::now();
        let err = resolver
            .fetch_document("did:web:example.com", parsed, url)
            .await
            .unwrap_err();
        assert!(matches!(err, DidWebError::Http(_)), "{err:?}");
        assert!(started.elapsed() < Duration::from_secs(5), "timed out late");
    }

    /// `with_egress_policy` keeps the builder's timeout and user agent
    /// (#1154). The mock is a loopback literal, which the connect-time guard
    /// never sees (no name is resolved), so the fetch is driven directly.
    #[tokio::test]
    async fn an_egress_policy_resolver_keeps_the_builders_timeout_and_user_agent() {
        let (server, parsed, url) = slow_server(Duration::from_secs(10)).await;
        let resolver = DIDWeb::with_egress_policy(
            reqwest::Client::builder().timeout(Duration::from_millis(200)),
            EgressPolicy::public_internet(),
        )
        .unwrap();
        let started = std::time::Instant::now();
        let err = resolver
            .fetch_document("did:web:example.com", parsed, url)
            .await
            .unwrap_err();
        assert!(matches!(err, DidWebError::Http(_)), "{err:?}");
        assert!(started.elapsed() < Duration::from_secs(5), "timed out late");
        drop(server);

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/.well-known/did.json"))
            .and(wiremock::matchers::header("user-agent", "caller/1.0"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "id": "did:web:example.com" })),
            )
            .mount(&server)
            .await;
        let url = format!("{}/.well-known/did.json", server.uri());
        let resolver = DIDWeb::with_egress_policy(
            reqwest::Client::builder()
                .user_agent("caller/1.0")
                .timeout(Duration::from_secs(5)),
            EgressPolicy::public_internet(),
        )
        .unwrap();
        resolver
            .fetch_document(
                "did:web:example.com",
                reqwest::Url::parse(&url).unwrap(),
                url,
            )
            .await
            .expect("the caller's user agent was sent");
    }

    #[cfg(feature = "resolver-traits")]
    #[tokio::test]
    async fn the_resolver_trait_declines_other_methods_and_maps_errors() {
        use affinidi_did_resolver_traits::{AsyncResolver, ResolverError};
        let resolver = DIDWeb::new();
        assert_eq!(AsyncResolver::name(&resolver), "WebResolver");
        let other: DID = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
            .parse()
            .unwrap();
        assert!(AsyncResolver::resolve(&resolver, &other).await.is_none());

        let blocked: DID = "did:web:127.0.0.1".parse().unwrap();
        let Some(Err(err)) = AsyncResolver::resolve(&resolver, &blocked).await else {
            panic!("a refused host is handled and fails");
        };
        assert!(matches!(err, ResolverError::ResolutionFailed(_)), "{err:?}");

        let status = super::resolver_impl::resolver_error(DidWebError::Network(
            NetworkError::new("HTTP 429")
                .with_url("https://example.com/.well-known/did.json")
                .with_status(429)
                .with_retry_after(Duration::from_secs(30)),
        ));
        let ResolverError::NetworkFetch(fetch) = status else {
            panic!("expected NetworkFetch, got {status:?}");
        };
        assert!(fetch.is_rate_limited());
        assert_eq!(
            fetch.url.as_deref(),
            Some("https://example.com/.well-known/did.json")
        );
        assert_eq!(fetch.retry_after, Some(Duration::from_secs(30)));
    }

    /// Under `PublicOnly` no proxy is used, even one the caller's builder
    /// names: a proxy resolves the hostname itself, so the connect-time check
    /// would never see the address the request went to. The "proxy" here is a
    /// bare listener that counts connections; an honoured proxy would be
    /// connected to for the CONNECT tunnel.
    #[tokio::test]
    async fn public_only_uses_no_proxy_even_one_the_caller_names() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = format!("http://{}", listener.local_addr().unwrap());
        let accepted = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = accepted.clone();
        tokio::spawn(async move {
            while let Ok((_socket, _)) = listener.accept().await {
                counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
        });

        let builder = reqwest::Client::builder()
            .proxy(reqwest::Proxy::all(&proxy).unwrap())
            .timeout(std::time::Duration::from_secs(5));
        let resolver = DIDWeb::with_client_builder(builder, HostPolicy::PublicOnly).unwrap();
        resolver
            .resolve("did:web:did-web-proxy-test.example.com")
            .await
            .expect_err("the host does not exist");

        assert_eq!(
            accepted.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "the proxy was used"
        );
    }

    /// A caller's builder keeps the guard: a loopback name is still refused at
    /// connect time when the caller supplied the builder.
    #[tokio::test]
    async fn a_callers_builder_keeps_the_dns_guard() {
        let builder = reqwest::Client::builder().timeout(std::time::Duration::from_secs(5));
        let resolver = DIDWeb::with_client_builder(builder, HostPolicy::PublicOnly).unwrap();
        // Drive the client directly: `localhost` would be refused by name
        // before any request, and only the DNS guard is under test here.
        let err = resolver
            .client
            .get("https://localhost:1/")
            .send()
            .await
            .expect_err("the guarded resolver must refuse localhost");
        assert!(
            affinidi_net_guard::blocked_in_chain(&err).is_some(),
            "expected the DNS guard to refuse, got {err:?}"
        );
    }
}
