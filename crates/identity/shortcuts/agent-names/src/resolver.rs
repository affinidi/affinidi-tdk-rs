//! Backends that turn an agent name into a DID.

use std::{future::Future, pin::Pin, sync::Arc, time::Duration};

use affinidi_net_guard::{EgressError, EgressPolicy, GuardedResolver};
use tracing::debug;
use url::Url;

use crate::{error::AgentNameError, name::AgentName};

/// Default request timeout.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(20);

/// Default connect timeout.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Default cap on redirect hops followed while chasing a name.
pub const DEFAULT_MAX_HOPS: u8 = 5;

/// The outcome of asking one backend to resolve a name.
///
/// Mirrors `affinidi_did_resolver_traits::Resolution`, so a chain of agent name
/// backends reads the same way as a chain of DID method resolvers:
///
/// - `None` — "not mine, try the next backend"
/// - `Some(Ok(did))` — resolved
/// - `Some(Err(e))` — recognised, but failed
pub type NameResolution = Option<Result<String, AgentNameError>>;

/// A backend that maps an agent name to a DID.
///
/// Implement this to resolve names from somewhere other than a live HTTP
/// redirect — a registry API, DNS, a cache server, or a fixed map in tests.
pub trait AgentNameResolver: Send + Sync {
    /// Short name for this backend, used for logging and de-duplication.
    fn name(&self) -> &str;

    /// Attempt to resolve `name` to a DID string.
    fn resolve<'a>(
        &'a self,
        name: &'a AgentName,
    ) -> Pin<Box<dyn Future<Output = NameResolution> + Send + 'a>>;
}

/// Resolves an agent name by following the web redirect it serves.
///
/// # The redirect contract is not pinned down by the specification
///
/// The agent name FAQ says only that resolution "typically works through a
/// simple web redirect". It does not state the status code, whether the DID
/// arrives as a bare `did:…` string or wrapped in a URI, or whether content
/// negotiation is involved. At the time of writing there is no reference
/// implementation to check against: `firstperson.network` is live but its
/// example names return 404.
///
/// This backend is therefore deliberately permissive, and every guess is
/// contained here rather than in the crate's data types:
///
/// - any 3xx carrying a `Location` header is accepted (301/302/303/307/308);
/// - the target is accepted as a bare `did:…`, or as a URI whose last path
///   segment is a DID, or with a `did=` query parameter;
/// - up to [`DEFAULT_MAX_HOPS`] hops are followed, so an apex-to-`www`
///   redirect on the way to the DID does not break resolution.
///
/// # Outbound requests
///
/// Redirects are **not** followed automatically by `reqwest`; each hop is
/// inspected explicitly, which is what makes the hop cap and the HTTPS
/// requirement enforceable.
///
/// Unless [`allow_private_addresses`](Self::allow_private_addresses) is set,
/// every hop is held to `affinidi_net_guard::EgressPolicy::public_internet()`
/// in two places, as `affinidi-did-web` does:
///
/// - the URL is vetted before the request: IP literals and special-use names
///   (`localhost`, `*.local`, `*.internal`, single-label names, ...);
/// - the client's DNS resolver is `affinidi_net_guard::GuardedResolver`, which
///   refuses the name if any address it resolves to is not globally routable
///   and hands the connection only the addresses it checked. There is no
///   second lookup, so the answer that was checked is the one connected to.
///
/// Proxies are turned off, since a proxy resolves the name itself and the
/// resolver would never see the address.
#[derive(Debug, Clone)]
pub struct HttpRedirectResolver {
    client: reqwest::Client,
    client_origin: ClientOrigin,
    max_hops: u8,
    allow_insecure_http: bool,
    allow_private_addresses: bool,
}

/// Who built the client, which decides whether
/// [`HttpRedirectResolver::allow_private_addresses`] can rebuild it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClientOrigin {
    Default,
    CallerBuilder,
    CallerClient,
}

impl HttpRedirectResolver {
    /// A resolver with redirects disabled, a 20s timeout, HTTPS required, and
    /// public addresses only.
    ///
    /// # Panics
    ///
    /// If the HTTP client cannot be built (the TLS backend fails to
    /// initialise), as `reqwest::Client::new` does.
    pub fn new() -> Self {
        Self::from_client(default_client(true), ClientOrigin::Default)
    }

    /// A resolver over a client the caller configures (headers, TLS,
    /// connection pool), with [`DEFAULT_TIMEOUT`] and
    /// [`DEFAULT_CONNECT_TIMEOUT`].
    ///
    /// The guard settings are applied after the caller's, so nothing set on
    /// `builder` can undo them: redirects are never followed, every proxy
    /// (including one named by `HTTPS_PROXY`) is turned off, and the guarded
    /// DNS resolver is installed. The timeouts are applied after the caller's
    /// too, so any timeout set on `builder` is replaced; use
    /// [`with_client_builder_and_timeouts`](Self::with_client_builder_and_timeouts)
    /// to choose them.
    ///
    /// The guarded resolver stays installed even if
    /// [`allow_private_addresses`](Self::allow_private_addresses) is set later,
    /// since `builder` cannot be rebuilt: with this constructor that switch
    /// admits private IP literals only.
    ///
    /// # Errors
    ///
    /// [`AgentNameError::Http`] if `reqwest` cannot build the client.
    pub fn with_client_builder(builder: reqwest::ClientBuilder) -> Result<Self, AgentNameError> {
        Self::with_client_builder_and_timeouts(builder, DEFAULT_TIMEOUT, DEFAULT_CONNECT_TIMEOUT)
    }

    /// As [`with_client_builder`](Self::with_client_builder), with the
    /// whole-request `timeout` and the `connect_timeout` given here. They
    /// replace any timeout set on `builder`.
    ///
    /// # Errors
    ///
    /// [`AgentNameError::Http`] if `reqwest` cannot build the client.
    pub fn with_client_builder_and_timeouts(
        builder: reqwest::ClientBuilder,
        timeout: Duration,
        connect_timeout: Duration,
    ) -> Result<Self, AgentNameError> {
        Self::from_builder(builder, timeout, connect_timeout, None)
    }

    fn from_builder(
        builder: reqwest::ClientBuilder,
        timeout: Duration,
        connect_timeout: Duration,
        inner: Option<Arc<dyn reqwest::dns::Resolve>>,
    ) -> Result<Self, AgentNameError> {
        let builder = builder.timeout(timeout).connect_timeout(connect_timeout);
        let client = guard(builder, true, inner).build()?;
        Ok(Self::from_client(client, ClientOrigin::CallerBuilder))
    }

    /// Use a caller-supplied client.
    ///
    /// The client **must** have redirects disabled
    /// (`reqwest::redirect::Policy::none()`); otherwise the hop cap and the
    /// per-hop HTTPS check do not hold. A built client cannot be inspected or
    /// changed, so only the URL of each hop is vetted: a name that resolves to
    /// a private address, or a proxy, is stopped only if the caller built the
    /// client to stop it.
    #[deprecated(
        since = "0.1.4",
        note = "a built client may not carry the connect-time address check; use `with_client_builder`, which applies it"
    )]
    pub fn with_client(client: reqwest::Client) -> Self {
        Self::from_client(client, ClientOrigin::CallerClient)
    }

    fn from_client(client: reqwest::Client, client_origin: ClientOrigin) -> Self {
        Self {
            client,
            client_origin,
            max_hops: DEFAULT_MAX_HOPS,
            allow_insecure_http: false,
            allow_private_addresses: false,
        }
    }

    /// Override the redirect hop cap.
    pub fn with_max_hops(mut self, max_hops: u8) -> Self {
        self.max_hops = max_hops;
        self
    }

    /// Permit plain-HTTP agent names.
    ///
    /// Off by default and intended for local development and tests. A plain
    /// HTTP redirect can be rewritten in transit, which lets a third party
    /// point the name at a DID of their choosing — `alsoKnownAs` verification
    /// will usually catch that, but do not rely on it in production.
    pub fn allow_insecure_http(mut self, allow: bool) -> Self {
        self.allow_insecure_http = allow;
        self
    }

    /// Permit agent names that resolve to private, loopback or link-local
    /// addresses.
    ///
    /// Off by default. Agent names are public-web identifiers, so a name
    /// pointing at `127.0.0.1`, `10.0.0.0/8` or the cloud metadata address
    /// `169.254.169.254` is almost never a real name. That matters most when
    /// this resolver runs **server-side** (the DID cache server), where the
    /// caller supplies the name and the server makes the request from inside
    /// your network.
    ///
    /// On a resolver from [`new`](Self::new) this rebuilds the client without
    /// the guarded DNS resolver. On one from
    /// [`with_client_builder`](Self::with_client_builder) the client keeps it,
    /// so only private IP literals are admitted.
    ///
    /// Turn it on only for local development and tests.
    pub fn allow_private_addresses(mut self, allow: bool) -> Self {
        if self.client_origin == ClientOrigin::Default && allow != self.allow_private_addresses {
            self.client = default_client(!allow);
        }
        self.allow_private_addresses = allow;
        self
    }

    /// Vet a hop's URL under the public-internet policy: IP literals,
    /// special-use names and userinfo. What a name resolves to is checked by
    /// the client's DNS resolver when it connects.
    fn check_url(&self, url: &Url, name: &AgentName) -> Result<(), AgentNameError> {
        if self.allow_private_addresses {
            return Ok(());
        }
        // The scheme is this resolver's decision (`allow_insecure_http`), so
        // vet the address under the https rules either way.
        let mut vetted = url.clone();
        if vetted.scheme() == "http" {
            let port = vetted.port_or_known_default();
            vetted
                .set_scheme("https")
                .and_then(|()| vetted.set_port(port))
                .map_err(|()| AgentNameError::InvalidName {
                    input: url.to_string(),
                    reason: "cannot vet the URL".to_string(),
                })?;
        }
        EgressPolicy::public_internet()
            .vet_url(&vetted)
            .map(|_| ())
            .map_err(|e| egress_error(e, url, name))
    }

    async fn fetch(
        &self,
        url: &Url,
        name: &AgentName,
    ) -> Result<reqwest::Response, AgentNameError> {
        self.client.get(url.clone()).send().await.map_err(|e| {
            match affinidi_net_guard::blocked_in_chain(&e) {
                Some(EgressError::BlockedAddress { addr, .. }) => AgentNameError::BlockedAddress {
                    name: name.as_str().to_string(),
                    address: addr.to_string(),
                },
                _ => AgentNameError::Http(e),
            }
        })
    }

    async fn resolve_inner(&self, name: &AgentName) -> Result<String, AgentNameError> {
        if !name.is_https() && !self.allow_insecure_http {
            return Err(AgentNameError::InsecureScheme(name.as_str().to_string()));
        }

        let mut url = name.resolution_url()?;

        for hop in 0..self.max_hops {
            // Re-checked on *every* hop: a public host can redirect inward.
            self.check_url(&url, name)?;
            debug!(hop, %url, "resolving agent name");
            let response = self.fetch(&url, name).await?;
            let status = response.status();

            if !status.is_redirection() {
                return Err(AgentNameError::NoRedirect {
                    name: name.as_str().to_string(),
                    status: status.as_u16(),
                });
            }

            let location = response
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|v| v.to_str().ok())
                .ok_or_else(|| AgentNameError::NoRedirect {
                    name: name.as_str().to_string(),
                    status: status.as_u16(),
                })?
                .to_string();

            if let Some(did) = extract_did(&location) {
                return Ok(did);
            }

            // Not a DID yet — could be an apex→www or http→https hop. Resolve
            // the target relative to the current URL and keep going.
            let next = url.join(&location).map_err(|_| AgentNameError::NotADid {
                name: name.as_str().to_string(),
                target: location.clone(),
            })?;

            if next.scheme() != "https" && !self.allow_insecure_http {
                return Err(AgentNameError::InsecureScheme(next.to_string()));
            }
            let _ = hop;
            url = next;
        }

        Err(AgentNameError::TooManyRedirects {
            name: name.as_str().to_string(),
            limit: self.max_hops,
        })
    }
}

impl Default for HttpRedirectResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl AgentNameResolver for HttpRedirectResolver {
    fn name(&self) -> &str {
        "http-redirect"
    }

    fn resolve<'a>(
        &'a self,
        name: &'a AgentName,
    ) -> Pin<Box<dyn Future<Output = NameResolution> + Send + 'a>> {
        Box::pin(async move { Some(self.resolve_inner(name).await) })
    }
}

/// Pull a DID out of a redirect target.
///
/// Accepts, in order: a bare `did:…`; a `did=` query parameter; a URI whose
/// last path segment is a DID. Returns `None` if the target carries no DID,
/// which the caller treats as "keep following".
fn extract_did(target: &str) -> Option<String> {
    let trimmed = target.trim();

    if is_did(trimmed) {
        return Some(trimmed.to_string());
    }

    if let Ok(url) = Url::parse(trimmed) {
        if let Some((_, value)) = url.query_pairs().find(|(k, _)| k == "did")
            && is_did(&value)
        {
            return Some(value.into_owned());
        }
        // A DID in a path arrives percent-encoded, since ':' is reserved.
        if let Some(last) = url.path_segments().and_then(|mut s| s.next_back())
            && let Ok(decoded) = percent_decode(last)
            && is_did(&decoded)
        {
            return Some(decoded);
        }
    }

    None
}

/// Map a URL refusal onto this crate's errors.
fn egress_error(err: EgressError, url: &Url, name: &AgentName) -> AgentNameError {
    match err {
        EgressError::BlockedAddress { addr, .. } => AgentNameError::BlockedAddress {
            name: name.as_str().to_string(),
            address: addr.to_string(),
        },
        EgressError::BlockedName(host) => AgentNameError::BlockedHost {
            name: name.as_str().to_string(),
            host,
        },
        other => AgentNameError::InvalidName {
            input: url.to_string(),
            reason: other.to_string(),
        },
    }
}

/// The timeouts of a client this crate builds from scratch.
fn default_settings(builder: reqwest::ClientBuilder) -> reqwest::ClientBuilder {
    builder
        .timeout(DEFAULT_TIMEOUT)
        .connect_timeout(DEFAULT_CONNECT_TIMEOUT)
}

/// The guard settings. Applied last, so nothing set before can undo them.
///
/// `inner` replaces the system resolver underneath the guard; tests use it to
/// answer a public-looking name with a private address.
fn guard(
    builder: reqwest::ClientBuilder,
    public_only: bool,
    inner: Option<Arc<dyn reqwest::dns::Resolve>>,
) -> reqwest::ClientBuilder {
    let builder = builder
        .redirect(reqwest::redirect::Policy::none())
        .referer(false);
    if !public_only {
        return match inner {
            Some(inner) => builder.dns_resolver(inner),
            None => builder,
        };
    }
    let mut resolver = GuardedResolver::new(EgressPolicy::public_internet());
    if let Some(inner) = inner {
        resolver = resolver.with_inner(inner);
    }
    builder.dns_resolver(Arc::new(resolver)).no_proxy()
}

fn default_client(public_only: bool) -> reqwest::Client {
    guard(
        default_settings(reqwest::Client::builder()),
        public_only,
        None,
    )
    .build()
    .expect("reqwest client with default config")
}

fn is_did(s: &str) -> bool {
    // did:<method>:<id> — enough structure to distinguish a DID from a URL.
    let mut parts = s.splitn(3, ':');
    parts.next() == Some("did")
        && parts.next().is_some_and(|m| {
            !m.is_empty()
                && m.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        })
        && parts.next().is_some_and(|id| !id.is_empty())
}

fn percent_decode(s: &str) -> Result<String, ()> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                return Err(());
            }
            let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).map_err(|_| ())?;
            out.push(u8::from_str_radix(hex, 16).map_err(|_| ())?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- is_did ---

    #[test]
    fn recognises_dids() {
        assert!(is_did("did:web:example.com"));
        assert!(is_did("did:key:z6Mk"));
        assert!(is_did("did:webvh:QmScid:example.com"));
        assert!(is_did("did:scid:vh:1:QmScid"));
    }

    #[test]
    fn rejects_non_dids() {
        assert!(!is_did("https://example.com"));
        assert!(!is_did("did:"));
        assert!(!is_did("did::abc"));
        assert!(!is_did("did:web:"));
        assert!(!is_did("notdid:web:example.com"));
        // Method names are lowercase alphanumeric.
        assert!(!is_did("did:WEB:example.com"));
        assert!(!is_did("did:we-b:example.com"));
    }

    // --- extract_did ---

    #[test]
    fn extracts_bare_did() {
        assert_eq!(
            extract_did("did:web:example.com").as_deref(),
            Some("did:web:example.com")
        );
    }

    #[test]
    fn extracts_did_with_surrounding_whitespace() {
        assert_eq!(
            extract_did("  did:web:example.com  ").as_deref(),
            Some("did:web:example.com")
        );
    }

    #[test]
    fn extracts_did_from_query_parameter() {
        assert_eq!(
            extract_did("https://example.com/resolve?did=did:web:example.com").as_deref(),
            Some("did:web:example.com")
        );
    }

    #[test]
    fn extracts_percent_encoded_did_from_path() {
        assert_eq!(
            extract_did("https://example.com/dids/did%3Aweb%3Aexample.com").as_deref(),
            Some("did:web:example.com")
        );
    }

    #[test]
    fn returns_none_for_plain_url() {
        // An apex->www hop carries no DID; the caller keeps following.
        assert_eq!(extract_did("https://www.example.com/@alice"), None);
    }

    // --- percent_decode ---

    #[test]
    fn percent_decodes() {
        assert_eq!(percent_decode("did%3Aweb%3Ax").unwrap(), "did:web:x");
        assert_eq!(percent_decode("plain").unwrap(), "plain");
        assert!(percent_decode("%zz").is_err());
        assert!(percent_decode("truncated%4").is_err());
    }

    // --- per-hop URL vetting ---

    fn alice() -> AgentName {
        AgentName::parse("https://example.com/@alice").unwrap()
    }

    fn check(url: &str) -> Result<(), AgentNameError> {
        HttpRedirectResolver::new().check_url(&Url::parse(url).unwrap(), &alice())
    }

    #[test]
    fn refuses_non_public_literals() {
        for host in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "0.0.0.0",
            "0.1.2.3",         // 0.0.0.0/8
            "169.254.169.254", // cloud metadata
            "100.64.0.1",      // carrier-grade NAT
            "198.18.0.1",      // benchmarking
            "255.255.255.255",
            "240.0.0.1",
            "[::1]",
            "[::]",
            "[fc00::1]",
            "[fd00::1]",
            "[fe80::1]",
            "[fec0::1]", // deprecated site-local
            "[ff02::1]",
            "[2001:db8::1]",      // documentation
            "[::ffff:127.0.0.1]", // IPv4-mapped
            "[::127.0.0.1]",      // IPv4-compatible
            "[64:ff9b::7f00:1]",  // NAT64 of 127.0.0.1
            "[2002:7f00:1::]",    // 6to4 of 127.0.0.1
            "[::ffff:10.0.0.1]",
        ] {
            let err = check(&format!("https://{host}/@alice")).unwrap_err();
            assert!(
                matches!(err, AgentNameError::BlockedAddress { .. }),
                "{host}: got {err:?}"
            );
        }
    }

    #[test]
    fn refuses_special_use_names() {
        for host in ["localhost", "router.local", "metadata.internal", "intranet"] {
            let err = check(&format!("https://{host}/@alice")).unwrap_err();
            assert!(
                matches!(err, AgentNameError::BlockedHost { .. }),
                "{host}: got {err:?}"
            );
        }
    }

    #[test]
    fn admits_public_hosts_on_https_and_http() {
        for url in [
            "https://1.1.1.1/@alice",
            "https://[2606:4700:4700::1111]/@alice",
            "https://[::ffff:8.8.8.8]/@alice",
            "https://example.com/@alice",
            "http://example.com/@alice",
            "http://example.com:8080/@alice",
        ] {
            check(url).unwrap_or_else(|e| panic!("{url}: {e:?}"));
        }
    }

    #[test]
    fn allow_private_addresses_skips_url_vetting() {
        HttpRedirectResolver::new()
            .allow_private_addresses(true)
            .check_url(&Url::parse("http://127.0.0.1/@alice").unwrap(), &alice())
            .unwrap();
    }

    // --- connect-time address check ---

    /// Answers every name with 127.0.0.1, as a name whose DNS points inward
    /// would.
    struct LoopbackDns;

    impl reqwest::dns::Resolve for LoopbackDns {
        fn resolve(&self, _name: reqwest::dns::Name) -> reqwest::dns::Resolving {
            Box::pin(async {
                let addrs: reqwest::dns::Addrs = Box::new(std::iter::once(
                    std::net::SocketAddr::from(([127, 0, 0, 1], 0)),
                ));
                Ok(addrs)
            })
        }
    }

    async fn resolve_via_loopback_dns(public_only: bool) -> Result<String, AgentNameError> {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::path("/@alice"))
            .respond_with(
                wiremock::ResponseTemplate::new(302)
                    .insert_header("location", "did:web:example.com"),
            )
            .mount(&server)
            .await;
        let port = server.address().port();
        let client = guard(
            default_settings(reqwest::Client::builder()),
            public_only,
            Some(Arc::new(LoopbackDns)),
        )
        .build()
        .unwrap();
        let resolver = HttpRedirectResolver::from_client(client, ClientOrigin::CallerBuilder)
            .allow_insecure_http(true);
        let name = AgentName::parse(&format!("http://names.example.com:{port}/@alice")).unwrap();
        resolver.resolve_inner(&name).await
    }

    /// A public-looking name whose DNS answers with a loopback address passes
    /// the URL check, so the client's resolver must refuse it when connecting.
    #[tokio::test]
    async fn refuses_a_name_that_resolves_to_loopback_when_connecting() {
        let err = resolve_via_loopback_dns(true).await.unwrap_err();
        assert!(
            matches!(&err, AgentNameError::BlockedAddress { address, .. } if address == "127.0.0.1"),
            "got {err:?}"
        );
    }

    /// Control for the test above: the same name and DNS reach the local
    /// server once the guard is off, so the refusal comes from the guard.
    #[tokio::test]
    async fn the_same_name_resolves_without_the_guard() {
        assert_eq!(
            resolve_via_loopback_dns(false).await.unwrap(),
            "did:web:example.com"
        );
    }

    /// A resolver from `with_client_builder` carries the same connect-time
    /// check as one from `new()`.
    #[tokio::test]
    async fn with_client_builder_refuses_a_name_that_resolves_to_loopback() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::path("/@alice"))
            .respond_with(
                wiremock::ResponseTemplate::new(302)
                    .insert_header("location", "did:web:example.com"),
            )
            .mount(&server)
            .await;
        let port = server.address().port();
        let resolver = HttpRedirectResolver::from_builder(
            reqwest::Client::builder(),
            DEFAULT_TIMEOUT,
            DEFAULT_CONNECT_TIMEOUT,
            Some(Arc::new(LoopbackDns)),
        )
        .unwrap()
        .allow_insecure_http(true);
        let name = AgentName::parse(&format!("http://names.example.com:{port}/@alice")).unwrap();
        let err = resolver.resolve_inner(&name).await.unwrap_err();
        assert!(
            matches!(&err, AgentNameError::BlockedAddress { address, .. } if address == "127.0.0.1"),
            "got {err:?}"
        );
    }

    async fn resolve_slow_name(resolver: HttpRedirectResolver) -> Result<String, AgentNameError> {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::path("/@alice"))
            .respond_with(
                wiremock::ResponseTemplate::new(302)
                    .insert_header("location", "did:web:example.com")
                    .set_delay(Duration::from_millis(500)),
            )
            .mount(&server)
            .await;
        let name = AgentName::parse(&format!("{}/@alice", server.uri())).unwrap();
        resolver
            .allow_insecure_http(true)
            .allow_private_addresses(true)
            .resolve_inner(&name)
            .await
    }

    #[tokio::test]
    async fn with_client_builder_and_timeouts_applies_the_given_timeout() {
        let resolver = HttpRedirectResolver::with_client_builder_and_timeouts(
            reqwest::Client::builder(),
            Duration::from_millis(50),
            DEFAULT_CONNECT_TIMEOUT,
        )
        .unwrap();
        let err = resolve_slow_name(resolver).await.unwrap_err();
        assert!(
            matches!(&err, AgentNameError::Http(e) if e.is_timeout()),
            "got {err:?}"
        );
    }

    /// The documented behaviour: `with_client_builder` replaces a timeout set
    /// on the caller's builder with the finite defaults.
    #[tokio::test]
    async fn with_client_builder_replaces_the_builders_timeout_with_the_default() {
        let resolver = HttpRedirectResolver::with_client_builder(
            reqwest::Client::builder().timeout(Duration::from_millis(50)),
        )
        .unwrap();
        assert_eq!(
            resolve_slow_name(resolver).await.unwrap(),
            "did:web:example.com"
        );
    }

    #[test]
    fn resolver_reports_its_name() {
        assert_eq!(HttpRedirectResolver::new().name(), "http-redirect");
    }
}
