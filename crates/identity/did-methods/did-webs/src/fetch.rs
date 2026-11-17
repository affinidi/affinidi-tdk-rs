//! Fetching the two artifacts a `did:webs` identifier publishes.
//!
//! Both are fetched, and both are needed for different reasons: `keri.cesr`
//! is the only thing that carries authority, and `did.json` is what the
//! verified key state is checked against. § Read fails a resolution when
//! either cannot be fetched: a host serving a log but no document has not
//! published the DID completely, and quietly accepting that would make the
//! cross-check optional for whoever controls the host.

use std::sync::LazyLock;
use std::time::Duration;

use affinidi_did_common::Document;
use affinidi_net_guard::EgressPolicy;
use tokio::sync::Semaphore;
use tracing::{debug, warn};

use crate::errors::DidWebsError;
use crate::identifier::{DID_JSON, DidWebs, KERI_CESR};
use crate::resolver::{Resolution, resolve_with_metadata};

/// Default request timeout, matching the in-tree `did:web` resolver.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(20);

/// Largest artifact this resolver will read.
///
/// A KEL grows with every rotation and interaction, so it has no natural
/// bound, and the server is not trusted. Without a cap a resolution can be
/// turned into unbounded memory use by anyone who can serve a URL.
pub const MAX_ARTIFACT_BYTES: usize = 4 * 1024 * 1024;

/// Which hosts resolution may fetch from.
///
/// A `did:webs` identifier names its own host, so a DID an attacker supplies
/// can aim the resolver at loopback, a private network or a cloud-metadata
/// address (SSRF), unless the resolver refuses to go there.
///
/// A shorthand for the two common cases. For anything in between (an operator
/// allow-list, named private ranges) build an [`EgressPolicy`] and use
/// [`WebsResolver::with_egress_policy`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum HostPolicy {
    /// Fetch only from globally routable addresses. Refuses loopback,
    /// private, carrier-grade NAT and link-local addresses, and special-use
    /// names such as `localhost`, `*.local`, `*.internal` and single-label
    /// names. That covers both a host the DID names as a literal and a
    /// hostname that *resolves* to such an address, checked at connect time
    /// so a DNS answer cannot change between the check and the connection.
    /// The rules are `affinidi-net-guard`'s `EgressPolicy::public_internet`.
    /// The default.
    #[default]
    PublicOnly,
    /// Fetch from any host, including loopback and private ones, and over
    /// plain HTTP from a loopback host.
    ///
    /// This reopens the SSRF exposure [`HostPolicy::PublicOnly`] closes, so
    /// choose it only where the DIDs themselves are trusted, such as a
    /// local development or test stack or an internal deployment.
    AllowPrivate,
}

impl HostPolicy {
    /// The egress policy this shorthand stands for: `None` for
    /// [`HostPolicy::AllowPrivate`], which applies none.
    pub fn egress_policy(self) -> Option<EgressPolicy> {
        match self {
            HostPolicy::AllowPrivate => None,
            _ => Some(EgressPolicy::public_internet()),
        }
    }
}

/// A `did:webs` resolver holding a reusable HTTP client.
///
/// Resolution fetches two artifacts from the same host, so sharing a client —
/// and its connection pool — across them and across calls is worth doing.
///
/// Redirects are never followed by the client this builds: the DID names the
/// host, and a redirect would let that host send the resolver anywhere.
#[derive(Debug, Clone)]
pub struct WebsResolver {
    client: reqwest::Client,
    allow_http: bool,
    /// What every fetch is vetted against, before the request (the host as
    /// written) and at connect time (what a name resolves to). `None` under
    /// [`HostPolicy::AllowPrivate`].
    egress: Option<EgressPolicy>,
}

impl WebsResolver {
    /// A resolver with the default client, under [`HostPolicy::PublicOnly`].
    pub fn new() -> Self {
        Self::with_policy(HostPolicy::PublicOnly)
    }

    /// A resolver with the default client, under an explicit [`HostPolicy`].
    ///
    /// # Panics
    /// If the HTTP client cannot be built (the TLS backend fails to
    /// initialise), as `reqwest::Client::new` does.
    pub fn with_policy(policy: HostPolicy) -> Self {
        Self::with_client_builder(reqwest::Client::builder(), policy)
            .expect("the did:webs HTTP client can be built")
    }

    /// A resolver over a client the caller configures (TLS, headers,
    /// connection pool), under an explicit [`HostPolicy`].
    ///
    /// The request timeout is set to [`DEFAULT_TIMEOUT`] and the user agent
    /// to this crate's, replacing any set on `builder`; to choose the timeout,
    /// use [`WebsResolver::with_client_builder_and_timeout`], and to keep the
    /// builder's own timeout and user agent, [`WebsResolver::with_egress_policy`].
    ///
    /// The guard settings are applied last, so nothing set on `builder` can
    /// undo them: redirects are never followed, and under
    /// [`HostPolicy::PublicOnly`] the guarded DNS resolver is installed and
    /// every proxy, including one named by `HTTPS_PROXY`, is turned off,
    /// because a proxy resolves the hostname itself and the DNS check would
    /// never see it.
    ///
    /// # Errors
    /// Returns [`DidWebsError::Fetch`] if `reqwest` cannot build the client.
    pub fn with_client_builder(
        builder: reqwest::ClientBuilder,
        policy: HostPolicy,
    ) -> Result<Self, DidWebsError> {
        Self::with_client_builder_and_timeout(builder, policy, DEFAULT_TIMEOUT)
    }

    /// As [`WebsResolver::with_client_builder`], with `timeout` as the
    /// request timeout.
    ///
    /// # Errors
    /// Returns [`DidWebsError::Fetch`] if `reqwest` cannot build the client.
    pub fn with_client_builder_and_timeout(
        builder: reqwest::ClientBuilder,
        policy: HostPolicy,
        timeout: Duration,
    ) -> Result<Self, DidWebsError> {
        if policy == HostPolicy::AllowPrivate {
            warn!(
                "did:webs resolver built with HostPolicy::AllowPrivate: it will fetch from \
                 loopback and private hosts, so SSRF protection is off. Use it only where the \
                 DIDs resolved are trusted."
            );
        }
        Self::build(default_settings(builder, timeout), policy.egress_policy())
    }

    /// A resolver over a client the caller configures, fetching only what
    /// `policy` admits: each artifact URL is vetted with
    /// [`EgressPolicy::vet_url`] before any request (in its `https` form; see
    /// [`WebsResolver::allow_http`]), and every address a hostname resolves to
    /// is vetted at connect time by `affinidi_net_guard::guarded_dns_resolver`
    /// under the same policy. A loopback host is fetched over plain HTTP when
    /// the policy admits loopback (`EgressPolicy::with_dev_loopback`).
    ///
    /// Use it for what [`HostPolicy`] cannot express, such as an operator
    /// allow-list (`EgressPolicy::with_allow_list`) or named private ranges
    /// (`EgressPolicy::allow_cidrs`).
    ///
    /// Only the guard settings are applied: redirects are never followed and
    /// proxies are turned off. The builder's own request timeout and user
    /// agent are kept, and `reqwest` sets neither by default, so set a
    /// timeout on `builder` (for example [`DEFAULT_TIMEOUT`]).
    ///
    /// # Errors
    /// Returns [`DidWebsError::Fetch`] if `reqwest` cannot build the client.
    pub fn with_egress_policy(
        builder: reqwest::ClientBuilder,
        policy: EgressPolicy,
    ) -> Result<Self, DidWebsError> {
        Self::build(builder, Some(policy))
    }

    fn build(
        builder: reqwest::ClientBuilder,
        egress: Option<EgressPolicy>,
    ) -> Result<Self, DidWebsError> {
        let client = guard(builder, egress.as_ref())
            .build()
            .map_err(|e| DidWebsError::Fetch {
                url: String::new(),
                reason: format!("cannot build the HTTP client: {e}"),
            })?;
        Ok(Self {
            client,
            allow_http: false,
            egress,
        })
    }

    /// A resolver over a caller-built client, under
    /// [`HostPolicy::PublicOnly`].
    ///
    /// Only the host the DID names is checked. A built client cannot be
    /// inspected or changed, so a hostname that resolves to a private
    /// address, a redirect, or a proxy is stopped only if the caller built the
    /// client to stop it.
    #[deprecated(
        since = "0.8.2",
        note = "a built client may not carry the DNS guard; use `with_client_builder`, which applies it"
    )]
    pub fn with_client(client: reqwest::Client) -> Self {
        Self {
            client,
            allow_http: false,
            egress: HostPolicy::PublicOnly.egress_policy(),
        }
    }

    /// Permit plain HTTP for **any** host, not just loopback.
    ///
    /// Off by default, and it should stay off in production. A `did:webs`
    /// document is derived from a self-verifying key event log, so an attacker
    /// on the network cannot forge one — but they can serve a *stale* log,
    /// hiding a key rotation that has already happened, which is exactly the
    /// attack pre-rotation exists to defeat.
    ///
    /// It exists because the reference implementation
    /// (`hyperledger-labs/did-webs-resolver`) fetches over plain HTTP, so
    /// interoperating with it — or with any KERI tooling on a private network
    /// without TLS — otherwise cannot work at all.
    pub fn allow_http(mut self, allow: bool) -> Self {
        self.allow_http = allow;
        self
    }

    /// The scheme to fetch this DID's artifacts over.
    ///
    /// A loopback host is fetched over plain HTTP only where loopback is
    /// reachable at all: under [`HostPolicy::AllowPrivate`], or an egress
    /// policy that admits loopback.
    fn scheme(&self, did: &DidWebs) -> &'static str {
        let loopback_reachable = self
            .egress
            .as_ref()
            .is_none_or(EgressPolicy::is_dev_loopback);
        if self.allow_http || (loopback_reachable && did.is_loopback()) {
            "http"
        } else {
            "https"
        }
    }

    /// Resolve a `did:webs` identifier.
    ///
    /// # Errors
    /// Returns [`DidWebsError`] if the DID is malformed, either artifact cannot
    /// be fetched, the key event log does not verify, the DID is not
    /// designated by its AID, or the published `did.json` disagrees with the
    /// verified state; [`DidWebsError::Deactivated`] if the identifier is
    /// deactivated, which
    /// [`resolve_with_metadata`](Self::resolve_with_metadata) reports in the
    /// metadata instead.
    pub async fn resolve(&self, did: &str) -> Result<Document, DidWebsError> {
        self.resolve_with_metadata(did).await?.into_document()
    }

    /// Resolve a `did:webs` identifier, with its DID document metadata. A DID
    /// URL with a `versionId` parameter resolves as of that key event. A
    /// deactivated identifier resolves as
    /// [`crate::resolve_with_metadata`] describes.
    ///
    /// Verifying the fetched stream is CPU work, so it runs on the blocking
    /// thread pool rather than the async executor, and no more streams are
    /// verified at once, across the process, than there are CPUs available.
    ///
    /// # Errors
    /// As [`resolve`](Self::resolve), except that a deactivated identifier is
    /// not an error.
    pub async fn resolve_with_metadata(&self, did: &str) -> Result<Resolution, DidWebsError> {
        self.resolve_parsed(DidWebs::parse(did)?).await
    }

    /// Resolve an already parsed identifier, as
    /// [`resolve_with_metadata`](Self::resolve_with_metadata).
    async fn resolve_parsed(&self, parsed: DidWebs) -> Result<Resolution, DidWebsError> {
        let scheme = self.scheme(&parsed);

        let cesr_url = parsed.artifact_url_with_scheme(scheme, KERI_CESR);
        let did_json_url = parsed.artifact_url_with_scheme(scheme, DID_JSON);
        let keri_cesr = self.fetch(&cesr_url).await?;
        let did_json = self.fetch(&did_json_url).await?;
        debug!("fetched {cesr_url} and {did_json_url}");

        verify_off_executor(parsed, keri_cesr, did_json).await
    }

    /// Fetch one artifact, refusing anything larger than [`MAX_ARTIFACT_BYTES`].
    async fn fetch(&self, url: &str) -> Result<Vec<u8>, DidWebsError> {
        let parsed = reqwest::Url::parse(url).map_err(|e| DidWebsError::Fetch {
            url: url.to_string(),
            reason: format!("not a valid URL: {e}"),
        })?;
        if let Some(policy) = &self.egress {
            vet(policy, &parsed)?;
        }

        let response = self.client.get(parsed).send().await.map_err(|e| {
            match affinidi_net_guard::blocked_in_chain(&e) {
                Some(refusal) => DidWebsError::BlockedHost(refusal.to_string()),
                None => DidWebsError::Fetch {
                    url: url.to_string(),
                    reason: e.to_string(),
                },
            }
        })?;

        let status = response.status();
        if !status.is_success() {
            let retry_after = response
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|value| value.to_str().ok());
            return Err(DidWebsError::Network(
                affinidi_did_common::NetworkError::new(format!("HTTP {status}"))
                    .with_url(url)
                    .with_status(status.as_u16())
                    .with_retry_after_header(retry_after),
            ));
        }

        read_capped(response, url, MAX_ARTIFACT_BYTES).await
    }
}

/// Read a response body, refusing one larger than `cap` bytes.
///
/// The advertised `Content-Length` is checked before reading, so a body that
/// declares itself too large is refused without being read. The body is then
/// read chunk by chunk and counted as it arrives, so a body sent without a
/// `Content-Length`, or with one smaller than the body, stops being read as
/// soon as it passes the cap.
async fn read_capped(
    mut response: reqwest::Response,
    url: &str,
    cap: usize,
) -> Result<Vec<u8>, DidWebsError> {
    if let Some(len) = response.content_length()
        && len > cap as u64
    {
        return Err(DidWebsError::Fetch {
            url: url.to_string(),
            reason: format!("artifact declares {len} bytes, over the {cap} cap"),
        });
    }

    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|e| DidWebsError::Fetch {
        url: url.to_string(),
        reason: e.to_string(),
    })? {
        if body.len() + chunk.len() > cap {
            return Err(DidWebsError::Fetch {
                url: url.to_string(),
                reason: format!("artifact is over the {cap} cap"),
            });
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// Check the URL's host, port and userinfo under `policy`, before any request
/// is made.
///
/// This half sees literal addresses, which never reach a DNS resolver. The
/// URL is checked in its `https` form, because the scheme is not what this
/// guards: `affinidi-net-guard` admits plain HTTP only for loopback, while
/// [`WebsResolver::allow_http`] is an explicit choice to fetch public hosts
/// over HTTP.
fn vet(policy: &EgressPolicy, url: &reqwest::Url) -> Result<(), DidWebsError> {
    let mut https = url.clone();
    if https.scheme() != "https" && https.set_scheme("https").is_err() {
        return Err(DidWebsError::BlockedHost(format!(
            "{url} cannot be checked as an https URL"
        )));
    }
    policy
        .vet_url(&https)
        .map(|_| ())
        .map_err(|e| DidWebsError::BlockedHost(e.to_string()))
}

/// The user agent and request timeout. They replace any the caller's
/// builder set; the guard settings are applied after them.
fn default_settings(builder: reqwest::ClientBuilder, timeout: Duration) -> reqwest::ClientBuilder {
    builder
        .user_agent(concat!("affinidi-did-webs/", env!("CARGO_PKG_VERSION")))
        .timeout(timeout)
}

/// The guard settings. Applied last, so nothing set before can undo them.
fn guard(builder: reqwest::ClientBuilder, egress: Option<&EgressPolicy>) -> reqwest::ClientBuilder {
    // The DID names the host. Following a redirect lets that host send the
    // resolver to an internal address the literal check never saw.
    let builder = builder
        .redirect(reqwest::redirect::Policy::none())
        .referer(false);
    match egress {
        None => builder,
        // A proxy resolves the hostname itself, so the guarded resolver would
        // see only the proxy's name.
        Some(policy) => builder
            .dns_resolver(affinidi_net_guard::guarded_dns_resolver(policy.clone()))
            .no_proxy(),
    }
}

/// did:webs as an `affinidi-did-resolver-traits`
/// [`AsyncResolver`](affinidi_did_resolver_traits::AsyncResolver).
#[cfg(feature = "resolver-traits")]
mod resolver_impl {
    use std::future::Future;
    use std::pin::Pin;

    use affinidi_did_common::{DID, DIDMethod};
    use affinidi_did_resolver_traits::{AsyncResolver, Resolution, ResolverError};

    use super::WebsResolver;
    use crate::{DidWebs, DidWebsError};

    /// The [`ResolverError`] for a failed did:webs resolution: a failed fetch
    /// (with its URL, status and `Retry-After` when the host answered) is
    /// [`ResolverError::NetworkFetch`], everything else
    /// [`ResolverError::ResolutionFailed`].
    pub(crate) fn resolver_error(err: DidWebsError) -> ResolverError {
        match err.network_error() {
            Some(network) => ResolverError::from(network),
            None => ResolverError::ResolutionFailed(err.to_string()),
        }
    }

    /// Resolves did:webs under the resolver's host policy, and declines
    /// (`None`) every other method. A `versionId` DID parameter resolves as
    /// of that key event; a deactivated identifier is an error, as
    /// [`WebsResolver::resolve`] reports it.
    impl AsyncResolver for WebsResolver {
        fn name(&self) -> &str {
            "WebsResolver"
        }

        fn resolve<'a>(
            &'a self,
            did: &'a DID,
        ) -> Pin<Box<dyn Future<Output = Resolution> + Send + 'a>> {
            Box::pin(async move {
                if !matches!(did.method_ref(), DIDMethod::Webs { .. }) {
                    return None;
                }
                let resolution = match DidWebs::from_did(did) {
                    Ok(parsed) => self.resolve_parsed(parsed).await,
                    Err(e) => Err(e),
                };
                Some(
                    resolution
                        .and_then(super::Resolution::into_document)
                        .map_err(resolver_error),
                )
            })
        }
    }
}

impl Default for WebsResolver {
    fn default() -> Self {
        Self::new()
    }
}

/// Resolve a `did:webs` identifier with a one-off client.
///
/// Prefer [`WebsResolver`] when resolving more than once, so the connection
/// pool is reused.
///
/// # Errors
/// See [`WebsResolver::resolve`].
pub async fn resolve(did: &str) -> Result<Document, DidWebsError> {
    WebsResolver::new().resolve(did).await
}

/// How many fetched streams may be verified at once, across every
/// [`WebsResolver`] in the process: the number of CPUs available, at least
/// one.
fn concurrent_verifications() -> usize {
    std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get)
}

/// Permits for [`verify_off_executor`], [`concurrent_verifications`] of them.
static VERIFICATIONS: LazyLock<Semaphore> =
    LazyLock::new(|| Semaphore::new(concurrent_verifications()));

/// Verify fetched artifacts on the blocking thread pool, under
/// [`run_bounded`].
async fn verify_off_executor(
    did: DidWebs,
    keri_cesr: Vec<u8>,
    did_json: Vec<u8>,
) -> Result<Resolution, DidWebsError> {
    run_bounded(move || resolve_with_metadata(&did, &keri_cesr, Some(&did_json))).await?
}

/// Run `work` on the blocking thread pool once a permit is free, so that a
/// large stream occupies a blocking thread rather than an executor thread,
/// and only so many run at once.
///
/// The permit moves into the blocking task and is released when `work`
/// ends, not when the caller stops waiting: a caller that times out or is
/// dropped leaves `work` running, and it still counts against the bound.
async fn run_bounded<T, F>(work: F) -> Result<T, DidWebsError>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    let permit = VERIFICATIONS
        .acquire()
        .await
        .map_err(|e| DidWebsError::Stream(format!("verification unavailable: {e}")))?;
    let verification = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        work()
    })
    .await;
    match verification {
        Ok(result) => Ok(result),
        Err(e) if e.is_panic() => std::panic::resume_unwind(e.into_panic()),
        Err(e) => Err(DidWebsError::Stream(format!(
            "verification did not complete: {e}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Wait on the blocking pool, so the executor keeps running.
    async fn blocking_sleep(millis: u64) {
        tokio::task::spawn_blocking(move || {
            std::thread::sleep(std::time::Duration::from_millis(millis))
        })
        .await
        .expect("sleeps");
    }

    /// `with_egress_policy` keeps the caller's timeout and user agent
    /// (#1154). The client is driven directly at a loopback literal, which
    /// the connect-time guard never sees (no name is resolved).
    #[tokio::test]
    async fn an_egress_policy_resolver_keeps_the_builders_timeout_and_user_agent() {
        use wiremock::matchers::{header, method};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(header("user-agent", "caller/1.0"))
            .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(10)))
            .mount(&server)
            .await;
        let resolver = WebsResolver::with_egress_policy(
            reqwest::Client::builder()
                .user_agent("caller/1.0")
                .timeout(Duration::from_millis(200)),
            EgressPolicy::public_internet(),
        )
        .expect("builds");
        let started = std::time::Instant::now();
        let err = resolver
            .client
            .get(server.uri())
            .send()
            .await
            .expect_err("the caller's 200 ms timeout applies");
        assert!(err.is_timeout(), "{err:?}");
        assert!(started.elapsed() < Duration::from_secs(5));
        // The request reached the mock only because it carried the caller's
        // user agent; a mismatch would have been answered 404 at once.
        assert_eq!(server.received_requests().await.expect("recorded").len(), 1);
    }

    #[tokio::test]
    async fn an_egress_policy_allow_list_is_enforced_before_any_request() {
        use affinidi_net_guard::{AllowList, HostRule};

        let policy = EgressPolicy::public_internet().with_allow_list(
            AllowList::new([HostRule::Exact("only.example".into())]).expect("valid"),
        );
        let resolver = WebsResolver::with_egress_policy(
            reqwest::Client::builder().timeout(Duration::from_secs(5)),
            policy,
        )
        .expect("builds");
        let err = resolver
            .resolve("did:webs:example.com:ENro7uf0ePmiK3jdTo2YCdXLqW7z7xoP6qhhBou6gBLe")
            .await
            .expect_err("example.com is not on the allow-list");
        assert!(matches!(err, DidWebsError::BlockedHost(_)), "{err:?}");
    }

    #[test]
    fn host_policy_maps_onto_an_egress_policy() {
        assert!(HostPolicy::AllowPrivate.egress_policy().is_none());
        let public = HostPolicy::PublicOnly.egress_policy().expect("a policy");
        assert!(!public.is_dev_loopback());
        assert!(public.vet("https://localhost/x").is_err());
    }

    #[cfg(feature = "resolver-traits")]
    #[tokio::test]
    async fn the_resolver_trait_declines_other_methods_and_keeps_fetch_failures() {
        use affinidi_did_common::DID;
        use affinidi_did_resolver_traits::{AsyncResolver, ResolverError};
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let resolver = WebsResolver::with_policy(HostPolicy::AllowPrivate);
        assert_eq!(AsyncResolver::name(&resolver), "WebsResolver");
        let web: DID = "did:web:example.com".parse().expect("valid");
        assert!(AsyncResolver::resolve(&resolver, &web).await.is_none());

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(429).insert_header("Retry-After", "7"))
            .mount(&server)
            .await;
        let did: DID = format!(
            "did:webs:{}:ENro7uf0ePmiK3jdTo2YCdXLqW7z7xoP6qhhBou6gBLe",
            server.address().to_string().replace(':', "%3A")
        )
        .parse()
        .expect("valid");
        let Some(Err(ResolverError::NetworkFetch(fetch))) =
            AsyncResolver::resolve(&resolver, &did).await
        else {
            panic!("a 429 is a network fetch failure");
        };
        assert!(fetch.is_rate_limited());
        assert_eq!(fetch.retry_after, Some(Duration::from_secs(7)));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_dropped_caller_keeps_the_permit_until_the_work_ends() {
        let total = concurrent_verifications();
        let (started_tx, started_rx) = std::sync::mpsc::channel::<()>();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();

        let caller = tokio::spawn(run_bounded(move || {
            started_tx.send(()).expect("signals");
            release_rx.recv().ok();
        }));
        tokio::task::spawn_blocking(move || started_rx.recv())
            .await
            .expect("joins")
            .expect("the work started");

        caller.abort();
        assert!(caller.await.is_err(), "the caller was dropped");
        blocking_sleep(20).await;
        assert_eq!(
            VERIFICATIONS.available_permits(),
            total - 1,
            "the running work still holds its permit"
        );

        release_tx.send(()).expect("releases");
        for _ in 0..500 {
            if VERIFICATIONS.available_permits() == total {
                return;
            }
            blocking_sleep(10).await;
        }
        panic!("the permit was not returned when the work ended");
    }
}
