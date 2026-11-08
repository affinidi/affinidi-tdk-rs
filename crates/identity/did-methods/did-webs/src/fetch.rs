//! Fetching the two artifacts a `did:webs` identifier publishes.
//!
//! Both are fetched, and both are needed for different reasons: `keri.cesr`
//! is the only thing that carries authority, and `did.json` is what the
//! verified key state is checked against. § Read fails a resolution when
//! either cannot be fetched: a host serving a log but no document has not
//! published the DID completely, and quietly accepting that would make the
//! cross-check optional for whoever controls the host.

use std::time::Duration;

use affinidi_did_common::Document;
use tracing::debug;

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
    policy: HostPolicy,
}

impl WebsResolver {
    /// A resolver with the default client, under [`HostPolicy::PublicOnly`].
    pub fn new() -> Self {
        Self::with_policy(HostPolicy::PublicOnly)
    }

    /// A resolver with the default client, under an explicit [`HostPolicy`].
    pub fn with_policy(policy: HostPolicy) -> Self {
        Self {
            client: default_client(policy),
            allow_http: false,
            policy,
        }
    }

    /// A resolver over a caller-supplied client, for custom timeouts, proxies,
    /// or a client shared with the rest of an application, under
    /// [`HostPolicy::PublicOnly`].
    ///
    /// The host the DID names is still checked before any request. The other
    /// half of the guard, a hostname that resolves to a non-routable address,
    /// lives in the client's DNS resolver, so a caller supplying a client owns
    /// it: install `affinidi_net_guard::guarded_dns_resolver`, and disable
    /// redirects.
    pub fn with_client(client: reqwest::Client) -> Self {
        Self::with_client_and_policy(client, HostPolicy::PublicOnly)
    }

    /// A resolver over a caller-supplied client under an explicit
    /// [`HostPolicy`]. Same caveat as [`with_client`](Self::with_client).
    pub fn with_client_and_policy(client: reqwest::Client, policy: HostPolicy) -> Self {
        Self {
            client,
            allow_http: false,
            policy,
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
    /// reachable at all, under [`HostPolicy::AllowPrivate`].
    fn scheme(&self, did: &DidWebs) -> &'static str {
        if self.allow_http || (self.policy == HostPolicy::AllowPrivate && did.is_loopback()) {
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
    /// verified state.
    pub async fn resolve(&self, did: &str) -> Result<Document, DidWebsError> {
        self.resolve_with_metadata(did).await.map(|r| r.document)
    }

    /// Resolve a `did:webs` identifier, with its DID document metadata. A DID
    /// URL with a `versionId` parameter resolves as of that key event.
    ///
    /// # Errors
    /// As [`resolve`](Self::resolve).
    pub async fn resolve_with_metadata(&self, did: &str) -> Result<Resolution, DidWebsError> {
        let parsed = DidWebs::parse(did)?;
        let scheme = self.scheme(&parsed);

        let cesr_url = parsed.artifact_url_with_scheme(scheme, KERI_CESR);
        let did_json_url = parsed.artifact_url_with_scheme(scheme, DID_JSON);
        let keri_cesr = self.fetch(&cesr_url).await?;
        let did_json = self.fetch(&did_json_url).await?;
        debug!("fetched {cesr_url} and {did_json_url}");

        resolve_with_metadata(&parsed, &keri_cesr, Some(&did_json))
    }

    /// Fetch one artifact, refusing anything larger than [`MAX_ARTIFACT_BYTES`].
    async fn fetch(&self, url: &str) -> Result<Vec<u8>, DidWebsError> {
        let parsed = reqwest::Url::parse(url).map_err(|e| DidWebsError::Fetch {
            url: url.to_string(),
            reason: format!("not a valid URL: {e}"),
        })?;
        if self.policy == HostPolicy::PublicOnly {
            vet_public(&parsed)?;
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

        if !response.status().is_success() {
            return Err(DidWebsError::Fetch {
                url: url.to_string(),
                reason: format!("HTTP {}", response.status()),
            });
        }

        // Check the advertised length first so an oversized body is refused
        // before it is read, then check again while reading: `Content-Length`
        // is the server's claim, not a fact.
        if let Some(len) = response.content_length()
            && len > MAX_ARTIFACT_BYTES as u64
        {
            return Err(DidWebsError::Fetch {
                url: url.to_string(),
                reason: format!("artifact declares {len} bytes, over the {MAX_ARTIFACT_BYTES} cap"),
            });
        }

        let bytes = response.bytes().await.map_err(|e| DidWebsError::Fetch {
            url: url.to_string(),
            reason: e.to_string(),
        })?;

        if bytes.len() > MAX_ARTIFACT_BYTES {
            return Err(DidWebsError::Fetch {
                url: url.to_string(),
                reason: format!(
                    "artifact is {} bytes, over the {MAX_ARTIFACT_BYTES} cap",
                    bytes.len()
                ),
            });
        }

        Ok(bytes.to_vec())
    }
}

/// Check the URL's host, port and userinfo under
/// `EgressPolicy::public_internet`, before any request is made.
///
/// This half sees literal addresses, which never reach a DNS resolver. The
/// URL is checked in its `https` form, because the scheme is not what this
/// guards: `affinidi-net-guard` admits plain HTTP only for loopback, while
/// [`WebsResolver::allow_http`] is an explicit choice to fetch public hosts
/// over HTTP.
fn vet_public(url: &reqwest::Url) -> Result<(), DidWebsError> {
    let mut https = url.clone();
    if https.scheme() != "https" && https.set_scheme("https").is_err() {
        return Err(DidWebsError::BlockedHost(format!(
            "{url} cannot be checked as an https URL"
        )));
    }
    affinidi_net_guard::EgressPolicy::public_internet()
        .vet_url(&https)
        .map(|_| ())
        .map_err(|e| DidWebsError::BlockedHost(e.to_string()))
}

/// The HTTP client [`WebsResolver::with_policy`] builds.
fn default_client(policy: HostPolicy) -> reqwest::Client {
    let mut builder = reqwest::Client::builder()
        .user_agent(concat!("affinidi-did-webs/", env!("CARGO_PKG_VERSION")))
        .timeout(DEFAULT_TIMEOUT)
        // The DID names the host. Following a redirect lets that host send
        // the resolver to an internal address the literal check never saw.
        .redirect(reqwest::redirect::Policy::none());
    if policy == HostPolicy::PublicOnly {
        builder = builder.dns_resolver(affinidi_net_guard::guarded_dns_resolver(
            affinidi_net_guard::EgressPolicy::public_internet(),
        ));
    }
    builder.build().unwrap_or_default()
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
