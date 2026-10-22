//! Network DID method resolvers implementing [`AsyncResolver`].
//!
//! Each struct wraps an external resolver crate and normalizes its interface
//! into the uniform `AsyncResolver` contract. Feature-gated resolvers are
//! conditionally compiled.

use std::future::Future;
use std::pin::Pin;

use affinidi_did_common::{DID, DIDMethod};
use affinidi_did_resolver_traits::{AsyncResolver, NetworkFetchError, Resolution, ResolverError};
pub use affinidi_did_web::HostPolicy;
use tracing::error;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Keep the HTTP status of a failed did:webvh fetch as data rather than text.
///
/// `didwebvh-rs` reports a failure to read or decode the body with the `200` it
/// had already received. That status did not cause the failure, so it is not
/// recorded: `status` means "the host answered with this unsuccessful status".
#[cfg(any(feature = "did-webvh", feature = "did-scid"))]
fn webvh_network_error(url: String, status_code: Option<u16>, message: String) -> ResolverError {
    let mut fetch = NetworkFetchError::new(message);
    if !url.is_empty() {
        fetch = fetch.with_url(url);
    }
    if let Some(status) = status_code.filter(|status| !(200..300).contains(status)) {
        fetch = fetch.with_status(status);
    }
    ResolverError::NetworkFetch(fetch)
}

/// The error for a did:webvh whose log ends in a deactivation.
///
/// `didwebvh-rs` resolves a cleanly deactivated DID `Ok`, as DID Resolution
/// says it should: the last document comes back unchanged, keys and all, and
/// only `MetaData::deactivated` says it is retired. The resolver contract here
/// returns a bare `Document`, so a caller has nowhere to see that flag — a
/// retired DID would go on authenticating and verifying signatures with its
/// last keys. Refusing it matches `did:web`, whose deactivation is a 404.
#[cfg(feature = "did-webvh")]
pub(crate) fn webvh_deactivated(did: &str) -> didwebvh_rs::DIDWebVHError {
    didwebvh_rs::DIDWebVHError::DeactivatedError(format!("{did} has been deactivated"))
}

fn did_web_error(err: affinidi_did_web::DidWebError) -> ResolverError {
    match err {
        affinidi_did_web::DidWebError::ResolutionFailed { status, url, .. } => {
            ResolverError::NetworkFetch(
                NetworkFetchError::new(format!("HTTP {status}"))
                    .with_url(url)
                    .with_status(status),
            )
        }
        affinidi_did_web::DidWebError::Http(message) => {
            ResolverError::NetworkFetch(NetworkFetchError::new(message))
        }
        other => ResolverError::ResolutionFailed(other.to_string()),
    }
}

// ---------------------------------------------------------------------------
// did:ethr
// ---------------------------------------------------------------------------

/// Resolver for `did:ethr` — Ethereum DID method.
///
/// Resolution is an offline derivation from the identifier: this does not
/// replay ERC-1056 registry events, so the document is the DID's genesis state.
#[cfg(feature = "did-ethr")]
pub struct EthrResolver;

#[cfg(feature = "did-ethr")]
impl AsyncResolver for EthrResolver {
    fn name(&self) -> &str {
        "EthrResolver"
    }

    fn resolve<'a>(
        &'a self,
        did: &'a DID,
    ) -> Pin<Box<dyn Future<Output = Resolution> + Send + 'a>> {
        Box::pin(async move {
            let identifier = match did.method() {
                DIDMethod::Ethr { identifier, .. } => identifier,
                _ => return None,
            };

            Some(
                affinidi_did_ethr::resolve_identifier(&identifier).map_err(|e| {
                    error!("did:ethr resolution error: {e:?}");
                    ResolverError::ResolutionFailed(e.to_string())
                }),
            )
        })
    }
}

// ---------------------------------------------------------------------------
// did:pkh
// ---------------------------------------------------------------------------

/// Resolver for `did:pkh` — PKH (Public Key Hash) DID method.
#[cfg(feature = "did-pkh")]
pub struct PkhResolver;

#[cfg(feature = "did-pkh")]
impl AsyncResolver for PkhResolver {
    fn name(&self) -> &str {
        "PkhResolver"
    }

    fn resolve<'a>(
        &'a self,
        did: &'a DID,
    ) -> Pin<Box<dyn Future<Output = Resolution> + Send + 'a>> {
        Box::pin(async move {
            let identifier = match did.method() {
                DIDMethod::Pkh { identifier, .. } => identifier,
                _ => return None,
            };

            Some(
                affinidi_did_pkh::resolve_identifier(&identifier).map_err(|e| {
                    error!("did:pkh resolution error: {e:?}");
                    ResolverError::ResolutionFailed(e.to_string())
                }),
            )
        })
    }
}

// ---------------------------------------------------------------------------
// did:web
// ---------------------------------------------------------------------------

/// Resolver for `did:web` — Web DID method.
///
/// Backed by [`affinidi_did_web`], which sits on `reqwest 0.13` / `rustls 0.23`
/// instead of the spruceid `did-web` crate's `reqwest 0.11` / `rustls 0.21`
/// stack — clearing the rustls-webpki advisories that previously came in
/// transitively through this resolver.
///
/// A `did:web` value names the host to fetch from, so by default this refuses
/// non-routable targets — see [`HostPolicy`]. A deployment whose did:web hosts
/// really do live on an internal network (or a local test stack using
/// `did:web:localhost%3A8080`) opts out with [`WebResolver::with_policy`] and
/// installs it via [`crate::DIDCacheClient::set_resolver`].
pub struct WebResolver {
    inner: affinidi_did_web::DIDWeb,
}

impl WebResolver {
    /// Create a resolver with the default HTTP client, refusing non-routable
    /// hosts.
    pub fn new() -> Self {
        Self::with_policy(HostPolicy::PublicOnly)
    }

    /// Create a resolver with the default HTTP client under an explicit
    /// [`HostPolicy`].
    pub fn with_policy(policy: HostPolicy) -> Self {
        Self {
            inner: affinidi_did_web::DIDWeb::with_policy(policy),
        }
    }
}

impl Default for WebResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl AsyncResolver for WebResolver {
    fn name(&self) -> &str {
        "WebResolver"
    }

    fn resolve<'a>(
        &'a self,
        did: &'a DID,
    ) -> Pin<Box<dyn Future<Output = Resolution> + Send + 'a>> {
        Box::pin(async move {
            if !matches!(did.method(), DIDMethod::Web { .. }) {
                return None;
            }

            let did_str = did.to_string();
            Some(match self.inner.resolve(&did_str).await {
                Ok(doc) => Ok(doc),
                Err(e) => {
                    error!("did:web resolution error: {e:?}");
                    Err(did_web_error(e))
                }
            })
        })
    }
}

// ---------------------------------------------------------------------------
// did:jwk (feature-gated)
// ---------------------------------------------------------------------------

/// Resolver for `did:jwk` — JSON Web Key DID method.
#[cfg(feature = "did-jwk")]
pub struct JwkResolver;

#[cfg(feature = "did-jwk")]
impl AsyncResolver for JwkResolver {
    fn name(&self) -> &str {
        "JwkResolver"
    }

    fn resolve<'a>(
        &'a self,
        did: &'a DID,
    ) -> Pin<Box<dyn Future<Output = Resolution> + Send + 'a>> {
        Box::pin(async move {
            let identifier = match did.method() {
                DIDMethod::Jwk { identifier, .. } => identifier,
                _ => return None,
            };

            Some(
                affinidi_did_jwk::resolve_identifier(&identifier).map_err(|e| {
                    error!("did:jwk resolution error: {e:?}");
                    ResolverError::ResolutionFailed(e.to_string())
                }),
            )
        })
    }
}

// ---------------------------------------------------------------------------
// did:webvh (feature-gated)
// ---------------------------------------------------------------------------

/// Resolver for `did:webvh` — Web Verifiable History DID method.
///
/// Like `did:web`, a `did:webvh` value names the host its log is fetched from,
/// so by default this refuses non-public hosts — see [`HostPolicy`]. Special-use
/// names such as `localhost` are refused before any request is made, and a
/// name that resolves to a non-public address is refused at connect time. A
/// local stack using `did:webvh:{SCID}:localhost%3A8000` opts out with
/// [`WebvhResolver::with_policy`], or with
/// [`DIDCacheConfigBuilder::with_host_policy`](crate::config::DIDCacheConfigBuilder::with_host_policy),
/// which sets did:web and did:webvh together.
///
/// No HTTP client is handed to `didwebvh-rs`, so resolution uses the client it
/// builds itself: redirects refused, system proxy settings ignored and, under
/// [`HostPolicy::PublicOnly`], every resolved address vetted before connecting.
#[cfg(feature = "did-webvh")]
#[derive(Debug, Clone, Copy)]
pub struct WebvhResolver {
    policy: HostPolicy,
}

#[cfg(feature = "did-webvh")]
impl WebvhResolver {
    /// Create a resolver refusing non-public hosts.
    pub fn new() -> Self {
        Self::with_policy(HostPolicy::PublicOnly)
    }

    /// Create a resolver under an explicit [`HostPolicy`].
    pub fn with_policy(policy: HostPolicy) -> Self {
        Self { policy }
    }

    fn resolve_options(&self) -> didwebvh_rs::resolve::ResolveOptions {
        let policy = match self.policy {
            HostPolicy::AllowPrivate => didwebvh_rs::resolve::HostPolicy::AllowPrivate,
            _ => didwebvh_rs::resolve::HostPolicy::PublicOnly,
        };
        didwebvh_rs::resolve::ResolveOptions::default().with_host_policy(policy)
    }
}

#[cfg(feature = "did-webvh")]
impl Default for WebvhResolver {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "did-webvh")]
impl AsyncResolver for WebvhResolver {
    fn name(&self) -> &str {
        "WebvhResolver"
    }

    fn resolve<'a>(
        &'a self,
        did: &'a DID,
    ) -> Pin<Box<dyn Future<Output = Resolution> + Send + 'a>> {
        Box::pin(async move {
            if !matches!(did.method(), DIDMethod::Webvh { .. }) {
                return None;
            }

            use didwebvh_rs::log_entry::LogEntryMethods;

            let mut method = didwebvh_rs::DIDWebVHState::default();
            let did_str = did.to_string();

            let resolution = method.resolve(&did_str, self.resolve_options()).await;
            Some(match resolution {
                Ok((_, metadata)) if metadata.deactivated => {
                    tracing::warn!("did:webvh {did_str} is deactivated; refusing its document");
                    Err(ResolverError::ResolutionFailed(
                        webvh_deactivated(&did_str).to_string(),
                    ))
                }
                Ok((log_entry, _)) => {
                    let doc_value = log_entry.get_did_document().map_err(|e| {
                        ResolverError::InvalidDocument(format!(
                            "Resolved webvh DID but couldn't convert to DID Document: {e}"
                        ))
                    });
                    match doc_value {
                        Ok(value) => serde_json::from_value(value).map_err(|e| {
                            ResolverError::InvalidDocument(format!("Invalid document: {e}"))
                        }),
                        Err(e) => Err(e),
                    }
                }
                Err(e @ didwebvh_rs::DIDWebVHError::BlockedHost(_)) => {
                    tracing::warn!("did:webvh resolution refused by host policy: {e}");
                    Err(ResolverError::ResolutionFailed(e.to_string()))
                }
                Err(didwebvh_rs::DIDWebVHError::NetworkError {
                    url,
                    status_code,
                    message,
                }) => {
                    error!(
                        "did:webvh resolution fetch failed: url={url} status={status_code:?} {message}"
                    );
                    Err(webvh_network_error(url, status_code, message))
                }
                Err(e) => {
                    error!("did:webvh resolution error: {e:?}");
                    Err(ResolverError::ResolutionFailed(e.to_string()))
                }
            })
        })
    }
}

// ---------------------------------------------------------------------------
// did:cheqd (feature-gated)
// ---------------------------------------------------------------------------

/// Resolver for `did:cheqd` — retired in 0.8.36, kept so the type still exists.
///
/// It now declines every DID with a `ResolutionFailed` explaining why, rather
/// than resolving. The implementation came from `did-resolver-cheqd`, a crate
/// with no published source repository and a single 2025 release, which pinned
/// `ssi-dids-core 0.1` and pulled eight advisories — including a live h2 DoS —
/// into the lockfile even though the feature is off by default and nothing in
/// this workspace enabled it.
///
/// `did:cheqd` still *parses* (see `affinidi-did-common`). To resolve it, append
/// your own [`AsyncResolver`] for the method; the chain is a public extension
/// point precisely so a method can live outside this crate.
#[cfg(feature = "did-cheqd")]
pub struct CheqdResolver;

#[cfg(feature = "did-cheqd")]
impl AsyncResolver for CheqdResolver {
    fn name(&self) -> &str {
        "CheqdResolver"
    }

    fn resolve<'a>(
        &'a self,
        did: &'a DID,
    ) -> Pin<Box<dyn Future<Output = Resolution> + Send + 'a>> {
        Box::pin(async move {
            if !matches!(did.method(), DIDMethod::Cheqd { .. }) {
                return None;
            }

            // Deliberately `Some(Err(..))`, not `None`: declining would fall
            // through to "no resolver registered for DID method 'cheqd'", which
            // reads like a configuration mistake. This says what actually
            // happened and what to do about it.
            error!("did:cheqd resolution is retired; refusing {did}");
            Some(Err(ResolverError::ResolutionFailed(
                "did:cheqd resolution was retired in affinidi-did-resolver-cache-sdk 0.8.36; \
                 append your own AsyncResolver for the method if you need it"
                    .to_string(),
            )))
        })
    }
}

// ---------------------------------------------------------------------------
// did:scid (feature-gated)
// ---------------------------------------------------------------------------

/// Resolver for `did:scid` — Self-Certifying Identifier DID method.
///
/// Refuses non-public hosts for the `vh` format; [`ScidResolverWithPolicy`]
/// takes an explicit [`HostPolicy`], and is what [`DIDCacheClient`] registers.
///
/// [`DIDCacheClient`]: crate::DIDCacheClient
#[cfg(feature = "did-scid")]
pub struct ScidResolver;

#[cfg(feature = "did-scid")]
impl AsyncResolver for ScidResolver {
    fn name(&self) -> &str {
        "ScidResolver"
    }

    fn resolve<'a>(
        &'a self,
        did: &'a DID,
    ) -> Pin<Box<dyn Future<Output = Resolution> + Send + 'a>> {
        Box::pin(resolve_scid(did, HostPolicy::PublicOnly, None))
    }
}

/// What a resolver has verified about one `did:scid` identity: where its log
/// has been found, and the latest version verified for it.
///
/// A service that authorises did:scid identities persists these (from
/// [`ScidSourceBook::records`] or the [`ScidSourceBook::set_listener`] hook) and
/// seeds them back at boot with [`ScidSourceBook::seed`], so the floor survives
/// a restart (VTI-KEY-162).
#[cfg(feature = "did-scid")]
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScidSourceRecord {
    /// The bare `did:scid:vh:1:<scid>` DID.
    pub did: String,
    /// Sources the log has been found at, in `src` form, most recent first.
    pub sources: Vec<String>,
    /// The latest version verified, or `None` for sources seeded but never
    /// verified.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<ScidVersion>,
}

/// A did:webvh log version: its number and its `versionId`.
#[cfg(feature = "did-scid")]
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScidVersion {
    /// The version number (the `N` of `N-<hash>`).
    pub number: u32,
    /// The full `versionId`.
    pub id: String,
}

/// Called with a record each time the book's record for an identity changes.
#[cfg(feature = "did-scid")]
pub type ScidSourceListener = std::sync::Arc<dyn Fn(&ScidSourceRecord) + Send + Sync>;

/// What a resolver has verified about each `did:scid` SCID: where its log has
/// been found, and the latest version it has verified.
///
/// A did:scid identity is the bare DID; `?src=` is only a locator (VTI-KEY-160).
/// The book lets the bare DID resolve after a source has been seen, and refuses
/// an older copy of the log from any source (VTI-KEY-162): the SCID makes a
/// copy unforgeable, not current. Because the `src` a peer presents is its own
/// choice, a DID URL whose source the book does not know is also checked
/// against the sources it does know, and refused when they hold a newer log.
///
/// It is in memory and bounded at [`ScidSourceBook::CAPACITY`] identities of
/// [`ScidSourceBook::MAX_SOURCES`] sources each. A service that authorises
/// did:scid identities persists the records and seeds them back at boot.
#[cfg(feature = "did-scid")]
#[derive(Default)]
pub struct ScidSourceBook {
    seen: std::sync::Mutex<std::collections::HashMap<String, ScidSeen>>,
    listener: std::sync::Mutex<Option<ScidSourceListener>>,
}

#[cfg(feature = "did-scid")]
impl std::fmt::Debug for ScidSourceBook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let len = self.seen.lock().map(|s| s.len()).unwrap_or_default();
        f.debug_struct("ScidSourceBook")
            .field("identities", &len)
            .finish()
    }
}

#[cfg(feature = "did-scid")]
#[derive(Debug, Clone, Default)]
struct ScidSeen {
    /// Canonical `src` forms, most recent first.
    sources: Vec<String>,
    /// `None` until a resolution is verified.
    version: Option<(u32, String)>,
}

#[cfg(feature = "did-scid")]
impl ScidSourceBook {
    /// How many identities the book holds before it forgets one to make room.
    pub const CAPACITY: usize = 100_000;
    /// How many sources it keeps per identity.
    pub const MAX_SOURCES: usize = 4;

    fn key(did: &str) -> String {
        let did = affinidi_did_common::scid::strip_scid_src(did);
        did.split('#').next().unwrap_or(&did).to_string()
    }

    /// The `src` of `src` for `bare`, in the form the log's own did:webvh DID
    /// gives it, so `localhost:8000` and `localhost%3A8000` are one source.
    fn canonical_src(bare: &str, src: &str) -> Option<String> {
        let webvh =
            didwebvh_rs::DIDWebVHState::convert_scid_id_to_webvh_id(&format!("{bare}?src={src}"))?;
        didwebvh_rs::DIDWebVHState::convert_webvh_id_to_scid_id(&webvh)
            .split_once("?src=")
            .map(|(_, src)| src.to_string())
    }

    fn record_of(key: &str, seen: &ScidSeen) -> ScidSourceRecord {
        ScidSourceRecord {
            did: key.to_string(),
            sources: seen.sources.clone(),
            version: seen
                .version
                .clone()
                .map(|(number, id)| ScidVersion { number, id }),
        }
    }

    fn notify(&self, record: Option<ScidSourceRecord>) {
        if let Some(record) = record
            && let Some(listener) = self.listener.lock().ok().and_then(|l| l.clone())
        {
            listener(&record);
        }
    }

    /// The most recent source recorded for the identity of `did`, in `src` form.
    pub fn source(&self, did: &str) -> Option<String> {
        self.sources(did).into_iter().next()
    }

    /// Every source recorded for the identity of `did`, most recent first.
    pub fn sources(&self, did: &str) -> Vec<String> {
        self.seen
            .lock()
            .ok()
            .and_then(|seen| seen.get(&Self::key(did)).map(|s| s.sources.clone()))
            .unwrap_or_default()
    }

    /// The record held for the identity of `did`.
    pub fn record(&self, did: &str) -> Option<ScidSourceRecord> {
        let key = Self::key(did);
        let seen = self.seen.lock().ok()?;
        seen.get(&key).map(|s| Self::record_of(&key, s))
    }

    /// Every record held, for a service to persist.
    pub fn records(&self) -> Vec<ScidSourceRecord> {
        self.seen
            .lock()
            .map(|seen| seen.iter().map(|(k, s)| Self::record_of(k, s)).collect())
            .unwrap_or_default()
    }

    /// Calls `listener` with the identity's record each time the book records
    /// a new source or a newer verified version for it. Replaces any listener
    /// already set. The listener runs on the resolving task, after the book's
    /// lock is released; it must not block.
    pub fn set_listener(&self, listener: ScidSourceListener) {
        if let Ok(mut slot) = self.listener.lock() {
            *slot = Some(listener);
        }
    }

    /// Merges a persisted record into the book: its sources are added after
    /// any the book already holds, and its version raises the floor but never
    /// lowers it. Returns `false` for a record whose `did` is not a did:scid.
    pub fn seed(&self, record: &ScidSourceRecord) -> bool {
        if !record.did.starts_with("did:scid:") {
            return false;
        }
        let key = Self::key(&record.did);
        let Ok(mut seen) = self.seen.lock() else {
            return false;
        };
        if !seen.contains_key(&key) {
            Self::make_room(&mut seen);
        }
        let entry = seen.entry(key.clone()).or_default();
        for src in &record.sources {
            if let Some(src) = Self::canonical_src(&key, src)
                && !entry.sources.contains(&src)
                && entry.sources.len() < Self::MAX_SOURCES
            {
                entry.sources.push(src);
            }
        }
        if let Some(version) = &record.version
            && entry
                .version
                .as_ref()
                .is_none_or(|(n, _)| version.number > *n)
        {
            entry.version = Some((version.number, version.id.clone()));
        }
        true
    }

    /// Records the `src` of a did:scid DID URL as the most recent place to look
    /// for that identity, without changing the version verified for it.
    /// Returns `false` when `did_url` carries no usable `src`.
    pub fn add_source(&self, did_url: &str) -> bool {
        let key = Self::key(did_url);
        let Some(src) = affinidi_did_common::scid::scid_src(did_url)
            .and_then(|src| Self::canonical_src(&key, src))
        else {
            return false;
        };
        let record = {
            let Ok(mut seen) = self.seen.lock() else {
                return false;
            };
            if !seen.contains_key(&key) {
                Self::make_room(&mut seen);
            }
            let entry = seen.entry(key.clone()).or_default();
            if entry.sources.first() == Some(&src) {
                return true;
            }
            Self::push_front(&mut entry.sources, src);
            Self::record_of(&key, entry)
        };
        self.notify(Some(record));
        true
    }

    fn push_front(sources: &mut Vec<String>, src: String) {
        sources.retain(|s| *s != src);
        sources.insert(0, src);
        sources.truncate(Self::MAX_SOURCES);
    }

    fn make_room(seen: &mut std::collections::HashMap<String, ScidSeen>) {
        if seen.len() >= Self::CAPACITY
            && let Some(key) = seen.keys().next().cloned()
        {
            seen.remove(&key);
        }
    }

    /// Refuses a version older than the floor, or a different entry at the
    /// floor's number (a fork).
    fn below_floor(
        floor: Option<&(u32, String)>,
        key: &str,
        source: &str,
        version_number: u32,
        version_id: &str,
    ) -> Result<(), ResolverError> {
        if let Some((latest, latest_id)) = floor
            && (version_number < *latest || (version_number == *latest && version_id != latest_id))
        {
            return Err(ResolverError::ResolutionFailed(format!(
                "{key}: the log at {source} is at version {version_id}, behind {latest_id} \
                 already verified for this SCID"
            )));
        }
        Ok(())
    }

    /// Accepts a verified resolution, or refuses it as older than one already
    /// verified for the same SCID.
    fn accept(
        &self,
        did: &str,
        source: &str,
        version_number: u32,
        version_id: &str,
    ) -> Result<(), ResolverError> {
        let key = Self::key(did);
        let record = {
            let mut seen = self.seen.lock().map_err(|_| {
                ResolverError::ResolutionFailed("did:scid source book poisoned".into())
            })?;
            Self::below_floor(
                seen.get(&key).and_then(|s| s.version.as_ref()),
                &key,
                source,
                version_number,
                version_id,
            )?;
            if !seen.contains_key(&key) {
                Self::make_room(&mut seen);
            }
            let entry = seen.entry(key.clone()).or_default();
            let changed = entry.sources.first().map(String::as_str) != Some(source)
                || entry.version.as_ref().map(|(n, _)| *n) != Some(version_number);
            Self::push_front(&mut entry.sources, source.to_string());
            entry.version = Some((version_number, version_id.to_string()));
            changed.then(|| Self::record_of(&key, entry))
        };
        self.notify(record);
        Ok(())
    }
}

/// Resolver for `did:scid` under an explicit [`HostPolicy`].
///
/// A `did:scid:vh:1` DID resolves through its did:webvh log, so the policy
/// applies exactly as it does to [`WebvhResolver`]: a local stack serving
/// `did:scid:vh:1:{SCID}?src=localhost:8000` opts out with
/// [`HostPolicy::AllowPrivate`], or with
/// [`DIDCacheConfigBuilder::with_host_policy`](crate::config::DIDCacheConfigBuilder::with_host_policy).
///
/// The document is the did:scid's own, under the bare DID. A DID URL with `src`
/// resolves through that source; a bare DID through the source its
/// [`ScidSourceBook`] holds for the SCID, and fails when it holds none.
#[cfg(feature = "did-scid")]
#[derive(Debug, Clone)]
pub struct ScidResolverWithPolicy {
    policy: HostPolicy,
    sources: std::sync::Arc<ScidSourceBook>,
}

#[cfg(feature = "did-scid")]
impl ScidResolverWithPolicy {
    /// Create a resolver under an explicit [`HostPolicy`], with its own source
    /// book.
    pub fn new(policy: HostPolicy) -> Self {
        Self::with_sources(policy, Default::default())
    }

    /// Create a resolver that records into, and resolves bare DIDs from, a
    /// shared source book.
    pub fn with_sources(policy: HostPolicy, sources: std::sync::Arc<ScidSourceBook>) -> Self {
        Self { policy, sources }
    }
}

#[cfg(feature = "did-scid")]
impl AsyncResolver for ScidResolverWithPolicy {
    fn name(&self) -> &str {
        "ScidResolver"
    }

    fn resolve<'a>(
        &'a self,
        did: &'a DID,
    ) -> Pin<Box<dyn Future<Output = Resolution> + Send + 'a>> {
        Box::pin(resolve_scid(did, self.policy, Some(&self.sources)))
    }
}

#[cfg(feature = "did-scid")]
async fn resolve_scid(
    did: &DID,
    policy: HostPolicy,
    sources: Option<&ScidSourceBook>,
) -> Resolution {
    if !matches!(did.method(), DIDMethod::Scid { .. }) {
        return None;
    }

    let did_str = did.to_string();
    let policy = match policy {
        HostPolicy::AllowPrivate => didwebvh_rs::resolve::HostPolicy::AllowPrivate,
        _ => didwebvh_rs::resolve::HostPolicy::PublicOnly,
    };
    let options = didwebvh_rs::resolve::ResolveOptions::default().with_host_policy(policy);
    let key = ScidSourceBook::key(&did_str);
    let known = sources
        .map(|book| book.sources(&did_str))
        .unwrap_or_default();
    let presented = affinidi_did_common::scid::scid_src(&did_str)
        .and_then(|src| ScidSourceBook::canonical_src(&key, src));

    let resolution = if affinidi_did_common::scid::scid_src(&did_str).is_some() {
        match did_scid::resolve_scid(&did_str, None, options.clone()).await {
            Ok(resolution) => resolution,
            // Formats other than `vh` keep their source method's document.
            Err(did_scid::errors::DIDSCIDError::UnsupportedFormat) => {
                return Some(
                    did_scid::resolve_with_options(&did_str, None, options)
                        .await
                        .map_err(scid_error),
                );
            }
            Err(e) => return Some(Err(scid_error(e))),
        }
    } else {
        // A bare DID: the known sources, most recent first.
        let mut last = Err(did_scid::errors::DIDSCIDError::MissingPeerSource);
        for src in &known {
            last = did_scid::resolve_scid(
                &did_str,
                Some(did_scid::ScidMethod::WebVH(src.clone())),
                options.clone(),
            )
            .await;
            if last.is_ok() {
                break;
            }
        }
        match last {
            Ok(resolution) => resolution,
            Err(e) => return Some(Err(scid_error(e))),
        }
    };

    // A source the book has not seen for this identity is the presenter's own
    // choice, and could serve a copy of the log it took before a rotation.
    // Check what the known sources serve now; a newer log there means the
    // presented one is stale.
    if let Some(presented) = presented
        && !known.is_empty()
        && !known.contains(&presented)
    {
        for src in &known {
            if let Ok(current) = did_scid::resolve_scid(
                &key,
                Some(did_scid::ScidMethod::WebVH(src.clone())),
                options.clone(),
            )
            .await
            {
                if let Err(e) = ScidSourceBook::below_floor(
                    Some(&(current.version_number, current.version_id.clone())),
                    &key,
                    &resolution.source,
                    resolution.version_number,
                    &resolution.version_id,
                ) {
                    error!("did:scid resolution refused: {e}");
                    return Some(Err(e));
                }
                break;
            }
        }
    }

    if let Some(book) = sources
        && let Err(e) = book.accept(
            &did_str,
            &resolution.source,
            resolution.version_number,
            &resolution.version_id,
        )
    {
        error!("did:scid resolution refused: {e}");
        return Some(Err(e));
    }
    Some(Ok(resolution.document))
}

#[cfg(feature = "did-scid")]
fn scid_error(e: did_scid::errors::DIDSCIDError) -> ResolverError {
    match e {
        did_scid::errors::DIDSCIDError::WebVHError(didwebvh_rs::DIDWebVHError::NetworkError {
            url,
            status_code,
            message,
        }) => {
            error!("did:scid resolution fetch failed: url={url} status={status_code:?} {message}");
            webvh_network_error(url, status_code, message)
        }
        did_scid::errors::DIDSCIDError::MissingPeerSource => ResolverError::ResolutionFailed(
            "no source is known for this did:scid; resolve it once with its ?src= DID URL"
                .to_string(),
        ),
        other => {
            error!("did:scid resolution error: {other:?}");
            ResolverError::ResolutionFailed(other.to_string())
        }
    }
}

// ---------------------------------------------------------------------------
// did:ebsi (feature-gated)
// ---------------------------------------------------------------------------

/// Resolver for `did:ebsi` — EBSI DID method for legal entities.
///
/// Resolves DIDs via the EBSI DID Registry API (pilot environment by default).
#[cfg(feature = "did-ebsi")]
pub struct EbsiResolver;

#[cfg(feature = "did-ebsi")]
impl AsyncResolver for EbsiResolver {
    fn name(&self) -> &str {
        "EbsiResolver"
    }

    fn resolve<'a>(
        &'a self,
        did: &'a DID,
    ) -> Pin<Box<dyn Future<Output = Resolution> + Send + 'a>> {
        Box::pin(async move {
            if !matches!(did.method(), DIDMethod::Ebsi { .. }) {
                return None;
            }

            let did_str = did.to_string();
            Some(
                did_ebsi::resolve_ebsi_did(&did_str, did_ebsi::EBSI_PILOT_API)
                    .await
                    .map_err(|e| {
                        error!("did:ebsi resolution error: {e:?}");
                        ResolverError::ResolutionFailed(e.to_string())
                    }),
            )
        })
    }
}

// ---------------------------------------------------------------------------
// did:webs (feature-gated)
// ---------------------------------------------------------------------------

/// Resolver for `did:webs` — `did:web` discovery with KERI-verified key state.
///
/// Fetches `keri.cesr` and `did.json` from the DID's location, verifies the key
/// event log, and returns the document that key state implies. The published
/// `did.json` is cross-checked rather than trusted; a disagreement fails the
/// resolution.
///
/// `did:webs` is not modelled by [`DIDMethod`], so it arrives here as
/// `DIDMethod::Other { method: "webs", .. }` and is registered under
/// `MethodName::Other("webs")`.
#[cfg(feature = "did-webs")]
pub struct WebsResolver {
    inner: affinidi_did_webs::WebsResolver,
}

#[cfg(feature = "did-webs")]
impl WebsResolver {
    /// A resolver with its own HTTP client and connection pool.
    pub fn new() -> Self {
        Self {
            inner: affinidi_did_webs::WebsResolver::new(),
        }
    }
}

#[cfg(feature = "did-webs")]
impl Default for WebsResolver {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "did-webs")]
impl AsyncResolver for WebsResolver {
    fn name(&self) -> &str {
        "WebsResolver"
    }

    fn resolve<'a>(
        &'a self,
        did: &'a DID,
    ) -> Pin<Box<dyn Future<Output = Resolution> + Send + 'a>> {
        Box::pin(async move {
            match did.method() {
                DIDMethod::Other { method, .. } if method == "webs" => {}
                _ => return None,
            }

            let did_str = did.to_string();
            Some(self.inner.resolve(&did_str).await.map_err(|e| {
                error!("did:webs resolution error: {e:?}");
                ResolverError::ResolutionFailed(e.to_string())
            }))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn did_web_http_status_is_kept() {
        let error = did_web_error(affinidi_did_web::DidWebError::ResolutionFailed {
            status: 429,
            url: "https://example.com/.well-known/did.json".to_string(),
        });
        let ResolverError::NetworkFetch(fetch) = error else {
            panic!("expected NetworkFetch, got {error:?}");
        };
        assert!(fetch.is_rate_limited());
        assert_eq!(
            fetch.url.as_deref(),
            Some("https://example.com/.well-known/did.json")
        );
    }

    #[test]
    fn did_web_invalid_did_is_not_a_fetch_failure() {
        let error = did_web_error(affinidi_did_web::DidWebError::InvalidDid("bad".into()));
        assert!(
            matches!(error, ResolverError::ResolutionFailed(_)),
            "{error:?}"
        );
    }

    #[cfg(any(feature = "did-webvh", feature = "did-scid"))]
    #[test]
    fn webvh_body_failure_after_200_records_no_status() {
        let error = webvh_network_error(
            "https://example.com/.well-known/did.jsonl".to_string(),
            Some(200),
            "Failed to read response body".to_string(),
        );
        let ResolverError::NetworkFetch(fetch) = error else {
            panic!("expected NetworkFetch, got {error:?}");
        };
        assert_eq!(fetch.status, None);
        assert_eq!(fetch.message, "Failed to read response body");
    }
}
