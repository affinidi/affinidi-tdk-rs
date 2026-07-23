//! Unified resolution of DIDs **and** agent names.
//!
//! Client code should not have to care whether it holds a DID or a human-memorable
//! shortcut. [`DIDCacheClient::resolve_any`] takes either and returns the same
//! [`ResolveResponse`].
//!
//! # Two-level cache
//!
//! ```text
//! agent name --[ name cache: hash -> DID ]--> DID --[ document cache ]--> Document
//! ```
//!
//! The name mapping is cached separately from the document, which matters for two
//! reasons:
//!
//! 1. **A name and its DID share one document entry.** Resolving
//!    `example.com/@alice` warms the cache for `did:webvh:…` and vice versa, so
//!    neither form pays twice and the two can never hold divergent copies.
//! 2. **It sidesteps a TTL trap.** `DIDExpiry` decides expiry from the *resolved
//!    document's* `id`, not from the cache key, so a document reached via an agent
//!    name pointing at an immutable method (`did:key`, say) would be cached
//!    **forever** if the name were used as the key — pinning a mapping that is a
//!    web redirect and can change at any time. Keeping the mapping in its own
//!    cache, with an unconditional TTL, makes that structurally impossible.

use agent_names::{AgentName, AgentNameError, AgentNameResolver, verify_also_known_as};
use tokio::sync::watch;
use tracing::{debug, warn};

use crate::{DIDCacheClient, DidShortcut, ResolveResponse, errors::DIDCacheError};

/// How many claimed names to check before giving up establishing a shortcut.
///
/// Each candidate costs a request to its naming host, and a hostile document is
/// free to list hundreds, so the work one resolve can provoke has to be capped.
/// The first candidate that verifies wins, so a well-formed document — one name,
/// or a few — never reaches this limit.
#[cfg(feature = "agent-names")]
const MAX_SHORTCUT_CANDIDATES: usize = 4;

/// Either a DID or an agent name.
///
/// Parsing is a cheap syntactic test on the `/@` marker — no network access.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Identifier {
    /// A DID string, e.g. `did:webvh:QmScid:example.com`.
    Did(String),
    /// An agent name, e.g. `example.com/@alice`.
    AgentName(Box<AgentName>),
}

impl Identifier {
    /// Classify an identifier without touching the network.
    ///
    /// A string containing `/@` is treated as an agent name and must parse as
    /// one; anything else is passed through as a DID for [`DIDCacheClient::resolve`]
    /// to validate.
    pub fn parse(input: &str) -> Result<Self, DIDCacheError> {
        if AgentName::looks_like_agent_name(input) {
            let name = AgentName::parse(input).map_err(DIDCacheError::from)?;
            Ok(Identifier::AgentName(Box::new(name)))
        } else {
            Ok(Identifier::Did(input.to_string()))
        }
    }
}

impl std::str::FromStr for Identifier {
    type Err = DIDCacheError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl DIDCacheClient {
    /// Resolve a DID **or** an agent name.
    ///
    /// This is the single entry point client code should reach for when an
    /// identifier may be either form. A DID is passed straight through to
    /// [`DIDCacheClient::resolve`] with identical behaviour, so existing callers
    /// lose nothing by switching.
    ///
    /// For an agent name the flow is:
    ///
    /// 1. look the name up in the name cache; on a miss, ask each registered
    ///    [`AgentNameResolver`] in turn until one resolves it to a DID;
    /// 2. cache the mapping with an unconditional TTL;
    /// 3. resolve the DID through the normal path — reusing the document cache,
    ///    the resolver chain and single-flight de-duplication;
    /// 4. **verify** the resolved document claims the name via `alsoKnownAs`.
    ///
    /// Step 4 is mandatory. A failure there also **evicts** the name-cache entry,
    /// so a poisoned mapping is not retained and re-checked forever.
    ///
    /// The returned [`ResolveResponse`]'s `did` is the **resolved DID**, not the
    /// agent name that was passed in.
    ///
    /// # Backends
    ///
    /// A [`agent_names::HttpRedirectResolver`] is registered by default. Register
    /// others with [`DIDCacheClient::set_agent_name_resolvers`] — like the DID
    /// resolver chain, **all registration must happen before the client is
    /// cloned**.
    pub async fn resolve_any(&self, input: &str) -> Result<ResolveResponse, DIDCacheError> {
        match Identifier::parse(input)? {
            Identifier::Did(did) => self.resolve(&did).await,
            Identifier::AgentName(name) => self.resolve_agent_name(&name).await,
        }
    }

    /// Resolve an already-parsed agent name.
    pub async fn resolve_agent_name(
        &self,
        name: &AgentName,
    ) -> Result<ResolveResponse, DIDCacheError> {
        let name_hash = Self::hash_did(name.as_str());

        // One-round-trip path: the cache server resolves name -> DID -> document
        // in a single exchange, so there is no separate DID resolution to do.
        // Verification still happens here, against a document this client
        // received directly — the server is a cache, never a trust anchor.
        #[cfg(all(feature = "agent-names", feature = "network"))]
        if self.config.agent_names_over_websocket && self.network_task_tx.is_some() {
            let (did, doc) = self.network_resolve_agent_name(name.as_str()).await?;

            if let Err(e) = verify_also_known_as(&doc, name) {
                warn!("agent name verification failed: {e}");
                return Err(DIDCacheError::from(e));
            }

            let did_hash = Self::hash_did(&did);
            // Populate the shared document cache so a later lookup by DID hits.
            self.cache.insert(did_hash, doc.clone()).await;
            self.agent_name_cache.insert(name_hash, did.clone()).await;

            let method: crate::DIDMethod = did
                .split(':')
                .nth(1)
                .and_then(|m| crate::DIDMethod::try_from(m).ok())
                .unwrap_or(crate::DIDMethod::OTHER);

            // Verification succeeded just above, so the name is safe to carry
            // back as this DID's display shortcut.
            return Ok(ResolveResponse::new(did, method, did_hash, doc, false)
                .with_shortcut(DidShortcut::AgentName(name.without_scheme().to_string())));
        }

        let did = match self.agent_name_cache.get(&name_hash).await {
            Some(did) => {
                debug!("agent name cache hit: {name}");
                did
            }
            None => {
                debug!("agent name cache miss: {name}");
                self.resolve_name_deduplicated(name, name_hash).await?
            }
        };

        // `resolve_document`, not `resolve`: we already hold the name and attach
        // it below, so letting `resolve` establish a shortcut here would repeat
        // the same lookup we are in the middle of.
        let response = match self.resolve_document(&did).await {
            Ok(response) => response,
            Err(e) => {
                // The mapping points at a DID that will not resolve. Drop it so a
                // transient failure does not stay cached for the whole TTL; the
                // next caller re-asks the backend.
                debug!("dropping agent name mapping for unresolvable DID: {name} -> {did}");
                self.agent_name_cache.remove(&name_hash).await;
                return Err(e);
            }
        };

        // Layer 1: the DID must claim the name back. Without this the redirect
        // proves nothing — anyone can point a name they control at someone
        // else's DID.
        if let Err(e) = verify_also_known_as(&response.doc, name) {
            warn!("agent name verification failed: {e}");
            // Evict, so a poisoned mapping is re-fetched rather than re-failed
            // from cache until its TTL happens to expire.
            self.agent_name_cache.remove(&name_hash).await;
            return Err(DIDCacheError::from(e));
        }

        // Past verification: the caller asked by name and the DID claimed it
        // back, so the name is this DID's display shortcut. Without this the
        // name the caller supplied would be dropped from the response and every
        // consumer would have to re-derive it.
        Ok(response.with_shortcut(DidShortcut::AgentName(name.without_scheme().to_string())))
    }

    /// Establish a verified display shortcut for a document we have already
    /// resolved, or `None` if no claimed name checks out.
    ///
    /// This completes the same three-stage check as [`Self::resolve_agent_name`],
    /// just entered from the other end — from a DID rather than from a name:
    ///
    /// 1. the candidate names come from *this* document's `alsoKnownAs`, so the
    ///    DID demonstrably claims them (the stage that stops anyone labelling
    ///    someone else's DID);
    /// 2. the document is the one just resolved for `did`;
    /// 3. each candidate's forward resolution must land back on `did` — the
    ///    stage that stops a document claiming a name it does not own, since
    ///    only the name's controller decides where it points.
    ///
    /// Candidates are resolved through the name backends directly rather than
    /// through [`Self::resolve_any`]. That is what keeps this non-recursive:
    /// `resolve_any` would resolve the DID again, re-entering shortcut
    /// derivation and recursing without bound. It also skips a redundant
    /// document fetch, since stage 2 is already satisfied.
    pub(crate) async fn derive_shortcut(
        &self,
        did: &str,
        doc: &affinidi_did_common::Document,
    ) -> Option<DidShortcut> {
        for name in agent_names::extract_agent_names(doc)
            .into_iter()
            .take(MAX_SHORTCUT_CANDIDATES)
        {
            let name_hash = Self::hash_did(name.as_str());
            let resolved = match self.agent_name_cache.get(&name_hash).await {
                Some(cached) => Some(cached),
                None => self
                    .resolve_name_deduplicated(&name, name_hash)
                    .await
                    .map_err(|e| debug!("agent name '{name}' did not resolve: {e}"))
                    .ok(),
            };
            match resolved.as_deref() {
                Some(got) if got == did => {
                    return Some(DidShortcut::AgentName(name.without_scheme().to_string()));
                }
                // Claimed, but the name belongs to someone else. Never display
                // it, and keep looking rather than failing the whole resolve.
                Some(other) => {
                    warn!("agent name '{name}' claimed by {did} resolves to {other}; ignoring");
                }
                None => {}
            }
        }
        None
    }

    /// Resolve a name to a DID, collapsing concurrent lookups of the *same*
    /// name into one backend call.
    ///
    /// Mirrors the document cache's single-flight in
    /// `DIDCacheClient::resolve_uncached`: one caller becomes the leader and
    /// does the work, the rest wait on a `watch` channel and then re-read the
    /// mapping cache.
    ///
    /// Without this, N concurrent first-time lookups of one name make N
    /// outbound HTTP requests. That matters more than the equivalent for DIDs,
    /// because a name lookup is an uncached fetch against somebody else's web
    /// server — the thing a shared resolver exists to avoid doing repeatedly.
    async fn resolve_name_deduplicated(
        &self,
        name: &AgentName,
        name_hash: [u64; 2],
    ) -> Result<String, DIDCacheError> {
        loop {
            // Decide our role under the lock; no `.await` is held across it.
            enum Role {
                Leader(watch::Sender<()>),
                Follower(watch::Receiver<()>),
            }
            let role = {
                let mut map = self
                    .agent_name_inflight
                    .lock()
                    .expect("agent name inflight mutex not poisoned");
                if let Some(rx) = map.get(&name_hash) {
                    Role::Follower(rx.clone())
                } else {
                    let (tx, rx) = watch::channel(());
                    map.insert(name_hash, rx);
                    Role::Leader(tx)
                }
            };

            match role {
                Role::Follower(mut rx) => {
                    // The leader drops its sender when done, which closes the
                    // channel and resolves `changed()`.
                    let _ = rx.changed().await;
                    if let Some(did) = self.agent_name_cache.get(&name_hash).await {
                        debug!("agent name '{name}' resolved by another caller");
                        return Ok(did);
                    }
                    // The leader errored and cached nothing. Loop and try to
                    // become the leader ourselves.
                    continue;
                }
                Role::Leader(tx) => {
                    // A prior leader may have populated the mapping between our
                    // cache miss and our acquiring leadership.
                    if let Some(did) = self.agent_name_cache.get(&name_hash).await {
                        self.release_name_leadership(name_hash, tx);
                        return Ok(did);
                    }

                    let result = self.resolve_name_to_did(name).await;
                    if let Ok(ref did) = result {
                        self.agent_name_cache.insert(name_hash, did.clone()).await;
                    }
                    // Release leadership and wake followers regardless of
                    // outcome — an early return here would hang every waiter.
                    self.release_name_leadership(name_hash, tx);
                    return result;
                }
            }
        }
    }

    fn release_name_leadership(&self, name_hash: [u64; 2], tx: watch::Sender<()>) {
        self.agent_name_inflight
            .lock()
            .expect("agent name inflight mutex not poisoned")
            .remove(&name_hash);
        drop(tx);
    }

    /// Walk the registered backends until one resolves the name.
    async fn resolve_name_to_did(&self, name: &AgentName) -> Result<String, DIDCacheError> {
        for resolver in self.agent_name_resolvers.iter() {
            match resolver.resolve(name).await {
                Some(Ok(did)) => {
                    debug!(
                        "agent name '{name}' resolved to '{did}' by {}",
                        resolver.name()
                    );
                    return Ok(did);
                }
                Some(Err(e)) => {
                    // The backend recognised the name but failed. Report rather
                    // than silently falling through to a backend that might
                    // answer differently.
                    return Err(DIDCacheError::from(e));
                }
                None => continue,
            }
        }
        Err(DIDCacheError::from(AgentNameError::Unresolvable(
            name.as_str().to_string(),
        )))
    }

    /// Replace the agent name resolution backends.
    ///
    /// # Panics
    ///
    /// Panics if the client has already been cloned, matching
    /// [`DIDCacheClient::set_resolver`]. Register backends during setup.
    pub fn set_agent_name_resolvers(&mut self, resolvers: Vec<Box<dyn AgentNameResolver>>) {
        *std::sync::Arc::get_mut(&mut self.agent_name_resolvers)
            .expect("Cannot modify agent name resolvers after DIDCacheClient has been cloned") =
            resolvers;
    }

    /// Add a backend to the front of the chain (tried first).
    ///
    /// # Panics
    ///
    /// Panics if the client has already been cloned.
    pub fn prepend_agent_name_resolver(&mut self, resolver: Box<dyn AgentNameResolver>) {
        std::sync::Arc::get_mut(&mut self.agent_name_resolvers)
            .expect("Cannot modify agent name resolvers after DIDCacheClient has been cloned")
            .insert(0, resolver);
    }

    /// Add a backend to the end of the chain (tried last).
    ///
    /// # Panics
    ///
    /// Panics if the client has already been cloned.
    pub fn append_agent_name_resolver(&mut self, resolver: Box<dyn AgentNameResolver>) {
        std::sync::Arc::get_mut(&mut self.agent_name_resolvers)
            .expect("Cannot modify agent name resolvers after DIDCacheClient has been cloned")
            .push(resolver);
    }

    /// Names of the registered backends, in the order they are tried.
    pub fn agent_name_resolver_names(&self) -> Vec<&str> {
        self.agent_name_resolvers.iter().map(|r| r.name()).collect()
    }

    /// Drop a cached agent name mapping, forcing the next lookup to re-resolve.
    ///
    /// Returns the DID that was cached, if any.
    pub async fn remove_agent_name(&self, name: &AgentName) -> Option<String> {
        self.agent_name_cache
            .remove(&Self::hash_did(name.as_str()))
            .await
    }
}

impl From<AgentNameError> for DIDCacheError {
    fn from(err: AgentNameError) -> Self {
        DIDCacheError::AgentNameError(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_a_did() {
        assert_eq!(
            Identifier::parse("did:web:example.com").unwrap(),
            Identifier::Did("did:web:example.com".to_string())
        );
    }

    #[test]
    fn classifies_an_agent_name() {
        let id = Identifier::parse("example.com/@alice").unwrap();
        match id {
            Identifier::AgentName(n) => assert_eq!(n.as_str(), "https://example.com/@alice"),
            other => panic!("expected an agent name, got {other:?}"),
        }
    }

    /// An email has an '@' but no '/@', so it is not mistaken for a name. It is
    /// passed through as a DID and rejected later by `resolve`.
    #[test]
    fn does_not_mistake_an_email_for_an_agent_name() {
        assert!(matches!(
            Identifier::parse("alice@example.com").unwrap(),
            Identifier::Did(_)
        ));
    }

    #[test]
    fn rejects_a_malformed_agent_name() {
        // Contains the marker, so it is treated as a name — and is invalid.
        assert!(Identifier::parse("example.com/@").is_err());
    }

    #[test]
    fn from_str_works() {
        let id: Identifier = "example.com/@alice".parse().unwrap();
        assert!(matches!(id, Identifier::AgentName(_)));
    }

    #[test]
    fn agent_name_error_maps_to_cache_error() {
        let err = DIDCacheError::from(AgentNameError::Unresolvable("x".to_string()));
        assert!(matches!(err, DIDCacheError::AgentNameError(_)));
        assert!(err.to_string().contains('x'));
    }
}
