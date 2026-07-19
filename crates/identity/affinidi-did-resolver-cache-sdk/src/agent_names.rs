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
use tracing::{debug, warn};

use crate::{DIDCacheClient, ResolveResponse, errors::DIDCacheError};

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

        let did = match self.agent_name_cache.get(&name_hash).await {
            Some(did) => {
                debug!("agent name cache hit: {name}");
                did
            }
            None => {
                debug!("agent name cache miss: {name}");
                let did = self.resolve_name_to_did(name).await?;
                self.agent_name_cache.insert(name_hash, did.clone()).await;
                did
            }
        };

        let response = match self.resolve(&did).await {
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

        Ok(response)
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
