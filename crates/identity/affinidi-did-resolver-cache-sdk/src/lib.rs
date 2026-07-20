/*!
DID Universal Resolver Cache Client SDK

Used to easily connect to the DID Universal Resolver Cache.

# Crate features
As this crate can be used either natively or in a WASM environment, the following features are available:
* **local**
  * **default** - Enables the local mode of the SDK. This is the default mode.
* **network**
    * Enables the network mode of the SDK. This mode requires a run-time service address to connect to.
    * This feature is NOT supported in a WASM environment. Will cause a compile error if used in WASM.
*/

#[cfg(all(feature = "network", target_arch = "wasm32"))]
compile_error!("The 'network' feature is not supported on wasm32 targets");

use affinidi_did_common::{DID, Document};
#[cfg(feature = "network")]
use affinidi_task_utils::{CancellationToken, HealthRegistry, TaskSupervisor};
use config::DIDCacheConfig;
use errors::DIDCacheError;
use highway::{HighwayHash, HighwayHasher};
use moka::{Expiry, future::Cache};
#[cfg(feature = "network")]
use networking::{
    WSRequest,
    network::{NetworkTask, WSCommands},
};

#[cfg(feature = "network")]
pub use affinidi_task_utils::{ComponentHealth, ComponentState};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex as StdMutex};
use std::{fmt, time::Duration};
use tokio::sync::watch;
#[cfg(feature = "network")]
use tokio::sync::{Mutex, mpsc};
use tracing::debug;
#[cfg(feature = "network")]
use tracing::warn;
use wasm_bindgen::JsValue;
use wasm_bindgen::prelude::*;

#[cfg(feature = "agent-names")]
pub mod agent_names;
pub mod config;
pub mod errors;
#[cfg(feature = "network")]
pub mod networking;
mod resolver;

// Re-export resolver traits and network resolver implementations
pub use affinidi_did_resolver_traits::{
    AsyncResolver, MethodName, Resolution, Resolver, ResolverError,
};
pub use resolver::network_resolvers;

/// DID Methods supported by the DID Universal Resolver Cache
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[wasm_bindgen]
pub enum DIDMethod {
    ETHR,
    JWK,
    KEY,
    PEER,
    PKH,
    WEB,
    WEBVH,
    CHEQD,
    SCID,
    EBSI,
    EXAMPLE,
    /// A DID method with no built-in support — resolved only if a custom
    /// resolver has been registered for it (see [`DIDCacheClient::set_resolver`]).
    /// The concrete method name is preserved in [`ResolveResponse::did`].
    OTHER,
}

/// Helper function to convert a DIDMethod to a string
impl fmt::Display for DIDMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DIDMethod::ETHR => write!(f, "ethr"),
            DIDMethod::JWK => write!(f, "jwk"),
            DIDMethod::KEY => write!(f, "key"),
            DIDMethod::PEER => write!(f, "peer"),
            DIDMethod::PKH => write!(f, "pkh"),
            DIDMethod::WEB => write!(f, "web"),
            DIDMethod::WEBVH => write!(f, "webvh"),
            DIDMethod::CHEQD => write!(f, "cheqd"),
            DIDMethod::SCID => write!(f, "scid"),
            DIDMethod::EBSI => write!(f, "ebsi"),
            DIDMethod::EXAMPLE => write!(f, "example"),
            DIDMethod::OTHER => write!(f, "other"),
        }
    }
}

/// Helper function to convert a string to a DIDMethod
impl TryFrom<String> for DIDMethod {
    type Error = DIDCacheError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.as_str().try_into()
    }
}

impl TryFrom<&str> for DIDMethod {
    type Error = DIDCacheError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value.to_lowercase().as_str() {
            "ethr" => Ok(DIDMethod::ETHR),
            "jwk" => Ok(DIDMethod::JWK),
            "key" => Ok(DIDMethod::KEY),
            "peer" => Ok(DIDMethod::PEER),
            "pkh" => Ok(DIDMethod::PKH),
            "web" => Ok(DIDMethod::WEB),
            "webvh" => Ok(DIDMethod::WEBVH),
            "cheqd" => Ok(DIDMethod::CHEQD),
            "scid" => Ok(DIDMethod::SCID),
            "ebsi" => Ok(DIDMethod::EBSI),
            #[cfg(feature = "did_example")]
            "example" => Ok(DIDMethod::EXAMPLE),
            _ => Err(DIDCacheError::UnsupportedMethod(value.to_string())),
        }
    }
}

impl DIDMethod {
    /// Returns `true` for DID methods whose documents are fetched from external
    /// infrastructure and can change over time (web, webvh, cheqd, scid, ebsi).
    ///
    /// Returns `false` for deterministic methods where the document is derived
    /// entirely from the DID string itself (key, peer, jwk, ethr, pkh, example).
    ///
    /// A custom (`OTHER`) method is treated as **mutable** — its resolver may
    /// fetch from external infrastructure, so the cached document is given the
    /// mutable TTL rather than being kept forever.
    pub fn is_mutable(&self) -> bool {
        matches!(
            self,
            DIDMethod::WEB
                | DIDMethod::WEBVH
                | DIDMethod::CHEQD
                | DIDMethod::SCID
                | DIDMethod::EBSI
                | DIDMethod::OTHER
        )
    }
}

/// The result of resolving an identifier.
///
/// `#[non_exhaustive]`: build via [`ResolveResponse::new`] rather than a struct
/// literal. Fields stay public for reads.
///
/// This is a *returned* type — callers read it, they do not normally construct
/// one — so sealing it costs nothing in practice and buys the ability to report
/// more about a resolution later without a breaking release. Per
/// [ADR 0003](https://github.com/affinidi/affinidi-tdk-rs/blob/main/docs/adr/0003-public-api-semver-policy.md),
/// new fields on a sealed struct are additive.
#[derive(Debug)]
#[non_exhaustive]
pub struct ResolveResponse {
    /// The identifier that was resolved. For [`DIDCacheClient::resolve_any`]
    /// given an agent name, this is the **DID the name resolved to**, not the
    /// name.
    pub did: String,
    /// The DID method of [`Self::did`].
    pub method: DIDMethod,
    /// HighwayHash128 of [`Self::did`] — the document cache key.
    pub did_hash: [u64; 2],
    /// The resolved DID Document.
    pub doc: Document,
    /// Whether the document came from cache rather than a fresh resolution.
    pub cache_hit: bool,
}

impl ResolveResponse {
    /// Assemble a response.
    ///
    /// The construction path for a `#[non_exhaustive]` struct. Mainly useful to
    /// consumers building a fixture or a mock resolver; the client returns these
    /// itself in normal use.
    pub fn new(
        did: String,
        method: DIDMethod,
        did_hash: [u64; 2],
        doc: Document,
        cache_hit: bool,
    ) -> Self {
        Self {
            did,
            method,
            did_hash,
            doc,
            cache_hit,
        }
    }
}

/// Per-entry expiry policy for the DID document cache.
///
/// - **Immutable methods** (key, peer, jwk, ethr, pkh): no expiry — entries
///   stay cached until evicted by capacity pressure.
/// - **Mutable methods** (web, webvh, cheqd, scid, ebsi): expire after `mutable_ttl`
///   so that updated documents are eventually re-fetched.
struct DIDExpiry {
    mutable_ttl: Duration,
}

impl Expiry<[u64; 2], Document> for DIDExpiry {
    fn expire_after_create(
        &self,
        _key: &[u64; 2],
        value: &Document,
        _created_at: std::time::Instant,
    ) -> Option<Duration> {
        let did_str = value.id.as_str();

        // Extract the method name from "did:<method>:..."
        let is_mutable = did_str
            .split(':')
            .nth(1)
            .and_then(|m| DIDMethod::try_from(m).ok())
            .is_some_and(|m| m.is_mutable());

        if is_mutable {
            Some(self.mutable_ttl)
        } else {
            None // no expiry — evicted only by capacity
        }
    }
}

// ***************************************************************************

/// [DIDCacheClient] is how you interact with the DID Universal Resolver Cache
/// config: Configuration for the SDK
/// cache: Local cache for resolved DIDs
/// network_task: OPTIONAL: Task to handle network requests
/// network_rx: OPTIONAL: Channel to listen for responses from the network task
#[wasm_bindgen(getter_with_clone)]
pub struct DIDCacheClient {
    config: DIDCacheConfig,
    cache: Cache<[u64; 2], Document>,
    #[cfg(feature = "network")]
    network_task_tx: Option<mpsc::Sender<WSCommands>>,
    #[cfg(feature = "network")]
    network_task_rx: Option<Arc<Mutex<mpsc::Receiver<WSCommands>>>>,
    /// Shutdown token for the supervised network task; cancelling it stops
    /// the task (see [`DIDCacheClient::stop`]).
    #[cfg(feature = "network")]
    network_shutdown: Option<CancellationToken>,
    /// Health registry of the supervised network task, for observing its
    /// lifecycle (see [`DIDCacheClient::network_health`]).
    #[cfg(feature = "network")]
    network_health: Option<HealthRegistry>,
    #[cfg(feature = "did_example")]
    did_example_cache: did_example::DiDExampleCache,
    resolvers: Arc<HashMap<MethodName, VecDeque<Box<dyn AsyncResolver>>>>,
    /// Agent name -> DID mappings. Deliberately a *separate* cache from the
    /// document cache: the mapping is a web redirect and is therefore always
    /// mutable, so it always carries a TTL, whereas `DIDExpiry` would derive
    /// "no expiry" from an immutable resolved DID. See `agent_names`.
    #[cfg(feature = "agent-names")]
    agent_name_cache: Cache<[u64; 2], String>,
    #[cfg(feature = "agent-names")]
    agent_name_resolvers: Arc<Vec<Box<dyn ::agent_names::AgentNameResolver>>>,
    /// Single-flight map for the name -> DID step, mirroring `inflight`.
    ///
    /// Deliberately separate from `inflight` rather than shared: the two key
    /// spaces are different (a hashed agent name vs a hashed DID), and keeping
    /// them apart means a hash collision between the two can never make one
    /// wait on the other.
    #[cfg(feature = "agent-names")]
    agent_name_inflight: Arc<StdMutex<HashMap<[u64; 2], watch::Receiver<()>>>>,
    /// Single-flight map: concurrent cache misses for the same DID hash share
    /// one underlying resolution. The leader holds the `watch::Sender`; the
    /// stored `Receiver` is cloned by followers, who wake when the leader drops
    /// it and then read the freshly-cached document.
    inflight: Arc<StdMutex<HashMap<[u64; 2], watch::Receiver<()>>>>,
}

impl Clone for DIDCacheClient {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            cache: self.cache.clone(),
            #[cfg(feature = "network")]
            network_task_tx: self.network_task_tx.clone(),
            #[cfg(feature = "network")]
            network_task_rx: self.network_task_rx.clone(),
            #[cfg(feature = "network")]
            network_shutdown: self.network_shutdown.clone(),
            #[cfg(feature = "network")]
            network_health: self.network_health.clone(),
            #[cfg(feature = "did_example")]
            did_example_cache: self.did_example_cache.clone(),
            resolvers: self.resolvers.clone(),
            #[cfg(feature = "agent-names")]
            agent_name_cache: self.agent_name_cache.clone(),
            #[cfg(feature = "agent-names")]
            agent_name_resolvers: self.agent_name_resolvers.clone(),
            #[cfg(feature = "agent-names")]
            agent_name_inflight: self.agent_name_inflight.clone(),
            inflight: self.inflight.clone(),
        }
    }
}

/// Deterministic DID methods the client can resolve locally with no network
/// access — the fallback set used when the cache server is unreachable.
#[cfg(feature = "network")]
fn is_locally_resolvable(method: &DIDMethod) -> bool {
    matches!(method, DIDMethod::KEY | DIDMethod::PEER)
}

impl DIDCacheClient {
    /// Get a mutable reference to the inner resolver map.
    ///
    /// # Panics
    /// Panics if the client has already been cloned (Arc refcount > 1).
    /// All resolver mutations must happen during setup, before the client is shared.
    fn resolvers_mut(&mut self) -> &mut HashMap<MethodName, VecDeque<Box<dyn AsyncResolver>>> {
        Arc::get_mut(&mut self.resolvers)
            .expect("Cannot modify resolvers after DIDCacheClient has been cloned")
    }

    /// Replace all resolvers for a method with a single resolver.
    ///
    /// This is the most common operation — "I want this resolver for this method."
    /// Clears any existing resolvers for the method before inserting.
    pub fn set_resolver(&mut self, method: MethodName, resolver: Box<dyn AsyncResolver>) {
        let map = self.resolvers_mut();
        let deque = map.entry(method).or_default();
        deque.clear();
        deque.push_back(resolver);
    }

    /// Add a resolver to the front of the chain for a method (highest priority).
    ///
    /// Returns `Err` if a resolver with the same `name()` already exists for this method.
    pub fn prepend_resolver(
        &mut self,
        method: MethodName,
        resolver: Box<dyn AsyncResolver>,
    ) -> Result<(), DIDCacheError> {
        let name = resolver.name().to_string();
        let map = self.resolvers_mut();
        let deque = map.entry(method.clone()).or_default();
        if deque.iter().any(|r| r.name() == name) {
            return Err(DIDCacheError::DIDError(format!(
                "Resolver '{name}' already registered for method '{method}'"
            )));
        }
        deque.push_front(resolver);
        Ok(())
    }

    /// Add a resolver to the back of the chain for a method (lowest priority / fallback).
    ///
    /// Returns `Err` if a resolver with the same `name()` already exists for this method.
    pub fn append_resolver(
        &mut self,
        method: MethodName,
        resolver: Box<dyn AsyncResolver>,
    ) -> Result<(), DIDCacheError> {
        let name = resolver.name().to_string();
        let map = self.resolvers_mut();
        let deque = map.entry(method.clone()).or_default();
        if deque.iter().any(|r| r.name() == name) {
            return Err(DIDCacheError::DIDError(format!(
                "Resolver '{name}' already registered for method '{method}'"
            )));
        }
        deque.push_back(resolver);
        Ok(())
    }

    /// Remove all resolvers for a method.
    pub fn clear_resolvers(&mut self, method: &MethodName) {
        self.resolvers_mut().remove(method);
    }

    /// Remove a resolver at a specific index in a method's chain.
    ///
    /// Returns the removed resolver, or `None` if the index is out of bounds.
    pub fn remove_resolver(
        &mut self,
        method: &MethodName,
        index: usize,
    ) -> Option<Box<dyn AsyncResolver>> {
        let map = self.resolvers_mut();
        let deque = map.get_mut(method)?;
        let removed = deque.remove(index);
        if deque.is_empty() {
            map.remove(method);
        }
        removed
    }

    /// Find a resolver by name within a method's chain.
    ///
    /// Returns the index if found, suitable for use with `remove_resolver`.
    pub fn find_resolver(&self, method: &MethodName, name: &str) -> Option<usize> {
        self.resolvers
            .get(method)?
            .iter()
            .position(|r| r.name() == name)
    }

    /// Front end for resolving a DID
    /// Will check the cache first, and if not found, will resolve the DID
    /// Returns the initial DID, the hashed DID, and the resolved DID Document
    /// NOTE: The DID Document id may be different to the requested DID due to the DID having been updated.
    ///       The original DID should be in the `also_known_as` field of the DID Document.
    pub async fn resolve(&self, did: &str) -> Result<ResolveResponse, DIDCacheError> {
        // Size guard before any parsing
        if did.len() > self.config.max_did_size_in_bytes {
            return Err(DIDCacheError::DIDError(format!(
                "The DID size of {0} bytes exceeds the limit of {1}. Please ensure the size is less than {1}.",
                did.len(),
                self.config.max_did_size_in_bytes
            )));
        }

        // Parse the DID string (validates "did:method:specific-id" format)
        let parsed_did: DID = did
            .parse()
            .map_err(|e| DIDCacheError::DIDError(format!("Failed to parse DID: {e}")))?;

        // Check max parts in the method-specific-id
        let method_specific_id = parsed_did.method_specific_id();
        let key_parts: Vec<&str> = method_specific_id.split('.').collect();
        if key_parts.len() > self.config.max_did_parts {
            return Err(DIDCacheError::DIDError(format!(
                "The total number of keys and/or services must be less than or equal to {}, but {} were found.",
                self.config.max_did_parts,
                key_parts.len()
            )));
        }

        // Map the parsed method onto the cache's method tag. An unknown method is
        // tagged `OTHER` (rather than rejected) so a registered custom resolver
        // can still handle it; if none is registered, `local_resolve` reports it
        // as unsupported.
        let method: DIDMethod = parsed_did
            .method()
            .to_string()
            .as_str()
            .try_into()
            .unwrap_or(DIDMethod::OTHER);

        let hash = DIDCacheClient::hash_did(did);

        #[cfg(feature = "did_example")]
        // Short-circuit for example DIDs
        if matches!(method, DIDMethod::EXAMPLE)
            && let Some(doc) = self.did_example_cache.get(did)
        {
            return Ok(ResolveResponse {
                did: did.to_string(),
                method,
                did_hash: hash,
                doc: doc.clone(),
                cache_hit: true,
            });
        }

        // Check if the DID is in the cache
        if let Some(doc) = self.cache.get(&hash).await {
            debug!("DID cache hit: {}", did);
            Ok(ResolveResponse {
                did: did.to_string(),
                method,
                did_hash: hash,
                doc,
                cache_hit: true,
            })
        } else {
            debug!("DID cache miss: {}", did);
            self.resolve_uncached(did, &parsed_did, &method, hash).await
        }
    }

    /// Resolve a DID that wasn't in the cache, with single-flight dedup: when
    /// several callers miss on the same DID at once, exactly one performs the
    /// underlying resolution and the rest wait and read the cached result. On
    /// success the document is inserted into the cache.
    async fn resolve_uncached(
        &self,
        did: &str,
        parsed_did: &DID,
        method: &DIDMethod,
        hash: [u64; 2],
    ) -> Result<ResolveResponse, DIDCacheError> {
        loop {
            // Decide our role under the lock. No `.await` is held across it.
            enum Role {
                Leader(watch::Sender<()>),
                Follower(watch::Receiver<()>),
            }
            let role = {
                let mut map = self.inflight.lock().expect("inflight mutex not poisoned");
                if let Some(rx) = map.get(&hash) {
                    Role::Follower(rx.clone())
                } else {
                    let (tx, rx) = watch::channel(());
                    map.insert(hash, rx);
                    Role::Leader(tx)
                }
            };

            match role {
                Role::Follower(mut rx) => {
                    // Wait for the leader to finish (it drops the sender, which
                    // closes the channel and resolves `changed()` with an Err).
                    let _ = rx.changed().await;
                    if let Some(doc) = self.cache.get(&hash).await {
                        return Ok(ResolveResponse {
                            did: did.to_string(),
                            method: method.clone(),
                            did_hash: hash,
                            doc,
                            cache_hit: true,
                        });
                    }
                    // Leader didn't populate the cache (it errored). Loop and
                    // try to become the leader ourselves.
                    continue;
                }
                Role::Leader(tx) => {
                    // A prior leader may have populated the cache between our
                    // miss check and acquiring leadership.
                    if let Some(doc) = self.cache.get(&hash).await {
                        self.inflight
                            .lock()
                            .expect("inflight mutex not poisoned")
                            .remove(&hash);
                        drop(tx);
                        return Ok(ResolveResponse {
                            did: did.to_string(),
                            method: method.clone(),
                            did_hash: hash,
                            doc,
                            cache_hit: true,
                        });
                    }

                    let result = self.resolve_once(did, parsed_did, method, hash).await;
                    if let Ok(ref doc) = result {
                        debug!("DID cached: {}", did);
                        self.cache.insert(hash, doc.clone()).await;
                    }
                    // Release leadership and wake followers regardless of outcome.
                    self.inflight
                        .lock()
                        .expect("inflight mutex not poisoned")
                        .remove(&hash);
                    drop(tx);

                    return result.map(|doc| ResolveResponse {
                        did: did.to_string(),
                        method: method.clone(),
                        did_hash: hash,
                        doc,
                        cache_hit: false,
                    });
                }
            }
        }
    }

    /// Perform a single (un-deduplicated) resolution. In network mode, a
    /// network failure falls back to local resolution for deterministic methods
    /// (did:key / did:peer) so a down cache server doesn't break resolutions the
    /// client can compute itself.
    async fn resolve_once(
        &self,
        did: &str,
        parsed_did: &DID,
        method: &DIDMethod,
        hash: [u64; 2],
    ) -> Result<Document, DIDCacheError> {
        let _ = (did, hash, method); // some are unused without the `network` feature

        #[cfg(feature = "network")]
        {
            if self.config.service_address.is_some() {
                match self.network_resolve(did, hash).await {
                    Ok(doc) => Ok(doc),
                    Err(e) if is_locally_resolvable(method) => {
                        warn!(
                            "Network resolution failed for {did} ({e}); falling back to local \
                             resolution"
                        );
                        self.local_resolve(parsed_did).await
                    }
                    Err(e) => Err(e),
                }
            } else {
                self.local_resolve(parsed_did).await
            }
        }

        #[cfg(not(feature = "network"))]
        {
            self.local_resolve(parsed_did).await
        }
    }

    /// If you want to interact directly with the DID Document cache
    /// This will return a clone of the cache (the clone is cheap, and the cache is shared)
    /// For example, accessing cache statistics or manually inserting a DID Document
    pub fn get_cache(&self) -> Cache<[u64; 2], Document> {
        self.cache.clone()
    }

    /// Stops the network task if it is running and removes any resources.
    ///
    /// Cancels the supervisor's shutdown token, which aborts the network task
    /// and marks it `Stopped` (no restart). This is safe to call from either
    /// a sync or async context — unlike the previous `blocking_send`, which
    /// could panic when called from within a tokio runtime.
    #[cfg(feature = "network")]
    pub fn stop(&self) {
        if let Some(shutdown) = self.network_shutdown.as_ref() {
            shutdown.cancel();
        }
    }

    /// Current health of the supervised network task, or `None` when the SDK
    /// is running in local mode (no network task). Lets callers observe a
    /// network task that is restarting/degraded vs. running normally.
    #[cfg(feature = "network")]
    pub fn network_health(&self) -> Option<ComponentHealth> {
        self.network_health
            .as_ref()?
            .get("did_cache_network")
            .map(|h| h.clone())
    }

    /// Removes the specified DID from the cache
    /// Returns the removed DID Document if it was in the cache, or None if it was not
    pub async fn remove(&self, did: &str) -> Option<Document> {
        self.cache.remove(&DIDCacheClient::hash_did(did)).await
    }

    /// Add a DID Document to the cache manually
    pub async fn add_did_document(&mut self, did: &str, doc: Document) {
        let hash = DIDCacheClient::hash_did(did);
        debug!("DID manually cached: {}", did);
        self.cache.insert(hash, doc).await;
    }

    /// Convenience function to hash a DID
    pub fn hash_did(did: &str) -> [u64; 2] {
        // Use a consistent Seed so it always hashes to the same value
        HighwayHasher::default().hash128(did.as_bytes())
    }
}

/// Following are the WASM bindings for the DIDCacheClient
#[wasm_bindgen]
impl DIDCacheClient {
    /// Create a new DIDCacheClient with configuration generated from [ClientConfigBuilder](config::ClientConfigBuilder)
    ///
    /// Will return an error if the configuration is invalid.
    ///
    /// Establishes websocket connection and sets up the cache.
    // using Self instead of DIDCacheClient leads to E0401 errors in dependent crates
    // this is due to wasm_bindgen generated code (check via `cargo expand`)
    pub async fn new(config: DIDCacheConfig) -> Result<DIDCacheClient, DIDCacheError> {
        // Create the cache with per-entry expiry:
        // - Immutable DID methods (key, peer, jwk, ethr, pkh) → no TTL (evicted only by capacity)
        // - Mutable DID methods (web, webvh, cheqd, scid, ebsi) → expire after cache_ttl seconds
        let cache = Cache::builder()
            .max_capacity(config.cache_capacity.into())
            .expire_after(DIDExpiry {
                mutable_ttl: Duration::from_secs(config.cache_ttl.into()),
            })
            .build();

        // Register built-in resolvers
        let mut resolvers: HashMap<MethodName, VecDeque<Box<dyn AsyncResolver>>> = HashMap::new();

        // Local (sync) resolvers via blanket impl
        resolvers
            .entry(MethodName::Key)
            .or_default()
            .push_back(Box::new(affinidi_did_resolver_traits::KeyResolver));
        resolvers
            .entry(MethodName::Peer)
            .or_default()
            .push_back(Box::new(affinidi_did_resolver_traits::PeerResolver));
        // Network resolvers
        resolvers
            .entry(MethodName::Ethr)
            .or_default()
            .push_back(Box::new(network_resolvers::EthrResolver));
        resolvers
            .entry(MethodName::Pkh)
            .or_default()
            .push_back(Box::new(network_resolvers::PkhResolver));
        resolvers
            .entry(MethodName::Web)
            .or_default()
            .push_back(Box::new(network_resolvers::WebResolver::new()));
        #[cfg(feature = "did-jwk")]
        resolvers
            .entry(MethodName::Jwk)
            .or_default()
            .push_back(Box::new(network_resolvers::JwkResolver));
        #[cfg(feature = "did-webvh")]
        resolvers
            .entry(MethodName::Webvh)
            .or_default()
            .push_back(Box::new(network_resolvers::WebvhResolver));
        #[cfg(feature = "did-cheqd")]
        resolvers
            .entry(MethodName::Cheqd)
            .or_default()
            .push_back(Box::new(network_resolvers::CheqdResolver));
        #[cfg(feature = "did-scid")]
        resolvers
            .entry(MethodName::Scid)
            .or_default()
            .push_back(Box::new(network_resolvers::ScidResolver));
        #[cfg(feature = "did-ebsi")]
        resolvers
            .entry(MethodName::Ebsi)
            .or_default()
            .push_back(Box::new(network_resolvers::EbsiResolver));

        let resolvers = Arc::new(resolvers);

        // Agent name (DID shortcut) support. The mapping cache always carries a
        // TTL: an agent name is a web redirect and can change at any time,
        // regardless of how immutable the DID it currently points at is.
        #[cfg(feature = "agent-names")]
        let agent_name_cache: Cache<[u64; 2], String> = Cache::builder()
            .max_capacity(config.agent_name_cache_capacity.into())
            .time_to_live(Duration::from_secs(config.agent_name_ttl.into()))
            .build();
        #[cfg(feature = "agent-names")]
        let agent_name_resolvers: Arc<Vec<Box<dyn ::agent_names::AgentNameResolver>>> =
            Arc::new(vec![
                Box::new(::agent_names::HttpRedirectResolver::new()) as Box<_>
            ]);

        #[cfg(feature = "network")]
        let mut client = Self {
            config,
            cache,
            network_task_tx: None,
            network_task_rx: None,
            network_shutdown: None,
            network_health: None,
            #[cfg(feature = "did_example")]
            did_example_cache: did_example::DiDExampleCache::new(),
            resolvers: resolvers.clone(),
            #[cfg(feature = "agent-names")]
            agent_name_cache: agent_name_cache.clone(),
            #[cfg(feature = "agent-names")]
            agent_name_resolvers: agent_name_resolvers.clone(),
            #[cfg(feature = "agent-names")]
            agent_name_inflight: Arc::new(StdMutex::new(HashMap::new())),
            inflight: Arc::new(StdMutex::new(HashMap::new())),
        };
        #[cfg(not(feature = "network"))]
        let client = Self {
            config,
            cache,
            #[cfg(feature = "did_example")]
            did_example_cache: did_example::DiDExampleCache::new(),
            resolvers,
            #[cfg(feature = "agent-names")]
            agent_name_cache,
            #[cfg(feature = "agent-names")]
            agent_name_resolvers,
            #[cfg(feature = "agent-names")]
            agent_name_inflight: Arc::new(StdMutex::new(HashMap::new())),
            inflight: Arc::new(StdMutex::new(HashMap::new())),
        };

        #[cfg(feature = "network")]
        {
            if client.config.service_address.is_some() {
                // Running in network mode

                // Channel to communicate from SDK to network task
                let (sdk_tx, task_rx) = mpsc::channel(32);
                // Channel to communicate from network task to SDK
                let (task_tx, sdk_rx) = mpsc::channel(32);

                client.network_task_tx = Some(sdk_tx);
                client.network_task_rx = Some(Arc::new(Mutex::new(sdk_rx)));

                // Start the network task under the shared TaskSupervisor. The
                // task reconnects internally on transient drops; the
                // supervisor catches the task itself *dying* (a panic or a
                // propagated fatal error) and restarts it with capped backoff
                // — a silent task death would otherwise leave the SDK
                // permanently unable to resolve over the network. The
                // supervisor owns cancellation: `stop()` cancels the token and
                // the supervisor aborts the task with no restart. The SDK→task
                // receiver is shared behind a `Mutex` so each (re)start
                // re-locks the same channel rather than rebuilding it.
                let network_shutdown = CancellationToken::new();
                let supervisor = TaskSupervisor::new(network_shutdown.clone());
                client.network_health = Some(supervisor.registry());

                let task_rx = Arc::new(Mutex::new(task_rx));
                let task_config = client.config.clone();
                let task_shutdown = network_shutdown.clone();
                supervisor.spawn("did_cache_network", false, move || {
                    let task_rx = task_rx.clone();
                    let task_tx = task_tx.clone();
                    let task_config = task_config.clone();
                    let shutdown = task_shutdown.clone();
                    async move {
                        let mut rx = task_rx.lock().await;
                        NetworkTask::run(task_config, &mut rx, &task_tx, shutdown).await
                    }
                });
                client.network_shutdown = Some(network_shutdown);

                if let Some(arc_rx) = client.network_task_rx.as_ref() {
                    // Wait for the network task to signal it's connected — but
                    // bounded, and never via `unwrap()`:
                    // - Connected: ready.
                    // - timeout (server unreachable): proceed in degraded mode;
                    //   the task keeps reconnecting with backoff, and resolution
                    //   falls back to local for deterministic methods.
                    // - channel closed (task died/panicked before signalling):
                    //   return an error rather than panicking the caller.
                    let mut rx = arc_rx.lock().await;
                    match tokio::time::timeout(client.config.network_timeout, rx.recv()).await {
                        Ok(Some(WSCommands::Connected)) => {
                            debug!("Network task connected");
                        }
                        Ok(Some(other)) => {
                            warn!(
                                "Unexpected first message from network task ({other:?}); \
                                 continuing — will reconnect in the background"
                            );
                        }
                        Ok(None) => {
                            return Err(DIDCacheError::TransportError(
                                "Network task terminated before signalling readiness".to_string(),
                            ));
                        }
                        Err(_elapsed) => {
                            warn!(
                                "Cache server not reachable at startup; continuing in degraded \
                                 mode (local resolution for did:key/did:peer). The network task \
                                 will keep retrying with backoff."
                            );
                        }
                    }
                }
            }
        }

        Ok(client)
    }

    pub async fn wasm_resolve(&self, did: &str) -> Result<JsValue, DIDCacheError> {
        let response = self.resolve(did).await?;

        match serde_wasm_bindgen::to_value(&response.doc) {
            Ok(values) => Ok(values),
            Err(err) => Err(DIDCacheError::DIDError(format!(
                "Error serializing DID Document: {err}",
            ))),
        }
    }

    #[cfg(feature = "did_example")]
    pub fn add_example_did(&mut self, doc: &str) -> Result<(), DIDCacheError> {
        self.did_example_cache
            .insert_from_string(doc)
            .map_err(|e| DIDCacheError::DIDError(format!("Couldn't parse example DID: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DID_KEY: &str = "did:key:z6MkiToqovww7vYtxm1xNM15u9JzqzUFZ1k7s7MazYJUyAxv";

    async fn basic_local_client() -> DIDCacheClient {
        let config = config::DIDCacheConfigBuilder::default().build();
        DIDCacheClient::new(config).await.unwrap()
    }

    // -----------------------------------------------------------------------
    // Cache operations
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn remove_existing_cached_did() {
        let client = basic_local_client().await;

        // Resolve a DID which automatically adds it to the cache
        let response = client.resolve(DID_KEY).await.unwrap();
        let removed_doc = client.remove(DID_KEY).await;
        assert_eq!(removed_doc, Some(response.doc));
    }

    #[tokio::test]
    async fn remove_non_existing_cached_did() {
        let client = basic_local_client().await;

        // We haven't resolved the cache, so it shouldn't be in the cache
        let removed_doc = client.remove(DID_KEY).await;
        assert_eq!(removed_doc, None);
    }

    #[tokio::test]
    async fn resolve_returns_cache_hit_on_second_call() {
        let client = basic_local_client().await;

        let first = client.resolve(DID_KEY).await.unwrap();
        assert!(!first.cache_hit);

        let second = client.resolve(DID_KEY).await.unwrap();
        assert!(second.cache_hit);
        assert_eq!(first.doc, second.doc);
        assert_eq!(first.did_hash, second.did_hash);
    }

    #[tokio::test]
    async fn add_did_document_makes_it_retrievable() {
        let mut client = basic_local_client().await;

        // Resolve to get a valid document, then remove it
        let response = client.resolve(DID_KEY).await.unwrap();
        client.remove(DID_KEY).await;

        // Manually add it back
        client.add_did_document(DID_KEY, response.doc.clone()).await;

        // Should be a cache hit now
        let cached = client.resolve(DID_KEY).await.unwrap();
        assert!(cached.cache_hit);
        assert_eq!(cached.doc, response.doc);
    }

    #[tokio::test]
    async fn get_cache_returns_shared_cache() {
        let client = basic_local_client().await;
        client.resolve(DID_KEY).await.unwrap();

        let cache = client.get_cache();
        let hash = DIDCacheClient::hash_did(DID_KEY);
        assert!(cache.get(&hash).await.is_some());
    }

    #[tokio::test]
    async fn clone_shares_cache() {
        let client = basic_local_client().await;
        let cloned = client.clone();

        // Resolve on original, visible on clone
        client.resolve(DID_KEY).await.unwrap();
        let from_clone = cloned.resolve(DID_KEY).await.unwrap();
        assert!(from_clone.cache_hit);
    }

    // -----------------------------------------------------------------------
    // resolve() validation
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn resolve_rejects_did_exceeding_size_limit() {
        let config = config::DIDCacheConfigBuilder::default()
            .with_max_did_size_in_bytes(20)
            .build();
        let client = DIDCacheClient::new(config).await.unwrap();

        let result = client.resolve(DID_KEY).await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("exceeds the limit"), "got: {err}");
    }

    #[tokio::test]
    async fn resolve_rejects_malformed_did() {
        let client = basic_local_client().await;

        // Not enough colons
        let result = client.resolve("not-a-did").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn resolve_rejects_too_many_parts() {
        let config = config::DIDCacheConfigBuilder::default()
            .with_max_did_parts(1)
            .build();
        let client = DIDCacheClient::new(config).await.unwrap();

        // did:peer DIDs have multiple dot-separated parts in method-specific-id
        let did = "did:peer:2.Vz6MkiToqovww7vYtxm1xNM15u9JzqzUFZ1k7s7MazYJUyAxv.EzQ3shQLqRUza6AMJFbPuMdvFRFWm1wKviQRnQSC1fScovJN4s";
        let result = client.resolve(did).await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("keys and/or services"), "got: {err}");
    }

    #[tokio::test]
    async fn resolve_populates_response_fields() {
        let client = basic_local_client().await;

        let response = client.resolve(DID_KEY).await.unwrap();
        assert_eq!(response.did, DID_KEY);
        assert_eq!(response.method, DIDMethod::KEY);
        assert_eq!(response.did_hash, DIDCacheClient::hash_did(DID_KEY));
        assert!(!response.cache_hit);
        assert_eq!(response.doc.id.as_str(), DID_KEY);
    }

    // -----------------------------------------------------------------------
    // hash_did
    // -----------------------------------------------------------------------

    #[test]
    fn hash_did_is_deterministic() {
        let hash1 = DIDCacheClient::hash_did(DID_KEY);
        let hash2 = DIDCacheClient::hash_did(DID_KEY);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn hash_did_differs_for_different_dids() {
        let hash1 = DIDCacheClient::hash_did("did:key:abc");
        let hash2 = DIDCacheClient::hash_did("did:key:def");
        assert_ne!(hash1, hash2);
    }

    // -----------------------------------------------------------------------
    // DIDMethod Display / TryFrom
    // -----------------------------------------------------------------------

    #[test]
    fn did_method_display_roundtrips() {
        let methods = [
            DIDMethod::ETHR,
            DIDMethod::JWK,
            DIDMethod::KEY,
            DIDMethod::PEER,
            DIDMethod::PKH,
            DIDMethod::WEB,
            DIDMethod::WEBVH,
            DIDMethod::CHEQD,
            DIDMethod::SCID,
        ];
        for method in &methods {
            let s = method.to_string();
            let back: DIDMethod = s.as_str().try_into().unwrap();
            assert_eq!(&back, method);
        }
    }

    #[test]
    fn did_method_try_from_is_case_insensitive() {
        let result: Result<DIDMethod, _> = "KEY".try_into();
        assert_eq!(result.unwrap(), DIDMethod::KEY);

        let result: Result<DIDMethod, _> = "Ethr".try_into();
        assert_eq!(result.unwrap(), DIDMethod::ETHR);
    }

    #[test]
    fn did_method_try_from_string_works() {
        let result: Result<DIDMethod, _> = String::from("peer").try_into();
        assert_eq!(result.unwrap(), DIDMethod::PEER);
    }

    #[test]
    fn did_method_try_from_unknown_returns_error() {
        let result: Result<DIDMethod, _> = "unknown".try_into();
        assert!(result.is_err());
        match result.unwrap_err() {
            DIDCacheError::UnsupportedMethod(m) => assert_eq!(m, "unknown"),
            other => panic!("expected UnsupportedMethod, got: {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // DIDMethod::is_mutable
    // -----------------------------------------------------------------------

    #[test]
    fn immutable_methods_are_not_mutable() {
        assert!(!DIDMethod::KEY.is_mutable());
        assert!(!DIDMethod::PEER.is_mutable());
        assert!(!DIDMethod::JWK.is_mutable());
        assert!(!DIDMethod::ETHR.is_mutable());
        assert!(!DIDMethod::PKH.is_mutable());
        assert!(!DIDMethod::EXAMPLE.is_mutable());
    }

    #[test]
    fn mutable_methods_are_mutable() {
        assert!(DIDMethod::WEB.is_mutable());
        assert!(DIDMethod::WEBVH.is_mutable());
        assert!(DIDMethod::CHEQD.is_mutable());
        assert!(DIDMethod::SCID.is_mutable());
    }

    // -----------------------------------------------------------------------
    // Per-method cache TTL
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn immutable_did_survives_beyond_ttl() {
        // Configure a very short TTL (1 second)
        let config = config::DIDCacheConfigBuilder::default()
            .with_cache_ttl(1)
            .build();
        let client = DIDCacheClient::new(config).await.unwrap();

        // Resolve a did:key (immutable)
        client.resolve(DID_KEY).await.unwrap();

        // Wait longer than the TTL
        tokio::time::sleep(Duration::from_secs(2)).await;

        // Sync Moka's internal state so expired entries are actually evicted
        client.cache.run_pending_tasks().await;

        // Immutable DID should still be cached (no TTL applied)
        let result = client.resolve(DID_KEY).await.unwrap();
        assert!(
            result.cache_hit,
            "immutable did:key should survive beyond TTL"
        );
    }

    // -----------------------------------------------------------------------
    // W3 resilience: single-flight dedup + degraded-mode local fallback
    // -----------------------------------------------------------------------

    use std::future::Future;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Test resolver that counts how many times it is actually invoked and
    /// sleeps before returning, so concurrent callers overlap on the miss.
    struct CountingResolver {
        calls: Arc<AtomicUsize>,
        delay: Duration,
        doc: Document,
    }

    impl AsyncResolver for CountingResolver {
        fn name(&self) -> &str {
            "counting-test-resolver"
        }
        fn resolve<'a>(
            &'a self,
            _did: &'a DID,
        ) -> Pin<Box<dyn Future<Output = Resolution> + Send + 'a>> {
            let calls = self.calls.clone();
            let delay = self.delay;
            let doc = self.doc.clone();
            Box::pin(async move {
                calls.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(delay).await;
                Some(Ok(doc))
            })
        }
    }

    /// `ResolveResponse` is `#[non_exhaustive]`, so `new` is the construction
    /// path for anything outside this crate — a fixture or a mock resolver.
    /// Fields stay readable.
    #[test]
    fn resolve_response_is_built_via_new() {
        let doc = Document::new("did:example:123").unwrap();
        let response = ResolveResponse::new(
            "did:example:123".to_string(),
            DIDMethod::EXAMPLE,
            DIDCacheClient::hash_did("did:example:123"),
            doc,
            true,
        );

        assert_eq!(response.did, "did:example:123");
        assert_eq!(response.method, DIDMethod::EXAMPLE);
        assert_eq!(
            response.did_hash,
            DIDCacheClient::hash_did("did:example:123")
        );
        assert_eq!(response.doc.id.as_str(), "did:example:123");
        assert!(response.cache_hit);
    }

    #[tokio::test]
    async fn concurrent_misses_resolve_exactly_once() {
        let did = "did:web:example.com";
        let calls = Arc::new(AtomicUsize::new(0));
        let mut client = basic_local_client().await;
        client.set_resolver(
            MethodName::Web,
            Box::new(CountingResolver {
                calls: calls.clone(),
                delay: Duration::from_millis(100),
                doc: Document::new(did).unwrap(),
            }),
        );

        // Fire many concurrent resolutions of the same uncached DID.
        let mut handles = Vec::new();
        for _ in 0..10 {
            let c = client.clone();
            let d = did.to_string();
            handles.push(tokio::spawn(async move { c.resolve(&d).await }));
        }
        for h in handles {
            let res = h.await.unwrap().expect("resolve succeeds");
            assert_eq!(res.doc.id.as_str(), did);
        }

        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "10 concurrent misses for one DID must trigger exactly one resolution"
        );
    }

    #[cfg(feature = "network")]
    #[tokio::test]
    async fn network_mode_degrades_then_falls_back_to_local() {
        // Point at a port with nothing listening: construction must neither
        // panic nor hang, and did:key must still resolve via local fallback
        // while the cache server is unreachable.
        let config = config::DIDCacheConfigBuilder::default()
            .with_network_mode("ws://127.0.0.1:9")
            .with_network_timeout(500)
            .build();
        let client = DIDCacheClient::new(config)
            .await
            .expect("client constructs in degraded mode when the server is down");

        let res = client
            .resolve(DID_KEY)
            .await
            .expect("did:key resolves locally while the cache server is down");
        assert_eq!(res.doc.id.as_str(), DID_KEY);

        // The network task is supervised, so its health is observable even
        // while it is busy reconnecting in the background.
        assert!(
            client.network_health().is_some(),
            "a network-mode client must expose supervised network-task health"
        );
    }

    /// A panic in the network task must be caught by the supervisor and the
    /// task restarted (it would otherwise die silently, leaving the SDK
    /// permanently unable to resolve over the network), with the fault
    /// recorded. Mirrors the SDK's wiring — the SDK→task receiver shared
    /// behind a `Mutex` and re-locked per (re)start — with an injected panic,
    /// and confirms a clean shutdown stops it without further restarts.
    #[cfg(feature = "network")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn supervised_network_task_restarts_after_panic() {
        let (_sdk_tx, task_rx) = mpsc::channel::<WSCommands>(4);
        let task_rx = Arc::new(Mutex::new(task_rx));
        let token = CancellationToken::new();
        let supervisor = TaskSupervisor::new(token.clone());
        let registry = supervisor.registry();
        let attempts = Arc::new(std::sync::atomic::AtomicU32::new(0));

        {
            let task_rx = task_rx.clone();
            let attempts = attempts.clone();
            supervisor.spawn("did_cache_network", false, move || {
                let task_rx = task_rx.clone();
                let attempts = attempts.clone();
                async move {
                    // Prove the shared receiver re-locks cleanly across restarts.
                    let _rx = task_rx.lock().await;
                    if attempts.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                        panic!("injected network task panic");
                    }
                    std::future::pending::<()>().await; // stay Running until cancel
                    Ok::<(), crate::errors::DIDCacheError>(())
                }
            });
        }

        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            let restarted = attempts.load(std::sync::atomic::Ordering::SeqCst) >= 2;
            let running = registry
                .get("did_cache_network")
                .map(|h| h.state == ComponentState::Running && h.restarts >= 1)
                .unwrap_or(false);
            if restarted && running {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "supervisor did not restart the network task after a panic"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(
            registry
                .get("did_cache_network")
                .and_then(|h| h.last_error.clone())
                .is_some_and(|e| e.contains("panicked")),
            "the panic must be recorded as the last error"
        );

        // Cancelling the token must stop the task without restarting it.
        token.cancel();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            if registry
                .get("did_cache_network")
                .map(|h| h.state == ComponentState::Stopped)
                .unwrap_or(false)
            {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "network task did not stop on cancellation"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
}
