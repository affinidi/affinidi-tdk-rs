//! Handles the initial configuration for the DID Cache Client.
//!
//! Call the [DIDCacheConfigBuilder] to create a new configuration.
//!
//! Example: Running in local mode with defaults:
//! ```rust
//! use affinidi_did_resolver_cache_sdk::config::DIDCacheConfigBuilder;
//! let config = DIDCacheConfigBuilder::default().build();
//! ```
//!
//! Example: Running in network mode with custom settings:
//! ```rust,ignore
//! use affinidi_did_resolver_cache_sdk::config::DIDCacheConfigBuilder;
//! let config = DIDCacheConfigBuilder::default()
//!     .with_network_mode("ws://127.0.0.1:8080/did/v1/ws")
//!     .with_cache_capacity(500)
//!     .with_cache_ttl(60)
//!     .with_network_timeout(10000)
//!     .with_network_cache_limit_count(200)
//!     .build();
//! ```
//!

#[cfg(feature = "network")]
use std::time::Duration;
use wasm_bindgen::prelude::*;

/// Configuration for the DID Cache client.
///
/// Use the [DIDCacheConfigBuilder] to create a new configuration.
#[derive(Clone, Debug)]
#[wasm_bindgen(getter_with_clone)]
pub struct DIDCacheConfig {
    #[cfg(feature = "network")]
    pub(crate) service_address: Option<String>,
    pub(crate) cache_capacity: u32,
    pub(crate) cache_ttl: u32,
    #[cfg(feature = "network")]
    pub(crate) network_timeout: Duration,
    #[cfg(feature = "network")]
    pub(crate) network_cache_limit_count: u32,
    pub(crate) max_did_parts: usize,
    pub(crate) max_did_size_in_bytes: usize,
    #[cfg(feature = "agent-names")]
    pub(crate) agent_name_ttl: u32,
    #[cfg(feature = "agent-names")]
    pub(crate) agent_name_cache_capacity: u32,
    #[cfg(all(feature = "agent-names", feature = "network"))]
    pub(crate) agent_names_over_websocket: bool,
}

/// DID Cache Config Builder to construct options required for the client.
/// You must at least set the service address.
///
/// - service_address: REQUIRED: The address of the service to connect to.
/// - cache_capacity: The maximum number of items to store in the local cache (default: 100).
/// - cache_ttl: The time-to-live in seconds for each item in the local cache (default: 300 (5 Minutes)).
/// - network_timeout: The timeout for network requests in milliseconds (default: 5000 (5 seconds)).
/// - network_cache_limit_count: The maximum number of items to store in the network cache (default: 100).
pub struct DIDCacheConfigBuilder {
    #[cfg(feature = "network")]
    service_address: Option<String>,
    cache_capacity: u32,
    cache_ttl: u32,
    #[cfg(feature = "network")]
    network_timeout: u32,
    #[cfg(feature = "network")]
    network_cache_limit_count: u32,
    max_did_parts: usize,
    max_did_size_in_bytes: usize,
    #[cfg(feature = "agent-names")]
    agent_name_ttl: u32,
    #[cfg(feature = "agent-names")]
    agent_name_cache_capacity: u32,
    #[cfg(all(feature = "agent-names", feature = "network"))]
    agent_names_over_websocket: bool,
}

impl Default for DIDCacheConfigBuilder {
    fn default() -> Self {
        Self {
            #[cfg(feature = "network")]
            service_address: None,
            cache_capacity: 100,
            cache_ttl: 300,
            #[cfg(feature = "network")]
            network_timeout: 5000,
            #[cfg(feature = "network")]
            network_cache_limit_count: 100,
            max_did_parts: 12,
            max_did_size_in_bytes: 1_000,
            #[cfg(feature = "agent-names")]
            agent_name_ttl: 300,
            #[cfg(feature = "agent-names")]
            agent_name_cache_capacity: 1_000,
            #[cfg(all(feature = "agent-names", feature = "network"))]
            agent_names_over_websocket: false,
        }
    }
}

impl DIDCacheConfigBuilder {
    /// Enables network mode and sets the service address.
    /// Example: `ws://127.0.0.1:8080/did/v1/ws`
    #[cfg(feature = "network")]
    pub fn with_network_mode(mut self, service_address: &str) -> Self {
        self.service_address = Some(service_address.into());
        self
    }

    /// Set the cache capacity (approx)
    /// Default: 100 items
    pub fn with_cache_capacity(mut self, cache_capacity: u32) -> Self {
        self.cache_capacity = cache_capacity;
        self
    }

    /// Set the time-to-live in seconds for mutable DID methods (web, webvh, cheqd, scid)
    /// in the local cache. Immutable methods (key, peer, jwk, ethr, pkh) are cached
    /// indefinitely and only evicted by capacity pressure.
    /// Default: 300 (5 Minutes)
    pub fn with_cache_ttl(mut self, cache_ttl: u32) -> Self {
        self.cache_ttl = cache_ttl;
        self
    }

    /// Set the timeout for network requests in milliseconds.
    /// Default: 5000 (5 seconds)
    #[cfg(feature = "network")]
    pub fn with_network_timeout(mut self, network_timeout: u32) -> Self {
        self.network_timeout = network_timeout;
        self
    }

    /// Set the network cache limit count
    /// Default: 100 items
    #[cfg(feature = "network")]
    pub fn with_network_cache_limit_count(mut self, limit_count: u32) -> Self {
        self.network_cache_limit_count = limit_count;
        self
    }

    /// Set maximum number of parts after splitting method-specific-id on "."
    /// Default: 12 parts
    pub fn with_max_did_parts(mut self, max_did_parts: usize) -> Self {
        self.max_did_parts = max_did_parts;
        self
    }

    /// Set maximum size in bytes of did to be resolved
    /// Default: 1_000 bytes
    pub fn with_max_did_size_in_bytes(mut self, max_did_size_in_bytes: usize) -> Self {
        self.max_did_size_in_bytes = max_did_size_in_bytes;
        self
    }

    /// Set the time-to-live in seconds for cached agent name to DID mappings.
    ///
    /// Unlike DID documents, this **always** applies: an agent name mapping is a
    /// web redirect and is therefore always mutable, no matter how immutable the
    /// DID it points at happens to be.
    /// Default: 300 (5 minutes)
    #[cfg(feature = "agent-names")]
    pub fn with_agent_name_ttl(mut self, ttl: u32) -> Self {
        self.agent_name_ttl = ttl;
        self
    }

    /// Set the capacity of the agent name to DID mapping cache.
    ///
    /// Entries are short strings rather than whole documents, so this can be far
    /// larger than the document cache for the same memory.
    /// Default: 1000 items
    #[cfg(feature = "agent-names")]
    pub fn with_agent_name_cache_capacity(mut self, capacity: u32) -> Self {
        self.agent_name_cache_capacity = capacity;
        self
    }

    /// Resolve agent names over the WebSocket connection instead of through the
    /// registered backends.
    ///
    /// Saves a round trip and a transport: the cache server does name → DID →
    /// document in one exchange, rather than the client making an HTTP call for
    /// name → DID and then a WebSocket call for DID → document.
    ///
    /// **Requires `affinidi-did-resolver-cache-server` 0.9.9 or newer.** Off by
    /// default, and deliberately not auto-detected: an older server answers a
    /// name request with a generic "failed to parse DID" error, and telling that
    /// apart from a real failure would mean matching on error strings. The
    /// failure is at least clean — a reported error, not a hang — so enabling
    /// this against an old server is safe, just useless.
    #[cfg(all(feature = "agent-names", feature = "network"))]
    pub fn with_agent_names_over_websocket(mut self, enabled: bool) -> Self {
        self.agent_names_over_websocket = enabled;
        self
    }

    /// Build the [ClientConfig].
    pub fn build(self) -> DIDCacheConfig {
        DIDCacheConfig {
            #[cfg(feature = "network")]
            service_address: self.service_address,
            cache_capacity: self.cache_capacity,
            cache_ttl: self.cache_ttl,
            #[cfg(feature = "network")]
            network_timeout: Duration::from_millis(self.network_timeout.into()),
            #[cfg(feature = "network")]
            network_cache_limit_count: self.network_cache_limit_count,
            max_did_parts: self.max_did_parts,
            max_did_size_in_bytes: self.max_did_size_in_bytes,
            #[cfg(feature = "agent-names")]
            agent_name_ttl: self.agent_name_ttl,
            #[cfg(feature = "agent-names")]
            agent_name_cache_capacity: self.agent_name_cache_capacity,
            #[cfg(all(feature = "agent-names", feature = "network"))]
            agent_names_over_websocket: self.agent_names_over_websocket,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_has_expected_values() {
        let config = DIDCacheConfigBuilder::default().build();
        assert_eq!(config.cache_capacity, 100);
        assert_eq!(config.cache_ttl, 300);
        assert_eq!(config.max_did_parts, 12);
        assert_eq!(config.max_did_size_in_bytes, 1_000);
    }

    #[test]
    fn builder_overrides_cache_capacity() {
        let config = DIDCacheConfigBuilder::default()
            .with_cache_capacity(500)
            .build();
        assert_eq!(config.cache_capacity, 500);
    }

    #[test]
    fn builder_overrides_cache_ttl() {
        let config = DIDCacheConfigBuilder::default().with_cache_ttl(60).build();
        assert_eq!(config.cache_ttl, 60);
    }

    #[test]
    fn builder_overrides_max_did_parts() {
        let config = DIDCacheConfigBuilder::default()
            .with_max_did_parts(5)
            .build();
        assert_eq!(config.max_did_parts, 5);
    }

    #[test]
    fn builder_overrides_max_did_size() {
        let config = DIDCacheConfigBuilder::default()
            .with_max_did_size_in_bytes(2_000)
            .build();
        assert_eq!(config.max_did_size_in_bytes, 2_000);
    }

    #[test]
    fn builder_chaining_works() {
        let config = DIDCacheConfigBuilder::default()
            .with_cache_capacity(200)
            .with_cache_ttl(120)
            .with_max_did_parts(8)
            .with_max_did_size_in_bytes(500)
            .build();
        assert_eq!(config.cache_capacity, 200);
        assert_eq!(config.cache_ttl, 120);
        assert_eq!(config.max_did_parts, 8);
        assert_eq!(config.max_did_size_in_bytes, 500);
    }

    #[test]
    fn config_is_cloneable() {
        let config = DIDCacheConfigBuilder::default().build();
        let cloned = config.clone();
        assert_eq!(config.cache_capacity, cloned.cache_capacity);
        assert_eq!(config.cache_ttl, cloned.cache_ttl);
        assert_eq!(config.max_did_parts, cloned.max_did_parts);
        assert_eq!(config.max_did_size_in_bytes, cloned.max_did_size_in_bytes);
    }
}
