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
//! ```rust
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

    /// Set the time-to-live in seconds for each item in the local cache.
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
    /// Default: 5 parts
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
        }
    }
}
