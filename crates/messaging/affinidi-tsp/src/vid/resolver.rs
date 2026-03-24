//! VID resolution — resolve a VID string to its public keys and endpoints.
//!
//! The resolver detects whether a VID is a DID and delegates accordingly.
//! Non-DID VIDs can be resolved through custom implementations or an
//! in-memory store.

use std::collections::HashMap;
use std::sync::RwLock;

use crate::error::TspError;
use crate::vid::{ResolvedVid, is_did};

/// Resolves a VID string to its public keys and service endpoints.
///
/// Implementations should:
/// - Detect DIDs (starting with "did:") and delegate to DID resolution
/// - Support other VID types as needed
/// - Cache results where appropriate
pub trait VidResolver: Send + Sync {
    /// Resolve a VID to its public keys and endpoints.
    fn resolve(&self, vid: &str) -> Result<ResolvedVid, TspError>;
}

/// A simple in-memory VID resolver for testing and local VIDs.
///
/// DIDs can optionally be delegated to a [`DidVidResolver`] if the
/// `did-resolver` feature is enabled.
pub struct MemoryVidResolver {
    vids: RwLock<HashMap<String, ResolvedVid>>,
}

impl MemoryVidResolver {
    pub fn new() -> Self {
        Self {
            vids: RwLock::new(HashMap::new()),
        }
    }

    /// Register a resolved VID in the store.
    pub fn insert(&self, vid: ResolvedVid) {
        self.vids.write().unwrap().insert(vid.id.clone(), vid);
    }

    /// Remove a VID from the store.
    pub fn remove(&self, id: &str) -> Option<ResolvedVid> {
        self.vids.write().unwrap().remove(id)
    }
}

impl Default for MemoryVidResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl VidResolver for MemoryVidResolver {
    fn resolve(&self, vid: &str) -> Result<ResolvedVid, TspError> {
        self.vids
            .read()
            .unwrap()
            .get(vid)
            .cloned()
            .ok_or_else(|| TspError::VidNotFound(vid.to_string()))
    }
}

/// A delegating resolver that checks VID type and routes accordingly.
///
/// - DIDs → delegates to a DID-specific resolver (or falls back to memory)
/// - Other VIDs → looks up in the memory store
pub struct DelegatingVidResolver {
    memory: MemoryVidResolver,
    did_resolver: Option<Box<dyn VidResolver>>,
}

impl DelegatingVidResolver {
    pub fn new() -> Self {
        Self {
            memory: MemoryVidResolver::new(),
            did_resolver: None,
        }
    }

    /// Set a DID-specific resolver for handling `did:*` VIDs.
    pub fn with_did_resolver(mut self, resolver: Box<dyn VidResolver>) -> Self {
        self.did_resolver = Some(resolver);
        self
    }

    /// Register a resolved VID in the memory store.
    pub fn insert(&self, vid: ResolvedVid) {
        self.memory.insert(vid);
    }
}

impl Default for DelegatingVidResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl VidResolver for DelegatingVidResolver {
    fn resolve(&self, vid: &str) -> Result<ResolvedVid, TspError> {
        // Try memory first (covers both DIDs and non-DIDs registered locally)
        if let Ok(resolved) = self.memory.resolve(vid) {
            return Ok(resolved);
        }

        // For DIDs, delegate to the DID resolver if available
        if is_did(vid) {
            if let Some(did_resolver) = &self.did_resolver {
                return did_resolver.resolve(vid);
            }
        }

        Err(TspError::VidNotFound(vid.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_vid() -> ResolvedVid {
        ResolvedVid {
            id: "did:example:alice".to_string(),
            signing_key: [1u8; 32],
            encryption_key: [2u8; 32],
            endpoints: vec![],
        }
    }

    #[test]
    fn memory_resolver_insert_resolve() {
        let resolver = MemoryVidResolver::new();
        resolver.insert(test_vid());

        let resolved = resolver.resolve("did:example:alice").unwrap();
        assert_eq!(resolved.signing_key, [1u8; 32]);
    }

    #[test]
    fn memory_resolver_not_found() {
        let resolver = MemoryVidResolver::new();
        assert!(resolver.resolve("did:example:nobody").is_err());
    }

    #[test]
    fn memory_resolver_remove() {
        let resolver = MemoryVidResolver::new();
        resolver.insert(test_vid());
        assert!(resolver.resolve("did:example:alice").is_ok());

        resolver.remove("did:example:alice");
        assert!(resolver.resolve("did:example:alice").is_err());
    }

    #[test]
    fn delegating_resolver_memory_first() {
        let resolver = DelegatingVidResolver::new();
        resolver.insert(test_vid());

        // Memory lookup should work for DIDs too
        let resolved = resolver.resolve("did:example:alice").unwrap();
        assert_eq!(resolved.id, "did:example:alice");
    }

    #[test]
    fn delegating_resolver_non_did() {
        let resolver = DelegatingVidResolver::new();
        resolver.insert(ResolvedVid {
            id: "keri:EDP12345".to_string(),
            signing_key: [3u8; 32],
            encryption_key: [4u8; 32],
            endpoints: vec![],
        });

        let resolved = resolver.resolve("keri:EDP12345").unwrap();
        assert_eq!(resolved.signing_key, [3u8; 32]);
    }

    #[test]
    fn delegating_resolver_falls_through_to_did_resolver() {
        // Create a mock DID resolver
        struct MockDidResolver;
        impl VidResolver for MockDidResolver {
            fn resolve(&self, vid: &str) -> Result<ResolvedVid, TspError> {
                if vid == "did:key:z6Mk_test" {
                    Ok(ResolvedVid {
                        id: vid.to_string(),
                        signing_key: [5u8; 32],
                        encryption_key: [6u8; 32],
                        endpoints: vec![],
                    })
                } else {
                    Err(TspError::VidNotFound(vid.to_string()))
                }
            }
        }

        let resolver = DelegatingVidResolver::new().with_did_resolver(Box::new(MockDidResolver));

        let resolved = resolver.resolve("did:key:z6Mk_test").unwrap();
        assert_eq!(resolved.signing_key, [5u8; 32]);

        // Non-DID should not go to DID resolver
        assert!(resolver.resolve("keri:unknown").is_err());
    }
}
