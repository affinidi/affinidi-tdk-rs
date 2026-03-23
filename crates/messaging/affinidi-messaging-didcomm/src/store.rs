//! In-memory identity store for DIDComm.
//!
//! Simpler than TspStore — DIDComm has implicit relationships based on
//! message exchange rather than explicit relationship state machines.
//!
//! **Note:** This store is intended for development and testing. It is a
//! single-threaded, non-persistent `HashMap`-backed store with no encryption
//! at rest or audit logging. Production deployments should implement a
//! persistent store with appropriate key protection.

use std::collections::HashMap;

use crate::error::DIDCommError;
use crate::identity::{Mediator, PrivateIdentity, ResolvedIdentity};

/// An in-memory store for local and resolved identities.
///
/// Suitable for development, testing, and single-threaded use cases.
/// Not recommended for production — see module docs for details.
#[derive(Default)]
pub struct DIDCommStore {
    /// Local identities (keyed by DID)
    local: HashMap<String, PrivateIdentity>,
    /// Resolved remote identities (keyed by DID)
    resolved: HashMap<String, ResolvedIdentity>,
    /// Mediator routes: maps recipient DID → mediator to forward through
    routes: HashMap<String, Mediator>,
}

impl DIDCommStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a local identity.
    pub fn add_local(&mut self, identity: PrivateIdentity) {
        self.local.insert(identity.did.clone(), identity);
    }

    /// Get a local identity by DID.
    pub fn get_local(&self, did: &str) -> Result<&PrivateIdentity, DIDCommError> {
        self.local
            .get(did)
            .ok_or_else(|| DIDCommError::IdentityNotFound(did.to_string()))
    }

    /// Add a resolved remote identity.
    pub fn add_resolved(&mut self, identity: ResolvedIdentity) {
        self.resolved.insert(identity.did.clone(), identity);
    }

    /// Get a resolved identity by DID.
    pub fn get_resolved(&self, did: &str) -> Result<&ResolvedIdentity, DIDCommError> {
        self.resolved
            .get(did)
            .ok_or_else(|| DIDCommError::IdentityNotFound(did.to_string()))
    }

    /// Add a mediator route: messages for `recipient_did` should be forwarded through this mediator.
    pub fn add_route(&mut self, recipient_did: String, mediator: Mediator) {
        self.routes.insert(recipient_did, mediator);
    }

    /// Get the mediator for a given recipient DID (if any).
    pub fn get_route(&self, recipient_did: &str) -> Option<&Mediator> {
        self.routes.get(recipient_did)
    }

    /// Remove a local identity.
    pub fn remove_local(&mut self, did: &str) -> Option<PrivateIdentity> {
        self.local.remove(did)
    }

    /// Remove a resolved identity.
    pub fn remove_resolved(&mut self, did: &str) -> Option<ResolvedIdentity> {
        self.resolved.remove(did)
    }

    /// List all local DIDs.
    pub fn local_dids(&self) -> Vec<&str> {
        self.local.keys().map(|s| s.as_str()).collect()
    }

    /// List all resolved DIDs.
    pub fn resolved_dids(&self) -> Vec<&str> {
        self.resolved.keys().map(|s| s.as_str()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::PrivateIdentity;

    #[test]
    fn store_basic_ops() {
        let mut store = DIDCommStore::new();

        let alice = PrivateIdentity::generate("did:example:alice");
        let bob_resolved = alice.to_resolved();

        store.add_local(alice);
        store.add_resolved(ResolvedIdentity::new(
            "did:example:bob".into(),
            "did:example:bob#key-1".into(),
            bob_resolved.key_agreement_public,
        ));

        assert!(store.get_local("did:example:alice").is_ok());
        assert!(store.get_resolved("did:example:bob").is_ok());
        assert!(store.get_local("did:example:unknown").is_err());

        assert_eq!(store.local_dids().len(), 1);
        assert_eq!(store.resolved_dids().len(), 1);
    }
}
