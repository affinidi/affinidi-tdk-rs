//! In-memory identity store for DIDComm v1.
//!
//! Mirrors [`affinidi_messaging_didcomm::store::DIDCommStore`], with one
//! addition the v1 protocol forces: a **verkey -> DID index**.
//!
//! A v2 store can key everything by DID, because a v2 envelope names its sender
//! with a DID URL. A v1 envelope names its sender with a raw verkey, so unpack
//! needs to look up in the other direction. In Aries terms this index is the
//! connection table — `theirDid` retrieved by the key that authenticated the
//! message. See [`crate::identity`].
//!
//! **Note:** like its v2 counterpart, this store is for development and
//! testing — single-threaded, non-persistent, no encryption at rest. A
//! production agent already has a connection database, and should implement
//! [`SenderBindings`] over it rather than mirroring state in here.

use std::collections::HashMap;

use crate::error::DIDCommV1Error;
use crate::identity::{Did, Mediator, PrivateIdentity, ResolvedIdentity, Verkey};
use crate::message::unpack::SenderBindings;

/// An in-memory store for local and resolved v1 identities.
#[derive(Default)]
pub struct DIDCommV1Store {
    /// Local identities, keyed by DID.
    local: HashMap<String, PrivateIdentity>,
    /// Resolved remote identities, keyed by DID.
    resolved: HashMap<String, ResolvedIdentity>,
    /// The verkey -> DID index that v1 unpack depends on.
    by_verkey: HashMap<Verkey, Did>,
    /// Routing: recipient DID -> mediator to forward through.
    routes: HashMap<String, Mediator>,
}

impl DIDCommV1Store {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a local identity.
    pub fn add_local(&mut self, identity: PrivateIdentity) {
        self.by_verkey.insert(identity.verkey, identity.did.clone());
        self.local.insert(identity.did.to_string(), identity);
    }

    /// Get a local identity by DID.
    pub fn get_local(&self, did: &str) -> Result<&PrivateIdentity, DIDCommV1Error> {
        self.local
            .get(did)
            .ok_or_else(|| DIDCommV1Error::IdentityNotFound(did.to_string()))
    }

    /// Bind a remote DID to the verkey that authenticates its messages.
    ///
    /// This is what turns an authenticated verkey into a `theirDid` at unpack
    /// time; without it an authcrypt message comes back as
    /// [`AuthcryptUnknownSender`](crate::UnpackResult::AuthcryptUnknownSender).
    pub fn add_resolved(&mut self, identity: ResolvedIdentity) {
        self.by_verkey.insert(identity.verkey, identity.did.clone());
        self.resolved.insert(identity.did.to_string(), identity);
    }

    /// Get a resolved identity by DID.
    pub fn get_resolved(&self, did: &str) -> Result<&ResolvedIdentity, DIDCommV1Error> {
        self.resolved
            .get(did)
            .ok_or_else(|| DIDCommV1Error::IdentityNotFound(did.to_string()))
    }

    /// Route messages for `recipient_did` through `mediator`.
    pub fn add_route(
        &mut self,
        recipient_did: &str,
        mediator: Mediator,
    ) -> Result<(), DIDCommV1Error> {
        self.routes
            .insert(Did::parse(recipient_did)?.to_string(), mediator);
        Ok(())
    }

    /// The mediator for a recipient DID, if any.
    pub fn get_route(&self, recipient_did: &str) -> Option<&Mediator> {
        self.routes.get(recipient_did)
    }

    /// Remove a local identity and its verkey binding.
    pub fn remove_local(&mut self, did: &str) -> Option<PrivateIdentity> {
        let removed = self.local.remove(did)?;
        self.unbind(&removed.verkey, &removed.did);
        Some(removed)
    }

    /// Remove a resolved identity and its verkey binding.
    pub fn remove_resolved(&mut self, did: &str) -> Option<ResolvedIdentity> {
        let removed = self.resolved.remove(did)?;
        self.unbind(&removed.verkey, &removed.did);
        Some(removed)
    }

    /// Drop a verkey binding, but only if it still points at the DID being
    /// removed — a later `add_*` may have rebound the key to someone else.
    fn unbind(&mut self, verkey: &Verkey, did: &Did) {
        if self.by_verkey.get(verkey) == Some(did) {
            self.by_verkey.remove(verkey);
        }
    }

    /// All local DIDs.
    pub fn local_dids(&self) -> Vec<&str> {
        self.local.keys().map(String::as_str).collect()
    }

    /// All resolved DIDs.
    pub fn resolved_dids(&self) -> Vec<&str> {
        self.resolved.keys().map(String::as_str).collect()
    }

    /// Every local identity, for use as unpack recipients.
    pub fn local_identities(&self) -> Vec<&PrivateIdentity> {
        self.local.values().collect()
    }
}

impl SenderBindings for DIDCommV1Store {
    fn did_for_verkey(&self, verkey: &Verkey) -> Option<Did> {
        self.by_verkey.get(verkey).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_ops() {
        let mut store = DIDCommV1Store::new();
        let alice = PrivateIdentity::generate("did:example:alice").unwrap();
        let bob = PrivateIdentity::generate("did:example:bob").unwrap();

        store.add_resolved(bob.to_resolved());
        store.add_local(alice);

        assert!(store.get_local("did:example:alice").is_ok());
        assert!(store.get_resolved("did:example:bob").is_ok());
        assert!(store.get_local("did:example:unknown").is_err());
        assert_eq!(store.local_dids().len(), 1);
        assert_eq!(store.resolved_dids().len(), 1);
    }

    #[test]
    fn indexes_verkeys_in_both_directions() {
        let mut store = DIDCommV1Store::new();
        let alice = PrivateIdentity::generate("did:example:alice").unwrap();
        let alice_verkey = alice.verkey;
        store.add_resolved(alice.to_resolved());

        assert_eq!(
            store.did_for_verkey(&alice_verkey).unwrap().as_str(),
            "did:example:alice"
        );
        assert_eq!(
            store.did_for_verkey(&Verkey::from_bytes([0u8; 32])),
            None,
            "an unknown verkey must not resolve to anything"
        );
    }

    #[test]
    fn removal_drops_the_verkey_binding() {
        let mut store = DIDCommV1Store::new();
        let alice = PrivateIdentity::generate("did:example:alice").unwrap();
        let verkey = alice.verkey;
        store.add_resolved(alice.to_resolved());

        store.remove_resolved("did:example:alice").unwrap();
        assert_eq!(store.did_for_verkey(&verkey), None);
    }

    /// Rebinding a verkey to a new DID and then removing the *old* DID must not
    /// tear down the live binding.
    #[test]
    fn removal_does_not_drop_a_rebound_verkey() {
        let mut store = DIDCommV1Store::new();
        let alice = PrivateIdentity::generate("did:example:alice").unwrap();
        let verkey = alice.verkey;

        store.add_resolved(alice.to_resolved());
        store.add_resolved(ResolvedIdentity::new("did:example:alice-renamed", verkey).unwrap());
        store.remove_resolved("did:example:alice");

        assert_eq!(
            store.did_for_verkey(&verkey).unwrap().as_str(),
            "did:example:alice-renamed"
        );
    }

    #[test]
    fn routes_are_keyed_by_normalised_did() {
        let mut store = DIDCommV1Store::new();
        let mediator = Mediator::new(Verkey::from_bytes([3u8; 32]));

        store
            .add_route("did:example:bob#key-1", mediator.clone())
            .unwrap();
        assert_eq!(store.get_route("did:example:bob"), Some(&mediator));
    }
}
