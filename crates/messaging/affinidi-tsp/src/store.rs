//! VID and relationship store.
//!
//! Manages local private VIDs, known remote VIDs, and relationship state
//! between VID pairs.

use std::collections::HashMap;
use std::sync::RwLock;

use crate::error::TspError;
use crate::relationship::{RelationshipEvent, RelationshipState};
use crate::vid::{PrivateVid, ResolvedVid};

/// Build a compact relationship key from two VID strings.
/// Format: "{our_vid}\0{their_vid}" — null byte separator is safe since VIDs can't contain it.
fn relationship_key(our_vid: &str, their_vid: &str) -> String {
    let mut key = String::with_capacity(our_vid.len() + 1 + their_vid.len());
    key.push_str(our_vid);
    key.push('\0');
    key.push_str(their_vid);
    key
}

/// Extract their_vid from a relationship key (everything after the null separator).
fn their_vid_from_key(key: &str) -> &str {
    key.split_once('\0').map_or(key, |(_, their)| their)
}

/// Check if a relationship key belongs to the given our_vid.
fn key_belongs_to(key: &str, our_vid: &str) -> bool {
    key.starts_with(our_vid) && key.as_bytes().get(our_vid.len()) == Some(&b'\0')
}

/// In-memory store for VIDs and relationships.
pub struct TspStore {
    /// Our private VIDs (identities we control).
    private_vids: RwLock<HashMap<String, PrivateVid>>,
    /// Known remote VIDs (resolved public identities).
    remote_vids: RwLock<HashMap<String, ResolvedVid>>,
    /// Relationship states between VID pairs. Key format: "{our_vid}\0{their_vid}".
    relationships: RwLock<HashMap<String, RelationshipState>>,
}

impl TspStore {
    pub fn new() -> Self {
        Self {
            private_vids: RwLock::new(HashMap::new()),
            remote_vids: RwLock::new(HashMap::new()),
            relationships: RwLock::new(HashMap::new()),
        }
    }

    // --- Private VID management ---

    /// Register a private VID (an identity we control).
    pub fn add_private_vid(&self, vid: PrivateVid) {
        // Also store the public part as a remote VID so it can be resolved
        let resolved = vid.to_resolved();
        self.remote_vids
            .write()
            .unwrap()
            .insert(resolved.id.clone(), resolved);
        self.private_vids
            .write()
            .unwrap()
            .insert(vid.id.clone(), vid);
    }

    /// Get a private VID by identifier.
    pub fn get_private_vid(&self, id: &str) -> Result<PrivateVid, TspError> {
        self.private_vids
            .read()
            .unwrap()
            .get(id)
            .cloned()
            .ok_or_else(|| TspError::NoSigningKey(id.to_string()))
    }

    /// List all private VID identifiers.
    pub fn list_private_vids(&self) -> Vec<String> {
        self.private_vids.read().unwrap().keys().cloned().collect()
    }

    // --- Remote VID management ---

    /// Register a known remote VID.
    pub fn add_remote_vid(&self, vid: ResolvedVid) {
        self.remote_vids
            .write()
            .unwrap()
            .insert(vid.id.clone(), vid);
    }

    /// Get a remote VID by identifier.
    pub fn get_remote_vid(&self, id: &str) -> Result<ResolvedVid, TspError> {
        self.remote_vids
            .read()
            .unwrap()
            .get(id)
            .cloned()
            .ok_or_else(|| TspError::VidNotFound(id.to_string()))
    }

    // --- Relationship management ---

    /// Get the relationship state between two VIDs.
    pub fn relationship_state(&self, our_vid: &str, their_vid: &str) -> RelationshipState {
        let key = relationship_key(our_vid, their_vid);
        self.relationships
            .read()
            .unwrap()
            .get(&key)
            .copied()
            .unwrap_or(RelationshipState::None)
    }

    /// Apply a relationship event, transitioning the state.
    pub fn transition_relationship(
        &self,
        our_vid: &str,
        their_vid: &str,
        event: RelationshipEvent,
    ) -> Result<RelationshipState, TspError> {
        let key = relationship_key(our_vid, their_vid);

        let mut relationships = self.relationships.write().unwrap();
        let current = relationships
            .get(&key)
            .copied()
            .unwrap_or(RelationshipState::None);

        let new_state = current.transition(event).map_err(|e| {
            TspError::Relationship(format!("{our_vid} → {their_vid} via {event:?}: {e}"))
        })?;

        if new_state == RelationshipState::None {
            relationships.remove(&key);
        } else {
            relationships.insert(key, new_state);
        }

        Ok(new_state)
    }

    /// List all relationships for a given VID.
    pub fn list_relationships(&self, our_vid: &str) -> Vec<(String, RelationshipState)> {
        self.relationships
            .read()
            .unwrap()
            .iter()
            .filter(|(k, _)| key_belongs_to(k, our_vid))
            .map(|(k, &v)| (their_vid_from_key(k).to_string(), v))
            .collect()
    }
}

impl Default for TspStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relationship::RelationshipEvent;

    #[test]
    fn store_private_vid() {
        let store = TspStore::new();
        let vid = PrivateVid::generate("did:example:alice");
        store.add_private_vid(vid);

        assert!(store.get_private_vid("did:example:alice").is_ok());
        assert!(store.get_private_vid("did:example:bob").is_err());

        // Private VID should also be resolvable as remote
        assert!(store.get_remote_vid("did:example:alice").is_ok());
    }

    #[test]
    fn store_remote_vid() {
        let store = TspStore::new();
        store.add_remote_vid(ResolvedVid {
            id: "did:example:bob".to_string(),
            signing_key: [1u8; 32],
            encryption_key: [2u8; 32],
            endpoints: vec![],
        });

        let resolved = store.get_remote_vid("did:example:bob").unwrap();
        assert_eq!(resolved.signing_key, [1u8; 32]);
    }

    #[test]
    fn relationship_lifecycle() {
        let store = TspStore::new();

        // Initially none
        assert_eq!(
            store.relationship_state("alice", "bob"),
            RelationshipState::None
        );

        // Send invite
        let state = store
            .transition_relationship("alice", "bob", RelationshipEvent::SendInvite)
            .unwrap();
        assert_eq!(state, RelationshipState::Pending);

        // Receive accept
        let state = store
            .transition_relationship("alice", "bob", RelationshipEvent::ReceiveAccept)
            .unwrap();
        assert_eq!(state, RelationshipState::Bidirectional);
    }

    #[test]
    fn relationship_cancel_removes_entry() {
        let store = TspStore::new();

        store
            .transition_relationship("alice", "bob", RelationshipEvent::SendInvite)
            .unwrap();
        store
            .transition_relationship("alice", "bob", RelationshipEvent::SendCancel)
            .unwrap();

        assert_eq!(
            store.relationship_state("alice", "bob"),
            RelationshipState::None
        );
    }

    #[test]
    fn list_private_vids() {
        let store = TspStore::new();
        store.add_private_vid(PrivateVid::generate("alice"));
        store.add_private_vid(PrivateVid::generate("bob"));

        let vids = store.list_private_vids();
        assert_eq!(vids.len(), 2);
        assert!(vids.contains(&"alice".to_string()));
        assert!(vids.contains(&"bob".to_string()));
    }

    #[test]
    fn list_relationships() {
        let store = TspStore::new();
        store
            .transition_relationship("alice", "bob", RelationshipEvent::SendInvite)
            .unwrap();
        store
            .transition_relationship("alice", "carol", RelationshipEvent::SendInvite)
            .unwrap();

        let rels = store.list_relationships("alice");
        assert_eq!(rels.len(), 2);
    }
}
