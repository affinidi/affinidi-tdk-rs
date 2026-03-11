//! TSP adapter implementing the `affinidi-messaging-core` traits.
//!
//! This module bridges the TSP-specific API (`TspAgent`) to the
//! protocol-agnostic messaging traits, allowing TSP to be used
//! interchangeably with DIDComm.

use affinidi_messaging_core::{
    IdentityResolver, MessagingError, MessagingProtocol, Protocol, ReceivedMessage,
    RelationshipManager, RelationshipState, ResolvedIdentity,
};

use crate::message::direct;
use crate::vid::resolver::VidResolver;
use crate::TspAgent;

/// TSP adapter implementing the unified messaging traits.
///
/// Wraps a `TspAgent` and exposes it through the protocol-agnostic API
/// defined in `affinidi-messaging-core`.
pub struct TspAdapter {
    agent: TspAgent,
    /// The default local VID to use as "self" when not specified.
    default_vid: Option<String>,
}

impl TspAdapter {
    /// Create a new TSP adapter wrapping the given agent.
    pub fn new(agent: TspAgent) -> Self {
        Self {
            agent,
            default_vid: None,
        }
    }

    /// Set the default local VID for this adapter.
    pub fn with_default_vid(mut self, vid: impl Into<String>) -> Self {
        self.default_vid = Some(vid.into());
        self
    }

    /// Get the underlying TSP agent for direct access.
    pub fn agent(&self) -> &TspAgent {
        &self.agent
    }

    fn default_vid(&self) -> Result<&str, MessagingError> {
        self.default_vid
            .as_deref()
            .ok_or_else(|| MessagingError::Protocol("no default VID set on TSP adapter".into()))
    }
}

#[async_trait::async_trait]
impl MessagingProtocol for TspAdapter {
    fn protocol(&self) -> Protocol {
        Protocol::TSP
    }

    async fn pack(
        &self,
        payload: &[u8],
        sender: &str,
        recipient: &str,
    ) -> Result<Vec<u8>, MessagingError> {
        let packed = self
            .agent
            .send(sender, recipient, payload)
            .map_err(|e| MessagingError::Pack(e.to_string()))?;
        Ok(packed.bytes)
    }

    async fn pack_anonymous(
        &self,
        _payload: &[u8],
        _recipient: &str,
    ) -> Result<Vec<u8>, MessagingError> {
        // TSP always authenticates the sender — anonymous sending is not supported
        Err(MessagingError::NotSupported(
            "TSP does not support anonymous messages — sender authentication is mandatory".into(),
        ))
    }

    async fn unpack(&self, packed: &[u8]) -> Result<ReceivedMessage, MessagingError> {
        let vid = self.default_vid()?;
        let received = self
            .agent
            .receive(vid, packed)
            .map_err(|e| MessagingError::Unpack(e.to_string()))?;

        Ok(ReceivedMessage {
            id: hex::encode(direct::message_digest(
                &direct::PackedMessage {
                    bytes: packed.to_vec(),
                },
            )),
            sender: Some(received.sender),
            recipient: received.receiver,
            payload: received.payload,
            protocol: Protocol::TSP,
            verified: true,  // TSP always verifies sender
            encrypted: true, // TSP always encrypts
        })
    }

    async fn wrap_for_relay(
        &self,
        _packed: &[u8],
        _next_hop: &str,
        _final_recipient: &str,
    ) -> Result<Vec<u8>, MessagingError> {
        // Nested/routed modes are Phase 3
        Err(MessagingError::NotSupported(
            "TSP nested/routed modes not yet implemented".into(),
        ))
    }
}

#[async_trait::async_trait]
impl IdentityResolver for TspAdapter {
    async fn resolve(&self, id: &str) -> Result<ResolvedIdentity, MessagingError> {
        let resolved = self
            .agent
            .resolver
            .resolve(id)
            .map_err(|e| MessagingError::Resolution(e.to_string()))?;

        Ok(ResolvedIdentity {
            id: resolved.id,
            verification_key: resolved.signing_key.to_vec(),
            encryption_key: resolved.encryption_key.to_vec(),
            endpoints: resolved.endpoints,
        })
    }
}

#[async_trait::async_trait]
impl RelationshipManager for TspAdapter {
    async fn request_relationship(
        &self,
        my_id: &str,
        their_id: &str,
    ) -> Result<RelationshipState, MessagingError> {
        self.agent
            .send_relationship_invite(my_id, their_id)
            .map_err(|e| MessagingError::Relationship(e.to_string()))?;

        Ok(RelationshipState::Pending)
    }

    async fn accept_relationship(
        &self,
        my_id: &str,
        their_id: &str,
        request_id: &[u8],
    ) -> Result<RelationshipState, MessagingError> {
        self.agent
            .send_relationship_accept(my_id, their_id, request_id.to_vec())
            .map_err(|e| MessagingError::Relationship(e.to_string()))?;

        Ok(RelationshipState::Bidirectional)
    }

    async fn cancel_relationship(
        &self,
        my_id: &str,
        their_id: &str,
    ) -> Result<RelationshipState, MessagingError> {
        self.agent
            .send_relationship_cancel(my_id, their_id)
            .map_err(|e| MessagingError::Relationship(e.to_string()))?;

        Ok(RelationshipState::None)
    }

    async fn relationship_state(
        &self,
        my_id: &str,
        their_id: &str,
    ) -> Result<RelationshipState, MessagingError> {
        let state = self.agent.relationship_state(my_id, their_id);
        Ok(match state {
            crate::RelationshipState::None => RelationshipState::None,
            crate::RelationshipState::Pending => RelationshipState::Pending,
            crate::RelationshipState::InviteReceived => RelationshipState::InviteReceived,
            crate::RelationshipState::Bidirectional => RelationshipState::Bidirectional,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vid::PrivateVid;

    fn setup() -> (TspAdapter, TspAdapter) {
        let alice_agent = TspAgent::new();
        let bob_agent = TspAgent::new();

        let alice_vid = PrivateVid::generate("did:example:alice");
        let bob_vid = PrivateVid::generate("did:example:bob");

        let alice_pub = alice_vid.to_resolved();
        let bob_pub = bob_vid.to_resolved();

        alice_agent.add_private_vid(alice_vid);
        alice_agent.add_verified_vid(bob_pub.clone());
        bob_agent.add_private_vid(bob_vid);
        bob_agent.add_verified_vid(alice_pub);

        let alice = TspAdapter::new(alice_agent).with_default_vid("did:example:alice");
        let bob = TspAdapter::new(bob_agent).with_default_vid("did:example:bob");

        (alice, bob)
    }

    #[tokio::test]
    async fn protocol_type() {
        let (alice, _) = setup();
        assert_eq!(alice.protocol(), Protocol::TSP);
    }

    #[tokio::test]
    async fn anonymous_not_supported() {
        let (alice, _) = setup();
        let result = alice
            .pack_anonymous(b"test", "did:example:bob")
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn identity_resolution() {
        let (alice, _) = setup();
        let resolved = alice.resolve("did:example:bob").await.unwrap();
        assert_eq!(resolved.id, "did:example:bob");
        assert_eq!(resolved.verification_key.len(), 32);
        assert_eq!(resolved.encryption_key.len(), 32);
    }

    #[tokio::test]
    async fn relationship_flow_via_traits() {
        let (alice, bob) = setup();

        // Check initial state
        let state = alice
            .relationship_state("did:example:alice", "did:example:bob")
            .await
            .unwrap();
        assert_eq!(state, RelationshipState::None);

        // Alice requests relationship (sends RFI)
        let state = alice
            .request_relationship("did:example:alice", "did:example:bob")
            .await
            .unwrap();
        assert_eq!(state, RelationshipState::Pending);

        // Bob receives the invite via the agent to update his state
        // (In real usage, the RFI wire bytes would be transported and received)
        bob.agent()
            .store
            .transition_relationship(
                "did:example:bob",
                "did:example:alice",
                crate::relationship::RelationshipEvent::ReceiveInvite,
            )
            .unwrap();

        // Now Bob can accept
        let state = bob
            .accept_relationship("did:example:bob", "did:example:alice", b"digest")
            .await
            .unwrap();
        assert_eq!(state, RelationshipState::Bidirectional);
    }

    #[tokio::test]
    async fn relay_not_yet_supported() {
        let (alice, _) = setup();
        let result = alice
            .wrap_for_relay(b"msg", "intermediary", "recipient")
            .await;
        assert!(result.is_err());
    }
}
