//! TSP adapter implementing the `affinidi-messaging-core` traits.
//!
//! This module bridges the TSP-specific API (`TspAgent`) to the
//! protocol-agnostic messaging traits, allowing TSP to be used
//! interchangeably with DIDComm.

use affinidi_messaging_core::{
    IdentityResolver, MessagingError, MessagingProtocol, Protocol, ReceivedMessage,
    RelationshipChange, RelationshipManager, RelationshipState, ResolvedIdentity,
};

use crate::TspAgent;
use crate::message::direct;
use crate::vid::resolver::VidResolver;

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
            // BLAKE2s-256 of the wire bytes. The hop id a mediator and the SDK
            // know the same message by is its SHA-256; `receive::message_ids`
            // computes both from the bytes.
            id: hex::encode(direct::message_digest_bytes(packed)),
            sender: Some(received.sender),
            recipient: received.receiver,
            payload: received.payload,
            protocol: Protocol::TSP,
            // `receive` refuses a message whose signature does not verify.
            verified: true,
            // Rev 3 §3.5 permits signed-only (non-confidential) messages, and
            // `receive` accepts them, so this is reported, not assumed.
            encrypted: received.confidential,
        })
    }

    async fn wrap_for_relay(
        &self,
        packed: &[u8],
        next_hop: &str,
        final_recipient: &str,
    ) -> Result<Vec<u8>, MessagingError> {
        // Relay as our default VID: build a routed layer addressed to `next_hop`
        // carrying the opaque `packed` inner; `next_hop` forwards it to
        // `final_recipient` (the single remaining route entry).
        let our_vid = self.default_vid()?;
        let our_private = self
            .agent
            .store
            .get_private_vid(our_vid)
            .map_err(|e| MessagingError::Protocol(e.to_string()))?;
        let next = self
            .agent
            .resolver
            .resolve(next_hop)
            .map_err(|e| MessagingError::Resolution(e.to_string()))?;

        let relayed = crate::message::routed::pack_routed(
            packed,
            &[final_recipient.to_string()],
            our_vid,
            next_hop,
            &our_private.signing_key,
            &next.encryption_key,
        )
        .map_err(|e| MessagingError::Protocol(e.to_string()))?;

        Ok(relayed.bytes)
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
            verification_key: Some(resolved.signing_key.to_vec()),
            encryption_key: resolved.encryption_key.to_vec(),
            endpoints: Some(resolved.endpoints),
        })
    }
}

/// The state-only methods refuse: they would move the local FSM and return
/// nothing to transmit, leaving the peer never hearing of the change and the
/// next call failing on an invalid transition. Use the `*_with_control`
/// methods, which return the packed control message for the caller to send.
fn state_only_refused(op: &str) -> MessagingError {
    MessagingError::NotSupported(format!(
        "TSP `{op}` must transmit a control message; use `{op}_with_control` and send the \
         returned `control_message` to the peer"
    ))
}

#[async_trait::async_trait]
impl RelationshipManager for TspAdapter {
    async fn request_relationship(
        &self,
        _my_id: &str,
        _their_id: &str,
    ) -> Result<RelationshipState, MessagingError> {
        Err(state_only_refused("request_relationship"))
    }

    async fn accept_relationship(
        &self,
        _my_id: &str,
        _their_id: &str,
        _request_id: &[u8],
    ) -> Result<RelationshipState, MessagingError> {
        Err(state_only_refused("accept_relationship"))
    }

    async fn cancel_relationship(
        &self,
        _my_id: &str,
        _their_id: &str,
    ) -> Result<RelationshipState, MessagingError> {
        Err(state_only_refused("cancel_relationship"))
    }

    async fn request_relationship_with_control(
        &self,
        my_id: &str,
        their_id: &str,
    ) -> Result<RelationshipChange, MessagingError> {
        let invite = self
            .agent
            .send_relationship_invite(my_id, their_id)
            .map_err(|e| MessagingError::Relationship(e.to_string()))?;

        Ok(RelationshipChange::with_control_message(
            self.agent.relationship_state(my_id, their_id).into(),
            invite.bytes,
        ))
    }

    async fn accept_relationship_with_control(
        &self,
        my_id: &str,
        their_id: &str,
        _request_id: &[u8],
    ) -> Result<RelationshipChange, MessagingError> {
        // The TSP agent correlates the accept to the received invite via the
        // thread digest it recorded on receipt, so `request_id` is unused here.
        let accept = self
            .agent
            .send_relationship_accept(my_id, their_id)
            .map_err(|e| MessagingError::Relationship(e.to_string()))?;

        Ok(RelationshipChange::with_control_message(
            self.agent.relationship_state(my_id, their_id).into(),
            accept.bytes,
        ))
    }

    async fn cancel_relationship_with_control(
        &self,
        my_id: &str,
        their_id: &str,
    ) -> Result<RelationshipChange, MessagingError> {
        let cancel = self
            .agent
            .send_relationship_cancel(my_id, their_id)
            .map_err(|e| MessagingError::Relationship(e.to_string()))?;

        Ok(RelationshipChange::with_control_message(
            self.agent.relationship_state(my_id, their_id).into(),
            cancel.bytes,
        ))
    }

    async fn relationship_state(
        &self,
        my_id: &str,
        their_id: &str,
    ) -> Result<RelationshipState, MessagingError> {
        Ok(self.agent.relationship_state(my_id, their_id).into())
    }
}

impl From<crate::RelationshipState> for RelationshipState {
    fn from(state: crate::RelationshipState) -> Self {
        match state {
            crate::RelationshipState::None => RelationshipState::None,
            crate::RelationshipState::Pending => RelationshipState::Pending,
            crate::RelationshipState::InviteReceived => RelationshipState::InviteReceived,
            crate::RelationshipState::Bidirectional => RelationshipState::Bidirectional,
        }
    }
}

impl From<RelationshipState> for crate::RelationshipState {
    fn from(state: RelationshipState) -> Self {
        match state {
            RelationshipState::None => crate::RelationshipState::None,
            RelationshipState::Pending => crate::RelationshipState::Pending,
            RelationshipState::InviteReceived => crate::RelationshipState::InviteReceived,
            RelationshipState::Bidirectional => crate::RelationshipState::Bidirectional,
        }
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
        let result = alice.pack_anonymous(b"test", "did:example:bob").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn identity_resolution() {
        let (alice, _) = setup();
        let resolved = alice.resolve("did:example:bob").await.unwrap();
        assert_eq!(resolved.id, "did:example:bob");
        assert_eq!(resolved.verification_key.as_ref().unwrap().len(), 32);
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

        // Alice requests a relationship: the trait hands back the RFI to send.
        let invite = alice
            .request_relationship_with_control("did:example:alice", "did:example:bob")
            .await
            .unwrap();
        assert_eq!(invite.state, RelationshipState::Pending);
        let rfi = invite.control_message.expect("an invite to transmit");

        // Bob receives the invite — this records the invite's thread digest so
        // his accept can reference it.
        bob.unpack(&rfi).await.unwrap();

        // Bob accepts, and gets the RFA to send back.
        let accept = bob
            .accept_relationship_with_control("did:example:bob", "did:example:alice", b"unused")
            .await
            .unwrap();
        assert_eq!(accept.state, RelationshipState::Bidirectional);
        let rfa = accept.control_message.expect("an accept to transmit");

        // Alice processes the accept and can now send.
        alice.unpack(&rfa).await.unwrap();
        assert_eq!(
            alice
                .relationship_state("did:example:alice", "did:example:bob")
                .await
                .unwrap(),
            RelationshipState::Bidirectional
        );
        let packed = alice
            .pack(b"hello", "did:example:alice", "did:example:bob")
            .await
            .unwrap();
        let received = bob.unpack(&packed).await.unwrap();
        assert!(received.encrypted);
        assert!(received.verified);

        // Cancelling hands back the cancel, which tears down Bob's side too.
        let cancel = alice
            .cancel_relationship_with_control("did:example:alice", "did:example:bob")
            .await
            .unwrap();
        assert_eq!(cancel.state, RelationshipState::None);
        bob.unpack(&cancel.control_message.unwrap()).await.unwrap();
        assert_eq!(
            bob.relationship_state("did:example:bob", "did:example:alice")
                .await
                .unwrap(),
            RelationshipState::None
        );
    }

    /// #1024: the state-only methods used to move the FSM and return nothing
    /// to send. They now refuse, and leave the state untouched.
    #[tokio::test]
    async fn state_only_relationship_calls_refuse_without_changing_state() {
        let (alice, _) = setup();
        let err = alice
            .request_relationship("did:example:alice", "did:example:bob")
            .await
            .unwrap_err();
        assert!(matches!(err, MessagingError::NotSupported(_)), "{err:?}");
        assert_eq!(
            alice
                .relationship_state("did:example:alice", "did:example:bob")
                .await
                .unwrap(),
            RelationshipState::None
        );
        assert!(
            alice
                .cancel_relationship("did:example:alice", "did:example:bob")
                .await
                .is_err()
        );
        assert!(
            alice
                .accept_relationship("did:example:alice", "did:example:bob", b"")
                .await
                .is_err()
        );
    }

    /// #1024: a signed-only (non-confidential) message verifies, and the
    /// adapter now says it was not encrypted instead of asserting it was.
    #[tokio::test]
    async fn signed_only_message_is_reported_as_not_encrypted() {
        let (alice, bob) = setup();
        let rfi = alice
            .request_relationship_with_control("did:example:alice", "did:example:bob")
            .await
            .unwrap()
            .control_message
            .unwrap();
        bob.unpack(&rfi).await.unwrap();

        let alice_private = alice
            .agent()
            .store
            .get_private_vid("did:example:alice")
            .unwrap();
        let signed_only = crate::pack_signed_only(
            b"in the clear",
            crate::MessageType::Direct,
            "did:example:alice",
            "did:example:bob",
            &alice_private.signing_key,
        )
        .unwrap();
        let received = bob.unpack(&signed_only.bytes).await.unwrap();
        assert_eq!(received.payload, b"in the clear");
        assert!(received.verified);
        assert!(!received.encrypted);
    }

    #[test]
    fn relationship_state_round_trips_between_crates() {
        for state in [
            crate::RelationshipState::None,
            crate::RelationshipState::Pending,
            crate::RelationshipState::InviteReceived,
            crate::RelationshipState::Bidirectional,
        ] {
            let core: RelationshipState = state.into();
            assert_eq!(crate::RelationshipState::from(core), state);
            assert_eq!(core.can_send(), state.can_send());
        }
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
