//! # affinidi-tsp
//!
//! Trust Spanning Protocol (TSP) implementation for the Affinidi TDK.
//!
//! TSP is a ToIP Layer 2 protocol that provides authenticated, encrypted
//! messaging between Verifiable Identifiers (VIDs). It uses HPKE-Auth for
//! encryption, Ed25519 for signing, and CESR for encoding.
//!
//! ## Quick Start
//!
//! ```rust
//! use affinidi_tsp::{TspAgent, vid::PrivateVid};
//!
//! // Create an agent
//! let agent = TspAgent::new();
//!
//! // Generate identities
//! let alice = PrivateVid::generate("did:example:alice");
//! let bob = PrivateVid::generate("did:example:bob");
//!
//! // Register identities
//! let bob_public = bob.to_resolved();
//! agent.add_private_vid(alice);
//! agent.add_verified_vid(bob_public);
//!
//! // Send a message (after establishing a relationship)
//! // let packed = agent.send("did:example:alice", "did:example:bob", b"Hello!")?;
//! ```

#[cfg(feature = "messaging-core")]
pub mod adapter;
pub mod crypto;
pub mod error;
pub mod message;
pub mod relationship;
pub mod store;
pub mod vid;

pub use error::TspError;
pub use message::MessageType;
pub use relationship::RelationshipState;
pub use vid::{PrivateVid, ResolvedVid};
pub use vid::resolver::VidResolver;

use message::control::ControlMessage;
use message::direct::{self, PackedMessage};
use relationship::RelationshipEvent;
use store::TspStore;
use vid::resolver::DelegatingVidResolver;

/// High-level TSP agent for sending and receiving messages.
///
/// The agent manages local identities (private VIDs), known remote identities,
/// and relationship state. It provides a simple API for the full TSP lifecycle:
///
/// 1. Create/register identities
/// 2. Form relationships (RFI/RFA handshake)
/// 3. Send and receive encrypted, authenticated messages
pub struct TspAgent {
    pub(crate) store: TspStore,
    pub(crate) resolver: DelegatingVidResolver,
}

impl TspAgent {
    /// Create a new TSP agent with an in-memory store and resolver.
    pub fn new() -> Self {
        Self {
            store: TspStore::new(),
            resolver: DelegatingVidResolver::new(),
        }
    }

    /// Create a TSP agent with a custom DID resolver for DID-based VIDs.
    pub fn with_did_resolver(did_resolver: Box<dyn VidResolver>) -> Self {
        Self {
            store: TspStore::new(),
            resolver: DelegatingVidResolver::new().with_did_resolver(did_resolver),
        }
    }

    // --- Identity management ---

    /// Register a private VID (an identity this agent controls).
    pub fn add_private_vid(&self, vid: PrivateVid) {
        let resolved = vid.to_resolved();
        self.resolver.insert(resolved);
        self.store.add_private_vid(vid);
    }

    /// Register a remote VID (a known external identity).
    pub fn add_verified_vid(&self, vid: ResolvedVid) {
        self.resolver.insert(vid.clone());
        self.store.add_remote_vid(vid);
    }

    /// Generate and register a new private VID.
    pub fn create_vid(&self, id: impl Into<String>) -> ResolvedVid {
        let vid = PrivateVid::generate(id);
        let resolved = vid.to_resolved();
        self.add_private_vid(vid);
        resolved
    }

    // --- Relationship management ---

    /// Get the relationship state between two VIDs.
    pub fn relationship_state(&self, our_vid: &str, their_vid: &str) -> RelationshipState {
        self.store.relationship_state(our_vid, their_vid)
    }

    /// Build and pack a Relationship Forming Invite (RFI).
    ///
    /// This sends a control message to initiate a relationship.
    pub fn send_relationship_invite(
        &self,
        our_vid: &str,
        their_vid: &str,
    ) -> Result<PackedMessage, TspError> {
        let control = ControlMessage::invite();
        let packed = self.pack_control(our_vid, their_vid, &control)?;

        self.store
            .transition_relationship(our_vid, their_vid, RelationshipEvent::SendInvite)?;

        Ok(packed)
    }

    /// Build and pack a Relationship Forming Accept (RFA).
    ///
    /// `invite_digest` is the BLAKE2s-256 digest of the received invite message.
    pub fn send_relationship_accept(
        &self,
        our_vid: &str,
        their_vid: &str,
        invite_digest: Vec<u8>,
    ) -> Result<PackedMessage, TspError> {
        let control = ControlMessage::accept(invite_digest);
        let packed = self.pack_control(our_vid, their_vid, &control)?;

        self.store
            .transition_relationship(our_vid, their_vid, RelationshipEvent::SendAccept)?;

        Ok(packed)
    }

    /// Build and pack a Relationship Cancel (RFD).
    pub fn send_relationship_cancel(
        &self,
        our_vid: &str,
        their_vid: &str,
    ) -> Result<PackedMessage, TspError> {
        let control = ControlMessage::cancel();
        let packed = self.pack_control(our_vid, their_vid, &control)?;

        self.store
            .transition_relationship(our_vid, their_vid, RelationshipEvent::SendCancel)?;

        Ok(packed)
    }

    // --- Messaging ---

    /// Pack (seal + sign) a direct message.
    ///
    /// Requires a `Bidirectional` relationship with the recipient.
    pub fn send(
        &self,
        our_vid: &str,
        their_vid: &str,
        payload: &[u8],
    ) -> Result<PackedMessage, TspError> {
        // Check relationship
        let state = self.store.relationship_state(our_vid, their_vid);
        if !state.can_send() {
            return Err(TspError::Relationship(format!(
                "cannot send: relationship with {their_vid} is {state:?}, not Bidirectional"
            )));
        }

        self.pack_message(our_vid, their_vid, payload, MessageType::Direct)
    }

    /// Unpack (verify + decrypt) a received message.
    ///
    /// Returns the decrypted payload along with sender/receiver metadata.
    /// For control messages, also updates the relationship state.
    pub fn receive(
        &self,
        our_vid: &str,
        wire: &[u8],
    ) -> Result<ReceivedMessage, TspError> {
        // Parse envelope to get sender VID (before full unpack)
        let (envelope, _) = message::envelope::Envelope::decode(wire)?;

        if envelope.receiver != our_vid {
            return Err(TspError::InvalidMessage(format!(
                "message addressed to {}, not {our_vid}",
                envelope.receiver
            )));
        }

        // Look up keys
        let our_private = self.store.get_private_vid(our_vid)?;
        let sender_resolved = self.resolver.resolve(&envelope.sender)?;

        // Unpack
        let unpacked = direct::unpack(
            wire,
            &our_private.decryption_key,
            &sender_resolved.encryption_key,
            &sender_resolved.signing_key,
        )?;

        // Handle control messages
        if unpacked.message_type == MessageType::Control {
            let control = ControlMessage::decode(&unpacked.payload)?;
            self.handle_control(our_vid, &unpacked.sender, &control, wire)?;

            return Ok(ReceivedMessage {
                payload: unpacked.payload,
                sender: unpacked.sender,
                receiver: unpacked.receiver,
                message_type: unpacked.message_type,
                control: Some(control),
            });
        }

        Ok(ReceivedMessage {
            payload: unpacked.payload,
            sender: unpacked.sender,
            receiver: unpacked.receiver,
            message_type: unpacked.message_type,
            control: None,
        })
    }

    // --- Internal helpers ---

    fn pack_message(
        &self,
        our_vid: &str,
        their_vid: &str,
        payload: &[u8],
        msg_type: MessageType,
    ) -> Result<PackedMessage, TspError> {
        let our_private = self.store.get_private_vid(our_vid)?;
        let their_resolved = self.resolver.resolve(their_vid)?;

        direct::pack(
            payload,
            msg_type,
            our_vid,
            their_vid,
            &our_private.signing_key,
            &our_private.decryption_key,
            &their_resolved.encryption_key,
        )
    }

    fn pack_control(
        &self,
        our_vid: &str,
        their_vid: &str,
        control: &ControlMessage,
    ) -> Result<PackedMessage, TspError> {
        let payload = control.encode();
        self.pack_message(our_vid, their_vid, &payload, MessageType::Control)
    }

    fn handle_control(
        &self,
        our_vid: &str,
        their_vid: &str,
        control: &ControlMessage,
        _wire: &[u8],
    ) -> Result<(), TspError> {
        use message::control::ControlType;

        match control.control_type {
            ControlType::RelationshipFormingInvite => {
                self.store.transition_relationship(
                    our_vid,
                    their_vid,
                    RelationshipEvent::ReceiveInvite,
                )?;
            }
            ControlType::RelationshipFormingAccept => {
                self.store.transition_relationship(
                    our_vid,
                    their_vid,
                    RelationshipEvent::ReceiveAccept,
                )?;
            }
            ControlType::RelationshipCancel => {
                self.store.transition_relationship(
                    our_vid,
                    their_vid,
                    RelationshipEvent::ReceiveCancel,
                )?;
            }
        }

        Ok(())
    }
}

impl Default for TspAgent {
    fn default() -> Self {
        Self::new()
    }
}

/// A received and unpacked TSP message.
#[derive(Debug, Clone)]
pub struct ReceivedMessage {
    /// The decrypted payload bytes.
    pub payload: Vec<u8>,
    /// The sender's VID.
    pub sender: String,
    /// The receiver's VID.
    pub receiver: String,
    /// The message type.
    pub message_type: MessageType,
    /// If this is a control message, the parsed control payload.
    pub control: Option<ControlMessage>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup_agents() -> (TspAgent, TspAgent, String, String) {
        let alice_agent = TspAgent::new();
        let bob_agent = TspAgent::new();

        let alice_vid = PrivateVid::generate("did:example:alice");
        let bob_vid = PrivateVid::generate("did:example:bob");

        let alice_public = alice_vid.to_resolved();
        let bob_public = bob_vid.to_resolved();

        // Alice knows Bob, Bob knows Alice
        alice_agent.add_private_vid(alice_vid);
        alice_agent.add_verified_vid(bob_public.clone());

        bob_agent.add_private_vid(bob_vid);
        bob_agent.add_verified_vid(alice_public);

        (
            alice_agent,
            bob_agent,
            "did:example:alice".to_string(),
            "did:example:bob".to_string(),
        )
    }

    #[test]
    fn full_relationship_handshake() {
        let (alice, bob, alice_id, bob_id) = setup_agents();

        // Alice sends RFI to Bob
        let rfi = alice.send_relationship_invite(&alice_id, &bob_id).unwrap();
        assert_eq!(
            alice.relationship_state(&alice_id, &bob_id),
            RelationshipState::Pending
        );

        // Bob receives the RFI
        let received = bob.receive(&bob_id, &rfi.bytes).unwrap();
        assert_eq!(received.message_type, MessageType::Control);
        assert_eq!(
            bob.relationship_state(&bob_id, &alice_id),
            RelationshipState::InviteReceived
        );

        // Bob sends RFA back to Alice
        let digest = direct::message_digest(&rfi).to_vec();
        let rfa = bob
            .send_relationship_accept(&bob_id, &alice_id, digest)
            .unwrap();
        assert_eq!(
            bob.relationship_state(&bob_id, &alice_id),
            RelationshipState::Bidirectional
        );

        // Alice receives the RFA
        alice.receive(&alice_id, &rfa.bytes).unwrap();
        assert_eq!(
            alice.relationship_state(&alice_id, &bob_id),
            RelationshipState::Bidirectional
        );
    }

    #[test]
    fn send_after_handshake() {
        let (alice, bob, alice_id, bob_id) = setup_agents();

        // Establish relationship
        let rfi = alice.send_relationship_invite(&alice_id, &bob_id).unwrap();
        bob.receive(&bob_id, &rfi.bytes).unwrap();
        let digest = direct::message_digest(&rfi).to_vec();
        let rfa = bob
            .send_relationship_accept(&bob_id, &alice_id, digest)
            .unwrap();
        alice.receive(&alice_id, &rfa.bytes).unwrap();

        // Now Alice can send a message
        let msg = alice
            .send(&alice_id, &bob_id, b"Hello Bob!")
            .unwrap();

        let received = bob.receive(&bob_id, &msg.bytes).unwrap();
        assert_eq!(received.payload, b"Hello Bob!");
        assert_eq!(received.sender, alice_id);
        assert_eq!(received.message_type, MessageType::Direct);
    }

    #[test]
    fn send_without_relationship_fails() {
        let (alice, _bob, alice_id, bob_id) = setup_agents();

        let result = alice.send(&alice_id, &bob_id, b"premature message");
        assert!(result.is_err());
    }

    #[test]
    fn relationship_cancel() {
        let (alice, bob, alice_id, bob_id) = setup_agents();

        // Establish relationship
        let rfi = alice.send_relationship_invite(&alice_id, &bob_id).unwrap();
        bob.receive(&bob_id, &rfi.bytes).unwrap();
        let digest = direct::message_digest(&rfi).to_vec();
        let rfa = bob
            .send_relationship_accept(&bob_id, &alice_id, digest)
            .unwrap();
        alice.receive(&alice_id, &rfa.bytes).unwrap();

        // Alice cancels
        let cancel = alice
            .send_relationship_cancel(&alice_id, &bob_id)
            .unwrap();
        assert_eq!(
            alice.relationship_state(&alice_id, &bob_id),
            RelationshipState::None
        );

        // Bob receives cancel
        bob.receive(&bob_id, &cancel.bytes).unwrap();
        assert_eq!(
            bob.relationship_state(&bob_id, &alice_id),
            RelationshipState::None
        );
    }

    #[test]
    fn create_vid_helper() {
        let agent = TspAgent::new();
        let resolved = agent.create_vid("did:example:test");
        assert_eq!(resolved.id, "did:example:test");

        // Should be resolvable
        let found = agent.resolver.resolve("did:example:test").unwrap();
        assert_eq!(found.id, "did:example:test");
    }

    #[test]
    fn wrong_recipient_rejects() {
        let (alice, _bob, alice_id, bob_id) = setup_agents();

        let rfi = alice.send_relationship_invite(&alice_id, &bob_id).unwrap();

        // Try to receive as Alice (but message is for Bob)
        let result = alice.receive(&alice_id, &rfi.bytes);
        assert!(result.is_err());
    }
}
