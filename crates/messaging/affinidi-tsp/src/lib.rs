//! # affinidi-tsp
//!
//! Trust Spanning Protocol (TSP) implementation for the Affinidi TDK.
//!
//! TSP is a ToIP Layer 2 protocol that provides authenticated, encrypted
//! messaging between Verifiable Identifiers (VIDs). It uses HPKE-Base for
//! encryption, Ed25519 for signing, and CESR for encoding, per the TSP
//! specification Rev 3.
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
pub use message::meta::{MetaEnvelope, TSP_MAGIC_BYTE, is_tsp};
pub use message::routed::{MAX_HOPS, RouteStep};
pub use relationship::{RelationshipPolicy, RelationshipState};
pub use vid::resolver::VidResolver;
#[cfg(feature = "did-resolver")]
pub use vid::{DidVidResolver, TSP_SERVICE_TYPE};
pub use vid::{PrivateVid, ResolvedVid};

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
    pub(crate) relationship_policy: RelationshipPolicy,
}

impl TspAgent {
    /// Create a new TSP agent with an in-memory store and resolver.
    pub fn new() -> Self {
        Self {
            store: TspStore::new(),
            resolver: DelegatingVidResolver::new(),
            relationship_policy: RelationshipPolicy::default(),
        }
    }

    /// Set whether inbound application messages are gated on an existing
    /// relationship (Rev 3 §7.2.2). Defaults to [`RelationshipPolicy::Gated`];
    /// a node that is not an endpoint — an intermediary — sets `Ungated`.
    pub fn with_relationship_policy(mut self, policy: RelationshipPolicy) -> Self {
        self.relationship_policy = policy;
        self
    }

    /// Create a TSP agent with a custom DID resolver for DID-based VIDs.
    pub fn with_did_resolver(did_resolver: Box<dyn VidResolver>) -> Self {
        Self {
            store: TspStore::new(),
            resolver: DelegatingVidResolver::new().with_did_resolver(did_resolver),
            relationship_policy: RelationshipPolicy::default(),
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
    /// This sends a control message to initiate a relationship. The invite's
    /// thread digest (`SHA256` of its plaintext frame) is remembered so a later
    /// accept can be correlated, and is used as the cancel reference.
    pub fn send_relationship_invite(
        &self,
        our_vid: &str,
        their_vid: &str,
    ) -> Result<PackedMessage, TspError> {
        let control = ControlMessage::invite();
        let packed = self.pack_control(our_vid, their_vid, &control)?;

        self.store
            .transition_relationship(our_vid, their_vid, RelationshipEvent::SendInvite)?;
        // Remember the invite's thread digest to correlate the accept and to
        // reference on cancel.
        self.store
            .set_thread_digest(our_vid, their_vid, packed.thread_digest);

        Ok(packed)
    }

    /// Build and pack a Relationship Forming Accept (RFA).
    ///
    /// The accept's `reply` is the thread digest of the invite being accepted
    /// — the `thread_digest` of the received invite (see
    /// [`ReceivedMessage::thread_digest`]), which the FSM remembers when it
    /// transitions to [`RelationshipState::InviteReceived`]. The accept's own
    /// thread digest then becomes the relationship reference for cancel.
    pub fn send_relationship_accept(
        &self,
        our_vid: &str,
        their_vid: &str,
    ) -> Result<PackedMessage, TspError> {
        let invite_digest = self
            .store
            .thread_digest(our_vid, their_vid)
            .ok_or_else(|| {
                TspError::Relationship(format!("no invite on record from {their_vid} to accept"))
            })?;
        let control = ControlMessage::accept(invite_digest);
        let packed = self.pack_control(our_vid, their_vid, &control)?;

        self.store
            .transition_relationship(our_vid, their_vid, RelationshipEvent::SendAccept)?;

        Ok(packed)
    }

    /// Build and pack a Relationship Cancel (RFD).
    ///
    /// The cancel's `reply` references the relationship-forming message's thread
    /// digest (the remembered invite digest); if none is on record (e.g. a
    /// degenerate teardown) a zero digest is used.
    pub fn send_relationship_cancel(
        &self,
        our_vid: &str,
        their_vid: &str,
    ) -> Result<PackedMessage, TspError> {
        let reply = self
            .store
            .thread_digest(our_vid, their_vid)
            .unwrap_or([0u8; 32]);
        let control = ControlMessage::cancel(reply);
        let packed = self.pack_control(our_vid, their_vid, &control)?;

        self.store
            .transition_relationship(our_vid, their_vid, RelationshipEvent::SendCancel)?;
        self.store.clear_thread_digest(our_vid, their_vid);

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
    pub fn receive(&self, our_vid: &str, wire: &[u8]) -> Result<ReceivedMessage, TspError> {
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
            &sender_resolved.signing_key,
        )?;

        // Handle control messages
        if unpacked.message_type == MessageType::Control {
            let control = unpacked
                .control
                .clone()
                .ok_or_else(|| TspError::InvalidMessage("control message has no payload".into()))?;
            let outcome =
                self.handle_control(our_vid, &unpacked.sender, &control, unpacked.thread_digest)?;

            return Ok(ReceivedMessage {
                payload: unpacked.payload,
                sender: unpacked.sender,
                receiver: unpacked.receiver,
                message_type: unpacked.message_type,
                thread_digest: unpacked.thread_digest,
                control: Some(control),
                outcome,
            });
        }

        // §7.2.2: an application message from a VID we hold no relationship
        // with is dropped. An exchange begins with control messages, and this
        // enforces that ordering — it is not admission control, which stays a
        // decision the application makes when it sees the invite.
        if self.relationship_policy == RelationshipPolicy::Gated
            && !self
                .store
                .relationship_state(our_vid, &unpacked.sender)
                .admits_application_message()
        {
            return Err(TspError::Discarded(format!(
                "application message from {} with no relationship to {our_vid}",
                unpacked.sender
            )));
        }

        Ok(ReceivedMessage {
            payload: unpacked.payload,
            sender: unpacked.sender,
            receiver: unpacked.receiver,
            message_type: unpacked.message_type,
            thread_digest: unpacked.thread_digest,
            control: None,
            outcome: ControlOutcome::None,
        })
    }

    // --- Routed / nested messaging (§5.3 / §5.5) ---

    /// Send a message to `final_vid` routed through `intermediaries` (in order).
    ///
    /// The payload is sealed end-to-end to `final_vid` (so intermediaries cannot
    /// read it), then wrapped in a routed layer addressed to the first
    /// intermediary. Each intermediary calls [`TspAgent::forward_routed`] to
    /// advance the message. With an empty `intermediaries` list this is an
    /// ordinary direct send.
    ///
    /// Requires a `Bidirectional` relationship with `final_vid` (the inner is a
    /// direct message); resolution of every hop's keys is via the agent resolver.
    pub fn send_routed(
        &self,
        our_vid: &str,
        final_vid: &str,
        intermediaries: &[&str],
        payload: &[u8],
    ) -> Result<PackedMessage, TspError> {
        // Inner: end-to-end sealed to the final recipient.
        let inner = self.pack_message(our_vid, final_vid, payload, MessageType::Direct)?;

        if intermediaries.is_empty() {
            return Ok(inner);
        }

        // Route is the intermediaries followed by the final recipient, so the
        // last intermediary forwards the inner directly to `final_vid`.
        let mut route: Vec<String> = intermediaries[1..].iter().map(|s| s.to_string()).collect();
        route.push(final_vid.to_string());

        let first_hop = intermediaries[0];
        let our_private = self.store.get_private_vid(our_vid)?;
        let first_resolved = self.resolver.resolve(first_hop)?;

        message::routed::pack_routed(
            &inner.bytes,
            &route,
            our_vid,
            first_hop,
            &our_private.signing_key,
            &first_resolved.encryption_key,
        )
    }

    /// Wrap an already-packed message inside a nested outer message addressed to
    /// `intermediary_vid`, for metadata privacy (§5.5). The intermediary can
    /// open the outer but not the opaque inner.
    pub fn send_nested(
        &self,
        our_vid: &str,
        intermediary_vid: &str,
        inner: &PackedMessage,
    ) -> Result<PackedMessage, TspError> {
        let our_private = self.store.get_private_vid(our_vid)?;
        let intermediary = self.resolver.resolve(intermediary_vid)?;
        message::routed::pack_nested(
            inner,
            our_vid,
            intermediary_vid,
            &our_private.signing_key,
            &intermediary.encryption_key,
        )
    }

    /// Process a routed message addressed to `our_vid` as an intermediary:
    /// open our routing layer, then either re-seal the remaining route to the
    /// next intermediary, or hand the opaque inner to the final recipient.
    pub fn forward_routed(&self, our_vid: &str, wire: &[u8]) -> Result<ForwardOutcome, TspError> {
        // Parse the envelope to authenticate the previous hop (the sender).
        let (envelope, _) = message::envelope::Envelope::decode(wire)?;
        if envelope.receiver != our_vid {
            return Err(TspError::InvalidMessage(format!(
                "routed message addressed to {}, not {our_vid}",
                envelope.receiver
            )));
        }
        let our_private = self.store.get_private_vid(our_vid)?;
        let prev = self.resolver.resolve(&envelope.sender)?;
        let unpacked = direct::unpack(
            wire,
            &our_private.decryption_key,
            &prev.signing_key,
        )?;

        // The message kind lives in the encrypted payload (the cleartext envelope
        // reports a Direct placeholder), so verify it after unpacking.
        if unpacked.message_type != MessageType::Routed {
            return Err(TspError::InvalidMessage(format!(
                "expected a Routed message, got {:?}",
                unpacked.message_type
            )));
        }

        match message::routed::next_hop(&unpacked)? {
            // Last intermediary: deliver the opaque inner to the final recipient.
            message::routed::RouteStep::Forward {
                next,
                remaining,
                inner,
            } if remaining.is_empty() => Ok(ForwardOutcome::Deliver {
                to: next,
                message: inner,
            }),
            // Re-seal the remaining route to the next intermediary.
            message::routed::RouteStep::Forward {
                next,
                remaining,
                inner,
            } => {
                let next_resolved = self.resolver.resolve(&next)?;
                let relayed = message::routed::pack_routed(
                    &inner,
                    &remaining,
                    our_vid,
                    &next,
                    &our_private.signing_key,
                    &next_resolved.encryption_key,
                )?;
                Ok(ForwardOutcome::Relay {
                    to: next,
                    message: relayed,
                })
            }
            // Empty route: the inner is for us to consume.
            message::routed::RouteStep::Deliver { inner } => Ok(ForwardOutcome::Deliver {
                to: our_vid.to_string(),
                message: inner,
            }),
        }
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

    /// Apply a received control message to the relationship FSM, correlating it
    /// to the relationship-forming message via the thread digest.
    ///
    /// `thread_digest` is the `SHA256` of the received message's plaintext frame
    /// (for an invite it is the value the accepter must echo back as `reply`).
    fn handle_control(
        &self,
        our_vid: &str,
        their_vid: &str,
        control: &ControlMessage,
        thread_digest: [u8; 32],
    ) -> Result<ControlOutcome, TspError> {
        use message::control::ControlType;

        let state = self.store.relationship_state(our_vid, their_vid);

        match control.control_type {
            ControlType::RelationshipFormingInvite => {
                // §7.2.3, the invite race. Both endpoints may invite each other
                // for the same VID pair at once. Both keep the invite whose
                // digest is lexicographically lower and discard the other, so
                // the two sides converge on one exchange and one thread id
                // rather than each believing it opened the relationship.
                if state == RelationshipState::Pending {
                    let ours = self.store.thread_digest(our_vid, their_vid);
                    if let Some(ours) = ours {
                        if ours.as_slice() < thread_digest.as_slice() {
                            return Err(TspError::Discarded(format!(
                                "invite race with {their_vid}: ours has the lower digest, keeping it"
                            )));
                        }
                        // Theirs wins: adopt it, replacing the invite we sent.
                        self.store.set_relationship_state(
                            our_vid,
                            their_vid,
                            RelationshipState::InviteReceived,
                        );
                        self.store
                            .set_thread_digest(our_vid, their_vid, thread_digest);
                        return Ok(ControlOutcome::None);
                    }
                }

                self.store.transition_relationship(
                    our_vid,
                    their_vid,
                    RelationshipEvent::ReceiveInvite,
                )?;
                // Remember the invite's digest: our accept echoes it back, and
                // a cancellation names the relationship by it.
                self.store
                    .set_thread_digest(our_vid, their_vid, thread_digest);
            }
            ControlType::RelationshipFormingAccept => {
                // The accept's first digest is the invite it answers.
                let reply = control.require_reply()?;
                if let Some(expected) = self.store.thread_digest(our_vid, their_vid)
                    && reply != &expected
                {
                    return Err(TspError::Discarded(format!(
                        "accept from {their_vid} answers an invite we did not send"
                    )));
                }
                self.store.transition_relationship(
                    our_vid,
                    their_vid,
                    RelationshipEvent::ReceiveAccept,
                )?;
                // The accept's own digest identifies the other direction; a
                // cancellation may name either half (§7.2.1).
                self.store
                    .set_reply_thread_digest(our_vid, their_vid, thread_digest);
            }
            ControlType::RelationshipCancel => {
                // §7.3. What we do depends on what we hold:
                //
                //   nothing            -> ignore the cancellation entirely
                //   one direction only -> remove it, send no reply
                //   bidirectional      -> reply with a cancellation, then remove
                //
                // A cancellation naming a relationship we do not recognise is
                // ignored rather than answered, so it cannot be used to probe
                // which relationships we hold.
                if state == RelationshipState::None {
                    return Err(TspError::Discarded(format!(
                        "cancellation from {their_vid} names no relationship we hold"
                    )));
                }
                if let Some(named) = control.reply.as_ref()
                    && !self.store.recognizes_digest(our_vid, their_vid, named)
                {
                    return Err(TspError::Discarded(format!(
                        "cancellation from {their_vid} names an unrecognised relationship"
                    )));
                }

                let reply_expected = state == RelationshipState::Bidirectional;
                self.store.transition_relationship(
                    our_vid,
                    their_vid,
                    RelationshipEvent::ReceiveCancel,
                )?;
                self.store.clear_thread_digest(our_vid, their_vid);
                if reply_expected {
                    return Ok(ControlOutcome::ReplyToCancellation);
                }
            }
        }

        Ok(ControlOutcome::None)
    }
}

impl Default for TspAgent {
    fn default() -> Self {
        Self::new()
    }
}

/// What a control message asks of the receiving endpoint beyond updating state.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum ControlOutcome {
    /// Nothing further to do.
    #[default]
    None,
    /// The peer cancelled a relationship we held in both directions, so §7.3
    /// asks us to answer with a cancellation of our own before forgetting it.
    ReplyToCancellation,
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
    /// The TSP thread digest. For an invite this is the value an accept must
    /// echo back; for an accept, this message's own digest.
    pub thread_digest: [u8; 32],
    /// If this is a control message, the parsed control payload.
    pub control: Option<ControlMessage>,
    /// What the message asks of this endpoint beyond a state change — see
    /// [`ControlOutcome`]. Always [`ControlOutcome::None`] for a non-control
    /// message.
    pub outcome: ControlOutcome,
}

/// The result of forwarding a routed message at an intermediary
/// ([`TspAgent::forward_routed`]).
#[derive(Debug, Clone)]
pub enum ForwardOutcome {
    /// A re-sealed routed layer to relay onward to the next intermediary.
    Relay {
        /// The next intermediary's VID (the new envelope receiver).
        to: String,
        /// The packed routed layer to send to `to`.
        message: PackedMessage,
    },
    /// The opaque inner message to deliver to the final recipient (last hop).
    Deliver {
        /// The final recipient's VID.
        to: String,
        /// The opaque inner message bytes (sealed to the final recipient).
        message: Vec<u8>,
    },
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
    fn routed_through_two_intermediaries() {
        let alice = TspAgent::new();
        let m1 = TspAgent::new();
        let m2 = TspAgent::new();
        let bob = TspAgent::new();

        let alice_v = PrivateVid::generate("did:example:alice");
        let m1_v = PrivateVid::generate("did:example:m1");
        let m2_v = PrivateVid::generate("did:example:m2");
        let bob_v = PrivateVid::generate("did:example:bob");
        let (a, m1p, m2p, b) = (
            alice_v.to_resolved(),
            m1_v.to_resolved(),
            m2_v.to_resolved(),
            bob_v.to_resolved(),
        );

        // Each party knows the VIDs it must resolve along the route.
        alice.add_private_vid(alice_v);
        alice.add_verified_vid(m1p.clone()); // first hop
        alice.add_verified_vid(b.clone()); // final (inner seal)

        m1.add_private_vid(m1_v);
        m1.add_verified_vid(a.clone()); // previous hop
        m1.add_verified_vid(m2p.clone()); // next hop

        m2.add_private_vid(m2_v);
        m2.add_verified_vid(m1p.clone()); // previous hop
        m2.add_verified_vid(b.clone()); // final

        bob.add_private_vid(bob_v);
        bob.add_verified_vid(a.clone()); // inner sender

        // Alice routes a message to Bob through m1 then m2.
        let layer1 = alice
            .send_routed(
                "did:example:alice",
                "did:example:bob",
                &["did:example:m1", "did:example:m2"],
                b"hi bob",
            )
            .unwrap();

        // m1 relays to m2.
        let layer2 = match m1.forward_routed("did:example:m1", &layer1.bytes).unwrap() {
            ForwardOutcome::Relay { to, message } => {
                assert_eq!(to, "did:example:m2");
                message
            }
            other => panic!("m1 expected Relay, got {other:?}"),
        };

        // m2 is the last hop: it delivers the opaque inner to bob.
        let inner = match m2.forward_routed("did:example:m2", &layer2.bytes).unwrap() {
            ForwardOutcome::Deliver { to, message } => {
                assert_eq!(to, "did:example:bob");
                message
            }
            other => panic!("m2 expected Deliver, got {other:?}"),
        };

        // §7.2.2 gates application messages on an existing relationship, so
        // the endpoints form one before the routed exchange — as they would in
        // practice, over the same route.
        bob.store.set_relationship_state(
            "did:example:bob",
            "did:example:alice",
            RelationshipState::Bidirectional,
        );

        // Bob recovers the plaintext; only he could (the inner was sealed to him).
        let received = bob.receive("did:example:bob", &inner).unwrap();
        assert_eq!(received.payload, b"hi bob");
        assert_eq!(received.sender, "did:example:alice");
        assert_eq!(received.message_type, MessageType::Direct);
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
        let rfa = bob.send_relationship_accept(&bob_id, &alice_id).unwrap();
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
        let rfa = bob.send_relationship_accept(&bob_id, &alice_id).unwrap();
        alice.receive(&alice_id, &rfa.bytes).unwrap();

        // Now Alice can send a message
        let msg = alice.send(&alice_id, &bob_id, b"Hello Bob!").unwrap();

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
        let rfa = bob.send_relationship_accept(&bob_id, &alice_id).unwrap();
        alice.receive(&alice_id, &rfa.bytes).unwrap();

        // Alice cancels
        let cancel = alice.send_relationship_cancel(&alice_id, &bob_id).unwrap();
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

    // ---- Rev 3 §7.2.2 / §7.2.3 / §7.3 protocol behaviour ----

    /// Build two agents that know each other's VIDs but hold no relationship.
    fn two_strangers() -> (TspAgent, TspAgent) {
        let alice = TspAgent::new();
        let bob = TspAgent::new();
        let a = PrivateVid::generate("did:example:alice");
        let b = PrivateVid::generate("did:example:bob");
        let (ap, bp) = (a.to_resolved(), b.to_resolved());
        alice.add_private_vid(a);
        alice.add_verified_vid(bp.clone());
        bob.add_private_vid(b);
        bob.add_verified_vid(ap.clone());
        (alice, bob)
    }

    /// §7.2.2: an application message from a VID we hold no relationship with
    /// is dropped. "It is not permissible that one endpoint which has learned a
    /// VID of the other simply starts with an application level message."
    #[test]
    fn an_application_message_without_a_relationship_is_dropped() {
        let (alice, bob) = two_strangers();
        // Built with the internal packer: our own `send` refuses to produce
        // this, so it stands in for a sender that does not follow the rule.
        let packed = alice
            .pack_message(
                "did:example:alice",
                "did:example:bob",
                b"unsolicited",
                MessageType::Direct,
            )
            .unwrap();

        let err = bob.receive("did:example:bob", &packed.bytes).unwrap_err();
        assert!(matches!(err, TspError::Discarded(_)), "got {err:?}");
    }

    /// An invite records the inbound half, which admits the messages that
    /// follow it — §3.6 lets a sender pack user data with its invite rather
    /// than wait a round trip.
    #[test]
    fn an_invite_admits_the_messages_that_follow_it() {
        let (alice, bob) = two_strangers();

        let invite = alice
            .send_relationship_invite("did:example:alice", "did:example:bob")
            .unwrap();
        bob.receive("did:example:bob", &invite.bytes).unwrap();

        // §3.6 lets a sender put user data alongside its invite rather than
        // wait a round trip, so this is packed directly rather than via `send`,
        // which waits for the relationship to complete.
        let packed = alice
            .pack_message(
                "did:example:alice",
                "did:example:bob",
                b"now allowed",
                MessageType::Direct,
            )
            .unwrap();
        let got = bob.receive("did:example:bob", &packed.bytes).unwrap();
        assert_eq!(got.payload, b"now allowed");
    }

    /// A node that is not an endpoint — an intermediary — can opt out.
    #[test]
    fn an_ungated_agent_accepts_a_message_from_a_stranger() {
        let alice = TspAgent::new();
        let bob = TspAgent::new().with_relationship_policy(RelationshipPolicy::Ungated);
        let a = PrivateVid::generate("did:example:alice");
        let b = PrivateVid::generate("did:example:bob");
        alice.add_private_vid(a.clone());
        alice.add_verified_vid(b.to_resolved());
        bob.add_private_vid(b);
        bob.add_verified_vid(a.to_resolved());

        let packed = alice
            .pack_message(
                "did:example:alice",
                "did:example:bob",
                b"ungated",
                MessageType::Direct,
            )
            .unwrap();
        let got = bob.receive("did:example:bob", &packed.bytes).unwrap();
        assert_eq!(got.payload, b"ungated");
    }

    /// §7.2.3: when both endpoints invite each other at once, both keep the
    /// invite whose digest is lexicographically lower. Run from both sides of
    /// the same pair of invites, so the two agents converge on one exchange.
    #[test]
    fn the_invite_race_is_broken_the_same_way_on_both_sides() {
        let (alice, bob) = two_strangers();

        let a_invite = alice
            .send_relationship_invite("did:example:alice", "did:example:bob")
            .unwrap();
        let b_invite = bob
            .send_relationship_invite("did:example:bob", "did:example:alice")
            .unwrap();

        let a_lower = a_invite.thread_digest.as_slice() < b_invite.thread_digest.as_slice();

        let alice_got = alice.receive("did:example:alice", &b_invite.bytes);
        let bob_got = bob.receive("did:example:bob", &a_invite.bytes);

        if a_lower {
            // Alice keeps her own and discards Bob's; Bob adopts Alice's.
            assert!(matches!(alice_got, Err(TspError::Discarded(_))));
            assert!(bob_got.is_ok());
            assert_eq!(
                bob.store
                    .thread_digest("did:example:bob", "did:example:alice"),
                Some(a_invite.thread_digest)
            );
        } else {
            assert!(matches!(bob_got, Err(TspError::Discarded(_))));
            assert!(alice_got.is_ok());
            assert_eq!(
                alice
                    .store
                    .thread_digest("did:example:alice", "did:example:bob"),
                Some(b_invite.thread_digest)
            );
        }
    }

    /// §7.3: a cancellation naming a relationship the receiver does not hold is
    /// ignored rather than answered, so it cannot be used to probe which
    /// relationships exist.
    #[test]
    fn a_cancellation_for_an_unknown_relationship_is_ignored() {
        let (alice, bob) = two_strangers();
        // A cancellation naming a relationship neither side holds. Built
        // directly, since the helper derives the digest from stored state.
        let cancel = alice
            .pack_control(
                "did:example:alice",
                "did:example:bob",
                &ControlMessage::cancel([0x11; 32]),
            )
            .unwrap();

        let err = bob.receive("did:example:bob", &cancel.bytes).unwrap_err();
        assert!(matches!(err, TspError::Discarded(_)), "got {err:?}");
    }

    /// §7.3: cancelling a relationship held in both directions asks the
    /// receiver to answer with a cancellation of its own before forgetting it.
    #[test]
    fn cancelling_a_bidirectional_relationship_expects_a_reply() {
        let (alice, bob) = two_strangers();

        let invite = alice
            .send_relationship_invite("did:example:alice", "did:example:bob")
            .unwrap();
        let received = bob.receive("did:example:bob", &invite.bytes).unwrap();
        let accept = bob
            .send_relationship_accept("did:example:bob", "did:example:alice")
            .unwrap();
        alice.receive("did:example:alice", &accept.bytes).unwrap();
        let _ = received;

        assert_eq!(
            bob.relationship_state("did:example:bob", "did:example:alice"),
            RelationshipState::Bidirectional
        );

        let cancel = alice
            .send_relationship_cancel("did:example:alice", "did:example:bob")
            .unwrap();
        let got = bob.receive("did:example:bob", &cancel.bytes).unwrap();

        assert_eq!(got.outcome, ControlOutcome::ReplyToCancellation);
        assert_eq!(
            bob.relationship_state("did:example:bob", "did:example:alice"),
            RelationshipState::None
        );
    }

    /// A cancellation of a half-formed relationship removes it without a reply.
    #[test]
    fn cancelling_a_one_sided_relationship_expects_no_reply() {
        let (alice, bob) = two_strangers();

        let invite = alice
            .send_relationship_invite("did:example:alice", "did:example:bob")
            .unwrap();
        bob.receive("did:example:bob", &invite.bytes).unwrap();

        let cancel = alice
            .send_relationship_cancel("did:example:alice", "did:example:bob")
            .unwrap();
        let got = bob.receive("did:example:bob", &cancel.bytes).unwrap();

        assert_eq!(got.outcome, ControlOutcome::None);
        assert_eq!(
            bob.relationship_state("did:example:bob", "did:example:alice"),
            RelationshipState::None
        );
    }
}
