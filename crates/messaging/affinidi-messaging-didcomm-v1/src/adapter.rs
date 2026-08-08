//! DIDComm v1 adapter for the `affinidi-messaging-core` traits.
//!
//! The counterpart to [`affinidi_messaging_didcomm::adapter::DIDCommAdapter`],
//! and the seam that makes v1 and v2.1 usable interchangeably: a consumer
//! holding a `dyn MessagingProtocol` can drive DIDComm v1, DIDComm v2.1
//! (`affinidi-messaging-didcomm`), or TSP (`affinidi-tsp`) through one surface,
//! and tell them apart by [`Protocol`].
//!
//! # What the flat trait cannot express
//!
//! [`ReceivedMessage`] reports the sender as `Option<String>` beside a
//! `verified: bool` — the exact shape [`crate::UnpackResult`] exists to avoid.
//! It is fine for v2.1, where an authenticated envelope always yields a DID.
//! It cannot represent v1's third state: an envelope that is cryptographically
//! authenticated by a verkey which is bound to no known DID
//! ([`UnpackResult::AuthcryptUnknownSender`]).
//!
//! This adapter therefore **degrades that case to unauthenticated** —
//! `sender: None`, `verified: false` — because a consumer of the flat API has
//! no DID to act on either way, and reporting `verified: true` with no sender
//! would invite exactly the careless read the typed API prevents.
//!
//! A caller that needs to distinguish "unknown sender" from "no sender" (to
//! start a connection handshake, say) must use [`DIDCommV1Agent::unpack`]
//! directly. That is a real limitation of the shared trait, not of v1.

use affinidi_messaging_core::{
    IdentityResolver, MessagingError, MessagingProtocol, Protocol, ReceivedMessage,
    RelationshipManager, RelationshipState, ResolvedIdentity as CoreResolvedIdentity,
};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use crate::message::unpack::UnpackResult;
use crate::protocols::{basic_message, forward};
use crate::{DIDCommV1Agent, MessageV1};

/// Wraps a [`DIDCommV1Agent`] and exposes it through the protocol-agnostic API.
pub struct DIDCommV1Adapter {
    agent: DIDCommV1Agent,
}

impl DIDCommV1Adapter {
    /// Wrap an agent.
    pub fn new(agent: DIDCommV1Agent) -> Self {
        Self { agent }
    }

    /// The underlying agent, for v1-specific operations the trait cannot express.
    pub fn agent(&self) -> &DIDCommV1Agent {
        &self.agent
    }

    /// The underlying agent, mutably.
    pub fn agent_mut(&mut self) -> &mut DIDCommV1Agent {
        &mut self.agent
    }
}

/// Wrap a raw payload in a basic message, mirroring how the v2.1 adapter wraps
/// one in a `basicmessage/2.0` body.
///
/// Non-UTF-8 payloads are base64url-encoded, as the v2 adapter does — `content`
/// is a JSON string and cannot hold arbitrary bytes.
fn wrap_payload(payload: &[u8]) -> Result<MessageV1, MessagingError> {
    let content =
        String::from_utf8(payload.to_vec()).unwrap_or_else(|_| URL_SAFE_NO_PAD.encode(payload));
    basic_message::BasicMessage::new(content)
        .map(basic_message::BasicMessage::finalize)
        .map_err(|e| MessagingError::Pack(e.to_string()))
}

/// Pull the payload back out of a received message.
fn extract_payload(msg: &MessageV1) -> Vec<u8> {
    match basic_message::content(msg) {
        Some(content) => content.as_bytes().to_vec(),
        // Not a basic message (or no `content`): hand back the whole body,
        // since v1 has no single canonical payload member.
        None => serde_json::to_vec(&msg.body).unwrap_or_default(),
    }
}

#[async_trait::async_trait]
impl MessagingProtocol for DIDCommV1Adapter {
    fn protocol(&self) -> Protocol {
        Protocol::DIDCommV1
    }

    async fn pack(
        &self,
        payload: &[u8],
        sender: &str,
        recipient: &str,
    ) -> Result<Vec<u8>, MessagingError> {
        let msg = wrap_payload(payload)?;
        self.agent
            .pack_authcrypt(&msg, sender, recipient)
            .map(String::into_bytes)
            .map_err(|e| MessagingError::Pack(e.to_string()))
    }

    async fn pack_anonymous(
        &self,
        payload: &[u8],
        recipient: &str,
    ) -> Result<Vec<u8>, MessagingError> {
        let msg = wrap_payload(payload)?;
        self.agent
            .pack_anoncrypt(&msg, recipient)
            .map(String::into_bytes)
            .map_err(|e| MessagingError::Pack(e.to_string()))
    }

    async fn unpack(&self, packed: &[u8]) -> Result<ReceivedMessage, MessagingError> {
        let input = std::str::from_utf8(packed)
            .map_err(|e| MessagingError::Unpack(format!("invalid UTF-8: {e}")))?;

        let result = self
            .agent
            .unpack(input)
            .map_err(|e| MessagingError::Unpack(e.to_string()))?;

        // v1 carries no `from` header, so there is no plaintext sender claim to
        // cross-check against the authenticated one — the check the v2 adapter
        // performs has nothing to operate on here, and nothing to catch.
        let (sender, recipient, verified, encrypted) = match &result {
            UnpackResult::Authcrypt {
                sender, recipient, ..
            } => (Some(sender.to_string()), recipient.to_string(), true, true),
            // Authenticated by a key, but attributable to no DID. Reported as
            // unauthenticated — see the module docs.
            UnpackResult::AuthcryptUnknownSender { recipient, .. } => {
                (None, recipient.to_string(), false, true)
            }
            UnpackResult::Anoncrypt { recipient, .. } => (None, recipient.to_string(), false, true),
            UnpackResult::Plaintext(_) => (None, String::new(), false, false),
        };

        let message = result.into_message();
        Ok(ReceivedMessage {
            id: message.id.clone(),
            sender,
            recipient,
            payload: extract_payload(&message),
            protocol: Protocol::DIDCommV1,
            verified,
            encrypted,
        })
    }

    async fn wrap_for_relay(
        &self,
        packed: &[u8],
        next_hop: &str,
        final_recipient: &str,
    ) -> Result<Vec<u8>, MessagingError> {
        let packed = std::str::from_utf8(packed)
            .map_err(|e| MessagingError::Pack(format!("invalid UTF-8: {e}")))?;

        // Unlike the v2 adapter, `final_recipient` is load-bearing here: a v1
        // forward addresses its destination by **verkey**, so the inner
        // recipient has to be resolved rather than left to the envelope.
        let destination = self
            .agent
            .store()
            .get_resolved(final_recipient)
            .map_err(|e| MessagingError::Resolution(e.to_string()))?;
        let relay = self
            .agent
            .store()
            .get_resolved(next_hop)
            .map_err(|e| MessagingError::Resolution(e.to_string()))?;

        forward::wrap_in_forward(&destination.verkey, packed, &relay.verkey)
            .map(String::into_bytes)
            .map_err(|e| MessagingError::Pack(e.to_string()))
    }
}

#[async_trait::async_trait]
impl IdentityResolver for DIDCommV1Adapter {
    async fn resolve(&self, id: &str) -> Result<CoreResolvedIdentity, MessagingError> {
        let resolved = self
            .agent
            .store()
            .get_resolved(id)
            .map_err(|e| MessagingError::Resolution(e.to_string()))?;

        Ok(CoreResolvedIdentity {
            id: resolved.did.to_string(),
            // In v1 these are the same key: the Ed25519 verkey verifies, and
            // its Montgomery form does key agreement.
            verification_key: Some(resolved.verkey.as_bytes().to_vec()),
            encryption_key: resolved
                .x25519_public()
                .map_err(|e| MessagingError::Resolution(e.to_string()))?
                .to_vec(),
            endpoints: None,
        })
    }
}

#[async_trait::async_trait]
impl RelationshipManager for DIDCommV1Adapter {
    async fn request_relationship(
        &self,
        _my_id: &str,
        _their_id: &str,
    ) -> Result<RelationshipState, MessagingError> {
        // Like v2, relationships are implicit once both parties are known.
        Ok(RelationshipState::Bidirectional)
    }

    async fn accept_relationship(
        &self,
        _my_id: &str,
        _their_id: &str,
        _request_id: &[u8],
    ) -> Result<RelationshipState, MessagingError> {
        Ok(RelationshipState::Bidirectional)
    }

    async fn cancel_relationship(
        &self,
        _my_id: &str,
        _their_id: &str,
    ) -> Result<RelationshipState, MessagingError> {
        Ok(RelationshipState::None)
    }

    async fn relationship_state(
        &self,
        _my_id: &str,
        _their_id: &str,
    ) -> Result<RelationshipState, MessagingError> {
        Ok(RelationshipState::Bidirectional)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Mediator, PrivateIdentity};

    fn adapters() -> (DIDCommV1Adapter, DIDCommV1Adapter) {
        let alice = PrivateIdentity::generate("did:example:alice").unwrap();
        let bob = PrivateIdentity::generate("did:example:bob").unwrap();

        let mut alice_agent = DIDCommV1Agent::new();
        let mut bob_agent = DIDCommV1Agent::new();

        alice_agent.add_peer(bob.to_resolved());
        bob_agent.add_peer(alice.to_resolved());
        alice_agent.add_identity(alice);
        bob_agent.add_identity(bob);

        (
            DIDCommV1Adapter::new(alice_agent),
            DIDCommV1Adapter::new(bob_agent),
        )
    }

    #[tokio::test]
    async fn reports_its_own_protocol() {
        let (alice, _) = adapters();
        assert_eq!(alice.protocol(), Protocol::DIDCommV1);
        assert_ne!(
            alice.protocol(),
            Protocol::DIDComm,
            "v1 must be distinguishable from v2.1 through the shared trait"
        );
    }

    #[tokio::test]
    async fn pack_unpack_authenticated() {
        let (alice, bob) = adapters();

        let packed = alice
            .pack(
                b"Hello over the shared trait",
                "did:example:alice",
                "did:example:bob",
            )
            .await
            .unwrap();

        let received = bob.unpack(&packed).await.unwrap();
        assert_eq!(received.protocol, Protocol::DIDCommV1);
        assert!(received.verified);
        assert!(received.encrypted);
        assert_eq!(received.sender.as_deref(), Some("did:example:alice"));
        assert_eq!(received.recipient, "did:example:bob");
        assert_eq!(
            std::str::from_utf8(&received.payload).unwrap(),
            "Hello over the shared trait"
        );
    }

    #[tokio::test]
    async fn pack_unpack_anonymous_is_not_verified() {
        let (alice, bob) = adapters();

        let packed = alice
            .pack_anonymous(b"Anonymous message", "did:example:bob")
            .await
            .unwrap();

        let received = bob.unpack(&packed).await.unwrap();
        assert!(!received.verified);
        assert!(received.encrypted);
        assert_eq!(received.sender, None);
    }

    /// The degradation documented at the top of this module: authenticated by a
    /// key we cannot attribute must never surface as `verified`.
    #[tokio::test]
    async fn unknown_sender_degrades_to_unverified() {
        let alice_identity = PrivateIdentity::generate("did:example:alice").unwrap();
        let bob_identity = PrivateIdentity::generate("did:example:bob").unwrap();

        let mut alice_agent = DIDCommV1Agent::new();
        alice_agent.add_peer(bob_identity.to_resolved());
        alice_agent.add_identity(alice_identity);
        let alice = DIDCommV1Adapter::new(alice_agent);

        // Bob holds his own key but has no binding for Alice's verkey, so the
        // envelope authenticates without being attributable.
        let mut bob_agent = DIDCommV1Agent::new();
        bob_agent.add_identity(bob_identity);
        let bob = DIDCommV1Adapter::new(bob_agent);

        let packed = alice
            .pack(b"who am i", "did:example:alice", "did:example:bob")
            .await
            .unwrap();

        let received = bob.unpack(&packed).await.unwrap();
        assert_eq!(received.sender, None);
        assert!(
            !received.verified,
            "an unattributable sender must not be reported as verified"
        );

        // The native API still exposes the real state.
        let native = bob
            .agent()
            .unpack(std::str::from_utf8(&packed).unwrap())
            .unwrap();
        assert!(native.is_authcrypt());
        assert!(matches!(
            native,
            UnpackResult::AuthcryptUnknownSender { .. }
        ));
    }

    #[tokio::test]
    async fn wrap_for_relay_addresses_the_final_recipient_by_verkey() {
        let (mut alice, bob) = adapters();
        let mediator_identity = PrivateIdentity::generate("did:example:mediator").unwrap();
        alice.agent_mut().add_peer(mediator_identity.to_resolved());

        let packed = alice
            .pack(b"through a relay", "did:example:alice", "did:example:bob")
            .await
            .unwrap();
        let relayed = alice
            .wrap_for_relay(&packed, "did:example:mediator", "did:example:bob")
            .await
            .unwrap();

        let mut mediator_agent = DIDCommV1Agent::new();
        mediator_agent.add_identity(mediator_identity);
        let mediator = DIDCommV1Adapter::new(mediator_agent);

        let at_mediator = mediator
            .agent()
            .unpack(std::str::from_utf8(&relayed).unwrap())
            .unwrap()
            .into_message();
        assert!(forward::is_forward(&at_mediator));

        let inner = forward::extract_payload(&at_mediator).unwrap();
        let received = bob.unpack(inner.as_bytes()).await.unwrap();
        assert!(received.verified);
        assert_eq!(received.sender.as_deref(), Some("did:example:alice"));
    }

    #[tokio::test]
    async fn identity_resolution_exposes_both_key_forms() {
        let (alice, _) = adapters();
        let resolved = alice.resolve("did:example:bob").await.unwrap();

        assert_eq!(resolved.id, "did:example:bob");
        assert_eq!(resolved.verification_key.as_ref().unwrap().len(), 32);
        assert_eq!(resolved.encryption_key.len(), 32);
        assert_ne!(
            resolved.verification_key.as_deref().unwrap(),
            resolved.encryption_key.as_slice(),
            "the Ed25519 verkey and its Montgomery form are different bytes"
        );
    }

    #[tokio::test]
    async fn relationships_are_implicit_like_v2() {
        let (alice, _) = adapters();
        assert_eq!(
            alice
                .relationship_state("did:example:alice", "did:example:bob")
                .await
                .unwrap(),
            RelationshipState::Bidirectional
        );
    }

    /// The parity claim, exercised through a trait object: the same code drives
    /// both crates and can still tell which protocol produced a message.
    #[tokio::test]
    async fn drives_v1_and_v2_through_one_trait_object() {
        use affinidi_messaging_didcomm::DIDCommAgent;
        use affinidi_messaging_didcomm::adapter::DIDCommAdapter;
        use affinidi_messaging_didcomm::identity::PrivateIdentity as V2Identity;

        let (v1_alice, v1_bob) = adapters();

        let mut v2_alice_agent = DIDCommAgent::new();
        let mut v2_bob_agent = DIDCommAgent::new();
        let v2_alice = V2Identity::generate("did:example:alice");
        let v2_bob = V2Identity::generate("did:example:bob");
        v2_alice_agent.add_peer(v2_bob.to_resolved());
        v2_bob_agent.add_peer(v2_alice.to_resolved());
        v2_alice_agent.add_identity(v2_alice);
        v2_bob_agent.add_identity(v2_bob);

        let senders: Vec<Box<dyn MessagingProtocol>> = vec![
            Box::new(v1_alice),
            Box::new(DIDCommAdapter::new(v2_alice_agent)),
        ];
        let receivers: Vec<Box<dyn MessagingProtocol>> = vec![
            Box::new(v1_bob),
            Box::new(DIDCommAdapter::new(v2_bob_agent)),
        ];

        for (sender, receiver) in senders.iter().zip(receivers.iter()) {
            let packed = sender
                .pack(
                    b"transport agnostic",
                    "did:example:alice",
                    "did:example:bob",
                )
                .await
                .unwrap();
            let received = receiver.unpack(&packed).await.unwrap();

            assert!(received.verified);
            assert!(received.encrypted);
            assert_eq!(received.sender.as_deref(), Some("did:example:alice"));
            assert_eq!(
                std::str::from_utf8(&received.payload).unwrap(),
                "transport agnostic"
            );
            assert_eq!(received.protocol, sender.protocol());
        }

        assert_ne!(
            senders[0].protocol(),
            senders[1].protocol(),
            "the two protocols must remain distinguishable"
        );
    }

    #[tokio::test]
    async fn mediator_route_is_applied_by_the_agent() {
        let (mut alice, _) = adapters();
        let mediator_identity = PrivateIdentity::generate("did:example:mediator").unwrap();
        alice
            .agent_mut()
            .add_route("did:example:bob", Mediator::new(mediator_identity.verkey))
            .unwrap();

        let packed = alice
            .pack(b"routed", "did:example:alice", "did:example:bob")
            .await
            .unwrap();

        let mut mediator_agent = DIDCommV1Agent::new();
        mediator_agent.add_identity(mediator_identity);
        let at_mediator = mediator_agent
            .unpack(std::str::from_utf8(&packed).unwrap())
            .unwrap()
            .into_message();
        assert!(forward::is_forward(&at_mediator));
    }
}
