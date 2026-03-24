//! DIDComm adapter implementing the `affinidi-messaging-core` traits.
//!
//! This module bridges the DIDComm-specific API (`DIDCommAgent`) to the
//! protocol-agnostic messaging traits, allowing DIDComm to be used
//! interchangeably with TSP.

use base64ct::{Base64UrlUnpadded, Encoding};

use affinidi_messaging_core::{
    IdentityResolver, MessagingError, MessagingProtocol, Protocol, ReceivedMessage,
    RelationshipManager, RelationshipState, ResolvedIdentity,
};

use crate::DIDCommAgent;
use crate::message::forward;
use crate::message::unpack::UnpackResult;

/// DIDComm adapter implementing the unified messaging traits.
///
/// Wraps a `DIDCommAgent` and exposes it through the protocol-agnostic API
/// defined in `affinidi-messaging-core`.
pub struct DIDCommAdapter {
    agent: DIDCommAgent,
}

impl DIDCommAdapter {
    /// Create a new DIDComm adapter wrapping the given agent.
    pub fn new(agent: DIDCommAgent) -> Self {
        Self { agent }
    }

    /// Get the underlying DIDComm agent for direct access.
    pub fn agent(&self) -> &DIDCommAgent {
        &self.agent
    }

    /// Get a mutable reference to the underlying agent.
    pub fn agent_mut(&mut self) -> &mut DIDCommAgent {
        &mut self.agent
    }
}

#[async_trait::async_trait]
impl MessagingProtocol for DIDCommAdapter {
    fn protocol(&self) -> Protocol {
        Protocol::DIDComm
    }

    async fn pack(
        &self,
        payload: &[u8],
        sender: &str,
        recipient: &str,
    ) -> Result<Vec<u8>, MessagingError> {
        // Build a DIDComm message wrapping the raw payload
        let msg = crate::message::Message::new(
            "https://didcomm.org/basicmessage/2.0/message",
            serde_json::Value::String(
                String::from_utf8(payload.to_vec())
                    .unwrap_or_else(|_| Base64UrlUnpadded::encode_string(payload)),
            ),
        )
        .from(sender)
        .to(vec![recipient.to_string()]);

        let packed = self
            .agent
            .pack_authcrypt(&msg, sender, recipient)
            .map_err(|e| MessagingError::Pack(e.to_string()))?;

        Ok(packed.into_bytes())
    }

    async fn pack_anonymous(
        &self,
        payload: &[u8],
        recipient: &str,
    ) -> Result<Vec<u8>, MessagingError> {
        let msg = crate::message::Message::new(
            "https://didcomm.org/basicmessage/2.0/message",
            serde_json::Value::String(
                String::from_utf8(payload.to_vec())
                    .unwrap_or_else(|_| Base64UrlUnpadded::encode_string(payload)),
            ),
        )
        .to(vec![recipient.to_string()]);

        let packed = self
            .agent
            .pack_anoncrypt(&msg, recipient)
            .map_err(|e| MessagingError::Pack(e.to_string()))?;

        Ok(packed.into_bytes())
    }

    async fn unpack(&self, packed: &[u8]) -> Result<ReceivedMessage, MessagingError> {
        let input = std::str::from_utf8(packed)
            .map_err(|e| MessagingError::Unpack(format!("invalid UTF-8: {e}")))?;

        // Try to detect sender from the JWE header (skid field)
        let sender_did = self.detect_sender(input);

        let result = self
            .agent
            .unpack(input, sender_did.as_deref())
            .map_err(|e| MessagingError::Unpack(e.to_string()))?;

        match result {
            UnpackResult::Encrypted {
                message,
                authenticated,
                sender_kid,
                recipient_kid,
            } => {
                // Extract payload from message body
                let payload = extract_payload(&message.body);

                Ok(ReceivedMessage {
                    id: message.id,
                    sender: message.from.or_else(|| {
                        sender_kid.map(|kid| kid.split('#').next().unwrap_or(&kid).to_string())
                    }),
                    recipient: message
                        .to
                        .and_then(|t| t.into_iter().next())
                        .unwrap_or_else(|| {
                            recipient_kid
                                .split('#')
                                .next()
                                .unwrap_or(&recipient_kid)
                                .to_string()
                        }),
                    payload,
                    protocol: Protocol::DIDComm,
                    verified: authenticated,
                    encrypted: true,
                })
            }
            UnpackResult::Signed {
                message,
                signer_kid,
            } => {
                let payload = extract_payload(&message.body);

                Ok(ReceivedMessage {
                    id: message.id,
                    sender: message.from.or_else(|| {
                        signer_kid.map(|kid| kid.split('#').next().unwrap_or(&kid).to_string())
                    }),
                    recipient: message
                        .to
                        .and_then(|t| t.into_iter().next())
                        .unwrap_or_default(),
                    payload,
                    protocol: Protocol::DIDComm,
                    verified: true,
                    encrypted: false,
                })
            }
            UnpackResult::Plaintext(message) => {
                let payload = extract_payload(&message.body);

                Ok(ReceivedMessage {
                    id: message.id,
                    sender: message.from,
                    recipient: message
                        .to
                        .and_then(|t| t.into_iter().next())
                        .unwrap_or_default(),
                    payload,
                    protocol: Protocol::DIDComm,
                    verified: false,
                    encrypted: false,
                })
            }
        }
    }

    async fn wrap_for_relay(
        &self,
        packed: &[u8],
        next_hop: &str,
        _final_recipient: &str,
    ) -> Result<Vec<u8>, MessagingError> {
        let packed_str = std::str::from_utf8(packed)
            .map_err(|e| MessagingError::Pack(format!("invalid UTF-8: {e}")))?;

        // Wrap in a forward message
        let forward_msg = forward::wrap_in_forward(next_hop, packed_str)
            .map_err(|e| MessagingError::Pack(e.to_string()))?;

        // Encrypt the forward message for the next hop (anoncrypt)
        let forward_json = forward_msg
            .to_json()
            .map_err(|e| MessagingError::Pack(e.to_string()))?;

        let recipient = self
            .agent
            .store()
            .get_resolved(next_hop)
            .map_err(|e| MessagingError::Resolution(e.to_string()))?;

        let packed = crate::jwe::encrypt::anoncrypt(
            &forward_json,
            &[(
                recipient.key_agreement_kid.as_str(),
                &recipient.key_agreement_public,
            )],
        )
        .map_err(|e| MessagingError::Pack(e.to_string()))?;

        Ok(packed.into_bytes())
    }
}

impl DIDCommAdapter {
    /// Try to detect the sender DID from the JWE protected header's skid field.
    fn detect_sender(&self, input: &str) -> Option<String> {
        let value: serde_json::Value = serde_json::from_str(input).ok()?;
        let protected_b64 = value.get("protected")?.as_str()?;
        let header_bytes = Base64UrlUnpadded::decode_vec(protected_b64).ok()?;
        let header: serde_json::Value = serde_json::from_slice(&header_bytes).ok()?;
        let skid = header.get("skid")?.as_str()?;
        // Extract DID from DID URL (strip fragment)
        Some(skid.split('#').next().unwrap_or(skid).to_string())
    }
}

#[async_trait::async_trait]
impl IdentityResolver for DIDCommAdapter {
    async fn resolve(&self, id: &str) -> Result<ResolvedIdentity, MessagingError> {
        let resolved = self
            .agent
            .store()
            .get_resolved(id)
            .map_err(|e| MessagingError::Resolution(e.to_string()))?;

        Ok(ResolvedIdentity {
            id: resolved.did.clone(),
            verification_key: resolved.verifying_key.map(|k| k.to_vec()),
            encryption_key: public_key_bytes(&resolved.key_agreement_public),
            endpoints: None, // DIDComm endpoints come from DID resolution, not stored here
        })
    }
}

#[async_trait::async_trait]
impl RelationshipManager for DIDCommAdapter {
    async fn request_relationship(
        &self,
        _my_id: &str,
        _their_id: &str,
    ) -> Result<RelationshipState, MessagingError> {
        // DIDComm has implicit relationships — always bidirectional
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
        // DIDComm: if we know their identity, relationship is bidirectional
        Ok(RelationshipState::Bidirectional)
    }
}

/// Extract payload bytes from a DIDComm message body.
fn extract_payload(body: &serde_json::Value) -> Vec<u8> {
    match body {
        serde_json::Value::String(s) => s.as_bytes().to_vec(),
        other => serde_json::to_vec(other).unwrap_or_default(),
    }
}

/// Get raw bytes from a PublicKeyAgreement for the ResolvedIdentity.
fn public_key_bytes(key: &crate::crypto::key_agreement::PublicKeyAgreement) -> Vec<u8> {
    use crate::crypto::key_agreement::PublicKeyAgreement;
    match key {
        PublicKeyAgreement::X25519(bytes) => bytes.to_vec(),
        PublicKeyAgreement::P256(pk) => {
            use p256::elliptic_curve::sec1::ToEncodedPoint;
            pk.to_encoded_point(true).as_bytes().to_vec()
        }
        PublicKeyAgreement::K256(pk) => {
            use k256::elliptic_curve::sec1::ToEncodedPoint;
            pk.to_encoded_point(true).as_bytes().to_vec()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::PrivateIdentity;

    fn setup() -> (DIDCommAdapter, DIDCommAdapter) {
        let mut alice_agent = DIDCommAgent::new();
        let mut bob_agent = DIDCommAgent::new();

        let alice = PrivateIdentity::generate("did:example:alice");
        let bob = PrivateIdentity::generate("did:example:bob");

        alice_agent.add_peer(bob.to_resolved());
        bob_agent.add_peer(alice.to_resolved());

        alice_agent.add_identity(alice);
        bob_agent.add_identity(bob);

        (
            DIDCommAdapter::new(alice_agent),
            DIDCommAdapter::new(bob_agent),
        )
    }

    #[tokio::test]
    async fn protocol_type() {
        let (alice, _) = setup();
        assert_eq!(alice.protocol(), Protocol::DIDComm);
    }

    #[tokio::test]
    async fn pack_unpack_authenticated() {
        let (alice, bob) = setup();

        let packed = alice
            .pack(
                b"Hello from messaging-core!",
                "did:example:alice",
                "did:example:bob",
            )
            .await
            .unwrap();

        let received = bob.unpack(&packed).await.unwrap();
        assert_eq!(received.protocol, Protocol::DIDComm);
        assert!(received.verified);
        assert!(received.encrypted);
        assert_eq!(
            std::str::from_utf8(&received.payload).unwrap(),
            "Hello from messaging-core!"
        );
    }

    #[tokio::test]
    async fn pack_unpack_anonymous() {
        // Create Bob with a known identity
        let mut bob_agent = DIDCommAgent::new();
        let bob = PrivateIdentity::generate("did:example:bob");
        let bob_resolved = bob.to_resolved();
        bob_agent.add_identity(bob);
        let bob_adapter = DIDCommAdapter::new(bob_agent);

        // Anonymous sender only needs Bob's public identity
        let mut anon_agent = DIDCommAgent::new();
        anon_agent.add_peer(bob_resolved);
        let anon = DIDCommAdapter::new(anon_agent);

        let packed = anon
            .pack_anonymous(b"Anonymous message", "did:example:bob")
            .await
            .unwrap();

        let received = bob_adapter.unpack(&packed).await.unwrap();
        assert!(!received.verified); // anoncrypt — sender not authenticated
        assert!(received.encrypted);
    }

    #[tokio::test]
    async fn implicit_relationships() {
        let (alice, _) = setup();

        let state = alice
            .relationship_state("did:example:alice", "did:example:bob")
            .await
            .unwrap();
        assert_eq!(state, RelationshipState::Bidirectional);

        let state = alice
            .request_relationship("did:example:alice", "did:example:bob")
            .await
            .unwrap();
        assert_eq!(state, RelationshipState::Bidirectional);
    }

    #[tokio::test]
    async fn identity_resolution() {
        let (alice, _) = setup();
        let resolved = alice.resolve("did:example:bob").await.unwrap();
        assert_eq!(resolved.id, "did:example:bob");
        assert!(!resolved.encryption_key.is_empty());
    }
}
