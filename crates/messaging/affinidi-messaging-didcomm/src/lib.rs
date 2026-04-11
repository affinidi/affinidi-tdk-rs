//! # affinidi-messaging-didcomm
//!
//! A lean DIDComm v2.1 implementation for the Affinidi TDK.
//!
//! Supports:
//! - **Authcrypt** (ECDH-1PU+A256KW, A256CBC-HS512) — authenticated encryption
//! - **Anoncrypt** (ECDH-ES+A256KW, A256CBC-HS512) — anonymous encryption
//! - **Signed messages** (EdDSA / Ed25519)
//! - **Plaintext messages**
//! - **Forward/routing** (DIDComm Routing Protocol 2.0)
//! - **Curves**: X25519, P-256, K-256 (secp256k1)
//!
//! ## Architecture
//!
//! Mirrors the `affinidi-tsp` TspAgent pattern with `DIDCommAgent` as the
//! high-level entry point. Both can be abstracted behind the same
//! `MessagingProtocol` trait from `affinidi-messaging-core`.

pub mod crypto;
pub mod error;
pub mod identity;
pub mod jwe;
pub mod jws;
pub mod message;
pub mod store;

#[cfg(feature = "messaging-core")]
pub mod adapter;

// Re-export core types at crate root for convenience and legacy API compat.
pub use crate::error::DIDCommError;
pub use crate::message::unpack::UnpackResult;
pub use crate::message::{Attachment, AttachmentData, Message, MessageBuilder};

use crate::identity::{PrivateIdentity, ResolvedIdentity};
use crate::message::forward;
use crate::message::pack;
use crate::message::unpack;
use crate::store::DIDCommStore;

/// Compatibility type matching the legacy `UnpackMetadata`.
///
/// The new DIDComm crate returns structured [`UnpackResult`] variants instead of a
/// flat metadata struct. This shim lets callers that depend on the old API keep working.
#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
pub struct UnpackMetadata {
    pub encrypted: bool,
    pub authenticated: bool,
    pub non_repudiation: bool,
    pub anonymous_sender: bool,
    pub re_wrapped_in_forward: bool,
    pub encrypted_from_kid: Option<String>,
    pub encrypted_to_kids: Vec<String>,
    pub sign_from: Option<String>,
}

impl UnpackMetadata {
    /// Construct from an [`UnpackResult`] (convenience for migration).
    pub fn from_unpack_result(result: &UnpackResult) -> Self {
        match result {
            UnpackResult::Encrypted {
                authenticated,
                sender_kid,
                recipient_kid,
                ..
            } => Self {
                encrypted: true,
                authenticated: *authenticated,
                anonymous_sender: !*authenticated,
                encrypted_from_kid: sender_kid.clone(),
                encrypted_to_kids: vec![recipient_kid.clone()],
                ..Default::default()
            },
            UnpackResult::Signed { signer_kid, .. } => Self {
                non_repudiation: true,
                sign_from: signer_kid.clone(),
                ..Default::default()
            },
            UnpackResult::Plaintext(_) => Self::default(),
        }
    }
}

/// High-level DIDComm agent — mirrors the TspAgent pattern.
///
/// Manages local identities, resolved remote identities, and mediator
/// routes. Provides simple pack/unpack operations.
pub struct DIDCommAgent {
    store: DIDCommStore,
}

impl DIDCommAgent {
    /// Create a new agent with an empty store.
    pub fn new() -> Self {
        Self {
            store: DIDCommStore::new(),
        }
    }

    /// Get a reference to the underlying store.
    pub fn store(&self) -> &DIDCommStore {
        &self.store
    }

    /// Get a mutable reference to the underlying store.
    pub fn store_mut(&mut self) -> &mut DIDCommStore {
        &mut self.store
    }

    /// Add a local identity to the agent.
    pub fn add_identity(&mut self, identity: PrivateIdentity) {
        self.store.add_local(identity);
    }

    /// Add a resolved remote identity.
    pub fn add_peer(&mut self, identity: ResolvedIdentity) {
        self.store.add_resolved(identity);
    }

    /// Pack a message with authcrypt for a specific recipient.
    ///
    /// Looks up the sender and recipient in the store.
    pub fn pack_authcrypt(
        &self,
        msg: &Message,
        sender_did: &str,
        recipient_did: &str,
    ) -> Result<String, DIDCommError> {
        let sender = self.store.get_local(sender_did)?;
        let recipient = self.store.get_resolved(recipient_did)?;

        let packed = pack::pack_encrypted_authcrypt(
            msg,
            &sender.key_agreement_kid,
            &sender.key_agreement_private,
            &[(
                recipient.key_agreement_kid.as_str(),
                &recipient.key_agreement_public,
            )],
        )?;

        // If there's a mediator route, wrap in a forward
        if let Some(mediator) = self.store.get_route(recipient_did) {
            let forward_msg = forward::wrap_in_forward(recipient_did, &packed)?;
            let forward_json = forward_msg.to_json()?;
            crate::jwe::encrypt::anoncrypt(
                &forward_json,
                &[(
                    mediator.key_agreement_kid.as_str(),
                    &mediator.key_agreement_public,
                )],
            )
        } else {
            Ok(packed)
        }
    }

    /// Pack a message with anoncrypt for a specific recipient.
    pub fn pack_anoncrypt(
        &self,
        msg: &Message,
        recipient_did: &str,
    ) -> Result<String, DIDCommError> {
        let recipient = self.store.get_resolved(recipient_did)?;

        let packed = pack::pack_encrypted_anoncrypt(
            msg,
            &[(
                recipient.key_agreement_kid.as_str(),
                &recipient.key_agreement_public,
            )],
        )?;

        if let Some(mediator) = self.store.get_route(recipient_did) {
            let forward_msg = forward::wrap_in_forward(recipient_did, &packed)?;
            let forward_json = forward_msg.to_json()?;
            crate::jwe::encrypt::anoncrypt(
                &forward_json,
                &[(
                    mediator.key_agreement_kid.as_str(),
                    &mediator.key_agreement_public,
                )],
            )
        } else {
            Ok(packed)
        }
    }

    /// Pack a signed message.
    pub fn pack_signed(&self, msg: &Message, signer_did: &str) -> Result<String, DIDCommError> {
        let signer = self.store.get_local(signer_did)?;
        let kid = signer
            .signing_kid
            .as_deref()
            .ok_or_else(|| DIDCommError::NoKeyAgreement("no signing key".into()))?;
        let sk = signer
            .signing_private
            .as_ref()
            .ok_or_else(|| DIDCommError::NoKeyAgreement("no signing key".into()))?;
        pack::pack_signed(msg, kid, sk)
    }

    /// Unpack a received message.
    ///
    /// Tries to detect the format (JWE, JWS, plaintext) and unpack accordingly.
    /// For JWE, tries each local identity until one matches.
    /// For JWS, requires the sender's resolved identity.
    pub fn unpack(
        &self,
        input: &str,
        sender_did: Option<&str>,
    ) -> Result<UnpackResult, DIDCommError> {
        let value: serde_json::Value = serde_json::from_str(input)
            .map_err(|e| DIDCommError::InvalidMessage(format!("invalid JSON: {e}")))?;

        if value.get("ciphertext").is_some() && value.get("recipients").is_some() {
            // JWE — try to find a matching local identity
            let sender_public = sender_did
                .map(|did| {
                    self.store
                        .get_resolved(did)
                        .map(|r| &r.key_agreement_public)
                })
                .transpose()?;

            // Extract recipient KIDs from the JWE to find matching local identity
            let recipients = value["recipients"]
                .as_array()
                .ok_or_else(|| DIDCommError::InvalidMessage("no recipients array".into()))?;

            for recipient in recipients {
                if let Some(kid) = recipient["header"]["kid"].as_str() {
                    // Try each local identity to see if the KID matches
                    for local_did in self.store.local_dids() {
                        if let Ok(local) = self.store.get_local(local_did)
                            && local.key_agreement_kid == kid
                        {
                            return unpack::unpack(
                                input,
                                Some(kid),
                                Some(&local.key_agreement_private),
                                sender_public,
                                None,
                            );
                        }
                    }
                }
            }

            Err(DIDCommError::IdentityNotFound(
                "no local identity matches any JWE recipient".into(),
            ))
        } else if value.get("payload").is_some() && value.get("signatures").is_some() {
            // JWS — need signer's public key
            let signer_did = sender_did.ok_or_else(|| {
                DIDCommError::InvalidMessage("sender_did required for JWS verification".into())
            })?;
            let resolved = self.store.get_resolved(signer_did)?;
            let vk = resolved.verifying_key.as_ref().ok_or_else(|| {
                DIDCommError::NoKeyAgreement("no verifying key for sender".into())
            })?;
            unpack::unpack(input, None, None, None, Some(vk))
        } else {
            // Plaintext
            unpack::unpack(input, None, None, None, None)
        }
    }
}

impl Default for DIDCommAgent {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::key_agreement::Curve;

    #[test]
    fn agent_authcrypt_roundtrip() {
        let mut alice_agent = DIDCommAgent::new();
        let mut bob_agent = DIDCommAgent::new();

        let alice = PrivateIdentity::generate("did:example:alice");
        let bob = PrivateIdentity::generate("did:example:bob");

        // Alice knows Bob's public identity, Bob knows Alice's
        alice_agent.add_peer(bob.to_resolved());
        bob_agent.add_peer(alice.to_resolved());

        alice_agent.add_identity(alice);
        bob_agent.add_identity(bob);

        let msg = Message::new(
            "https://didcomm.org/basicmessage/2.0/message",
            serde_json::json!({"content": "Hello from agent!"}),
        )
        .from("did:example:alice")
        .to(vec!["did:example:bob".into()]);

        let packed = alice_agent
            .pack_authcrypt(&msg, "did:example:alice", "did:example:bob")
            .unwrap();

        let result = bob_agent
            .unpack(&packed, Some("did:example:alice"))
            .unwrap();

        match result {
            UnpackResult::Encrypted {
                message,
                authenticated,
                ..
            } => {
                assert!(authenticated);
                assert_eq!(message.body["content"], "Hello from agent!");
            }
            _ => panic!("expected Encrypted"),
        }
    }

    #[test]
    fn agent_anoncrypt_roundtrip() {
        let mut alice_agent = DIDCommAgent::new();
        let mut bob_agent = DIDCommAgent::new();

        let bob = PrivateIdentity::generate("did:example:bob");
        alice_agent.add_peer(bob.to_resolved());
        bob_agent.add_identity(bob);

        let msg = Message::new("test", serde_json::json!({"anon": true}));

        let packed = alice_agent.pack_anoncrypt(&msg, "did:example:bob").unwrap();

        let result = bob_agent.unpack(&packed, None).unwrap();

        match result {
            UnpackResult::Encrypted {
                authenticated,
                message,
                ..
            } => {
                assert!(!authenticated);
                assert_eq!(message.body["anon"], true);
            }
            _ => panic!("expected Encrypted"),
        }
    }

    #[test]
    fn agent_authcrypt_roundtrip_p256() {
        let mut alice_agent = DIDCommAgent::new();
        let mut bob_agent = DIDCommAgent::new();

        let alice = PrivateIdentity::generate_with_curve("did:example:alice", Curve::P256);
        let bob = PrivateIdentity::generate_with_curve("did:example:bob", Curve::P256);

        alice_agent.add_peer(bob.to_resolved());
        bob_agent.add_peer(alice.to_resolved());

        alice_agent.add_identity(alice);
        bob_agent.add_identity(bob);

        let msg = Message::new(
            "https://didcomm.org/basicmessage/2.0/message",
            serde_json::json!({"content": "P-256 agent authcrypt"}),
        )
        .from("did:example:alice")
        .to(vec!["did:example:bob".into()]);

        let packed = alice_agent
            .pack_authcrypt(&msg, "did:example:alice", "did:example:bob")
            .unwrap();

        let result = bob_agent
            .unpack(&packed, Some("did:example:alice"))
            .unwrap();

        match result {
            UnpackResult::Encrypted {
                message,
                authenticated,
                ..
            } => {
                assert!(authenticated);
                assert_eq!(message.body["content"], "P-256 agent authcrypt");
            }
            _ => panic!("expected Encrypted"),
        }
    }

    #[test]
    fn agent_authcrypt_roundtrip_k256() {
        let mut alice_agent = DIDCommAgent::new();
        let mut bob_agent = DIDCommAgent::new();

        let alice = PrivateIdentity::generate_with_curve("did:example:alice", Curve::K256);
        let bob = PrivateIdentity::generate_with_curve("did:example:bob", Curve::K256);

        alice_agent.add_peer(bob.to_resolved());
        bob_agent.add_peer(alice.to_resolved());

        alice_agent.add_identity(alice);
        bob_agent.add_identity(bob);

        let msg = Message::new(
            "https://didcomm.org/basicmessage/2.0/message",
            serde_json::json!({"content": "K-256 agent authcrypt"}),
        )
        .from("did:example:alice")
        .to(vec!["did:example:bob".into()]);

        let packed = alice_agent
            .pack_authcrypt(&msg, "did:example:alice", "did:example:bob")
            .unwrap();

        let result = bob_agent
            .unpack(&packed, Some("did:example:alice"))
            .unwrap();

        match result {
            UnpackResult::Encrypted {
                message,
                authenticated,
                ..
            } => {
                assert!(authenticated);
                assert_eq!(message.body["content"], "K-256 agent authcrypt");
            }
            _ => panic!("expected Encrypted"),
        }
    }

    #[test]
    fn agent_anoncrypt_roundtrip_p256() {
        let mut alice_agent = DIDCommAgent::new();
        let mut bob_agent = DIDCommAgent::new();

        let bob = PrivateIdentity::generate_with_curve("did:example:bob", Curve::P256);
        alice_agent.add_peer(bob.to_resolved());
        bob_agent.add_identity(bob);

        let msg = Message::new("test", serde_json::json!({"curve": "P-256"}));

        let packed = alice_agent.pack_anoncrypt(&msg, "did:example:bob").unwrap();

        let result = bob_agent.unpack(&packed, None).unwrap();

        match result {
            UnpackResult::Encrypted {
                authenticated,
                message,
                ..
            } => {
                assert!(!authenticated);
                assert_eq!(message.body["curve"], "P-256");
            }
            _ => panic!("expected Encrypted"),
        }
    }

    #[test]
    fn agent_anoncrypt_roundtrip_k256() {
        let mut alice_agent = DIDCommAgent::new();
        let mut bob_agent = DIDCommAgent::new();

        let bob = PrivateIdentity::generate_with_curve("did:example:bob", Curve::K256);
        alice_agent.add_peer(bob.to_resolved());
        bob_agent.add_identity(bob);

        let msg = Message::new("test", serde_json::json!({"curve": "K-256"}));

        let packed = alice_agent.pack_anoncrypt(&msg, "did:example:bob").unwrap();

        let result = bob_agent.unpack(&packed, None).unwrap();

        match result {
            UnpackResult::Encrypted {
                authenticated,
                message,
                ..
            } => {
                assert!(!authenticated);
                assert_eq!(message.body["curve"], "K-256");
            }
            _ => panic!("expected Encrypted"),
        }
    }

    #[test]
    fn agent_signed_roundtrip() {
        let mut alice_agent = DIDCommAgent::new();
        let mut bob_agent = DIDCommAgent::new();

        let alice = PrivateIdentity::generate("did:example:alice");
        bob_agent.add_peer(alice.to_resolved());
        alice_agent.add_identity(alice);

        let msg =
            Message::new("test", serde_json::json!({"signed": true})).from("did:example:alice");

        let packed = alice_agent.pack_signed(&msg, "did:example:alice").unwrap();

        let result = bob_agent
            .unpack(&packed, Some("did:example:alice"))
            .unwrap();

        match result {
            UnpackResult::Signed { message, .. } => {
                assert_eq!(message.body["signed"], true);
            }
            _ => panic!("expected Signed"),
        }
    }
}
