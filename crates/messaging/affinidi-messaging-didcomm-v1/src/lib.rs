//! # affinidi-messaging-didcomm-v1
//!
//! A DIDComm **v1** (Aries RFC 0019) implementation for the Affinidi TDK,
//! sitting alongside [`affinidi-messaging-didcomm`] (v2.1) rather than
//! replacing it. Every Aries-lineage wallet — Credo and everything built on it
//! — speaks v1 and only v1; this crate is what lets the TDK reach them.
//!
//! Supports:
//! - **Authcrypt** (`crypto_box` + ChaCha20-Poly1305) — sender-authenticated
//! - **Anoncrypt** (`crypto_box_seal` + ChaCha20-Poly1305) — anonymous
//! - **Plaintext** messages
//! - **Forward/routing** (Aries RFC 0094)
//! - **Basic Message 1.0** (Aries RFC 0095) as the carrier protocol
//! - **Keys**: Ed25519 verkeys, X25519 key agreement (v1 has no curve agility)
//!
//! ## Scope
//!
//! Transport primitives only: packing, unpacking, message construction, thread
//! decorators, and connection identity. Framework semantics — document
//! validation, consumer pipelines, error-response routing, proof verification —
//! belong to the layer above. This crate's job ends at "here is a decrypted
//! message body and the authenticated identity of who sent it".
//!
//! ## Parity with v2.1, and where it deliberately breaks
//!
//! The API mirrors the v2.1 crate module-for-module — [`identity`],
//! [`message`], [`store`], [`error`], a [`DIDCommV1Agent`] matching
//! `DIDCommAgent`, and (behind the `messaging-core` feature) the same
//! `MessagingProtocol` trait — so a consumer can write transport-agnostic code
//! over both. Where the protocols genuinely differ, this crate diverges rather
//! than pretending:
//!
//! | | v2.1 | v1 | Why it cannot be papered over |
//! |---|---|---|---|
//! | Envelope | real JWE, JWA algorithms | JWE-shaped JSON, libsodium algorithms | see [`crypto`] |
//! | Sender identifier | `skid`: a DID URL | a bare base58 Ed25519 verkey | see [`identity`] |
//! | Message headers | `id` / `type` | `@id` / `@type` | see [`message`] |
//! | Payload | nested `body` | top-level members | see [`message`] |
//! | Threading | `thid` / `pthid` headers | `~thread` decorator | see [`message::thread`] |
//! | Addressing | `from` / `to` headers | none — transport only | see [`message`] |
//! | Unpack result | `Encrypted { authenticated: bool, sender_kid: Option<_> }` | disjoint variants | see [`message::unpack`] |
//! | Signed envelopes | JWS, sign-then-encrypt | **none** | RFC 0019 defines only two protections |
//! | Curve agility | 5 curves | X25519 only | see [`crypto`] |
//!
//! The unpack-result row is the one to read before using this crate. v1
//! anoncrypt has no authenticated sender, so a consumer that mistakes it for an
//! authenticated message has nobody to route an error response to — and
//! replying anyway turns the agent into an identity oracle. [`UnpackResult`]
//! therefore makes authcrypt and anoncrypt disjoint variants with no
//! `Option<Did>` to unwrap carelessly, and [`UnpackResult::require_authenticated`]
//! is the one-call gate.
//!
//! ## Example
//!
//! ```
//! use affinidi_messaging_didcomm_v1::{
//!     DIDCommV1Agent, PrivateIdentity, UnpackResult, protocols::basic_message::BasicMessage,
//! };
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let alice = PrivateIdentity::generate("did:example:alice")?;
//! let bob = PrivateIdentity::generate("did:example:bob")?;
//!
//! let mut alice_agent = DIDCommV1Agent::new();
//! alice_agent.add_peer(bob.to_resolved());
//! let alice_resolved = alice.to_resolved();
//! alice_agent.add_identity(alice);
//!
//! let mut bob_agent = DIDCommV1Agent::new();
//! bob_agent.add_peer(alice_resolved);
//! bob_agent.add_identity(bob);
//!
//! let msg = BasicMessage::new("Your hovercraft is full of eels.")?
//!     .thid("thread-1")
//!     .finalize();
//!
//! let packed = alice_agent.pack_authcrypt(&msg, "did:example:alice", "did:example:bob")?;
//!
//! // The safe path: anything not attributably authcrypt is rejected here.
//! let authenticated = bob_agent.unpack(&packed)?.require_authenticated()?;
//! assert_eq!(authenticated.sender.as_str(), "did:example:alice");
//! assert_eq!(authenticated.recipient.as_str(), "did:example:bob");
//! assert_eq!(authenticated.message.explicit_thid(), Some("thread-1"));
//! # Ok(())
//! # }
//! ```
//!
//! [`affinidi-messaging-didcomm`]: affinidi_messaging_didcomm

pub mod crypto;
pub mod envelope;
pub mod error;
pub mod identity;
pub mod message;
pub mod protocols;
pub mod store;

#[cfg(feature = "messaging-core")]
pub mod adapter;

pub use crate::error::DIDCommV1Error;
pub use crate::identity::{Did, Mediator, PrivateIdentity, ResolvedIdentity, Verkey};
pub use crate::message::unpack::{AuthenticatedMessage, NoBindings, SenderBindings, UnpackResult};
pub use crate::message::{
    MessageBuilder, MessageType, MessageV1, ThreadDecorator, TypeFormat, types_match,
};
pub use crate::store::DIDCommV1Store;

use crate::message::{pack, unpack};

/// High-level DIDComm v1 agent — the counterpart to
/// [`DIDCommAgent`](affinidi_messaging_didcomm::DIDCommAgent).
///
/// Holds local identities, known peers, and mediator routes, and offers the
/// same `pack_authcrypt` / `pack_anoncrypt` / `unpack` surface.
///
/// The store doubles as the verkey -> DID index that v1 unpack needs (see
/// [`identity`]); an agent with its own connection database should call
/// [`message::unpack::unpack`] directly with its own [`SenderBindings`] rather
/// than mirroring state into [`DIDCommV1Store`].
#[derive(Default)]
pub struct DIDCommV1Agent {
    store: DIDCommV1Store,
}

impl DIDCommV1Agent {
    /// A new agent with an empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// The underlying store.
    pub fn store(&self) -> &DIDCommV1Store {
        &self.store
    }

    /// The underlying store, mutably.
    pub fn store_mut(&mut self) -> &mut DIDCommV1Store {
        &mut self.store
    }

    /// Add a local identity.
    pub fn add_identity(&mut self, identity: PrivateIdentity) {
        self.store.add_local(identity);
    }

    /// Add a known peer, binding its DID to the verkey that authenticates it.
    pub fn add_peer(&mut self, identity: ResolvedIdentity) {
        self.store.add_resolved(identity);
    }

    /// Route messages for `recipient_did` through `mediator`.
    pub fn add_route(
        &mut self,
        recipient_did: &str,
        mediator: Mediator,
    ) -> Result<(), DIDCommV1Error> {
        self.store.add_route(recipient_did, mediator)
    }

    /// Pack a message with authcrypt, forwarding through a mediator if one is
    /// registered for the recipient.
    pub fn pack_authcrypt(
        &self,
        msg: &MessageV1,
        sender_did: &str,
        recipient_did: &str,
    ) -> Result<String, DIDCommV1Error> {
        let sender = self.store.get_local(sender_did)?;
        let recipient = self.store.get_resolved(recipient_did)?;

        let packed = pack::pack_encrypted_authcrypt(msg, sender, &[recipient.verkey])?;
        self.maybe_forward(packed, recipient_did, &recipient.verkey)
    }

    /// Pack a message with anoncrypt, forwarding through a mediator if one is
    /// registered for the recipient.
    ///
    /// The recipient will have no way to attribute or reply to the result — see
    /// [`message::pack::pack_encrypted_anoncrypt`].
    pub fn pack_anoncrypt(
        &self,
        msg: &MessageV1,
        recipient_did: &str,
    ) -> Result<String, DIDCommV1Error> {
        let recipient = self.store.get_resolved(recipient_did)?;

        let packed = pack::pack_encrypted_anoncrypt(msg, &[recipient.verkey])?;
        self.maybe_forward(packed, recipient_did, &recipient.verkey)
    }

    /// Wrap in a forward when the recipient has a mediator route.
    fn maybe_forward(
        &self,
        packed: String,
        recipient_did: &str,
        recipient_verkey: &Verkey,
    ) -> Result<String, DIDCommV1Error> {
        match self.store.get_route(recipient_did) {
            Some(mediator) => {
                protocols::forward::wrap_in_forward(recipient_verkey, &packed, &mediator.verkey)
            }
            None => Ok(packed),
        }
    }

    /// Unpack a received message, trying every local identity.
    ///
    /// Unlike the v2 counterpart this takes no `sender_did` hint: a v1 envelope
    /// carries the sealed sender verkey itself, so the sender is recovered from
    /// the envelope and then looked up in the store.
    pub fn unpack(&self, input: &str) -> Result<UnpackResult, DIDCommV1Error> {
        unpack::unpack(input, &self.store.local_identities(), &self.store)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::basic_message::BasicMessage;

    fn agents() -> (DIDCommV1Agent, DIDCommV1Agent) {
        let alice = PrivateIdentity::generate("did:example:alice").unwrap();
        let bob = PrivateIdentity::generate("did:example:bob").unwrap();

        let mut alice_agent = DIDCommV1Agent::new();
        let mut bob_agent = DIDCommV1Agent::new();

        alice_agent.add_peer(bob.to_resolved());
        bob_agent.add_peer(alice.to_resolved());
        alice_agent.add_identity(alice);
        bob_agent.add_identity(bob);

        (alice_agent, bob_agent)
    }

    fn message() -> MessageV1 {
        BasicMessage::new("Hello from the v1 agent")
            .unwrap()
            .finalize()
    }

    #[test]
    fn agent_authcrypt_roundtrip() {
        let (alice, bob) = agents();

        let packed = alice
            .pack_authcrypt(&message(), "did:example:alice", "did:example:bob")
            .unwrap();
        let authenticated = bob
            .unpack(&packed)
            .unwrap()
            .require_authenticated()
            .unwrap();

        assert_eq!(authenticated.sender.as_str(), "did:example:alice");
        assert_eq!(authenticated.recipient.as_str(), "did:example:bob");
        assert_eq!(
            authenticated.message.body["content"],
            "Hello from the v1 agent"
        );
    }

    #[test]
    fn agent_anoncrypt_roundtrip_has_no_sender() {
        let (alice, bob) = agents();

        let packed = alice.pack_anoncrypt(&message(), "did:example:bob").unwrap();
        let result = bob.unpack(&packed).unwrap();

        assert!(matches!(result, UnpackResult::Anoncrypt { .. }));
        assert!(!result.is_authcrypt());
        assert!(result.require_authenticated().is_err());
    }

    #[test]
    fn agent_reports_unknown_identities() {
        let (alice, _) = agents();
        assert!(matches!(
            alice.pack_authcrypt(&message(), "did:example:alice", "did:example:nobody"),
            Err(DIDCommV1Error::IdentityNotFound(_))
        ));
    }

    #[test]
    fn agent_routes_through_a_mediator_when_registered() {
        let (mut alice, bob) = agents();
        let mediator_identity = PrivateIdentity::generate("did:example:mediator").unwrap();

        alice
            .add_route("did:example:bob", Mediator::new(mediator_identity.verkey))
            .unwrap();

        let packed = alice
            .pack_authcrypt(&message(), "did:example:alice", "did:example:bob")
            .unwrap();

        // Bob cannot open it directly — it is addressed to the mediator.
        assert!(bob.unpack(&packed).is_err());

        let mut mediator = DIDCommV1Agent::new();
        mediator.add_identity(mediator_identity);

        let forward = mediator.unpack(&packed).unwrap().into_message();
        let inner = protocols::forward::extract_payload(&forward).unwrap();

        let authenticated = bob.unpack(&inner).unwrap().require_authenticated().unwrap();
        assert_eq!(authenticated.sender.as_str(), "did:example:alice");
    }
}
