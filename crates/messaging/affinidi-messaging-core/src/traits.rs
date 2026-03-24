//! Protocol-agnostic messaging traits.
//!
//! These traits define the unified API that both DIDComm and TSP implement,
//! allowing application code to be protocol-independent.

use crate::error::MessagingError;
use crate::types::{Protocol, ReceivedMessage, RelationshipState, ResolvedIdentity};

/// Core messaging operations — implemented by DIDComm and TSP adapters.
///
/// This trait abstracts the pack/unpack cycle that both protocols share:
/// - **Pack**: take a payload, encrypt and sign it for a recipient
/// - **Unpack**: take wire bytes, verify and decrypt to recover the payload
#[async_trait::async_trait]
pub trait MessagingProtocol: Send + Sync {
    /// Which protocol this adapter implements.
    fn protocol(&self) -> Protocol;

    /// Pack a message for a recipient (encrypt + sign).
    ///
    /// Returns the wire-format bytes ready for transport.
    async fn pack(
        &self,
        payload: &[u8],
        sender: &str,
        recipient: &str,
    ) -> Result<Vec<u8>, MessagingError>;

    /// Pack a message anonymously (encrypt only, no sender identity).
    ///
    /// Not all protocols support this — TSP always authenticates the sender.
    async fn pack_anonymous(
        &self,
        payload: &[u8],
        recipient: &str,
    ) -> Result<Vec<u8>, MessagingError>;

    /// Unpack a received message (decrypt + verify).
    async fn unpack(&self, packed: &[u8]) -> Result<ReceivedMessage, MessagingError>;

    /// Wrap a packed message for relay through an intermediary.
    ///
    /// - DIDComm: creates a forward message wrapping the inner packed message
    /// - TSP: creates a nested/routed message for the intermediary
    async fn wrap_for_relay(
        &self,
        packed: &[u8],
        next_hop: &str,
        final_recipient: &str,
    ) -> Result<Vec<u8>, MessagingError>;
}

/// Identity resolution — resolve an identifier to keys and endpoints.
///
/// Both DIDComm (DIDs) and TSP (VIDs) need to resolve identifiers to
/// public keys and service endpoints before messaging.
#[async_trait::async_trait]
pub trait IdentityResolver: Send + Sync {
    /// Resolve an identifier to its public keys and endpoints.
    async fn resolve(&self, id: &str) -> Result<ResolvedIdentity, MessagingError>;
}

/// Relationship management — explicit in TSP, implicit in DIDComm.
///
/// TSP requires a relationship handshake (RFI → RFA) before messaging.
/// DIDComm relationships are implicit — just start sending. The DIDComm
/// adapter can return `Bidirectional` immediately.
#[async_trait::async_trait]
pub trait RelationshipManager: Send + Sync {
    /// Request a relationship with another party.
    ///
    /// - DIDComm: returns `Bidirectional` immediately (implicit relationships)
    /// - TSP: sends RFI control message, returns `Pending`
    async fn request_relationship(
        &self,
        my_id: &str,
        their_id: &str,
    ) -> Result<RelationshipState, MessagingError>;

    /// Accept an incoming relationship request.
    ///
    /// `request_id` references the original invite (e.g., message digest).
    async fn accept_relationship(
        &self,
        my_id: &str,
        their_id: &str,
        request_id: &[u8],
    ) -> Result<RelationshipState, MessagingError>;

    /// Cancel/terminate a relationship.
    async fn cancel_relationship(
        &self,
        my_id: &str,
        their_id: &str,
    ) -> Result<RelationshipState, MessagingError>;

    /// Query the current state of a relationship.
    async fn relationship_state(
        &self,
        my_id: &str,
        their_id: &str,
    ) -> Result<RelationshipState, MessagingError>;
}
