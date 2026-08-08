//! Shared types for the unified messaging layer.

use serde::{Deserialize, Serialize};
use url::Url;

/// Which messaging protocol was used.
///
/// `#[non_exhaustive]`: match with a `_ =>` arm so that adding a protocol is not
/// a breaking change. [`DIDCommV1`](Self::DIDCommV1) was the first addition
/// after this attribute was applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Protocol {
    /// DIDComm v2.1 messaging (`affinidi-messaging-didcomm`).
    DIDComm,
    /// DIDComm v1 messaging, Aries RFC 0019
    /// (`affinidi-messaging-didcomm-v1`).
    ///
    /// Deliberately a separate variant rather than a flavour of
    /// [`DIDComm`](Self::DIDComm): the two share no wire format, no algorithms,
    /// and no identifier scheme, and a consumer routing an inbound message
    /// has to know which one it is holding.
    DIDCommV1,
    /// Trust Spanning Protocol.
    TSP,
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::DIDComm => write!(f, "DIDComm"),
            Protocol::DIDCommV1 => write!(f, "DIDComm v1"),
            Protocol::TSP => write!(f, "TSP"),
        }
    }
}

/// A received and unpacked message (protocol-agnostic).
#[derive(Debug, Clone)]
pub struct ReceivedMessage {
    /// Unique message identifier.
    pub id: String,
    /// Sender identifier (DID or VID). None for anonymous messages.
    pub sender: Option<String>,
    /// Recipient identifier (DID or VID).
    pub recipient: String,
    /// The decrypted message payload.
    pub payload: Vec<u8>,
    /// Which protocol produced this message.
    pub protocol: Protocol,
    /// Whether the sender's identity was cryptographically verified.
    pub verified: bool,
    /// Whether the message was encrypted.
    pub encrypted: bool,
}

/// Resolved identity with public keys and endpoints (protocol-agnostic).
#[derive(Debug, Clone)]
pub struct ResolvedIdentity {
    /// The identifier string (DID or VID).
    pub id: String,
    /// Signing/verification public key bytes (if available).
    pub verification_key: Option<Vec<u8>>,
    /// Encryption public key bytes.
    pub encryption_key: Vec<u8>,
    /// Service endpoint URLs for message delivery (if available).
    pub endpoints: Option<Vec<Url>>,
}

/// State of a relationship between two parties.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RelationshipState {
    /// No relationship exists.
    None,
    /// A relationship request has been sent, awaiting response.
    Pending,
    /// A relationship request has been received, awaiting decision.
    InviteReceived,
    /// Relationship is fully established.
    Bidirectional,
}

impl RelationshipState {
    /// Whether messaging is allowed in this state.
    pub fn can_send(&self) -> bool {
        matches!(self, RelationshipState::Bidirectional)
    }
}
