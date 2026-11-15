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

/// The result of a relationship operation: the new local state, and the
/// control message the caller must transmit for the peer to learn of it.
///
/// Returned by the `*_with_control` methods of
/// [`RelationshipManager`](crate::RelationshipManager). Nothing has been sent
/// when this is returned — if `control_message` is `Some`, delivering it is the
/// caller's job.
///
/// `#[non_exhaustive]`: construct with [`new`](Self::new) or
/// [`with_control_message`](Self::with_control_message).
///
/// `#[must_use]`: the local state has already moved when this is returned, so
/// discarding it (and with it `control_message`) leaves the two sides
/// disagreeing. The compiler warns when a caller drops it unread:
///
/// ```compile_fail
/// #![deny(unused_must_use)]
/// use affinidi_messaging_core::types::{RelationshipChange, RelationshipState};
/// fn main() {
///     RelationshipChange::with_control_message(RelationshipState::Pending, vec![1]);
/// }
/// ```
///
/// ```
/// #![deny(unused_must_use)]
/// use affinidi_messaging_core::types::{RelationshipChange, RelationshipState};
/// fn main() {
///     let change = RelationshipChange::with_control_message(RelationshipState::Pending, vec![1]);
///     assert_eq!(change.control_message.as_deref(), Some(&[1u8][..]));
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[must_use = "the local relationship state has already moved; transmit `control_message` to the peer or the two sides diverge"]
pub struct RelationshipChange {
    /// The local relationship state after the operation.
    pub state: RelationshipState,
    /// Packed wire bytes of the control message to deliver to the peer, or
    /// `None` when the protocol needs nothing on the wire (DIDComm's implicit
    /// relationships).
    pub control_message: Option<Vec<u8>>,
}

impl RelationshipChange {
    /// A state change with nothing to transmit.
    pub fn new(state: RelationshipState) -> Self {
        Self {
            state,
            control_message: None,
        }
    }

    /// A state change whose peer must be sent `control_message`.
    pub fn with_control_message(state: RelationshipState, control_message: Vec<u8>) -> Self {
        Self {
            state,
            control_message: Some(control_message),
        }
    }
}
