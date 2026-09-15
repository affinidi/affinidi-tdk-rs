//! The `relay-ack` WebSocket subprotocol: per-frame acknowledgement for
//! inter-mediator relay.
//!
//! # Why this exists
//!
//! REST relay is status-checked. `deliver_via_rest` treats a non-2xx as a
//! delivery failure, so a frame the receiving mediator *rejects* — an untrusted
//! relay peer, an ACL denial, a detected loop — is retried, and eventually
//! abandoned with a problem report to the original sender. That is the
//! contract every "delivered" claim downstream is built on.
//!
//! A WebSocket write has no such answer. Handing a frame to the socket says
//! only that the bytes left this process, so relaying over a bare WebSocket
//! would ACK the queue entry for a message the peer threw away, and the
//! rejection would exist only as a log line on the far side.
//!
//! So the WebSocket relay transport carries its own acknowledgement. A relaying
//! mediator offers the `relay-ack` subprotocol at upgrade; a receiving mediator
//! that supports it echoes it back and answers **every** relayed frame with a
//! [`RelayAck`]. The sender treats a missing or negative ack exactly as it
//! treats a non-2xx REST response, so the delivery semantics of the two
//! transports are the same.
//!
//! # Compatibility
//!
//! The subprotocol is the negotiation. A peer that does not echo `relay-ack`
//! — an older mediator, or something else entirely — gets no relayed frames
//! over the socket at all: the connection is dropped and delivery falls back to
//! REST, which is what carried this traffic before the WebSocket path worked.
//! There is therefore no version of this exchange in which a frame is relayed
//! without an acknowledgement path.

use serde::{Deserialize, Serialize};

/// The WebSocket subprotocol name offered by a relaying mediator and echoed by
/// a receiving mediator that answers with [`RelayAck`] frames.
///
/// Offering it is also how an *anonymous* upgrade identifies itself as an
/// inter-mediator relay rather than a client, which is what the receiving
/// mediator's admission check keys on.
pub const RELAY_ACK_SUBPROTOCOL: &str = "relay-ack";

/// The `typ` every [`RelayAck`] carries, so a frame is self-describing and a
/// future revision can be told apart from this one.
pub const RELAY_ACK_TYPE: &str = "relay-ack/1.0";

/// One receiving mediator's answer to one relayed frame.
///
/// Sent as a JSON text frame on the relay socket, in the order the frames were
/// received.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[non_exhaustive]
pub struct RelayAck {
    /// Always [`RELAY_ACK_TYPE`].
    pub typ: String,
    /// [`frame_id`] of the frame being answered.
    ///
    /// Content-addressed rather than a sequence number so neither side has to
    /// keep ordering state, and so an ack can never be mistaken for the answer
    /// to a different frame.
    pub id: String,
    /// Whether the frame was accepted for delivery.
    ///
    /// `true` means the receiving mediator has taken responsibility for it —
    /// stored, live-streamed, or queued onward — exactly as a 2xx does on the
    /// REST path.
    pub ok: bool,
    /// Mediator error code when `ok` is false. See the mediator's `ERRORS.md`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<u16>,
    /// Human-readable rejection reason when `ok` is false. Diagnostic only —
    /// never parsed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl RelayAck {
    /// A positive acknowledgement for the frame with this [`frame_id`].
    pub fn accepted(id: impl Into<String>) -> Self {
        Self {
            typ: RELAY_ACK_TYPE.to_string(),
            id: id.into(),
            ok: true,
            code: None,
            reason: None,
        }
    }

    /// A negative acknowledgement: the frame reached us and was refused.
    ///
    /// The sender treats this as it treats a non-2xx REST response — retry with
    /// backoff, then abandon with a problem report — so the reason travels back
    /// to whoever sent the message rather than dying in the peer's logs.
    pub fn rejected(id: impl Into<String>, code: u16, reason: impl Into<String>) -> Self {
        Self {
            typ: RELAY_ACK_TYPE.to_string(),
            id: id.into(),
            ok: false,
            code: Some(code),
            reason: Some(reason.into()),
        }
    }

    /// Whether this ack answers `frame_id` and carries the type we understand.
    ///
    /// Both halves matter: a differently-typed frame is not an ack of ours, and
    /// an ack for another id must never be read as the answer to this frame —
    /// that is precisely the confusion that would let a rejected message be
    /// reported as delivered.
    pub fn answers(&self, frame_id: &str) -> bool {
        self.typ == RELAY_ACK_TYPE && self.id == frame_id
    }
}

/// Identify a relayed frame by the SHA-256 of its exact bytes, hex-encoded.
///
/// Both sides compute this independently over the same wire bytes, so the
/// relayed envelope needs no correlation field added to it and the two
/// implementations cannot disagree about which frame an ack refers to.
pub fn frame_id(frame: &[u8]) -> String {
    sha256::digest(frame)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_id_is_stable_and_distinguishes_frames() {
        assert_eq!(
            frame_id(b"a-relayed-envelope"),
            frame_id(b"a-relayed-envelope")
        );
        assert_ne!(frame_id(b"a-relayed-envelope"), frame_id(b"another-one"));
        // Hex-encoded SHA-256.
        assert_eq!(frame_id(b"x").len(), 64);
    }

    #[test]
    fn accepted_answers_only_its_own_frame() {
        let id = frame_id(b"envelope");
        let ack = RelayAck::accepted(&id);

        assert!(ack.ok);
        assert!(ack.answers(&id));
        assert!(!ack.answers(&frame_id(b"a different envelope")));
    }

    #[test]
    fn rejected_carries_the_code_and_reason_back_to_the_sender() {
        let id = frame_id(b"envelope");
        let ack = RelayAck::rejected(
            &id,
            60,
            "Relaying mediator is not in the trusted relay allowlist",
        );

        assert!(!ack.ok);
        assert_eq!(ack.code, Some(60));
        assert!(ack.reason.unwrap().contains("trusted relay allowlist"));
    }

    /// An ack of an unknown type must not be accepted as an answer, or a future
    /// revision of this subprotocol would be silently misread as this one.
    #[test]
    fn an_ack_of_another_type_answers_nothing() {
        let id = frame_id(b"envelope");
        let mut ack = RelayAck::accepted(&id);
        ack.typ = "relay-ack/2.0".to_string();

        assert!(!ack.answers(&id));
    }

    #[test]
    fn round_trips_through_json_without_the_optional_fields() {
        let id = frame_id(b"envelope");
        let json = serde_json::to_string(&RelayAck::accepted(&id)).unwrap();

        // A positive ack is three fields — no null code/reason on the wire.
        assert!(!json.contains("code"), "{json}");
        assert!(!json.contains("reason"), "{json}");

        let back: RelayAck = serde_json::from_str(&json).unwrap();
        assert!(back.answers(&id));
        assert!(back.ok);
    }

    #[test]
    fn round_trips_a_rejection() {
        let id = frame_id(b"envelope");
        let json = serde_json::to_string(&RelayAck::rejected(&id, 94, "loop detected")).unwrap();
        let back: RelayAck = serde_json::from_str(&json).unwrap();

        assert!(back.answers(&id));
        assert!(!back.ok);
        assert_eq!(back.code, Some(94));
        assert_eq!(back.reason.as_deref(), Some("loop detected"));
    }
}
