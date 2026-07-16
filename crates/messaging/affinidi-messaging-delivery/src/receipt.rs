//! §5a **layer receipt** — the strongest delivery-confirmation evidence.
//!
//! Both peers run the delivery layer. When the *receiving* layer durably
//! persists an inbound message, it emits a small fire-and-forget **receipt**
//! back to the sender, echoing the layer correlation id (the message's thread
//! id). The *sending* layer recognises that receipt and settles the matching
//! outbox entry `Sent → Delivered` — real end-to-end evidence for **every**
//! `Guaranteed` message, one-way traffic included, with no application-protocol
//! reply. It is the only evidence that also closes the mediator's power-loss
//! window (it is end-to-end, not mediator-trusting).
//!
//! **Fire-and-forget by design** (§5a "who acks the ack? nobody"): a lost
//! receipt just means the sender's delivery window expires and it re-sends (same
//! idempotency key); the receiver dedups the re-send and re-emits the receipt.
//! Receipt loss is self-healing via the existing outbox-retry + receiver-dedup
//! machinery — no recursion, no "guaranteed ack of a guaranteed ack". The only
//! cost of a lost receipt is one extra round trip.
//!
//! ## Correlation
//!
//! A receipt confirms an outbox *idempotency key*. The receiving layer knows
//! only what the wire surfaces, so it echoes the inbound message's **thread id**
//! ([`Inbound::thread_id`]) — the layer's correlation anchor. For our own
//! services (both run the layer) the sending layer stamps `thid == idempotency
//! key` on a `Guaranteed` send, so the echo lines up; a spurious receipt for an
//! unknown key is a harmless no-op ([`confirm_delivered`] returns `false`).
//! Stamping the thread id automatically at pack time lands with the Phase-3
//! packing integration; until then a caller that sets its own correlation id
//! gets the same behaviour.
//!
//! ## Packing lives outside this crate
//!
//! Emitting a receipt requires DID-encrypting it to the recipient — a crypto
//! concern this crate (which depends only on the transport contract) does not
//! own, exactly as durable storage is abstracted behind [`OutboxStore`]. A
//! service wires in a [`ReceiptPacker`] (the SDK packs via the mediator's
//! `pack_encrypted`); the consume half needs no packer and is always active.
//!
//! [`Inbound::thread_id`]: affinidi_messaging_core::Inbound::thread_id
//! [`confirm_delivered`]: crate::confirm::confirm_delivered
//! [`OutboxStore`]: crate::outbox::OutboxStore

use serde::{Deserialize, Serialize};

use affinidi_messaging_core::{MessagingError, ReceivedMessage};

use crate::outbox::Key;

/// The delivery-layer receipt message type — the marker that distinguishes a
/// layer receipt from application traffic on the wire. A specific URI so an
/// application body cannot be mistaken for a receipt.
pub const RECEIPT_TYPE: &str = "https://affinidi.com/delivery/1.0/receipt";

/// A layer receipt: positive end-to-end evidence that the peer's delivery layer
/// durably received the message whose idempotency key is [`Receipt::confirms`].
///
/// This is the message *body* the receiving layer sends back; the transport
/// packs and moves it like any other message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Receipt {
    /// Discriminates a receipt from any other message body; always
    /// [`RECEIPT_TYPE`].
    #[serde(rename = "type")]
    pub kind: String,
    /// The sender's outbox idempotency key this receipt confirms.
    pub confirms: Key,
}

impl Receipt {
    /// A receipt confirming `idempotency_key`.
    pub fn new(idempotency_key: impl Into<Key>) -> Self {
        Self {
            kind: RECEIPT_TYPE.to_string(),
            confirms: idempotency_key.into(),
        }
    }

    /// Encode this receipt as packed-message *body* bytes.
    pub fn encode(&self) -> Vec<u8> {
        // A fixed two-field struct always serializes.
        serde_json::to_vec(self).expect("receipt serializes")
    }
}

/// Decode a message body as a layer receipt, returning the confirmed idempotency
/// key. `None` for any body that is not a receipt (application traffic, or
/// non-JSON), so a caller can cheaply tell layer traffic from application
/// traffic without a separate type channel.
pub fn receipt_key(payload: &[u8]) -> Option<Key> {
    let receipt: Receipt = serde_json::from_slice(payload).ok()?;
    (receipt.kind == RECEIPT_TYPE).then_some(receipt.confirms)
}

/// The idempotency key a received message is a receipt for, if it is one.
pub fn receipt_of(message: &ReceivedMessage) -> Option<Key> {
    receipt_key(&message.payload)
}

/// Packs a delivery-layer receipt into transport-ready bytes.
///
/// Packing is the crypto layer's concern and is deliberately **not** in this
/// crate — exactly as durable storage is abstracted behind [`OutboxStore`]. A
/// service wires in a packer that DID-encrypts the receipt body to the recipient
/// (the SDK does this via the mediator's `pack_encrypted`); tests use a trivial
/// one. Only the *emit* half needs a packer — the *consume* half (recognising an
/// inbound receipt and confirming the outbox entry) is always active.
///
/// [`OutboxStore`]: crate::outbox::OutboxStore
#[async_trait::async_trait]
pub trait ReceiptPacker: Send + Sync {
    /// Pack a receipt `body` addressed to `to` into bytes ready for
    /// [`MessageTransport::send`]. Returns `Err` if the recipient can't be
    /// resolved or the body can't be encrypted — the receipt is then dropped
    /// (fire-and-forget; the sender's window recovers it).
    ///
    /// [`MessageTransport::send`]: affinidi_messaging_core::MessageTransport::send
    async fn pack_receipt(&self, to: &str, body: Vec<u8>) -> Result<Vec<u8>, MessagingError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use affinidi_messaging_core::Protocol;

    fn message_with(payload: Vec<u8>) -> ReceivedMessage {
        ReceivedMessage {
            id: "m1".to_string(),
            sender: Some("did:example:alice".to_string()),
            recipient: "did:example:bob".to_string(),
            payload,
            protocol: Protocol::DIDComm,
            verified: true,
            encrypted: true,
        }
    }

    #[test]
    fn encode_decode_roundtrips_the_confirmed_key() {
        // A key with colons (DIDs, the default `to:now:seq` shape) must survive.
        let key = "did:example:bob:1737000000000:7";
        let bytes = Receipt::new(key).encode();
        assert_eq!(receipt_key(&bytes).as_deref(), Some(key));
        assert_eq!(receipt_of(&message_with(bytes)).as_deref(), Some(key));
    }

    #[test]
    fn application_traffic_is_not_mistaken_for_a_receipt() {
        // Non-JSON.
        assert_eq!(receipt_key(b"not json at all"), None);
        // JSON, but not a receipt.
        assert_eq!(receipt_key(br#"{"hello":"world"}"#), None);
        // JSON with a `confirms` but the wrong type marker.
        assert_eq!(
            receipt_key(br#"{"type":"https://example.com/other","confirms":"k"}"#),
            None
        );
        // Empty body.
        assert_eq!(receipt_key(b""), None);
    }

    #[test]
    fn receipt_type_is_the_stable_marker() {
        let bytes = Receipt::new("k").encode();
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains(RECEIPT_TYPE));
    }
}
