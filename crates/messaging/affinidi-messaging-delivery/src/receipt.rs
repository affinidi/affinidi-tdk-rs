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
//! unknown key is a harmless no-op ([`confirm_delivered_by`] returns `false`).
//! Stamping the thread id automatically at pack time lands with the Phase-3
//! packing integration; until then a caller that sets its own correlation id
//! gets the same behaviour.
//!
//! A receipt confirms an entry only when it comes from that entry's recipient:
//! the sending layer checks the sender the transport authenticated against the
//! entry's `dest_did`, so a receipt from any other party, or from an
//! unauthenticated one, settles nothing. Likewise the receiving layer emits a
//! receipt only to an authenticated sender.
//!
//! ## Packing lives outside this crate
//!
//! Emitting a receipt requires DID-encrypting it to the recipient — a crypto
//! concern this crate (which has no DIDComm or TSP stack of its own) does not
//! own, exactly as durable storage is abstracted behind [`OutboxStore`]. A
//! service wires in a [`ReceiptPacker`] (the SDK packs via the mediator's
//! `pack_encrypted`); the consume half needs no packer and is always active.
//!
//! [`Inbound::thread_id`]: affinidi_messaging_core::Inbound::thread_id
//! [`confirm_delivered_by`]: crate::confirm::confirm_delivered_by
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
    // Two wire shapes a transport can surface as `payload`:
    // (1) the Receipt JSON **directly** — a transport whose payload is the
    //     message body (e.g. TSP surfaces the unpacked payload).
    // (2) a **full DIDComm plaintext message** whose `body` is the Receipt — the
    //     DIDComm transport sets `ReceivedMessage.payload = message.to_json()`,
    //     so the receipt lives under `body`, not at the top level. Without this
    //     a layer receipt over DIDComm is never recognised (the whole message
    //     JSON is not a `Receipt`).
    //
    // Both are read in one pass: every inbound message comes through here on
    // the dispatcher, so it is parsed once and only these fields are kept.
    let shape: ReceiptShape = serde_json::from_slice(payload).ok()?;
    marked_key(shape.kind, shape.confirms).or_else(|| {
        shape
            .body
            .and_then(|body| marked_key(body.kind, body.confirms))
    })
}

/// The fields of an inbound payload that can carry a receipt, at the top level
/// and under `body`. Every other field is skipped without being kept.
#[derive(Deserialize)]
struct ReceiptShape {
    #[serde(rename = "type", default, deserialize_with = "string_or_none")]
    kind: Option<String>,
    #[serde(default, deserialize_with = "string_or_none")]
    confirms: Option<Key>,
    #[serde(default, deserialize_with = "object_or_none")]
    body: Option<ReceiptFields>,
}

#[derive(Deserialize)]
struct ReceiptFields {
    #[serde(rename = "type", default, deserialize_with = "string_or_none")]
    kind: Option<String>,
    #[serde(default, deserialize_with = "string_or_none")]
    confirms: Option<Key>,
}

/// The confirmed key iff `kind` is the [`RECEIPT_TYPE`] marker, so application
/// JSON that merely happens to be an object is not mistaken for a receipt.
fn marked_key(kind: Option<String>, confirms: Option<Key>) -> Option<Key> {
    (kind.as_deref() == Some(RECEIPT_TYPE)).then_some(confirms)?
}

/// A string, or `None` for a value of any other type, so a field of another
/// type in application traffic does not stop the payload being read.
fn string_or_none<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<String>, D::Error> {
    deserializer.deserialize_any(LenientVisitor::<StringField>::default())
}

/// An object read for receipt fields, or `None` for a value of any other type.
fn object_or_none<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<ReceiptFields>, D::Error> {
    deserializer.deserialize_any(LenientVisitor::<ObjectField>::default())
}

/// What a [`LenientVisitor`] keeps; every other JSON value becomes `None`.
trait Lenient {
    type Value;
    fn string(_value: &str) -> Option<Self::Value> {
        None
    }
    fn map<'de, A: serde::de::MapAccess<'de>>(map: A) -> Result<Option<Self::Value>, A::Error>;
}

#[derive(Default)]
struct StringField;
impl Lenient for StringField {
    type Value = String;
    fn string(value: &str) -> Option<String> {
        Some(value.to_string())
    }
    fn map<'de, A: serde::de::MapAccess<'de>>(mut map: A) -> Result<Option<String>, A::Error> {
        while map
            .next_entry::<serde::de::IgnoredAny, serde::de::IgnoredAny>()?
            .is_some()
        {}
        Ok(None)
    }
}

#[derive(Default)]
struct ObjectField;
impl Lenient for ObjectField {
    type Value = ReceiptFields;
    fn map<'de, A: serde::de::MapAccess<'de>>(map: A) -> Result<Option<ReceiptFields>, A::Error> {
        ReceiptFields::deserialize(serde::de::value::MapAccessDeserializer::new(map)).map(Some)
    }
}

#[derive(Default)]
struct LenientVisitor<L>(std::marker::PhantomData<L>);

impl<'de, L: Lenient> serde::de::Visitor<'de> for LenientVisitor<L> {
    type Value = Option<L::Value>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("any JSON value")
    }
    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(L::string(value))
    }
    fn visit_map<A: serde::de::MapAccess<'de>>(self, map: A) -> Result<Self::Value, A::Error> {
        L::map(map)
    }
    fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        while seq.next_element::<serde::de::IgnoredAny>()?.is_some() {}
        Ok(None)
    }
    fn visit_bool<E>(self, _: bool) -> Result<Self::Value, E> {
        Ok(None)
    }
    fn visit_i64<E>(self, _: i64) -> Result<Self::Value, E> {
        Ok(None)
    }
    fn visit_u64<E>(self, _: u64) -> Result<Self::Value, E> {
        Ok(None)
    }
    fn visit_f64<E>(self, _: f64) -> Result<Self::Value, E> {
        Ok(None)
    }
    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(None)
    }
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
    fn recognises_a_receipt_carried_as_a_didcomm_message_body() {
        // The DIDComm transport sets `payload` = the FULL plaintext message JSON
        // (`Message::to_json()`), so the Receipt lives under `body`, not at the
        // top level. This is the shape `to_inbound` produces — it must be
        // recognised. (Regression: `receipt_key` used to parse the whole message
        // as a `Receipt`, which never matched, so DIDComm layer receipts were
        // silently ignored.)
        let key = "did:example:bob:1737000000000:7";
        let receipt_body =
            serde_json::from_slice::<serde_json::Value>(&Receipt::new(key).encode()).unwrap();
        let full_message = serde_json::json!({
            "id": "urn:uuid:msg-1",
            "typ": "application/didcomm-plain+json",
            "from": "did:example:alice",
            "to": ["did:example:bob"],
            "body": receipt_body,
        });
        let payload = serde_json::to_vec(&full_message).unwrap();
        assert_eq!(receipt_key(&payload).as_deref(), Some(key));
        assert_eq!(receipt_of(&message_with(payload)).as_deref(), Some(key));
    }

    #[test]
    fn a_didcomm_message_with_a_non_receipt_body_is_not_a_receipt() {
        let full_message = serde_json::json!({
            "id": "urn:uuid:msg-2",
            "typ": "application/didcomm-plain+json",
            "from": "did:example:alice",
            "body": { "hello": "world" },
        });
        let payload = serde_json::to_vec(&full_message).unwrap();
        assert_eq!(receipt_key(&payload), None);
        assert_eq!(receipt_of(&message_with(payload)), None);
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

    /// Fields of other types, or a `body` that is not an object, are read past
    /// rather than stopping the receipt check.
    #[test]
    fn unexpected_field_types_do_not_hide_or_fake_a_receipt() {
        let key = "did:example:bob:1:2";
        let in_body = serde_json::json!({
            "type": 7,
            "confirms": ["not", "a", "key"],
            "attachments": [{ "data": { "json": { "type": RECEIPT_TYPE } } }],
            "body": { "type": RECEIPT_TYPE, "confirms": key, "extra": [1, 2, 3] },
        });
        assert_eq!(
            receipt_key(&serde_json::to_vec(&in_body).unwrap()).as_deref(),
            Some(key)
        );
        for body in [
            serde_json::json!("text"),
            serde_json::json!([RECEIPT_TYPE, key]),
            serde_json::json!(null),
            serde_json::json!({ "type": RECEIPT_TYPE, "confirms": 42 }),
            serde_json::json!({ "type": RECEIPT_TYPE }),
        ] {
            let message = serde_json::json!({ "id": "m", "body": body });
            assert_eq!(
                receipt_key(&serde_json::to_vec(&message).unwrap()),
                None,
                "{message}"
            );
        }
    }

    #[test]
    fn receipt_type_is_the_stable_marker() {
        let bytes = Receipt::new("k").encode();
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains(RECEIPT_TYPE));
    }
}
