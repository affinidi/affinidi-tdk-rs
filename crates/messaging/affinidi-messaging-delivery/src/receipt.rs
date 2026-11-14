//! Delivery receipts — end-to-end evidence that the recipient holds a message.
//!
//! A sender that wants to know a message arrived **asks** for a receipt by
//! stamping a delivery id on it: the DIDComm binding's `delivery_id` header, or
//! the TSP binding envelope's `deliveryId` (DIDComm / TSP binding 0.2 §2.1).
//! The recipient's delivery layer, once it holds the message, sends back the
//! `messaging/receipt/0.1` Trust Task whose `confirms` echoes the id, and the
//! sender settles the matching outbox entry `Sent → Delivered`. It is the only
//! evidence that works across mediators: a mediator can answer only for a
//! message it still holds, and the receipt comes from the recipient itself.
//!
//! ## Requested, never automatic (VTI-TRN-060, VTI-TRN-061)
//!
//! A receipt tells its sender when the recipient came online, so a receiver
//! sends one only for a message that asked ([`Inbound::delivery_id`]), only to
//! the sender the transport authenticated, and only after handing the message
//! off. A message that asked for nothing gets nothing, in either form.
//!
//! ## Correlation
//!
//! A receipt's `confirms` is matched to an outbox **idempotency key**, so a
//! sender stamps an entry's idempotency key as its delivery id. A retry of the
//! entry keeps the key, so a receipt for either attempt settles it. Because a
//! delivery id must not be reused for another recipient and should be
//! unpredictable (`messaging/receipt` "Requesting a receipt"), a sender that
//! asks for receipts uses idempotency keys with those properties.
//!
//! A receipt settles an entry only when it comes from that entry's recipient,
//! as the transport authenticated it (VTI-TRN-062). Anything else — another
//! sender, no authenticated sender, a key nothing is waiting on — settles
//! nothing and is dropped without an answer: nobody acknowledges an
//! acknowledgement.
//!
//! ## Both forms are read (VTI-TRN-063)
//!
//! Before `messaging/receipt` existed this layer sent the same evidence as a
//! bare body, `{"type": RECEIPT_TYPE, "confirms": …}`, correlated on the
//! DIDComm `thid`. [`receipt_key`] reads both, under the same rules. This layer
//! sends only the Trust Task form.
//!
//! ## Packing lives outside this crate
//!
//! Emitting a receipt means building a Trust Task document and sealing it to
//! the recipient — the crypto layer's concern, which this crate (no DIDComm or
//! TSP stack of its own) does not own, exactly as durable storage is abstracted
//! behind [`OutboxStore`]. A service wires in a [`ReceiptPacker`]; the consume
//! half needs none and is always active.
//!
//! [`Inbound::delivery_id`]: affinidi_messaging_core::Inbound::delivery_id
//! [`OutboxStore`]: crate::outbox::OutboxStore

use serde::{Deserialize, Serialize};

use affinidi_messaging_core::{MessagingError, Protocol, ReceivedMessage, is_valid_delivery_id};

use crate::outbox::Key;

/// The type of the earlier delivery-layer receipt body, which this layer still
/// reads (VTI-TRN-063) but no longer sends.
pub const RECEIPT_TYPE: &str = "https://affinidi.com/delivery/1.0/receipt";

/// The Type URI of the `messaging/receipt/0.1` Trust Task — the receipt this
/// layer reads and asks a [`ReceiptPacker`] to send.
pub const RECEIPT_TASK_TYPE: &str = "https://trusttasks.org/spec/messaging/receipt/0.1";

/// The earlier receipt body, `{"type": RECEIPT_TYPE, "confirms": …}`.
///
/// Still read on receive (VTI-TRN-063); this layer no longer sends it. Kept
/// for a peer that must speak to a sender predating `messaging/receipt`.
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

/// Decode an inbound payload as a delivery receipt, in either form, returning
/// the delivery id (idempotency key) it confirms. `None` for anything that is
/// not a receipt (application traffic, or non-JSON), so a caller can cheaply
/// tell receipts from application traffic without a separate type channel.
///
/// The shapes a transport surfaces as `payload`:
///
/// - **DIDComm**: the full plaintext message (`Message::to_json()`), so the
///   receipt is its `body` — the earlier body, or the Trust Task document the
///   DIDComm binding envelope carries.
/// - **TSP**: the decrypted payload — the TSP binding envelope, whose
///   `document` is the Trust Task, or a bare body or document.
///
/// The Trust Task form's `confirms` is its `payload.confirms`, and counts only
/// when it is a delivery id the bindings allow (1 to 256 characters).
pub fn receipt_key(payload: &[u8]) -> Option<Key> {
    // Every inbound message comes through here on the dispatcher, so it is
    // parsed once and only these fields are kept.
    let shape: ReceiptShape = serde_json::from_slice(payload).ok()?;
    let top = ReceiptFields {
        kind: shape.kind,
        confirms: shape.confirms,
        payload: shape.payload,
    };
    top.confirmed()
        .or_else(|| shape.body.and_then(ReceiptFields::confirmed))
        .or_else(|| shape.document.and_then(ReceiptFields::confirmed))
}

/// The fields of an inbound payload that can carry a receipt, at the top level
/// and under `body` or `document`. Every other field is skipped without being
/// kept.
#[derive(Deserialize)]
struct ReceiptShape {
    #[serde(rename = "type", default, deserialize_with = "string_or_none")]
    kind: Option<String>,
    #[serde(default, deserialize_with = "string_or_none")]
    confirms: Option<Key>,
    #[serde(default, deserialize_with = "payload_or_none")]
    payload: Option<PayloadFields>,
    #[serde(default, deserialize_with = "object_or_none")]
    body: Option<ReceiptFields>,
    #[serde(default, deserialize_with = "object_or_none")]
    document: Option<ReceiptFields>,
}

#[derive(Deserialize)]
struct ReceiptFields {
    #[serde(rename = "type", default, deserialize_with = "string_or_none")]
    kind: Option<String>,
    #[serde(default, deserialize_with = "string_or_none")]
    confirms: Option<Key>,
    #[serde(default, deserialize_with = "payload_or_none")]
    payload: Option<PayloadFields>,
}

#[derive(Deserialize)]
struct PayloadFields {
    #[serde(default, deserialize_with = "string_or_none")]
    confirms: Option<Key>,
}

impl ReceiptFields {
    /// The confirmed id iff `kind` names a receipt, so application JSON that
    /// merely happens to be an object is not mistaken for one.
    fn confirmed(self) -> Option<Key> {
        match self.kind.as_deref() {
            Some(RECEIPT_TYPE) => self.confirms,
            Some(RECEIPT_TASK_TYPE) => self
                .payload
                .and_then(|payload| payload.confirms)
                .filter(|confirms| is_valid_delivery_id(confirms)),
            _ => None,
        }
    }
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

/// An object read for a Trust Task payload's `confirms`, or `None` for a value
/// of any other type.
fn payload_or_none<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<PayloadFields>, D::Error> {
    deserializer.deserialize_any(LenientVisitor::<PayloadField>::default())
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
struct PayloadField;
impl Lenient for PayloadField {
    type Value = PayloadFields;
    fn map<'de, A: serde::de::MapAccess<'de>>(map: A) -> Result<Option<PayloadFields>, A::Error> {
        PayloadFields::deserialize(serde::de::value::MapAccessDeserializer::new(map)).map(Some)
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

/// The delivery id a received message is a receipt for, if it is one.
pub fn receipt_of(message: &ReceivedMessage) -> Option<Key> {
    receipt_key(&message.payload)
}

/// A receipt the delivery layer wants sent: the `messaging/receipt/0.1` Trust
/// Task confirming [`confirms`](Self::confirms), from [`from`](Self::from) to
/// [`to`](Self::to), over [`protocol`](Self::protocol).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ReceiptRequest {
    /// The sender of the receipted message, as its transport authenticated it
    /// — the receipt's `recipient`, and the only party it may go to.
    pub to: String,
    /// The identity the receipted message was addressed to — the receipt's
    /// `issuer`.
    pub from: String,
    /// The delivery id the message carried, echoed exactly.
    pub confirms: String,
    /// The binding the receipted message arrived on, which the receipt goes
    /// back over (`messaging/receipt` producer rule 4).
    pub protocol: Protocol,
}

impl ReceiptRequest {
    /// A request to confirm `confirms` to `to`, from `from`, over `protocol`.
    pub fn new(
        to: impl Into<String>,
        from: impl Into<String>,
        confirms: impl Into<String>,
        protocol: Protocol,
    ) -> Self {
        Self {
            to: to.into(),
            from: from.into(),
            confirms: confirms.into(),
            protocol,
        }
    }
}

/// What a [`ReceiptPacker`] made of a [`ReceiptRequest`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PackedReceipt {
    /// Bytes for [`MessageTransport::send`] on the transport the receipted
    /// message arrived on.
    ///
    /// [`MessageTransport::send`]: affinidi_messaging_core::MessageTransport::send
    Packed(Vec<u8>),
    /// The packer sent the receipt itself, because the transport the message
    /// arrived on cannot carry this binding's bytes (a TSP receipt over a
    /// DIDComm-framed transport).
    Sent,
}

/// Builds — and where it must, sends — a `messaging/receipt/0.1` receipt.
///
/// Packing is the crypto layer's concern and is deliberately **not** in this
/// crate — exactly as durable storage is abstracted behind [`OutboxStore`]. A
/// service wires one in with
/// [`MessagingService::with_receipts`](crate::MessagingService::with_receipts);
/// the SDK provides one for DIDComm and TSP. Only the *emit* half needs it — the
/// *consume* half (recognising an inbound receipt and confirming the outbox
/// entry) is always active.
///
/// The receipt carries no delivery id of its own: nobody receipts a receipt.
///
/// [`OutboxStore`]: crate::outbox::OutboxStore
#[async_trait::async_trait]
pub trait ReceiptPacker: Send + Sync {
    /// Build the receipt `request` describes, sealed to `request.to`. `Err`
    /// if the recipient can't be resolved or the receipt can't be sealed or
    /// sent — the receipt is then dropped (fire-and-forget; the sender re-sends
    /// within its window and the re-send is receipted again).
    async fn pack_receipt(&self, request: &ReceiptRequest)
    -> Result<PackedReceipt, MessagingError>;
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

    fn task_receipt(confirms: &str) -> serde_json::Value {
        serde_json::json!({
            "id": "urn:uuid:2b8e6d40-91c3-4f5a-8e27-c4d1a0b9f312",
            "type": RECEIPT_TASK_TYPE,
            "issuer": "did:example:bob",
            "recipient": "did:example:alice",
            "issuedAt": "2026-11-14T09:30:02Z",
            "payload": { "confirms": confirms },
        })
    }

    /// The Trust Task form over DIDComm: the binding envelope's `body` is the
    /// document.
    #[test]
    fn recognises_a_task_receipt_in_a_didcomm_envelope() {
        let message = serde_json::json!({
            "id": "m1",
            "type": "https://trusttasks.org/binding/didcomm/0.1/envelope",
            "from": "did:example:bob",
            "body": task_receipt("dlv_Hk3q9ZpX2mYc7RtW"),
        });
        assert_eq!(
            receipt_key(&serde_json::to_vec(&message).unwrap()).as_deref(),
            Some("dlv_Hk3q9ZpX2mYc7RtW")
        );
    }

    /// The Trust Task form over TSP: the binding envelope's `document`.
    #[test]
    fn recognises_a_task_receipt_in_a_tsp_envelope() {
        let envelope = serde_json::json!({
            "type": "https://trusttasks.org/binding/tsp/0.1/envelope",
            "document": task_receipt("k1"),
        });
        assert_eq!(
            receipt_key(&serde_json::to_vec(&envelope).unwrap()).as_deref(),
            Some("k1")
        );
        assert_eq!(
            receipt_key(&serde_json::to_vec(&task_receipt("k2")).unwrap()).as_deref(),
            Some("k2")
        );
    }

    /// A Trust Task receipt's id is its payload's; a top-level `confirms`
    /// beside the task type, or an id the bindings do not allow, is no receipt.
    #[test]
    fn a_task_receipt_confirms_only_through_its_payload() {
        let misplaced = serde_json::json!({ "type": RECEIPT_TASK_TYPE, "confirms": "k" });
        assert_eq!(receipt_key(&serde_json::to_vec(&misplaced).unwrap()), None);
        let empty = task_receipt("");
        assert_eq!(receipt_key(&serde_json::to_vec(&empty).unwrap()), None);
        let long = task_receipt(&"x".repeat(257));
        assert_eq!(receipt_key(&serde_json::to_vec(&long).unwrap()), None);
        let other_task = serde_json::json!({
            "type": "https://trusttasks.org/spec/messaging/ping/0.2",
            "payload": { "confirms": "k" },
        });
        assert_eq!(receipt_key(&serde_json::to_vec(&other_task).unwrap()), None);
    }

    #[test]
    fn receipt_type_is_the_stable_marker() {
        let bytes = Receipt::new("k").encode();
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains(RECEIPT_TYPE));
    }
}
