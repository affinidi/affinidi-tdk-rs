//! The SDK side of the delivery layer's receipts and delivery scope
//! (`affinidi-messaging-delivery`).
//!
//! - **Asking for a receipt.** A sender stamps a delivery id on what it sends:
//!   [`request_receipt`] for a DIDComm message (the `delivery_id` header,
//!   DIDComm binding 0.2 §2.1), [`tsp_envelope`] for a Trust Task carried over
//!   TSP (the envelope's `deliveryId`, TSP binding 0.2 §2.1). Use the outbox
//!   entry's idempotency key as the id, so a receipt settles that entry.
//! - **Reading a request.** [`DidCommTransport`](crate::DidCommTransport)
//!   surfaces the stamped id as `Inbound::delivery_id`, for DIDComm and TSP
//!   frames alike.
//! - **Sending a receipt.** [`AtmReceiptPacker`] is the delivery layer's
//!   `ReceiptPacker`: it builds the `messaging/receipt/0.1` Trust Task and seals
//!   it to the sender over the binding the receipted message arrived on.
//! - **Delivery scope.** [`ATM::delivery_scope`] says whether a message to a
//!   DID stays at the profile's own mediator or is relayed to another, which
//!   is what lets the delivery layer stop polling a mediator that can never
//!   answer (VTI-TRN-064).

use std::sync::Arc;

use affinidi_did_common::scid::same_reference;
use affinidi_messaging_core::{DeliveryScope, MessagingError, Protocol, is_valid_delivery_id};
use affinidi_messaging_delivery::{PackedReceipt, ReceiptPacker, ReceiptRequest};
use affinidi_messaging_didcomm::message::Message;
use serde::Deserialize;
use serde_json::Value;
use trust_tasks_rs::TrustTask;

use crate::protocols::trust_tasks::{ENVELOPE_TYPE, new_id};
use crate::tasks::messaging::receipt;
use crate::{ATM, errors::ATMError, profiles::ATMProfile};

/// The DIDComm header that asks for a delivery receipt (DIDComm binding 0.2
/// §2.1).
pub const DELIVERY_ID_HEADER: &str = "delivery_id";

/// The `type` of the TSP binding's envelope object, which carries a Trust Task
/// as `document` and, to ask for a receipt, a `deliveryId` (TSP binding 0.2
/// §2).
pub const TSP_ENVELOPE_TYPE: &str = "https://trusttasks.org/binding/tsp/0.1/envelope";

/// Ask for a delivery receipt for `message` by stamping `delivery_id` on it as
/// the `delivery_id` header.
///
/// `delivery_id` identifies the delivery being tracked — the outbox entry's
/// idempotency key, so the receipt settles it — and must not be derived from
/// the message's content or reused for another recipient (VTI-TRN-060). A
/// retry of the same delivery carries the same id. The header is not `thid`:
/// the DIDComm binding gives `thid` to the document's `threadId`.
///
/// `Err` for an id the binding does not allow (1 to 256 characters).
pub fn request_receipt(mut message: Message, delivery_id: &str) -> Result<Message, ATMError> {
    if !is_valid_delivery_id(delivery_id) {
        return Err(ATMError::MsgSendError(format!(
            "a delivery id is 1 to {} characters",
            affinidi_messaging_core::MAX_DELIVERY_ID_LEN
        )));
    }
    message.extra.insert(
        DELIVERY_ID_HEADER.to_string(),
        Value::String(delivery_id.to_string()),
    );
    Ok(message)
}

/// The TSP binding envelope carrying `document`, as the bytes to seal into a
/// TSP message: `{type, document}`, plus `deliveryId` when `delivery_id` asks
/// for a receipt (TSP binding 0.2 §2.1).
///
/// `Err` for a delivery id the binding does not allow (1 to 256 characters).
pub fn tsp_envelope(document: &Value, delivery_id: Option<&str>) -> Result<Vec<u8>, ATMError> {
    let mut envelope = serde_json::json!({
        "type": TSP_ENVELOPE_TYPE,
        "document": document,
    });
    if let Some(delivery_id) = delivery_id {
        if !is_valid_delivery_id(delivery_id) {
            return Err(ATMError::MsgSendError(format!(
                "a delivery id is 1 to {} characters",
                affinidi_messaging_core::MAX_DELIVERY_ID_LEN
            )));
        }
        envelope["deliveryId"] = Value::String(delivery_id.to_string());
    }
    serde_json::to_vec(&envelope)
        .map_err(|e| ATMError::MsgSendError(format!("couldn't serialise the TSP envelope: {e}")))
}

/// The delivery id a DIDComm message asks for a receipt with, if it asks and
/// the id is one the binding allows. [`DidCommTransport`](crate::DidCommTransport)
/// reads it into `Inbound::delivery_id`; this is for a receive path of its own.
pub fn didcomm_delivery_id(message: &Message) -> Option<String> {
    message
        .extra
        .get(DELIVERY_ID_HEADER)
        .and_then(Value::as_str)
        .filter(|id| is_valid_delivery_id(id))
        .map(str::to_string)
}

/// The delivery id a TSP payload asks for a receipt with: the `deliveryId` of
/// a TSP binding envelope, if the payload is one and the id is allowed.
/// [`DidCommTransport`](crate::DidCommTransport) reads it into
/// `Inbound::delivery_id`; this is for a receive path of its own.
pub fn tsp_delivery_id(payload: &[u8]) -> Option<String> {
    #[derive(Deserialize)]
    struct Envelope {
        #[serde(rename = "type")]
        kind: String,
        #[serde(rename = "deliveryId")]
        delivery_id: Option<String>,
    }
    let envelope: Envelope = serde_json::from_slice(payload).ok()?;
    (envelope.kind == TSP_ENVELOPE_TYPE)
        .then_some(envelope.delivery_id)?
        .filter(|id| is_valid_delivery_id(id))
}

/// The delivery layer's [`ReceiptPacker`] over this SDK, for one profile.
///
/// It builds the `messaging/receipt/0.1` Trust Task — `confirms` the delivery
/// id, `issuer` this profile, `recipient` the receipted message's sender — with
/// no delivery id of its own, since nobody receipts a receipt. Then, by the
/// binding the receipted message arrived on:
///
/// - **DIDComm**: the document rides the DIDComm binding envelope, authcrypted
///   to the sender, and is returned for the delivery layer to send over the
///   transport the message arrived on (which forwards it through the
///   profile's mediator).
/// - **TSP** (`tsp` feature): the document rides the TSP binding envelope,
///   sealed to the sender and sent here — cross-mediator with metadata privacy
///   where the sender's mediator is another one.
///
/// It sends a receipt only as the profile it was built for: a request to
/// confirm a message addressed to any other identity is refused rather than
/// answered from the wrong DID.
pub struct AtmReceiptPacker {
    atm: ATM,
    profile: Arc<ATMProfile>,
}

impl AtmReceiptPacker {
    /// A packer that sends receipts as `profile`.
    pub fn new(atm: ATM, profile: Arc<ATMProfile>) -> Self {
        Self { atm, profile }
    }

    async fn pack(&self, request: &ReceiptRequest) -> Result<PackedReceipt, ATMError> {
        let profile_did = self.profile.inner.did.as_str();
        if !same_reference(&request.from, profile_did) {
            return Err(ATMError::MsgSendError(format!(
                "the receipted message was addressed to {}, not to this packer's profile",
                request.from
            )));
        }
        let document = receipt_document(profile_did, &request.to, &request.confirms)?;
        match request.protocol {
            Protocol::DIDComm => {
                let now = chrono::Utc::now().timestamp().max(0) as u64;
                let message = Message::build(new_id(), ENVELOPE_TYPE.to_string(), document)
                    .to(request.to.clone())
                    .from(profile_did.to_string())
                    .created_time(now)
                    .finalize();
                let (packed, _) = self
                    .atm
                    .pack_encrypted(&message, &request.to, Some(profile_did), None)
                    .await?;
                Ok(PackedReceipt::Packed(packed.into_bytes()))
            }
            #[cfg(feature = "tsp")]
            Protocol::TSP => {
                let payload = tsp_envelope(&document, None)?;
                self.atm
                    .tsp()
                    .send_to_peer(&self.profile, &request.to, &payload)
                    .await?;
                Ok(PackedReceipt::Sent)
            }
            other => Err(ATMError::MsgSendError(format!(
                "this build sends no receipt over {other}"
            ))),
        }
    }
}

#[async_trait::async_trait]
impl ReceiptPacker for AtmReceiptPacker {
    async fn pack_receipt(
        &self,
        request: &ReceiptRequest,
    ) -> Result<PackedReceipt, MessagingError> {
        self.pack(request)
            .await
            .map_err(|e| MessagingError::Transport(format!("receipt: {e}")))
    }
}

/// The `messaging/receipt/0.1` document confirming `confirms`, from `issuer`
/// to `recipient`. `issuedAt` is REQUIRED by the specification; a `proof` is
/// OPTIONAL, since the sender relies on the binding's authenticated sender.
fn receipt_document(issuer: &str, recipient: &str, confirms: &str) -> Result<Value, ATMError> {
    let confirms = confirms
        .parse::<receipt::v0_1::PayloadConfirms>()
        .map_err(|e| ATMError::MsgSendError(format!("invalid delivery id: {e}")))?;
    let payload: receipt::v0_1::Payload = receipt::v0_1::Payload::builder()
        .confirms(confirms)
        .try_into()
        .map_err(|e| ATMError::MsgSendError(format!("invalid receipt payload: {e}")))?;
    let mut task = TrustTask::for_payload(new_id(), payload);
    task.issuer = Some(issuer.to_string());
    task.recipient = Some(recipient.to_string());
    task.issued_at = Some(chrono::Utc::now());
    serde_json::to_value(&task)
        .map_err(|e| ATMError::MsgSendError(format!("couldn't serialise the receipt: {e}")))
}

impl ATM {
    /// Whether a message `profile` sends to `dest` stays at the profile's own
    /// mediator or is relayed to the recipient's own mediator.
    ///
    /// Read from `dest`'s DID document the way the mediator reads it when it
    /// routes a `forward`: no `DIDCommMessaging` service, or one naming this
    /// mediator's DID or an address of this mediator, is
    /// [`Local`](DeliveryScope::Local); one naming any other address, or
    /// another mediator's DID whose own document names no address of this
    /// mediator, is [`Relayed`](DeliveryScope::Relayed).
    ///
    /// [`Unknown`](DeliveryScope::Unknown) when a document cannot be resolved
    /// or names nothing this can classify — never `Relayed` on a guess,
    /// because `Relayed` stops the delivery layer asking the mediator about
    /// the message.
    pub async fn delivery_scope(&self, profile: &Arc<ATMProfile>, dest: &str) -> DeliveryScope {
        let Ok((_, own_mediator)) = profile.dids() else {
            return DeliveryScope::Unknown;
        };
        if same_reference(dest, own_mediator) {
            return DeliveryScope::Local;
        }
        let own_authorities = own_authorities(profile);
        let Ok(resolved) = self.inner.tdk_common.did_resolver().resolve(dest).await else {
            return DeliveryScope::Unknown;
        };
        match classify(
            &didcomm_endpoints(&resolved.doc),
            own_mediator,
            &own_authorities,
        ) {
            Hop::Scope(scope) => scope,
            Hop::Via(peer_mediator) => {
                let Ok(resolved) = self
                    .inner
                    .tdk_common
                    .did_resolver()
                    .resolve(&peer_mediator)
                    .await
                else {
                    return DeliveryScope::Unknown;
                };
                let endpoints = didcomm_endpoints(&resolved.doc);
                if endpoints
                    .iter()
                    .any(|uri| authority(uri).is_some_and(|a| own_authorities.contains(&a)))
                {
                    DeliveryScope::Local
                } else {
                    DeliveryScope::Relayed
                }
            }
        }
    }
}

/// What one DID document's `DIDCommMessaging` endpoints say about where a
/// message to it goes.
#[derive(Debug, PartialEq, Eq)]
enum Hop {
    Scope(DeliveryScope),
    /// The endpoint names a mediator by DID, and that mediator is not ours —
    /// unless its own document names one of our addresses.
    Via(String),
}

/// Classify a recipient's `DIDCommMessaging` endpoints against this profile's
/// mediator, as the mediator's routing does: a service naming this mediator
/// wins wherever it appears; otherwise the first address decides, then the
/// first mediator DID.
fn classify(endpoints: &[String], own_mediator: &str, own_authorities: &[(String, u16)]) -> Hop {
    if endpoints.is_empty() {
        // The mediator stores a forward for a DID with no DIDComm service
        // locally.
        return Hop::Scope(DeliveryScope::Local);
    }
    let mut saw_address = false;
    let mut first_mediator: Option<&str> = None;
    for uri in endpoints {
        let uri = uri.trim_matches('"');
        if uri.starts_with("did:") {
            if same_reference(uri, own_mediator) {
                return Hop::Scope(DeliveryScope::Local);
            }
            first_mediator.get_or_insert(uri);
        } else if let Some(endpoint_authority) = authority(uri) {
            if own_authorities.contains(&endpoint_authority) {
                return Hop::Scope(DeliveryScope::Local);
            }
            saw_address = true;
        }
    }
    match (saw_address, first_mediator) {
        (true, _) => Hop::Scope(DeliveryScope::Relayed),
        (false, Some(mediator)) => Hop::Via(mediator.to_string()),
        (false, None) => Hop::Scope(DeliveryScope::Unknown),
    }
}

/// Every `DIDCommMessaging` endpoint URI in `doc`, in document order.
fn didcomm_endpoints(doc: &affinidi_did_common::Document) -> Vec<String> {
    doc.service
        .iter()
        .filter(|service| service.type_.iter().any(|t| t == "DIDCommMessaging"))
        .flat_map(|service| service.service_endpoint.get_uris())
        .collect()
}

/// The addresses this profile's mediator is reached at.
fn own_authorities(profile: &ATMProfile) -> Vec<(String, u16)> {
    match &*profile.inner.mediator {
        Some(mediator) => [&mediator.rest_endpoint, &mediator.websocket_endpoint]
            .into_iter()
            .flatten()
            .filter_map(|uri| authority(uri))
            .collect(),
        None => Vec::new(),
    }
}

/// The host and port of an HTTP(S) or WS(S) URL, lowercased, with the
/// scheme's default port when none is given. `None` for anything else.
fn authority(uri: &str) -> Option<(String, u16)> {
    let url = reqwest::Url::parse(uri.trim_matches('"')).ok()?;
    if !matches!(url.scheme(), "http" | "https" | "ws" | "wss") {
        return None;
    }
    let host = url.host_str()?.to_ascii_lowercase();
    let port = url.port_or_known_default()?;
    Some((host, port))
}

#[cfg(test)]
mod tests {
    use super::*;

    const OURS: &str = "did:web:mediator.example";

    fn ours() -> Vec<(String, u16)> {
        vec![("mediator.example".to_string(), 443)]
    }

    fn endpoints(uris: &[&str]) -> Vec<String> {
        uris.iter().map(|uri| uri.to_string()).collect()
    }

    #[test]
    fn a_recipient_naming_our_mediator_is_local() {
        assert_eq!(
            classify(&endpoints(&[OURS]), OURS, &ours()),
            Hop::Scope(DeliveryScope::Local)
        );
        assert_eq!(
            classify(&endpoints(&["wss://Mediator.example/ws"]), OURS, &ours()),
            Hop::Scope(DeliveryScope::Local)
        );
    }

    #[test]
    fn a_recipient_with_no_didcomm_service_is_local() {
        assert_eq!(
            classify(&[], OURS, &ours()),
            Hop::Scope(DeliveryScope::Local)
        );
    }

    #[test]
    fn a_recipient_at_another_address_is_relayed() {
        assert_eq!(
            classify(
                &endpoints(&["https://other.example/mediator/v1"]),
                OURS,
                &ours()
            ),
            Hop::Scope(DeliveryScope::Relayed)
        );
        // Same host, another port: another mediator.
        assert_eq!(
            classify(
                &endpoints(&["https://mediator.example:8443"]),
                OURS,
                &ours()
            ),
            Hop::Scope(DeliveryScope::Relayed)
        );
    }

    /// A service naming our mediator wins wherever it appears, as it does in
    /// the mediator's own routing.
    #[test]
    fn our_mediator_anywhere_in_the_list_is_local() {
        assert_eq!(
            classify(&endpoints(&["https://other.example", OURS]), OURS, &ours()),
            Hop::Scope(DeliveryScope::Local)
        );
    }

    #[test]
    fn another_mediator_named_by_did_is_followed_one_hop() {
        assert_eq!(
            classify(&endpoints(&["did:web:other.example"]), OURS, &ours()),
            Hop::Via("did:web:other.example".to_string())
        );
    }

    /// Never `Relayed` on a guess: an endpoint this cannot read says nothing.
    #[test]
    fn an_endpoint_nothing_can_be_read_from_is_unknown() {
        assert_eq!(
            classify(&endpoints(&["mailto:bob@example.com"]), OURS, &ours()),
            Hop::Scope(DeliveryScope::Unknown)
        );
    }

    #[test]
    fn a_receipt_is_requested_by_a_didcomm_header_and_read_back() {
        let message =
            Message::build("m1", "https://example.com/t", serde_json::json!({})).finalize();
        assert_eq!(didcomm_delivery_id(&message), None);
        let message = request_receipt(message, "k1").unwrap();
        assert_eq!(didcomm_delivery_id(&message).as_deref(), Some("k1"));
        assert!(
            message.thid.is_none(),
            "the delivery id is not the thread id"
        );

        let json = message.to_json().unwrap();
        let back = Message::from_json(&json).unwrap();
        assert_eq!(didcomm_delivery_id(&back).as_deref(), Some("k1"));
    }

    #[test]
    fn a_delivery_id_the_binding_does_not_allow_is_refused() {
        let message =
            Message::build("m1", "https://example.com/t", serde_json::json!({})).finalize();
        assert!(request_receipt(message, "").is_err());
        assert!(tsp_envelope(&serde_json::json!({}), Some(&"x".repeat(257))).is_err());
    }

    #[test]
    fn a_tsp_envelope_carries_the_delivery_id_only_when_asked() {
        let document = serde_json::json!({ "type": "https://example.com/t", "payload": {} });
        let plain = tsp_envelope(&document, None).unwrap();
        assert_eq!(tsp_delivery_id(&plain), None);
        let asked = tsp_envelope(&document, Some("k1")).unwrap();
        assert_eq!(tsp_delivery_id(&asked).as_deref(), Some("k1"));
        let value: Value = serde_json::from_slice(&asked).unwrap();
        assert_eq!(value["document"], document);

        // Not an envelope: no request, whatever it carries.
        let other = serde_json::to_vec(&serde_json::json!({
            "type": "https://example.com/other",
            "deliveryId": "k1",
        }))
        .unwrap();
        assert_eq!(tsp_delivery_id(&other), None);
    }

    /// The receipt is the specification's own task, readable by the delivery
    /// layer, and carries no delivery id of its own.
    #[test]
    fn a_receipt_document_is_read_back_by_the_delivery_layer() {
        let document = receipt_document("did:example:bob", "did:example:alice", "k1").unwrap();
        assert_eq!(
            document["type"],
            "https://trusttasks.org/spec/messaging/receipt/0.1"
        );
        assert_eq!(document["issuer"], "did:example:bob");
        assert_eq!(document["recipient"], "did:example:alice");
        assert!(document["issuedAt"].is_string());
        assert!(document.get("deliveryId").is_none());

        let didcomm = serde_json::json!({
            "id": "m",
            "type": ENVELOPE_TYPE,
            "body": document,
        });
        assert_eq!(
            affinidi_messaging_delivery::receipt_key(&serde_json::to_vec(&didcomm).unwrap())
                .as_deref(),
            Some("k1")
        );
        let tsp = tsp_envelope(&document, None).unwrap();
        assert_eq!(
            affinidi_messaging_delivery::receipt_key(&tsp).as_deref(),
            Some("k1")
        );
    }
}
