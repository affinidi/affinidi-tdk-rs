//! Message Pickup 2.0 (Aries RFC 0685).
//!
//! How an edge agent collects messages a mediator is holding for it:
//!
//! ```text
//! recipient                                mediator
//!    │  status-request  ────────────────────▶ │
//!    │ ◀───────────────────────── status     │  { message_count }
//!    │  delivery-request (limit) ───────────▶ │
//!    │ ◀─────────────────────── delivery     │  messages in ~attach
//!    │  messages-received (ids) ────────────▶ │
//!    │ ◀───────────────────────── status     │  remaining count
//! ```
//!
//! # Delivery is not deletion
//!
//! A `delivery` does **not** remove anything. The recipient acknowledges with
//! `messages-received`, and only then may the mediator drop them. That is what
//! makes pickup safe over a lossy transport: a delivery lost in flight is
//! re-delivered on the next request, because nothing was deleted on send.
//! A mediator that deletes on delivery silently loses messages.
//!
//! # `~transport.return_route`
//!
//! Every request here is sent expecting its response in the **HTTP response
//! body** — Aries' synchronous request/response over a one-way transport. The
//! decorator that asks for it is `~transport: { return_route: "all" }`; see
//! [`with_return_route`] and [`wants_return_route`].
//!
//! # Version
//!
//! 2.0 only. Credo's default pickup strategy is `PickUpV2`, and 1.0
//! (`batch-pickup`) is legacy — worth adding only if a target wallet turns out
//! to need it.

use serde_json::{Value, json};

use crate::error::DIDCommV1Error;
use crate::identity::Verkey;
use crate::message::{MessageV1, types_match};

/// `status-request` — ask how many messages are queued.
pub const STATUS_REQUEST_TYPE: &str =
    "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/messagepickup/2.0/status-request";
/// `status` — the queue state.
pub const STATUS_TYPE: &str = "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/messagepickup/2.0/status";
/// `delivery-request` — ask for up to `limit` queued messages.
pub const DELIVERY_REQUEST_TYPE: &str =
    "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/messagepickup/2.0/delivery-request";
/// `delivery` — queued messages, carried in the `~attach` decorator.
pub const DELIVERY_TYPE: &str = "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/messagepickup/2.0/delivery";
/// `messages-received` — acknowledge delivered messages so they can be dropped.
pub const MESSAGES_RECEIVED_TYPE: &str =
    "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/messagepickup/2.0/messages-received";
/// `live-delivery-change` — turn push delivery on or off.
pub const LIVE_DELIVERY_CHANGE_TYPE: &str =
    "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/messagepickup/2.0/live-delivery-change";

/// The `~transport` decorator value asking for a response on the same
/// connection.
pub const RETURN_ROUTE_ALL: &str = "all";

/// One queued message to deliver: its id and the packed envelope.
#[derive(Debug, Clone, PartialEq)]
pub struct QueuedMessage {
    /// The mediator's id for this message, echoed back in `messages-received`.
    pub id: String,
    /// The packed envelope, verbatim. Carried as attachment `data.json`.
    pub envelope: Value,
}

/// Which pickup message this is, if any.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MessagePickup {
    StatusRequest,
    Status,
    DeliveryRequest,
    Delivery,
    MessagesReceived,
    LiveDeliveryChange,
}

impl MessagePickup {
    /// Classify `msg`, or `None` if it is not a pickup message. Recognises both
    /// document-URI spellings.
    pub fn classify(msg: &MessageV1) -> Option<Self> {
        for (typ, kind) in [
            (STATUS_REQUEST_TYPE, Self::StatusRequest),
            (STATUS_TYPE, Self::Status),
            (DELIVERY_REQUEST_TYPE, Self::DeliveryRequest),
            (DELIVERY_TYPE, Self::Delivery),
            (MESSAGES_RECEIVED_TYPE, Self::MessagesReceived),
            (LIVE_DELIVERY_CHANGE_TYPE, Self::LiveDeliveryChange),
        ] {
            if types_match(&msg.typ, typ) {
                return Some(kind);
            }
        }
        None
    }
}

/// Attach `~transport: { return_route: "all" }`, asking the peer to answer on
/// the same connection.
pub fn with_return_route(msg: MessageV1) -> MessageV1 {
    msg.field("~transport", json!({ "return_route": RETURN_ROUTE_ALL }))
}

/// Whether `msg` asks for its response on the same connection.
///
/// A mediator uses this to decide between replying in the HTTP response body
/// and queueing the reply for later pickup.
pub fn wants_return_route(msg: &MessageV1) -> bool {
    msg.body
        .get("~transport")
        .and_then(|t| t.get("return_route"))
        .and_then(Value::as_str)
        .is_some_and(|route| route == RETURN_ROUTE_ALL)
}

/// The optional `recipient_key` scoping a request to one of the caller's keys.
///
/// Absent means "all of my keys". A key that cannot be decoded is an error, not
/// a silent fallback to "all" — the difference decides whose messages get
/// returned.
pub fn recipient_key(msg: &MessageV1) -> Result<Option<Verkey>, DIDCommV1Error> {
    match msg.body.get("recipient_key").and_then(Value::as_str) {
        Some(key) => Ok(Some(Verkey::parse(key)?)),
        None => Ok(None),
    }
}

/// Build a `status-request`.
pub fn status_request(recipient_key: Option<&Verkey>) -> Result<MessageV1, DIDCommV1Error> {
    let mut body = json!({});
    if let Some(key) = recipient_key {
        body["recipient_key"] = json!(key.to_base58());
    }
    Ok(with_return_route(MessageV1::new(
        STATUS_REQUEST_TYPE,
        body,
    )?))
}

/// Build a `status` reply carrying the queue depth.
pub fn status(
    request_id: &str,
    message_count: u64,
    recipient_key: Option<&Verkey>,
    live_delivery: bool,
) -> Result<MessageV1, DIDCommV1Error> {
    let mut body = json!({ "message_count": message_count, "live_delivery": live_delivery });
    if let Some(key) = recipient_key {
        body["recipient_key"] = json!(key.to_base58());
    }
    Ok(MessageV1::new(STATUS_TYPE, body)?.thid(request_id))
}

/// Build a `delivery-request` for up to `limit` messages.
pub fn delivery_request(
    limit: u32,
    recipient_key: Option<&Verkey>,
) -> Result<MessageV1, DIDCommV1Error> {
    let mut body = json!({ "limit": limit });
    if let Some(key) = recipient_key {
        body["recipient_key"] = json!(key.to_base58());
    }
    Ok(with_return_route(MessageV1::new(
        DELIVERY_REQUEST_TYPE,
        body,
    )?))
}

/// The `limit` of a `delivery-request`.
///
/// Absent or unreadable yields `None`; the caller decides its own default,
/// since a mediator's sensible cap is a policy question rather than a protocol
/// one.
pub fn delivery_limit(msg: &MessageV1) -> Option<u32> {
    msg.body
        .get("limit")
        .and_then(Value::as_u64)
        .and_then(|l| u32::try_from(l).ok())
}

/// Build a `delivery` carrying `messages` in the `~attach` decorator.
///
/// Each attachment is `{ "@id": <message id>, "data": { "json": <envelope> } }`
/// — the envelope inline, not re-encoded, matching what Credo emits and expects.
pub fn delivery(
    request_id: &str,
    messages: &[QueuedMessage],
    recipient_key: Option<&Verkey>,
) -> Result<MessageV1, DIDCommV1Error> {
    let attachments: Vec<Value> = messages
        .iter()
        .map(|m| json!({ "@id": m.id, "data": { "json": m.envelope } }))
        .collect();

    let mut body = json!({ "~attach": attachments });
    if let Some(key) = recipient_key {
        body["recipient_key"] = json!(key.to_base58());
    }
    Ok(MessageV1::new(DELIVERY_TYPE, body)?.thid(request_id))
}

/// Read the messages out of a `delivery`.
pub fn parse_delivery(msg: &MessageV1) -> Result<Vec<QueuedMessage>, DIDCommV1Error> {
    let attachments = msg
        .body
        .get("~attach")
        .and_then(Value::as_array)
        .ok_or_else(|| DIDCommV1Error::InvalidMessage("delivery has no `~attach`".into()))?;

    attachments
        .iter()
        .map(|attachment| {
            let id = attachment
                .get("@id")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    DIDCommV1Error::InvalidMessage("delivery attachment has no `@id`".into())
                })?
                .to_string();
            let envelope = attachment
                .get("data")
                .and_then(|d| d.get("json"))
                .ok_or_else(|| {
                    DIDCommV1Error::InvalidMessage(
                        "delivery attachment has no `data.json` envelope".into(),
                    )
                })?
                .clone();
            Ok(QueuedMessage { id, envelope })
        })
        .collect()
}

/// Build a `messages-received` acknowledging `ids`.
pub fn messages_received(ids: &[String]) -> Result<MessageV1, DIDCommV1Error> {
    Ok(with_return_route(MessageV1::new(
        MESSAGES_RECEIVED_TYPE,
        json!({ "message_id_list": ids }),
    )?))
}

/// Read the ids acknowledged by a `messages-received`.
pub fn parse_messages_received(msg: &MessageV1) -> Result<Vec<String>, DIDCommV1Error> {
    let ids = msg
        .body
        .get("message_id_list")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            DIDCommV1Error::InvalidMessage("messages-received has no `message_id_list`".into())
        })?;

    ids.iter()
        .map(|id| {
            id.as_str().map(str::to_string).ok_or_else(|| {
                DIDCommV1Error::InvalidMessage(
                    "messages-received `message_id_list` holds a non-string".into(),
                )
            })
        })
        .collect()
}

/// Build a `live-delivery-change`.
pub fn live_delivery_change(live: bool) -> Result<MessageV1, DIDCommV1Error> {
    Ok(with_return_route(MessageV1::new(
        LIVE_DELIVERY_CHANGE_TYPE,
        json!({ "live_delivery": live }),
    )?))
}

/// The requested state of a `live-delivery-change`.
pub fn live_delivery_requested(msg: &MessageV1) -> Option<bool> {
    msg.body.get("live_delivery").and_then(Value::as_bool)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::TypeFormat;

    fn envelope(tag: &str) -> Value {
        json!({ "protected": "eyJ0eXAiOiJKV00vMS4wIn0", "iv": "aXY", "ciphertext": tag, "tag": "dGFn" })
    }

    #[test]
    fn status_reports_the_queue_depth_and_threads_to_the_request() {
        let msg = status("req-1", 7, None, false).unwrap();
        let wire: Value = serde_json::from_slice(&msg.to_json().unwrap()).unwrap();

        assert_eq!(wire["@type"], STATUS_TYPE);
        assert_eq!(wire["message_count"], 7);
        assert_eq!(wire["live_delivery"], false);
        assert_eq!(wire["~thread"]["thid"], "req-1");
    }

    #[test]
    fn delivery_carries_envelopes_inline_in_attach() {
        let messages = vec![
            QueuedMessage {
                id: "m-1".into(),
                envelope: envelope("one"),
            },
            QueuedMessage {
                id: "m-2".into(),
                envelope: envelope("two"),
            },
        ];
        let msg = delivery("req-1", &messages, None).unwrap();
        let wire: Value = serde_json::from_slice(&msg.to_json().unwrap()).unwrap();

        assert_eq!(wire["@type"], DELIVERY_TYPE);
        assert_eq!(wire["~attach"][0]["@id"], "m-1");
        assert_eq!(
            wire["~attach"][0]["data"]["json"],
            envelope("one"),
            "the envelope rides inline as data.json, not re-encoded"
        );
        assert_eq!(wire["~attach"][1]["@id"], "m-2");
        assert_eq!(parse_delivery(&msg).unwrap(), messages);
    }

    #[test]
    fn messages_received_round_trips() {
        let ids = vec!["m-1".to_string(), "m-2".to_string()];
        let msg = messages_received(&ids).unwrap();
        assert_eq!(msg.body["message_id_list"], json!(ids));
        assert_eq!(parse_messages_received(&msg).unwrap(), ids);
    }

    /// Requests ask for a same-connection reply; a mediator keys its
    /// reply-vs-queue decision off this.
    #[test]
    fn requests_carry_return_route_all() {
        for msg in [
            status_request(None).unwrap(),
            delivery_request(10, None).unwrap(),
            messages_received(&["m-1".to_string()]).unwrap(),
            live_delivery_change(true).unwrap(),
        ] {
            assert!(
                wants_return_route(&msg),
                "{} must ask for a return route",
                msg.typ
            );
            let wire: Value = serde_json::from_slice(&msg.to_json().unwrap()).unwrap();
            assert_eq!(wire["~transport"]["return_route"], "all");
        }
    }

    #[test]
    fn return_route_is_absent_unless_asked_for() {
        let msg = status("req-1", 0, None, false).unwrap();
        assert!(
            !wants_return_route(&msg),
            "a reply does not itself request a return route"
        );
        // ...and an unrelated ~transport value is not mistaken for one.
        let other = MessageV1::new(STATUS_REQUEST_TYPE, json!({}))
            .unwrap()
            .field("~transport", json!({ "return_route": "none" }));
        assert!(!wants_return_route(&other));
    }

    #[test]
    fn recipient_key_accepts_both_spellings_and_absence() {
        let key = Verkey::from_bytes([5u8; 32]);

        for spelling in [key.to_base58(), key.to_did_key()] {
            let msg =
                MessageV1::new(STATUS_REQUEST_TYPE, json!({ "recipient_key": spelling })).unwrap();
            assert_eq!(recipient_key(&msg).unwrap(), Some(key));
        }

        let none = MessageV1::new(STATUS_REQUEST_TYPE, json!({})).unwrap();
        assert_eq!(
            recipient_key(&none).unwrap(),
            None,
            "absent means all of the caller's keys"
        );
    }

    /// An unreadable `recipient_key` must fail rather than fall back to "all" —
    /// the difference decides whose messages are returned.
    #[test]
    fn unreadable_recipient_key_is_an_error_not_a_wildcard() {
        let msg =
            MessageV1::new(STATUS_REQUEST_TYPE, json!({ "recipient_key": "nonsense" })).unwrap();
        assert!(recipient_key(&msg).is_err());
    }

    #[test]
    fn delivery_limit_is_read_when_present() {
        assert_eq!(
            delivery_limit(&delivery_request(25, None).unwrap()),
            Some(25)
        );
        let no_limit = MessageV1::new(DELIVERY_REQUEST_TYPE, json!({})).unwrap();
        assert_eq!(
            delivery_limit(&no_limit),
            None,
            "the caller supplies its own default"
        );
    }

    #[test]
    fn malformed_delivery_and_ack_are_errors() {
        let no_attach = MessageV1::new(DELIVERY_TYPE, json!({})).unwrap();
        assert!(parse_delivery(&no_attach).is_err());

        let no_data =
            MessageV1::new(DELIVERY_TYPE, json!({ "~attach": [{ "@id": "m-1" }] })).unwrap();
        assert!(parse_delivery(&no_data).is_err());

        let bad_ids =
            MessageV1::new(MESSAGES_RECEIVED_TYPE, json!({ "message_id_list": [1, 2] })).unwrap();
        assert!(parse_messages_received(&bad_ids).is_err());
    }

    #[test]
    fn classifies_every_message_in_both_type_spellings() {
        for (typ, expected) in [
            (STATUS_REQUEST_TYPE, MessagePickup::StatusRequest),
            (STATUS_TYPE, MessagePickup::Status),
            (DELIVERY_REQUEST_TYPE, MessagePickup::DeliveryRequest),
            (DELIVERY_TYPE, MessagePickup::Delivery),
            (MESSAGES_RECEIVED_TYPE, MessagePickup::MessagesReceived),
            (LIVE_DELIVERY_CHANGE_TYPE, MessagePickup::LiveDeliveryChange),
        ] {
            let legacy = MessageV1::new(typ, json!({})).unwrap();
            assert_eq!(MessagePickup::classify(&legacy), Some(expected));

            let modern = legacy.with_type_format(TypeFormat::DidCommOrg);
            assert!(
                modern
                    .typ
                    .starts_with("https://didcomm.org/messagepickup/2.0/")
            );
            assert_eq!(MessagePickup::classify(&modern), Some(expected));
        }
    }

    #[test]
    fn live_delivery_change_carries_its_flag() {
        assert_eq!(
            live_delivery_requested(&live_delivery_change(true).unwrap()),
            Some(true)
        );
        assert_eq!(
            live_delivery_requested(&live_delivery_change(false).unwrap()),
            Some(false)
        );
        let missing = MessageV1::new(LIVE_DELIVERY_CHANGE_TYPE, json!({})).unwrap();
        assert_eq!(live_delivery_requested(&missing), None);
    }
}
