//! DIDComm v1 plaintext messages.
//!
//! Mirrors [`affinidi_messaging_didcomm::message`] — a [`MessageV1`] with a
//! [`MessageBuilder`], `to_json` / `from_json`, and `pack` / `unpack`
//! submodules — so the two crates read alike. The structural differences below
//! are the protocol's, and each one is a place a v2 habit produces a message no
//! v1 agent will accept.
//!
//! # v1 vs v2.1 message structure
//!
//! | | v2.1 | v1 |
//! |---|---|---|
//! | Identifier | `id` | `@id` |
//! | Type | `type` | `@type` |
//! | Type URI | `https://didcomm.org/basicmessage/2.0/message` | `did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/basicmessage/1.0/message` |
//! | Payload | nested `body` object | **top-level members** |
//! | Threading | `thid` / `pthid` headers | `~thread` decorator |
//! | Sender / recipient | `from` / `to` headers | **absent — transport only** |
//!
//! ## There is no `body`
//!
//! A v1 message has no envelope member holding the payload. Protocol fields sit
//! directly alongside `@id` and `@type`:
//!
//! ```json
//! {
//!   "@type": "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/basicmessage/1.0/message",
//!   "@id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
//!   "sent_time": "2026-08-08T00:00:00Z",
//!   "content": "hello"
//! }
//! ```
//!
//! [`MessageV1::body`] is therefore a **flattened** map of those top-level
//! members, not a nested value. One consequence worth stating: a v1 body is
//! necessarily a JSON *object*. A v2 `body` may be any JSON value — the v2
//! adapter in this workspace packs a bare string — and there is nowhere to put
//! a non-object in a v1 message without inventing a member name for it.
//!
//! ## There is no `from` or `to`
//!
//! v2.1 puts the claimed sender in the plaintext `from` header, and the SDK
//! cross-checks it against the authenticated `skid`. A v1 message has no such
//! header, so there is nothing to cross-check and nothing to spoof: **the
//! transport identity is the only identity**. That is a simplification, not a
//! weakness — but it means a consumer cannot fall back on in-band addressing
//! when the transport identity is missing, which is exactly why
//! [`unpack::UnpackResult`] refuses to blur the anoncrypt case.

pub mod message_type;
pub mod pack;
pub mod thread;
pub mod unpack;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

pub use message_type::{MessageType, TypeFormat, types_match};
pub use thread::ThreadDecorator;

use crate::error::DIDCommV1Error;

/// A DIDComm v1 plaintext message.
///
/// See the [module docs](self) for how this differs from the v2.1
/// [`Message`](affinidi_messaging_didcomm::Message).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MessageV1 {
    /// The message identifier (`@id`).
    ///
    /// Note this is the *transport* identifier. It is unrelated to any
    /// identifier inside the payload — a Trust Task document's `id` is a
    /// different value with a different lifetime.
    #[serde(rename = "@id")]
    pub id: String,

    /// The message type URI (`@type`), in v1's legacy form.
    #[serde(rename = "@type")]
    pub typ: String,

    /// The `~thread` decorator, exactly as it appeared on the wire.
    ///
    /// `None` means no decorator was present — which is *not* the same as a
    /// decorator with no `thid`. See [`thread`].
    #[serde(rename = "~thread", default, skip_serializing_if = "Option::is_none")]
    pub thread: Option<ThreadDecorator>,

    /// Every other top-level member: the payload, plus any decorators this
    /// crate does not model (`~l10n`, `~attach`, `~transport`, …), carried
    /// through unchanged.
    #[serde(flatten)]
    pub body: Map<String, Value>,
}

impl MessageV1 {
    /// Create a message with a generated UUID `@id`.
    ///
    /// `body` supplies the top-level members. Passing a non-object is an error
    /// rather than a silent wrap — see the [module docs](self).
    pub fn new(typ: impl Into<String>, body: Value) -> Result<Self, DIDCommV1Error> {
        let body = match body {
            Value::Object(map) => map,
            other => {
                return Err(DIDCommV1Error::InvalidMessage(format!(
                    "a DIDComm v1 message body must be a JSON object (v1 has no `body` member to \
                     nest a {} in); wrap it in a named field",
                    kind_of(&other)
                )));
            }
        };
        Ok(Self {
            id: uuid::Uuid::new_v4().to_string(),
            typ: typ.into(),
            thread: None,
            body,
        })
    }

    /// Builder-style constructor, mirroring
    /// [`Message::build`](affinidi_messaging_didcomm::Message::build).
    pub fn build(
        id: impl Into<String>,
        typ: impl Into<String>,
        body: Value,
    ) -> Result<MessageBuilder, DIDCommV1Error> {
        let mut msg = Self::new(typ, body)?;
        msg.id = id.into();
        Ok(MessageBuilder { msg })
    }

    /// Set the `@id`.
    pub fn id(mut self, id: impl Into<String>) -> Self {
        self.id = id.into();
        self
    }

    /// Attach a `~thread` decorator wholesale.
    pub fn thread(mut self, thread: ThreadDecorator) -> Self {
        self.thread = Some(thread);
        self
    }

    /// Set `~thread.thid`, creating the decorator if absent.
    pub fn thid(mut self, thid: impl Into<String>) -> Self {
        self.thread.get_or_insert_with(ThreadDecorator::new).thid = Some(thid.into());
        self
    }

    /// Set `~thread.pthid`, creating the decorator if absent.
    pub fn pthid(mut self, pthid: impl Into<String>) -> Self {
        self.thread.get_or_insert_with(ThreadDecorator::new).pthid = Some(pthid.into());
        self
    }

    /// Set one top-level member.
    pub fn field(mut self, name: impl Into<String>, value: Value) -> Self {
        self.body.insert(name.into(), value);
        self
    }

    /// The `~thread.thid` **exactly as it appeared on the wire**.
    ///
    /// `None` covers both "no `~thread`" and "`~thread` with no `thid`". Use
    /// this when comparing against an in-band value: a defaulted `thid` is a
    /// value this crate synthesised, not one the sender asserted. See
    /// [`thread`].
    pub fn explicit_thid(&self) -> Option<&str> {
        self.thread.as_ref()?.thid.as_deref()
    }

    /// The thread id with RFC 0008 defaulting applied: `~thread.thid` when
    /// present, otherwise this message's `@id`.
    ///
    /// Use this for routing a reply, not for comparing against in-band values.
    pub fn effective_thid(&self) -> &str {
        self.explicit_thid().unwrap_or(&self.id)
    }

    /// Whether [`effective_thid`](Self::effective_thid) came from the default
    /// rather than the wire.
    pub fn thid_is_defaulted(&self) -> bool {
        self.explicit_thid().is_none()
    }

    /// The `~thread.pthid`. Never defaulted — a message with no parent thread
    /// genuinely has none.
    pub fn pthid_value(&self) -> Option<&str> {
        self.thread.as_ref()?.pthid.as_deref()
    }

    /// Whether this message's `@type` names `other`, treating the two v1
    /// document URIs as interchangeable.
    ///
    /// **Use this instead of comparing `typ` with `==`** — see
    /// [`message_type`] for why exact comparison silently drops peers
    /// configured for the other prefix.
    pub fn typ_matches(&self, other: &str) -> bool {
        types_match(&self.typ, other)
    }

    /// Rewrite `@type` into the given document-URI form, leaving it unchanged
    /// if it is not a parseable v1 message type.
    pub fn with_type_format(mut self, format: TypeFormat) -> Self {
        if let Ok(parsed) = MessageType::parse(&self.typ) {
            self.typ = parsed.to_uri(format);
        }
        self
    }

    /// Serialize to JSON bytes.
    pub fn to_json(&self) -> Result<Vec<u8>, DIDCommV1Error> {
        serde_json::to_vec(self).map_err(|e| DIDCommV1Error::Serialization(format!("message: {e}")))
    }

    /// Deserialize from JSON bytes.
    pub fn from_json(data: &[u8]) -> Result<Self, DIDCommV1Error> {
        serde_json::from_slice(data)
            .map_err(|e| DIDCommV1Error::InvalidMessage(format!("invalid v1 message: {e}")))
    }
}

fn kind_of(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// Builder for [`MessageV1`], mirroring the v2 crate's `MessageBuilder`.
pub struct MessageBuilder {
    msg: MessageV1,
}

impl MessageBuilder {
    /// Attach a `~thread` decorator.
    pub fn thread(mut self, thread: ThreadDecorator) -> Self {
        self.msg.thread = Some(thread);
        self
    }

    /// Set `~thread.thid`.
    pub fn thid(mut self, thid: String) -> Self {
        self.msg = self.msg.thid(thid);
        self
    }

    /// Set `~thread.pthid`.
    pub fn pthid(mut self, pthid: String) -> Self {
        self.msg = self.msg.pthid(pthid);
        self
    }

    /// Set one top-level member.
    pub fn field(mut self, name: String, value: Value) -> Self {
        self.msg.body.insert(name, value);
        self
    }

    /// Finalize the builder.
    pub fn finalize(self) -> MessageV1 {
        self.msg
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const BASIC_MESSAGE: &str = "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/basicmessage/1.0/message";

    #[test]
    fn serializes_with_at_prefixed_headers_and_a_flat_body() {
        let msg = MessageV1::new(BASIC_MESSAGE, json!({ "content": "hello" }))
            .unwrap()
            .id("msg-1");

        let json = serde_json::to_value(&msg).unwrap();
        assert_eq!(
            json,
            json!({
                "@id": "msg-1",
                "@type": BASIC_MESSAGE,
                "content": "hello",
            }),
            "v1 uses @id/@type and has no `body` member"
        );
    }

    #[test]
    fn roundtrips_through_json() {
        let msg = MessageV1::new(
            BASIC_MESSAGE,
            json!({ "content": "hi", "sent_time": "now" }),
        )
        .unwrap()
        .thid("t-1")
        .pthid("p-1");

        let parsed = MessageV1::from_json(&msg.to_json().unwrap()).unwrap();
        assert_eq!(parsed, msg);
    }

    #[test]
    fn parses_a_wire_message_with_unmodelled_decorators() {
        let wire = json!({
            "@type": BASIC_MESSAGE,
            "@id": "msg-1",
            "~thread": { "thid": "t-1" },
            "~l10n": { "locale": "en" },
            "sent_time": "2026-08-08T00:00:00Z",
            "content": "Your hovercraft is full of eels."
        });

        let msg = MessageV1::from_json(&serde_json::to_vec(&wire).unwrap()).unwrap();
        assert_eq!(msg.id, "msg-1");
        assert_eq!(msg.explicit_thid(), Some("t-1"));
        assert_eq!(msg.body["content"], "Your hovercraft is full of eels.");
        assert_eq!(
            msg.body["~l10n"]["locale"], "en",
            "unmodelled decorators are preserved"
        );

        // Round-tripping must not drop them either.
        let reparsed: Value = serde_json::from_slice(&msg.to_json().unwrap()).unwrap();
        assert_eq!(reparsed, wire);
    }

    #[test]
    fn rejects_a_non_object_body() {
        let err = MessageV1::new(BASIC_MESSAGE, json!("a bare string")).unwrap_err();
        assert!(matches!(err, DIDCommV1Error::InvalidMessage(_)));
        assert!(MessageV1::new(BASIC_MESSAGE, json!([1, 2, 3])).is_err());
        assert!(MessageV1::new(BASIC_MESSAGE, json!({})).is_ok());
    }

    // --- the absent-vs-defaulted thid distinction ---------------------------

    #[test]
    fn absent_thread_defaults_thid_to_the_message_id() {
        let msg = MessageV1::new(BASIC_MESSAGE, json!({}))
            .unwrap()
            .id("msg-1");

        assert_eq!(msg.thread, None);
        assert_eq!(msg.explicit_thid(), None);
        assert_eq!(msg.effective_thid(), "msg-1");
        assert!(msg.thid_is_defaulted());
    }

    /// A `~thread` that is present but carries no `thid` is a third state: the
    /// sender attached a decorator (perhaps for `pthid` or ordering) without
    /// asserting a thread id. It defaults the same way but is *not* the same
    /// wire fact as an absent decorator.
    #[test]
    fn present_thread_without_thid_is_distinct_from_absent() {
        let wire = r#"{"@id":"msg-1","@type":"t","~thread":{"pthid":"p-1"}}"#;
        let msg = MessageV1::from_json(wire.as_bytes()).unwrap();

        assert!(
            msg.thread.is_some(),
            "the decorator was present on the wire"
        );
        assert_eq!(msg.explicit_thid(), None);
        assert_eq!(msg.pthid_value(), Some("p-1"));
        assert_eq!(msg.effective_thid(), "msg-1");
        assert!(msg.thid_is_defaulted());

        // And it survives a round trip as a present decorator.
        let reparsed = MessageV1::from_json(&msg.to_json().unwrap()).unwrap();
        assert!(reparsed.thread.is_some());
    }

    /// `thid` explicitly equal to `@id` is indistinguishable from the default
    /// *by value*, and must remain distinguishable by provenance.
    #[test]
    fn thid_equal_to_the_message_id_is_still_explicit() {
        let msg = MessageV1::new(BASIC_MESSAGE, json!({}))
            .unwrap()
            .id("msg-1")
            .thid("msg-1");

        assert_eq!(msg.explicit_thid(), Some("msg-1"));
        assert_eq!(msg.effective_thid(), "msg-1");
        assert!(
            !msg.thid_is_defaulted(),
            "the sender asserted this value; it was not synthesised"
        );
    }

    /// Serialization must never synthesise a `~thread` the sender did not send.
    #[test]
    fn defaulting_is_never_written_back_to_the_wire() {
        let msg = MessageV1::new(BASIC_MESSAGE, json!({}))
            .unwrap()
            .id("msg-1");
        assert_eq!(msg.effective_thid(), "msg-1");

        let json: Value = serde_json::from_slice(&msg.to_json().unwrap()).unwrap();
        assert!(
            json.get("~thread").is_none(),
            "reading the effective thid must not materialise a decorator"
        );
    }

    #[test]
    fn builder_mirrors_the_v2_shape() {
        let msg = MessageV1::build("msg-1".to_string(), BASIC_MESSAGE.to_string(), json!({}))
            .unwrap()
            .thid("t-1".to_string())
            .field("content".to_string(), json!("hi"))
            .finalize();

        assert_eq!(msg.id, "msg-1");
        assert_eq!(msg.typ, BASIC_MESSAGE);
        assert_eq!(msg.explicit_thid(), Some("t-1"));
        assert_eq!(msg.body["content"], "hi");
    }
}
