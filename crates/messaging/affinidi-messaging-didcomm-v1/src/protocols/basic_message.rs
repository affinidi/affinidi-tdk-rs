//! Basic Message 1.0 (Aries RFC 0095) — the v1 carrier protocol.
//!
//! ```json
//! {
//!   "@type": "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/basicmessage/1.0/message",
//!   "@id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
//!   "~l10n": { "locale": "en" },
//!   "sent_time": "2026-08-08T00:00:00Z",
//!   "content": "Your hovercraft is full of eels."
//! }
//! ```
//!
//! The v2.1 counterpart is `https://didcomm.org/basicmessage/2.0/message`, whose
//! `content` sits inside a `body` object. Here it is a top-level member.
//!
//! The type URI has **two equally valid forms** — the `did:sov:…;spec/` one
//! above and `https://didcomm.org/basicmessage/1.0/message`. Which one a peer
//! sends is its configuration, not its protocol version, so match with
//! [`is_basic_message`] rather than comparing against
//! [`BASIC_MESSAGE_TYPE`]. See [`crate::message::message_type`].
//!
//! # Carrying a structured payload
//!
//! RFC 0095 types `content` as a **string** meant for human display, and Credo
//! surfaces it to the user as chat text. There is no member in the message
//! schema for a structured document.
//!
//! That leaves a binding specification three options, and it has to pick one
//! explicitly — this crate supports all three but endorses none, because the
//! choice is the binding's to make:
//!
//! 1. **JSON-in-`content`.** Serialize the document and put the string in
//!    `content`. Interoperable with every v1 agent, at the cost of a
//!    double-encoded payload that a human-facing wallet will render as a wall
//!    of JSON. [`BasicMessage::with_json_content`].
//! 2. **A sibling top-level member.** Put the document under its own key and
//!    leave `content` as human-readable text. Nothing rejects it (v1 parsers
//!    ignore unknown members), but a strict RFC 0095 reader will not look for
//!    it. [`BasicMessage::field`].
//! 3. **An `~attach` decorator.** The idiomatic Aries place for a structured
//!    payload. Carried through by this crate as an ordinary top-level member.
//!
//! Whichever the binding picks, it must say so normatively: unlike v2.1, where
//! the message `body` is the obvious home, a v1 basic-message has no
//! self-evident slot and two implementations will otherwise choose differently.

use serde_json::Value;

use crate::error::DIDCommV1Error;
use crate::message::{MessageV1, ThreadDecorator, TypeFormat, types_match};

/// The Basic Message 1.0 type URI, in v1's legacy `did:sov` form.
///
/// This is what [`BasicMessage`] emits by default. The equivalent modern form
/// is [`BASIC_MESSAGE_TYPE_DIDCOMM_ORG`] — both are legal and mean the same
/// thing, so **never compare an incoming `@type` against this constant with
/// `==`**; use [`is_basic_message`]. See [`crate::message::message_type`].
pub const BASIC_MESSAGE_TYPE: &str = "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/basicmessage/1.0/message";

/// The Basic Message 1.0 type URI in the RFC 0348 form, which is what Credo
/// emits by default.
pub const BASIC_MESSAGE_TYPE_DIDCOMM_ORG: &str = "https://didcomm.org/basicmessage/1.0/message";

/// Builder for a basic message.
pub struct BasicMessage {
    msg: MessageV1,
}

impl BasicMessage {
    /// A basic message with human-readable `content`.
    pub fn new(content: impl Into<String>) -> Result<Self, DIDCommV1Error> {
        Ok(Self {
            msg: MessageV1::new(
                BASIC_MESSAGE_TYPE,
                serde_json::json!({ "content": content.into() }),
            )?,
        })
    }

    /// A basic message whose `content` is a JSON document, serialized to a
    /// string — option 1 in the [module docs](self).
    pub fn with_json_content(document: &Value) -> Result<Self, DIDCommV1Error> {
        let encoded = serde_json::to_string(document)
            .map_err(|e| DIDCommV1Error::Serialization(format!("content: {e}")))?;
        Self::new(encoded)
    }

    /// Set the `@id`.
    pub fn id(mut self, id: impl Into<String>) -> Self {
        self.msg = self.msg.id(id);
        self
    }

    /// Set `sent_time` (RFC 3339).
    ///
    /// Taken as a parameter rather than read from the clock: this crate does no
    /// timekeeping, matching how the workspace injects a `Clock` elsewhere.
    pub fn sent_time(mut self, sent_time: impl Into<String>) -> Self {
        self.msg = self.msg.field("sent_time", Value::String(sent_time.into()));
        self
    }

    /// Set the `~l10n` locale decorator.
    pub fn locale(mut self, locale: impl Into<String>) -> Self {
        self.msg = self
            .msg
            .field("~l10n", serde_json::json!({ "locale": locale.into() }));
        self
    }

    /// Set `~thread.thid`.
    pub fn thid(mut self, thid: impl Into<String>) -> Self {
        self.msg = self.msg.thid(thid);
        self
    }

    /// Set `~thread.pthid`.
    pub fn pthid(mut self, pthid: impl Into<String>) -> Self {
        self.msg = self.msg.pthid(pthid);
        self
    }

    /// Attach a `~thread` decorator wholesale — full control, including leaving
    /// `thid` absent while setting other members.
    pub fn thread(mut self, thread: ThreadDecorator) -> Self {
        self.msg = self.msg.thread(thread);
        self
    }

    /// Emit the `@type` in the given document-URI form. Defaults to
    /// [`TypeFormat::DidSov`]; see [`crate::message::message_type`].
    pub fn type_format(mut self, format: TypeFormat) -> Self {
        self.msg = self.msg.with_type_format(format);
        self
    }

    /// Set an arbitrary top-level member — option 2 or 3 in the
    /// [module docs](self).
    pub fn field(mut self, name: impl Into<String>, value: Value) -> Self {
        self.msg = self.msg.field(name, value);
        self
    }

    /// Finalize into a [`MessageV1`].
    pub fn finalize(self) -> MessageV1 {
        self.msg
    }
}

/// Read the `content` member of a basic message.
///
/// `None` when absent or not a string — this returns what is on the wire and
/// does not coerce.
pub fn content(msg: &MessageV1) -> Option<&str> {
    msg.body.get("content")?.as_str()
}

/// Read `content` and parse it as JSON — the counterpart to
/// [`BasicMessage::with_json_content`].
pub fn json_content(msg: &MessageV1) -> Result<Value, DIDCommV1Error> {
    let raw = content(msg).ok_or_else(|| {
        DIDCommV1Error::InvalidMessage("basic message has no string `content`".into())
    })?;
    serde_json::from_str(raw)
        .map_err(|e| DIDCommV1Error::InvalidMessage(format!("`content` is not valid JSON: {e}")))
}

/// Whether `msg` is a basic message, in either document-URI form.
pub fn is_basic_message(msg: &MessageV1) -> bool {
    types_match(&msg.typ, BASIC_MESSAGE_TYPE)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn matches_the_rfc_0095_wire_shape() {
        let msg = BasicMessage::new("Your hovercraft is full of eels.")
            .unwrap()
            .id("msg-1")
            .sent_time("2026-08-08T00:00:00Z")
            .locale("en")
            .finalize();

        let wire: Value = serde_json::from_slice(&msg.to_json().unwrap()).unwrap();
        assert_eq!(
            wire,
            json!({
                "@type": BASIC_MESSAGE_TYPE,
                "@id": "msg-1",
                "~l10n": { "locale": "en" },
                "sent_time": "2026-08-08T00:00:00Z",
                "content": "Your hovercraft is full of eels."
            })
        );
    }

    /// Both document-URI forms must be recognised on input, and the emitted
    /// form must be selectable.
    #[test]
    fn recognises_and_emits_both_type_uri_forms() {
        let legacy = BasicMessage::new("hi").unwrap().finalize();
        assert_eq!(legacy.typ, BASIC_MESSAGE_TYPE, "the default is did:sov");
        assert!(is_basic_message(&legacy));

        let modern = BasicMessage::new("hi")
            .unwrap()
            .type_format(TypeFormat::DidCommOrg)
            .finalize();
        assert_eq!(modern.typ, BASIC_MESSAGE_TYPE_DIDCOMM_ORG);
        assert!(
            is_basic_message(&modern),
            "a Credo-style @type must still be recognised as a basic message"
        );

        // And an unrelated type in either form must not be.
        let other = MessageV1::new("https://didcomm.org/trust_ping/1.0/ping", json!({})).unwrap();
        assert!(!is_basic_message(&other));
    }

    #[test]
    fn default_type_uri_uses_the_legacy_did_sov_form() {
        assert!(BASIC_MESSAGE_TYPE.starts_with("did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/"));
        assert!(
            !BASIC_MESSAGE_TYPE.starts_with("https://"),
            "the v2 https:// form is not routable by a v1 agent"
        );
    }

    #[test]
    fn json_content_roundtrips() {
        let document = json!({ "id": "doc-1", "issuer": "did:example:alice" });
        let msg = BasicMessage::with_json_content(&document)
            .unwrap()
            .finalize();

        assert!(is_basic_message(&msg));
        assert!(content(&msg).is_some(), "content is a string on the wire");
        assert_eq!(json_content(&msg).unwrap(), document);
    }

    #[test]
    fn json_content_reports_a_non_json_body() {
        let msg = BasicMessage::new("just text").unwrap().finalize();
        assert!(json_content(&msg).is_err());
    }

    #[test]
    fn arbitrary_members_ride_alongside_content() {
        let msg = BasicMessage::new("see attachment")
            .unwrap()
            .field(
                "~attach",
                json!([{ "@id": "a-1", "data": { "json": { "x": 1 } } }]),
            )
            .finalize();

        let wire: Value = serde_json::from_slice(&msg.to_json().unwrap()).unwrap();
        assert_eq!(wire["content"], "see attachment");
        assert_eq!(wire["~attach"][0]["data"]["json"]["x"], 1);
    }

    #[test]
    fn thread_decorator_is_fully_controllable() {
        let msg = BasicMessage::new("reply")
            .unwrap()
            .thread(ThreadDecorator::new().pthid("p-1").sender_order(2))
            .finalize();

        assert!(msg.thread.is_some());
        assert_eq!(msg.explicit_thid(), None, "thid left deliberately absent");
        assert_eq!(msg.pthid_value(), Some("p-1"));
    }
}
