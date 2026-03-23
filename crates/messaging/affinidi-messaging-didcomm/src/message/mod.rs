//! DIDComm message types and packing/unpacking.

pub mod forward;
pub mod pack;
pub mod unpack;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A DIDComm plaintext message.
///
/// This is the core message type — before any encryption or signing.
/// Conforms to DIDComm v2.1 message structure.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Message {
    /// Unique message ID (typically a UUID)
    pub id: String,
    /// Message type URI (e.g., "https://didcomm.org/basicmessage/2.0/message")
    #[serde(rename = "type")]
    pub typ: String,
    /// Sender DID (optional for anoncrypt)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    /// Recipient DID(s)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to: Option<Vec<String>>,
    /// Message body (type-specific JSON)
    pub body: Value,
    /// Thread ID for conversation threading
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thid: Option<String>,
    /// Parent thread ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pthid: Option<String>,
    /// Message creation time (Unix epoch seconds)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_time: Option<u64>,
    /// Message expiry time (Unix epoch seconds)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_time: Option<u64>,
    /// Attachments
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attachments: Option<Vec<Attachment>>,
    /// Additional headers (catch-all for extensions)
    #[serde(flatten)]
    pub extra: std::collections::HashMap<String, Value>,
}

impl Message {
    /// Create a new message with a generated UUID.
    pub fn new(typ: impl Into<String>, body: Value) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            typ: typ.into(),
            from: None,
            to: None,
            body,
            thid: None,
            pthid: None,
            created_time: None,
            expires_time: None,
            attachments: None,
            extra: std::collections::HashMap::new(),
        }
    }

    /// Builder-style constructor compatible with the legacy DIDComm API.
    ///
    /// Usage: `Message::build(id, typ, body).from(did).to(did).finalize()`
    pub fn build(id: impl Into<String>, typ: impl Into<String>, body: Value) -> MessageBuilder {
        MessageBuilder {
            msg: Message {
                id: id.into(),
                typ: typ.into(),
                from: None,
                to: None,
                body,
                thid: None,
                pthid: None,
                created_time: None,
                expires_time: None,
                attachments: None,
                extra: std::collections::HashMap::new(),
            },
        }
    }

    /// Set the sender.
    pub fn from(mut self, did: impl Into<String>) -> Self {
        self.from = Some(did.into());
        self
    }

    /// Set the recipient(s).
    pub fn to(mut self, dids: Vec<String>) -> Self {
        self.to = Some(dids);
        self
    }

    /// Set the thread ID.
    pub fn thid(mut self, thid: impl Into<String>) -> Self {
        self.thid = Some(thid.into());
        self
    }

    /// Set the parent thread ID.
    pub fn pthid(mut self, pthid: impl Into<String>) -> Self {
        self.pthid = Some(pthid.into());
        self
    }

    /// Set a custom message ID (overrides the generated UUID).
    pub fn id(mut self, id: impl Into<String>) -> Self {
        self.id = id.into();
        self
    }

    /// Set the created time.
    pub fn created_time(mut self, time: u64) -> Self {
        self.created_time = Some(time);
        self
    }

    /// Set the expiry time.
    pub fn expires_time(mut self, time: u64) -> Self {
        self.expires_time = Some(time);
        self
    }

    /// Add attachments.
    pub fn attachments(mut self, attachments: Vec<Attachment>) -> Self {
        self.attachments = Some(attachments);
        self
    }

    /// Serialize to JSON bytes.
    pub fn to_json(&self) -> Result<Vec<u8>, crate::error::DIDCommError> {
        serde_json::to_vec(self)
            .map_err(|e| crate::error::DIDCommError::Serialization(format!("message: {e}")))
    }

    /// Deserialize from JSON bytes.
    pub fn from_json(data: &[u8]) -> Result<Self, crate::error::DIDCommError> {
        serde_json::from_slice(data)
            .map_err(|e| {
                crate::error::DIDCommError::InvalidMessage(format!("invalid message: {e}"))
            })
    }
}

/// Builder for constructing Messages (legacy API compatibility).
pub struct MessageBuilder {
    msg: Message,
}

impl MessageBuilder {
    pub fn from(mut self, did: String) -> Self {
        self.msg.from = Some(did);
        self
    }

    pub fn to(mut self, did: String) -> Self {
        self.msg.to = Some(vec![did]);
        self
    }

    pub fn thid(mut self, thid: String) -> Self {
        self.msg.thid = Some(thid);
        self
    }

    pub fn pthid(mut self, pthid: String) -> Self {
        self.msg.pthid = Some(pthid);
        self
    }

    pub fn created_time(mut self, time: u64) -> Self {
        self.msg.created_time = Some(time);
        self
    }

    pub fn expires_time(mut self, time: u64) -> Self {
        self.msg.expires_time = Some(time);
        self
    }

    pub fn attachments(mut self, attachments: Vec<Attachment>) -> Self {
        self.msg.attachments = Some(attachments);
        self
    }

    /// Set an arbitrary header (stored in the `extra` map).
    pub fn header(mut self, name: String, value: serde_json::Value) -> Self {
        self.msg.extra.insert(name, value);
        self
    }

    /// Add a single attachment (appends to existing attachments).
    pub fn attachment(mut self, attachment: Attachment) -> Self {
        self.msg
            .attachments
            .get_or_insert_with(Vec::new)
            .push(attachment);
        self
    }

    /// Finalize the builder and return the Message.
    pub fn finalize(self) -> Message {
        self.msg
    }
}

/// A DIDComm attachment.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Attachment {
    /// Attachment ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Filename
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,
    /// Media type
    #[serde(skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,
    /// Format
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    /// Last modified time
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lastmod_time: Option<u64>,
    /// Byte count
    #[serde(skip_serializing_if = "Option::is_none")]
    pub byte_count: Option<u64>,
    /// The attachment data
    pub data: AttachmentData,
}

/// The data portion of an attachment.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct AttachmentData {
    /// JSON data
    #[serde(skip_serializing_if = "Option::is_none")]
    pub json: Option<Value>,
    /// Base64-encoded data
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base64: Option<String>,
    /// Links/URIs
    #[serde(skip_serializing_if = "Option::is_none")]
    pub links: Option<Vec<String>>,
    /// Content hash (used with links)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
    /// JWS signature
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jws: Option<String>,
}

impl Attachment {
    /// Create an attachment with JSON data.
    pub fn json(data: Value) -> AttachmentBuilder {
        AttachmentBuilder {
            attachment: Self {
                id: None,
                description: None,
                filename: None,
                media_type: Some("application/json".into()),
                format: None,
                lastmod_time: None,
                byte_count: None,
                data: AttachmentData {
                    json: Some(data),
                    base64: None,
                    links: None,
                    hash: None,
                    jws: None,
                },
            },
        }
    }

    /// Create an attachment with base64-encoded data.
    pub fn base64(data: String) -> AttachmentBuilder {
        AttachmentBuilder {
            attachment: Self {
                id: None,
                description: None,
                filename: None,
                media_type: None,
                format: None,
                lastmod_time: None,
                byte_count: None,
                data: AttachmentData {
                    json: None,
                    base64: Some(data),
                    links: None,
                    hash: None,
                    jws: None,
                },
            },
        }
    }

    /// Create an attachment with link URIs.
    pub fn links(links: Vec<String>, hash: String) -> AttachmentBuilder {
        AttachmentBuilder {
            attachment: Self {
                id: None,
                description: None,
                filename: None,
                media_type: None,
                format: None,
                lastmod_time: None,
                byte_count: None,
                data: AttachmentData {
                    json: None,
                    base64: None,
                    links: Some(links),
                    hash: Some(hash),
                    jws: None,
                },
            },
        }
    }

    /// Set the attachment ID.
    pub fn with_id(mut self, id: impl Into<String>) -> Self {
        self.id = Some(id.into());
        self
    }

    /// Set the media type.
    pub fn with_media_type(mut self, media_type: impl Into<String>) -> Self {
        self.media_type = Some(media_type.into());
        self
    }
}

/// Builder for constructing Attachments (legacy API compatibility).
pub struct AttachmentBuilder {
    attachment: Attachment,
}

impl AttachmentBuilder {
    pub fn id(mut self, id: String) -> Self {
        self.attachment.id = Some(id);
        self
    }

    pub fn description(mut self, description: String) -> Self {
        self.attachment.description = Some(description);
        self
    }

    pub fn filename(mut self, filename: String) -> Self {
        self.attachment.filename = Some(filename);
        self
    }

    pub fn media_type(mut self, media_type: String) -> Self {
        self.attachment.media_type = Some(media_type);
        self
    }

    pub fn format(mut self, format: String) -> Self {
        self.attachment.format = Some(format);
        self
    }

    pub fn lastmod_time(mut self, lastmod_time: u64) -> Self {
        self.attachment.lastmod_time = Some(lastmod_time);
        self
    }

    pub fn byte_count(mut self, byte_count: u64) -> Self {
        self.attachment.byte_count = Some(byte_count);
        self
    }

    pub fn jws(mut self, jws: String) -> Self {
        self.attachment.data.jws = Some(jws);
        self
    }

    /// Finalize the builder and return the Attachment.
    pub fn finalize(self) -> Attachment {
        self.attachment
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_roundtrip() {
        let msg = Message::new(
            "https://didcomm.org/basicmessage/2.0/message",
            serde_json::json!({"content": "Hello"}),
        )
        .from("did:example:alice")
        .to(vec!["did:example:bob".into()]);

        let json = msg.to_json().unwrap();
        let parsed = Message::from_json(&json).unwrap();
        assert_eq!(parsed.typ, msg.typ);
        assert_eq!(parsed.from, msg.from);
        assert_eq!(parsed.to, msg.to);
        assert_eq!(parsed.body, msg.body);
    }

    #[test]
    fn builder_compat() {
        let msg = Message::build(
            "msg-1".to_string(),
            "test/v1".to_string(),
            serde_json::json!({"key": "value"}),
        )
        .from("did:example:alice".into())
        .to("did:example:bob".into())
        .created_time(1234567890)
        .finalize();

        assert_eq!(msg.id, "msg-1");
        assert_eq!(msg.typ, "test/v1");
        assert_eq!(msg.from.as_deref(), Some("did:example:alice"));
        assert_eq!(msg.to.as_deref(), Some(vec!["did:example:bob".to_string()].as_slice()));
        assert_eq!(msg.created_time, Some(1234567890));
    }

    #[test]
    fn message_with_attachments() {
        let msg = Message::new("test", serde_json::json!({}))
            .attachments(vec![
                Attachment::json(serde_json::json!({"inner": "data"})).finalize(),
                Attachment::base64("SGVsbG8=".into()).id("att-1".into()).finalize(),
            ]);

        let json = msg.to_json().unwrap();
        let parsed = Message::from_json(&json).unwrap();
        let atts = parsed.attachments.unwrap();
        assert_eq!(atts.len(), 2);
        assert_eq!(atts[0].data.json.as_ref().unwrap()["inner"], "data");
        assert_eq!(atts[1].id.as_deref(), Some("att-1"));
    }
}
