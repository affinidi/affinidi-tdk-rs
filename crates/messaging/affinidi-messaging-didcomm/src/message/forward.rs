//! DIDComm forward/routing messages.
//!
//! Implements the DIDComm Routing Protocol 2.0:
//! <https://identity.foundation/didcomm-messaging/spec/v2.1/#routing-protocol-20>

use serde_json::Value;

use crate::error::DIDCommError;
use crate::message::Message;

/// The DIDComm Routing Protocol 2.0 forward message type.
pub const FORWARD_MESSAGE_TYPE: &str = "https://didcomm.org/routing/2.0/forward";

/// Wrap an encrypted message in a forward envelope for a mediator/relay.
///
/// # Arguments
/// * `next` - The DID of the next hop (the intended recipient)
/// * `encrypted_msg` - The already-encrypted JWE string to forward
pub fn wrap_in_forward(next: &str, encrypted_msg: &str) -> Result<Message, DIDCommError> {
    let inner: Value = serde_json::from_str(encrypted_msg)
        .map_err(|e| DIDCommError::InvalidMessage(format!("invalid encrypted message: {e}")))?;

    let body = serde_json::json!({
        "next": next,
    });

    let mut msg = Message::new(FORWARD_MESSAGE_TYPE, body);

    // The forwarded message goes in attachments per DIDComm spec
    msg.extra.insert(
        "attachments".to_string(),
        serde_json::json!([{
            "data": {
                "json": inner
            }
        }]),
    );

    Ok(msg)
}

/// Extract the inner encrypted message from a forward envelope.
///
/// Returns the `next` DID and the inner encrypted message as a JSON string.
pub fn unwrap_forward(msg: &Message) -> Result<(String, String), DIDCommError> {
    if msg.typ != FORWARD_MESSAGE_TYPE {
        return Err(DIDCommError::InvalidMessage(format!(
            "expected forward message, got: {}",
            msg.typ
        )));
    }

    let next = msg.body["next"]
        .as_str()
        .ok_or_else(|| DIDCommError::InvalidMessage("missing 'next' in forward body".into()))?
        .to_string();

    // A forward built by `wrap_in_forward` carries its attachment in `extra`;
    // the same forward after a JSON round trip (i.e. as a relay receives it)
    // has it in the typed `attachments` field. Accept both.
    let inner = if let Some(attachments) = msg.attachments.as_ref() {
        attachments
            .first()
            .and_then(|a| a.data.json.clone())
            .ok_or_else(|| {
                DIDCommError::InvalidMessage("missing inner message in forward".into())
            })?
    } else {
        let attachments = msg
            .extra
            .get("attachments")
            .and_then(|v| v.as_array())
            .ok_or_else(|| DIDCommError::InvalidMessage("missing attachments in forward".into()))?;
        attachments
            .first()
            .and_then(|a| a.get("data"))
            .and_then(|d| d.get("json"))
            .cloned()
            .ok_or_else(|| {
                DIDCommError::InvalidMessage("missing inner message in forward".into())
            })?
    };

    let inner_str = serde_json::to_string(&inner)
        .map_err(|e| DIDCommError::Serialization(format!("inner message: {e}")))?;

    Ok((next, inner_str))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forward_roundtrip() {
        let inner_jwe =
            r#"{"protected":"abc","recipients":[],"iv":"def","ciphertext":"ghi","tag":"jkl"}"#;

        let forward = wrap_in_forward("did:example:bob", inner_jwe).unwrap();
        assert_eq!(forward.typ, FORWARD_MESSAGE_TYPE);
        assert_eq!(forward.body["next"], "did:example:bob");

        let (next, unwrapped) = unwrap_forward(&forward).unwrap();
        assert_eq!(next, "did:example:bob");

        // Parse both as JSON to compare (ordering may differ)
        let original: Value = serde_json::from_str(inner_jwe).unwrap();
        let parsed: Value = serde_json::from_str(&unwrapped).unwrap();
        assert_eq!(original, parsed);
    }

    /// A forward as a relay sees it — serialized and parsed back — still
    /// unwraps: its attachment is then in the typed `attachments` field.
    #[test]
    fn forward_roundtrip_through_json() {
        let inner_jwe =
            r#"{"protected":"abc","recipients":[],"iv":"def","ciphertext":"ghi","tag":"jkl"}"#;
        let forward = wrap_in_forward("did:example:bob", inner_jwe).unwrap();
        let parsed = Message::from_json(&forward.to_json().unwrap()).unwrap();

        let (next, unwrapped) = unwrap_forward(&parsed).unwrap();
        assert_eq!(next, "did:example:bob");
        let original: Value = serde_json::from_str(inner_jwe).unwrap();
        let parsed: Value = serde_json::from_str(&unwrapped).unwrap();
        assert_eq!(original, parsed);
    }
}
