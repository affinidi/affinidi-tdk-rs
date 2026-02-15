use crate::{ATM, SharedState, errors::ATMError};
use affinidi_messaging_didcomm::{
    AttachmentData, Message, UnpackMetadata, UnpackOptions, envelope::MetaEnvelope,
};
use base64::{Engine, prelude::BASE64_URL_SAFE};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{Instrument, Level, debug, span, warn};

impl ATM {
    pub async fn unpack(&self, message: &str) -> Result<(Message, UnpackMetadata), ATMError> {
        let _span = span!(Level::DEBUG, "unpack",);

        async move { self.inner.unpack(message).await }
            .instrument(_span)
            .await
    }

    /// Tries to process a mesage that contains a forwarded message (raw envelope).
    pub async fn unpack_forward(
        &self,
        message: &Message,
    ) -> Result<(Message, UnpackMetadata), ATMError> {
        let _span = span!(Level::DEBUG, "unpack_forward",);

        async move { self.inner.unpack_forward(message).await }
            .instrument(_span)
            .await
    }
}

impl SharedState {
    pub async fn unpack(&self, message: &str) -> Result<(Message, UnpackMetadata), ATMError> {
        let _span = span!(Level::DEBUG, "unpack",);

        async move {
            let mut msg_string = message.to_string();

            loop {
                let mut envelope =
                    match MetaEnvelope::new(&msg_string, &self.tdk_common.did_resolver).await {
                        Ok(envelope) => envelope,
                        Err(e) => {
                            return Err(ATMError::DidcommError(
                                "Cannot convert string to MetaEnvelope".into(),
                                e.to_string(),
                            ));
                        }
                    };
                debug!("message converted to MetaEnvelope");

                // Unpack the message
                let (msg, metadata) = match Message::unpack(
                    &mut envelope,
                    &self.tdk_common.did_resolver,
                    &self.tdk_common.secrets_resolver,
                    &UnpackOptions::default(),
                )
                .await
                {
                    Ok(ok) => ok,
                    Err(e) => {
                        return Err(ATMError::DidcommError(
                            "Couldn't unpack incoming message".into(),
                            e.to_string(),
                        ));
                    }
                };

                debug!("message unpacked:\n{:#?}", msg);

                if self.config.unpack_forwards
                    && msg.type_ == "https://didcomm.org/routing/2.0/forward"
                {
                    // Extract the inner message and loop to unpack it
                    msg_string = Self::extract_forward_payload(&msg)?;
                } else {
                    return Ok((msg, metadata));
                }
            }
        }
        .instrument(_span)
        .await
    }

    pub async fn unpack_forward(
        &self,
        message: &Message,
    ) -> Result<(Message, UnpackMetadata), ATMError> {
        let _span = span!(Level::DEBUG, "unpack_forward",);

        async move {
            debug!("Attempting to unpack a forwarded message");
            let inner = Self::extract_forward_payload(message)?;
            self.unpack(&inner).await
        }
        .instrument(_span)
        .await
    }

    /// Extracts the inner message string from a forward message's attachment.
    /// Checks expiry and supports JSON and Base64 attachment formats.
    pub(crate) fn extract_forward_payload(message: &Message) -> Result<String, ATMError> {
        debug!("Extracting payload from forwarded message");

        // Check expiry time if it exists
        if let Some(expires_time) = message.expires_time {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            if expires_time <= now {
                return Err(ATMError::MsgReceiveError(String::from(
                    "Forwarded Message has expired and cannot be processed",
                )));
            }
        }

        if let Some(attachments) = &message.attachments
            && !attachments.is_empty()
        {
            if attachments.len() > 1 {
                warn!(
                    "There is more than one attachment, only unpacking the first forwarded \
                     attachment. Total attachments ({})",
                    attachments.len()
                );
            }
            if let Some(attachment) = attachments.first() {
                match &attachment.data {
                    AttachmentData::Json { value } => {
                        serde_json::to_string(&value.json).map_err(|e| {
                            ATMError::MsgReceiveError(format!(
                                "Attachment data is in JSON format, but cannot be converted \
                                 to string: {e}"
                            ))
                        })
                    }
                    AttachmentData::Base64 { value } => {
                        let bytes = BASE64_URL_SAFE.decode(&value.base64).map_err(|e| {
                            ATMError::MsgReceiveError(format!(
                                "Attachment data is in Base64 format, but cannot be decoded: {e}"
                            ))
                        })?;
                        String::from_utf8(bytes).map_err(|e| {
                            ATMError::MsgReceiveError(format!(
                                "Attachment data is in Base64 format and can be decoded, but \
                                 the decoded data cannot be converted to a UTF-8 string: {e}"
                            ))
                        })
                    }
                    _ => Err(ATMError::MsgReceiveError(String::from(
                        "Attachment data is not in a supported format \
                         (only JSON and Base64 are supported)",
                    ))),
                }
            } else {
                Err(ATMError::MsgReceiveError(String::from(
                    "Message has attachments, but cannot access the first attachment",
                )))
            }
        } else {
            Err(ATMError::MsgReceiveError(String::from(
                "Trying to unpack a forwarded message, though there are no attachments!",
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ATMConfig;
    use affinidi_messaging_didcomm::Attachment;
    use affinidi_tdk_common::TDKSharedState;
    use serde_json::json;
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};

    const FORWARD_TYPE: &str = "https://didcomm.org/routing/2.0/forward";

    /// Creates an ATM instance with default config (unpack_forwards=true).
    async fn create_atm() -> ATM {
        let config = ATMConfig::builder().build().unwrap();
        let tdk = Arc::new(TDKSharedState::default().await);
        ATM::new(config, tdk).await.unwrap()
    }

    /// Creates an ATM instance with unpack_forwards disabled.
    async fn create_atm_no_unpack_forwards() -> ATM {
        let config = ATMConfig::builder()
            .with_unpack_forwards(false)
            .build()
            .unwrap();
        let tdk = Arc::new(TDKSharedState::default().await);
        ATM::new(config, tdk).await.unwrap()
    }

    /// Builds a simple plaintext test message.
    fn make_inner_message() -> Message {
        Message::build(
            "test-msg-1".into(),
            "example/v1".into(),
            json!({"hello": "world"}),
        )
        .from("did:example:sender".into())
        .to("did:example:recipient".into())
        .finalize()
    }

    /// Serializes a Message to a JSON string.
    fn make_plaintext_json(msg: &Message) -> String {
        serde_json::to_string(msg).unwrap()
    }

    /// Wraps inner_json in a forward envelope with a JSON attachment.
    fn wrap_in_forward_json(inner_json: &str, expires_time: Option<u64>) -> Message {
        let inner_value: serde_json::Value = serde_json::from_str(inner_json).unwrap();
        let attachment = Attachment::json(inner_value)
            .id("fwd-1".into())
            .finalize();
        let mut builder = Message::build(
            "fwd-msg-1".into(),
            FORWARD_TYPE.into(),
            json!({"next": "did:example:recipient"}),
        )
        .attachment(attachment);
        if let Some(exp) = expires_time {
            builder = builder.expires_time(exp);
        }
        builder.finalize()
    }

    /// Wraps inner_json in a forward envelope with a Base64 attachment.
    fn wrap_in_forward_base64(inner_json: &str, expires_time: Option<u64>) -> Message {
        let encoded = BASE64_URL_SAFE.encode(inner_json.as_bytes());
        let attachment = Attachment::base64(encoded)
            .id("fwd-1".into())
            .finalize();
        let mut builder = Message::build(
            "fwd-msg-1".into(),
            FORWARD_TYPE.into(),
            json!({"next": "did:example:recipient"}),
        )
        .attachment(attachment);
        if let Some(exp) = expires_time {
            builder = builder.expires_time(exp);
        }
        builder.finalize()
    }

    // ---- ATM::unpack tests ----

    #[tokio::test]
    async fn unpack_plaintext_message() {
        let atm = create_atm().await;
        let msg = make_inner_message();
        let json_str = make_plaintext_json(&msg);

        let (unpacked, metadata) = atm.unpack(&json_str).await.unwrap();

        assert_eq!(unpacked.id, "test-msg-1");
        assert_eq!(unpacked.type_, "example/v1");
        assert_eq!(unpacked.body, json!({"hello": "world"}));
        assert_eq!(unpacked.from.as_deref(), Some("did:example:sender"));
        assert!(!metadata.encrypted);
        assert!(!metadata.authenticated);
        assert!(!metadata.non_repudiation);
    }

    #[tokio::test]
    async fn unpack_forward_json_attachment() {
        let atm = create_atm().await;
        let inner = make_inner_message();
        let inner_json = make_plaintext_json(&inner);
        let forward = wrap_in_forward_json(&inner_json, None);
        let forward_json = make_plaintext_json(&forward);

        let (unpacked, _metadata) = atm.unpack(&forward_json).await.unwrap();

        assert_eq!(unpacked.id, "test-msg-1");
        assert_eq!(unpacked.type_, "example/v1");
        assert_eq!(unpacked.body, json!({"hello": "world"}));
    }

    #[tokio::test]
    async fn unpack_forward_base64_attachment() {
        let atm = create_atm().await;
        let inner = make_inner_message();
        let inner_json = make_plaintext_json(&inner);
        let forward = wrap_in_forward_base64(&inner_json, None);
        let forward_json = make_plaintext_json(&forward);

        let (unpacked, _metadata) = atm.unpack(&forward_json).await.unwrap();

        assert_eq!(unpacked.id, "test-msg-1");
        assert_eq!(unpacked.type_, "example/v1");
        assert_eq!(unpacked.body, json!({"hello": "world"}));
    }

    #[tokio::test]
    async fn unpack_forward_disabled() {
        let atm = create_atm_no_unpack_forwards().await;
        let inner = make_inner_message();
        let inner_json = make_plaintext_json(&inner);
        let forward = wrap_in_forward_json(&inner_json, None);
        let forward_json = make_plaintext_json(&forward);

        let (unpacked, _metadata) = atm.unpack(&forward_json).await.unwrap();

        // Should return the forward envelope itself, not the inner message
        assert_eq!(unpacked.type_, FORWARD_TYPE);
        assert_eq!(unpacked.id, "fwd-msg-1");
    }

    #[tokio::test]
    async fn unpack_forward_nested() {
        let atm = create_atm().await;
        let inner = make_inner_message();
        let inner_json = make_plaintext_json(&inner);
        let forward1 = wrap_in_forward_json(&inner_json, None);
        let forward1_json = make_plaintext_json(&forward1);
        let forward2 = wrap_in_forward_base64(&forward1_json, None);
        let forward2_json = make_plaintext_json(&forward2);

        let (unpacked, _metadata) = atm.unpack(&forward2_json).await.unwrap();

        assert_eq!(unpacked.id, "test-msg-1");
        assert_eq!(unpacked.type_, "example/v1");
        assert_eq!(unpacked.body, json!({"hello": "world"}));
    }

    #[tokio::test]
    async fn unpack_forward_method() {
        let atm = create_atm().await;
        let inner = make_inner_message();
        let inner_json = make_plaintext_json(&inner);
        let forward = wrap_in_forward_json(&inner_json, None);

        let (unpacked, _metadata) = atm.unpack_forward(&forward).await.unwrap();

        assert_eq!(unpacked.id, "test-msg-1");
        assert_eq!(unpacked.type_, "example/v1");
    }

    #[tokio::test]
    async fn unpack_invalid_message() {
        let atm = create_atm().await;
        let result = atm.unpack("not a valid message").await;

        assert!(result.is_err());
        assert!(
            matches!(result.unwrap_err(), ATMError::DidcommError(_, _)),
            "Expected DidcommError"
        );
    }

    // ---- SharedState::extract_forward_payload tests ----

    #[test]
    fn extract_forward_payload_json() {
        let inner = make_inner_message();
        let inner_json = make_plaintext_json(&inner);
        let forward = wrap_in_forward_json(&inner_json, None);

        let extracted = SharedState::extract_forward_payload(&forward).unwrap();

        let extracted_value: serde_json::Value = serde_json::from_str(&extracted).unwrap();
        let inner_value: serde_json::Value = serde_json::from_str(&inner_json).unwrap();
        assert_eq!(extracted_value, inner_value);
    }

    #[test]
    fn extract_forward_payload_base64() {
        let inner = make_inner_message();
        let inner_json = make_plaintext_json(&inner);
        let forward = wrap_in_forward_base64(&inner_json, None);

        let extracted = SharedState::extract_forward_payload(&forward).unwrap();

        assert_eq!(extracted, inner_json);
    }

    #[test]
    fn extract_forward_payload_expired() {
        let inner = make_inner_message();
        let inner_json = make_plaintext_json(&inner);
        let forward = wrap_in_forward_json(&inner_json, Some(1));

        let result = SharedState::extract_forward_payload(&forward);

        assert!(result.is_err());
        assert!(
            matches!(&result.unwrap_err(), ATMError::MsgReceiveError(msg) if msg.contains("expired")),
            "Expected MsgReceiveError mentioning expiry"
        );
    }

    #[test]
    fn extract_forward_payload_not_expired() {
        let inner = make_inner_message();
        let inner_json = make_plaintext_json(&inner);
        let future = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;
        let forward = wrap_in_forward_json(&inner_json, Some(future));

        let result = SharedState::extract_forward_payload(&forward);

        assert!(result.is_ok());
    }

    #[test]
    fn extract_forward_payload_no_attachments() {
        let msg = Message::build(
            "fwd-no-attach".into(),
            FORWARD_TYPE.into(),
            json!({"next": "did:example:recipient"}),
        )
        .finalize();

        let result = SharedState::extract_forward_payload(&msg);

        assert!(result.is_err());
        assert!(
            matches!(&result.unwrap_err(), ATMError::MsgReceiveError(msg) if msg.contains("no attachments")),
            "Expected MsgReceiveError mentioning no attachments"
        );
    }

    #[test]
    fn extract_forward_payload_empty_attachments() {
        let mut msg = Message::build(
            "fwd-empty-attach".into(),
            FORWARD_TYPE.into(),
            json!({"next": "did:example:recipient"}),
        )
        .finalize();
        msg.attachments = Some(vec![]);

        let result = SharedState::extract_forward_payload(&msg);

        assert!(result.is_err());
        assert!(
            matches!(&result.unwrap_err(), ATMError::MsgReceiveError(msg) if msg.contains("no attachments")),
            "Expected MsgReceiveError mentioning no attachments"
        );
    }

    #[test]
    fn extract_forward_payload_unsupported_format() {
        let attachment = Attachment::links(
            vec!["https://example.com/msg".into()],
            "abc123hash".into(),
        )
        .id("fwd-link".into())
        .finalize();
        let msg = Message::build(
            "fwd-links".into(),
            FORWARD_TYPE.into(),
            json!({"next": "did:example:recipient"}),
        )
        .attachment(attachment)
        .finalize();

        let result = SharedState::extract_forward_payload(&msg);

        assert!(result.is_err());
        assert!(
            matches!(&result.unwrap_err(), ATMError::MsgReceiveError(msg) if msg.contains("not in a supported format")),
            "Expected MsgReceiveError mentioning unsupported format"
        );
    }

    #[test]
    fn extract_forward_payload_invalid_base64() {
        let attachment = Attachment::base64("!!!not-valid-base64!!!".into())
            .id("fwd-bad-b64".into())
            .finalize();
        let msg = Message::build(
            "fwd-bad-b64".into(),
            FORWARD_TYPE.into(),
            json!({"next": "did:example:recipient"}),
        )
        .attachment(attachment)
        .finalize();

        let result = SharedState::extract_forward_payload(&msg);

        assert!(result.is_err());
        assert!(
            matches!(&result.unwrap_err(), ATMError::MsgReceiveError(msg) if msg.contains("cannot be decoded")),
            "Expected MsgReceiveError mentioning decode failure"
        );
    }

    #[test]
    fn extract_forward_payload_base64_invalid_utf8() {
        let invalid_utf8: [u8; 4] = [0xFF, 0xFE, 0xFD, 0xFC];
        let encoded = BASE64_URL_SAFE.encode(invalid_utf8);
        let attachment = Attachment::base64(encoded)
            .id("fwd-bad-utf8".into())
            .finalize();
        let msg = Message::build(
            "fwd-bad-utf8".into(),
            FORWARD_TYPE.into(),
            json!({"next": "did:example:recipient"}),
        )
        .attachment(attachment)
        .finalize();

        let result = SharedState::extract_forward_payload(&msg);

        assert!(result.is_err());
        assert!(
            matches!(&result.unwrap_err(), ATMError::MsgReceiveError(msg) if msg.contains("cannot be converted to a UTF-8 string")),
            "Expected MsgReceiveError mentioning UTF-8 conversion failure"
        );
    }
}
