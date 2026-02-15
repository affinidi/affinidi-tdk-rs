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
    fn extract_forward_payload(message: &Message) -> Result<String, ATMError> {
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
