use affinidi_messaging_didcomm::{Message, UnpackMetadata, UnpackOptions, envelope::MetaEnvelope};
use tracing::{Instrument, Level, debug, span};

use crate::{ATM, SharedState, errors::ATMError};

impl ATM {
    pub async fn unpack(&self, message: &str) -> Result<(Message, UnpackMetadata), ATMError> {
        let _span = span!(Level::DEBUG, "unpack",);

        async move { self.inner.unpack(message).await }
            .instrument(_span)
            .await
    }
}

impl SharedState {
    pub async fn unpack(&self, message: &str) -> Result<(Message, UnpackMetadata), ATMError> {
        let _span = span!(Level::DEBUG, "unpack",);

        async move {
            let mut envelope = match MetaEnvelope::new(message, &self.tdk_common.did_resolver).await
            {
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
            Ok((msg, metadata))
        }
        .instrument(_span)
        .await
    }
}
