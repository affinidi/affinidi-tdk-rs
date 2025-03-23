use affinidi_messaging_didcomm::{
    Message, PackEncryptedMetadata, PackEncryptedOptions, PackSignedMetadata,
};
use tracing::{Instrument, Level, span};

use crate::{ATM, SharedState, errors::ATMError};

impl ATM {
    /// Pack a message for sending to a recipient
    /// from: if None, then will use anonymous encryption
    /// sign_by: If None, then will not sign the message
    pub async fn pack_encrypted(
        &self,
        message: &Message,
        to: &str,
        from: Option<&str>,
        sign_by: Option<&str>,
    ) -> Result<(String, PackEncryptedMetadata), ATMError> {
        self.inner.pack_encrypted(message, to, from, sign_by).await
    }
}

impl SharedState {
    /// Pack a message for sending to a recipient
    /// from: if None, then will use anonymous encryption
    /// sign_by: If None, then will not sign the message
    pub async fn pack_encrypted(
        &self,
        message: &Message,
        to: &str,
        from: Option<&str>,
        sign_by: Option<&str>,
    ) -> Result<(String, PackEncryptedMetadata), ATMError> {
        let _span = span!(Level::DEBUG, "pack_encrypted",);

        async move {
            message
                .pack_encrypted(
                    to,
                    from,
                    sign_by,
                    &self.tdk_common.did_resolver,
                    &self.tdk_common.secrets_resolver,
                    &PackEncryptedOptions::default(),
                )
                .await
        }
        .instrument(_span)
        .await
        .map_err(|e| {
            ATMError::DidcommError(
                "SDK".to_string(),
                format!("pack_encrypted() failed. Reason: {}", e),
            )
        })
    }

    /// Rare case of creating an unencrypted message, but you want to prove who sent the message
    /// Signs the unencrypted message with the sign_by key
    #[allow(dead_code)]
    pub async fn pack_signed(
        &self,
        message: &Message,
        sign_by: &str,
    ) -> Result<(String, PackSignedMetadata), ATMError> {
        let _span = span!(Level::DEBUG, "pack_signed",);

        async move {
            message
                .pack_signed(
                    sign_by,
                    &self.tdk_common.did_resolver,
                    &self.tdk_common.secrets_resolver,
                )
                .await
        }
        .instrument(_span)
        .await
        .map_err(|e| {
            ATMError::DidcommError(
                "SDK".to_string(),
                format!("pack_signed() failed. Reason: {}", e),
            )
        })
    }

    /// creates a plaintext (unencrypted and unsigned) message
    #[allow(dead_code)]
    pub async fn pack_plaintext(&self, message: &Message) -> Result<String, ATMError> {
        let _span = span!(Level::DEBUG, "pack_plaintext",);

        async move { message.pack_plaintext(&self.tdk_common.did_resolver).await }
            .instrument(_span)
            .await
            .map_err(|e| {
                ATMError::DidcommError(
                    "SDK".to_string(),
                    format!("pack_plaintext() failed. Reason: {}", e),
                )
            })
    }
}
