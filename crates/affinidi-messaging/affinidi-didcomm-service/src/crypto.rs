use affinidi_messaging_didcomm::{Message, UnpackMetadata};
use affinidi_messaging_sdk::{ATM, profiles::ATMProfile};
use async_trait::async_trait;

use crate::error::DIDCommServiceError;

#[async_trait]
pub trait MessageCryptoProvider: Send + Sync + 'static {
    async fn unpack(
        &self,
        atm: &ATM,
        profile: &ATMProfile,
        packed_message: &str,
    ) -> Result<(Message, UnpackMetadata), DIDCommServiceError>;

    async fn pack(
        &self,
        atm: &ATM,
        profile: &ATMProfile,
        message: &Message,
    ) -> Result<String, DIDCommServiceError>;
}

pub struct DefaultCryptoProvider;

#[async_trait]
impl MessageCryptoProvider for DefaultCryptoProvider {
    async fn unpack(
        &self,
        atm: &ATM,
        _profile: &ATMProfile,
        packed_message: &str,
    ) -> Result<(Message, UnpackMetadata), DIDCommServiceError> {
        let (message, meta) = atm.unpack(packed_message).await?;
        Ok((message, meta))
    }

    async fn pack(
        &self,
        atm: &ATM,
        profile: &ATMProfile,
        message: &Message,
    ) -> Result<String, DIDCommServiceError> {
        let recipient = message
            .to
            .as_ref()
            .and_then(|to| to.first())
            .ok_or_else(|| {
                DIDCommServiceError::Crypto("Message has no recipient in 'to' field".into())
            })?;

        let (packed, _) = atm
            .pack_encrypted(
                message,
                recipient,
                Some(&profile.inner.did),
                Some(&profile.inner.did),
                None,
            )
            .await?;

        Ok(packed)
    }
}
