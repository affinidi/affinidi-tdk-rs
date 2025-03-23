use affinidi_messaging_mediator_common::errors::ProcessorError;
use serde::{Deserialize, Serialize};

/// MessageExpiryCleanup Struct contains configuration specific to cleaning up expired messages
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MessageExpiryCleanupConfig {
    pub enabled: bool,
}

impl Default for MessageExpiryCleanupConfig {
    fn default() -> Self {
        MessageExpiryCleanupConfig { enabled: true }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MessageExpiryCleanupConfigRaw {
    pub enabled: String,
}

impl std::convert::TryFrom<MessageExpiryCleanupConfigRaw> for MessageExpiryCleanupConfig {
    type Error = ProcessorError;

    fn try_from(raw: MessageExpiryCleanupConfigRaw) -> Result<Self, Self::Error> {
        Ok(MessageExpiryCleanupConfig {
            enabled: raw.enabled.parse().unwrap_or(true),
        })
    }
}
