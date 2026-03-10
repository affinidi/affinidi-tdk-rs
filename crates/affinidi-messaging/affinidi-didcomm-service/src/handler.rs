use std::sync::Arc;

use affinidi_messaging_didcomm::{Message, UnpackMetadata};
use affinidi_messaging_sdk::{ATM, profiles::ATMProfile};
use async_trait::async_trait;

use crate::error::DIDCommServiceError;

#[derive(Clone)]
pub struct HandlerContext {
    pub atm: ATM,
    pub profile: Arc<ATMProfile>,
    pub sender_did: String,
    pub message_id: String,
    pub thread_id: Option<String>,
    pub parent_thread_id: Option<String>,
}

#[async_trait]
pub trait DIDCommHandler: Send + Sync + 'static {
    async fn handle(
        &self,
        ctx: HandlerContext,
        message: Message,
        meta: UnpackMetadata,
    ) -> Result<Option<Message>, DIDCommServiceError>;
}
