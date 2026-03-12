mod context;
pub mod extractor;

pub use context::HandlerContext;
pub use extractor::{Extension, Extensions, FromMessageParts, MessageParts};

use affinidi_messaging_didcomm::{Message, UnpackMetadata};
use async_trait::async_trait;

use crate::error::DIDCommServiceError;
use crate::response::DIDCommResponse;

#[async_trait]
pub trait DIDCommHandler: Send + Sync + 'static {
    async fn handle(
        &self,
        ctx: HandlerContext,
        message: Message,
        meta: UnpackMetadata,
    ) -> Result<Option<DIDCommResponse>, DIDCommServiceError>;
}
