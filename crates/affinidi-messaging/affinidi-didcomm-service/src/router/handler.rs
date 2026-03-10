use std::future::Future;
use std::pin::Pin;

use affinidi_messaging_didcomm::{Message, UnpackMetadata};
use async_trait::async_trait;

use crate::error::DIDCommServiceError;
use crate::handler::HandlerContext;

#[async_trait]
pub trait MessageHandler: Send + Sync + 'static {
    async fn handle(
        &self,
        ctx: HandlerContext,
        message: Message,
        meta: UnpackMetadata,
    ) -> Result<Option<Message>, DIDCommServiceError>;
}

type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;

type HandlerFnType = dyn Fn(
        HandlerContext,
        Message,
        UnpackMetadata,
    ) -> BoxFuture<Result<Option<Message>, DIDCommServiceError>>
    + Send
    + Sync
    + 'static;

struct FnHandler {
    f: Box<HandlerFnType>,
}

#[async_trait]
impl MessageHandler for FnHandler {
    async fn handle(
        &self,
        ctx: HandlerContext,
        message: Message,
        meta: UnpackMetadata,
    ) -> Result<Option<Message>, DIDCommServiceError> {
        (self.f)(ctx, message, meta).await
    }
}

pub fn handler_fn<F, Fut>(f: F) -> impl MessageHandler
where
    F: Fn(HandlerContext, Message, UnpackMetadata) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<Option<Message>, DIDCommServiceError>> + Send + 'static,
{
    FnHandler {
        f: Box::new(move |ctx, msg, meta| Box::pin(f(ctx, msg, meta))),
    }
}
