use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use affinidi_messaging_didcomm::{Message, UnpackMetadata};
use async_trait::async_trait;

use crate::error::DIDCommServiceError;
use crate::handler::HandlerContext;
use crate::handler::extractor::Extensions;
use crate::response::DIDCommResponse;
use crate::router::MessageHandler;

mod policy;
mod request_logging;

pub use policy::MessagePolicy;
pub use request_logging::RequestLogging;

type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;
type MiddlewareResult = Result<Option<DIDCommResponse>, DIDCommServiceError>;

pub struct Next {
    handler: Arc<dyn MessageHandler>,
    middleware: Arc<[Arc<dyn MiddlewareHandler>]>,
    extensions: Extensions,
    index: usize,
}

impl Next {
    pub(crate) fn new(
        handler: Arc<dyn MessageHandler>,
        middleware: Arc<[Arc<dyn MiddlewareHandler>]>,
        extensions: Extensions,
    ) -> Self {
        Self {
            handler,
            middleware,
            extensions,
            index: 0,
        }
    }

    pub async fn run(
        self,
        ctx: HandlerContext,
        message: Message,
        meta: UnpackMetadata,
    ) -> MiddlewareResult {
        if self.index < self.middleware.len() {
            let current = self.middleware[self.index].clone();
            let next = Next {
                handler: self.handler,
                middleware: self.middleware,
                extensions: self.extensions,
                index: self.index + 1,
            };
            current.handle(ctx, message, meta, next).await
        } else {
            self.handler
                .handle(ctx, message, meta, self.extensions)
                .await
        }
    }
}

/// Middleware that intercepts messages before they reach the route handler.
///
/// Call `next.run(ctx, message, meta)` to pass control to the next middleware
/// or the final handler. Return early to short-circuit the chain.
#[async_trait]
pub trait MiddlewareHandler: Send + Sync + 'static {
    async fn handle(
        &self,
        ctx: HandlerContext,
        message: Message,
        meta: UnpackMetadata,
        next: Next,
    ) -> MiddlewareResult;
}

type MiddlewareFnType = dyn Fn(HandlerContext, Message, UnpackMetadata, Next) -> BoxFuture<MiddlewareResult>
    + Send
    + Sync
    + 'static;

struct FnMiddleware {
    f: Box<MiddlewareFnType>,
}

#[async_trait]
impl MiddlewareHandler for FnMiddleware {
    async fn handle(
        &self,
        ctx: HandlerContext,
        message: Message,
        meta: UnpackMetadata,
        next: Next,
    ) -> MiddlewareResult {
        (self.f)(ctx, message, meta, next).await
    }
}

pub fn middleware_fn<F, Fut>(f: F) -> impl MiddlewareHandler
where
    F: Fn(HandlerContext, Message, UnpackMetadata, Next) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = MiddlewareResult> + Send + 'static,
{
    FnMiddleware {
        f: Box::new(move |ctx, msg, meta, next| Box::pin(f(ctx, msg, meta, next))),
    }
}
