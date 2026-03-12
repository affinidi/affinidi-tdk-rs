mod handler;
mod route;

use std::sync::Arc;

use affinidi_messaging_didcomm::{Message, UnpackMetadata};
use async_trait::async_trait;

use crate::error::DIDCommServiceError;
use crate::handler::extractor::Extensions;
use crate::handler::{DIDCommHandler, HandlerContext};
use crate::middleware::{MiddlewareHandler, Next};
use crate::response::DIDCommResponse;

pub use handler::{MessageHandler, handler_fn};
use route::Route;

pub struct Router {
    routes: Vec<Route>,
    fallback: Option<Arc<dyn MessageHandler>>,
    middleware: Vec<Arc<dyn MiddlewareHandler>>,
    extensions: Extensions,
}

impl Router {
    pub fn new() -> Self {
        Self {
            routes: Vec::new(),
            fallback: None,
            middleware: Vec::new(),
            extensions: Extensions::default(),
        }
    }

    pub fn route(mut self, pattern: &str, handler: impl MessageHandler) -> Self {
        self.routes.push(Route::new(pattern, Arc::new(handler)));
        self
    }

    pub fn route_regex(mut self, pattern: &str, handler: impl MessageHandler) -> Self {
        self.routes.push(Route::regex(pattern, Arc::new(handler)));
        self
    }

    pub fn fallback(mut self, handler: impl MessageHandler) -> Self {
        self.fallback = Some(Arc::new(handler));
        self
    }

    pub fn layer(mut self, middleware: impl MiddlewareHandler) -> Self {
        self.middleware.push(Arc::new(middleware));
        self
    }

    pub fn extension<T: Clone + Send + Sync + 'static>(mut self, val: T) -> Self {
        self.extensions.insert(val);
        self
    }

    fn find_handler(&self, message_type: &str) -> Option<&Arc<dyn MessageHandler>> {
        self.routes
            .iter()
            .find(|r| r.matches(message_type))
            .map(|r| &r.handler)
            .or(self.fallback.as_ref())
    }
}

impl Default for Router {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl DIDCommHandler for Router {
    async fn handle(
        &self,
        ctx: HandlerContext,
        message: Message,
        meta: UnpackMetadata,
    ) -> Result<Option<DIDCommResponse>, DIDCommServiceError> {
        let message_type = &message.type_;

        if let Some(handler) = self.find_handler(message_type) {
            let handler = handler.clone();
            let middleware: Arc<[Arc<dyn MiddlewareHandler>]> = self.middleware.clone().into();
            let next = Next::new(handler, middleware, self.extensions.clone());
            next.run(ctx, message, meta).await
        } else {
            tracing::debug!("No handler for message type: {}", message_type);
            Ok(None)
        }
    }
}
