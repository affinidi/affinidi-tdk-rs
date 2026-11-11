mod handler;
mod route;

use std::sync::Arc;

use affinidi_messaging_didcomm::{Message, UnpackMetadata};
use async_trait::async_trait;

use crate::error::DIDCommServiceError;
use crate::handler::extractor::Extensions;
use crate::handler::{
    DIDCommHandler, DefaultErrorHandler, ErrorHandler, HandlerContext, MESSAGE_PICKUP_STATUS_TYPE,
};
use crate::middleware::{MiddlewareHandler, Next};
use crate::problem_report::{ProblemReport, ServiceProblemReport};
use crate::response::DIDCommResponse;
use crate::transport::is_problem_report_type;

pub use handler::{MessageHandler, handler_fn};
use route::Route;

/// Comment in the problem report sent for a message type with no route.
pub const UNSUPPORTED_TYPE_COMMENT: &str = "Unsupported message type";

/// Message router that dispatches incoming DIDComm messages to handlers based on message type.
///
/// Routes are matched in order — the first matching route wins. If no route matches,
/// the optional fallback handler is invoked. Middleware layers are applied to every
/// matched route in the order they were added.
///
/// With no matching route and no fallback, the sender gets a `bad-request`
/// problem report, except for a problem report or a message pickup `status`,
/// which get no reply.
pub struct Router {
    routes: Vec<Route>,
    fallback: Option<Arc<dyn MessageHandler>>,
    middleware: Vec<Arc<dyn MiddlewareHandler>>,
    extensions: Extensions,
    error_handler: Arc<dyn ErrorHandler>,
}

impl Router {
    pub fn new() -> Self {
        Self {
            routes: Vec::new(),
            fallback: None,
            middleware: Vec::new(),
            extensions: Extensions::default(),
            error_handler: Arc::new(DefaultErrorHandler),
        }
    }

    /// Add an exact-match route for a message type. Returns an error if the pattern is invalid.
    pub fn route(
        mut self,
        pattern: &str,
        handler: impl MessageHandler,
    ) -> Result<Self, DIDCommServiceError> {
        self.routes.push(Route::new(pattern, Arc::new(handler))?);
        Ok(self)
    }

    /// Add a regex-match route for a message type. Returns an error if the pattern is invalid.
    pub fn route_regex(
        mut self,
        pattern: &str,
        handler: impl MessageHandler,
    ) -> Result<Self, DIDCommServiceError> {
        self.routes.push(Route::regex(pattern, Arc::new(handler))?);
        Ok(self)
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

    pub fn on_error(mut self, handler: impl ErrorHandler) -> Self {
        self.error_handler = Arc::new(handler);
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
        let message_type = &message.typ;

        if let Some(handler) = self.find_handler(message_type) {
            let handler = handler.clone();
            let middleware: Arc<[Arc<dyn MiddlewareHandler>]> = self.middleware.clone().into();
            let next = Next::new(handler, middleware, self.extensions.clone());
            match next.run(ctx.clone(), message, meta).await {
                Ok(response) => Ok(response),
                Err(e) => {
                    let response = self.error_handler.on_error(&ctx, &e).await;
                    Ok(response)
                }
            }
        } else if is_problem_report_type(message_type) || message_type == MESSAGE_PICKUP_STATUS_TYPE
        {
            tracing::debug!(message_type = %message_type, "No handler found; not answered");
            Ok(None)
        } else {
            tracing::debug!(message_type = %message_type, "No handler found");
            Ok(Some(DIDCommResponse::problem_report(
                ProblemReport::bad_request(UNSUPPORTED_TYPE_COMMENT),
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handler::test_context;
    use crate::problem_report::codes;
    use crate::transport::PROBLEM_REPORT_TYPE;
    use serde_json::json;

    fn message(message_type: &str) -> Message {
        Message::build("msg-1", message_type, json!({}))
            .from("did:example:peer".into())
            .to("did:example:service".into())
            .finalize()
    }

    async fn reply_to(router: &Router, message_type: &str) -> Option<DIDCommResponse> {
        router
            .handle(
                test_context().await,
                message(message_type),
                UnpackMetadata::default(),
            )
            .await
            .expect("the router answers Ok")
    }

    #[tokio::test]
    async fn an_unrouted_problem_report_gets_no_reply() {
        let router = Router::new();
        assert!(reply_to(&router, PROBLEM_REPORT_TYPE).await.is_none());
        assert!(
            reply_to(
                &router,
                "https://didcomm.org/report-problem/1.0/problem-report"
            )
            .await
            .is_none()
        );
    }

    #[tokio::test]
    async fn an_unrouted_pickup_status_gets_no_reply() {
        assert!(
            reply_to(&Router::new(), MESSAGE_PICKUP_STATUS_TYPE)
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn an_unrouted_type_gets_a_bad_request_without_the_type_in_it() {
        let message_type = "https://example.com/unknown/1.0/thing";
        let response = reply_to(&Router::new(), message_type)
            .await
            .expect("a problem report");
        assert_eq!(response.type_, PROBLEM_REPORT_TYPE);
        assert_eq!(response.body["code"], codes::ERROR_BAD_REQUEST);
        assert_eq!(response.body["comment"], UNSUPPORTED_TYPE_COMMENT);
        assert!(!response.body.to_string().contains(message_type));
    }

    #[tokio::test]
    async fn a_handler_error_is_reported_without_its_text() {
        async fn failing(
            _ctx: HandlerContext,
            _message: Message,
        ) -> Result<Option<DIDCommResponse>, DIDCommServiceError> {
            Err(DIDCommServiceError::Handler(
                "backend at /var/lib/store refused".into(),
            ))
        }
        let router = Router::new()
            .route("https://example.com/fails", handler_fn(failing))
            .unwrap();
        let response = reply_to(&router, "https://example.com/fails")
            .await
            .expect("a problem report");
        assert_eq!(response.body["code"], codes::ERROR_INTERNAL);
        assert_eq!(
            response.body["comment"],
            crate::handler::INTERNAL_ERROR_COMMENT
        );
        assert!(!response.body.to_string().contains("/var/lib/store"));
    }
}
