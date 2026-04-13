mod context;
pub mod extractor;
mod message_pickup;
mod trust_ping;

pub use context::HandlerContext;
pub use extractor::{Extension, Extensions, FromMessageParts, MessageParts};
pub use message_pickup::MESSAGE_PICKUP_STATUS_TYPE;
pub use trust_ping::{TRUST_PING_TYPE, TRUST_PONG_TYPE, trust_ping_handler};

use affinidi_messaging_didcomm::{Message, UnpackMetadata};
use async_trait::async_trait;

use crate::error::DIDCommServiceError;
use crate::problem_report::ServiceProblemReport;
use crate::response::DIDCommResponse;

/// Top-level handler for incoming DIDComm messages.
///
/// Implement this trait to define how your service processes messages.
/// Return `Ok(Some(response))` to send a reply, `Ok(None)` for no reply,
/// or `Err(_)` to signal a processing failure.
///
/// The return type is `Result` (not plain `Option`) so that raw implementors
/// keep `?` ergonomics and middleware can intercept errors.
/// When used through [`crate::router::Router`], handler errors are caught and forwarded to
/// the configured [`ErrorHandler`], so `Router::handle` always returns `Ok`.
#[async_trait]
pub trait DIDCommHandler: Send + Sync + 'static {
    async fn handle(
        &self,
        ctx: HandlerContext,
        message: Message,
        meta: UnpackMetadata,
    ) -> Result<Option<DIDCommResponse>, DIDCommServiceError>;
}

/// Handler invoked when a route handler returns an error.
///
/// Return `Some(response)` to send a reply (e.g., a problem report) back to the
/// sender. Return `None` to silently drop the error.
///
/// The default implementation logs the error and returns a problem report.
#[async_trait]
pub trait ErrorHandler: Send + Sync + 'static {
    async fn on_error(
        &self,
        ctx: &HandlerContext,
        error: &DIDCommServiceError,
    ) -> Option<DIDCommResponse>;
}

pub struct DefaultErrorHandler;

#[async_trait]
impl ErrorHandler for DefaultErrorHandler {
    async fn on_error(
        &self,
        ctx: &HandlerContext,
        error: &DIDCommServiceError,
    ) -> Option<DIDCommResponse> {
        tracing::warn!(
            profile = %ctx.profile.inner.alias,
            message_id = %ctx.message_id,
            thread_id = %ctx.thread_id,
            sender = ?ctx.sender_did,
            error = %error,
            "Error handling message"
        );

        Some(DIDCommResponse::problem_report(
            crate::problem_report::ProblemReport::internal_error(error.to_string()),
        ))
    }
}

/// No-op handler that silently drops the message.
/// Use with any message type that should be acknowledged but not processed.
pub async fn ignore_handler(
    _ctx: HandlerContext,
    _message: Message,
) -> Result<Option<DIDCommResponse>, DIDCommServiceError> {
    Ok(None)
}
