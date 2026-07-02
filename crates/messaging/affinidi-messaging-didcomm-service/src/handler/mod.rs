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

/// A reply a [`TspHandler`] asks the service to send back to the sender.
///
/// The service seals `payload` to the message's authenticated `sender_vid` and
/// routes it back over the same shared mediator websocket (see
/// [`AffinidiMessageService::dispatch_tsp`](crate::AffinidiMessageService) for
/// the routing rule). This is the TSP analogue of [`DIDCommResponse`]: the
/// handler decides *what* to say, the service handles *how* it gets there.
///
/// Correlation (matching a reply to its request) is the application's concern —
/// a TSP frame carries no thread id, so embed any request/response id in
/// `payload` (e.g. a Trust Task `#response` document's `threadId`).
#[derive(Debug, Clone)]
pub struct TspResponse {
    /// Cleartext reply bytes. Sealed + routed to the sender by the service.
    pub payload: Vec<u8>,
}

impl TspResponse {
    /// Construct a reply from raw cleartext bytes.
    #[must_use]
    pub fn new(payload: impl Into<Vec<u8>>) -> Self {
        Self {
            payload: payload.into(),
        }
    }
}

/// Top-level handler for incoming **TSP** messages.
///
/// The message service unpacks the TSP frame off the shared websocket and
/// invokes this with the cleartext `payload` and the cryptographically
/// authenticated `sender_vid` (a DID).
///
/// Symmetric with [`DIDCommHandler`]: a multiplexing service routes DIDComm
/// frames to the `DIDCommHandler` and TSP frames to the `TspHandler`. Return
/// `Ok(Some(response))` to send a reply back to the sender — the service seals
/// and routes it over the same shared socket, so consumers never touch the
/// outbound TSP plumbing — `Ok(None)` for one-way (fire-and-forget) receipt, or
/// `Err(_)` to signal a processing failure (logged, no reply sent).
#[async_trait]
pub trait TspHandler: Send + Sync + 'static {
    async fn handle(
        &self,
        ctx: HandlerContext,
        payload: Vec<u8>,
        sender_vid: String,
    ) -> Result<Option<TspResponse>, DIDCommServiceError>;
}

/// No-op [`TspHandler`] that silently drops TSP messages — the TSP analogue of
/// [`ignore_handler`]. Directly usable as `Arc<dyn TspHandler>`.
pub struct IgnoreTspHandler;

#[async_trait]
impl TspHandler for IgnoreTspHandler {
    async fn handle(
        &self,
        _ctx: HandlerContext,
        _payload: Vec<u8>,
        _sender_vid: String,
    ) -> Result<Option<TspResponse>, DIDCommServiceError> {
        Ok(None)
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tsp_response_new_accepts_bytes_and_vec() {
        assert_eq!(TspResponse::new(b"pong".to_vec()).payload, b"pong");
        assert_eq!(TspResponse::new(&b"pong"[..]).payload, b"pong");
        assert_eq!(TspResponse::new(vec![1u8, 2, 3]).payload, vec![1, 2, 3]);
    }
}
