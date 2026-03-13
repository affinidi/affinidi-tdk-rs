use std::time::Instant;

use affinidi_messaging_didcomm::{Message, UnpackMetadata};
use async_trait::async_trait;

use super::{MiddlewareHandler, MiddlewareResult, Next};
use crate::handler::HandlerContext;

pub struct RequestLogging;

#[async_trait]
impl MiddlewareHandler for RequestLogging {
    async fn handle(
        &self,
        ctx: HandlerContext,
        message: Message,
        meta: UnpackMetadata,
        next: Next,
    ) -> MiddlewareResult {
        let start = Instant::now();
        let message_type = message.type_.clone();
        let sender = ctx.sender_did.as_deref().unwrap_or("<anon>").to_string();
        let profile = ctx.profile.inner.alias.clone();

        let result = next.run(ctx, message, meta).await;

        let latency = start.elapsed();
        let status = match &result {
            Ok(Some(_)) => "ok(response)",
            Ok(None) => "ok(empty)",
            Err(_) => "error",
        };

        tracing::info!(
            target: "didcomm_server::request",
            "[profile = {}] {} from={} status={} latency={:?}",
            profile,
            message_type,
            sender,
            status,
            latency,
        );

        result
    }
}
