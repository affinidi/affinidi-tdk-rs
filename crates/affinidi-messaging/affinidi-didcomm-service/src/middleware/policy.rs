use affinidi_messaging_didcomm::{Message, UnpackMetadata};
use async_trait::async_trait;
use tracing::warn;

use super::{MiddlewareHandler, MiddlewareResult, Next};
use crate::error::PolicyViolation;
use crate::handler::HandlerContext;

#[derive(Clone)]
pub struct MessagePolicy {
    require_encrypted: bool,
    require_authenticated: bool,
    require_non_repudiation: bool,
    allow_anonymous_sender: bool,
    require_sender_did: bool,
}

impl MessagePolicy {
    pub fn new() -> Self {
        Self {
            require_encrypted: false,
            require_authenticated: false,
            require_non_repudiation: false,
            allow_anonymous_sender: true,
            require_sender_did: false,
        }
    }

    pub fn require_encrypted(mut self, val: bool) -> Self {
        self.require_encrypted = val;
        self
    }

    pub fn require_authenticated(mut self, val: bool) -> Self {
        self.require_authenticated = val;
        self
    }

    pub fn require_non_repudiation(mut self, val: bool) -> Self {
        self.require_non_repudiation = val;
        self
    }

    pub fn allow_anonymous_sender(mut self, val: bool) -> Self {
        self.allow_anonymous_sender = val;
        self
    }

    pub fn require_sender_did(mut self, val: bool) -> Self {
        self.require_sender_did = val;
        self
    }

    fn check(&self, message: &Message, meta: &UnpackMetadata) -> Result<(), PolicyViolation> {
        if self.require_encrypted && !meta.encrypted {
            return Err(PolicyViolation::NotEncrypted);
        }
        if self.require_authenticated && !meta.authenticated {
            return Err(PolicyViolation::NotAuthenticated);
        }
        if self.require_non_repudiation && !meta.non_repudiation {
            return Err(PolicyViolation::NoNonRepudiation);
        }
        if !self.allow_anonymous_sender && meta.anonymous_sender {
            return Err(PolicyViolation::AnonymousSender);
        }
        if self.require_sender_did && message.from.is_none() {
            return Err(PolicyViolation::MissingSenderDid);
        }
        Ok(())
    }
}

impl Default for MessagePolicy {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl MiddlewareHandler for MessagePolicy {
    async fn handle(
        &self,
        ctx: HandlerContext,
        message: Message,
        meta: UnpackMetadata,
        next: Next,
    ) -> MiddlewareResult {
        if let Err(violation) = self.check(&message, &meta) {
            // TODO: allow to silence this or change level
            warn!(
                "[policy] Rejected message {} from {}: {}",
                message.id, ctx.sender_did, violation
            );
            return Err(violation.into());
        }
        next.run(ctx, message, meta).await
    }
}
