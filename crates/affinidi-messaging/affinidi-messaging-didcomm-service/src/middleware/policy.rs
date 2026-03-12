use affinidi_messaging_didcomm::{Message, UnpackMetadata};
use async_trait::async_trait;

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

    pub(crate) fn check(
        &self,
        message: &Message,
        meta: &UnpackMetadata,
    ) -> Result<(), PolicyViolation> {
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
            tracing::debug!(
                "[policy] Rejected message {} from {}: {}",
                message.id,
                ctx.sender_did,
                violation
            );
            return Err(violation.into());
        }
        next.run(ctx, message, meta).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn msg_with_from(from: Option<&str>) -> Message {
        let mut b = Message::build("id".into(), "test".into(), json!({}));
        if let Some(f) = from {
            b = b.from(f.into());
        }
        b.finalize()
    }

    fn meta(
        encrypted: bool,
        authenticated: bool,
        non_repudiation: bool,
        anonymous_sender: bool,
    ) -> UnpackMetadata {
        UnpackMetadata {
            encrypted,
            authenticated,
            non_repudiation,
            anonymous_sender,
            ..Default::default()
        }
    }

    #[test]
    fn default_policy_allows_everything() {
        let policy = MessagePolicy::new();
        let m = msg_with_from(None);
        let mt = UnpackMetadata::default();
        assert!(policy.check(&m, &mt).is_ok());
    }

    #[test]
    fn require_encrypted_rejects_plaintext() {
        let policy = MessagePolicy::new().require_encrypted(true);
        let result = policy.check(&msg_with_from(None), &meta(false, false, false, false));
        assert!(matches!(result, Err(PolicyViolation::NotEncrypted)));
    }

    #[test]
    fn require_encrypted_accepts_encrypted() {
        let policy = MessagePolicy::new().require_encrypted(true);
        assert!(
            policy
                .check(&msg_with_from(None), &meta(true, false, false, false))
                .is_ok()
        );
    }

    #[test]
    fn require_authenticated_rejects_unauthenticated() {
        let policy = MessagePolicy::new().require_authenticated(true);
        let result = policy.check(&msg_with_from(None), &meta(false, false, false, false));
        assert!(matches!(result, Err(PolicyViolation::NotAuthenticated)));
    }

    #[test]
    fn require_authenticated_accepts_authenticated() {
        let policy = MessagePolicy::new().require_authenticated(true);
        assert!(
            policy
                .check(&msg_with_from(None), &meta(false, true, false, false))
                .is_ok()
        );
    }

    #[test]
    fn require_non_repudiation_rejects_unsigned() {
        let policy = MessagePolicy::new().require_non_repudiation(true);
        let result = policy.check(&msg_with_from(None), &meta(false, false, false, false));
        assert!(matches!(result, Err(PolicyViolation::NoNonRepudiation)));
    }

    #[test]
    fn require_non_repudiation_accepts_signed() {
        let policy = MessagePolicy::new().require_non_repudiation(true);
        assert!(
            policy
                .check(&msg_with_from(None), &meta(false, false, true, false))
                .is_ok()
        );
    }

    #[test]
    fn disallow_anonymous_rejects_anonymous() {
        let policy = MessagePolicy::new().allow_anonymous_sender(false);
        let result = policy.check(&msg_with_from(None), &meta(false, false, false, true));
        assert!(matches!(result, Err(PolicyViolation::AnonymousSender)));
    }

    #[test]
    fn disallow_anonymous_accepts_non_anonymous() {
        let policy = MessagePolicy::new().allow_anonymous_sender(false);
        assert!(
            policy
                .check(&msg_with_from(None), &meta(false, false, false, false))
                .is_ok()
        );
    }

    #[test]
    fn require_sender_did_rejects_missing_from() {
        let policy = MessagePolicy::new().require_sender_did(true);
        let result = policy.check(&msg_with_from(None), &UnpackMetadata::default());
        assert!(matches!(result, Err(PolicyViolation::MissingSenderDid)));
    }

    #[test]
    fn require_sender_did_accepts_present_from() {
        let policy = MessagePolicy::new().require_sender_did(true);
        assert!(
            policy
                .check(
                    &msg_with_from(Some("did:example:sender")),
                    &UnpackMetadata::default()
                )
                .is_ok()
        );
    }

    #[test]
    fn combined_policies_first_violation_wins() {
        let policy = MessagePolicy::new()
            .require_encrypted(true)
            .require_authenticated(true);
        let result = policy.check(&msg_with_from(None), &meta(false, false, false, false));
        assert!(matches!(result, Err(PolicyViolation::NotEncrypted)));
    }
}
