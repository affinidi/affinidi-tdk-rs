use affinidi_messaging_didcomm::Message;
use serde_json::Value;

use crate::handler::HandlerContext;
use crate::problem_report::{ProblemReport, ServiceProblemReport};
use crate::transport::PROBLEM_REPORT_TYPE;
use crate::utils::new_message_id;

/// A response to be sent back to the message sender.
///
/// A response always goes to the authenticated sender of the message being
/// answered, encrypted from the listener's profile DID. Its headers say so:
///
/// - **`from`** — the listener's profile DID
/// - **`to`** — the incoming message's authenticated sender DID
/// - **`thid`** — the incoming message's thread ID, unless set with
///   [`thid`](Self::thid)
/// - **`pthid`** — the incoming message's parent thread ID (if any), unless set
///   with [`pthid`](Self::pthid)
///
/// To send to anyone else, or from another DID, use
/// [`AffinidiMessageService::send_message`](crate::AffinidiMessageService::send_message).
/// The [`to`](Self::to), [`to_many`](Self::to_many) and [`from`](Self::from)
/// setters are deprecated: they only ever changed the headers, never who the
/// reply was encrypted for or routed to, so a receiver checking addressing
/// rejected the reply. Since 0.35 their values are ignored (and logged at
/// warn when they differ from the real addressing).
///
/// This means a minimal response only needs a type and body:
/// ```ignore
/// Ok(Some(DIDCommResponse::new("https://example.com/ack", json!({}))))
/// ```
#[derive(Debug)]
pub struct DIDCommResponse {
    pub(crate) type_: String,
    pub(crate) body: Value,
    pub(crate) to: Vec<String>,
    pub(crate) from: Option<String>,
    pub(crate) thid: Option<String>,
    pub(crate) pthid: Option<String>,
}

impl DIDCommResponse {
    pub fn new(type_: impl Into<String>, body: Value) -> Self {
        Self {
            type_: type_.into(),
            body,
            to: Vec::new(),
            from: None,
            thid: None,
            pthid: None,
        }
    }

    pub fn problem_report(report: ProblemReport) -> Self {
        Self::new(PROBLEM_REPORT_TYPE, report.to_body())
    }

    #[deprecated(
        since = "0.35.0",
        note = "a response always goes to the message's sender; use \
                AffinidiMessageService::send_message to reach anyone else"
    )]
    pub fn to(mut self, did: impl Into<String>) -> Self {
        self.to.push(did.into());
        self
    }

    #[deprecated(
        since = "0.35.0",
        note = "a response always goes to the message's sender; use \
                AffinidiMessageService::send_message to reach anyone else"
    )]
    pub fn to_many(mut self, dids: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.to.extend(dids.into_iter().map(Into::into));
        self
    }

    #[deprecated(
        since = "0.35.0",
        note = "a response is always sent from the listener's profile DID"
    )]
    pub fn from(mut self, did: impl Into<String>) -> Self {
        self.from = Some(did.into());
        self
    }

    pub fn thid(mut self, thid: impl Into<String>) -> Self {
        self.thid = Some(thid.into());
        self
    }

    pub fn pthid(mut self, pthid: impl Into<String>) -> Self {
        self.pthid = Some(pthid.into());
        self
    }

    pub(crate) fn into_message(
        self,
        ctx: &HandlerContext,
    ) -> Result<Message, crate::error::DIDCommServiceError> {
        // The reply is packed from the profile DID and routed to the sender
        // (`transport::send_response`), so the headers say exactly that.
        let from = ctx.profile.inner.did.clone();
        let sender = ctx
            .sender_did
            .as_deref()
            .ok_or(crate::error::TransportError::MissingSenderDid)?;
        if self.from.as_deref().is_some_and(|f| f != from) || self.to.iter().any(|t| t != sender) {
            tracing::warn!(
                requested_from = ?self.from,
                requested_to = ?self.to,
                sender = %sender,
                "DIDCommResponse to/to_many/from are ignored: a response goes to the \
                 message's sender, from the listener's DID"
            );
        }
        let to = vec![sender.to_string()];

        let thid = self
            .thid
            .or_else(|| Some(ctx.thread_id.clone()))
            .unwrap_or_else(new_message_id);

        let mut builder = Message::build(new_message_id(), self.type_, self.body)
            .from(from)
            .thid(thid);

        for recipient in &to {
            builder = builder.to(recipient.clone());
        }

        if let Some(pthid) = self.pthid.or_else(|| ctx.parent_thread_id.clone()) {
            builder = builder.pthid(pthid);
        }

        Ok(builder.finalize())
    }
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn new_sets_type_and_body() {
        let resp = DIDCommResponse::new("test/type", json!({"key": "val"}));
        assert_eq!(resp.type_, "test/type");
        assert_eq!(resp.body, json!({"key": "val"}));
        assert!(resp.to.is_empty());
        assert!(resp.from.is_none());
        assert!(resp.thid.is_none());
        assert!(resp.pthid.is_none());
    }

    #[test]
    fn to_adds_recipient() {
        let resp = DIDCommResponse::new("t", json!({})).to("did:example:alice");
        assert_eq!(resp.to, vec!["did:example:alice"]);
    }

    #[test]
    fn to_many_adds_multiple() {
        let resp = DIDCommResponse::new("t", json!({})).to_many(vec!["did:a", "did:b"]);
        assert_eq!(resp.to, vec!["did:a", "did:b"]);
    }

    #[test]
    fn to_chains_append() {
        let resp = DIDCommResponse::new("t", json!({})).to("did:a").to("did:b");
        assert_eq!(resp.to, vec!["did:a", "did:b"]);
    }

    #[test]
    fn from_sets_sender() {
        let resp = DIDCommResponse::new("t", json!({})).from("did:example:bob");
        assert_eq!(resp.from, Some("did:example:bob".into()));
    }

    #[test]
    fn thid_sets_thread_id() {
        let resp = DIDCommResponse::new("t", json!({})).thid("thread-1");
        assert_eq!(resp.thid, Some("thread-1".into()));
    }

    #[test]
    fn pthid_sets_parent_thread_id() {
        let resp = DIDCommResponse::new("t", json!({})).pthid("parent-1");
        assert_eq!(resp.pthid, Some("parent-1".into()));
    }

    #[test]
    fn problem_report_uses_problem_report_type() {
        let report = ProblemReport::unauthorized("nope");
        let resp = DIDCommResponse::problem_report(report);
        assert_eq!(resp.type_, PROBLEM_REPORT_TYPE);
    }

    #[test]
    fn builder_chain() {
        let resp = DIDCommResponse::new("t", json!({}))
            .to("did:a")
            .from("did:b")
            .thid("t1")
            .pthid("p1");
        assert_eq!(resp.to, vec!["did:a"]);
        assert_eq!(resp.from, Some("did:b".into()));
        assert_eq!(resp.thid, Some("t1".into()));
        assert_eq!(resp.pthid, Some("p1".into()));
    }

    /// #1033: the deprecated setters no longer put an address in the headers
    /// that the reply is not actually encrypted for or sent from.
    #[tokio::test]
    async fn headers_always_name_the_sender_and_the_profile() {
        let mut ctx = crate::handler::test_context().await;
        ctx.sender_did = Some("did:example:alice".into());
        ctx.thread_id = "req-1".into();
        let msg = DIDCommResponse::new("t", json!({}))
            .to("did:example:carol")
            .from("did:example:mallory")
            .into_message(&ctx)
            .unwrap();
        assert_eq!(msg.to, Some(vec!["did:example:alice".to_string()]));
        assert_eq!(msg.from.as_deref(), Some("did:example:service"));
        assert_eq!(msg.thid.as_deref(), Some("req-1"));
    }
}
