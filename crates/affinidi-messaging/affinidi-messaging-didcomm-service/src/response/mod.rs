use affinidi_messaging_didcomm::Message;
use serde_json::Value;

use crate::handler::HandlerContext;
use crate::problem_report::{ProblemReport, ServiceProblemReport};
use crate::transport::PROBLEM_REPORT_TYPE;
use crate::utils::new_message_id;

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

    pub fn to(mut self, did: impl Into<String>) -> Self {
        self.to.push(did.into());
        self
    }

    pub fn to_many(mut self, dids: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.to.extend(dids.into_iter().map(Into::into));
        self
    }

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

    pub(crate) fn into_message(self, ctx: &HandlerContext) -> Message {
        let from = self.from.unwrap_or_else(|| ctx.profile.inner.did.clone());

        let to = if self.to.is_empty() {
            vec![ctx.sender_did.clone()]
        } else {
            self.to
        };

        let thid = self
            .thid
            .or_else(|| ctx.thread_id.clone())
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

        builder.finalize()
    }
}

#[cfg(test)]
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
}
