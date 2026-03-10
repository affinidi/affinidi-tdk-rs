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
            builder = builder.header("pthid".into(), Value::String(pthid));
        }

        builder.finalize()
    }
}
