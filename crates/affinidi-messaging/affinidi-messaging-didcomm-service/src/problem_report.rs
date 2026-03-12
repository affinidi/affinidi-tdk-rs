pub use affinidi_messaging_sdk::messages::problem_report::{
    ProblemReport, ProblemReportScope, ProblemReportSorter,
};

/// DIDComm error codes for server-side problem reports.
pub mod codes {
    pub const ERROR_UNAUTHORIZED: &str = "e.p.msg.unauthorized";
    pub const ERROR_BAD_REQUEST: &str = "e.p.msg.bad-request";
    pub const ERROR_NOT_FOUND: &str = "e.p.msg.not-found";
    pub const ERROR_CONFLICT: &str = "e.p.msg.conflict";
    pub const ERROR_INTERNAL: &str = "e.p.msg.internal-error";
}

/// Convenience constructors and builders for server-side DIDComm problem reports.
/// Consumers can define their own trait on `ProblemReport` for domain-specific constructors.
pub trait ServiceProblemReport {
    fn unauthorized(comment: impl Into<String>) -> Self;
    fn bad_request(comment: impl Into<String>) -> Self;
    fn not_found(comment: impl Into<String>) -> Self;
    fn conflict(comment: impl Into<String>) -> Self;
    fn internal_error(comment: impl Into<String>) -> Self;
    fn with_args(self, args: Vec<String>) -> Self;
    fn with_escalate_to(self, escalate_to: String) -> Self;
    fn to_body(&self) -> serde_json::Value;
}

impl ServiceProblemReport for ProblemReport {
    fn unauthorized(comment: impl Into<String>) -> Self {
        Self::from_code(codes::ERROR_UNAUTHORIZED, comment)
    }

    fn bad_request(comment: impl Into<String>) -> Self {
        Self::from_code(codes::ERROR_BAD_REQUEST, comment)
    }

    fn not_found(comment: impl Into<String>) -> Self {
        Self::from_code(codes::ERROR_NOT_FOUND, comment)
    }

    fn conflict(comment: impl Into<String>) -> Self {
        Self::from_code(codes::ERROR_CONFLICT, comment)
    }

    fn internal_error(comment: impl Into<String>) -> Self {
        Self::from_code(codes::ERROR_INTERNAL, comment)
    }

    fn with_args(mut self, args: Vec<String>) -> Self {
        self.args = args;
        self
    }

    fn with_escalate_to(mut self, escalate_to: String) -> Self {
        self.escalate_to = Some(escalate_to);
        self
    }

    fn to_body(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or_default()
    }
}

trait FromCode {
    fn from_code(code: &str, comment: impl Into<String>) -> Self;
}

impl FromCode for ProblemReport {
    fn from_code(code: &str, comment: impl Into<String>) -> Self {
        Self {
            code: code.to_string(),
            comment: comment.into(),
            args: Vec::new(),
            escalate_to: None,
        }
    }
}
