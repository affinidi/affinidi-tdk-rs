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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unauthorized_sets_correct_code() {
        let r = ProblemReport::unauthorized("denied");
        assert_eq!(r.code, codes::ERROR_UNAUTHORIZED);
        assert_eq!(r.comment, "denied");
    }

    #[test]
    fn bad_request_sets_correct_code() {
        let r = ProblemReport::bad_request("invalid");
        assert_eq!(r.code, codes::ERROR_BAD_REQUEST);
        assert_eq!(r.comment, "invalid");
    }

    #[test]
    fn not_found_sets_correct_code() {
        let r = ProblemReport::not_found("missing");
        assert_eq!(r.code, codes::ERROR_NOT_FOUND);
        assert_eq!(r.comment, "missing");
    }

    #[test]
    fn conflict_sets_correct_code() {
        let r = ProblemReport::conflict("duplicate");
        assert_eq!(r.code, codes::ERROR_CONFLICT);
        assert_eq!(r.comment, "duplicate");
    }

    #[test]
    fn internal_error_sets_correct_code() {
        let r = ProblemReport::internal_error("oops");
        assert_eq!(r.code, codes::ERROR_INTERNAL);
        assert_eq!(r.comment, "oops");
    }

    #[test]
    fn with_args_sets_args() {
        let r = ProblemReport::bad_request("err").with_args(vec!["a".into(), "b".into()]);
        assert_eq!(r.args, vec!["a", "b"]);
    }

    #[test]
    fn with_escalate_to_sets_field() {
        let r = ProblemReport::bad_request("err").with_escalate_to("admin@example.com".into());
        assert_eq!(r.escalate_to, Some("admin@example.com".into()));
    }

    #[test]
    fn to_body_produces_valid_json() {
        let r = ProblemReport::unauthorized("nope");
        let body = r.to_body();
        assert_eq!(body["code"], codes::ERROR_UNAUTHORIZED);
        assert_eq!(body["comment"], "nope");
    }

    #[test]
    fn to_body_includes_args_when_present() {
        let r = ProblemReport::bad_request("err").with_args(vec!["x".into()]);
        let body = r.to_body();
        assert_eq!(body["args"], serde_json::json!(["x"]));
    }

    #[test]
    fn to_body_includes_escalate_to_when_present() {
        let r = ProblemReport::bad_request("err").with_escalate_to("support@example.com".into());
        let body = r.to_body();
        assert_eq!(body["escalate_to"], "support@example.com");
    }

    #[test]
    fn default_has_no_args_or_escalate() {
        let r = ProblemReport::internal_error("fail");
        assert!(r.args.is_empty());
        assert!(r.escalate_to.is_none());
    }
}
