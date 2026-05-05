use crate::types::{
    messages::GenericDataStruct,
    problem_report::{ProblemReport, ProblemReportScope, ProblemReportSorter},
};
use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use rand::{RngExt, distr::Alphanumeric};
use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;
use tracing::{Level, event};

/// Session ID is a random string of 12 characters
type SessId = String;

/// Error Code (unique code for each error)
type ErrorCode = u16;

/// Structured context carried alongside an error for logging and client responses.
///
/// Attach this to an [`AppError`] via [`AppError::with_context`] so that
/// `request_id`, `session_id`, and `did_hash` appear automatically in log
/// output. Only `request_id` is serialized to the client in [`ErrorResponse`].
#[derive(Debug, Default, Clone, Serialize)]
pub struct ErrorContext {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub did_hash: Option<String>,
}

/// Wrapper that converts a [`MediatorError`] into an Axum HTTP response.
pub struct AppError {
    error: MediatorError,
    context: ErrorContext,
}

impl AppError {
    /// Attach structured context (request_id, session_id, did_hash) to this error.
    ///
    /// The context fields will be included in log output and — where appropriate —
    /// in the JSON response sent to the client.
    pub fn with_context(mut self, ctx: ErrorContext) -> Self {
        self.context = ctx;
        self
    }
}

impl<E> From<E> for AppError
where
    E: Into<MediatorError>,
{
    fn from(err: E) -> Self {
        Self {
            error: err.into(),
            context: ErrorContext::default(),
        }
    }
}

/// Errors relating to the Mediator Processors. These are largely internal to the Mediator errors
/// They should not be exposed to the user
#[derive(Clone, Error, Debug)]
pub enum ProcessorError {
    /// A general-purpose internal error in a background processor.
    #[error("CommonError: {0}")]
    CommonError(String),
    /// An error that occurred while forwarding a message to a remote mediator.
    #[error("ForwardingError: {0}")]
    ForwardingError(String),
    /// An error during the periodic cleanup of expired messages.
    #[error("MessageExpiryCleanupError: {0}")]
    MessageExpiryCleanupError(String),
}

/// MediatorError the first String is always the session_id
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum MediatorError {
    #[error("Internal error handling failure: {2}")]
    ErrorHandlingError(ErrorCode, SessId, String),
    #[error("{2}")]
    InternalError(ErrorCode, SessId, String),
    #[error("Couldn't parse ({2}). Reason: {3}")]
    ParseError(ErrorCode, SessId, String, String),
    #[error("Permission Error: {2}")]
    PermissionError(ErrorCode, SessId, String),
    #[error("Request is invalid: {2}")]
    RequestDataError(ErrorCode, SessId, String),
    #[error("Service Limit exceeded: {2}")]
    ServiceLimitError(ErrorCode, SessId, String),
    #[error("Unauthorized: {2}")]
    Unauthorized(ErrorCode, SessId, String),
    #[error("DID error: did({2}) Reason: {3}")]
    DIDError(ErrorCode, SessId, String, String),
    #[error("Configuration Error: {2}")]
    ConfigError(ErrorCode, SessId, String),
    #[error("Database Error: {2}")]
    DatabaseError(ErrorCode, SessId, String),
    #[error("Failed to unpack message: {2}")]
    MessageUnpackError(ErrorCode, SessId, String),
    #[error("MessageExpired: expiry({2}) now({3})")]
    MessageExpired(ErrorCode, SessId, String, String),
    #[error("Failed to pack message: {2}")]
    MessagePackError(ErrorCode, SessId, String),
    #[error("Feature not implemented: {2}")]
    NotImplemented(ErrorCode, SessId, String),
    #[error("Authorization Session ({1}) error: {2}")]
    SessionError(ErrorCode, SessId, String),
    #[error("Anonymous message error: {2}")]
    AnonymousMessageError(ErrorCode, SessId, String),
    #[error("Forwarding/Routing message error: {2}")]
    ForwardMessageError(ErrorCode, SessId, String),
    #[error("Authentication error: {1}")]
    AuthenticationError(ErrorCode, String),
    #[error("ACL denied: {1}")]
    ACLDenied(ErrorCode, String),
    #[error("Processor ({1}) error: {2}")]
    ProcessorError(ErrorCode, ProcessorError, String),

    /// This is a catch-all for any error that is using DIDComm Problem Reports
    /// `ErrorCode` - Unique Error code
    /// `SessId` - Session ID
    /// `Option<String>` - MSG ID responding to
    /// `ProblemReport` - DIDComm Problem Report
    /// `u16` - HTTP status code
    /// `String` - Log message
    #[error("Mediator Error: code({3}): {4}")]
    MediatorError(
        ErrorCode,
        SessId,
        Option<String>,
        Box<ProblemReport>,
        u16,
        String,
    ),
}

impl MediatorError {
    /// Creates a `MediatorError::MediatorError` with a DIDComm Problem Report.
    ///
    /// The `comment` is also used as the log message. For cases where the log
    /// message should differ (e.g., when comment has `{1}` placeholders but the
    /// log should have interpolated values), use [`problem_with_log`](Self::problem_with_log).
    #[allow(clippy::too_many_arguments)]
    pub fn problem(
        code: u16,
        session_id: impl Into<String>,
        msg_id: Option<String>,
        sorter: ProblemReportSorter,
        scope: ProblemReportScope,
        descriptor: &str,
        comment: &str,
        args: Vec<String>,
        http_status: StatusCode,
    ) -> Self {
        Self::MediatorError(
            code,
            session_id.into(),
            msg_id,
            Box::new(ProblemReport::new(
                sorter,
                scope,
                descriptor.into(),
                comment.into(),
                args,
                None,
            )),
            http_status.as_u16(),
            comment.to_string(),
        )
    }

    /// Like [`problem`](Self::problem) but with a separate log message.
    ///
    /// Use this when the Problem Report comment has `{1}`, `{2}` placeholders
    /// but the log message should contain the actual interpolated values.
    #[allow(clippy::too_many_arguments)]
    pub fn problem_with_log(
        code: u16,
        session_id: impl Into<String>,
        msg_id: Option<String>,
        sorter: ProblemReportSorter,
        scope: ProblemReportScope,
        descriptor: &str,
        comment: &str,
        args: Vec<String>,
        http_status: StatusCode,
        log_msg: impl Into<String>,
    ) -> Self {
        Self::MediatorError(
            code,
            session_id.into(),
            msg_id,
            Box::new(ProblemReport::new(
                sorter,
                scope,
                descriptor.into(),
                comment.into(),
                args,
                None,
            )),
            http_status.as_u16(),
            log_msg.into(),
        )
    }
}

impl From<MediatorError> for ProcessorError {
    fn from(error: MediatorError) -> Self {
        ProcessorError::CommonError(error.to_string())
    }
}

impl From<ProcessorError> for MediatorError {
    fn from(error: ProcessorError) -> Self {
        MediatorError::ProcessorError(0, error.clone(), error.to_string())
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let ctx = &self.context;

        // Build a context suffix for log lines. Contains whichever of
        // request_id / session_id / did_hash are present.
        let ctx_log: String = {
            let mut parts = Vec::new();
            if let Some(ref rid) = ctx.request_id {
                parts.push(format!("request_id={rid}"));
            }
            if let Some(ref sid) = ctx.session_id {
                parts.push(format!("session_id={sid}"));
            }
            if let Some(ref dh) = ctx.did_hash {
                parts.push(format!("did_hash={dh}"));
            }
            if parts.is_empty() {
                String::new()
            } else {
                format!(" [{}]", parts.join(" "))
            }
        };

        let request_id = ctx.request_id.clone();

        let response = match self.error {
            MediatorError::ErrorHandlingError(error_code, session_id, msg) => {
                event!(
                    Level::WARN,
                    "{}: ErrorHandlingError({}): {}{}",
                    session_id,
                    error_code,
                    msg,
                    ctx_log
                );
                ErrorResponse {
                    http_code: StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
                    session_id,
                    request_id,
                    error_code,
                    error_code_str: "ErrorHandlingError".to_string(),
                    message: "Internal server error".to_string(),
                }
            }
            MediatorError::InternalError(error_code, session_id, msg) => {
                event!(
                    Level::WARN,
                    "{}: InternalError({}): {}{}",
                    session_id,
                    error_code,
                    msg,
                    ctx_log
                );
                ErrorResponse {
                    http_code: StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
                    session_id,
                    request_id,
                    error_code,
                    error_code_str: "InternalError".to_string(),
                    message: "Internal server error".to_string(),
                }
            }
            MediatorError::ParseError(error_code, session_id, what, msg) => {
                event!(
                    Level::WARN,
                    "{}: ParseError({}): couldn't parse ({}). Reason: {}{}",
                    session_id,
                    error_code,
                    what,
                    msg,
                    ctx_log
                );
                ErrorResponse {
                    http_code: StatusCode::BAD_REQUEST.as_u16(),
                    session_id,
                    request_id,
                    error_code,
                    error_code_str: "BadRequest: ParseError".to_string(),
                    message: format!("Couldn't parse ({what})"),
                }
            }
            MediatorError::PermissionError(error_code, session_id, msg) => {
                let response = ErrorResponse {
                    http_code: StatusCode::FORBIDDEN.as_u16(),
                    session_id: session_id.to_string(),
                    request_id,
                    error_code,
                    error_code_str: "Forbidden: PermissionError".to_string(),
                    message: msg.to_string(),
                };
                event!(Level::WARN, "{}{}", response.to_string(), ctx_log);
                response
            }
            MediatorError::RequestDataError(error_code, session_id, msg) => {
                let response = ErrorResponse {
                    http_code: StatusCode::BAD_REQUEST.as_u16(),
                    session_id: session_id.to_string(),
                    request_id,
                    error_code,
                    error_code_str: "BadRequest: RequestDataError".to_string(),
                    message: format!("Bad Request: ({msg})"),
                };
                event!(Level::WARN, "{}{}", response.to_string(), ctx_log);
                response
            }
            MediatorError::ServiceLimitError(error_code, session_id, msg) => {
                let response = ErrorResponse {
                    http_code: StatusCode::BAD_REQUEST.as_u16(),
                    session_id: session_id.to_string(),
                    request_id,
                    error_code,
                    error_code_str: "BadRequest: ServiceLimitError".to_string(),
                    message: msg.to_string(),
                };
                event!(Level::WARN, "{}{}", response.to_string(), ctx_log);
                response
            }
            MediatorError::Unauthorized(error_code, session_id, msg) => {
                let response = ErrorResponse {
                    http_code: StatusCode::UNAUTHORIZED.as_u16(),
                    session_id: session_id.to_string(),
                    request_id,
                    error_code,
                    error_code_str: "Unauthorized".to_string(),
                    message: "Unauthorized access".to_string(),
                };
                event!(
                    Level::WARN,
                    "{}: Unauthorized({}): {}{}",
                    session_id,
                    error_code,
                    msg,
                    ctx_log
                );
                response
            }
            MediatorError::DIDError(error_code, session_id, did, msg) => {
                event!(
                    Level::WARN,
                    "{}: DIDError({}): did({}) Error: {}{}",
                    session_id,
                    error_code,
                    did,
                    msg,
                    ctx_log
                );
                ErrorResponse {
                    http_code: StatusCode::BAD_REQUEST.as_u16(),
                    session_id,
                    request_id,
                    error_code,
                    error_code_str: "DIDError".to_string(),
                    message: format!("did({did}) Error: invalid or unresolvable DID"),
                }
            }
            MediatorError::ConfigError(error_code, session_id, message) => {
                event!(
                    Level::WARN,
                    "{}: ConfigError({}): {}{}",
                    session_id,
                    error_code,
                    message,
                    ctx_log
                );
                ErrorResponse {
                    http_code: StatusCode::SERVICE_UNAVAILABLE.as_u16(),
                    session_id,
                    request_id,
                    error_code,
                    error_code_str: "ConfigError".to_string(),
                    message: "Service configuration error".to_string(),
                }
            }
            MediatorError::DatabaseError(error_code, session_id, message) => {
                event!(
                    Level::WARN,
                    "{}: DatabaseError({}): {}{}",
                    session_id,
                    error_code,
                    message,
                    ctx_log
                );
                ErrorResponse {
                    http_code: StatusCode::SERVICE_UNAVAILABLE.as_u16(),
                    session_id,
                    request_id,
                    error_code,
                    error_code_str: "DatabaseError".to_string(),
                    message: "Service temporarily unavailable".to_string(),
                }
            }
            MediatorError::MessageUnpackError(error_code, session_id, message) => {
                event!(
                    Level::WARN,
                    "{}: MessageUnpackError({}): {}{}",
                    session_id,
                    error_code,
                    message,
                    ctx_log
                );
                ErrorResponse {
                    http_code: StatusCode::BAD_REQUEST.as_u16(),
                    session_id,
                    request_id,
                    error_code,
                    error_code_str: "MessageUnpackError".to_string(),
                    message: "Failed to unpack message".to_string(),
                }
            }
            MediatorError::MessageExpired(error_code, session_id, expired, now) => {
                let response = ErrorResponse {
                    http_code: StatusCode::UNPROCESSABLE_ENTITY.as_u16(),
                    session_id: session_id.to_string(),
                    request_id,
                    error_code,
                    error_code_str: "MessageExpired".to_string(),
                    message: format!("Message expired: expiry({expired}) now({now})"),
                };
                event!(Level::WARN, "{}{}", response.to_string(), ctx_log);
                response
            }
            MediatorError::MessagePackError(error_code, session_id, message) => {
                event!(
                    Level::WARN,
                    "{}: MessagePackError({}): {}{}",
                    session_id,
                    error_code,
                    message,
                    ctx_log
                );
                ErrorResponse {
                    http_code: StatusCode::BAD_REQUEST.as_u16(),
                    session_id,
                    request_id,
                    error_code,
                    error_code_str: "MessagePackError".to_string(),
                    message: "Failed to pack message".to_string(),
                }
            }
            MediatorError::NotImplemented(error_code, session_id, message) => {
                let response = ErrorResponse {
                    http_code: StatusCode::NOT_IMPLEMENTED.as_u16(),
                    session_id: session_id.to_string(),
                    request_id,
                    error_code,
                    error_code_str: "NotImplemented".to_string(),
                    message,
                };
                event!(Level::WARN, "{}{}", response.to_string(), ctx_log);
                response
            }
            MediatorError::SessionError(error_code, session_id, message) => {
                let response = ErrorResponse {
                    http_code: StatusCode::NOT_ACCEPTABLE.as_u16(),
                    session_id: session_id.to_string(),
                    request_id,
                    error_code,
                    error_code_str: "SessionError".to_string(),
                    message,
                };
                event!(Level::WARN, "{}{}", response.to_string(), ctx_log);
                response
            }
            MediatorError::AnonymousMessageError(error_code, session_id, message) => {
                let response = ErrorResponse {
                    http_code: StatusCode::NOT_ACCEPTABLE.as_u16(),
                    session_id: session_id.to_string(),
                    request_id,
                    error_code,
                    error_code_str: "AnonymousMessageError".to_string(),
                    message,
                };
                event!(Level::WARN, "{}{}", response.to_string(), ctx_log);
                response
            }
            MediatorError::ForwardMessageError(error_code, session_id, message) => {
                let response = ErrorResponse {
                    http_code: StatusCode::NOT_ACCEPTABLE.as_u16(),
                    session_id: session_id.to_string(),
                    request_id,
                    error_code,
                    error_code_str: "ForwardMessageError".to_string(),
                    message,
                };
                event!(Level::WARN, "{}{}", response.to_string(), ctx_log);
                response
            }
            MediatorError::AuthenticationError(error_code, message) => {
                event!(
                    Level::WARN,
                    "AuthenticationError({}): {}{}",
                    error_code,
                    message,
                    ctx_log
                );
                ErrorResponse {
                    http_code: StatusCode::UNAUTHORIZED.as_u16(),
                    session_id: "NO-SESSION".to_string(),
                    request_id,
                    error_code,
                    error_code_str: "AuthenticationError".to_string(),
                    message: "Authentication failed".to_string(),
                }
            }
            MediatorError::ACLDenied(error_code, message) => {
                let response = ErrorResponse {
                    http_code: StatusCode::UNAUTHORIZED.as_u16(),
                    session_id: "NO-SESSION".to_string(),
                    request_id,
                    error_code,
                    error_code_str: "ACLDenied".to_string(),
                    message,
                };
                event!(Level::WARN, "{}{}", response.to_string(), ctx_log);
                response
            }
            MediatorError::ProcessorError(error_code, processor, message) => {
                event!(
                    Level::WARN,
                    "ProcessorError({}): Processor ({}): {}{}",
                    error_code,
                    processor,
                    message,
                    ctx_log
                );
                ErrorResponse {
                    http_code: StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
                    session_id: "NO-SESSION".to_string(),
                    request_id,
                    error_code,
                    error_code_str: "ProcessorError".to_string(),
                    message: "Internal server error".to_string(),
                }
            }
            MediatorError::MediatorError(
                error_code,
                session_id,
                _,
                problem_report,
                http_code,
                log_text,
            ) => {
                event!(Level::WARN, "{}{}", log_text, ctx_log);
                ErrorResponse {
                    http_code,
                    session_id,
                    request_id,
                    error_code,
                    error_code_str: "DIDCommProblemReport".to_string(),
                    message: serde_json::to_string(&problem_report)
                        .unwrap_or_else(|_| "Failed to serialize Problem Report".to_string()),
                }
            }
        };
        (
            StatusCode::from_u16(response.http_code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            Json(response),
        )
            .into_response()
    }
}

/// JSON error response body returned by the mediator's HTTP API.
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ErrorResponse {
    pub session_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    pub http_code: u16,
    pub error_code: u16,
    pub error_code_str: String,
    pub message: String,
}

impl fmt::Display for ErrorResponse {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}: httpcode({}) errorCode({}), errorCodeStr({}) message({})",
            self.session_id, self.http_code, self.error_code, self.error_code_str, self.message,
        )?;
        if let Some(ref rid) = self.request_id {
            write!(f, " request_id({rid})")?;
        }
        Ok(())
    }
}
/// JSON success response body returned by the mediator's HTTP API.
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct SuccessResponse<T: GenericDataStruct> {
    pub session_id: String,
    pub http_code: u16,
    pub error_code: i32,
    pub error_code_str: String,
    pub message: String,
    #[serde(bound(deserialize = ""))]
    pub data: Option<T>,
}

impl<T: GenericDataStruct> fmt::Display for SuccessResponse<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}: httpcode({}) errorCode({}), errorCodeStr({}) message({})",
            self.session_id, self.http_code, self.error_code, self.error_code_str, self.message,
        )
    }
}

impl<T: GenericDataStruct> SuccessResponse<T> {
    pub fn response(
        session_id: &str,
        http_code: StatusCode,
        msg: &str,
        data: Option<T>,
    ) -> Json<SuccessResponse<T>> {
        let response = SuccessResponse {
            session_id: session_id.to_string(),
            http_code: http_code.as_u16(),
            error_code: 0,
            error_code_str: "Ok".to_string(),
            message: msg.to_string(),
            data,
        };
        event!(Level::INFO, "{response}");
        Json(response)
    }
}

/// Creates a random 12-character alphanumeric session identifier.
pub fn create_session_id() -> String {
    rand::rng()
        .sample_iter(&Alphanumeric)
        .take(12)
        .map(char::from)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::problem_report::{ProblemReportScope, ProblemReportSorter};
    use axum::http::StatusCode;

    #[test]
    fn test_problem_creates_mediator_error() {
        let err = MediatorError::problem(
            44,
            "test-session",
            None,
            ProblemReportSorter::Error,
            ProblemReportScope::Protocol,
            "authorization.send",
            "DID isn't allowed to send",
            vec![],
            StatusCode::FORBIDDEN,
        );
        match err {
            MediatorError::MediatorError(code, session, msg_id, report, http, log) => {
                assert_eq!(code, 44);
                assert_eq!(session, "test-session");
                assert!(msg_id.is_none());
                assert_eq!(report.code, "e.p.authorization.send");
                assert_eq!(report.comment, "DID isn't allowed to send");
                assert_eq!(http, 403);
                assert_eq!(log, "DID isn't allowed to send");
            }
            _ => panic!("Expected MediatorError::MediatorError variant"),
        }
    }

    #[test]
    fn test_problem_with_log_separate_messages() {
        let err = MediatorError::problem_with_log(
            19,
            "sess-123",
            Some("msg-456".to_string()),
            ProblemReportSorter::Warning,
            ProblemReportScope::Message,
            "message.serialize",
            "Couldn't serialize: {1}",
            vec!["parse error".to_string()],
            StatusCode::BAD_REQUEST,
            "Couldn't serialize message",
        );
        match err {
            MediatorError::MediatorError(code, session, msg_id, report, http, log) => {
                assert_eq!(code, 19);
                assert_eq!(session, "sess-123");
                assert_eq!(msg_id, Some("msg-456".to_string()));
                assert_eq!(report.code, "w.m.message.serialize");
                assert_eq!(report.comment, "Couldn't serialize: {1}");
                assert_eq!(report.args, vec!["parse error"]);
                assert_eq!(http, 400);
                assert_eq!(log, "Couldn't serialize message");
            }
            _ => panic!("Expected MediatorError::MediatorError variant"),
        }
    }

    #[test]
    fn test_problem_with_args() {
        let err = MediatorError::problem(
            63,
            "s1",
            Some("m1".to_string()),
            ProblemReportSorter::Warning,
            ProblemReportScope::Message,
            "protocol.forwarding.attachments.too_many",
            "Too many attachments ({1}). Limit ({2})",
            vec!["5".to_string(), "1".to_string()],
            StatusCode::BAD_REQUEST,
        );
        match err {
            MediatorError::MediatorError(_, _, _, report, _, _) => {
                assert_eq!(report.args.len(), 2);
                assert_eq!(report.args[0], "5");
                assert_eq!(report.args[1], "1");
            }
            _ => panic!("Expected MediatorError::MediatorError variant"),
        }
    }

    #[test]
    fn test_create_session_id_length() {
        let id = create_session_id();
        assert_eq!(id.len(), 12);
        assert!(id.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn test_create_session_id_uniqueness() {
        let id1 = create_session_id();
        let id2 = create_session_id();
        assert_ne!(id1, id2, "Two session IDs should not be identical");
    }
}
