use affinidi_messaging_sdk::messages::{GenericDataStruct, problem_report::ProblemReport};
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

pub struct AppError(MediatorError);

impl<E> From<E> for AppError
where
    E: Into<MediatorError>,
{
    fn from(err: E) -> Self {
        Self(err.into())
    }
}

/// Errors relating to the Mediator Processors. These are largely internal to the Mediator errors
/// They should not be exposed to the user
#[derive(Clone, Error, Debug)]
pub enum ProcessorError {
    #[error("CommonError: {0}")]
    CommonError(String),
    #[error("ForwardingError: {0}")]
    ForwardingError(String),
    #[error("MessageExpiryCleanupError: {0}")]
    MessageExpiryCleanupError(String),
}

/// MediatorError the first String is always the session_id
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum MediatorError {
    #[error("Error in handling errors! {2}")]
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
    #[error("ErrorCode, Unauthorized: {2}")]
    Unauthorized(ErrorCode, SessId, String),
    #[error("DID Error: did({2}) Error: {3}")]
    DIDError(ErrorCode, SessId, String, String),
    #[error("Configuration Error: {2}")]
    ConfigError(ErrorCode, SessId, String),
    #[error("Database Error: {2}")]
    DatabaseError(ErrorCode, SessId, String),
    #[error("Message unpack error: {2}")]
    MessageUnpackError(ErrorCode, SessId, String),
    #[error("MessageExpired: expiry({2}) now({3})")]
    MessageExpired(ErrorCode, SessId, String, String),
    #[error("Message pack error: {2}")]
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
    #[error("ACL Denied: {1}")]
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
        let response = match self.0 {
            MediatorError::ErrorHandlingError(error_code, session_id, msg) => {
                let response = ErrorResponse {
                    httpCode: StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
                    sessionId: session_id.to_string(),
                    errorCode: error_code,
                    errorCodeStr: "ErrorHandlingError".to_string(),
                    message: msg.to_string(),
                };
                event!(Level::WARN, "{}", response.to_string());
                response
            }
            MediatorError::InternalError(error_code, session_id, msg) => {
                let response = ErrorResponse {
                    httpCode: StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
                    sessionId: session_id.to_string(),
                    errorCode: error_code,
                    errorCodeStr: "InternalError".to_string(),
                    message: msg.to_string(),
                };
                event!(Level::WARN, "{}", response.to_string());
                response
            }
            MediatorError::ParseError(error_code, session_id, _, msg) => {
                let response = ErrorResponse {
                    httpCode: StatusCode::BAD_REQUEST.as_u16(),
                    sessionId: session_id.to_string(),
                    errorCode: error_code,
                    errorCodeStr: "BadRequest: ParseError".to_string(),
                    message: msg.to_string(),
                };
                event!(Level::WARN, "{}", response.to_string());
                response
            }
            MediatorError::PermissionError(error_code, session_id, msg) => {
                let response = ErrorResponse {
                    httpCode: StatusCode::FORBIDDEN.as_u16(),
                    sessionId: session_id.to_string(),
                    errorCode: error_code,
                    errorCodeStr: "Forbidden: PermissionError".to_string(),
                    message: msg.to_string(),
                };
                event!(Level::WARN, "{}", response.to_string());
                response
            }
            MediatorError::RequestDataError(error_code, session_id, msg) => {
                let response = ErrorResponse {
                    httpCode: StatusCode::BAD_REQUEST.as_u16(),
                    sessionId: session_id.to_string(),
                    errorCode: error_code,
                    errorCodeStr: "BadRequest: RequestDataError".to_string(),
                    message: format!("Bad Request: ({msg})"),
                };
                event!(Level::WARN, "{}", response.to_string());
                response
            }
            MediatorError::ServiceLimitError(error_code, session_id, msg) => {
                let response = ErrorResponse {
                    httpCode: StatusCode::BAD_REQUEST.as_u16(),
                    sessionId: session_id.to_string(),
                    errorCode: error_code,
                    errorCodeStr: "BadRequest: ServiceLimitError".to_string(),
                    message: msg.to_string(),
                };
                event!(Level::WARN, "{}", response.to_string());
                response
            }
            MediatorError::Unauthorized(error_code, session_id, msg) => {
                let response = ErrorResponse {
                    httpCode: StatusCode::UNAUTHORIZED.as_u16(),
                    sessionId: session_id.to_string(),
                    errorCode: error_code,
                    errorCodeStr: "Unauthorized".to_string(),
                    message: format!("Unauthorized access: {msg}"),
                };
                event!(Level::WARN, "{}", response.to_string());
                response
            }
            MediatorError::DIDError(error_code, session_id, did, msg) => {
                let response = ErrorResponse {
                    httpCode: StatusCode::BAD_REQUEST.as_u16(),
                    sessionId: session_id.to_string(),
                    errorCode: error_code,
                    errorCodeStr: "DIDError".to_string(),
                    message: format!("did({did}) Error: {msg}"),
                };
                event!(Level::WARN, "{}", response.to_string());
                response
            }
            MediatorError::ConfigError(error_code, session_id, message) => {
                let response = ErrorResponse {
                    httpCode: StatusCode::SERVICE_UNAVAILABLE.as_u16(),
                    sessionId: session_id.to_string(),
                    errorCode: error_code,
                    errorCodeStr: "ConfigError".to_string(),
                    message,
                };
                event!(Level::WARN, "{}", response.to_string());
                response
            }
            MediatorError::DatabaseError(error_code, session_id, message) => {
                let response = ErrorResponse {
                    httpCode: StatusCode::SERVICE_UNAVAILABLE.as_u16(),
                    sessionId: session_id.to_string(),
                    errorCode: error_code,
                    errorCodeStr: "DatabaseError".to_string(),
                    message,
                };
                event!(Level::WARN, "{}: {}", session_id, response.to_string());
                response
            }
            MediatorError::MessageUnpackError(error_code, session_id, message) => {
                let response = ErrorResponse {
                    httpCode: StatusCode::BAD_REQUEST.as_u16(),
                    sessionId: session_id.to_string(),
                    errorCode: error_code,
                    errorCodeStr: "MessageUnpackError".to_string(),
                    message,
                };
                event!(Level::WARN, "{}", response.to_string());
                response
            }
            MediatorError::MessageExpired(error_code, session_id, expired, now) => {
                let response = ErrorResponse {
                    httpCode: StatusCode::UNPROCESSABLE_ENTITY.as_u16(),
                    sessionId: session_id.to_string(),
                    errorCode: error_code,
                    errorCodeStr: "MessageExpired".to_string(),
                    message: format!("Message expired: expiry({expired}) now({now})"),
                };
                event!(Level::WARN, "{}", response.to_string());
                response
            }
            MediatorError::MessagePackError(error_code, session_id, message) => {
                let response = ErrorResponse {
                    httpCode: StatusCode::BAD_REQUEST.as_u16(),
                    sessionId: session_id.to_string(),
                    errorCode: error_code,
                    errorCodeStr: "MessagePackError".to_string(),
                    message,
                };
                event!(Level::WARN, "{}", response.to_string());
                response
            }
            MediatorError::NotImplemented(error_code, session_id, message) => {
                let response = ErrorResponse {
                    httpCode: StatusCode::NOT_IMPLEMENTED.as_u16(),
                    sessionId: session_id.to_string(),
                    errorCode: error_code,
                    errorCodeStr: "NotImplemented".to_string(),
                    message,
                };
                event!(Level::WARN, "{}", response.to_string());
                response
            }
            MediatorError::SessionError(error_code, session_id, message) => {
                let response = ErrorResponse {
                    httpCode: StatusCode::NOT_ACCEPTABLE.as_u16(),
                    sessionId: session_id.to_string(),
                    errorCode: error_code,
                    errorCodeStr: "SessionError".to_string(),
                    message,
                };
                event!(Level::WARN, "{}", response.to_string());
                response
            }
            MediatorError::AnonymousMessageError(error_code, session_id, message) => {
                let response = ErrorResponse {
                    httpCode: StatusCode::NOT_ACCEPTABLE.as_u16(),
                    sessionId: session_id.to_string(),
                    errorCode: error_code,
                    errorCodeStr: "AnonymousMessageError".to_string(),
                    message,
                };
                event!(Level::WARN, "{}", response.to_string());
                response
            }
            MediatorError::ForwardMessageError(error_code, session_id, message) => {
                let response = ErrorResponse {
                    httpCode: StatusCode::NOT_ACCEPTABLE.as_u16(),
                    sessionId: session_id.to_string(),
                    errorCode: error_code,
                    errorCodeStr: "ForwardMessageError".to_string(),
                    message,
                };
                event!(Level::WARN, "{}", response.to_string());
                response
            }
            MediatorError::AuthenticationError(error_code, message) => {
                let response = ErrorResponse {
                    httpCode: StatusCode::UNAUTHORIZED.as_u16(),
                    sessionId: "NO-SESSION".to_string(),
                    errorCode: error_code,
                    errorCodeStr: "AuthenticationError".to_string(),
                    message,
                };
                event!(Level::WARN, "{}", response.to_string());
                response
            }
            MediatorError::ACLDenied(error_code, message) => {
                let response = ErrorResponse {
                    httpCode: StatusCode::UNAUTHORIZED.as_u16(),
                    sessionId: "NO-SESSION".to_string(),
                    errorCode: error_code,
                    errorCodeStr: "ACLDenied".to_string(),
                    message,
                };
                event!(Level::WARN, "{}", response.to_string());
                response
            }
            MediatorError::ProcessorError(error_code, processor, message) => {
                let response = ErrorResponse {
                    httpCode: StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
                    sessionId: "NO-SESSION".to_string(),
                    errorCode: error_code,
                    errorCodeStr: "ACLDenied".to_string(),
                    message: format!("Processor ({processor}): {message}"),
                };
                event!(Level::WARN, "{}", response.to_string());
                response
            }
            MediatorError::MediatorError(
                error_code,
                session_id,
                _,
                problem_report,
                http_code,
                log_text,
            ) => {
                let response = ErrorResponse {
                    httpCode: http_code,
                    sessionId: session_id,
                    errorCode: error_code,
                    errorCodeStr: "DIDCommProblemReport".to_string(),
                    message: serde_json::to_string(&problem_report)
                        .unwrap_or_else(|_| "Failed to serialize Problem Report".to_string()),
                };
                event!(Level::WARN, log_text);
                response
            }
        };
        (
            StatusCode::from_u16(response.httpCode).ok().unwrap(),
            Json(response),
        )
            .into_response()
    }
}

#[derive(Serialize, Debug)]
#[allow(non_snake_case)]
pub struct ErrorResponse {
    pub sessionId: String,
    pub httpCode: u16,
    pub errorCode: u16,
    pub errorCodeStr: String,
    pub message: String,
}

impl fmt::Display for ErrorResponse {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}: httpcode({}) errorCode({}), errorCodeStr({}) message({})",
            self.sessionId, self.httpCode, self.errorCode, self.errorCodeStr, self.message,
        )
    }
}
#[derive(Serialize, Deserialize, Debug)]
#[allow(non_snake_case)]
pub struct SuccessResponse<T: GenericDataStruct> {
    pub sessionId: String,
    pub httpCode: u16,
    pub errorCode: i32,
    pub errorCodeStr: String,
    pub message: String,
    #[serde(bound(deserialize = ""))]
    pub data: Option<T>,
}

impl<T: GenericDataStruct> fmt::Display for SuccessResponse<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}: httpcode({}) errorCode({}), errorCodeStr({}) message({})",
            self.sessionId, self.httpCode, self.errorCode, self.errorCodeStr, self.message,
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
            sessionId: session_id.to_string(),
            httpCode: http_code.as_u16(),
            errorCode: 0,
            errorCodeStr: "Ok".to_string(),
            message: msg.to_string(),
            data,
        };
        event!(Level::INFO, "{response}");
        Json(response)
    }
}

// Creates a random transaction identifier for each transaction
pub fn create_session_id() -> String {
    rand::rng()
        .sample_iter(&Alphanumeric)
        .take(12)
        .map(char::from)
        .collect()
}
