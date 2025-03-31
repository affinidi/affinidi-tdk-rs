use affinidi_messaging_sdk::messages::{GenericDataStruct, problem_report::ProblemReport};
use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use rand::{Rng, distr::Alphanumeric};
use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;
use tracing::{Level, event};

type SessId = String;

pub struct AppError(MediatorError);

impl<E> From<E> for AppError
where
    E: Into<MediatorError>,
{
    fn from(err: E) -> Self {
        Self(err.into())
    }
}

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
pub enum MediatorError {
    #[error("Error in handling errors! {1}")]
    ErrorHandlingError(SessId, String),
    #[error("{1}")]
    InternalError(SessId, String),
    #[error("Couldn't parse ({1}). Reason: {2}")]
    ParseError(SessId, String, String),
    #[error("Permission Error: {1}")]
    PermissionError(SessId, String),
    #[error("Request is invalid: {1}")]
    RequestDataError(SessId, String),
    #[error("Service Limit exceeded: {1}")]
    ServiceLimitError(SessId, String),
    #[error("Unauthorized: {1}")]
    Unauthorized(SessId, String),
    #[error("DID Error: did({1}) Error: {2}")]
    DIDError(SessId, String, String),
    #[error("Configuration Error: {1}")]
    ConfigError(SessId, String),
    #[error("Database Error: {1}")]
    DatabaseError(SessId, String),
    #[error("Message unpack error: {1}")]
    MessageUnpackError(SessId, String),
    #[error("MessageExpired: expiry({1}) now({2})")]
    MessageExpired(SessId, String, String),
    #[error("Message pack error: {1}")]
    MessagePackError(SessId, String),
    #[error("Feature not implemented: {1}")]
    NotImplemented(SessId, String),
    #[error("Authorization Session ({0}) error: {1}")]
    SessionError(SessId, String),
    #[error("Anonymous message error: {1}")]
    AnonymousMessageError(SessId, String),
    #[error("Forwarding/Routing message error: {1}")]
    ForwardMessageError(SessId, String),
    #[error("Authentication error: {0}")]
    AuthenticationError(String),
    #[error("ACL Denied: {0}")]
    ACLDenied(String),
    #[error("Processor ({0}) error: {1}")]
    ProcessorError(ProcessorError, String),

    /// This is a catch-all for any error that is using DIDComm Problem Reports
    /// `SessId` - Session ID
    /// `Option<String>` - MSG ID responding to
    /// `ProblemReport` - DIDComm Problem Report
    /// `u16` - HTTP status code
    /// `String` - Log message
    #[error("Mediator Error: code({3}): {4}")]
    MediatorError(SessId, Option<String>, Box<ProblemReport>, u16, String),
}

impl From<MediatorError> for ProcessorError {
    fn from(error: MediatorError) -> Self {
        ProcessorError::CommonError(error.to_string())
    }
}

impl From<ProcessorError> for MediatorError {
    fn from(error: ProcessorError) -> Self {
        MediatorError::ProcessorError(error.clone(), error.to_string())
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let response = match self.0 {
            MediatorError::ErrorHandlingError(session_id, msg) => {
                let response = ErrorResponse {
                    httpCode: StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
                    sessionId: session_id.to_string(),
                    errorCode: 1,
                    errorCodeStr: "ErrorHandlingError".to_string(),
                    message: msg.to_string(),
                };
                event!(Level::WARN, "{}", response.to_string());
                response
            }
            MediatorError::InternalError(session_id, msg) => {
                let response = ErrorResponse {
                    httpCode: StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
                    sessionId: session_id.to_string(),
                    errorCode: 2,
                    errorCodeStr: "InternalError".to_string(),
                    message: msg.to_string(),
                };
                event!(Level::WARN, "{}", response.to_string());
                response
            }
            MediatorError::ParseError(session_id, _, msg) => {
                let response = ErrorResponse {
                    httpCode: StatusCode::BAD_REQUEST.as_u16(),
                    sessionId: session_id.to_string(),
                    errorCode: 3,
                    errorCodeStr: "BadRequest: ParseError".to_string(),
                    message: msg.to_string(),
                };
                event!(Level::WARN, "{}", response.to_string());
                response
            }
            MediatorError::PermissionError(session_id, msg) => {
                let response = ErrorResponse {
                    httpCode: StatusCode::FORBIDDEN.as_u16(),
                    sessionId: session_id.to_string(),
                    errorCode: 4,
                    errorCodeStr: "Forbidden: PermissionError".to_string(),
                    message: msg.to_string(),
                };
                event!(Level::WARN, "{}", response.to_string());
                response
            }
            MediatorError::RequestDataError(session_id, msg) => {
                let response = ErrorResponse {
                    httpCode: StatusCode::BAD_REQUEST.as_u16(),
                    sessionId: session_id.to_string(),
                    errorCode: 5,
                    errorCodeStr: "BadRequest: RequestDataError".to_string(),
                    message: format!("Bad Request: ({})", msg),
                };
                event!(Level::WARN, "{}", response.to_string());
                response
            }
            MediatorError::ServiceLimitError(session_id, msg) => {
                let response = ErrorResponse {
                    httpCode: StatusCode::BAD_REQUEST.as_u16(),
                    sessionId: session_id.to_string(),
                    errorCode: 6,
                    errorCodeStr: "BadRequest: ServiceLimitError".to_string(),
                    message: msg.to_string(),
                };
                event!(Level::WARN, "{}", response.to_string());
                response
            }
            MediatorError::Unauthorized(session_id, msg) => {
                let response = ErrorResponse {
                    httpCode: StatusCode::UNAUTHORIZED.as_u16(),
                    sessionId: session_id.to_string(),
                    errorCode: 7,
                    errorCodeStr: "Unauthorized".to_string(),
                    message: format!("Unauthorized access: {}", msg),
                };
                event!(Level::WARN, "{}", response.to_string());
                response
            }
            MediatorError::DIDError(session_id, did, msg) => {
                let response = ErrorResponse {
                    httpCode: StatusCode::BAD_REQUEST.as_u16(),
                    sessionId: session_id.to_string(),
                    errorCode: 8,
                    errorCodeStr: "DIDError".to_string(),
                    message: format!("did({}) Error: {}", did, msg),
                };
                event!(Level::WARN, "{}", response.to_string());
                response
            }
            MediatorError::ConfigError(session_id, message) => {
                let response = ErrorResponse {
                    httpCode: StatusCode::SERVICE_UNAVAILABLE.as_u16(),
                    sessionId: session_id.to_string(),
                    errorCode: 9,
                    errorCodeStr: "ConfigError".to_string(),
                    message,
                };
                event!(Level::WARN, "{}", response.to_string());
                response
            }
            MediatorError::DatabaseError(session_id, message) => {
                let response = ErrorResponse {
                    httpCode: StatusCode::SERVICE_UNAVAILABLE.as_u16(),
                    sessionId: session_id.to_string(),
                    errorCode: 10,
                    errorCodeStr: "DatabaseError".to_string(),
                    message,
                };
                event!(Level::WARN, "{}: {}", session_id, response.to_string());
                response
            }
            MediatorError::MessageUnpackError(session_id, message) => {
                let response = ErrorResponse {
                    httpCode: StatusCode::BAD_REQUEST.as_u16(),
                    sessionId: session_id.to_string(),
                    errorCode: 11,
                    errorCodeStr: "MessageUnpackError".to_string(),
                    message,
                };
                event!(Level::WARN, "{}", response.to_string());
                response
            }
            MediatorError::MessageExpired(session_id, expired, now) => {
                let response = ErrorResponse {
                    httpCode: StatusCode::UNPROCESSABLE_ENTITY.as_u16(),
                    sessionId: session_id.to_string(),
                    errorCode: 12,
                    errorCodeStr: "MessageExpired".to_string(),
                    message: format!("Message expired: expiry({}) now({})", expired, now),
                };
                event!(Level::WARN, "{}", response.to_string());
                response
            }
            MediatorError::MessagePackError(session_id, message) => {
                let response = ErrorResponse {
                    httpCode: StatusCode::BAD_REQUEST.as_u16(),
                    sessionId: session_id.to_string(),
                    errorCode: 13,
                    errorCodeStr: "MessagePackError".to_string(),
                    message,
                };
                event!(Level::WARN, "{}", response.to_string());
                response
            }
            MediatorError::NotImplemented(session_id, message) => {
                let response = ErrorResponse {
                    httpCode: StatusCode::NOT_IMPLEMENTED.as_u16(),
                    sessionId: session_id.to_string(),
                    errorCode: 14,
                    errorCodeStr: "NotImplemented".to_string(),
                    message,
                };
                event!(Level::WARN, "{}", response.to_string());
                response
            }
            MediatorError::SessionError(session_id, message) => {
                let response = ErrorResponse {
                    httpCode: StatusCode::NOT_ACCEPTABLE.as_u16(),
                    sessionId: session_id.to_string(),
                    errorCode: 15,
                    errorCodeStr: "SessionError".to_string(),
                    message,
                };
                event!(Level::WARN, "{}", response.to_string());
                response
            }
            MediatorError::AnonymousMessageError(session_id, message) => {
                let response = ErrorResponse {
                    httpCode: StatusCode::NOT_ACCEPTABLE.as_u16(),
                    sessionId: session_id.to_string(),
                    errorCode: 16,
                    errorCodeStr: "AnonymousMessageError".to_string(),
                    message,
                };
                event!(Level::WARN, "{}", response.to_string());
                response
            }
            MediatorError::ForwardMessageError(session_id, message) => {
                let response = ErrorResponse {
                    httpCode: StatusCode::NOT_ACCEPTABLE.as_u16(),
                    sessionId: session_id.to_string(),
                    errorCode: 17,
                    errorCodeStr: "ForwardMessageError".to_string(),
                    message,
                };
                event!(Level::WARN, "{}", response.to_string());
                response
            }
            MediatorError::AuthenticationError(message) => {
                let response = ErrorResponse {
                    httpCode: StatusCode::UNAUTHORIZED.as_u16(),
                    sessionId: "NO-SESSION".to_string(),
                    errorCode: 18,
                    errorCodeStr: "AuthenticationError".to_string(),
                    message,
                };
                event!(Level::WARN, "{}", response.to_string());
                response
            }
            MediatorError::ACLDenied(message) => {
                let response = ErrorResponse {
                    httpCode: StatusCode::UNAUTHORIZED.as_u16(),
                    sessionId: "NO-SESSION".to_string(),
                    errorCode: 19,
                    errorCodeStr: "ACLDenied".to_string(),
                    message,
                };
                event!(Level::WARN, "{}", response.to_string());
                response
            }
            MediatorError::ProcessorError(processor, message) => {
                let response = ErrorResponse {
                    httpCode: StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
                    sessionId: "NO-SESSION".to_string(),
                    errorCode: 20,
                    errorCodeStr: "ACLDenied".to_string(),
                    message: format!("Processor ({}): {}", processor, message),
                };
                event!(Level::WARN, "{}", response.to_string());
                response
            }
            MediatorError::MediatorError(session_id, _, problem_report, http_code, log_text) => {
                let response = ErrorResponse {
                    httpCode: http_code,
                    sessionId: session_id,
                    errorCode: 20,
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
