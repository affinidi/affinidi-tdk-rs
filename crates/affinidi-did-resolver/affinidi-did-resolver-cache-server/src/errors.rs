use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;
use tracing::{Level, event};

use crate::common::GenericDataStruct;

type SessId = String;

pub struct AppError(CacheError);

impl<E> From<E> for AppError
where
    E: Into<CacheError>,
{
    fn from(err: E) -> Self {
        Self(err.into())
    }
}

/// CacheError the first String is always the session_id
#[derive(Error, Debug)]
pub enum CacheError {
    #[error("Error in handling errors! {1}")]
    ErrorHandlingError(SessId, String),
    #[error("{1}")]
    InternalError(SessId, String),
    #[error("Couldn't parse ({1}). Reason: {2}")]
    ParseError(SessId, String, String),
    #[error("DID Error: did({1}) Error: {2}")]
    DIDError(SessId, String, String),
    #[error("Configuration Error: {1}")]
    ConfigError(SessId, String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let response = match self.0 {
            CacheError::ErrorHandlingError(session_id, msg) => {
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
            CacheError::InternalError(session_id, msg) => {
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
            CacheError::ParseError(session_id, _, msg) => {
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
            CacheError::DIDError(session_id, did, msg) => {
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
            CacheError::ConfigError(session_id, message) => {
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
