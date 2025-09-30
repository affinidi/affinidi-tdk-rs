//! Error types for the DID Cache Client SDK
use std::string::FromUtf8Error;

use thiserror::Error;
use wasm_bindgen::JsValue;

/// DIDCacheError is the error type for the DID Cache Client SDK.
///
/// This error type is used for all errors that can occur in the DID Cache Client SDK.
#[derive(Error, Debug)]
pub enum DIDCacheError {
    /// There was an error in resolving the DID.
    #[error("DID error: {0}")]
    DIDError(String),
    /// Unsupported DID Method
    #[error("Unsupported DID method: {0}")]
    UnsupportedMethod(String),
    /// An error occurred at the transport layer.
    #[error("Transport error: {0}")]
    TransportError(String),
    /// An error occurred in the configuration.
    #[error("Config error: {0}")]
    ConfigError(String),
    /// A network timeout occurred.
    #[error("Network timeout")]
    NetworkTimeout,

    /// String parsing error
    #[error("Parsing error: {0}")]
    ParsingError(String),
}

// Converts DIDCacheError to JsValue which is required for propagating errors to WASM
impl From<DIDCacheError> for JsValue {
    fn from(err: DIDCacheError) -> JsValue {
        JsValue::from(err.to_string())
    }
}

impl From<FromUtf8Error> for DIDCacheError {
    fn from(err: FromUtf8Error) -> DIDCacheError {
        DIDCacheError::ParsingError(format!("utf8: {err}"))
    }
}

impl From<serde_json::Error> for DIDCacheError {
    fn from(err: serde_json::Error) -> DIDCacheError {
        DIDCacheError::ParsingError(format!("serde_json: {err}"))
    }
}
