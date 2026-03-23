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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn did_error_display() {
        let err = DIDCacheError::DIDError("bad did".to_string());
        assert_eq!(err.to_string(), "DID error: bad did");
    }

    #[test]
    fn unsupported_method_display() {
        let err = DIDCacheError::UnsupportedMethod("foo".to_string());
        assert_eq!(err.to_string(), "Unsupported DID method: foo");
    }

    #[test]
    fn transport_error_display() {
        let err = DIDCacheError::TransportError("connection refused".to_string());
        assert_eq!(err.to_string(), "Transport error: connection refused");
    }

    #[test]
    fn config_error_display() {
        let err = DIDCacheError::ConfigError("missing field".to_string());
        assert_eq!(err.to_string(), "Config error: missing field");
    }

    #[test]
    fn network_timeout_display() {
        let err = DIDCacheError::NetworkTimeout;
        assert_eq!(err.to_string(), "Network timeout");
    }

    #[test]
    fn parsing_error_display() {
        let err = DIDCacheError::ParsingError("bad json".to_string());
        assert_eq!(err.to_string(), "Parsing error: bad json");
    }

    #[test]
    fn from_utf8_error() {
        let bytes = vec![0xff, 0xfe];
        let utf8_err = String::from_utf8(bytes).unwrap_err();
        let err: DIDCacheError = utf8_err.into();
        assert!(err.to_string().contains("utf8:"));
    }

    #[test]
    fn from_serde_json_error() {
        let json_err = serde_json::from_str::<serde_json::Value>("not json").unwrap_err();
        let err: DIDCacheError = json_err.into();
        assert!(err.to_string().contains("serde_json:"));
    }

    #[test]
    #[cfg(target_arch = "wasm32")]
    fn to_jsvalue_contains_message() {
        let err = DIDCacheError::DIDError("test".to_string());
        let js: JsValue = err.into();
        let s = js.as_string().unwrap();
        assert!(s.contains("test"));
    }
}
