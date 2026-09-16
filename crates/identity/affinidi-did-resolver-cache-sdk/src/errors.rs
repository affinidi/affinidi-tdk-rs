//! Error types for the DID Cache Client SDK
use std::string::FromUtf8Error;

pub use affinidi_did_resolver_traits::NetworkFetchError;
use thiserror::Error;
use wasm_bindgen::JsValue;

/// DIDCacheError is the error type for the DID Cache Client SDK.
///
/// This error type is used for all errors that can occur in the DID Cache Client SDK.
///
/// `Clone` so that one failed resolution can be handed to every caller that
/// was waiting on it (see `DIDCacheClient::resolve`).
#[derive(Error, Debug, Clone)]
#[non_exhaustive]
pub enum DIDCacheError {
    /// There was an error in resolving the DID.
    #[error("DID error: {0}")]
    DIDError(String),
    /// Resolving the DID needed a network fetch, and the fetch failed.
    ///
    /// Distinct from [`DIDCacheError::DIDError`]: this is a statement about
    /// the host serving the DID, not about the DID. Match on the
    /// [`NetworkFetchError`] to tell a rate-limited resolution
    /// ([`NetworkFetchError::is_rate_limited`], HTTP 429) from any other HTTP
    /// status or from a request that got no response at all.
    ///
    /// Produced for did:web, did:webvh and did:scid (vh) resolved locally. A
    /// client in network mode receives the cache server's error as a
    /// [`DIDCacheError::TransportError`] string instead, because the websocket
    /// protocol carries errors as text.
    #[error("{0}")]
    NetworkFetch(NetworkFetchError),
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

    /// An agent name (DID shortcut) failed to parse, resolve, or verify.
    ///
    /// Notably includes the mandatory `alsoKnownAs` check: a name that resolves
    /// to a DID whose document does not claim the name back is rejected here.
    #[cfg(feature = "agent-names")]
    #[error("Agent name error: {0}")]
    AgentNameError(String),
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
    fn network_fetch_rate_limited_display() {
        let err = DIDCacheError::NetworkFetch(
            NetworkFetchError::new("HTTP 429")
                .with_url("https://example.com/.well-known/did.jsonl")
                .with_status(429),
        );
        assert_eq!(
            err.to_string(),
            "DID host https://example.com/.well-known/did.jsonl rate-limited resolution (HTTP 429)"
        );
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
