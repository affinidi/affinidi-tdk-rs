/*!
 * Trust List error types.
 */

use thiserror::Error;

/// Errors that can occur during Trust List operations.
#[derive(Error, Debug)]
pub enum TrustListError {
    /// The Trust List XML is malformed or cannot be parsed.
    #[error("Parse error: {0}")]
    Parse(String),

    /// A required field is missing from the Trust List.
    #[error("Missing field: {0}")]
    MissingField(String),

    /// The Trust List signature is invalid.
    #[error("Signature error: {0}")]
    Signature(String),

    /// A certificate could not be parsed.
    #[error("Certificate error: {0}")]
    Certificate(String),

    /// The service type identifier is not recognized.
    #[error("Unknown service type: {0}")]
    UnknownServiceType(String),

    /// A lookup operation found no matching entry.
    #[error("Not found: {0}")]
    NotFound(String),

    /// XML processing error.
    #[error("XML error: {0}")]
    Xml(String),

    /// JSON processing error.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Base64 decoding error.
    #[error("Base64 error: {0}")]
    Base64(String),
}

pub type Result<T> = std::result::Result<T, TrustListError>;
