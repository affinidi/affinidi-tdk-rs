/*!
 * SD-JWT error types
 */

use thiserror::Error;

/// Errors that can occur during SD-JWT operations.
#[derive(Error, Debug)]
pub enum SdJwtError {
    /// The SD-JWT string could not be parsed (malformed JWS, missing parts, etc.).
    #[error("Invalid SD-JWT format: {0}")]
    InvalidFormat(String),

    /// A disclosure could not be parsed or has invalid structure.
    #[error("Invalid disclosure: {0}")]
    InvalidDisclosure(String),

    /// The JWT signing operation failed.
    #[error("Signing error: {0}")]
    Signing(String),

    /// Verification of the SD-JWT failed (signature, digest, or claim mismatch).
    #[error("Verification error: {0}")]
    Verification(String),

    /// The disclosure frame is invalid (reserved claim names, bad structure).
    #[error("Invalid disclosure frame: {0}")]
    InvalidFrame(String),

    /// JSON serialization or deserialization failed.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Base64 decoding failed.
    #[error("Base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),

    /// Key Binding JWT verification failed (missing cnf, sd_hash mismatch, etc.).
    #[error("Key binding error: {0}")]
    KeyBinding(String),
}

pub type Result<T> = std::result::Result<T, SdJwtError>;
