/*!
 * SD-JWT error types
 */

use thiserror::Error;

/// Errors that can occur during SD-JWT operations
#[derive(Error, Debug)]
pub enum SdJwtError {
    #[error("Invalid SD-JWT format: {0}")]
    InvalidFormat(String),

    #[error("Invalid disclosure: {0}")]
    InvalidDisclosure(String),

    #[error("Signing error: {0}")]
    Signing(String),

    #[error("Verification error: {0}")]
    Verification(String),

    #[error("Invalid disclosure frame: {0}")]
    InvalidFrame(String),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("Key binding error: {0}")]
    KeyBinding(String),
}

pub type Result<T> = std::result::Result<T, SdJwtError>;
