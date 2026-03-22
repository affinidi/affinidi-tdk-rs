/*!
 * Verifiable Credential error types.
 */

use thiserror::Error;

/// Errors that can occur during Verifiable Credential operations.
#[derive(Error, Debug)]
pub enum VcError {
    /// The credential is missing required fields or has invalid structure.
    #[error("Invalid credential: {0}")]
    InvalidCredential(String),

    /// The presentation is missing required fields or has invalid structure.
    #[error("Invalid presentation: {0}")]
    InvalidPresentation(String),

    /// A required JSON-LD context is missing.
    #[error("Missing context: {0}")]
    MissingContext(String),

    /// The credential type is invalid or missing.
    #[error("Invalid type: {0}")]
    InvalidType(String),

    /// A timestamp could not be parsed.
    #[error("Invalid date: {0}")]
    InvalidDate(String),

    /// The credential has expired.
    #[error("Credential expired")]
    Expired,

    /// The credential is not yet valid (before `validFrom` / `issuanceDate`).
    #[error("Credential not yet valid")]
    NotYetValid,

    /// JSON serialization/deserialization failed.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// The credential status check failed.
    #[error("Status check failed: {0}")]
    StatusCheck(String),
}

pub type Result<T> = std::result::Result<T, VcError>;
