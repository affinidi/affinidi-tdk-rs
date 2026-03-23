/*!
 * SIOPv2 error types.
 */

use thiserror::Error;

/// Errors specific to SIOPv2 operations.
#[derive(Error, Debug)]
pub enum SiopError {
    /// The authorization request is invalid.
    #[error("Invalid request: {0}")]
    InvalidRequest(String),

    /// The ID Token is invalid or validation failed.
    #[error("Invalid ID Token: {0}")]
    InvalidIdToken(String),

    /// The subject identifier type is not supported.
    #[error("Subject syntax types not supported: {0}")]
    SubjectSyntaxNotSupported(String),

    /// The user cancelled the authentication.
    #[error("User cancelled")]
    UserCancelled,

    /// The client metadata is invalid.
    #[error("Invalid client metadata: {0}")]
    InvalidClientMetadata(String),

    /// The nonce does not match.
    #[error("Nonce mismatch")]
    NonceMismatch,

    /// The ID Token has expired.
    #[error("ID Token expired")]
    Expired,

    /// The iss != sub invariant is violated.
    #[error("Self-issued invariant violated: iss must equal sub")]
    IssSubMismatch,

    /// The audience does not match the client_id.
    #[error("Audience mismatch: expected {expected}, got {actual}")]
    AudienceMismatch { expected: String, actual: String },

    /// The JWK Thumbprint does not match the sub claim.
    #[error("JWK Thumbprint mismatch")]
    ThumbprintMismatch,

    /// JSON error.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, SiopError>;
