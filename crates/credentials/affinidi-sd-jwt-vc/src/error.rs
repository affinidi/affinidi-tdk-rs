/*!
 * SD-JWT VC error types.
 */

use thiserror::Error;

/// Errors specific to SD-JWT VC operations.
#[derive(Error, Debug)]
pub enum SdJwtVcError {
    /// The `vct` (Verifiable Credential Type) claim is missing or invalid.
    #[error("Invalid vct: {0}")]
    InvalidVct(String),

    /// The `iss` (issuer) claim is missing or invalid.
    #[error("Invalid issuer: {0}")]
    InvalidIssuer(String),

    /// A required temporal claim (`iat`, `exp`, `nbf`) is missing or invalid.
    #[error("Invalid temporal claim: {0}")]
    InvalidTemporal(String),

    /// The credential has expired (`exp` is in the past).
    #[error("Credential expired")]
    Expired,

    /// The credential is not yet valid (`nbf` is in the future).
    #[error("Credential not yet valid")]
    NotYetValid,

    /// The underlying SD-JWT operation failed.
    #[error("SD-JWT error: {0}")]
    SdJwt(#[from] affinidi_sd_jwt::SdJwtError),

    /// JSON error.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, SdJwtVcError>;
