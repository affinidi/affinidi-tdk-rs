/*!
 * OpenID4VCI error types.
 */

use thiserror::Error;

/// Errors that can occur during OpenID4VCI operations.
#[derive(Error, Debug)]
pub enum Oid4vciError {
    /// The credential issuer metadata is invalid.
    #[error("Invalid metadata: {0}")]
    InvalidMetadata(String),

    /// The credential offer is invalid.
    #[error("Invalid offer: {0}")]
    InvalidOffer(String),

    /// The credential request is invalid.
    #[error("Invalid request: {0}")]
    InvalidRequest(String),

    /// The authorization flow failed.
    #[error("Authorization error: {0}")]
    Authorization(String),

    /// The proof of possession is invalid.
    #[error("Invalid proof: {0}")]
    InvalidProof(String),

    /// JSON error.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, Oid4vciError>;
