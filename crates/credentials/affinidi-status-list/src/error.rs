/*!
 * Status list error types.
 */

use thiserror::Error;

/// Errors that can occur during status list operations.
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum StatusListError {
    /// The status list index is out of bounds.
    #[error("Index out of bounds: {index} (list size: {size})")]
    IndexOutOfBounds { index: usize, size: usize },

    /// Compression or decompression failed.
    #[error("Compression error: {0}")]
    Compression(String),

    /// Base64 encoding/decoding failed.
    #[error("Encoding error: {0}")]
    Encoding(String),

    /// The status list data is invalid.
    #[error("Invalid status list: {0}")]
    Invalid(String),

    /// A Status List Token's signature did not verify.
    #[error("Status list token signature: {0}")]
    Signature(String),

    /// A Status List Token is malformed or its claims are not acceptable.
    #[error("Invalid status list token: {0}")]
    Token(String),

    /// A Status List Token's `exp` has passed.
    #[error("Status list token expired at {exp} (now {now})")]
    Expired { exp: i64, now: i64 },

    /// JSON serialization/deserialization failed.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, StatusListError>;
