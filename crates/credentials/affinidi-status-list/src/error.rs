/*!
 * Status list error types.
 */

use thiserror::Error;

/// Errors that can occur during status list operations.
#[derive(Error, Debug)]
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

    /// JSON serialization/deserialization failed.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, StatusListError>;
