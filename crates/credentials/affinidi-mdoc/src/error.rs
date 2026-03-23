/*!
 * mdoc error types.
 */

use thiserror::Error;

/// Errors that can occur during mdoc operations.
#[derive(Error, Debug)]
pub enum MdocError {
    /// CBOR encoding/decoding failed.
    #[error("CBOR error: {0}")]
    Cbor(String),

    /// COSE signature operation failed.
    #[error("COSE error: {0}")]
    Cose(String),

    /// The MSO (Mobile Security Object) is invalid.
    #[error("Invalid MSO: {0}")]
    InvalidMso(String),

    /// A namespace or attribute is invalid.
    #[error("Invalid namespace: {0}")]
    InvalidNamespace(String),

    /// Digest verification failed.
    #[error("Digest mismatch: {0}")]
    DigestMismatch(String),

    /// The document has expired.
    #[error("Document expired")]
    Expired,

    /// A required field is missing.
    #[error("Missing field: {0}")]
    MissingField(String),

    /// Device authentication failed.
    #[error("Device auth error: {0}")]
    DeviceAuth(String),

    /// Reader authentication failed.
    #[error("Reader auth error: {0}")]
    ReaderAuth(String),

    /// Session transcript error.
    #[error("Session transcript error: {0}")]
    SessionTranscript(String),

    /// JSON conversion error.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, MdocError>;
