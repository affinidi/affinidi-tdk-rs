/*!
 * BBS signature error types.
 */

use thiserror::Error;

/// Errors that can occur during BBS operations.
#[derive(Error, Debug)]
pub enum BbsError {
    /// Key material is invalid or too short.
    #[error("Invalid key: {0}")]
    InvalidKey(String),

    /// The signature is invalid or malformed.
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),

    /// The proof is invalid or malformed.
    #[error("Invalid proof: {0}")]
    InvalidProof(String),

    /// A message index is out of bounds.
    #[error("Invalid index: {0}")]
    InvalidIndex(String),

    /// A deserialization operation failed.
    #[error("Deserialization error: {0}")]
    Deserialization(String),

    /// A cryptographic operation failed.
    #[error("Crypto error: {0}")]
    Crypto(String),
}

pub type Result<T> = std::result::Result<T, BbsError>;
