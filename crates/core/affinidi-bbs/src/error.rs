/*!
 * BBS signature error types.
 */

use thiserror::Error;

/// Errors that can occur during BBS operations.
#[derive(Error, Debug)]
pub enum BbsError {
    /// Key material is invalid or too short.
    /// Check that key_material is >= 32 bytes and key_info <= 65535 bytes.
    #[error("Invalid key: {0}")]
    InvalidKey(String),

    /// The signature is invalid or malformed.
    /// The signature may be corrupted or was created with different parameters.
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),

    /// The proof is invalid or malformed.
    /// The proof may be corrupted, use different parameters, or be forged.
    #[error("Invalid proof: {0}")]
    InvalidProof(String),

    /// A message index is out of bounds or duplicated.
    /// Ensure all disclosed_indexes are unique and < message count.
    #[error("Invalid index: {0}")]
    InvalidIndex(String),

    /// A deserialization operation failed.
    /// The input bytes are malformed or truncated.
    #[error("Deserialization error: {0}")]
    Deserialization(String),

    /// A cryptographic operation failed.
    /// This may indicate invalid parameters or an internal error.
    #[error("Crypto error: {0}")]
    Crypto(String),
}

pub type Result<T> = std::result::Result<T, BbsError>;
