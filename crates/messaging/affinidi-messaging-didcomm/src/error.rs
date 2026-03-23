//! Error types for the DIDComm crate.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum DIDCommError {
    #[error("key agreement failed: {0}")]
    KeyAgreement(String),

    #[error("key wrap failed: {0}")]
    KeyWrap(String),

    #[error("content encryption failed: {0}")]
    ContentEncryption(String),

    #[error("signing failed: {0}")]
    Signing(String),

    #[error("verification failed: {0}")]
    Verification(String),

    #[error("invalid message: {0}")]
    InvalidMessage(String),

    #[error("identity not found: {0}")]
    IdentityNotFound(String),

    #[error("unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("no compatible key agreement key: {0}")]
    NoKeyAgreement(String),
}
