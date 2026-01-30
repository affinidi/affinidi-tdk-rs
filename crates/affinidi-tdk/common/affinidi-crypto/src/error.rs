//! Error types for cryptographic operations

use thiserror::Error;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Key error: {0}")]
    KeyError(String),

    #[error("Decoding error: {0}")]
    Decoding(String),

    #[error("Unsupported key type: {0}")]
    UnsupportedKeyType(String),

    #[error("Encoding error: {0}")]
    Encoding(#[from] affinidi_encoding::EncodingError),
}

pub type Result<T> = std::result::Result<T, CryptoError>;
