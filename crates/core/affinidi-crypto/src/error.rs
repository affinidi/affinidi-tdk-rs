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

    // ─── JOSE primitives (`jose` feature) ───────────────────────────────────
    #[error("Key derivation error: {0}")]
    KeyDerivation(String),

    #[error("Key wrap error: {0}")]
    KeyWrap(String),

    #[error("Content encryption error: {0}")]
    ContentEncryption(String),

    #[error("Signing error: {0}")]
    Signing(String),

    #[error("Verification error: {0}")]
    Verification(String),
}

pub type Result<T> = std::result::Result<T, CryptoError>;
