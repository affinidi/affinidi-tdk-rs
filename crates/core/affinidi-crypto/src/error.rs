//! Error types for cryptographic operations

use thiserror::Error;

/// This type is `#[non_exhaustive]`: callers must include a wildcard arm when
/// matching, so future additions do not constitute breaking changes.
#[derive(Error, Debug)]
#[non_exhaustive]
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
    #[error("Key agreement error: {0}")]
    KeyAgreement(String),

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
