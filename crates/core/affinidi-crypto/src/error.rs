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

/// Maps an error from decoding a multikey or `did:key` onto the variants this
/// crate has always reported for them: framing problems are `Decoding`, a
/// wrong codec or key length is `KeyError`.
#[allow(dead_code)]
pub(crate) fn key_decoding_error(e: affinidi_encoding::EncodingError) -> CryptoError {
    use affinidi_encoding::EncodingError as E;
    match e {
        E::InvalidDidKey(m) => CryptoError::Decoding(format!("Expected 'did:key:' prefix: {m}")),
        E::InvalidMultibasePrefix(c) => CryptoError::Decoding(format!(
            "Expected multibase 'z' (base58btc) prefix, got '{c}'"
        )),
        E::InvalidBase58(m) => CryptoError::Decoding(format!("Couldn't decode base58: {m}")),
        E::UnexpectedCodec { expected, actual } => CryptoError::KeyError(format!(
            "Expected public key codec 0x{expected:x}, instead received codec 0x{actual:x}"
        )),
        E::InvalidKeyLength {
            expected, actual, ..
        } => CryptoError::KeyError(format!(
            "Invalid public key byte length: expected {expected}, got {actual}"
        )),
        other => CryptoError::Encoding(other),
    }
}
