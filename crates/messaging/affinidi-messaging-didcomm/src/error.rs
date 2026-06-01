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

/// Map `affinidi-crypto`'s JOSE errors onto the envelope-layer error so
/// `?` works at call sites after the #327 crypto centralization. The
/// variants line up one-to-one; the few without a direct counterpart fold
/// into `KeyAgreement` (their original behaviour was a key/decoding
/// failure surfaced there).
impl From<affinidi_crypto::CryptoError> for DIDCommError {
    fn from(e: affinidi_crypto::CryptoError) -> Self {
        use affinidi_crypto::CryptoError as C;
        match e {
            C::KeyAgreement(m) => DIDCommError::KeyAgreement(m),
            C::KeyDerivation(m) => DIDCommError::KeyAgreement(m),
            C::KeyWrap(m) => DIDCommError::KeyWrap(m),
            C::ContentEncryption(m) => DIDCommError::ContentEncryption(m),
            C::Signing(m) => DIDCommError::Signing(m),
            C::Verification(m) => DIDCommError::Verification(m),
            C::UnsupportedKeyType(m) => DIDCommError::UnsupportedAlgorithm(m),
            C::KeyError(m) | C::Decoding(m) => DIDCommError::KeyAgreement(m),
            C::Encoding(err) => DIDCommError::KeyAgreement(err.to_string()),
        }
    }
}
