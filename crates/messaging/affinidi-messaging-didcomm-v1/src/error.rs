//! Error types for the DIDComm v1 crate.
//!
//! Deliberately mirrors [`affinidi_messaging_didcomm::error::DIDCommError`]
//! variant-for-variant where the two protocols can fail the same way, so a
//! caller handling both can map them uniformly. The v1-only variants at the
//! bottom cover failures that have no v2 counterpart.

use thiserror::Error;

/// This type is `#[non_exhaustive]`: callers must include a wildcard arm when
/// matching, so future additions do not constitute breaking changes.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum DIDCommV1Error {
    #[error("key agreement failed: {0}")]
    KeyAgreement(String),

    #[error("key wrap failed: {0}")]
    KeyWrap(String),

    #[error("content encryption failed: {0}")]
    ContentEncryption(String),

    #[error("invalid message: {0}")]
    InvalidMessage(String),

    #[error("identity not found: {0}")]
    IdentityNotFound(String),

    #[error("unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("invalid envelope: {0}")]
    InvalidEnvelope(String),

    /// The base58 verkey that authenticated an authcrypt envelope is not bound
    /// to any known DID, so the message has no `theirDid` to attribute it to.
    ///
    /// v1-only. A v2 authcrypt envelope carries a `skid` that *is* a DID URL,
    /// so the DID is always recoverable from the envelope alone; a v1 envelope
    /// carries only a raw key, and the key -> DID binding is connection state
    /// this crate must be told about. See [`crate::identity`].
    #[error("no DID is bound to verkey {0}")]
    UnknownSenderVerkey(String),

    /// The caller required an authenticated (authcrypt, DID-attributable)
    /// message and the envelope did not provide one.
    #[error("message is not authenticated: {0}")]
    NotAuthenticated(String),

    #[error("invalid key: {0}")]
    InvalidKey(String),

    #[error("invalid identifier: {0}")]
    InvalidIdentifier(String),
}

impl From<affinidi_crypto::CryptoError> for DIDCommV1Error {
    fn from(e: affinidi_crypto::CryptoError) -> Self {
        use affinidi_crypto::CryptoError as C;
        match e {
            C::KeyAgreement(m) | C::KeyDerivation(m) => DIDCommV1Error::KeyAgreement(m),
            C::KeyWrap(m) => DIDCommV1Error::KeyWrap(m),
            C::ContentEncryption(m) => DIDCommV1Error::ContentEncryption(m),
            C::UnsupportedKeyType(m) => DIDCommV1Error::UnsupportedAlgorithm(m),
            C::KeyError(m) | C::Decoding(m) => DIDCommV1Error::InvalidKey(m),
            // `CryptoError` is `#[non_exhaustive]`; map any future variant to a
            // generic key failure rather than failing to compile.
            other => DIDCommV1Error::InvalidKey(other.to_string()),
        }
    }
}
