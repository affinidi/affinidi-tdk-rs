/*!
 * Secrets Manager Errors
 */

use affinidi_crypto::CryptoError;
use affinidi_encoding::EncodingError;
use thiserror::Error;

/// Affinidi Secrets Resolver Errors
///
/// This type is `#[non_exhaustive]`: callers must include a wildcard arm when
/// matching, so future additions do not constitute breaking changes.
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum SecretsResolverError {
    #[error("Encoding error: {0}")]
    EncodingError(#[from] EncodingError),

    #[error("Crypto error: {0}")]
    CryptoError(#[from] CryptoError),

    #[error("Authentication Error: {0}")]
    AuthenticationError(String),
    #[error("Key Error: {0}")]
    KeyError(String),

    #[error("Encoding Error: {0}")]
    Encoding(String),

    #[error("Decoding Error: {0}")]
    Decoding(String),

    #[error("Unexpected Codec: {0}")]
    UnexpectedCodec(String),

    #[error("Unsupported Key Type: {0}")]
    UnsupportedKeyType(String),

    /// The secrets task behind a `ThreadedSecretsResolver` has stopped, so the
    /// command was not carried out.
    #[error("The secrets task has stopped")]
    SecretsTaskClosed,

    /// The secrets task did not accept or answer a command in time. The
    /// command may still be carried out later.
    #[error("The secrets task did not respond within {0:?}")]
    SecretsTaskTimeout(std::time::Duration),
}

pub type Result<T> = std::result::Result<T, SecretsResolverError>;
