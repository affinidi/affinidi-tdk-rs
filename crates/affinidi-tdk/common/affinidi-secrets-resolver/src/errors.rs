/*!
 * Secrets Manager Errors
 */

use thiserror::Error;

/// Affinidi Secrets Resolver Errors
#[derive(Error, Debug)]
pub enum SecretsResolverError {
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
}

pub type Result<T> = std::result::Result<T, SecretsResolverError>;
