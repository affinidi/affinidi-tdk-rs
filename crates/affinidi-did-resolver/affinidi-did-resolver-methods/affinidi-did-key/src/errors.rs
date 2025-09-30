use affinidi_secrets_resolver::errors::SecretsResolverError;
use thiserror::Error;

/// Error states for did:key method
#[derive(Error, Debug)]
pub enum Error<'a> {
    /// Wrong DID method or structure
    #[error("Invalid DID ({0}) Error: {1}")]
    InvalidDid(&'a str, String),

    /// DID URL isn't valid
    #[error("Invalid DID URL ({0}) Error: {1}")]
    InvalidDidUrl(&'a str, String),

    /// Public key string length doesn't match what is expected
    #[error("Invalid public key length ({0})")]
    InvalidPublicKeyLength(usize),

    /// Public key value isn't valid for the crypto algorithm
    #[error("Invalid public key error: {0}")]
    InvalidPublicKey(String),

    /// Unsupported Public Key type specified in the method
    #[error("Unsupported public key type: {0}")]
    UnsupportedPublicKeyType(String),

    /// Invalid Public Key type specified
    #[error("Invalid public key type: {0}")]
    InvalidPublicKeyType(&'a str),

    /// Couldn't generate did:key
    #[error("Failed to generate did:key: {0}")]
    GenerateError(#[from] SecretsResolverError),
}
