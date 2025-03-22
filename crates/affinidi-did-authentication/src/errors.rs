/*!
 * DID Authentication Errors
 */

use affinidi_did_resolver_cache_sdk::errors::DIDCacheError;
// use affinidi_messaging_didcomm::error::Error as DidcommError;
use affinidi_secrets_resolver::errors::SecretsResolverError;
use thiserror::Error;

/// DID Authentication Errors
#[derive(Error, Debug)]
pub enum DIDAuthError {
    /// Authentication error, can be retried
    #[error("Authentication failed: {0}")]
    Authentication(String),

    /// Authentication error, cannot be retried
    #[error("Authentication Aborted: {0}")]
    AuthenticationAbort(String),

    /// Access Control Denied
    #[error("ACL Denied: {0}")]
    ACLDenied(String),

    /// DIDComm related Error
    #[error("DIDComm error: {0}")]
    DIDComm(String),

    #[error("DID Resolver error: {0}")]
    DIDResolver(String),

    #[error("Secrets Error: {0}")]
    Secrets(String),
}

pub type Result<T> = std::result::Result<T, DIDAuthError>;

// impl From<DidcommError> for DIDAuthError {
//     fn from(error: DidcommError) -> Self {
//         DIDAuthError::DIDComm(error.to_string())
//     }
// }

impl From<DIDCacheError> for DIDAuthError {
    fn from(error: DIDCacheError) -> Self {
        DIDAuthError::DIDResolver(error.to_string())
    }
}

impl From<SecretsResolverError> for DIDAuthError {
    fn from(error: SecretsResolverError) -> Self {
        DIDAuthError::Secrets(error.to_string())
    }
}
