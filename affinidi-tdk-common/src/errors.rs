/*!
 * Common TDK Errors and handling/conversion
 */

use affinidi_did_resolver_cache_sdk::errors::DIDCacheError;
use affinidi_secrets_resolver::errors::SecretsResolverError;
use did_peer::DIDPeerError;
use thiserror::Error;

/// Affinidi Trust Development Kit Errors
#[derive(Error, Debug)]
pub enum TDKError {
    /// Authentication error, can be retried
    #[error("Authentication failed: {0}")]
    Authentication(String),

    /// Authentication error, cannot be retried
    #[error("Authentication Aborted: {0}")]
    AuthenticationAbort(String),

    /// Access Control Denied
    #[error("ACL Denied: {0}")]
    ACLDenied(String),

    #[error("Profile error: {0}")]
    Profile(String),

    #[error("DID Resolver error: {0}")]
    DIDResolver(String),

    #[error("Permission Denied: {0}")]
    PermissionDenied(String),

    #[error("DIDComm Error: {0}")]
    DIDComm(String),

    #[error("ATM Error: {0}")]
    ATM(String),

    #[error("Secrets Error: {0}")]
    Secrets(String),

    #[error("DID Method Error: {0}")]
    DIDMethod(String),
}

pub type Result<T> = std::result::Result<T, TDKError>;

impl From<DIDCacheError> for TDKError {
    fn from(error: DIDCacheError) -> Self {
        TDKError::DIDResolver(error.to_string())
    }
}

impl From<SecretsResolverError> for TDKError {
    fn from(error: SecretsResolverError) -> Self {
        TDKError::Secrets(error.to_string())
    }
}

impl From<DIDPeerError> for TDKError {
    fn from(error: DIDPeerError) -> Self {
        TDKError::DIDMethod(error.to_string())
    }
}
