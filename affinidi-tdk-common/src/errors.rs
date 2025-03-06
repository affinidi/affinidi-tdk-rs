/*!
 * Common TDK Errors and handling/conversion
 */

use affinidi_did_resolver_cache_sdk::errors::DIDCacheError;
use thiserror::Error;

/// Affinidi Trust Development Kit Errors
#[derive(Error, Debug)]
pub enum TDKError {
    #[error("Authentication failed: {0}")]
    Authentication(String),

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
}

pub type Result<T> = std::result::Result<T, TDKError>;

impl From<DIDCacheError> for TDKError {
    fn from(error: DIDCacheError) -> Self {
        TDKError::DIDResolver(error.to_string())
    }
}
