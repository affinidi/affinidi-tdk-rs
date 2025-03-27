/*!
 * Affinidi Meeting-Place Error Handling
 */

use affinidi_did_authentication::errors::DIDAuthError;
use affinidi_did_resolver_cache_sdk::errors::DIDCacheError;
use affinidi_tdk_common::errors::TDKError;
use thiserror::Error;

/// Meeting-Place Errors
#[derive(Error, Debug)]
pub enum MeetingPlaceError {
    /// Authentication error
    #[error("Authentication failed: {0}")]
    Authentication(String),

    /// REST API Error
    #[error("API error: {0}")]
    API(String),

    /// TDK Error
    #[error("API error: {0}")]
    TDK(String),

    /// Serialization Error
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// DID Error
    #[error("DID Error: {0}")]
    DIDError(String),

    /// Error
    #[error("Error: {0}")]
    Error(String),
}

pub type Result<T> = std::result::Result<T, MeetingPlaceError>;

impl From<TDKError> for MeetingPlaceError {
    fn from(error: TDKError) -> Self {
        MeetingPlaceError::TDK(error.to_string())
    }
}

impl From<DIDAuthError> for MeetingPlaceError {
    fn from(error: DIDAuthError) -> Self {
        MeetingPlaceError::Authentication(error.to_string())
    }
}

impl From<DIDCacheError> for MeetingPlaceError {
    fn from(error: DIDCacheError) -> Self {
        MeetingPlaceError::DIDError(error.to_string())
    }
}
