/*!
 * Error types for the Affinidi Meeting Place client.
 *
 * `#[non_exhaustive]` so that adding new variants in future releases is not
 * a SemVer break.
 */

use affinidi_did_authentication::errors::DIDAuthError;
use affinidi_did_resolver_cache_sdk::errors::DIDCacheError;
use affinidi_tdk_common::errors::TDKError;
use thiserror::Error;

/// Errors surfaced by [`crate::MeetingPlace`] and friends.
#[non_exhaustive]
#[derive(Error, Debug)]
pub enum MeetingPlaceError {
    /// Authentication / authorization failure (401 / 403, or upstream
    /// DID Auth error).
    #[error("Authentication failed: {0}")]
    Authentication(String),

    /// Non-success HTTP response or transport-level failure.
    #[error("API error: {0}")]
    API(String),

    /// Wrapped error from `affinidi-tdk-common`.
    #[error("TDK error: {0}")]
    TDK(String),

    /// JSON serialise / deserialise failure.
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// DID resolution failure.
    #[error("DID error: {0}")]
    DIDError(String),

    /// Misconfiguration detected at runtime (e.g. missing service endpoint
    /// in a DID document, mediator with the wrong number of endpoints).
    #[error("Configuration error: {0}")]
    Configuration(String),

    /// Catch-all for callers that don't fit the other variants.
    #[error("{0}")]
    Other(String),
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
