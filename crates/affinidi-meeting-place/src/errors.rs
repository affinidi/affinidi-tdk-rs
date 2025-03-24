/*!
 * Affinidi Meeting-Place Error Handling
 */

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
}

pub type Result<T> = std::result::Result<T, MeetingPlaceError>;

impl From<TDKError> for MeetingPlaceError {
    fn from(error: TDKError) -> Self {
        MeetingPlaceError::TDK(error.to_string())
    }
}
