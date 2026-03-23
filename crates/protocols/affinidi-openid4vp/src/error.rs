/*!
 * OpenID4VP error types.
 */

use thiserror::Error;

/// Errors that can occur during OpenID4VP operations.
#[derive(Error, Debug)]
pub enum Oid4vpError {
    /// The authorization request is invalid.
    #[error("Invalid request: {0}")]
    InvalidRequest(String),

    /// The authorization response is invalid.
    #[error("Invalid response: {0}")]
    InvalidResponse(String),

    /// The presentation definition is invalid.
    #[error("Invalid presentation definition: {0}")]
    InvalidPresentationDefinition(String),

    /// No matching credentials found for the request.
    #[error("No matching credentials: {0}")]
    NoMatchingCredentials(String),

    /// The VP token is invalid.
    #[error("Invalid VP token: {0}")]
    InvalidVpToken(String),

    /// JSON error.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, Oid4vpError>;
