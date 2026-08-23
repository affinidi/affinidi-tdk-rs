//! Errors raised while resolving a `did:webs` identifier.

use thiserror::Error;

/// Errors from `did:webs` parsing and resolution.
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum DidWebsError {
    /// The identifier is not a syntactically valid `did:webs` DID.
    #[error("invalid did:webs identifier: {0}")]
    InvalidDid(String),

    /// An artifact could not be fetched.
    #[error("could not fetch {url}: {reason}")]
    Fetch {
        /// The URL that was requested.
        url: String,
        /// Why it failed.
        reason: String,
    },

    /// The CESR stream could not be parsed, or carried something this
    /// implementation will not interpret.
    #[error("keri.cesr could not be read: {0}")]
    Stream(String),

    /// The key event log did not verify.
    #[error("key event log verification failed: {0}")]
    Kel(String),

    /// The published `did.json` disagrees with the document derived from the
    /// verified key state.
    #[error("did.json does not match the verified key state: {0}")]
    DocumentMismatch(String),

    /// An identifier could not be created or continued.
    #[error("could not create: {0}")]
    Create(String),

    /// JSON deserialization failed.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}
